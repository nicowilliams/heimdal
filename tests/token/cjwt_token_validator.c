/*
 * Copyright (c) 2019 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * This is a plugin by which the KDC and the kx509 REST proxy can validate JWT
 * Bearer tokens using the cjwt library.
 *
 * Configuration:
 *
 *  [kdc]
 *      realm = {
 *          A.REALM.NAME = {
 *              cjwt_jqk = PATH-TO-JWK-PEM-FILE
 *              cjwt_aud = AUDIENCE-FOR-KDC
 *          }
 *      }
 *
 * where AUDIENCE-FOR-KDC is the value of the "audience" (i.e., the target) of
 * the token.
 */

#define _DEFAULT_SOURCE
#define _GNU_SOURCE
#define _BSD_SOURCE

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <string.h>
#include <krb5.h>
#include <common_plugin.h>
#include <hdb.h>
#include <roken.h>
#include <token_validator_plugin.h>
#include <cjwt/cjwt.h>

static KRB5_LIB_CALL void
freestr(char **s)
{
    free(*s);
    *s = NULL;
}

static const char *
get_kv(krb5_context context, const char *realm, const char *k)
{
    return krb5_config_get_string(context, NULL, "kdc", "realm", realm,
                                  k, NULL);
}

static krb5_error_code
get_issuer_pubkey(krb5_context context,
                  const char *realm,
                  krb5_data *d,
                  char **errstr)
{
    krb5_error_code ret;
    const char *v;

    *errstr = NULL;
    if ((v = get_kv(context, realm, "cjwt_jwk"))) {
        if ((ret = rk_undumpdata(v, &d->data, &d->length)) == 0)
            return 0;
        (void) asprintf(errstr, "could not read jwk issuer key %s: %s (%d)", v,
                        strerror(ret), ret);
        return ret;
    }
    (void) asprintf(errstr, "jwk issuer key not specified in "
                    "[kdc]->realm->%s->cjwt->jwk", realm);
    return EINVAL;
}

static krb5_error_code
check_audience(krb5_context context,
               const char *realm,
               cjwt_t *jwt,
               char **erstr)
{
    const char *e;
    size_t i;

    if (!jwt->aud || (e = get_kv(context, realm, "cjwt_aud")) == NULL)
        return EACCES;
    for (i = 0; i < jwt->aud->count; i++)
        if (strcmp(e, jwt->aud->names[i]) == 0)
            return 0;
    return EACCES;
}

static krb5_error_code
get_princ(krb5_context context,
          const char *realm,
          cjwt_t *jwt,
          krb5_principal *actual_principal,
          char **errstr)
{
    krb5_error_code ret;

    if (jwt->sub == NULL) {
        *errstr = strdup("JWT token lacks 'sub' (subject name)!");
        return EACCES;
    }
    if (strchr(jwt->sub, '@')) {
        ret = krb5_parse_name(context, jwt->sub, actual_principal);
    } else {
        ret = krb5_parse_name_flags(context, jwt->sub,
                                    KRB5_PRINCIPAL_PARSE_NO_REALM,
                                    actual_principal);
    }
    if (ret)
        (void) asprintf(errstr, "JWT token 'sub' not a valid "
                        "principal name: %s", jwt->sub);
    else if (strchr(jwt->sub, '@') == NULL)
        ret = krb5_principal_set_realm(context, *actual_principal, realm);
    return ret;
}

static KRB5_LIB_CALL krb5_error_code
validate(void *ctx,
         krb5_context context,
         const char *realm,
         const char *token_type,
         krb5_data *token,
         krb5_const_principal on_behalf_of,
         krb5_boolean *result,
         krb5_principal *actual_principal,
         char **errstr,
         void (KRB5_LIB_CALL **freef)(char **))
{
    heim_octet_string issuer_pubkey;
    cjwt_t *jwt = NULL;
    char *tokstr = NULL;
    char *defrealm = NULL;
    int ret;

    *freef = freestr;
    if (strcmp(token_type, "Bearer") != 0)
        return KRB5_PLUGIN_NO_HANDLE; /* Not us */

    if ((tokstr = calloc(1, token->length + 1)) == NULL)
        return ENOMEM;
    memcpy(tokstr, token->data, token->length);

    if (realm == NULL) {
        ret = krb5_get_default_realm(context, &defrealm);
        if (ret) {
            *errstr = strdup("could not determine default realm");
            free(tokstr);
            return ret;
        }
        realm = defrealm;
    }

    ret = get_issuer_pubkey(context, NULL, &issuer_pubkey, errstr);
    if (ret) {
        free(defrealm);
        free(tokstr);
        return ret;
    }

    ret = cjwt_decode(tokstr, 0, &jwt, issuer_pubkey.data,
                      issuer_pubkey.length);
    free(issuer_pubkey.data);
    issuer_pubkey.data = NULL;
    free(tokstr);
    tokstr = NULL;
    switch (ret) {
    case 0:
        break;
    case -1:
        *errstr = strdup("invalid jwt format");
        free(defrealm);
        return EINVAL;
    case -2:
        *errstr = strdup("signature validation failed (wrong issuer)");
        free(defrealm);
        return EPERM;
    default:
        *errstr = strdup(strerror(ret));
        free(defrealm);
        return ret;
    }

    /* Success; check audience */
    if ((ret = check_audience(context, NULL, jwt, errstr))) {
        cjwt_destroy(&jwt);
        free(defrealm);
        return EACCES;
    }

    /* Success; extract principal name */
    if (jwt->sub == NULL) {
        cjwt_destroy(&jwt);
        free(defrealm);
        *errstr = strdup("missing claim");
        return EACCES;
    }

    /* XXX Sanity-check more of the decoded JWT */

    ret = get_princ(context, realm, jwt, actual_principal, errstr);
    cjwt_destroy(&jwt);
    free(defrealm);
    return ret;
}

static KRB5_LIB_CALL krb5_error_code
hcjwt_init(krb5_context context, void **c)
{
    *c = NULL;
    return 0;
}

static KRB5_LIB_CALL void
hcjwt_fini(void *c)
{
}

static krb5plugin_token_validator_ftable plug_desc =
    { 1, hcjwt_init, hcjwt_fini, validate };

static krb5plugin_token_validator_ftable *plugs[] = { &plug_desc };

static uintptr_t
hcjwt_get_instance(const char *libname)
{
    if (strcmp(libname, "krb5") == 0)
        return krb5_get_instance(libname);
    return 0;
}

krb5_plugin_load_ft kdc_plugin_bearer_token_plugin_load;

krb5_error_code KRB5_CALLCONV
kdc_plugin_bearer_token_plugin_load(krb5_context context,
                                    krb5_get_instance_func_t *get_instance,
                                    size_t *num_plugins,
                                    krb5_plugin_common_ftable_cp **plugins)
{
    *get_instance = hcjwt_get_instance;
    *num_plugins = sizeof(plugs) / sizeof(plugs[0]);
    *plugins = (krb5_plugin_common_ftable_cp *)plugs;
    return 0;
}
