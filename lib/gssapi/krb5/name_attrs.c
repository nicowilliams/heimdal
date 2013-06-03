/*
 * Copyright (c) 2013, Cryptonector LLC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions, and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of Cryptonector LLC nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY CRYPTONECTOR LLC AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL CRYPTONECTOR LLC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "gsskrb5_locl.h"

#define EQ_BUF2BUF(b1, b2) \
    ((b1)->length == (b2)->length && \
     memcmp((b1)->value, (b2)->value, (b1)->length) == 0)

#define EQ_BUF2STR(b, s) \
    ((b)->length == strlen(s) && \
     strncmp((b)->value, s, (b)->length) == 0)

#define KRB5_NAME_ATTR_URN_PREFIX \
    "urn:ietf:id:ietf-kitten-name-attrs-00-krb5-"

#define KRB5_NAME_ATTR_REALM KRB5_NAME_ATTR_URN_PREFIX "realm"
#define KRB5_NAME_ATTR_COMPS KRB5_NAME_ATTR_URN_PREFIX "comps"
#define KRB5_NAME_ATTR_COMPN KRB5_NAME_ATTR_URN_PREFIX "compN"
#define KRB5_NAME_ATTR_NAME_TYPE KRB5_NAME_ATTR_URN_PREFIX "name-type"


static OM_uint32 validate_username(krb5_context, OM_uint32 *, const char *,
                                   const char *, gss_buffer_t);
static OM_uint32 validate_domainname(krb5_context, OM_uint32 *, const char *,
                                     const char *, const char *, gss_buffer_t);
static OM_uint32 ret_issuer(krb5_context, OM_uint32 *, krb5_const_principal,
                            gss_buffer_t, gss_buffer_t);
static OM_uint32 ret_comp(krb5_context, OM_uint32 *, krb5_const_principal,
                          unsigned int, gss_buffer_t);
static OM_uint32 ret_comps(krb5_context, OM_uint32 *,
                           krb5_const_principal, int *, gss_buffer_t);

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_get_name_attribute(OM_uint32 *minor_status,
                            gss_name_t input_name,
                            gss_buffer_t attr,
                            int *authenticated,
                            int *complete,
                            gss_buffer_t value,
                            gss_buffer_t display_value,
                            int *more)
{
    krb5_context context;
    krb5_const_principal name = (krb5_const_principal)input_name;
    const char *nametype;
    char comp_attr[] = KRB5_NAME_ATTR_COMPN;
    char *s;
    size_t i, len;
    int32_t nt;
    OM_uint32 major_status;

    GSSAPI_KRB5_INIT(&context);

    *minor_status = 0;
    if (value) {
        value->length = 0;
        value->value = 0;
    }
    if (display_value) {
        display_value->length = 0;
        display_value->value = 0;
    }

    /*
     * For now our attributes are all "complete" in the sense that there
     * are no attributes/values that we don't know about.
     */
    if (complete)
        *complete = 1;

    /*
     * All principal name components are authenticated.  It's some
     * authz-data that might not be: those that are not in
     * AD-KDC-ISSUED in Ticket or similar (e.g., PAC, CAMMAC), an dall
     * that are in the Authenticator authz-data.  Since for now we have
     * none of the Ticket nor Authenticator authz-data in the krb5
     * mech's gss_name_t...
     */
    if (authenticated)
        *authenticated = 1;
    
    if (EQ_BUF2BUF(attr, GSS_C_ATTR_GENERIC_ISSUERNAME) ||
        EQ_BUF2STR(attr, KRB5_NAME_ATTR_REALM)) {
        if (more)
            *more = 0;
        return ret_issuer(context, minor_status, name,
                          value, display_value);
    }

    /* Need to add a krb5_principal_display_name_type() */
    if (EQ_BUF2STR(attr, KRB5_NAME_ATTR_NAME_TYPE)) {
        if (!display_value)
            return GSS_S_COMPLETE;
        nt = krb5_principal_get_type(context, name);
        nametype = krb5_display_nametype(context, nt);
        s = strdup(nametype ? nametype : "UNKNOWN");
        display_value->value = s;
        display_value->length = strlen(s);
        return GSS_S_COMPLETE;
    }

    if (EQ_BUF2BUF(attr, GSS_C_ATTR_GENERIC_UNCONSTRAINED_USERNAME) ||
        EQ_BUF2BUF(attr, GSS_C_ATTR_GENERIC_UNCONSTRAINED_SERVICENAME) ||
        EQ_BUF2BUF(attr, GSS_C_ATTR_GENERIC_SERVICENAME)) {
        if (more)
            *more = 0;
        major_status = ret_comp(context, minor_status, name, 0, display_value);
        if (major_status != GSS_S_COMPLETE)
            return major_status;
        if (EQ_BUF2BUF(attr, GSS_C_ATTR_GENERIC_USERNAME)) {
            return validate_username(context, minor_status,
                                     krb5_principal_get_realm(context, name),
                                     krb5_principal_get_comp_string(context,
                                                                    name, 0),
                                     display_value);
        }
        return GSS_S_COMPLETE;
    }
    if (EQ_BUF2BUF(attr, GSS_C_ATTR_GENERIC_UNCONSTRAINED_HOSTNAME) ||
        EQ_BUF2BUF(attr, GSS_C_ATTR_GENERIC_HOSTNAME)) {
        if (more)
            *more = 0;
        major_status = ret_comp(context, minor_status, name, 1, display_value);
        if (major_status != GSS_S_COMPLETE)
            return major_status;
        if (EQ_BUF2BUF(attr, GSS_C_ATTR_GENERIC_HOSTNAME)) {
            return validate_domainname(context, minor_status,
                                       krb5_principal_get_realm(context, name),
                                       NULL,
                                       krb5_principal_get_comp_string(context,
                                                                      name, 0),
                                       display_value);
        }
        return GSS_S_COMPLETE;
    }
    if (EQ_BUF2BUF(attr, GSS_C_ATTR_GENERIC_DOMAINNAME)) {
        if (more)
            *more = 0;
        major_status = ret_comp(context, minor_status, name, 2, display_value);
        if (major_status != GSS_S_COMPLETE)
            return major_status;
        if (EQ_BUF2BUF(attr, GSS_C_ATTR_GENERIC_DOMAINNAME)) {
            return validate_domainname(context, minor_status,
                                       krb5_principal_get_realm(context, name),
                                       krb5_principal_get_comp_string(context,
                                                                      name, 0),
                                       NULL,
                                       display_value);
        }
        return GSS_S_COMPLETE;
    }

    /* No validation for these */
    if (EQ_BUF2STR(attr, KRB5_NAME_ATTR_COMPS))
        return ret_comps(context, minor_status, name, more, display_value);

    /*
     * Lastly, get a specific component between 0 and 9 (inclusive),
     * where the number is the last digit char in the attribute name.
     */
    if (more)
        *more = 0;

    len = strlen(comp_attr);
    for (i = 0; i < 10; i++) {
        comp_attr[len - 1] = '0' + i;
        if (EQ_BUF2STR(attr, comp_attr))
            return ret_comp(context, minor_status, name, i, display_value);
    }

    /* Any other name attributes... we don't know them yet or are not for us */
    return GSS_S_UNAVAILABLE;
}

static
void
tolower_str(char *p)
{
    for (; *p; p++)
        *p = (char)tolower(*p);
}

static
OM_uint32
validate_username(krb5_context context, OM_uint32 *minor_status,
                  const char *realm, const char *username,
                  gss_buffer_t display_value)
{
    OM_uint32 major_status = GSS_S_UNAVAILABLE;
    krb5_error_code ret;
    const char *s;
    char *def_realm = NULL;
    char *domain = NULL;

    /* XXX Check user_realm instead */
    ret = krb5_get_default_realm(context, &def_realm);
    if (ret)
        goto cleanup;

    if (!strcmp(realm, def_realm)) {
        major_status = GSS_S_COMPLETE;
        goto cleanup;
    }

    s = strchr(username, '@');
    if (!s)
        goto cleanup;
    s++;
    domain = strdup(s);
    if (!domain) {
        ret = krb5_enomem(context);
        goto cleanup;
    }
    tolower_str(domain);
    if (!strcmp(domain, realm)) {
        major_status = GSS_S_COMPLETE;
        goto cleanup;
    }
    /* TODO: check aname2lname or kuserok() */

cleanup:
    free(def_realm);
    free(domain);
    if (display_value && (ret || major_status != GSS_S_COMPLETE)) {
        display_value->value = NULL;
        display_value->length = 0;
    }
    if (ret) {
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    return major_status;
}

static
OM_uint32
validate_domainname(krb5_context context, OM_uint32 *minor_status,
                  const char *realm, const char *domainname,
                  const char *host, gss_buffer_t display_value)
{
    OM_uint32 major_status = GSS_S_UNAVAILABLE;
    krb5_error_code ret = 0;
    krb5_realm *realms = NULL;
    char *domain = NULL;
    char *def_realm = NULL;
    size_t i;

    ret = krb5_get_default_realm(context, &def_realm);
    if (ret)
        goto cleanup;

    if (!strcmp(realm, def_realm)) {
        major_status = GSS_S_COMPLETE;
        goto cleanup;
    }

    if (host && !strchr(host, '.')) {
        /* We should check all default realms here */
        if (!strcmp(realm, def_realm))
            major_status = GSS_S_COMPLETE;
        goto cleanup;
    } else if (host) {
        domainname = strchr(host, '.') + 1;
    }

    domain = strdup(domainname);
    if (!domain) {
        ret = krb5_enomem(context);
        goto cleanup;
    }
    tolower_str(domain);
    if (!strcmp(domain, realm)) {
        major_status = GSS_S_COMPLETE;
        goto cleanup;
    }

    ret = _krb5_get_host_realm_int(context, host, 0 /*use_dns*/, &realms);
    if (ret)
        goto cleanup;
    for (i = 0; realms[i]; i++) {
        tolower_str(realms[i]);
        if (!strcmp(domain, realms[i])) {
            major_status = GSS_S_COMPLETE;
            goto cleanup;
        }
    }

cleanup:
    krb5_free_host_realm(context, realms);
    free(def_realm);
    free(domain);
    if (display_value && (ret || major_status != GSS_S_COMPLETE)) {
        display_value->value = NULL;
        display_value->length = 0;
    }
    if (ret) {
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    return major_status;
}

static
OM_uint32
ret_issuer(krb5_context context, OM_uint32 *minor_status,
           krb5_const_principal name, gss_buffer_t value,
           gss_buffer_t display_value)
{
    OM_uint32 major_status;
    krb5_error_code ret;
    krb5_principal root_krbtgt = NULL;
    char *s;

    s = strdup(krb5_principal_get_realm(context, name));
    if (s == NULL) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    if (display_value) {
        display_value->value = s;
        display_value->length = strlen(s);
    }
    ret = krb5_make_principal(context, &root_krbtgt, s, KRB5_TGS_NAME, s, NULL);
    if (ret) {
        *minor_status = ret;
        major_status = GSS_S_FAILURE;
        goto out;
    }
    major_status = _gsskrb5_export_name(minor_status,
                                        (const gss_name_t)root_krbtgt, value);

out:
    if (major_status != GSS_S_COMPLETE) {
        free(s);
        display_value->value = NULL;
        display_value->length = 0;
    }
    krb5_free_principal(context, root_krbtgt);
    return major_status;
}

static
OM_uint32
ret_comp(krb5_context context, OM_uint32 *minor_status,
         krb5_const_principal name, unsigned int comp,
         gss_buffer_t display_value)
{
    char *s;
    if (comp >= krb5_principal_get_num_comp(context, name))
        return GSS_S_COMPLETE; /* Attribute exists, but no value */

    s = strdup(krb5_principal_get_comp_string(context, name, comp));
    if (s == NULL) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    display_value->value = s;
    display_value->length = strlen(s);
    return GSS_S_COMPLETE;
}

static
OM_uint32
ret_comps(krb5_context context, OM_uint32 *minor_status,
          krb5_const_principal name, int *more,
          gss_buffer_t display_value)
{
    unsigned int comp;

    if (*more == -1) {
        *more = krb5_principal_get_num_comp(context, name);
    } else if (*more <= 0) {
        *minor_status = EINVAL;
        return GSS_S_FAILURE;
    } else {
        assert(*more > 0);
    }
    comp = *more - 1;
    (*more)--;
    assert(*more >= 0);
    return ret_comp(context, minor_status, name, comp, display_value);
}
