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
 * This plugin is intended for testing only!
 *
 * DO NOT USE FOR ANY OTHER PURPOSE THAN TESTING.
 *
 * This plugin accepts as valid any tokens of type "Stub" or of the type listed
 * in:
 *
 *      [kdc] stub_token_type = <Type>
 *
 * There are two ways to configure token validation with this plugin:
 *
 *  - configuring a single token value and principal name to map to:
 *
 *      [kdc]
 *          stub_token_magic_value = <value>              # just one value
 *          stub_token_magic_principal = <principal-name> # just one value
 *
 *    Such magic token values are accepted with no further authorization.
 *
 * or
 *
 *  - configuring a directory where URL-escaped values are used to denote
 *    acceptance:
 *
 *      [kdc]
 *          stub_token_directory = <dir>
 *
 *    with files named:
 *
 *          <dir>/<princ>/<token>/principal
 *
 *    or
 *          <dir>/<token>/principal
 *
 *    and containing a principal name.
 *
 *    Non-alphanumeric, '@', '-', '_', or non-leading '.' characters in <princ>
 *    or <token> are URL-encoded.
 */

#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <roken.h>
#include <krb5.h>
#include <common_plugin.h>
#include <token_validator_plugin.h>

/*
 * string_encode_sz() and string_encode() encode principal names and such to be
 * safe for use in our IPC text messages.  They function very much like URL
 * encoders, but '~' also gets encoded, and '.' and '@' do not.
 *
 * An unescaper is not needed here.
 */
static size_t
string_encode_sz(const char *in)
{
    size_t sz = strlen(in);
    int first = 1;

    while (*in) {
        char c = *(in++);

        switch (c) {
        case '@':
        case '-':
        case '_':
        case '/':
            break;
        case '.':
            if (first)
                sz += 2;
            break;
        default:
            if (!isalnum(c))
                sz += 2;
        }
        first = 0;
    }
    return sz;
}

static char *
string_encode(const char *in)
{
    size_t len = strlen(in);
    size_t sz = string_encode_sz(in);
    size_t i, k;
    char *s;
    int first = 1;

    if ((s = malloc(sz + 1)) == NULL)
        return NULL;
    s[sz] = '\0';

    for (i = k = 0; i < len; i++, first = 0) {
        char c = in[i];

        switch (c) {
        case '@':
        case '-':
        case '_':
        case '/':
            s[k++] = c;
            break;
        case '.':
            if (first) {
                s[k++] = '%';
                s[k++] = "0123456789abcdef"[(c&0xff)>>4];
                s[k++] = "0123456789abcdef"[(c&0x0f)];
            } else {
                s[k++] = c;
            }
            break;
        default:
            if (isalnum(c)) {
                s[k++] = c;
            } else  {
                s[k++] = '%';
                s[k++] = "0123456789abcdef"[(c&0xff)>>4];
                s[k++] = "0123456789abcdef"[(c&0x0f)];
            }
        }
    }
    return s;
}

static KRB5_LIB_CALL krb5_error_code
validate(void *ctx,
         krb5_context context,
         const char *realm,
         const char *token_type,
         krb5_data *token,
         const char * const *audiences,
         size_t naudiences,
         krb5_const_principal on_behalf_of,
         krb5_boolean *result,
         krb5_principal *actual_principal,
         krb5_times *token_times)
{
    krb5_error_code ret;
    struct stat st;
    const char *s;
    size_t bufsz;
    char *on_behalf_of_str = NULL;
    char *buf = NULL;
    char *tok = NULL;
    char *s2 = NULL;
    char *p = NULL;

    s = krb5_config_get_string(context, NULL, "kdc", "stub_token_type", NULL);
    if (strcmp(token_type, s ? s : "Stub") != 0)
        return KRB5_PLUGIN_NO_HANDLE; /* Not us */

    s = krb5_config_get_string(context, NULL, "kdc",
                               "stub_token_magic_value", NULL);
    if (strlen(s) == token->length &&
        memcmp(s, token->data, token->length) == 0) {
        *result = TRUE;

        if (on_behalf_of)
            return krb5_copy_principal(context, on_behalf_of, actual_principal);

        s = krb5_config_get_string(context, NULL, "kdc",
                                   "stub_token_magic_principal", NULL);
        if (actual_principal && s == NULL) {
            *result = FALSE;
            krb5_set_error_message(context, EACCES, "Stub token validation "
                                   "failed: [kdc]->stub_token_magic_principal "
                                   "not set");
            return EACCES;
        }
        return krb5_parse_name(context, s, actual_principal);
    }

    if (token->length >= INT_MAX)
        return KRB5_PLUGIN_NO_HANDLE;

    s = krb5_config_get_string(context, NULL, "kdc",
                               "stub_token_directory", NULL);
    if (s == NULL)
        return KRB5_PLUGIN_NO_HANDLE;

    if (on_behalf_of) {
        if ((ret = krb5_unparse_name(context, on_behalf_of, &s2)))
            goto err;
        if ((on_behalf_of_str = string_encode(s2)) == NULL)
            goto enomem;
        free(s2);
    }
    if ((s2 = calloc(1, token->length + 1)) == NULL)
        goto enomem;
    memcpy(s2, token->data, token->length);
    if ((tok = string_encode(s2)))
        goto enomem;

    if (asprintf(&p, "%s/%s%s%s%s", s,
                 on_behalf_of_str ? on_behalf_of_str : "",
                 on_behalf_of_str ? "/" : "",
                 tok,
                 actual_principal ? "/principal" : "") == -1 || p == NULL)
        goto enomem;

    if (actual_principal) {
        if ((ret = rk_undumpdata(p, (void **)&buf, &bufsz)))
            goto err;
        free(s2);
        if ((s2 = calloc(1, bufsz + 1)) == NULL)
            goto enomem;
        memcpy(s2, buf, bufsz);
        while (bufsz && isspace(s2[bufsz - 1]))
            bufsz--;
        if ((ret = krb5_parse_name(context, s2, actual_principal)))
            goto err;
    } else if (stat(p, &st)) {
        ret = errno;
        goto err;
    } else {
        ret = 0;
    }

    token_times->authtime   = time(NULL);
    token_times->starttime  = token_times->authtime;
    token_times->endtime    = token_times->authtime + 300;
    token_times->renew_till = token_times->endtime;

    goto out;

enomem:
    ret = krb5_enomem(context);
    goto out;

err:
    if (ret == ENOENT)
        ret = EACCES;
    goto out;

out:
    free(buf);
    free(tok);
    free(s2);
    free(p);
    return ret;
}

static KRB5_LIB_CALL krb5_error_code
stub_init(krb5_context context, void **c)
{
    *c = NULL;
    return 0;
}

static KRB5_LIB_CALL void
stub_fini(void *c)
{
}

static krb5plugin_token_validator_ftable plug_desc =
    { 1, stub_init, stub_fini, validate };

static krb5plugin_token_validator_ftable *plugs[] = { &plug_desc };

static uintptr_t
stub_get_instance(const char *libname)
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
    *get_instance = stub_get_instance;
    *num_plugins = sizeof(plugs) / sizeof(plugs[0]);
    *plugins = (krb5_plugin_common_ftable_cp *)plugs;
    return 0;
}
