/*
 * Copyright (c) 2019-2025 Kungliga Tekniska Högskolan
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
 * JWT Bearer token validator for bx509d/httpkadmind.
 *
 * Uses hx509 JOSE library for signature verification.
 *
 * Configuration:
 *
 *  [bx509]
 *      realms = {
 *          A.REALM.NAME = {
 *              # At least one of these must be set
 *              jwk_current = PATH-TO-JWK-PEM-FILE
 *              jwk_previous = PATH-TO-JWK-PEM-FILE
 *              jwk_next = PATH-TO-JWK-PEM-FILE
 *          }
 *      }
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <roken.h>
#include <krb5.h>
#include <hx509.h>
#include <heimbase.h>

#include "jwt_validator.h"

/*
 * Get a string value from a heim_dict_t, returning NULL if not present
 * or not a string.
 */
static const char *
heim_dict_get_string(heim_dict_t dict, const char *key)
{
    heim_string_t hkey = heim_string_create(key);
    heim_object_t val;
    const char *result = NULL;

    if (hkey == NULL)
        return NULL;
    val = heim_dict_get_value(dict, hkey);
    heim_release(hkey);
    if (val && heim_get_tid(val) == HEIM_TID_STRING)
        result = heim_string_get_utf8((heim_string_t)val);
    return result;
}

/*
 * Get a number value from a heim_dict_t, returning def if not present
 * or not a number.
 */
static int64_t
heim_dict_get_int(heim_dict_t dict, const char *key, int64_t def)
{
    heim_string_t hkey = heim_string_create(key);
    heim_object_t val;
    int64_t result = def;

    if (hkey == NULL)
        return def;
    val = heim_dict_get_value(dict, hkey);
    heim_release(hkey);
    if (val && heim_get_tid(val) == HEIM_TID_NUMBER)
        result = heim_number_get_long((heim_number_t)val);
    return result;
}

/*
 * Get an object value from a heim_dict_t.
 */
static heim_object_t
heim_dict_get_obj(heim_dict_t dict, const char *key)
{
    heim_string_t hkey = heim_string_create(key);
    heim_object_t val;

    if (hkey == NULL)
        return NULL;
    val = heim_dict_get_value(dict, hkey);
    heim_release(hkey);
    return val;
}

/* JWT claims structure for KDC use */

typedef struct jwt_claims {
    char *sub;           /* Subject */
    char *iss;           /* Issuer */
    char **aud;          /* Audience (array) */
    size_t aud_count;
    int64_t exp;         /* Expiration time */
    int64_t nbf;         /* Not before */
    int64_t iat;         /* Issued at */
    char *authz_sub;     /* Private claim: authz_sub */
} jwt_claims;

static void
jwt_claims_free(jwt_claims *claims)
{
    size_t i;

    if (claims == NULL)
        return;
    free(claims->sub);
    free(claims->iss);
    for (i = 0; i < claims->aud_count; i++)
        free(claims->aud[i]);
    free(claims->aud);
    free(claims->authz_sub);
}

static int
parse_jwt_claims(const char *payload_json, size_t payload_len, jwt_claims *claims)
{
    heim_object_t root = NULL;
    heim_object_t aud;
    const char *s;
    size_t i, k;

    memset(claims, 0, sizeof(*claims));

    root = heim_json_create_with_bytes(payload_json, payload_len, 10, 0, NULL);
    if (root == NULL || heim_get_tid(root) != HEIM_TID_DICT)
        goto fail;

    /* Required claims */
    if ((s = heim_dict_get_string((heim_dict_t)root, "sub")) != NULL &&
        (claims->sub = strdup(s)) == NULL)
        goto fail;
    if ((s = heim_dict_get_string((heim_dict_t)root, "iss")) != NULL &&
        (claims->iss = strdup(s)) == NULL)
        goto fail;

    claims->exp = heim_dict_get_int((heim_dict_t)root, "exp", 0);
    claims->nbf = heim_dict_get_int((heim_dict_t)root, "nbf", 0);
    claims->iat = heim_dict_get_int((heim_dict_t)root, "iat", 0);

    /* Audience can be string or array of strings */
    aud = heim_dict_get_obj((heim_dict_t)root, "aud");
    if (aud) {
        if (heim_get_tid(aud) == HEIM_TID_STRING) {
            claims->aud = malloc(sizeof(char *));
            if (claims->aud) {
                claims->aud[0] = strdup(heim_string_get_utf8((heim_string_t)aud));
                if (claims->aud[0] == NULL)
                    goto fail;
                claims->aud_count = 1;
            }
        } else if (heim_get_tid(aud) == HEIM_TID_ARRAY) {
            size_t count = heim_array_get_length((heim_array_t)aud);
            claims->aud = calloc(count, sizeof(char *));
            if (claims->aud) {
                for (k = i = 0; k < count; k++) {
                    heim_object_t item = heim_array_get_value((heim_array_t)aud, i);
                    if (item && heim_get_tid(item) == HEIM_TID_STRING) {
                        claims->aud[i] = strdup(heim_string_get_utf8((heim_string_t)item));
                        if (claims->aud[i] == NULL)
                            goto fail;
                        i++;
                    }
                }
                claims->aud_count = i;
            }
        }
    }

    /* Private claims */
    if ((s = heim_dict_get_string((heim_dict_t)root, "authz_sub")) != NULL &&
        (claims->authz_sub = strdup(s)) == NULL)
        goto fail;

    heim_release(root);
    return 0;

fail:
    heim_release(root);
    jwt_claims_free(claims);
    return -1;
}

/*
 * Read a PEM file into memory.
 * Returns allocated buffer (caller must free) or NULL on error.
 */
static char *
read_pem_file(const char *path, size_t *len_out)
{
    FILE *fp;
    long len;
    char *data;

    fp = fopen(path, "r");
    if (fp == NULL)
        return NULL;

    if (fseek(fp, 0, SEEK_END) < 0) {
        fclose(fp);
        return NULL;
    }
    len = ftell(fp);
    if (len < 0 || len > 1024 * 1024) { /* Max 1MB */
        fclose(fp);
        return NULL;
    }
    rewind(fp);

    data = malloc(len + 1);
    if (data == NULL) {
        fclose(fp);
        return NULL;
    }

    if (fread(data, 1, len, fp) != (size_t)len) {
        fclose(fp);
        free(data);
        return NULL;
    }
    data[len] = '\0';
    fclose(fp);

    if (len_out)
        *len_out = len;
    return data;
}

/*
 * Validate a JWT Bearer token.
 *
 * Uses hx509_jws_verify() for signature verification, then performs
 * KDC-specific claims validation.
 *
 * Returns 0 on success, error code on failure.
 */
krb5_error_code
validate_jwt_token(krb5_context context,
                   const char *token,
                   size_t token_len,
                   const char * const *jwk_paths,
                   size_t njwk_paths,
                   const char * const *audiences,
                   size_t naudiences,
                   krb5_boolean *result,
                   krb5_principal *actual_principal,
                   krb5_times *token_times,
                   const char *realm)
{
    hx509_context hx509ctx = NULL;
    char *tokstr = NULL;
    char **pem_keys = NULL;
    void *payload = NULL;
    size_t payload_len = 0;
    jwt_claims claims;
    time_t now;
    size_t i, j, k;
    int found_aud = 0;
    krb5_error_code ret = 0;
    int hx_ret;

    memset(&claims, 0, sizeof(claims));
    *result = FALSE;

    if (njwk_paths == 0) {
        krb5_set_error_message(context, EINVAL, "No JWK paths provided");
        return EINVAL;
    }

    /* Initialize hx509 context */
    hx_ret = hx509_context_init(&hx509ctx);
    if (hx_ret) {
        krb5_set_error_message(context, ENOMEM, "Could not initialize hx509 context");
        return ENOMEM;
    }

    /* Make a null-terminated copy of the token */
    tokstr = calloc(1, token_len + 1);
    if (tokstr == NULL) {
        ret = krb5_enomem(context);
        goto out;
    }
    memcpy(tokstr, token, token_len);

    /* Read PEM key files into memory */
    pem_keys = calloc(njwk_paths, sizeof(char *));
    if (pem_keys == NULL) {
        ret = krb5_enomem(context);
        goto out;
    }
    for (k = 0; k < njwk_paths; k++) {
        if (jwk_paths[k] == NULL)
            continue;
        pem_keys[k] = read_pem_file(jwk_paths[k], NULL);
        /* It's OK if some keys fail to load - we'll try others */
    }

    /*
     * Verify signature using hx509.
     * This handles all the crypto: algorithm detection, key type matching,
     * ECDSA signature format conversion, EdDSA, etc.
     */
    hx_ret = hx509_jws_verify(hx509ctx, tokstr,
                              (const char * const *)pem_keys, njwk_paths,
                              &payload, &payload_len);
    if (hx_ret) {
        ret = EPERM;
        krb5_set_error_message(context, ret,
                               "JWT signature verification failed: %s",
                               hx509_get_error_string(hx509ctx, hx_ret));
        goto out;
    }

    /* Parse claims */
    if (parse_jwt_claims(payload, payload_len, &claims) != 0) {
        ret = EINVAL;
        krb5_set_error_message(context, ret, "Invalid JWT: could not parse claims");
        goto out;
    }

    /* Validate exp/nbf */
    now = time(NULL);
    if (claims.exp && now >= claims.exp) {
        ret = EACCES;
        krb5_set_error_message(context, ret, "JWT token has expired");
        goto out;
    }
    if (claims.nbf && now < claims.nbf) {
        ret = EACCES;
        krb5_set_error_message(context, ret, "JWT token not yet valid");
        goto out;
    }

    /* Validate audience (support multiple allowed audiences) */
    if (naudiences > 0) {
        for (i = 0; i < claims.aud_count && !found_aud; i++) {
            for (j = 0; j < naudiences; j++) {
                if (strcmp(claims.aud[i], audiences[j]) == 0) {
                    found_aud = 1;
                    break;
                }
            }
        }
        if (!found_aud) {
            ret = EACCES;
            krb5_set_error_message(context, ret, "JWT audience does not match");
            goto out;
        }
    }

    /* Extract principal */
    if (claims.authz_sub) {
        ret = krb5_parse_name(context, claims.authz_sub, actual_principal);
    } else if (claims.sub) {
        const char *at = strchr(claims.sub, '@');
        if (at) {
            ret = krb5_parse_name(context, claims.sub, actual_principal);
        } else {
            ret = krb5_parse_name_flags(context, claims.sub,
                                        KRB5_PRINCIPAL_PARSE_NO_REALM,
                                        actual_principal);
            if (ret == 0 && realm)
                ret = krb5_principal_set_realm(context, *actual_principal, realm);
        }
    } else {
        ret = EACCES;
        krb5_set_error_message(context, ret, "JWT has no subject");
        goto out;
    }

    if (ret) {
        krb5_prepend_error_message(context, ret, "Could not parse JWT subject: ");
        goto out;
    }

    /* Set times */
    token_times->authtime = claims.iat ? claims.iat : now;
    token_times->starttime = claims.nbf ? claims.nbf : claims.iat;
    token_times->endtime = claims.exp ? claims.exp : 0;
    token_times->renew_till = claims.exp ? claims.exp : 0;

    *result = TRUE;

out:
    jwt_claims_free(&claims);
    if (pem_keys) {
        for (k = 0; k < njwk_paths; k++)
            free(pem_keys[k]);
        free(pem_keys);
    }
    free(tokstr);
    free(payload);
    hx509_context_free(&hx509ctx);
    return ret;
}
