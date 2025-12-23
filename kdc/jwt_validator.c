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
 * JWT Bearer token validator using OpenSSL 3.x APIs.
 *
 * Configuration:
 *
 *  [bx509]
 *      realms = {
 *          A.REALM.NAME = {
 *              # At least one of these must be set
 *              cjwt_jwk_current = PATH-TO-JWK-PEM-FILE
 *              cjwt_jwk_previous = PATH-TO-JWK-PEM-FILE
 *              cjwt_jwk_next = PATH-TO-JWK-PEM-FILE
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
#include <base64.h>
#include <heimbase.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "jwt_validator.h"

/* JSON parsing - simple recursive descent parser for JWT claims */

typedef struct json_value {
    enum { JSON_NULL, JSON_BOOL, JSON_NUMBER, JSON_STRING, JSON_ARRAY, JSON_OBJECT } type;
    union {
        int boolean;
        int64_t number;
        char *string;
        struct {
            struct json_value **items;
            size_t count;
        } array;
        struct {
            char **keys;
            struct json_value **values;
            size_t count;
        } object;
    } u;
} json_value;

static void json_free(json_value *v);

static void
json_free(json_value *v)
{
    size_t i;

    if (v == NULL)
        return;

    switch (v->type) {
    case JSON_STRING:
        free(v->u.string);
        break;
    case JSON_ARRAY:
        for (i = 0; i < v->u.array.count; i++)
            json_free(v->u.array.items[i]);
        free(v->u.array.items);
        break;
    case JSON_OBJECT:
        for (i = 0; i < v->u.object.count; i++) {
            free(v->u.object.keys[i]);
            json_free(v->u.object.values[i]);
        }
        free(v->u.object.keys);
        free(v->u.object.values);
        break;
    default:
        break;
    }
    free(v);
}

static const char *
skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    return p;
}

static json_value *json_parse_value(const char **pp);

static char *
json_parse_string_content(const char **pp)
{
    const char *p = *pp;
    char *result, *out;
    size_t len = 0;
    const char *start;

    if (*p != '"')
        return NULL;
    p++;
    start = p;

    /* First pass: calculate length */
    while (*p && *p != '"') {
        if (*p == '\\') {
            p++;
            if (*p == 'u') {
                p += 4;
                len += 3; /* UTF-8 worst case */
            } else {
                len++;
            }
            p++;
        } else {
            len++;
            p++;
        }
    }
    if (*p != '"')
        return NULL;

    result = malloc(len + 1);
    if (result == NULL)
        return NULL;

    /* Second pass: copy */
    p = start;
    out = result;
    while (*p && *p != '"') {
        if (*p == '\\') {
            p++;
            switch (*p) {
            case '"': *out++ = '"'; break;
            case '\\': *out++ = '\\'; break;
            case '/': *out++ = '/'; break;
            case 'b': *out++ = '\b'; break;
            case 'f': *out++ = '\f'; break;
            case 'n': *out++ = '\n'; break;
            case 'r': *out++ = '\r'; break;
            case 't': *out++ = '\t'; break;
            case 'u':
                /* Simplified: just skip unicode escapes for now */
                p += 4;
                *out++ = '?';
                continue;
            default:
                *out++ = *p;
                break;
            }
            p++;
        } else {
            *out++ = *p++;
        }
    }
    *out = '\0';
    p++; /* skip closing quote */
    *pp = p;
    return result;
}

static json_value *
json_parse_string(const char **pp)
{
    json_value *v;
    char *s;

    s = json_parse_string_content(pp);
    if (s == NULL)
        return NULL;

    v = calloc(1, sizeof(*v));
    if (v == NULL) {
        free(s);
        return NULL;
    }
    v->type = JSON_STRING;
    v->u.string = s;
    return v;
}

static json_value *
json_parse_number(const char **pp)
{
    const char *p = *pp;
    json_value *v;
    char *end;
    int64_t num;

    num = strtoll(p, &end, 10);
    if (end == p)
        return NULL;

    v = calloc(1, sizeof(*v));
    if (v == NULL)
        return NULL;
    v->type = JSON_NUMBER;
    v->u.number = num;
    *pp = end;
    return v;
}

static json_value *
json_parse_array(const char **pp)
{
    const char *p = *pp;
    json_value *v;
    json_value **items = NULL;
    size_t count = 0;
    size_t alloc = 0;

    if (*p != '[')
        return NULL;
    p++;
    p = skip_ws(p);

    v = calloc(1, sizeof(*v));
    if (v == NULL)
        return NULL;
    v->type = JSON_ARRAY;

    if (*p == ']') {
        p++;
        *pp = p;
        return v;
    }

    for (;;) {
        json_value *item;

        p = skip_ws(p);
        item = json_parse_value(&p);
        if (item == NULL)
            goto fail;

        if (count >= alloc) {
            json_value **new_items;
            alloc = alloc ? alloc * 2 : 4;
            new_items = realloc(items, alloc * sizeof(*items));
            if (new_items == NULL) {
                json_free(item);
                goto fail;
            }
            items = new_items;
        }
        items[count++] = item;

        p = skip_ws(p);
        if (*p == ']') {
            p++;
            break;
        }
        if (*p != ',')
            goto fail;
        p++;
    }

    v->u.array.items = items;
    v->u.array.count = count;
    *pp = p;
    return v;

fail:
    for (size_t i = 0; i < count; i++)
        json_free(items[i]);
    free(items);
    free(v);
    return NULL;
}

static json_value *
json_parse_object(const char **pp)
{
    const char *p = *pp;
    json_value *v;
    char **keys = NULL;
    json_value **values = NULL;
    size_t count = 0;
    size_t alloc = 0;

    if (*p != '{')
        return NULL;
    p++;
    p = skip_ws(p);

    v = calloc(1, sizeof(*v));
    if (v == NULL)
        return NULL;
    v->type = JSON_OBJECT;

    if (*p == '}') {
        p++;
        *pp = p;
        return v;
    }

    for (;;) {
        char *key;
        json_value *val;

        p = skip_ws(p);
        key = json_parse_string_content(&p);
        if (key == NULL)
            goto fail;

        p = skip_ws(p);
        if (*p != ':') {
            free(key);
            goto fail;
        }
        p++;

        p = skip_ws(p);
        val = json_parse_value(&p);
        if (val == NULL) {
            free(key);
            goto fail;
        }

        if (count >= alloc) {
            char **new_keys;
            json_value **new_values;
            alloc = alloc ? alloc * 2 : 4;
            new_keys = realloc(keys, alloc * sizeof(*keys));
            new_values = realloc(values, alloc * sizeof(*values));
            if (new_keys == NULL || new_values == NULL) {
                free(key);
                json_free(val);
                free(new_keys);
                free(new_values);
                goto fail;
            }
            keys = new_keys;
            values = new_values;
        }
        keys[count] = key;
        values[count] = val;
        count++;

        p = skip_ws(p);
        if (*p == '}') {
            p++;
            break;
        }
        if (*p != ',')
            goto fail;
        p++;
    }

    v->u.object.keys = keys;
    v->u.object.values = values;
    v->u.object.count = count;
    *pp = p;
    return v;

fail:
    for (size_t i = 0; i < count; i++) {
        free(keys[i]);
        json_free(values[i]);
    }
    free(keys);
    free(values);
    free(v);
    return NULL;
}

static json_value *
json_parse_value(const char **pp)
{
    const char *p = *pp;
    json_value *v;

    p = skip_ws(p);

    if (*p == '"')
        return json_parse_string(pp);
    if (*p == '[')
        return json_parse_array(pp);
    if (*p == '{')
        return json_parse_object(pp);
    if (*p == '-' || (*p >= '0' && *p <= '9'))
        return json_parse_number(pp);

    if (strncmp(p, "true", 4) == 0) {
        v = calloc(1, sizeof(*v));
        if (v) {
            v->type = JSON_BOOL;
            v->u.boolean = 1;
        }
        *pp = p + 4;
        return v;
    }
    if (strncmp(p, "false", 5) == 0) {
        v = calloc(1, sizeof(*v));
        if (v) {
            v->type = JSON_BOOL;
            v->u.boolean = 0;
        }
        *pp = p + 5;
        return v;
    }
    if (strncmp(p, "null", 4) == 0) {
        v = calloc(1, sizeof(*v));
        if (v)
            v->type = JSON_NULL;
        *pp = p + 4;
        return v;
    }

    return NULL;
}

static json_value *
json_parse(const char *s)
{
    return json_parse_value(&s);
}

static json_value *
json_get(json_value *obj, const char *key)
{
    size_t i;

    if (obj == NULL || obj->type != JSON_OBJECT)
        return NULL;
    for (i = 0; i < obj->u.object.count; i++) {
        if (strcmp(obj->u.object.keys[i], key) == 0)
            return obj->u.object.values[i];
    }
    return NULL;
}

static const char *
json_get_string(json_value *obj, const char *key)
{
    json_value *v = json_get(obj, key);
    if (v && v->type == JSON_STRING)
        return v->u.string;
    return NULL;
}

static int64_t
json_get_number(json_value *obj, const char *key, int64_t def)
{
    json_value *v = json_get(obj, key);
    if (v && v->type == JSON_NUMBER)
        return v->u.number;
    return def;
}

/* Base64URL decoding (JWT uses base64url without padding) */

static ssize_t
base64url_decode(const char *src, size_t src_len, unsigned char *dst, size_t dst_len)
{
    char *tmp;
    size_t i, padding;
    ssize_t ret;

    /* Convert base64url to base64 */
    tmp = malloc(src_len + 4);
    if (tmp == NULL)
        return -1;

    for (i = 0; i < src_len; i++) {
        if (src[i] == '-')
            tmp[i] = '+';
        else if (src[i] == '_')
            tmp[i] = '/';
        else
            tmp[i] = src[i];
    }

    /* Add padding */
    padding = (4 - (src_len % 4)) % 4;
    for (i = 0; i < padding; i++)
        tmp[src_len + i] = '=';
    tmp[src_len + padding] = '\0';

    ret = rk_base64_decode(tmp, dst);
    free(tmp);
    return ret;
}

/* JWT signature verification */

typedef enum {
    JWT_ALG_NONE,
    JWT_ALG_RS256,
    JWT_ALG_RS384,
    JWT_ALG_RS512,
    JWT_ALG_ES256,
    JWT_ALG_ES384,
    JWT_ALG_ES512,
    JWT_ALG_EDDSA,
    JWT_ALG_UNKNOWN
} jwt_alg_t;

static jwt_alg_t
parse_alg(const char *alg)
{
    if (alg == NULL)
        return JWT_ALG_UNKNOWN;
    if (strcmp(alg, "none") == 0)
        return JWT_ALG_NONE;
    if (strcmp(alg, "RS256") == 0)
        return JWT_ALG_RS256;
    if (strcmp(alg, "RS384") == 0)
        return JWT_ALG_RS384;
    if (strcmp(alg, "RS512") == 0)
        return JWT_ALG_RS512;
    if (strcmp(alg, "ES256") == 0)
        return JWT_ALG_ES256;
    if (strcmp(alg, "ES384") == 0)
        return JWT_ALG_ES384;
    if (strcmp(alg, "ES512") == 0)
        return JWT_ALG_ES512;
    if (strcmp(alg, "EdDSA") == 0)
        return JWT_ALG_EDDSA;
    return JWT_ALG_UNKNOWN;
}

static const EVP_MD *
alg_to_md(jwt_alg_t alg)
{
    switch (alg) {
    case JWT_ALG_RS256:
    case JWT_ALG_ES256:
        return EVP_sha256();
    case JWT_ALG_RS384:
    case JWT_ALG_ES384:
        return EVP_sha384();
    case JWT_ALG_RS512:
    case JWT_ALG_ES512:
        return EVP_sha512();
    default:
        return NULL;
    }
}

static int
alg_is_rsa(jwt_alg_t alg)
{
    return alg == JWT_ALG_RS256 || alg == JWT_ALG_RS384 || alg == JWT_ALG_RS512;
}

static int
alg_is_ecdsa(jwt_alg_t alg)
{
    return alg == JWT_ALG_ES256 || alg == JWT_ALG_ES384 || alg == JWT_ALG_ES512;
}

static int
alg_is_eddsa(jwt_alg_t alg)
{
    return alg == JWT_ALG_EDDSA;
}

/*
 * Convert ECDSA signature from JWS format (r || s) to DER format.
 * JWS uses fixed-size big-endian integers, OpenSSL expects DER.
 */
static unsigned char *
ecdsa_sig_to_der(const unsigned char *sig, size_t sig_len, size_t *der_len)
{
    ECDSA_SIG *ec_sig = NULL;
    BIGNUM *r = NULL, *s = NULL;
    unsigned char *der = NULL;
    size_t half = sig_len / 2;
    int len;

    r = BN_bin2bn(sig, half, NULL);
    s = BN_bin2bn(sig + half, half, NULL);
    if (r == NULL || s == NULL)
        goto out;

    ec_sig = ECDSA_SIG_new();
    if (ec_sig == NULL)
        goto out;

    if (ECDSA_SIG_set0(ec_sig, r, s) != 1)
        goto out;
    r = s = NULL; /* Now owned by ec_sig */

    len = i2d_ECDSA_SIG(ec_sig, &der);
    if (len < 0) {
        der = NULL;
        goto out;
    }
    *der_len = len;

out:
    BN_free(r);
    BN_free(s);
    ECDSA_SIG_free(ec_sig);
    return der;
}

static int
verify_signature(EVP_PKEY *pkey,
                 jwt_alg_t alg,
                 const unsigned char *data,
                 size_t data_len,
                 const unsigned char *sig,
                 size_t sig_len)
{
    EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *md;
    unsigned char *der_sig = NULL;
    size_t der_sig_len = 0;
    const unsigned char *use_sig;
    size_t use_sig_len;
    int ret = 0;

    /* For ECDSA, convert from JWS format to DER */
    if (alg_is_ecdsa(alg)) {
        der_sig = ecdsa_sig_to_der(sig, sig_len, &der_sig_len);
        if (der_sig == NULL)
            return 0;
        use_sig = der_sig;
        use_sig_len = der_sig_len;
    } else {
        use_sig = sig;
        use_sig_len = sig_len;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
        goto out;

    /*
     * EdDSA (Ed25519/Ed448) uses a different verification flow:
     * - No digest algorithm (pass NULL)
     * - Use EVP_DigestVerify() directly instead of Update/Final
     */
    if (alg_is_eddsa(alg)) {
        if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey) != 1)
            goto out;
        if (EVP_DigestVerify(mdctx, use_sig, use_sig_len, data, data_len) == 1)
            ret = 1;
    } else {
        md = alg_to_md(alg);
        if (md == NULL)
            goto out;

        if (EVP_DigestVerifyInit(mdctx, NULL, md, NULL, pkey) != 1)
            goto out;

        if (EVP_DigestVerifyUpdate(mdctx, data, data_len) != 1)
            goto out;

        if (EVP_DigestVerifyFinal(mdctx, use_sig, use_sig_len) == 1)
            ret = 1;
    }

out:
    EVP_MD_CTX_free(mdctx);
    OPENSSL_free(der_sig);
    return ret;
}

static EVP_PKEY *
load_pubkey_from_pem(const char *path)
{
    FILE *fp;
    EVP_PKEY *pkey = NULL;

    fp = fopen(path, "r");
    if (fp == NULL)
        return NULL;

    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return pkey;
}

/* Main JWT validation function */

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
parse_jwt_claims(const char *payload_json, jwt_claims *claims)
{
    json_value *root = NULL;
    json_value *aud;
    const char *s;
    size_t i;

    memset(claims, 0, sizeof(*claims));

    root = json_parse(payload_json);
    if (root == NULL || root->type != JSON_OBJECT)
        goto fail;

    /* Required claims */
    if ((s = json_get_string(root, "sub")) != NULL)
        claims->sub = strdup(s);
    if ((s = json_get_string(root, "iss")) != NULL)
        claims->iss = strdup(s);

    claims->exp = json_get_number(root, "exp", 0);
    claims->nbf = json_get_number(root, "nbf", 0);
    claims->iat = json_get_number(root, "iat", 0);

    /* Audience can be string or array of strings */
    aud = json_get(root, "aud");
    if (aud) {
        if (aud->type == JSON_STRING) {
            claims->aud = malloc(sizeof(char *));
            if (claims->aud) {
                claims->aud[0] = strdup(aud->u.string);
                claims->aud_count = 1;
            }
        } else if (aud->type == JSON_ARRAY) {
            claims->aud = calloc(aud->u.array.count, sizeof(char *));
            if (claims->aud) {
                for (i = 0; i < aud->u.array.count; i++) {
                    if (aud->u.array.items[i]->type == JSON_STRING)
                        claims->aud[i] = strdup(aud->u.array.items[i]->u.string);
                }
                claims->aud_count = aud->u.array.count;
            }
        }
    }

    /* Private claims */
    if ((s = json_get_string(root, "authz_sub")) != NULL)
        claims->authz_sub = strdup(s);

    json_free(root);
    return 0;

fail:
    json_free(root);
    jwt_claims_free(claims);
    return -1;
}

/*
 * Validate a JWT Bearer token.
 *
 * Tries multiple public keys in order (for key rotation support).
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
    char *tokstr = NULL;
    char *header_b64 = NULL, *payload_b64 = NULL, *sig_b64 = NULL;
    char *header_json = NULL, *payload_json = NULL;
    unsigned char *sig = NULL;
    char *dot1, *dot2;
    ssize_t header_len, payload_len, sig_len;
    json_value *header = NULL;
    const char *alg_str;
    jwt_alg_t alg;
    EVP_PKEY *pkey = NULL;
    jwt_claims claims;
    time_t now;
    size_t i, j, k;
    int found_aud = 0;
    int sig_verified = 0;
    krb5_error_code ret = 0;

    memset(&claims, 0, sizeof(claims));
    *result = FALSE;

    if (njwk_paths == 0) {
        krb5_set_error_message(context, EINVAL, "No JWK paths provided");
        return EINVAL;
    }

    /* Make a mutable copy */
    tokstr = calloc(1, token_len + 1);
    if (tokstr == NULL)
        return krb5_enomem(context);
    memcpy(tokstr, token, token_len);

    /* Split into header.payload.signature */
    dot1 = strchr(tokstr, '.');
    if (dot1 == NULL) {
        ret = EINVAL;
        krb5_set_error_message(context, ret, "Invalid JWT format: missing first dot");
        goto out;
    }
    *dot1 = '\0';
    header_b64 = tokstr;
    payload_b64 = dot1 + 1;

    dot2 = strchr(payload_b64, '.');
    if (dot2 == NULL) {
        ret = EINVAL;
        krb5_set_error_message(context, ret, "Invalid JWT format: missing second dot");
        goto out;
    }
    *dot2 = '\0';
    sig_b64 = dot2 + 1;

    /* Decode header */
    header_json = malloc(strlen(header_b64) + 1);
    if (header_json == NULL) {
        ret = krb5_enomem(context);
        goto out;
    }
    header_len = base64url_decode(header_b64, strlen(header_b64),
                                   (unsigned char *)header_json, strlen(header_b64));
    if (header_len < 0) {
        ret = EINVAL;
        krb5_set_error_message(context, ret, "Invalid JWT: header base64 decode failed");
        goto out;
    }
    header_json[header_len] = '\0';

    /* Parse header JSON */
    header = json_parse(header_json);
    if (header == NULL || header->type != JSON_OBJECT) {
        ret = EINVAL;
        krb5_set_error_message(context, ret, "Invalid JWT: header is not valid JSON");
        goto out;
    }

    /* Check algorithm */
    alg_str = json_get_string(header, "alg");
    alg = parse_alg(alg_str);
    if (alg == JWT_ALG_UNKNOWN) {
        ret = EINVAL;
        krb5_set_error_message(context, ret, "Invalid JWT: unknown algorithm '%s'",
                               alg_str ? alg_str : "(null)");
        goto out;
    }
    if (alg == JWT_ALG_NONE) {
        ret = EPERM;
        krb5_set_error_message(context, ret, "JWT algorithm 'none' not permitted");
        goto out;
    }

    /* Decode signature */
    sig = malloc(strlen(sig_b64) + 1);
    if (sig == NULL) {
        ret = krb5_enomem(context);
        goto out;
    }
    sig_len = base64url_decode(sig_b64, strlen(sig_b64), sig, strlen(sig_b64));
    if (sig_len < 0) {
        ret = EINVAL;
        krb5_set_error_message(context, ret, "Invalid JWT: signature base64 decode failed");
        goto out;
    }

    /* Try each public key in turn */
    *dot1 = '.';  /* Restore first dot for signature verification */
    for (k = 0; k < njwk_paths && !sig_verified; k++) {
        if (jwk_paths[k] == NULL)
            continue;

        pkey = load_pubkey_from_pem(jwk_paths[k]);
        if (pkey == NULL)
            continue;

        /* Verify key type matches algorithm */
        if (alg_is_rsa(alg) && EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
            EVP_PKEY_free(pkey);
            pkey = NULL;
            continue;
        }
        if (alg_is_ecdsa(alg) && EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
            EVP_PKEY_free(pkey);
            pkey = NULL;
            continue;
        }
        if (alg_is_eddsa(alg) &&
            EVP_PKEY_base_id(pkey) != EVP_PKEY_ED25519 &&
            EVP_PKEY_base_id(pkey) != EVP_PKEY_ED448) {
            EVP_PKEY_free(pkey);
            pkey = NULL;
            continue;
        }

        /* Verify signature over "header.payload" */
        if (verify_signature(pkey, alg,
                             (unsigned char *)tokstr, dot2 - tokstr,
                             sig, sig_len)) {
            sig_verified = 1;
        }
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    *dot1 = '\0';  /* Re-null for safety */

    if (!sig_verified) {
        ret = EPERM;
        krb5_set_error_message(context, ret, "JWT signature verification failed "
                               "(tried %zu key(s))", njwk_paths);
        goto out;
    }

    /* Decode payload */
    payload_json = malloc(strlen(payload_b64) + 1);
    if (payload_json == NULL) {
        ret = krb5_enomem(context);
        goto out;
    }
    payload_len = base64url_decode(payload_b64, strlen(payload_b64),
                                    (unsigned char *)payload_json, strlen(payload_b64));
    if (payload_len < 0) {
        ret = EINVAL;
        krb5_set_error_message(context, ret, "Invalid JWT: payload base64 decode failed");
        goto out;
    }
    payload_json[payload_len] = '\0';

    /* Parse claims */
    if (parse_jwt_claims(payload_json, &claims) != 0) {
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

    /* Validate audience */
    if (naudiences > 0) {
        for (i = 0; i < claims.aud_count && !found_aud; i++) {
            for (j = 0; j < naudiences; j++) {
                if (strcasecmp(claims.aud[i], audiences[j]) == 0) {
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
    json_free(header);
    free(tokstr);
    free(header_json);
    free(payload_json);
    free(sig);
    return ret;
}
