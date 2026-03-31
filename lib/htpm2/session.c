/*
 * Copyright (c) 2026 Kungliga Tekniska Högskolan
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
 * TPM 2.0 session management.
 *
 * TPM2_StartAuthSession:
 *   Command (no sessions -- this IS the session creation):
 *     tpmKey:        uint32 (key for salt, or TPM_RH_NULL)
 *     bind:          uint32 (bind entity, or TPM_RH_NULL)
 *     nonceCaller:   TPM2B_NONCE (16-32 bytes, random)
 *     encryptedSalt: TPM2B_ENCRYPTED_SECRET (empty if no salt key)
 *     sessionType:   uint8 (0=HMAC, 1=policy, 3=trial)
 *     symmetric:     TPMT_SYM_DEF (AES-128-CFB for encrypted, NULL otherwise)
 *     authHash:      uint16 (TPM2_ALG_SHA256)
 *
 *   Response:
 *     sessionHandle: uint32
 *     nonceTPM:      TPM2B_NONCE
 *
 * Session key derivation (when bind or salt is used):
 *   sessionKey = KDFa(authHash, (authValue || salt),
 *                     "ATH", nonceTPM, nonceCaller, hashSize*8)
 *
 * HMAC computation for each command:
 *   hmac = HMAC(sessionKey || authValue,
 *               cpHash || nonceNewer || nonceOlder || sessionAttributes)
 *   where cpHash = Hash(CC || names || cpBytes)
 *
 * Response HMAC verification:
 *   hmac = HMAC(sessionKey || authValue,
 *               rpHash || nonceTPM || nonceCaller || sessionAttributes)
 *   where rpHash = Hash(RC || CC || rpBytes)
 */

#include "htpm2_locl.h"
#include "marshal.h"
#include "crypto.h"

#include <openssl/ec.h>

#define TPM_RH_NULL     0x40000007
#define TPM2_SE_HMAC    0x00
#define TPM2_SE_POLICY  0x01
#define TPM2_SE_TRIAL   0x03

#define NONCE_SIZE 16  /* 16 bytes = 128 bits */

/*
 * Internal session structure.
 */
struct htpm2_session_data {
    uint32_t handle;            /* TPM session handle */
    htpm2_session_type type;
    htpm2_transport tp;
    unsigned int flags;

    /* Nonces (updated each command exchange) */
    uint8_t nonce_caller[32];
    size_t nonce_caller_len;
    uint8_t nonce_tpm[32];
    size_t nonce_tpm_len;

    /* Session key (derived from auth + salt via KDFa) */
    uint8_t session_key[32];
    size_t session_key_len;     /* 0 if no session key (unbound, unsalted) */

    /* Bound entity auth value */
    uint8_t bind_auth[64];
    size_t bind_auth_len;

    /* Symmetric algorithm for parameter encryption */
    uint16_t sym_alg;          /* TPM2_ALG_AES or TPM2_ALG_NULL */
    uint16_t sym_key_bits;     /* 128 */
    uint16_t sym_mode;         /* TPM2_ALG_CFB */

    /* Hash algorithm */
    uint16_t auth_hash;        /* TPM2_ALG_SHA256 */

    int closed;
};

htpm2_result
htpm2_session_start(const htpm2_context ctx,
                    htpm2_transport tp,
                    htpm2_result prior,
                    htpm2_session_type type,
                    htpm2_object salt_key,
                    htpm2_object bind,
                    unsigned int flags,
                    htpm2_session *session)
{
    heim_storage *cmd, *rsp;
    uint32_t rc;
    uint32_t tpm_key_handle, bind_handle;
    uint8_t se_type;
    htpm2_result r;
    struct htpm2_session_data *s;
    uint8_t nonce_caller[NONCE_SIZE];
    void *nonce_tpm_data = NULL;
    uint16_t nonce_tpm_len;
    uint32_t sess_handle;
    int ret;

    if (prior.code)
        return prior;

    *session = NULL;

    /* Generate caller nonce */
    r = htpm2_random_bytes(ctx, nonce_caller, NONCE_SIZE);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "StartAuthSession: nonce");

    tpm_key_handle = salt_key ? htpm2_object_get_handle(salt_key) : TPM_RH_NULL;
    bind_handle = bind ? htpm2_object_get_handle(bind) : TPM_RH_NULL;

    switch (type) {
    case HTPM2_SESSION_HMAC:   se_type = TPM2_SE_HMAC; break;
    case HTPM2_SESSION_POLICY: se_type = TPM2_SE_POLICY; break;
    case HTPM2_SESSION_TRIAL:  se_type = TPM2_SE_TRIAL; break;
    default:
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "StartAuthSession: bad type %d", type);
    }

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "StartAuthSession: alloc");

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS,
                                   TPM2_CC_StartAuthSession);
    if (ret) goto marshal_err;

    /* tpmKey */
    ret = heim_store_uint32(cmd, tpm_key_handle);
    if (ret) goto marshal_err;

    /* bind */
    ret = heim_store_uint32(cmd, bind_handle);
    if (ret) goto marshal_err;

    /* nonceCaller (TPM2B_NONCE) */
    ret = htpm2_marshal_tpm2b(cmd, nonce_caller, NONCE_SIZE);
    if (ret) goto marshal_err;

    /*
     * encryptedSalt (TPM2B_ENCRYPTED_SECRET).
     *
     * If a salt key is provided, we generate a random 32-byte salt,
     * RSA-OAEP encrypt it with the salt key's public key (label
     * "SECRET\0"), and send the ciphertext.  The TPM decrypts it
     * and uses the salt for session key derivation.
     *
     * For ECC salt keys, the protocol is different (ECDH) -- not yet
     * supported.
     */
    uint8_t salt[32];
    size_t salt_len = 0;
    void *encrypted_salt = NULL;
    size_t encrypted_salt_len = 0;

    if (salt_key != NULL) {
        const void *pub;
        size_t pub_len;
        heim_storage *pub_sp;
        uint16_t alg_type;
        htpm2_result sr;

        sr = htpm2_object_get_public(salt_key, &pub, &pub_len);
        if (htpm2_is_err(sr)) {
            heim_storage_free(cmd);
            return htpm2_result_prepend(sr, "StartAuthSession: get salt key pub");
        }

        /* Check if RSA by reading the first uint16 (algorithm type) */
        pub_sp = heim_storage_from_readonly_mem(pub, pub_len);
        if (pub_sp == NULL) {
            heim_storage_free(cmd);
            return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                      "StartAuthSession: alloc pub parse");
        }
        heim_ret_uint16(pub_sp, &alg_type);

        if (alg_type == TPM2_ALG_RSA) {
            /* Parse RSA modulus from TPMT_PUBLIC */
            uint16_t name_alg, auth_size, sym_alg, scheme_alg, key_bits;
            uint32_t obj_attrs, exp;
            void *modulus = NULL;
            uint16_t mod_size;

            heim_ret_uint16(pub_sp, &name_alg);
            heim_ret_uint32(pub_sp, &obj_attrs);
            heim_ret_uint16(pub_sp, &auth_size);
            if (auth_size > 0)
                heim_storage_seek(pub_sp, auth_size, SEEK_CUR);
            heim_ret_uint16(pub_sp, &sym_alg);
            if (sym_alg != TPM2_ALG_NULL) {
                uint16_t dummy;
                heim_ret_uint16(pub_sp, &dummy);
                heim_ret_uint16(pub_sp, &dummy);
            }
            heim_ret_uint16(pub_sp, &scheme_alg);
            if (scheme_alg != TPM2_ALG_NULL) {
                uint16_t dummy;
                heim_ret_uint16(pub_sp, &dummy);
            }
            heim_ret_uint16(pub_sp, &key_bits);
            heim_ret_uint32(pub_sp, &exp);
            htpm2_unmarshal_tpm2b(pub_sp, &modulus, &mod_size);
            heim_storage_free(pub_sp);

            if (modulus && mod_size > 0) {
                r = htpm2_random_bytes(ctx, salt, 32);
                if (htpm2_is_ok(r)) {
                    r = htpm2_rsa_oaep_encrypt(ctx, modulus, mod_size,
                                               exp == 0 ? 65537 : exp,
                                               "SECRET", 7,
                                               salt, 32,
                                               &encrypted_salt,
                                               &encrypted_salt_len);
                }
                free(modulus);
                if (htpm2_is_err(r)) {
                    heim_storage_free(cmd);
                    return htpm2_result_prepend(r, "StartAuthSession: salt encrypt");
                }
                salt_len = 32;
            }
        } else if (alg_type == TPM2_ALG_ECC) {
            /* Parse ECC public point from TPMT_PUBLIC */
            uint16_t name_alg, auth_size, sym_alg, scheme_alg, curve_id;
            uint32_t obj_attrs;
            uint16_t kdf_alg;
            void *x_data = NULL, *y_data = NULL;
            uint16_t x_len, y_len;
            int nid;

            heim_ret_uint16(pub_sp, &name_alg);
            heim_ret_uint32(pub_sp, &obj_attrs);
            heim_ret_uint16(pub_sp, &auth_size);
            if (auth_size > 0)
                heim_storage_seek(pub_sp, auth_size, SEEK_CUR);
            heim_ret_uint16(pub_sp, &sym_alg);
            if (sym_alg != TPM2_ALG_NULL) {
                uint16_t dummy;
                heim_ret_uint16(pub_sp, &dummy);
                heim_ret_uint16(pub_sp, &dummy);
            }
            heim_ret_uint16(pub_sp, &scheme_alg);
            if (scheme_alg != TPM2_ALG_NULL) {
                uint16_t dummy;
                heim_ret_uint16(pub_sp, &dummy);
            }
            heim_ret_uint16(pub_sp, &curve_id);
            heim_ret_uint16(pub_sp, &kdf_alg); /* kdf scheme */
            htpm2_unmarshal_tpm2b(pub_sp, &x_data, &x_len);
            htpm2_unmarshal_tpm2b(pub_sp, &y_data, &y_len);
            heim_storage_free(pub_sp);

            /* Map TPM curve ID to OpenSSL NID */
            switch (curve_id) {
            case 0x0003: nid = NID_X9_62_prime256v1; break; /* P-256 */
            case 0x0004: nid = NID_secp384r1; break;        /* P-384 */
            default: nid = 0; break;
            }

            if (nid != 0 && x_data && y_data && x_len > 0 && y_len > 0) {
                r = htpm2_ecc_salt(ctx, nid,
                                   x_data, x_len, y_data, y_len,
                                   x_data, x_len, /* salt_key_x for KDFe */
                                   salt,
                                   &encrypted_salt, &encrypted_salt_len);
                if (htpm2_is_err(r)) {
                    free(x_data);
                    free(y_data);
                    heim_storage_free(cmd);
                    return htpm2_result_prepend(r,
                        "StartAuthSession: ECC salt");
                }
                salt_len = 32;
            }
            free(x_data);
            free(y_data);
        } else {
            heim_storage_free(pub_sp);
            /* Unknown key type; proceed unsalted */
        }
    }

    if (encrypted_salt) {
        ret = htpm2_marshal_tpm2b(cmd, encrypted_salt, encrypted_salt_len);
        free(encrypted_salt);
    } else {
        ret = htpm2_marshal_tpm2b(cmd, NULL, 0);
    }
    if (ret) goto marshal_err;

    /* sessionType */
    ret = heim_store_uint8(cmd, se_type);
    if (ret) goto marshal_err;

    /* symmetric (TPMT_SYM_DEF) */
    if (flags & HTPM2_SESSION_ENC_DEC) {
        /* AES-128-CFB */
        ret = heim_store_uint16(cmd, TPM2_ALG_AES);
        if (ret) goto marshal_err;
        ret = heim_store_uint16(cmd, 128);
        if (ret) goto marshal_err;
        ret = heim_store_uint16(cmd, TPM2_ALG_CFB);
        if (ret) goto marshal_err;
    } else {
        ret = heim_store_uint16(cmd, TPM2_ALG_NULL);
        if (ret) goto marshal_err;
    }

    /* authHash */
    ret = heim_store_uint16(cmd, TPM2_ALG_SHA256);
    if (ret) goto marshal_err;

    r = htpm2_command_execute(ctx, tp, cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "StartAuthSession");

    /* Response: sessionHandle */
    ret = heim_ret_uint32(rsp, &sess_handle);
    if (ret) goto unmarshal_err;

    /* nonceTPM */
    ret = htpm2_unmarshal_tpm2b(rsp, &nonce_tpm_data, &nonce_tpm_len);
    if (ret) goto unmarshal_err;

    heim_storage_free(rsp);

    /* Build session state */
    s = calloc(1, sizeof(*s));
    if (s == NULL) {
        free(nonce_tpm_data);
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "StartAuthSession: alloc session");
    }

    s->handle = sess_handle;
    s->type = type;
    s->tp = tp;
    s->flags = flags;
    s->auth_hash = TPM2_ALG_SHA256;

    memcpy(s->nonce_caller, nonce_caller, NONCE_SIZE);
    s->nonce_caller_len = NONCE_SIZE;

    if (nonce_tpm_data && nonce_tpm_len > 0 && nonce_tpm_len <= 32) {
        memcpy(s->nonce_tpm, nonce_tpm_data, nonce_tpm_len);
        s->nonce_tpm_len = nonce_tpm_len;
    }
    free(nonce_tpm_data);

    if (flags & HTPM2_SESSION_ENC_DEC) {
        s->sym_alg = TPM2_ALG_AES;
        s->sym_key_bits = 128;
        s->sym_mode = TPM2_ALG_CFB;
    } else {
        s->sym_alg = TPM2_ALG_NULL;
    }

    /*
     * Derive session key.
     *
     * sessionKey = KDFa(SHA256, (authValue || salt),
     *                   "ATH", nonceTPM, nonceCaller, 256)
     *
     * - authValue comes from the bind entity (if bound session)
     * - salt comes from our random seed (if salted session)
     * - If neither bind nor salt, there is no session key (the session
     *   still works but can't authenticate or encrypt)
     */
    s->session_key_len = 0;

    {
        uint8_t kdf_key[96]; /* authValue(<=64) || salt(32) */
        size_t kdf_key_len = 0;

        /* Collect bind entity's authValue */
        if (bind != NULL) {
            const void *bauth;
            size_t bauth_len;
            htpm2_result ar = htpm2_object_get_public(bind, &bauth, &bauth_len);
            (void)ar;
            /* Get actual auth from object internals */
            /* The object stores auth_value via htpm2_object_set_auth() */
            /* We need an internal accessor for the raw auth bytes */
            const uint8_t *auth_bytes;
            size_t auth_bytes_len;
            htpm2_object_get_auth_internal(bind, &auth_bytes, &auth_bytes_len);
            if (auth_bytes && auth_bytes_len > 0 &&
                auth_bytes_len <= sizeof(kdf_key)) {
                memcpy(kdf_key + kdf_key_len, auth_bytes, auth_bytes_len);
                kdf_key_len += auth_bytes_len;
                /* Also store for HMAC computation */
                memcpy(s->bind_auth, auth_bytes, auth_bytes_len);
                s->bind_auth_len = auth_bytes_len;
            }
        }

        /* Append salt */
        if (salt_len > 0) {
            memcpy(kdf_key + kdf_key_len, salt, salt_len);
            kdf_key_len += salt_len;
        }

        /* Derive session key if we have either auth or salt */
        if (kdf_key_len > 0) {
            r = htpm2_kdfa(ctx, kdf_key, kdf_key_len, "ATH",
                           s->nonce_tpm, s->nonce_tpm_len,
                           s->nonce_caller, s->nonce_caller_len,
                           256, s->session_key, 32);
            memset(kdf_key, 0, sizeof(kdf_key));
            if (htpm2_is_err(r)) {
                memset(salt, 0, sizeof(salt));
                free(s);
                return htpm2_result_prepend(r, "StartAuthSession: derive key");
            }
            s->session_key_len = 32;
        }
        memset(salt, 0, sizeof(salt));
    }

    *session = s;
    return HTPM2_OK;

marshal_err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "StartAuthSession: marshal");

unmarshal_err:
    free(nonce_tpm_data);
    heim_storage_free(rsp);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "StartAuthSession: unmarshal");
}

void
htpm2_session_close(htpm2_session *session)
{
    struct htpm2_session_data *s;

    if (session == NULL || *session == NULL)
        return;

    s = *session;

    if (!s->closed && s->tp != NULL) {
        /* FlushContext on the session */
        heim_storage *cmd = heim_storage_emem();
        if (cmd) {
            if (htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS,
                                         TPM2_CC_FlushContext) == 0 &&
                heim_store_uint32(cmd, s->handle) == 0) {
                heim_storage *rsp = NULL;
                uint32_t rc;
                htpm2_result r = htpm2_command_execute(NULL, s->tp,
                                                       cmd, &rsp, &rc);
                if (htpm2_is_ok(r))
                    heim_storage_free(rsp);
                htpm2_result_free(&r);
            }
            heim_storage_free(cmd);
        }
    }

    memset(s->session_key, 0, sizeof(s->session_key));
    memset(s->bind_auth, 0, sizeof(s->bind_auth));
    memset(s, 0, sizeof(*s));
    free(s);
    *session = NULL;
}

/* htpm2_session_get_policy_digest is implemented in policy.c */

/* --- Internal accessors for the command layer --- */

uint32_t
htpm2_session_get_handle(htpm2_session session)
{
    return session ? session->handle : 0;
}

htpm2_transport
htpm2_session_get_transport(htpm2_session session)
{
    return session ? session->tp : NULL;
}

const uint8_t *
htpm2_session_get_nonce_caller(htpm2_session session, size_t *len)
{
    if (session == NULL) {
        *len = 0;
        return NULL;
    }
    *len = session->nonce_caller_len;
    return session->nonce_caller;
}

const uint8_t *
htpm2_session_get_nonce_tpm(htpm2_session session, size_t *len)
{
    if (session == NULL) {
        *len = 0;
        return NULL;
    }
    *len = session->nonce_tpm_len;
    return session->nonce_tpm;
}

void
htpm2_session_set_nonce_tpm(htpm2_session session,
                            const uint8_t *nonce, size_t len)
{
    if (session == NULL || len > 32)
        return;
    memcpy(session->nonce_tpm, nonce, len);
    session->nonce_tpm_len = len;
}

htpm2_result
htpm2_session_refresh_nonce_caller(const htpm2_context ctx,
                                   htpm2_session session)
{
    return htpm2_random_bytes(ctx, session->nonce_caller, NONCE_SIZE);
}

unsigned int
htpm2_session_get_flags(htpm2_session session)
{
    return session ? session->flags : 0;
}

const uint8_t *
htpm2_session_get_session_key(htpm2_session session, size_t *len)
{
    if (session == NULL || session->session_key_len == 0) {
        *len = 0;
        return NULL;
    }
    *len = session->session_key_len;
    return session->session_key;
}

void
htpm2_session_get_bind_auth(htpm2_session session,
                            const uint8_t **auth, size_t *auth_len)
{
    if (session == NULL || session->bind_auth_len == 0) {
        *auth = NULL;
        *auth_len = 0;
        return;
    }
    *auth = session->bind_auth;
    *auth_len = session->bind_auth_len;
}
