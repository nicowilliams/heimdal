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

    /* encryptedSalt (TPM2B_ENCRYPTED_SECRET) -- empty for now (no salting) */
    /* TODO: RSA OAEP encrypt a random salt with salt_key's public key */
    ret = htpm2_marshal_tpm2b(cmd, NULL, 0);
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
     * Derive session key if we have a bind entity.
     * sessionKey = KDFa(SHA256, (authValue || salt),
     *                   "ATH", nonceTPM, nonceCaller, 256)
     *
     * For now: unbound unsalted sessions have no session key.
     * The session still works for password-based auth; it just
     * doesn't provide HMAC binding or parameter encryption.
     *
     * TODO: implement salted sessions (RSA OAEP encrypt random salt
     * with salt_key, then derive session key from auth + salt).
     */
    s->session_key_len = 0;

    if (bind != NULL) {
        /*
         * For bound sessions, the session key is derived from the
         * bind entity's authValue.
         *
         * sessionKey = KDFa(SHA256, authValue, "ATH",
         *                   nonceTPM, nonceCaller, 256)
         */
        /* TODO: get bind entity's authValue from the object */
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

htpm2_result
htpm2_session_get_policy_digest(htpm2_session session,
                                htpm2_result prior,
                                void *digest,
                                size_t *digest_len)
{
    (void)session;
    (void)digest;
    (void)digest_len;

    if (prior.code)
        return prior;

    /* TODO: implement TPM2_PolicyGetDigest */
    return htpm2_result_local(ENOSYS, HTPM2_F_LOCAL, ENOSYS,
                              "session_get_policy_digest: not yet implemented");
}

/* --- Internal accessors for the command layer --- */

uint32_t
htpm2_session_get_handle(htpm2_session session)
{
    return session ? session->handle : 0;
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
