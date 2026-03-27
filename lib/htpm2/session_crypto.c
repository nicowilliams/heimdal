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
 * Session cryptographic operations.
 *
 * Command HMAC (TPMS_AUTH_COMMAND.hmac):
 *   key = sessionKey || authValue
 *   data = cpHash || nonceNewer || nonceOlder || sessionAttributes
 *   cpHash = SHA-256(commandCode || name1 || name2 || name3 || cpBytes)
 *
 * Response HMAC verification:
 *   key = sessionKey || authValue
 *   data = rpHash || nonceTPM || nonceCaller || sessionAttributes
 *   rpHash = SHA-256(responseCode || commandCode || rpBytes)
 *
 * Parameter encryption (first TPM2B in command/response):
 *   For AES-CFB:
 *     key = KDFa(sessionKey, "CFB", nonceNewer || nonceOlder, keyBits)
 *     iv  = KDFa(sessionKey, "CFB", nonceNewer || nonceOlder, ivBits)
 *     Note: keyBits come from the sym spec, ivBits = 128 (AES block size)
 *     The "Newer" nonce is from the most recent response for commands,
 *     or from the most recent command for responses.
 */

#include "htpm2_locl.h"
#include "marshal.h"
#include "crypto.h"

/*
 * Compute cpHash = SHA-256(commandCode || name1 || name2 || name3 || cpBytes)
 *
 * commandCode: big-endian uint32
 * names: the Name of each handle in the command (up to 3)
 * cpBytes: command parameters (everything after the handle area)
 */
htpm2_result
htpm2_compute_cp_hash(const htpm2_context ctx,
                      uint32_t command_code,
                      const void *name1, size_t name1_len,
                      const void *name2, size_t name2_len,
                      const void *name3, size_t name3_len,
                      const void *cp_bytes, size_t cp_bytes_len,
                      uint8_t cp_hash[32])
{
    EVP_MD_CTX *mdctx;
    unsigned int len = 32;
    uint8_t cc_buf[4];

    cc_buf[0] = (command_code >> 24) & 0xff;
    cc_buf[1] = (command_code >> 16) & 0xff;
    cc_buf[2] = (command_code >> 8) & 0xff;
    cc_buf[3] = command_code & 0xff;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
        return htpm2_result_ossl(1, "cpHash: alloc");

    if (EVP_DigestInit_ex(mdctx, ctx->md_sha256, NULL) != 1)
        goto err;
    if (EVP_DigestUpdate(mdctx, cc_buf, 4) != 1)
        goto err;
    if (name1 && name1_len > 0)
        if (EVP_DigestUpdate(mdctx, name1, name1_len) != 1)
            goto err;
    if (name2 && name2_len > 0)
        if (EVP_DigestUpdate(mdctx, name2, name2_len) != 1)
            goto err;
    if (name3 && name3_len > 0)
        if (EVP_DigestUpdate(mdctx, name3, name3_len) != 1)
            goto err;
    if (cp_bytes && cp_bytes_len > 0)
        if (EVP_DigestUpdate(mdctx, cp_bytes, cp_bytes_len) != 1)
            goto err;
    if (EVP_DigestFinal_ex(mdctx, cp_hash, &len) != 1)
        goto err;

    EVP_MD_CTX_free(mdctx);
    return HTPM2_OK;

err:
    EVP_MD_CTX_free(mdctx);
    return htpm2_result_ossl(1, "cpHash: digest failed");
}

/*
 * Compute rpHash = SHA-256(responseCode || commandCode || rpBytes)
 */
htpm2_result
htpm2_compute_rp_hash(const htpm2_context ctx,
                      uint32_t response_code,
                      uint32_t command_code,
                      const void *rp_bytes, size_t rp_bytes_len,
                      uint8_t rp_hash[32])
{
    EVP_MD_CTX *mdctx;
    unsigned int len = 32;
    uint8_t buf[8];

    buf[0] = (response_code >> 24) & 0xff;
    buf[1] = (response_code >> 16) & 0xff;
    buf[2] = (response_code >> 8) & 0xff;
    buf[3] = response_code & 0xff;
    buf[4] = (command_code >> 24) & 0xff;
    buf[5] = (command_code >> 16) & 0xff;
    buf[6] = (command_code >> 8) & 0xff;
    buf[7] = command_code & 0xff;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
        return htpm2_result_ossl(1, "rpHash: alloc");

    if (EVP_DigestInit_ex(mdctx, ctx->md_sha256, NULL) != 1 ||
        EVP_DigestUpdate(mdctx, buf, 8) != 1 ||
        (rp_bytes_len > 0 &&
         EVP_DigestUpdate(mdctx, rp_bytes, rp_bytes_len) != 1) ||
        EVP_DigestFinal_ex(mdctx, rp_hash, &len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return htpm2_result_ossl(1, "rpHash: digest failed");
    }

    EVP_MD_CTX_free(mdctx);
    return HTPM2_OK;
}

/*
 * Compute session HMAC.
 *
 * key = sessionKey || authValue  (concatenated)
 * data = pHash || nonceNewer || nonceOlder || sessionAttributes
 *
 * For commands:  nonceNewer = nonceTPM,    nonceOlder = nonceCaller
 * For responses: nonceNewer = nonceCaller, nonceOlder = nonceTPM
 *   (actually reversed: for commands nonceCaller is "newer" since the
 *    caller just generated it; but the TPM spec defines "newer" as the
 *    nonce from the last response, so nonceTPM is newer for commands)
 *
 * Wait, let me get this right from the spec:
 *   Command HMAC: pHash || nonceNewer || nonceOlder || attrs
 *     where nonceNewer = nonceCaller (just generated)
 *           nonceOlder = nonceTPM (from last response/StartAuthSession)
 *   Response HMAC: rpHash || nonceTPM || nonceCaller || attrs
 *     where nonceTPM is the new one from this response
 *           nonceCaller is from the command we just sent
 *
 * Actually the spec says for commands:
 *   HMAC(key, cpHash || nonceCaller || nonceTPM || sessionAttributes)
 * And for responses:
 *   HMAC(key, rpHash || nonceTPM || nonceCaller || sessionAttributes)
 */
htpm2_result
htpm2_compute_session_hmac(const htpm2_context ctx,
                           const uint8_t *session_key, size_t session_key_len,
                           const uint8_t *auth_value, size_t auth_value_len,
                           const uint8_t *p_hash, /* 32 bytes */
                           const uint8_t *nonce_newer, size_t nonce_newer_len,
                           const uint8_t *nonce_older, size_t nonce_older_len,
                           uint8_t session_attrs,
                           uint8_t hmac_out[32], size_t *hmac_out_len)
{
    /*
     * Build the HMAC key: sessionKey || authValue
     * Build the HMAC data: pHash || nonceNewer || nonceOlder || attrs
     */
    uint8_t key[128];  /* sessionKey (<=32) + authValue (<=64) */
    size_t key_len = 0;
    uint8_t data[256];
    size_t data_len = 0;

    if (session_key_len + auth_value_len > sizeof(key))
        return htpm2_result_local(ERANGE, HTPM2_F_SESSION, ERANGE,
                                  "session HMAC: key too long");

    if (session_key && session_key_len > 0) {
        memcpy(key, session_key, session_key_len);
        key_len += session_key_len;
    }
    if (auth_value && auth_value_len > 0) {
        memcpy(key + key_len, auth_value, auth_value_len);
        key_len += auth_value_len;
    }

    /* pHash (32 bytes) */
    memcpy(data, p_hash, 32);
    data_len = 32;

    /* nonceNewer */
    memcpy(data + data_len, nonce_newer, nonce_newer_len);
    data_len += nonce_newer_len;

    /* nonceOlder */
    memcpy(data + data_len, nonce_older, nonce_older_len);
    data_len += nonce_older_len;

    /* sessionAttributes (1 byte) */
    data[data_len++] = session_attrs;

    *hmac_out_len = 32;
    return htpm2_hmac_sha256(ctx, key, key_len, data, data_len,
                             hmac_out, hmac_out_len);
}

/*
 * Marshal a TPMS_AUTH_COMMAND for an HMAC session.
 *
 * Layout:
 *   sessionHandle:    uint32
 *   nonceCaller:      TPM2B_NONCE
 *   sessionAttributes: uint8
 *   hmac:             TPM2B_AUTH (HMAC or password)
 */
htpm2_result
htpm2_marshal_auth_area(const htpm2_context ctx,
                        heim_storage *sp,
                        htpm2_session session,
                        const uint8_t *cp_hash) /* 32 bytes */
{
    uint8_t attrs = 0;
    uint8_t hmac[32];
    size_t hmac_len = 32;
    size_t nonce_caller_len, nonce_tpm_len;
    const uint8_t *nonce_caller, *nonce_tpm;
    htpm2_result r;
    int ret;

    if (session == NULL) {
        /*
         * No session: use password authorization.
         * sessionHandle = TPM_RS_PW (0x40000009)
         * nonce = empty, attrs = continueSession, hmac = empty (no password)
         */
        ret = heim_store_uint32(sp, 0x40000009);  /* TPM_RS_PW */
        if (ret) goto merr;
        ret = htpm2_marshal_tpm2b(sp, NULL, 0);   /* nonce */
        if (ret) goto merr;
        ret = heim_store_uint8(sp, 0x01);          /* continueSession */
        if (ret) goto merr;
        ret = htpm2_marshal_tpm2b(sp, NULL, 0);   /* hmac (empty = no password) */
        if (ret) goto merr;
        return HTPM2_OK;
    }

    /* Build session attributes byte */
    if (session->flags & HTPM2_SESSION_CONTINUE)
        attrs |= 0x01;  /* continueSession */
    if (session->flags & HTPM2_SESSION_DECRYPT)
        attrs |= 0x20;  /* decrypt (caller->TPM param encryption) */
    if (session->flags & HTPM2_SESSION_ENCRYPT)
        attrs |= 0x40;  /* encrypt (TPM->caller param encryption) */

    /* Always set continueSession for now */
    attrs |= 0x01;

    nonce_caller = htpm2_session_get_nonce_caller(session, &nonce_caller_len);
    nonce_tpm = htpm2_session_get_nonce_tpm(session, &nonce_tpm_len);

    /* Compute HMAC */
    r = htpm2_compute_session_hmac(ctx,
                                   session->session_key,
                                   session->session_key_len,
                                   session->bind_auth,
                                   session->bind_auth_len,
                                   cp_hash,
                                   nonce_caller, nonce_caller_len,
                                   nonce_tpm, nonce_tpm_len,
                                   attrs,
                                   hmac, &hmac_len);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "marshal auth area");

    /* Marshal */
    ret = heim_store_uint32(sp, htpm2_session_get_handle(session));
    if (ret) goto merr;
    ret = htpm2_marshal_tpm2b(sp, nonce_caller, nonce_caller_len);
    if (ret) goto merr;
    ret = heim_store_uint8(sp, attrs);
    if (ret) goto merr;
    ret = htpm2_marshal_tpm2b(sp, hmac, hmac_len);
    if (ret) goto merr;

    return HTPM2_OK;

merr:
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "marshal auth area");
}
