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
 * TPM 2.0 command/response marshalling.
 * Uses heim_storage for big-endian serialization.
 */

#include "htpm2_locl.h"
#include "marshal.h"
#include "crypto.h"

int
htpm2_marshal_tpm2b(heim_storage *sp, const void *data, size_t len)
{
    int ret;

    if (len > UINT16_MAX)
        return ERANGE;
    ret = heim_store_uint16(sp, (uint16_t)len);
    if (ret)
        return ret;
    if (len > 0 && data != NULL)
        return heim_store_bytes(sp, data, len);
    if (len > 0 && data == NULL) {
        /* Write zero bytes */
        unsigned char zero[256];
        size_t done = 0;

        memset(zero, 0, sizeof(zero));
        while (done < len) {
            size_t chunk = len - done;
            if (chunk > sizeof(zero))
                chunk = sizeof(zero);
            ret = heim_store_bytes(sp, zero, chunk);
            if (ret)
                return ret;
            done += chunk;
        }
    }
    return 0;
}

int
htpm2_unmarshal_tpm2b(heim_storage *sp, void **data, uint16_t *len)
{
    uint16_t size;
    void *buf;
    int ret;

    *data = NULL;
    *len = 0;

    ret = heim_ret_uint16(sp, &size);
    if (ret)
        return ret;

    if (size == 0) {
        *len = 0;
        return 0;
    }

    buf = malloc(size);
    if (buf == NULL)
        return ENOMEM;

    ret = heim_ret_bytes(sp, buf, size);
    if (ret) {
        free(buf);
        return ret;
    }

    *data = buf;
    *len = size;
    return 0;
}

int
htpm2_marshal_cmd_header(heim_storage *sp, uint16_t tag, uint32_t cc)
{
    int ret;

    ret = heim_store_uint16(sp, tag);
    if (ret) return ret;
    /* Size placeholder -- will be fixed up later */
    ret = heim_store_uint32(sp, 0);
    if (ret) return ret;
    ret = heim_store_uint32(sp, cc);
    return ret;
}

int
htpm2_marshal_fixup_size(heim_storage *sp)
{
    off_t end, saved;
    uint32_t size;
    int ret;

    saved = heim_storage_seek(sp, 0, SEEK_CUR);
    end = saved;
    size = (uint32_t)end;

    /* Seek to offset 2 (after the tag) to patch the size field */
    heim_storage_seek(sp, 2, SEEK_SET);
    ret = heim_store_uint32(sp, size);
    heim_storage_seek(sp, end, SEEK_SET);
    return ret;
}

int
htpm2_unmarshal_rsp_header(heim_storage *sp, uint16_t *tag,
                           uint32_t *size, uint32_t *rc)
{
    int ret;

    ret = heim_ret_uint16(sp, tag);
    if (ret) return ret;
    ret = heim_ret_uint32(sp, size);
    if (ret) return ret;
    ret = heim_ret_uint32(sp, rc);
    return ret;
}

/*
 * Internal transport send_recv -- we need access to the transport internals
 * which are defined in transport.c.  For now we declare the function pointer
 * approach: the transport ops have a send_recv that we invoke.
 *
 * Actually, the transport structure and ops are internal to transport.c
 * but we need to call send_recv from here.  We expose a minimal internal
 * function in the transport.
 */

/* Declared in htpm2_locl.h or forward-declared here */
htpm2_result htpm2_transport_send_recv(htpm2_transport tp,
                                       const void *cmd, size_t cmd_len,
                                       void *rsp, size_t *rsp_len);

htpm2_result
htpm2_command_execute(const htpm2_context ctx,
                      htpm2_transport tp,
                      heim_storage *cmd_sp,
                      heim_storage **rsp_sp,
                      uint32_t *rc)
{
    void *cmd_data = NULL;
    size_t cmd_len = 0;
    unsigned char rsp_buf[4096];
    size_t rsp_len = sizeof(rsp_buf);
    heim_storage *rsp;
    uint16_t tag;
    uint32_t size;
    htpm2_result r;
    int ret;

    *rsp_sp = NULL;
    *rc = 0;

    /* Fix up command size */
    ret = htpm2_marshal_fixup_size(cmd_sp);
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "command: fixup_size failed");

    /* Extract command bytes */
    ret = heim_storage_to_data(cmd_sp, &cmd_data, &cmd_len);
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "command: storage_to_data failed");

    /* Send and receive */
    r = htpm2_transport_send_recv(tp, cmd_data, cmd_len, rsp_buf, &rsp_len);
    free(cmd_data);
    if (htpm2_is_err(r))
        return r;

    /* Parse response into a new storage */
    rsp = heim_storage_from_readonly_mem(rsp_buf, rsp_len);
    if (rsp == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "command: alloc response storage");

    ret = htpm2_unmarshal_rsp_header(rsp, &tag, &size, rc);
    if (ret) {
        heim_storage_free(rsp);
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "command: unmarshal response header");
    }

    if (*rc != TPM2_RC_SUCCESS) {
        heim_storage_free(rsp);
        return htpm2_result_tpm(*rc, "TPM error 0x%08x", *rc);
    }

    *rsp_sp = rsp;
    return HTPM2_OK;
}

/*
 * Build and execute a command with a single authorization session.
 *
 * Command layout for TPM_ST_SESSIONS:
 *   tag (uint16) = TPM_ST_SESSIONS
 *   commandSize (uint32)
 *   commandCode (uint32)
 *   handles (uint32 each)
 *   authorizationSize (uint32)
 *   authArea (TPMS_AUTH_COMMAND)
 *   parameters (command-specific)
 *
 * Response layout for TPM_ST_SESSIONS:
 *   tag (uint16) = TPM_ST_SESSIONS
 *   responseSize (uint32)
 *   responseCode (uint32)
 *   [handle if command creates one -- NOT for most commands]
 *   parameterSize (uint32)
 *   parameters
 *   authArea (TPMS_AUTH_RESPONSE)
 */
htpm2_result
htpm2_command_execute_with_auth(
    const htpm2_context ctx,
    htpm2_transport tp,
    uint32_t command_code,
    const uint32_t *handles, size_t num_handles,
    htpm2_session session,
    const void *param_bytes, size_t param_bytes_len,
    heim_storage **rsp_sp,
    uint32_t *rc)
{
    heim_storage *cmd, *auth_sp, *rsp;
    void *auth_data = NULL;
    size_t auth_len = 0;
    uint8_t cp_hash[32];
    uint32_t param_size;
    htpm2_result r;
    int ret;
    size_t i;

    *rsp_sp = NULL;
    *rc = 0;

    /*
     * Compute cpHash for the HMAC.
     * cpHash = SHA-256(commandCode || name1 || name2 || ... || cpBytes)
     *
     * For now we pass handle values as "names" for handles that don't
     * have a cached Name.  This is correct for hierarchy handles
     * (their name is just the handle value as 4 bytes).
     * For loaded objects, we should use the object's Name.
     *
     * TODO: use actual object Names from htpm2_object.
     */
    {
        uint8_t name_bufs[3][4];
        const void *names[3] = {NULL, NULL, NULL};
        size_t name_lens[3] = {0, 0, 0};

        for (i = 0; i < num_handles && i < 3; i++) {
            name_bufs[i][0] = (handles[i] >> 24) & 0xff;
            name_bufs[i][1] = (handles[i] >> 16) & 0xff;
            name_bufs[i][2] = (handles[i] >> 8) & 0xff;
            name_bufs[i][3] = handles[i] & 0xff;
            names[i] = name_bufs[i];
            name_lens[i] = 4;
        }

        r = htpm2_compute_cp_hash(ctx, command_code,
                                  names[0], name_lens[0],
                                  names[1], name_lens[1],
                                  names[2], name_lens[2],
                                  param_bytes, param_bytes_len,
                                  cp_hash);
        if (htpm2_is_err(r))
            return htpm2_result_prepend(r, "command_with_auth: cpHash");
    }

    /* Marshal auth area */
    auth_sp = heim_storage_emem();
    if (auth_sp == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "command_with_auth: alloc auth");

    r = htpm2_marshal_auth_area(ctx, auth_sp, session, cp_hash);
    if (htpm2_is_err(r)) {
        heim_storage_free(auth_sp);
        return r;
    }

    ret = heim_storage_to_data(auth_sp, &auth_data, &auth_len);
    heim_storage_free(auth_sp);
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "command_with_auth: auth to_data");

    /* Build complete command */
    cmd = heim_storage_emem();
    if (cmd == NULL) {
        free(auth_data);
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "command_with_auth: alloc cmd");
    }

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_SESSIONS, command_code);
    if (ret) goto marshal_err;

    /* Handles */
    for (i = 0; i < num_handles; i++) {
        ret = heim_store_uint32(cmd, handles[i]);
        if (ret) goto marshal_err;
    }

    /* authorizationSize + auth area */
    ret = heim_store_uint32(cmd, (uint32_t)auth_len);
    if (ret) goto marshal_err;
    ret = heim_store_bytes(cmd, auth_data, auth_len);
    if (ret) goto marshal_err;
    free(auth_data);
    auth_data = NULL;

    /* Parameters -- possibly encrypt the first TPM2B */
    if (param_bytes_len > 0) {
        unsigned int sflags = session ? htpm2_session_get_flags(session) : 0;
        size_t sk_len = 0;
        const uint8_t *sk = session ?
            htpm2_session_get_session_key(session, &sk_len) : NULL;

        if ((sflags & HTPM2_SESSION_DECRYPT) && sk_len > 0 &&
            param_bytes_len >= 2) {
            /*
             * Command parameter encryption (decrypt attribute):
             * Encrypt the first TPM2B's data in-place.
             *
             * The first TPM2B starts at offset 0 in param_bytes:
             *   size (uint16) + data (size bytes)
             *
             * We encrypt only the data portion, leaving the size prefix
             * as plaintext (the TPM needs it to know how many bytes to
             * decrypt).
             */
            const uint8_t *pb = param_bytes;
            uint16_t tpm2b_size = (uint16_t)(pb[0] << 8 | pb[1]);

            if (tpm2b_size > 0 && 2 + tpm2b_size <= param_bytes_len) {
                uint8_t enc_key[16], iv[16];
                size_t nc_len, nt_len;
                const uint8_t *nc = htpm2_session_get_nonce_caller(
                    session, &nc_len);
                const uint8_t *nt = htpm2_session_get_nonce_tpm(
                    session, &nt_len);
                uint8_t *enc_buf;

                r = htpm2_derive_param_key(ctx, sk, sk_len,
                                           nc, nc_len, nt, nt_len,
                                           128, enc_key, 16, iv, 16);
                if (htpm2_is_err(r)) {
                    free(auth_data);
                    heim_storage_free(cmd);
                    return htpm2_result_prepend(r,
                        "command_with_auth: derive cmd encrypt key");
                }

                /* Encrypt into a temporary buffer */
                enc_buf = malloc(tpm2b_size);
                if (enc_buf == NULL) {
                    free(auth_data);
                    heim_storage_free(cmd);
                    return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                        "command_with_auth: alloc encrypt buf");
                }

                r = htpm2_aes_cfb_encrypt(ctx, enc_key, 16, iv, 16,
                    (const uint8_t *)param_bytes + 2, tpm2b_size, enc_buf);
                memset(enc_key, 0, sizeof(enc_key));
                memset(iv, 0, sizeof(iv));

                if (htpm2_is_err(r)) {
                    free(enc_buf);
                    free(auth_data);
                    heim_storage_free(cmd);
                    return htpm2_result_prepend(r,
                        "command_with_auth: encrypt first param");
                }

                /* Write: size prefix (plaintext) + encrypted data + rest */
                ret = heim_store_bytes(cmd, param_bytes, 2);
                if (ret == 0)
                    ret = heim_store_bytes(cmd, enc_buf, tpm2b_size);
                if (ret == 0 && param_bytes_len > 2 + tpm2b_size)
                    ret = heim_store_bytes(cmd,
                        (const uint8_t *)param_bytes + 2 + tpm2b_size,
                        param_bytes_len - 2 - tpm2b_size);
                free(enc_buf);
                if (ret) goto marshal_err;
            } else {
                ret = heim_store_bytes(cmd, param_bytes, param_bytes_len);
                if (ret) goto marshal_err;
            }
        } else {
            ret = heim_store_bytes(cmd, param_bytes, param_bytes_len);
            if (ret) goto marshal_err;
        }
    }

    /* Execute */
    r = htpm2_command_execute(ctx, tp, cmd, &rsp, rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return r;

    /*
     * For TPM_ST_SESSIONS responses, after the 10-byte header comes
     * parameterSize (uint32), then parameters, then auth area.
     * We read parameterSize so the caller knows where params end.
     */
    ret = heim_ret_uint32(rsp, &param_size);
    if (ret) {
        heim_storage_free(rsp);
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "command_with_auth: read parameterSize");
    }

    /*
     * Response parameter decryption (encrypt attribute).
     *
     * If the session has the encrypt flag set, the TPM encrypted the
     * first TPM2B in the response parameters.  We decrypt it in-place
     * before HMAC verification (the HMAC is over plaintext params).
     */
    if (session && (htpm2_session_get_flags(session) & HTPM2_SESSION_ENCRYPT)) {
        size_t sk_len = 0;
        const uint8_t *sk = htpm2_session_get_session_key(session, &sk_len);

        if (sk_len > 0 && param_size >= 2) {
            off_t param_start = heim_storage_seek(rsp, 0, SEEK_CUR);
            uint16_t tpm2b_size;

            ret = heim_ret_uint16(rsp, &tpm2b_size);
            if (ret == 0 && tpm2b_size > 0 && tpm2b_size <= param_size - 2) {
                uint8_t enc_key[16], iv[16];
                size_t nc_len, nt_len;
                uint8_t *enc_data, *dec_data;

                /*
                 * For response decryption, the nonces are:
                 *   nonceNewer = nonceTPM (from the response auth area)
                 *   nonceOlder = nonceCaller
                 *
                 * But we haven't parsed the response auth area yet to get
                 * the new nonceTPM.  For response encryption, the TPM uses
                 * the *current* nonceTPM (which we already know from the
                 * previous exchange or StartAuthSession).
                 *
                 * Actually: the TPM generates a new nonceTPM for the
                 * response and uses it for encryption.  We need to peek
                 * ahead to get it.  Let's parse the auth area nonce first.
                 */
                off_t saved = heim_storage_seek(rsp, 0, SEEK_CUR);
                off_t auth_area_start = param_start + param_size;
                void *peek_nonce = NULL;
                uint16_t peek_nonce_len = 0;

                heim_storage_seek(rsp, auth_area_start, SEEK_SET);
                htpm2_unmarshal_tpm2b(rsp, &peek_nonce, &peek_nonce_len);
                heim_storage_seek(rsp, saved, SEEK_SET);

                const uint8_t *nc = htpm2_session_get_nonce_caller(
                    session, &nc_len);
                nt_len = peek_nonce_len;

                r = htpm2_derive_param_key(ctx, sk, sk_len,
                                           peek_nonce, nt_len,
                                           nc, nc_len,
                                           128, enc_key, 16, iv, 16);
                free(peek_nonce);

                if (htpm2_is_err(r)) {
                    heim_storage_free(rsp);
                    return htpm2_result_prepend(r,
                        "command_with_auth: derive rsp decrypt key");
                }

                /* Read encrypted data */
                enc_data = malloc(tpm2b_size);
                dec_data = malloc(tpm2b_size);
                if (!enc_data || !dec_data) {
                    free(enc_data);
                    free(dec_data);
                    heim_storage_free(rsp);
                    return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                        "command_with_auth: alloc decrypt buf");
                }

                ret = heim_ret_bytes(rsp, enc_data, tpm2b_size);
                if (ret) {
                    free(enc_data);
                    free(dec_data);
                    heim_storage_free(rsp);
                    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                        "command_with_auth: read encrypted param");
                }

                r = htpm2_aes_cfb_decrypt(ctx, enc_key, 16, iv, 16,
                                           enc_data, tpm2b_size, dec_data);
                memset(enc_key, 0, sizeof(enc_key));
                memset(iv, 0, sizeof(iv));
                free(enc_data);

                if (htpm2_is_err(r)) {
                    free(dec_data);
                    heim_storage_free(rsp);
                    return htpm2_result_prepend(r,
                        "command_with_auth: decrypt response param");
                }

                /*
                 * Replace the response storage with one containing
                 * the decrypted parameter.  We need to reconstruct:
                 *   [already consumed: header(10) + parameterSize(4)]
                 *   TPM2B_size(2, plaintext) + decrypted_data + rest_of_params
                 *   + auth_area
                 *
                 * Simplest approach: build a new storage with everything
                 * patched.  But that's expensive.  Instead, we create a
                 * new emem storage with just the params portion replaced.
                 */
                {
                    /* Read remaining params and auth area */
                    off_t cur = heim_storage_seek(rsp, 0, SEEK_CUR);
                    off_t end = heim_storage_seek(rsp, 0, SEEK_END);
                    size_t rest_len = end - cur;
                    void *rest = NULL;
                    heim_storage *new_rsp;

                    if (rest_len > 0) {
                        rest = malloc(rest_len);
                        if (rest) {
                            heim_storage_seek(rsp, cur, SEEK_SET);
                            heim_ret_bytes(rsp, rest, rest_len);
                        }
                    }

                    heim_storage_free(rsp);

                    new_rsp = heim_storage_emem();
                    if (new_rsp == NULL) {
                        free(dec_data);
                        free(rest);
                        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL,
                            ENOMEM, "command_with_auth: alloc new rsp");
                    }

                    /* Write decrypted first TPM2B */
                    heim_store_uint16(new_rsp, tpm2b_size);
                    heim_store_bytes(new_rsp, dec_data, tpm2b_size);
                    free(dec_data);

                    /* Write remaining params + auth area */
                    if (rest && rest_len > 0)
                        heim_store_bytes(new_rsp, rest, rest_len);
                    free(rest);

                    /* Seek back to start */
                    heim_storage_seek(new_rsp, 0, SEEK_SET);
                    rsp = new_rsp;
                }
            } else {
                /* No data to decrypt, seek back past the uint16 we read */
                heim_storage_seek(rsp, param_start, SEEK_SET);
            }
        }
    }

    /*
     * Parse response auth area (after parameterSize bytes of params).
     *
     * TPMS_AUTH_RESPONSE:
     *   nonce:            TPM2B_NONCE
     *   sessionAttributes: uint8
     *   hmac:             TPM2B_AUTH
     *
     * We need to:
     *   1. Record current position (start of params)
     *   2. Skip parameterSize bytes to reach auth area
     *   3. Parse nonce, attrs, hmac
     *   4. Verify response HMAC
     *   5. Update session's nonceTPM
     *   6. Seek back to start of params for the caller
     */
    if (session && htpm2_session_get_handle(session) != 0) {
        off_t param_start = heim_storage_seek(rsp, 0, SEEK_CUR);
        void *rsp_nonce_data = NULL;
        uint16_t rsp_nonce_size;
        uint8_t rsp_attrs;
        void *rsp_hmac_data = NULL;
        uint16_t rsp_hmac_size;

        /* Skip to auth area */
        heim_storage_seek(rsp, param_start + param_size, SEEK_SET);

        /* Parse TPMS_AUTH_RESPONSE */
        ret = htpm2_unmarshal_tpm2b(rsp, &rsp_nonce_data, &rsp_nonce_size);
        if (ret == 0)
            ret = heim_ret_uint8(rsp, &rsp_attrs);
        if (ret == 0)
            ret = htpm2_unmarshal_tpm2b(rsp, &rsp_hmac_data, &rsp_hmac_size);

        if (ret) {
            free(rsp_nonce_data);
            free(rsp_hmac_data);
            heim_storage_free(rsp);
            return htpm2_result_local(ret, HTPM2_F_SESSION, ret,
                                      "command_with_auth: parse response auth");
        }

        /* Update session nonceTPM */
        if (rsp_nonce_data && rsp_nonce_size > 0)
            htpm2_session_set_nonce_tpm(session, rsp_nonce_data, rsp_nonce_size);

        /* Verify response HMAC if the session has a key */
        {
            size_t sk_len;
            const uint8_t *sk = htpm2_session_get_session_key(session, &sk_len);
            const uint8_t *ba;
            size_t ba_len;
            htpm2_session_get_bind_auth(session, &ba, &ba_len);

            if (sk_len > 0 || ba_len > 0) {
                uint8_t rp_hash[32];
                uint8_t expected_hmac[32];
                size_t expected_hmac_len = 32;
                size_t rp_bytes_len;

                /* Read the param bytes for rpHash */
                rp_bytes_len = param_size;
                void *rp_buf = NULL;
                if (rp_bytes_len > 0) {
                    rp_buf = malloc(rp_bytes_len);
                    if (rp_buf) {
                        heim_storage_seek(rsp, param_start, SEEK_SET);
                        heim_ret_bytes(rsp, rp_buf, rp_bytes_len);
                    }
                }

                r = htpm2_compute_rp_hash(ctx, TPM2_RC_SUCCESS,
                                          command_code,
                                          rp_buf, rp_bytes_len,
                                          rp_hash);
                free(rp_buf);

                if (htpm2_is_ok(r)) {
                    size_t nc_len, nt_len;
                    const uint8_t *nc = htpm2_session_get_nonce_caller(
                        session, &nc_len);
                    const uint8_t *nt = rsp_nonce_data;
                    nt_len = rsp_nonce_size;

                    r = htpm2_compute_session_hmac(
                        ctx, sk, sk_len, ba, ba_len,
                        rp_hash,
                        nt, nt_len,       /* nonceTPM (newer for response) */
                        nc, nc_len,       /* nonceCaller (older for response) */
                        rsp_attrs,
                        expected_hmac, &expected_hmac_len);
                }

                if (htpm2_is_ok(r)) {
                    if (rsp_hmac_size != expected_hmac_len ||
                        !rsp_hmac_data ||
                        memcmp(rsp_hmac_data, expected_hmac,
                               expected_hmac_len) != 0) {
                        free(rsp_nonce_data);
                        free(rsp_hmac_data);
                        heim_storage_free(rsp);
                        return htpm2_result_local(
                            EACCES, HTPM2_F_SESSION, EACCES,
                            "command_with_auth: response HMAC verification failed");
                    }
                }

                if (htpm2_is_err(r)) {
                    free(rsp_nonce_data);
                    free(rsp_hmac_data);
                    heim_storage_free(rsp);
                    return htpm2_result_prepend(r, "response HMAC verify");
                }
            }
        }

        free(rsp_nonce_data);
        free(rsp_hmac_data);

        /* Seek back to start of params for the caller */
        heim_storage_seek(rsp, param_start, SEEK_SET);

        /* Refresh caller nonce for next command */
        htpm2_session_refresh_nonce_caller(ctx, session);
    }

    *rsp_sp = rsp;
    return HTPM2_OK;

marshal_err:
    free(auth_data);
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "command_with_auth: marshal");
}

/*
 * Multi-session variant.  Builds auth area with one TPMS_AUTH_COMMAND
 * per session.  For now, only the first session gets full HMAC/encrypt
 * treatment; additional sessions use password auth.
 *
 * TODO: full HMAC + response verification for all sessions.
 */
htpm2_result
htpm2_command_execute_with_auths(
    const htpm2_context ctx,
    htpm2_transport tp,
    uint32_t command_code,
    const uint32_t *handles, size_t num_handles,
    htpm2_session *sessions, size_t num_sessions,
    const void *param_bytes, size_t param_bytes_len,
    heim_storage **rsp_sp,
    uint32_t *rc)
{
    heim_storage *cmd, *auth_sp, *rsp;
    void *auth_data = NULL;
    size_t auth_len = 0;
    uint8_t cp_hash[32];
    uint32_t param_size;
    htpm2_result r;
    int ret;
    size_t i;

    *rsp_sp = NULL;
    *rc = 0;

    /* Compute cpHash (same as single-session) */
    {
        uint8_t name_bufs[3][4];
        const void *names[3] = {NULL, NULL, NULL};
        size_t name_lens[3] = {0, 0, 0};

        for (i = 0; i < num_handles && i < 3; i++) {
            name_bufs[i][0] = (handles[i] >> 24) & 0xff;
            name_bufs[i][1] = (handles[i] >> 16) & 0xff;
            name_bufs[i][2] = (handles[i] >> 8) & 0xff;
            name_bufs[i][3] = handles[i] & 0xff;
            names[i] = name_bufs[i];
            name_lens[i] = 4;
        }

        r = htpm2_compute_cp_hash(ctx, command_code,
                                  names[0], name_lens[0],
                                  names[1], name_lens[1],
                                  names[2], name_lens[2],
                                  param_bytes, param_bytes_len,
                                  cp_hash);
        if (htpm2_is_err(r))
            return htpm2_result_prepend(r, "command_with_auths: cpHash");
    }

    /* Marshal auth area with multiple sessions */
    auth_sp = heim_storage_emem();
    if (auth_sp == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "command_with_auths: alloc auth");

    for (i = 0; i < num_sessions; i++) {
        r = htpm2_marshal_auth_area(ctx, auth_sp,
                                    sessions ? sessions[i] : NULL,
                                    cp_hash);
        if (htpm2_is_err(r)) {
            heim_storage_free(auth_sp);
            return r;
        }
    }

    ret = heim_storage_to_data(auth_sp, &auth_data, &auth_len);
    heim_storage_free(auth_sp);
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "command_with_auths: auth to_data");

    /* Build command */
    cmd = heim_storage_emem();
    if (cmd == NULL) {
        free(auth_data);
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "command_with_auths: alloc cmd");
    }

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_SESSIONS, command_code);
    if (ret) goto marshal_err;

    for (i = 0; i < num_handles; i++) {
        ret = heim_store_uint32(cmd, handles[i]);
        if (ret) goto marshal_err;
    }

    ret = heim_store_uint32(cmd, (uint32_t)auth_len);
    if (ret) goto marshal_err;
    ret = heim_store_bytes(cmd, auth_data, auth_len);
    if (ret) goto marshal_err;
    free(auth_data);
    auth_data = NULL;

    if (param_bytes_len > 0) {
        ret = heim_store_bytes(cmd, param_bytes, param_bytes_len);
        if (ret) goto marshal_err;
    }

    r = htpm2_command_execute(ctx, tp, cmd, &rsp, rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return r;

    /* Read parameterSize */
    ret = heim_ret_uint32(rsp, &param_size);
    if (ret) {
        heim_storage_free(rsp);
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "command_with_auths: read parameterSize");
    }

    /* TODO: parse and verify response auth area for each session */

    *rsp_sp = rsp;
    return HTPM2_OK;

marshal_err:
    free(auth_data);
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "command_with_auths: marshal");
}
