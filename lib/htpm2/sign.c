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
 * TPM2_Sign and TPM2_VerifySignature.
 *
 * TPM2_Sign command (with session):
 *   keyHandle:   uint32 (handle of signing key -- requires USER auth)
 *   digest:      TPM2B_DIGEST (hash to sign)
 *   inScheme:    TPMT_SIG_SCHEME (TPM_ALG_NULL = use key's default scheme)
 *   validation:  TPMT_TK_HASHCHECK (can be NULL ticket)
 *
 * TPM2_Sign response:
 *   signature:   TPMT_SIGNATURE (algorithm + signature data)
 *
 * TPM2_VerifySignature command (no auth needed):
 *   keyHandle:   uint32
 *   digest:      TPM2B_DIGEST
 *   signature:   TPMT_SIGNATURE
 *
 * TPM2_VerifySignature response:
 *   validation:  TPMT_TK_VERIFIED
 */

#include "htpm2_locl.h"
#include "marshal.h"

htpm2_result
htpm2_sign(const htpm2_context ctx,
           htpm2_transport tp,
           htpm2_result prior,
           htpm2_session auth_session,
           htpm2_object sign_key,
           const void *digest, size_t digest_len,
           void **signature, size_t *signature_len)
{
    heim_storage *param_sp, *rsp;
    uint32_t rc, key_handle;
    uint32_t handles[1];
    void *param_data = NULL, *sig_data = NULL;
    size_t param_len = 0;
    htpm2_result r;
    int ret;

    if (prior.code)
        return prior;

    if (sign_key == NULL || digest == NULL)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "Sign: NULL argument");

    *signature = NULL;
    *signature_len = 0;

    key_handle = htpm2_object_get_handle(sign_key);
    handles[0] = key_handle;

    /* Marshal parameters */
    param_sp = heim_storage_emem();
    if (param_sp == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM, "Sign: alloc");

    /* digest (TPM2B_DIGEST) */
    ret = htpm2_marshal_tpm2b(param_sp, digest, digest_len);
    if (ret) goto marshal_err;

    /* inScheme = TPM_ALG_NULL (use key's default) */
    ret = heim_store_uint16(param_sp, TPM2_ALG_NULL);
    if (ret) goto marshal_err;

    /* validation = TPMT_TK_HASHCHECK { tag=0x8024, hierarchy=TPM_RH_NULL, digest=empty } */
    ret = heim_store_uint16(param_sp, 0x8024);  /* TPM_ST_HASHCHECK */
    if (ret) goto marshal_err;
    ret = heim_store_uint32(param_sp, 0x40000007);  /* TPM_RH_NULL */
    if (ret) goto marshal_err;
    ret = htpm2_marshal_tpm2b(param_sp, NULL, 0);   /* empty digest */
    if (ret) goto marshal_err;

    ret = heim_storage_to_data(param_sp, &param_data, &param_len);
    heim_storage_free(param_sp);
    param_sp = NULL;
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "Sign: param to_data");

    r = htpm2_command_execute_with_auth(ctx, tp, TPM2_CC_Sign,
                                        handles, 1, auth_session,
                                        param_data, param_len,
                                        &rsp, &rc);
    free(param_data);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "Sign");

    /*
     * Response: TPMT_SIGNATURE
     *   sigAlg (uint16) + scheme-specific data
     *
     * We return the raw bytes from the current position to the end
     * of the parameter area as the signature blob.  The caller (or
     * a future helper) can parse the TPMT_SIGNATURE structure.
     */
    {
        off_t pos = heim_storage_seek(rsp, 0, SEEK_CUR);
        off_t end = heim_storage_seek(rsp, 0, SEEK_END);
        size_t sig_bytes;

        /* The response also has an auth area at the end; for now we
         * conservatively read everything.  TODO: use parameterSize to
         * know exactly where params end and auth begins. */
        sig_bytes = end - pos;
        if (sig_bytes > 0) {
            sig_data = malloc(sig_bytes);
            if (sig_data == NULL) {
                heim_storage_free(rsp);
                return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                          "Sign: alloc signature");
            }
            heim_storage_seek(rsp, pos, SEEK_SET);
            ret = heim_ret_bytes(rsp, sig_data, sig_bytes);
            if (ret) {
                free(sig_data);
                heim_storage_free(rsp);
                return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                          "Sign: read signature");
            }
        }
        *signature = sig_data;
        *signature_len = sig_bytes;
    }

    heim_storage_free(rsp);
    return HTPM2_OK;

marshal_err:
    heim_storage_free(param_sp);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret, "Sign: marshal");
}

htpm2_result
htpm2_verify_signature(const htpm2_context ctx,
                       htpm2_transport tp,
                       htpm2_result prior,
                       htpm2_object verify_key,
                       const void *digest, size_t digest_len,
                       const void *signature, size_t signature_len,
                       void **validation_ticket,
                       size_t *validation_ticket_len)
{
    heim_storage *cmd, *rsp;
    uint32_t rc;
    htpm2_result r;
    int ret;

    if (prior.code)
        return prior;

    if (verify_key == NULL || digest == NULL || signature == NULL)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "VerifySignature: NULL argument");

    if (validation_ticket)
        *validation_ticket = NULL;
    if (validation_ticket_len)
        *validation_ticket_len = 0;

    /*
     * VerifySignature doesn't require authorization (it's a public
     * operation), so we use TPM_ST_NO_SESSIONS.
     */
    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "VerifySignature: alloc");

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS,
                                   TPM2_CC_VerifySignature);
    if (ret) goto marshal_err;

    /* keyHandle */
    ret = heim_store_uint32(cmd, htpm2_object_get_handle(verify_key));
    if (ret) goto marshal_err;

    /* digest (TPM2B_DIGEST) */
    ret = htpm2_marshal_tpm2b(cmd, digest, digest_len);
    if (ret) goto marshal_err;

    /* signature (TPMT_SIGNATURE -- raw bytes) */
    ret = heim_store_bytes(cmd, signature, signature_len);
    if (ret) goto marshal_err;

    r = htpm2_command_execute(ctx, tp, cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "VerifySignature");

    /* Response: TPMT_TK_VERIFIED -- read remaining bytes as ticket */
    if (validation_ticket && validation_ticket_len) {
        off_t pos = heim_storage_seek(rsp, 0, SEEK_CUR);
        off_t end = heim_storage_seek(rsp, 0, SEEK_END);
        size_t ticket_bytes = end - pos;

        if (ticket_bytes > 0) {
            *validation_ticket = malloc(ticket_bytes);
            if (*validation_ticket) {
                heim_storage_seek(rsp, pos, SEEK_SET);
                heim_ret_bytes(rsp, *validation_ticket, ticket_bytes);
                *validation_ticket_len = ticket_bytes;
            }
        }
    }

    heim_storage_free(rsp);
    return HTPM2_OK;

marshal_err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "VerifySignature: marshal");
}
