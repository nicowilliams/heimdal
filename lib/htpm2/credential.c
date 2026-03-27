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
 * TPM2_ActivateCredential.
 *
 * This is the TPM-side counterpart of MakeCredential.  The TPM decrypts
 * the credential blob using the EK and verifies it's bound to the AK's
 * name.
 *
 * Command (with sessions -- needs auth for both activateHandle and keyHandle):
 *   activateHandle: uint32 (AK handle -- needs USER auth)
 *   keyHandle:      uint32 (EK handle -- needs ADMIN auth, usually policy)
 *   credentialBlob: TPM2B_ID_OBJECT
 *   secret:         TPM2B_ENCRYPTED_SECRET
 *
 * Response:
 *   certInfo:       TPM2B_DIGEST (the decrypted credential)
 *
 * The standard EK requires PolicySecret(ENDORSEMENT) for authorization.
 * The AK typically requires USER auth (password or HMAC session).
 *
 * This command is complex because it requires TWO authorization sessions:
 * one for the AK and one for the EK.  For now we support password auth
 * on both, which works when:
 * - The AK has no authValue (empty password), and
 * - The EK uses PolicySecret(ENDORSEMENT) with empty endorsement password
 *
 * TODO: proper dual-session support.
 */

#include "htpm2_locl.h"
#include "marshal.h"

htpm2_result
htpm2_activate_credential(const htpm2_context ctx,
                          htpm2_transport tp,
                          htpm2_result prior,
                          htpm2_session auth_session_ak,
                          htpm2_session auth_session_ek,
                          htpm2_object activate_key,
                          htpm2_object key_handle,
                          const void *credential_blob,
                          size_t credential_blob_len,
                          const void *encrypted_secret,
                          size_t encrypted_secret_len,
                          void **credential_out,
                          size_t *credential_out_len)
{
    heim_storage *cmd, *rsp;
    heim_storage *auth_sp;
    void *auth_data = NULL;
    size_t auth_len = 0;
    uint32_t rc;
    uint32_t ak_handle, ek_handle;
    uint16_t rsp_tag;
    uint32_t rsp_size, param_size;
    void *cred_data = NULL;
    uint16_t cred_size;
    htpm2_result r;
    int ret;

    if (prior.code)
        return prior;

    if (activate_key == NULL || key_handle == NULL ||
        credential_blob == NULL || encrypted_secret == NULL)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "ActivateCredential: NULL argument");

    *credential_out = NULL;
    *credential_out_len = 0;

    ak_handle = htpm2_object_get_handle(activate_key);
    ek_handle = htpm2_object_get_handle(key_handle);

    /*
     * Build command with two auth sessions.
     * For now: both use password auth (TPM_RS_PW).
     */
    auth_sp = heim_storage_emem();
    if (auth_sp == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "ActivateCredential: alloc auth");

    /* Auth area 1: for activateHandle (AK) -- password auth */
    (void)auth_session_ak;
    ret = heim_store_uint32(auth_sp, 0x40000009);  /* TPM_RS_PW */
    if (ret) goto auth_err;
    ret = htpm2_marshal_tpm2b(auth_sp, NULL, 0);   /* nonce */
    if (ret) goto auth_err;
    ret = heim_store_uint8(auth_sp, 0x01);          /* continueSession */
    if (ret) goto auth_err;
    ret = htpm2_marshal_tpm2b(auth_sp, NULL, 0);   /* hmac (empty password) */
    if (ret) goto auth_err;

    /* Auth area 2: for keyHandle (EK) -- password auth */
    (void)auth_session_ek;
    ret = heim_store_uint32(auth_sp, 0x40000009);  /* TPM_RS_PW */
    if (ret) goto auth_err;
    ret = htpm2_marshal_tpm2b(auth_sp, NULL, 0);
    if (ret) goto auth_err;
    ret = heim_store_uint8(auth_sp, 0x01);
    if (ret) goto auth_err;
    ret = htpm2_marshal_tpm2b(auth_sp, NULL, 0);
    if (ret) goto auth_err;

    ret = heim_storage_to_data(auth_sp, &auth_data, &auth_len);
    heim_storage_free(auth_sp);
    auth_sp = NULL;
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "ActivateCredential: auth to_data");

    /* Build command */
    cmd = heim_storage_emem();
    if (cmd == NULL) {
        free(auth_data);
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "ActivateCredential: alloc cmd");
    }

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_SESSIONS,
                                   TPM2_CC_ActivateCredential);
    if (ret) goto marshal_err;

    /* Handles */
    ret = heim_store_uint32(cmd, ak_handle);
    if (ret) goto marshal_err;
    ret = heim_store_uint32(cmd, ek_handle);
    if (ret) goto marshal_err;

    /* authorizationSize + auth area */
    ret = heim_store_uint32(cmd, (uint32_t)auth_len);
    if (ret) goto marshal_err;
    ret = heim_store_bytes(cmd, auth_data, auth_len);
    if (ret) goto marshal_err;
    free(auth_data);
    auth_data = NULL;

    /* Parameters: credentialBlob + secret (already TPM2B-wrapped by caller) */
    ret = heim_store_bytes(cmd, credential_blob, credential_blob_len);
    if (ret) goto marshal_err;
    ret = heim_store_bytes(cmd, encrypted_secret, encrypted_secret_len);
    if (ret) goto marshal_err;

    r = htpm2_command_execute(ctx, tp, cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "ActivateCredential");

    /* Response has parameterSize for TPM_ST_SESSIONS */
    ret = heim_ret_uint32(rsp, &param_size);
    if (ret) goto unmarshal_err;

    /* certInfo (TPM2B_DIGEST) */
    ret = htpm2_unmarshal_tpm2b(rsp, &cred_data, &cred_size);
    if (ret) goto unmarshal_err;

    heim_storage_free(rsp);

    *credential_out = cred_data;
    *credential_out_len = cred_size;
    return HTPM2_OK;

auth_err:
    heim_storage_free(auth_sp);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "ActivateCredential: auth marshal");

marshal_err:
    free(auth_data);
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "ActivateCredential: marshal");

unmarshal_err:
    free(cred_data);
    heim_storage_free(rsp);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "ActivateCredential: unmarshal");
}
