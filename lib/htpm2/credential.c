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
 * Command (with two auth sessions):
 *   activateHandle: uint32 (key whose Name was bound -- USER auth)
 *   keyHandle:      uint32 (EK that decrypts -- ADMIN auth via policy)
 *   credentialBlob: TPM2B_ID_OBJECT
 *   secret:         TPM2B_ENCRYPTED_SECRET
 *
 * Response:
 *   certInfo:       TPM2B_DIGEST (the decrypted credential)
 *
 * For standard EK templates, the EK requires PolicySecret(ENDORSEMENT)
 * for ADMIN authorization.  We handle this automatically:
 *   1. Start a policy session
 *   2. Execute PolicySecret(ENDORSEMENT) with empty password
 *   3. Use that policy session as auth for the EK handle
 *   4. Use password auth (empty) for the activate handle
 */

#include "htpm2_locl.h"
#include "marshal.h"

#define TPM_RH_ENDORSEMENT 0x4000000B

/*
 * Create a policy session that satisfies PolicySecret(ENDORSEMENT).
 * This is the standard authorization for EKs.
 */
static htpm2_result
make_ek_policy_session(const htpm2_context ctx,
                       htpm2_transport tp,
                       htpm2_session *session_out)
{
    htpm2_session policy_session = NULL;
    htpm2_result r;

    /* Start a policy session */
    r = htpm2_session_start(ctx, tp, HTPM2_OK,
                            HTPM2_SESSION_POLICY,
                            NULL, NULL, 0, &policy_session);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r,
            "ActivateCredential: start EK policy session");

    /* Execute PolicySecret(ENDORSEMENT) */
    r = htpm2_policy_secret(ctx, policy_session, HTPM2_OK,
                            NULL, /* auth entity -- we pass the handle directly */
                            NULL, 0, /* policyRef */
                            0);  /* expiration */

    /*
     * htpm2_policy_secret takes an htpm2_object for the auth entity,
     * but for the endorsement hierarchy (a permanent handle) we don't
     * have an object.  We need to call the TPM command directly.
     */
    /* Actually, let's build the PolicySecret command manually since
     * the endorsement hierarchy is a permanent handle, not a loaded
     * object. */
    htpm2_session_close(&policy_session);

    /* Rebuild: use htpm2_command_execute_with_auths for PolicySecret
     * with the endorsement hierarchy handle directly. */
    r = htpm2_session_start(ctx, tp, HTPM2_OK,
                            HTPM2_SESSION_POLICY,
                            NULL, NULL, 0, &policy_session);
    if (htpm2_is_err(r))
        return r;

    /*
     * TPM2_PolicySecret:
     *   handles: authHandle(ENDORSEMENT), policySession
     *   auth: password auth on authHandle (empty endorsement password)
     *   params: nonceTPM(empty), cpHashA(empty), policyRef(empty), expiration(0)
     */
    {
        heim_storage *param_sp;
        void *param_data = NULL;
        size_t param_len = 0;
        heim_storage *rsp;
        uint32_t rc;
        uint32_t handles[2];
        int ret;

        handles[0] = TPM_RH_ENDORSEMENT;
        handles[1] = htpm2_session_get_handle(policy_session);

        param_sp = heim_storage_emem();
        if (param_sp == NULL) {
            htpm2_session_close(&policy_session);
            return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                      "EK policy: alloc");
        }

        /* nonceTPM (empty) */
        ret = htpm2_marshal_tpm2b(param_sp, NULL, 0);
        if (ret == 0)
            /* cpHashA (empty) */
            ret = htpm2_marshal_tpm2b(param_sp, NULL, 0);
        if (ret == 0)
            /* policyRef (empty) */
            ret = htpm2_marshal_tpm2b(param_sp, NULL, 0);
        if (ret == 0)
            /* expiration = 0 */
            ret = heim_store_uint32(param_sp, 0);

        if (ret) {
            heim_storage_free(param_sp);
            htpm2_session_close(&policy_session);
            return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                      "EK policy: marshal");
        }

        ret = heim_storage_to_data(param_sp, &param_data, &param_len);
        heim_storage_free(param_sp);
        if (ret) {
            htpm2_session_close(&policy_session);
            return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                      "EK policy: to_data");
        }

        /* Password auth on the endorsement hierarchy (empty password) */
        r = htpm2_command_execute_with_auth(ctx, tp,
                                            TPM2_CC_PolicySecret,
                                            handles, 2, NULL,
                                            param_data, param_len,
                                            &rsp, &rc);
        free(param_data);
        if (htpm2_is_err(r)) {
            htpm2_session_close(&policy_session);
            return htpm2_result_prepend(r,
                "ActivateCredential: PolicySecret(ENDORSEMENT)");
        }
        heim_storage_free(rsp);
    }

    *session_out = policy_session;
    return HTPM2_OK;
}

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
    uint32_t param_size;
    void *cred_data = NULL;
    uint16_t cred_size;
    htpm2_session ek_policy_session = NULL;
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
     * If no EK auth session was provided, create one automatically
     * using PolicySecret(ENDORSEMENT).  This is the standard policy
     * for EKs created with the TCG EK template.
     */
    if (auth_session_ek == NULL) {
        r = make_ek_policy_session(ctx, tp, &ek_policy_session);
        if (htpm2_is_err(r))
            return r;
        auth_session_ek = ek_policy_session;
    }

    /*
     * Build auth area with two sessions:
     *   1. activateHandle (AK): password auth or caller-provided session
     *   2. keyHandle (EK): the policy session from above
     */
    auth_sp = heim_storage_emem();
    if (auth_sp == NULL) {
        htpm2_session_close(&ek_policy_session);
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "ActivateCredential: alloc auth");
    }

    /* Auth area 1: activateHandle -- password or caller session */
    if (auth_session_ak == NULL) {
        /* Password auth with empty password */
        ret = heim_store_uint32(auth_sp, 0x40000009);  /* TPM_RS_PW */
        if (ret) goto auth_err;
        ret = htpm2_marshal_tpm2b(auth_sp, NULL, 0);
        if (ret) goto auth_err;
        ret = heim_store_uint8(auth_sp, 0x01);
        if (ret) goto auth_err;
        ret = htpm2_marshal_tpm2b(auth_sp, NULL, 0);
        if (ret) goto auth_err;
    } else {
        /* Use the provided session */
        uint8_t dummy_hash[32] = {0}; /* TODO: proper cpHash */
        r = htpm2_marshal_auth_area(ctx, auth_sp, auth_session_ak,
                                    dummy_hash);
        if (htpm2_is_err(r)) {
            heim_storage_free(auth_sp);
            htpm2_session_close(&ek_policy_session);
            return r;
        }
    }

    /* Auth area 2: keyHandle (EK) -- the policy session */
    {
        /*
         * For a policy session, the HMAC field in the auth area is
         * empty (policy sessions don't use HMAC auth -- the policy
         * itself is the authorization).
         */
        ret = heim_store_uint32(auth_sp,
                                htpm2_session_get_handle(auth_session_ek));
        if (ret) goto auth_err;
        ret = htpm2_marshal_tpm2b(auth_sp, NULL, 0); /* nonce (empty for policy) */
        if (ret) goto auth_err;
        ret = heim_store_uint8(auth_sp, 0x00); /* attrs: no continueSession */
        if (ret) goto auth_err;
        ret = htpm2_marshal_tpm2b(auth_sp, NULL, 0); /* hmac (empty for policy) */
        if (ret) goto auth_err;
    }

    ret = heim_storage_to_data(auth_sp, &auth_data, &auth_len);
    heim_storage_free(auth_sp);
    auth_sp = NULL;
    if (ret) {
        htpm2_session_close(&ek_policy_session);
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "ActivateCredential: auth to_data");
    }

    /* Build command */
    cmd = heim_storage_emem();
    if (cmd == NULL) {
        free(auth_data);
        htpm2_session_close(&ek_policy_session);
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "ActivateCredential: alloc cmd");
    }

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_SESSIONS,
                                   TPM2_CC_ActivateCredential);
    if (ret) goto marshal_err;

    ret = heim_store_uint32(cmd, ak_handle);
    if (ret) goto marshal_err;
    ret = heim_store_uint32(cmd, ek_handle);
    if (ret) goto marshal_err;

    ret = heim_store_uint32(cmd, (uint32_t)auth_len);
    if (ret) goto marshal_err;
    ret = heim_store_bytes(cmd, auth_data, auth_len);
    if (ret) goto marshal_err;
    free(auth_data);
    auth_data = NULL;

    ret = heim_store_bytes(cmd, credential_blob, credential_blob_len);
    if (ret) goto marshal_err;
    ret = heim_store_bytes(cmd, encrypted_secret, encrypted_secret_len);
    if (ret) goto marshal_err;

    r = htpm2_command_execute(ctx, tp, cmd, &rsp, &rc);
    heim_storage_free(cmd);

    /* The EK policy session is consumed (single-use) */
    htpm2_session_close(&ek_policy_session);

    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "ActivateCredential");

    ret = heim_ret_uint32(rsp, &param_size);
    if (ret) goto unmarshal_err;

    ret = htpm2_unmarshal_tpm2b(rsp, &cred_data, &cred_size);
    if (ret) goto unmarshal_err;

    heim_storage_free(rsp);

    *credential_out = cred_data;
    *credential_out_len = cred_size;
    return HTPM2_OK;

auth_err:
    heim_storage_free(auth_sp);
    htpm2_session_close(&ek_policy_session);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "ActivateCredential: auth marshal");

marshal_err:
    free(auth_data);
    heim_storage_free(cmd);
    htpm2_session_close(&ek_policy_session);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "ActivateCredential: marshal");

unmarshal_err:
    free(cred_data);
    heim_storage_free(rsp);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "ActivateCredential: unmarshal");
}
