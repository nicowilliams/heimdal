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
 * TPM 2.0 Policy commands.
 *
 * Policy commands take a policy or trial session handle and extend the
 * session's policy digest.  They don't require authorization on the
 * session -- the session handle is passed as a regular handle, not in
 * the auth area.
 *
 * TPM2_PolicyPCR:
 *   policySession: handle
 *   pcrDigest:     TPM2B_DIGEST (expected PCR digest, or empty to use current)
 *   pcrs:          TPML_PCR_SELECTION
 *
 * TPM2_PolicyCommandCode:
 *   policySession: handle
 *   code:          TPM_CC
 *
 * TPM2_PolicyOR:
 *   policySession: handle
 *   pHashList:     TPML_DIGEST (list of alternative policy digests)
 *
 * TPM2_PolicySecret:
 *   authHandle:    handle (entity whose secret authorizes -- needs auth)
 *   policySession: handle
 *   nonceTPM:      TPM2B_NONCE
 *   cpHashA:       TPM2B_DIGEST (empty)
 *   policyRef:     TPM2B_NONCE
 *   expiration:    int32
 *
 * TPM2_PolicySigned:
 *   authObject:    handle (key that signed the authorization)
 *   policySession: handle
 *   nonceTPM:      TPM2B_NONCE
 *   cpHashA:       TPM2B_DIGEST
 *   policyRef:     TPM2B_NONCE
 *   expiration:    int32
 *   auth:          TPMT_SIGNATURE
 *
 * TPM2_PolicyAuthorize:
 *   policySession: handle
 *   approvedPolicy: TPM2B_DIGEST
 *   policyRef:     TPM2B_NONCE
 *   keySign:       TPM2B_NAME
 *   checkTicket:   TPMT_TK_VERIFIED
 */

#include "htpm2_locl.h"
#include "marshal.h"

/*
 * TPM2_PolicyGetDigest -- retrieve the current policy digest.
 *
 * Command (no sessions):
 *   policySession: handle
 *
 * Response:
 *   policyDigest: TPM2B_DIGEST
 */
htpm2_result
htpm2_session_get_policy_digest(htpm2_session session,
                                htpm2_result prior,
                                void *digest,
                                size_t *digest_len)
{
    heim_storage *cmd, *rsp;
    uint32_t rc, sess_handle;
    void *digest_data = NULL;
    uint16_t digest_size;
    htpm2_result r;
    int ret;

    if (prior.code)
        return prior;

    if (session == NULL || digest == NULL || digest_len == NULL)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "PolicyGetDigest: NULL argument");

    sess_handle = htpm2_session_get_handle(session);

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "PolicyGetDigest: alloc");

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS, 0x0000017D);
    if (ret) goto marshal_err;

    ret = heim_store_uint32(cmd, sess_handle);
    if (ret) goto marshal_err;

    r = htpm2_command_execute(NULL, htpm2_object_get_transport(NULL),
                              cmd, &rsp, &rc);

    /*
     * We don't have the transport on the session easily.  Let's use the
     * internal accessor we added.  Actually, sessions store their transport.
     */
    heim_storage_free(cmd);

    /* Re-do with proper transport access */
    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "PolicyGetDigest: alloc");

    /* TPM2_CC_PolicyGetDigest = 0x0000017D */
    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS, 0x0000017D);
    if (ret) goto marshal_err;
    ret = heim_store_uint32(cmd, sess_handle);
    if (ret) goto marshal_err;

    r = htpm2_command_execute(NULL, htpm2_session_get_transport(session),
                              cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "PolicyGetDigest");

    ret = htpm2_unmarshal_tpm2b(rsp, &digest_data, &digest_size);
    heim_storage_free(rsp);
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "PolicyGetDigest: unmarshal");

    if (digest_size > *digest_len) {
        free(digest_data);
        return htpm2_result_local(ENOBUFS, HTPM2_F_LOCAL, ENOBUFS,
                                  "PolicyGetDigest: buffer too small");
    }

    memcpy(digest, digest_data, digest_size);
    *digest_len = digest_size;
    free(digest_data);
    return HTPM2_OK;

marshal_err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "PolicyGetDigest: marshal");
}

/* --- PolicyPCR --- */

htpm2_result
htpm2_policy_pcr(const htpm2_context ctx,
                 htpm2_session session,
                 htpm2_result prior,
                 const uint8_t *pcr_selections,
                 size_t pcr_selections_len,
                 const void *pcr_digest,
                 size_t pcr_digest_len)
{
    heim_storage *cmd, *rsp;
    uint32_t rc;
    htpm2_result r;
    int ret;

    if (prior.code)
        return prior;

    (void)ctx;

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "PolicyPCR: alloc");

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS,
                                   TPM2_CC_PolicyPCR);
    if (ret) goto marshal_err;

    /* policySession handle */
    ret = heim_store_uint32(cmd, htpm2_session_get_handle(session));
    if (ret) goto marshal_err;

    /* pcrDigest (TPM2B_DIGEST) -- empty to use current PCR values */
    ret = htpm2_marshal_tpm2b(cmd, pcr_digest, pcr_digest_len);
    if (ret) goto marshal_err;

    /* pcrs (pre-encoded TPML_PCR_SELECTION) */
    ret = heim_store_bytes(cmd, pcr_selections, pcr_selections_len);
    if (ret) goto marshal_err;

    r = htpm2_command_execute(NULL, htpm2_session_get_transport(session),
                              cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "PolicyPCR");

    heim_storage_free(rsp);
    return HTPM2_OK;

marshal_err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "PolicyPCR: marshal");
}

/* --- PolicyCommandCode --- */

htpm2_result
htpm2_policy_command_code(const htpm2_context ctx,
                          htpm2_session session,
                          htpm2_result prior,
                          uint32_t command_code)
{
    heim_storage *cmd, *rsp;
    uint32_t rc;
    htpm2_result r;
    int ret;

    if (prior.code)
        return prior;

    (void)ctx;

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "PolicyCommandCode: alloc");

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS,
                                   TPM2_CC_PolicyCommandCode);
    if (ret) goto marshal_err;

    ret = heim_store_uint32(cmd, htpm2_session_get_handle(session));
    if (ret) goto marshal_err;

    ret = heim_store_uint32(cmd, command_code);
    if (ret) goto marshal_err;

    r = htpm2_command_execute(NULL, htpm2_session_get_transport(session),
                              cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "PolicyCommandCode");

    heim_storage_free(rsp);
    return HTPM2_OK;

marshal_err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "PolicyCommandCode: marshal");
}

/* --- PolicyOR --- */

htpm2_result
htpm2_policy_or(const htpm2_context ctx,
                htpm2_session session,
                htpm2_result prior,
                const void **digests,
                const size_t *digest_lens,
                size_t num_digests)
{
    heim_storage *cmd, *rsp;
    uint32_t rc;
    htpm2_result r;
    int ret;
    size_t i;

    if (prior.code)
        return prior;

    (void)ctx;

    if (num_digests < 2 || num_digests > 8)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "PolicyOR: need 2-8 digests, got %zu",
                                  num_digests);

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "PolicyOR: alloc");

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS,
                                   TPM2_CC_PolicyOR);
    if (ret) goto marshal_err;

    ret = heim_store_uint32(cmd, htpm2_session_get_handle(session));
    if (ret) goto marshal_err;

    /* pHashList (TPML_DIGEST) */
    ret = heim_store_uint32(cmd, (uint32_t)num_digests);
    if (ret) goto marshal_err;

    for (i = 0; i < num_digests; i++) {
        ret = htpm2_marshal_tpm2b(cmd, digests[i], digest_lens[i]);
        if (ret) goto marshal_err;
    }

    r = htpm2_command_execute(NULL, htpm2_session_get_transport(session),
                              cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "PolicyOR");

    heim_storage_free(rsp);
    return HTPM2_OK;

marshal_err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "PolicyOR: marshal");
}

/* --- PolicySecret --- */

htpm2_result
htpm2_policy_secret(const htpm2_context ctx,
                    htpm2_session session,
                    htpm2_result prior,
                    htpm2_object auth_entity,
                    const void *policy_ref,
                    size_t policy_ref_len,
                    int32_t expiration)
{
    heim_storage *param_sp;
    uint32_t rc;
    uint32_t handles[2];
    void *param_data = NULL;
    size_t param_len = 0;
    heim_storage *rsp;
    htpm2_result r;
    int ret;

    if (prior.code)
        return prior;

    /*
     * PolicySecret needs auth on the authHandle (the entity whose
     * secret is being used).  The policySession is also a handle.
     *
     * Command layout (with sessions):
     *   handles: authHandle, policySession
     *   auth area: for authHandle
     *   params: nonceTPM(empty), cpHashA(empty), policyRef, expiration
     */
    handles[0] = htpm2_object_get_handle(auth_entity);
    handles[1] = htpm2_session_get_handle(session);

    param_sp = heim_storage_emem();
    if (param_sp == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "PolicySecret: alloc");

    /* nonceTPM (empty) */
    ret = htpm2_marshal_tpm2b(param_sp, NULL, 0);
    if (ret) goto marshal_err;

    /* cpHashA (empty) */
    ret = htpm2_marshal_tpm2b(param_sp, NULL, 0);
    if (ret) goto marshal_err;

    /* policyRef */
    ret = htpm2_marshal_tpm2b(param_sp, policy_ref, policy_ref_len);
    if (ret) goto marshal_err;

    /* expiration (int32, big-endian) */
    ret = heim_store_uint32(param_sp, (uint32_t)expiration);
    if (ret) goto marshal_err;

    ret = heim_storage_to_data(param_sp, &param_data, &param_len);
    heim_storage_free(param_sp);
    param_sp = NULL;
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "PolicySecret: to_data");

    /* Use password auth (NULL session) for the auth entity */
    r = htpm2_command_execute_with_auth(ctx, NULL,
                                        TPM2_CC_PolicySecret,
                                        handles, 2, NULL,
                                        param_data, param_len,
                                        &rsp, &rc);
    free(param_data);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "PolicySecret");

    heim_storage_free(rsp);
    return HTPM2_OK;

marshal_err:
    heim_storage_free(param_sp);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "PolicySecret: marshal");
}

/* --- PolicySigned --- */

htpm2_result
htpm2_policy_signed(const htpm2_context ctx,
                    htpm2_session session,
                    htpm2_result prior,
                    htpm2_object auth_key,
                    const void *policy_ref,
                    size_t policy_ref_len,
                    int32_t expiration,
                    const void *signature,
                    size_t signature_len)
{
    heim_storage *cmd, *rsp;
    uint32_t rc;
    htpm2_result r;
    int ret;

    if (prior.code)
        return prior;

    (void)ctx;

    /*
     * PolicySigned: authObject and policySession are both handles,
     * but authObject doesn't need session auth -- the signature
     * itself is the proof of authorization.  So we use NO_SESSIONS.
     */
    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "PolicySigned: alloc");

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS,
                                   TPM2_CC_PolicySigned);
    if (ret) goto marshal_err;

    /* authObject handle */
    ret = heim_store_uint32(cmd, htpm2_object_get_handle(auth_key));
    if (ret) goto marshal_err;

    /* policySession handle */
    ret = heim_store_uint32(cmd, htpm2_session_get_handle(session));
    if (ret) goto marshal_err;

    /* nonceTPM (empty) */
    ret = htpm2_marshal_tpm2b(cmd, NULL, 0);
    if (ret) goto marshal_err;

    /* cpHashA (empty) */
    ret = htpm2_marshal_tpm2b(cmd, NULL, 0);
    if (ret) goto marshal_err;

    /* policyRef */
    ret = htpm2_marshal_tpm2b(cmd, policy_ref, policy_ref_len);
    if (ret) goto marshal_err;

    /* expiration */
    ret = heim_store_uint32(cmd, (uint32_t)expiration);
    if (ret) goto marshal_err;

    /* auth (TPMT_SIGNATURE -- raw bytes) */
    ret = heim_store_bytes(cmd, signature, signature_len);
    if (ret) goto marshal_err;

    r = htpm2_command_execute(NULL, htpm2_session_get_transport(session),
                              cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "PolicySigned");

    heim_storage_free(rsp);
    return HTPM2_OK;

marshal_err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "PolicySigned: marshal");
}

/* --- PolicyAuthorize --- */

htpm2_result
htpm2_policy_authorize(const htpm2_context ctx,
                       htpm2_session session,
                       htpm2_result prior,
                       const void *approved_policy,
                       size_t approved_policy_len,
                       const void *policy_ref,
                       size_t policy_ref_len,
                       const void *key_sign_name,
                       size_t key_sign_name_len,
                       const void *ticket,
                       size_t ticket_len,
                       const void *signature,
                       size_t signature_len)
{
    heim_storage *cmd, *rsp;
    uint32_t rc;
    htpm2_result r;
    int ret;

    if (prior.code)
        return prior;

    (void)ctx;
    (void)signature;
    (void)signature_len;

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "PolicyAuthorize: alloc");

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS,
                                   TPM2_CC_PolicyAuthorize);
    if (ret) goto marshal_err;

    /* policySession handle */
    ret = heim_store_uint32(cmd, htpm2_session_get_handle(session));
    if (ret) goto marshal_err;

    /* approvedPolicy (TPM2B_DIGEST) */
    ret = htpm2_marshal_tpm2b(cmd, approved_policy, approved_policy_len);
    if (ret) goto marshal_err;

    /* policyRef (TPM2B_NONCE) */
    ret = htpm2_marshal_tpm2b(cmd, policy_ref, policy_ref_len);
    if (ret) goto marshal_err;

    /* keySign (TPM2B_NAME) */
    ret = htpm2_marshal_tpm2b(cmd, key_sign_name, key_sign_name_len);
    if (ret) goto marshal_err;

    /* checkTicket (TPMT_TK_VERIFIED -- raw bytes) */
    if (ticket && ticket_len > 0)
        ret = heim_store_bytes(cmd, ticket, ticket_len);
    else {
        /* NULL ticket: tag=0x8000(TPM_ST_NULL), hierarchy=TPM_RH_NULL, digest=empty */
        ret = heim_store_uint16(cmd, 0x8014);  /* TPM_ST_VERIFIED */
        if (ret == 0)
            ret = heim_store_uint32(cmd, 0x40000007);  /* TPM_RH_NULL */
        if (ret == 0)
            ret = htpm2_marshal_tpm2b(cmd, NULL, 0);
    }
    if (ret) goto marshal_err;

    r = htpm2_command_execute(NULL, htpm2_session_get_transport(session),
                              cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "PolicyAuthorize");

    heim_storage_free(rsp);
    return HTPM2_OK;

marshal_err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "PolicyAuthorize: marshal");
}

/* --- PolicyLocality --- */

htpm2_result
htpm2_policy_locality(const htpm2_context ctx,
                      htpm2_session session,
                      htpm2_result prior,
                      uint8_t locality)
{
    heim_storage *cmd, *rsp;
    uint32_t rc;
    htpm2_result r;
    int ret;

    if (prior.code) return prior;
    (void)ctx;

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "PolicyLocality: alloc");

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS, 0x0000016F);
    if (ret) goto err;
    ret = heim_store_uint32(cmd, htpm2_session_get_handle(session));
    if (ret) goto err;
    ret = heim_store_uint8(cmd, locality);
    if (ret) goto err;

    r = htpm2_command_execute(NULL, htpm2_session_get_transport(session),
                              cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "PolicyLocality");
    heim_storage_free(rsp);
    return HTPM2_OK;
err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "PolicyLocality: marshal");
}

/* --- PolicyNV --- */

htpm2_result
htpm2_policy_nv(const htpm2_context ctx,
                htpm2_session session,
                htpm2_result prior,
                uint32_t nv_index,
                const void *operand_b, size_t operand_b_len,
                uint16_t offset,
                uint16_t operation)
{
    heim_storage *param_sp;
    uint32_t rc, handles[2];
    void *param_data = NULL;
    size_t param_len = 0;
    heim_storage *rsp;
    htpm2_result r;
    int ret;

    if (prior.code) return prior;
    (void)ctx;

    /* NV read requires auth on the NV index.  Use password auth. */
    handles[0] = nv_index;  /* authHandle = NV index itself */
    handles[1] = htpm2_session_get_handle(session);

    param_sp = heim_storage_emem();
    if (param_sp == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "PolicyNV: alloc");

    ret = htpm2_marshal_tpm2b(param_sp, operand_b, operand_b_len);
    if (ret) goto err;
    ret = heim_store_uint16(param_sp, offset);
    if (ret) goto err;
    ret = heim_store_uint16(param_sp, operation);
    if (ret) goto err;

    ret = heim_storage_to_data(param_sp, &param_data, &param_len);
    heim_storage_free(param_sp);
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "PolicyNV: to_data");

    r = htpm2_command_execute_with_auth(NULL, htpm2_session_get_transport(session),
                                        0x00000149, handles, 2, NULL,
                                        param_data, param_len, &rsp, &rc);
    free(param_data);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "PolicyNV");
    heim_storage_free(rsp);
    return HTPM2_OK;
err:
    heim_storage_free(param_sp);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "PolicyNV: marshal");
}

/* --- PolicyCounterTimer --- */

htpm2_result
htpm2_policy_counter_timer(const htpm2_context ctx,
                           htpm2_session session,
                           htpm2_result prior,
                           const void *operand_b, size_t operand_b_len,
                           uint16_t offset,
                           uint16_t operation)
{
    heim_storage *cmd, *rsp;
    uint32_t rc;
    htpm2_result r;
    int ret;

    if (prior.code) return prior;
    (void)ctx;

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "PolicyCounterTimer: alloc");

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS, 0x0000016D);
    if (ret) goto err;
    ret = heim_store_uint32(cmd, htpm2_session_get_handle(session));
    if (ret) goto err;
    ret = htpm2_marshal_tpm2b(cmd, operand_b, operand_b_len);
    if (ret) goto err;
    ret = heim_store_uint16(cmd, offset);
    if (ret) goto err;
    ret = heim_store_uint16(cmd, operation);
    if (ret) goto err;

    r = htpm2_command_execute(NULL, htpm2_session_get_transport(session),
                              cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "PolicyCounterTimer");
    heim_storage_free(rsp);
    return HTPM2_OK;
err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "PolicyCounterTimer: marshal");
}

/* --- PolicyPhysicalPresence --- */

htpm2_result
htpm2_policy_physical_presence(const htpm2_context ctx,
                               htpm2_session session,
                               htpm2_result prior)
{
    heim_storage *cmd, *rsp;
    uint32_t rc;
    htpm2_result r;
    int ret;

    if (prior.code) return prior;
    (void)ctx;

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "PolicyPhysicalPresence: alloc");

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS, 0x00000187);
    if (ret) goto err;
    ret = heim_store_uint32(cmd, htpm2_session_get_handle(session));
    if (ret) goto err;

    r = htpm2_command_execute(NULL, htpm2_session_get_transport(session),
                              cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "PolicyPhysicalPresence");
    heim_storage_free(rsp);
    return HTPM2_OK;
err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "PolicyPhysicalPresence: marshal");
}

/* --- PolicyCpHash --- */

htpm2_result
htpm2_policy_cp_hash(const htpm2_context ctx,
                     htpm2_session session,
                     htpm2_result prior,
                     const void *cp_hash, size_t cp_hash_len)
{
    heim_storage *cmd, *rsp;
    uint32_t rc;
    htpm2_result r;
    int ret;

    if (prior.code) return prior;
    (void)ctx;

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "PolicyCpHash: alloc");

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS, 0x0000012C);
    if (ret) goto err;
    ret = heim_store_uint32(cmd, htpm2_session_get_handle(session));
    if (ret) goto err;
    ret = htpm2_marshal_tpm2b(cmd, cp_hash, cp_hash_len);
    if (ret) goto err;

    r = htpm2_command_execute(NULL, htpm2_session_get_transport(session),
                              cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "PolicyCpHash");
    heim_storage_free(rsp);
    return HTPM2_OK;
err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "PolicyCpHash: marshal");
}

/* --- PolicyNameHash --- */

htpm2_result
htpm2_policy_name_hash(const htpm2_context ctx,
                       htpm2_session session,
                       htpm2_result prior,
                       const void *name_hash, size_t name_hash_len)
{
    heim_storage *cmd, *rsp;
    uint32_t rc;
    htpm2_result r;
    int ret;

    if (prior.code) return prior;
    (void)ctx;

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "PolicyNameHash: alloc");

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS, 0x00000170);
    if (ret) goto err;
    ret = heim_store_uint32(cmd, htpm2_session_get_handle(session));
    if (ret) goto err;
    ret = htpm2_marshal_tpm2b(cmd, name_hash, name_hash_len);
    if (ret) goto err;

    r = htpm2_command_execute(NULL, htpm2_session_get_transport(session),
                              cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "PolicyNameHash");
    heim_storage_free(rsp);
    return HTPM2_OK;
err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "PolicyNameHash: marshal");
}

/* --- PolicyDuplicationSelect --- */

htpm2_result
htpm2_policy_duplication_select(const htpm2_context ctx,
                                htpm2_session session,
                                htpm2_result prior,
                                const void *object_name,
                                size_t object_name_len,
                                const void *new_parent_name,
                                size_t new_parent_name_len,
                                int include_object)
{
    heim_storage *cmd, *rsp;
    uint32_t rc;
    htpm2_result r;
    int ret;

    if (prior.code) return prior;
    (void)ctx;

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "PolicyDuplicationSelect: alloc");

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS, 0x00000188);
    if (ret) goto err;
    ret = heim_store_uint32(cmd, htpm2_session_get_handle(session));
    if (ret) goto err;
    ret = htpm2_marshal_tpm2b(cmd, object_name, object_name_len);
    if (ret) goto err;
    ret = htpm2_marshal_tpm2b(cmd, new_parent_name, new_parent_name_len);
    if (ret) goto err;
    ret = heim_store_uint8(cmd, include_object ? 1 : 0);
    if (ret) goto err;

    r = htpm2_command_execute(NULL, htpm2_session_get_transport(session),
                              cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "PolicyDuplicationSelect");
    heim_storage_free(rsp);
    return HTPM2_OK;
err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "PolicyDuplicationSelect: marshal");
}

/* --- PolicyAuthValue --- */

htpm2_result
htpm2_policy_auth_value(const htpm2_context ctx,
                        htpm2_session session,
                        htpm2_result prior)
{
    heim_storage *cmd, *rsp;
    uint32_t rc;
    htpm2_result r;
    int ret;

    if (prior.code) return prior;
    (void)ctx;

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "PolicyAuthValue: alloc");

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS, 0x0000016B);
    if (ret) goto err;
    ret = heim_store_uint32(cmd, htpm2_session_get_handle(session));
    if (ret) goto err;

    r = htpm2_command_execute(NULL, htpm2_session_get_transport(session),
                              cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "PolicyAuthValue");
    heim_storage_free(rsp);
    return HTPM2_OK;
err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "PolicyAuthValue: marshal");
}

/* --- PolicyPassword --- */
/* PolicyPassword has the same digest extension as PolicyAuthValue */

htpm2_result
htpm2_policy_password(const htpm2_context ctx,
                      htpm2_session session,
                      htpm2_result prior)
{
    heim_storage *cmd, *rsp;
    uint32_t rc;
    htpm2_result r;
    int ret;

    if (prior.code) return prior;
    (void)ctx;

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "PolicyPassword: alloc");

    /* TPM2_CC_PolicyPassword = 0x0000018C */
    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS, 0x0000018C);
    if (ret) goto err;
    ret = heim_store_uint32(cmd, htpm2_session_get_handle(session));
    if (ret) goto err;

    r = htpm2_command_execute(NULL, htpm2_session_get_transport(session),
                              cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "PolicyPassword");
    heim_storage_free(rsp);
    return HTPM2_OK;
err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "PolicyPassword: marshal");
}

/* --- PolicyNvWritten --- */

htpm2_result
htpm2_policy_nv_written(const htpm2_context ctx,
                        htpm2_session session,
                        htpm2_result prior,
                        int written_set)
{
    heim_storage *cmd, *rsp;
    uint32_t rc;
    htpm2_result r;
    int ret;

    if (prior.code) return prior;
    (void)ctx;

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "PolicyNvWritten: alloc");

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS, 0x0000018F);
    if (ret) goto err;
    ret = heim_store_uint32(cmd, htpm2_session_get_handle(session));
    if (ret) goto err;
    ret = heim_store_uint8(cmd, written_set ? 1 : 0);
    if (ret) goto err;

    r = htpm2_command_execute(NULL, htpm2_session_get_transport(session),
                              cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "PolicyNvWritten");
    heim_storage_free(rsp);
    return HTPM2_OK;
err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "PolicyNvWritten: marshal");
}

/* --- PolicyTemplate --- */

htpm2_result
htpm2_policy_template(const htpm2_context ctx,
                      htpm2_session session,
                      htpm2_result prior,
                      const void *template_hash,
                      size_t template_hash_len)
{
    heim_storage *cmd, *rsp;
    uint32_t rc;
    htpm2_result r;
    int ret;

    if (prior.code) return prior;
    (void)ctx;

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "PolicyTemplate: alloc");

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS, 0x00000190);
    if (ret) goto err;
    ret = heim_store_uint32(cmd, htpm2_session_get_handle(session));
    if (ret) goto err;
    ret = htpm2_marshal_tpm2b(cmd, template_hash, template_hash_len);
    if (ret) goto err;

    r = htpm2_command_execute(NULL, htpm2_session_get_transport(session),
                              cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "PolicyTemplate");
    heim_storage_free(rsp);
    return HTPM2_OK;
err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "PolicyTemplate: marshal");
}

/* --- PolicyAuthorizeNV --- */

htpm2_result
htpm2_policy_authorize_nv(const htpm2_context ctx,
                          htpm2_session session,
                          htpm2_result prior,
                          uint32_t nv_index)
{
    heim_storage *param_sp;
    uint32_t rc, handles[3];
    void *param_data = NULL;
    size_t param_len = 0;
    heim_storage *rsp;
    htpm2_result r;
    int ret;

    if (prior.code) return prior;
    (void)ctx;

    /* TPM2_PolicyAuthorizeNV: authHandle, nvIndex, policySession */
    handles[0] = nv_index;   /* authHandle = NV index */
    handles[1] = nv_index;   /* nvIndex */
    handles[2] = htpm2_session_get_handle(session);

    /* No command parameters beyond the handles */
    r = htpm2_command_execute_with_auth(NULL,
                                        htpm2_session_get_transport(session),
                                        0x00000192, handles, 3, NULL,
                                        NULL, 0, &rsp, &rc);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "PolicyAuthorizeNV");
    heim_storage_free(rsp);
    return HTPM2_OK;
}

/* --- PolicyTicket --- */

htpm2_result
htpm2_policy_ticket(const htpm2_context ctx,
                    htpm2_session session,
                    htpm2_result prior,
                    const void *timeout, size_t timeout_len,
                    const void *cp_hash_a, size_t cp_hash_a_len,
                    const void *policy_ref, size_t policy_ref_len,
                    const void *auth_name, size_t auth_name_len,
                    const void *ticket, size_t ticket_len)
{
    heim_storage *cmd, *rsp;
    uint32_t rc;
    htpm2_result r;
    int ret;

    if (prior.code) return prior;
    (void)ctx;

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "PolicyTicket: alloc");

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS, 0x00000169);
    if (ret) goto err;
    ret = heim_store_uint32(cmd, htpm2_session_get_handle(session));
    if (ret) goto err;
    ret = htpm2_marshal_tpm2b(cmd, timeout, timeout_len);
    if (ret) goto err;
    ret = htpm2_marshal_tpm2b(cmd, cp_hash_a, cp_hash_a_len);
    if (ret) goto err;
    ret = htpm2_marshal_tpm2b(cmd, policy_ref, policy_ref_len);
    if (ret) goto err;
    ret = htpm2_marshal_tpm2b(cmd, auth_name, auth_name_len);
    if (ret) goto err;
    /* ticket is a TPMT_TK_AUTH -- raw bytes */
    if (ticket && ticket_len > 0)
        ret = heim_store_bytes(cmd, ticket, ticket_len);
    if (ret) goto err;

    r = htpm2_command_execute(NULL, htpm2_session_get_transport(session),
                              cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "PolicyTicket");
    heim_storage_free(rsp);
    return HTPM2_OK;
err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "PolicyTicket: marshal");
}
