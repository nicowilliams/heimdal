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
 * TPM2_Certify and TPM2_CertifyCreation.
 *
 * TPM2_Certify (with session -- needs auth on objectHandle):
 *   objectHandle: handle to certify
 *   signHandle:   signing key handle
 *   qualifyingData: TPM2B_DATA
 *   inScheme:     TPMT_SIG_SCHEME (NULL = key default)
 *
 * Response:
 *   certifyInfo:  TPM2B_ATTEST
 *   signature:    TPMT_SIGNATURE
 */

#include "htpm2_locl.h"
#include "marshal.h"

htpm2_result
htpm2_certify(const htpm2_context ctx,
              htpm2_transport tp,
              htpm2_result prior,
              htpm2_session auth_session,
              htpm2_object object,
              htpm2_object sign_key,
              const void *qualifying_data,
              size_t qualifying_data_len,
              void **certify_info, size_t *certify_info_len,
              void **signature, size_t *signature_len)
{
    heim_storage *param_sp, *rsp;
    uint32_t rc, handles[2];
    void *param_data = NULL;
    size_t param_len = 0;
    void *ci_data = NULL, *sig_data = NULL;
    uint16_t ci_size;
    htpm2_result r;
    int ret;

    if (prior.code)
        return prior;

    *certify_info = NULL;
    *certify_info_len = 0;
    *signature = NULL;
    *signature_len = 0;

    handles[0] = htpm2_object_get_handle(object);
    handles[1] = htpm2_object_get_handle(sign_key);

    param_sp = heim_storage_emem();
    if (param_sp == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "Certify: alloc");

    ret = htpm2_marshal_tpm2b(param_sp, qualifying_data, qualifying_data_len);
    if (ret == 0)
        ret = heim_store_uint16(param_sp, TPM2_ALG_NULL);
    if (ret) {
        heim_storage_free(param_sp);
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "Certify: marshal");
    }

    ret = heim_storage_to_data(param_sp, &param_data, &param_len);
    heim_storage_free(param_sp);
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "Certify: to_data");

    r = htpm2_command_execute_with_auth(ctx, tp, TPM2_CC_Certify,
                                        handles, 2, auth_session,
                                        param_data, param_len, &rsp, &rc);
    free(param_data);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "Certify");

    ret = htpm2_unmarshal_tpm2b(rsp, &ci_data, &ci_size);
    if (ret) {
        heim_storage_free(rsp);
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "Certify: unmarshal certifyInfo");
    }

    /* Read remaining as signature */
    {
        off_t pos = heim_storage_seek(rsp, 0, SEEK_CUR);
        off_t end = heim_storage_seek(rsp, 0, SEEK_END);
        size_t sig_bytes = end - pos;

        if (sig_bytes > 0) {
            sig_data = malloc(sig_bytes);
            if (sig_data) {
                heim_storage_seek(rsp, pos, SEEK_SET);
                heim_ret_bytes(rsp, sig_data, sig_bytes);
                *signature = sig_data;
                *signature_len = sig_bytes;
            }
        }
    }

    heim_storage_free(rsp);
    *certify_info = ci_data;
    *certify_info_len = ci_size;
    return HTPM2_OK;
}

htpm2_result
htpm2_certify_creation(const htpm2_context ctx,
                       htpm2_transport tp,
                       htpm2_result prior,
                       htpm2_session auth_session,
                       htpm2_object object,
                       htpm2_object sign_key,
                       const void *qualifying_data,
                       size_t qualifying_data_len,
                       const void *creation_ticket,
                       size_t creation_ticket_len,
                       void **certify_info, size_t *certify_info_len,
                       void **signature, size_t *signature_len)
{
    /* TODO: implement TPM2_CertifyCreation */
    (void)ctx; (void)tp; (void)auth_session; (void)object; (void)sign_key;
    (void)qualifying_data; (void)qualifying_data_len;
    (void)creation_ticket; (void)creation_ticket_len;

    if (prior.code)
        return prior;

    *certify_info = NULL; *certify_info_len = 0;
    *signature = NULL; *signature_len = 0;

    return htpm2_result_local(ENOSYS, HTPM2_F_LOCAL, ENOSYS,
                              "CertifyCreation: not yet implemented");
}

htpm2_result
htpm2_certify_x509(const htpm2_context ctx,
                   htpm2_transport tp,
                   htpm2_result prior,
                   htpm2_session auth_session,
                   htpm2_object object,
                   htpm2_object sign_key,
                   const void *partial_cert,
                   size_t partial_cert_len,
                   void **added_to_cert,
                   size_t *added_to_cert_len,
                   void **tbs_digest,
                   size_t *tbs_digest_len,
                   void **signature,
                   size_t *signature_len)
{
    /* TODO: implement TPM2_CertifyX509 -- requires lib/asn1 */
    (void)ctx; (void)tp; (void)auth_session; (void)object; (void)sign_key;
    (void)partial_cert; (void)partial_cert_len;

    if (prior.code)
        return prior;

    *added_to_cert = NULL; *added_to_cert_len = 0;
    *tbs_digest = NULL; *tbs_digest_len = 0;
    *signature = NULL; *signature_len = 0;

    return htpm2_result_local(ENOSYS, HTPM2_F_LOCAL, ENOSYS,
                              "CertifyX509: not yet implemented");
}
