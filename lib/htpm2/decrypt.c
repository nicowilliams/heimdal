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
 * TPM2_RSA_Decrypt and TPM2_ECDH_ZGen.
 *
 * RSA_Decrypt command (with session):
 *   keyHandle:    uint32
 *   cipherText:   TPM2B_PUBLIC_KEY_RSA
 *   inScheme:     TPMT_RSA_DECRYPT (TPM_ALG_NULL = key's default scheme)
 *   label:        TPM2B_DATA (empty)
 *
 * RSA_Decrypt response:
 *   message:      TPM2B_PUBLIC_KEY_RSA
 */

#include "htpm2_locl.h"
#include "marshal.h"

htpm2_result
htpm2_rsa_decrypt(const htpm2_context ctx,
                  htpm2_transport tp,
                  htpm2_result prior,
                  htpm2_session auth_session,
                  htpm2_object key,
                  const void *ciphertext, size_t ciphertext_len,
                  void **plaintext, size_t *plaintext_len)
{
    heim_storage *param_sp, *rsp;
    uint32_t rc, handles[1];
    void *param_data = NULL;
    size_t param_len = 0;
    void *pt_data = NULL;
    uint16_t pt_size;
    htpm2_result r;
    int ret;

    if (prior.code)
        return prior;

    *plaintext = NULL;
    *plaintext_len = 0;

    handles[0] = htpm2_object_get_handle(key);

    param_sp = heim_storage_emem();
    if (param_sp == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "RSA_Decrypt: alloc");

    /* cipherText (TPM2B) */
    ret = htpm2_marshal_tpm2b(param_sp, ciphertext, ciphertext_len);
    if (ret == 0)
        /* inScheme = TPM_ALG_NULL (use key default) */
        ret = heim_store_uint16(param_sp, TPM2_ALG_NULL);
    if (ret == 0)
        /* label (empty TPM2B_DATA) */
        ret = htpm2_marshal_tpm2b(param_sp, NULL, 0);

    if (ret) {
        heim_storage_free(param_sp);
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "RSA_Decrypt: marshal");
    }

    ret = heim_storage_to_data(param_sp, &param_data, &param_len);
    heim_storage_free(param_sp);
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "RSA_Decrypt: to_data");

    r = htpm2_command_execute_with_auth(ctx, tp, TPM2_CC_RSA_Decrypt,
                                        handles, 1, auth_session,
                                        param_data, param_len, &rsp, &rc);
    free(param_data);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "RSA_Decrypt");

    ret = htpm2_unmarshal_tpm2b(rsp, &pt_data, &pt_size);
    heim_storage_free(rsp);
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "RSA_Decrypt: unmarshal");

    *plaintext = pt_data;
    *plaintext_len = pt_size;
    return HTPM2_OK;
}

/*
 * TPM2_ECDH_ZGen -- compute ECDH shared secret.
 *
 * Command (with session on keyHandle):
 *   keyHandle:  uint32
 *   inPoint:    TPM2B_ECC_POINT { TPMS_ECC_POINT { TPM2B x, TPM2B y } }
 *
 * Response:
 *   outPoint:   TPM2B_ECC_POINT
 */
htpm2_result
htpm2_ecdh_zgen(const htpm2_context ctx,
                htpm2_transport tp,
                htpm2_result prior,
                htpm2_session auth_session,
                htpm2_object key,
                const void *peer_point,
                size_t peer_point_len,
                void **shared_secret,
                size_t *shared_secret_len)
{
    heim_storage *param_sp, *rsp;
    uint32_t rc, handles[1];
    void *param_data = NULL;
    size_t param_len = 0;
    void *out_data = NULL;
    uint16_t out_size;
    htpm2_result r;
    int ret;

    if (prior.code)
        return prior;

    *shared_secret = NULL;
    *shared_secret_len = 0;

    handles[0] = htpm2_object_get_handle(key);

    param_sp = heim_storage_emem();
    if (param_sp == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "ECDH_ZGen: alloc");

    /* inPoint (TPM2B_ECC_POINT -- pre-encoded by caller) */
    ret = htpm2_marshal_tpm2b(param_sp, peer_point, peer_point_len);
    if (ret) {
        heim_storage_free(param_sp);
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "ECDH_ZGen: marshal");
    }

    ret = heim_storage_to_data(param_sp, &param_data, &param_len);
    heim_storage_free(param_sp);
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "ECDH_ZGen: to_data");

    r = htpm2_command_execute_with_auth(ctx, tp, TPM2_CC_ECDH_ZGen,
                                        handles, 1, auth_session,
                                        param_data, param_len, &rsp, &rc);
    free(param_data);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "ECDH_ZGen");

    /* outPoint (TPM2B_ECC_POINT) */
    ret = htpm2_unmarshal_tpm2b(rsp, &out_data, &out_size);
    heim_storage_free(rsp);
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "ECDH_ZGen: unmarshal");

    *shared_secret = out_data;
    *shared_secret_len = out_size;
    return HTPM2_OK;
}
