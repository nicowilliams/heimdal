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
 * TPM2_Quote -- PCR attestation.
 *
 * Command (with session for signing key auth):
 *   signHandle:     uint32
 *   qualifyingData: TPM2B_DATA
 *   inScheme:       TPMT_SIG_SCHEME (TPM_ALG_NULL = key default)
 *   PCRselect:      TPML_PCR_SELECTION
 *
 * Response:
 *   quoted:    TPM2B_ATTEST (TPMS_ATTEST structure)
 *   signature: TPMT_SIGNATURE
 */

#include "htpm2_locl.h"
#include "marshal.h"

htpm2_result
htpm2_quote(const htpm2_context ctx,
            htpm2_transport tp,
            htpm2_result prior,
            htpm2_session auth_session,
            htpm2_object sign_key,
            const uint8_t *pcr_selections,
            size_t pcr_selections_len,
            const void *qualifying_data,
            size_t qualifying_data_len,
            void **quoted, size_t *quoted_len,
            void **signature, size_t *signature_len)
{
    heim_storage *param_sp, *rsp;
    uint32_t rc, handles[1];
    void *param_data = NULL;
    size_t param_len = 0;
    void *quoted_data = NULL, *sig_data = NULL;
    uint16_t quoted_size;
    htpm2_result r;
    int ret;

    if (prior.code)
        return prior;

    if (sign_key == NULL || pcr_selections == NULL)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "Quote: NULL argument");

    *quoted = NULL;
    *quoted_len = 0;
    *signature = NULL;
    *signature_len = 0;

    handles[0] = htpm2_object_get_handle(sign_key);

    /* Marshal parameters */
    param_sp = heim_storage_emem();
    if (param_sp == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "Quote: alloc");

    /* qualifyingData (TPM2B_DATA) */
    ret = htpm2_marshal_tpm2b(param_sp, qualifying_data, qualifying_data_len);
    if (ret) goto marshal_err;

    /* inScheme = TPM_ALG_NULL */
    ret = heim_store_uint16(param_sp, TPM2_ALG_NULL);
    if (ret) goto marshal_err;

    /* PCRselect (pre-encoded TPML_PCR_SELECTION) */
    ret = heim_store_bytes(param_sp, pcr_selections, pcr_selections_len);
    if (ret) goto marshal_err;

    ret = heim_storage_to_data(param_sp, &param_data, &param_len);
    heim_storage_free(param_sp);
    param_sp = NULL;
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "Quote: to_data");

    r = htpm2_command_execute_with_auth(ctx, tp, TPM2_CC_Quote,
                                        handles, 1, auth_session,
                                        param_data, param_len,
                                        &rsp, &rc);
    free(param_data);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "Quote");

    /* Response: quoted (TPM2B_ATTEST) */
    ret = htpm2_unmarshal_tpm2b(rsp, &quoted_data, &quoted_size);
    if (ret) goto unmarshal_err;

    /* signature (TPMT_SIGNATURE) -- read remaining response bytes */
    {
        off_t pos = heim_storage_seek(rsp, 0, SEEK_CUR);
        off_t end = heim_storage_seek(rsp, 0, SEEK_END);
        size_t sig_bytes = end - pos;

        if (sig_bytes > 0) {
            sig_data = malloc(sig_bytes);
            if (sig_data == NULL) {
                free(quoted_data);
                heim_storage_free(rsp);
                return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                          "Quote: alloc sig");
            }
            heim_storage_seek(rsp, pos, SEEK_SET);
            heim_ret_bytes(rsp, sig_data, sig_bytes);
            *signature = sig_data;
            *signature_len = sig_bytes;
        }
    }

    heim_storage_free(rsp);

    *quoted = quoted_data;
    *quoted_len = quoted_size;
    return HTPM2_OK;

marshal_err:
    heim_storage_free(param_sp);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret, "Quote: marshal");

unmarshal_err:
    free(quoted_data);
    heim_storage_free(rsp);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret, "Quote: unmarshal");
}
