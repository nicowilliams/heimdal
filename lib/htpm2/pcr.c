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
 * TPM2_PCR_Read and TPM2_PCR_Extend.
 *
 * PCR_Read command (no auth):
 *   pcrSelectionIn: TPML_PCR_SELECTION
 *
 * PCR_Read response:
 *   pcrUpdateCounter: uint32
 *   pcrSelectionOut:   TPML_PCR_SELECTION
 *   pcrValues:         TPML_DIGEST
 */

#include "htpm2_locl.h"
#include "marshal.h"

/* --- PCR Selection helpers --- */

struct htpm2_pcr_selection_data {
    uint16_t hash_alg;
    uint8_t  bitmap[3];  /* PCR 0-23 */
};

htpm2_result
htpm2_pcr_selection_create(const htpm2_context ctx,
                           uint16_t hash_alg,
                           htpm2_pcr_selection *sel)
{
    struct htpm2_pcr_selection_data *s;

    (void)ctx;
    s = calloc(1, sizeof(*s));
    if (s == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "pcr_selection_create: alloc");
    s->hash_alg = hash_alg;
    *sel = s;
    return HTPM2_OK;
}

htpm2_result
htpm2_pcr_selection_add(htpm2_pcr_selection sel, uint32_t pcr_index)
{
    if (sel == NULL)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "pcr_selection_add: NULL");
    if (pcr_index > 23)
        return htpm2_result_local(ERANGE, HTPM2_F_LOCAL, ERANGE,
                                  "pcr_selection_add: index %u > 23",
                                  pcr_index);
    sel->bitmap[pcr_index / 8] |= (1 << (pcr_index % 8));
    return HTPM2_OK;
}

htpm2_result
htpm2_pcr_selection_encode(htpm2_pcr_selection sel,
                           void **encoded, size_t *encoded_len)
{
    /*
     * Encode as TPML_PCR_SELECTION with count=1:
     *   count: uint32 = 1
     *   TPMS_PCR_SELECTION:
     *     hash:      uint16
     *     sizeofSelect: uint8 = 3
     *     pcrSelect: 3 bytes
     */
    heim_storage *sp;
    int ret;

    if (sel == NULL)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "pcr_selection_encode: NULL");

    sp = heim_storage_emem();
    if (sp == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "pcr_selection_encode: alloc");

    ret = heim_store_uint32(sp, 1);           /* count */
    if (ret == 0)
        ret = heim_store_uint16(sp, sel->hash_alg);
    if (ret == 0)
        ret = heim_store_uint8(sp, 3);        /* sizeofSelect */
    if (ret == 0)
        ret = heim_store_bytes(sp, sel->bitmap, 3);

    if (ret) {
        heim_storage_free(sp);
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "pcr_selection_encode: marshal");
    }

    ret = heim_storage_to_data(sp, encoded, encoded_len);
    heim_storage_free(sp);
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_LOCAL, ret,
                                  "pcr_selection_encode: to_data");
    return HTPM2_OK;
}

void
htpm2_pcr_selection_free(htpm2_pcr_selection *sel)
{
    if (sel && *sel) {
        free(*sel);
        *sel = NULL;
    }
}

/* --- PCR_Read --- */

htpm2_result
htpm2_pcr_read(const htpm2_context ctx,
               htpm2_transport tp,
               htpm2_result prior,
               const uint8_t *pcr_selections,
               size_t pcr_selections_len,
               void **pcr_values,
               size_t *pcr_values_len,
               uint32_t *update_counter)
{
    heim_storage *cmd, *rsp;
    uint32_t rc;
    htpm2_result r;
    int ret;

    if (prior.code)
        return prior;

    *pcr_values = NULL;
    *pcr_values_len = 0;
    *update_counter = 0;

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "PCR_Read: alloc");

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS, TPM2_CC_PCR_Read);
    if (ret) goto marshal_err;

    /* pcrSelectionIn (pre-encoded TPML_PCR_SELECTION) */
    ret = heim_store_bytes(cmd, pcr_selections, pcr_selections_len);
    if (ret) goto marshal_err;

    r = htpm2_command_execute(ctx, tp, cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "PCR_Read");

    /* pcrUpdateCounter */
    ret = heim_ret_uint32(rsp, update_counter);
    if (ret) goto unmarshal_err;

    /* Read remaining bytes as the combined pcrSelectionOut + pcrValues */
    {
        off_t pos = heim_storage_seek(rsp, 0, SEEK_CUR);
        off_t end = heim_storage_seek(rsp, 0, SEEK_END);
        size_t remaining = end - pos;

        if (remaining > 0) {
            *pcr_values = malloc(remaining);
            if (*pcr_values == NULL) {
                heim_storage_free(rsp);
                return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                          "PCR_Read: alloc values");
            }
            heim_storage_seek(rsp, pos, SEEK_SET);
            ret = heim_ret_bytes(rsp, *pcr_values, remaining);
            if (ret) {
                free(*pcr_values);
                *pcr_values = NULL;
                goto unmarshal_err;
            }
            *pcr_values_len = remaining;
        }
    }

    heim_storage_free(rsp);
    return HTPM2_OK;

marshal_err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret, "PCR_Read: marshal");

unmarshal_err:
    heim_storage_free(rsp);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret, "PCR_Read: unmarshal");
}

htpm2_result
htpm2_pcr_extend(const htpm2_context ctx,
                 htpm2_transport tp,
                 htpm2_result prior,
                 htpm2_session auth_session,
                 uint32_t pcr_index,
                 uint16_t hash_alg,
                 const void *digest,
                 size_t digest_len)
{
    heim_storage *param_sp;
    uint32_t rc, handles[1];
    void *param_data = NULL;
    size_t param_len = 0;
    heim_storage *rsp;
    htpm2_result r;
    int ret;

    if (prior.code)
        return prior;

    handles[0] = pcr_index;

    /* Marshal parameters: TPML_DIGEST_VALUES { count=1, TPMT_HA } */
    param_sp = heim_storage_emem();
    if (param_sp == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "PCR_Extend: alloc");

    /* count = 1 */
    ret = heim_store_uint32(param_sp, 1);
    if (ret) goto marshal_err;

    /* TPMT_HA: hashAlg + digest */
    ret = heim_store_uint16(param_sp, hash_alg);
    if (ret) goto marshal_err;
    ret = heim_store_bytes(param_sp, digest, digest_len);
    if (ret) goto marshal_err;

    ret = heim_storage_to_data(param_sp, &param_data, &param_len);
    heim_storage_free(param_sp);
    param_sp = NULL;
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "PCR_Extend: to_data");

    r = htpm2_command_execute_with_auth(ctx, tp, TPM2_CC_PCR_Extend,
                                        handles, 1, auth_session,
                                        param_data, param_len,
                                        &rsp, &rc);
    free(param_data);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "PCR_Extend");

    heim_storage_free(rsp);
    return HTPM2_OK;

marshal_err:
    heim_storage_free(param_sp);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "PCR_Extend: marshal");
}
