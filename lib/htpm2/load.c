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
 * TPM2_Load and TPM2_ReadPublic.
 *
 * TPM2_Load command (no sessions):
 *   header:       tag=NO_SESSIONS, CC=Load
 *   parentHandle: uint32
 *   inPrivate:    TPM2B_PRIVATE
 *   inPublic:     TPM2B_PUBLIC
 *
 * TPM2_Load response:
 *   objectHandle: uint32
 *   name:         TPM2B_NAME
 *
 * TPM2_ReadPublic command (no sessions):
 *   header:       tag=NO_SESSIONS, CC=ReadPublic
 *   objectHandle: uint32
 *
 * TPM2_ReadPublic response:
 *   outPublic:       TPM2B_PUBLIC
 *   name:            TPM2B_NAME
 *   qualifiedName:   TPM2B_NAME
 */

#include "htpm2_locl.h"
#include "marshal.h"

htpm2_result
htpm2_load(const htpm2_context ctx,
           htpm2_transport tp,
           htpm2_result prior,
           htpm2_session auth_session,
           htpm2_object parent,
           const void *pub_blob, size_t pub_blob_len,
           const void *priv_blob, size_t priv_blob_len,
           htpm2_object *key)
{
    heim_storage *cmd, *rsp;
    uint32_t rc, handle, parent_handle;
    htpm2_result r;
    htpm2_object obj;
    void *name_data = NULL;
    uint16_t name_len = 0;
    int ret;

    if (prior.code)
        return prior;

    if (parent == NULL || pub_blob == NULL || priv_blob == NULL)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "Load: NULL argument");

    *key = NULL;
    parent_handle = htpm2_object_get_handle(parent);

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "Load: alloc");

    /* Load requires authorization for the parent handle */
    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_SESSIONS, TPM2_CC_Load);
    if (ret) goto marshal_err;

    ret = heim_store_uint32(cmd, parent_handle);
    if (ret) goto marshal_err;

    /* Password auth for parent */
    ret = heim_store_uint32(cmd, 9); /* authorizationSize */
    if (ret) goto marshal_err;
    ret = heim_store_uint32(cmd, 0x40000009); /* TPM_RS_PW */
    if (ret) goto marshal_err;
    ret = heim_store_uint16(cmd, 0); /* nonceCaller */
    if (ret) goto marshal_err;
    ret = heim_store_uint8(cmd, 0x01); /* continueSession */
    if (ret) goto marshal_err;
    ret = heim_store_uint16(cmd, 0); /* hmac (empty password) */
    if (ret) goto marshal_err;

    /* inPrivate (TPM2B_PRIVATE) */
    ret = htpm2_marshal_tpm2b(cmd, priv_blob, priv_blob_len);
    if (ret) goto marshal_err;

    /* inPublic (TPM2B_PUBLIC) */
    ret = htpm2_marshal_tpm2b(cmd, pub_blob, pub_blob_len);
    if (ret) goto marshal_err;

    r = htpm2_command_execute(ctx, tp, cmd, &rsp, &rc);
    heim_storage_free(cmd);
    cmd = NULL;
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "Load");

    /* objectHandle */
    ret = heim_ret_uint32(rsp, &handle);
    if (ret) goto unmarshal_err;

    /* parameterSize (TPM_ST_SESSIONS response) */
    {
        uint32_t param_size;
        ret = heim_ret_uint32(rsp, &param_size);
        if (ret) goto unmarshal_err;
    }

    /* name (TPM2B_NAME) */
    ret = htpm2_unmarshal_tpm2b(rsp, &name_data, &name_len);
    if (ret) goto unmarshal_err;

    heim_storage_free(rsp);

    obj = htpm2_object_alloc(tp, handle);
    if (obj == NULL) {
        free(name_data);
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "Load: alloc object");
    }

    htpm2_object_set_pub(obj, pub_blob, pub_blob_len);
    htpm2_object_set_priv(obj, priv_blob, priv_blob_len);
    htpm2_object_set_name(obj, name_data, name_len);
    free(name_data);

    *key = obj;
    return HTPM2_OK;

marshal_err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "Load: marshal error");

unmarshal_err:
    free(name_data);
    heim_storage_free(rsp);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "Load: unmarshal error");
}

htpm2_result
htpm2_read_public(const htpm2_context ctx,
                  htpm2_transport tp,
                  htpm2_result prior,
                  htpm2_object key,
                  void **pub_blob, size_t *pub_blob_len,
                  void **name, size_t *name_len)
{
    heim_storage *cmd, *rsp;
    uint32_t rc;
    htpm2_result r;
    void *pub_data = NULL, *name_data = NULL;
    uint16_t pub_size, name_size;
    int ret;

    if (prior.code)
        return prior;

    if (key == NULL)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "ReadPublic: NULL key");

    *pub_blob = NULL;
    *pub_blob_len = 0;
    *name = NULL;
    *name_len = 0;

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "ReadPublic: alloc");

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS,
                                   TPM2_CC_ReadPublic);
    if (ret) goto marshal_err;

    ret = heim_store_uint32(cmd, htpm2_object_get_handle(key));
    if (ret) goto marshal_err;

    r = htpm2_command_execute(ctx, tp, cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "ReadPublic");

    /* outPublic (TPM2B_PUBLIC) */
    ret = htpm2_unmarshal_tpm2b(rsp, &pub_data, &pub_size);
    if (ret) goto unmarshal_err;

    /* name (TPM2B_NAME) */
    ret = htpm2_unmarshal_tpm2b(rsp, &name_data, &name_size);
    if (ret) goto unmarshal_err;

    /* qualifiedName -- skip */
    heim_storage_free(rsp);

    *pub_blob = pub_data;
    *pub_blob_len = pub_size;
    *name = name_data;
    *name_len = name_size;
    return HTPM2_OK;

marshal_err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "ReadPublic: marshal error");

unmarshal_err:
    free(pub_data);
    free(name_data);
    heim_storage_free(rsp);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "ReadPublic: unmarshal error");
}
