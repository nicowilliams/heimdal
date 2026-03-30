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
 * TPM2_CreatePrimary and TPM2_Create.
 *
 * CreatePrimary command layout (no sessions):
 *   header:       tag=NO_SESSIONS, CC=CreatePrimary
 *   primaryHandle: uint32 (hierarchy handle)
 *   inSensitive:  TPM2B_SENSITIVE_CREATE { TPM2B userAuth, TPM2B data }
 *   inPublic:     TPM2B_PUBLIC { TPMT_PUBLIC }
 *   outsideInfo:  TPM2B_DATA (empty)
 *   creationPCR:  TPML_PCR_SELECTION (count=0)
 *
 * CreatePrimary response:
 *   objectHandle: uint32
 *   outPublic:    TPM2B_PUBLIC
 *   creationData: TPM2B_CREATION_DATA
 *   creationHash: TPM2B_DIGEST
 *   creationTicket: TPMT_TK_CREATION
 *   name:         TPM2B_NAME
 */

#include "htpm2_locl.h"
#include "marshal.h"

/*
 * Marshal TPMS_SENSITIVE_CREATE:
 *   userAuth:  TPM2B_AUTH (password)
 *   data:      TPM2B_SENSITIVE_DATA (sensitive data, empty for keys)
 */
static int
marshal_sensitive_create(heim_storage *sp,
                         const void *auth_value, size_t auth_value_len)
{
    heim_storage *inner;
    void *inner_data;
    size_t inner_len;
    int ret;

    /*
     * We need to marshal the inner TPMS_SENSITIVE_CREATE first to get
     * its size, then wrap it as TPM2B_SENSITIVE_CREATE.
     */
    inner = heim_storage_emem();
    if (inner == NULL)
        return ENOMEM;

    /* userAuth (TPM2B_AUTH) */
    ret = htpm2_marshal_tpm2b(inner, auth_value, auth_value_len);
    if (ret == 0)
        /* data (TPM2B_SENSITIVE_DATA) -- empty for key creation */
        ret = htpm2_marshal_tpm2b(inner, NULL, 0);

    if (ret) {
        heim_storage_free(inner);
        return ret;
    }

    ret = heim_storage_to_data(inner, &inner_data, &inner_len);
    heim_storage_free(inner);
    if (ret)
        return ret;

    /* Wrap as TPM2B (uint16 size + bytes) */
    ret = htpm2_marshal_tpm2b(sp, inner_data, inner_len);
    free(inner_data);
    return ret;
}

/*
 * Marshal TPM2B_PUBLIC: a TPM2B wrapping TPMT_PUBLIC.
 */
static int
marshal_inpublic(heim_storage *sp, htpm2_key_type type,
                 const void *policy, size_t policy_len)
{
    heim_storage *inner;
    void *inner_data;
    size_t inner_len;
    int ret;

    inner = heim_storage_emem();
    if (inner == NULL)
        return ENOMEM;

    ret = htpm2_marshal_key_template(inner, type, policy, policy_len);
    if (ret) {
        heim_storage_free(inner);
        return ret;
    }

    ret = heim_storage_to_data(inner, &inner_data, &inner_len);
    heim_storage_free(inner);
    if (ret)
        return ret;

    ret = htpm2_marshal_tpm2b(sp, inner_data, inner_len);
    free(inner_data);
    return ret;
}

/*
 * Skip over a TPM2B in the response storage (read and discard).
 */
static int
skip_tpm2b(heim_storage *sp)
{
    uint16_t size;
    int ret;

    ret = heim_ret_uint16(sp, &size);
    if (ret) return ret;
    if (size > 0)
        heim_storage_seek(sp, size, SEEK_CUR);
    return 0;
}

/*
 * Read a TPM2B from response storage into allocated memory.
 */
static int
read_tpm2b_alloc(heim_storage *sp, void **data, size_t *data_len)
{
    uint16_t size;
    int ret;

    ret = htpm2_unmarshal_tpm2b(sp, data, &size);
    if (ret) return ret;
    *data_len = size;
    return 0;
}

htpm2_result
htpm2_create_primary(const htpm2_context ctx,
                     htpm2_transport tp,
                     htpm2_result prior,
                     htpm2_session auth_session,
                     uint32_t hierarchy,
                     htpm2_key_type type,
                     const void *auth_value,
                     size_t auth_value_len,
                     const void *policy,
                     size_t policy_len,
                     htpm2_object *key)
{
    heim_storage *cmd, *rsp;
    uint32_t rc, handle;
    htpm2_result r;
    htpm2_object obj;
    void *pub_data = NULL, *name_data = NULL;
    size_t pub_len = 0, name_len = 0;
    int ret;

    if (prior.code)
        return prior;

    *key = NULL;

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "CreatePrimary: alloc");

    /*
     * CreatePrimary requires authorization for the hierarchy handle.
     * Use TPM_ST_SESSIONS with password auth (TPM_RS_PW).
     */
    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_SESSIONS,
                                   TPM2_CC_CreatePrimary);
    if (ret) goto marshal_err;

    /* primaryHandle (hierarchy) */
    ret = heim_store_uint32(cmd, hierarchy);
    if (ret) goto marshal_err;

    /* Authorization area size + password auth session */
    {
        /*
         * TPMS_AUTH_COMMAND for password auth:
         *   sessionHandle  = TPM_RS_PW (0x40000009)
         *   nonceCaller    = empty TPM2B (size=0)
         *   sessionAttributes = 0x01 (continueSession)
         *   hmac           = empty TPM2B (empty password)
         *
         * Total: 4 + 2 + 1 + 2 = 9 bytes
         */
        ret = heim_store_uint32(cmd, 9); /* authorizationSize */
        if (ret) goto marshal_err;
        ret = heim_store_uint32(cmd, 0x40000009); /* TPM_RS_PW */
        if (ret) goto marshal_err;
        ret = heim_store_uint16(cmd, 0); /* nonceCaller (empty) */
        if (ret) goto marshal_err;
        ret = heim_store_uint8(cmd, 0x01); /* sessionAttributes: continueSession */
        if (ret) goto marshal_err;
        ret = heim_store_uint16(cmd, 0); /* hmac (empty password) */
        if (ret) goto marshal_err;
    }

    /* inSensitive */
    ret = marshal_sensitive_create(cmd, auth_value, auth_value_len);
    if (ret) goto marshal_err;

    /* inPublic */
    ret = marshal_inpublic(cmd, type, policy, policy_len);
    if (ret) goto marshal_err;

    /* outsideInfo (empty TPM2B_DATA) */
    ret = htpm2_marshal_tpm2b(cmd, NULL, 0);
    if (ret) goto marshal_err;

    /* creationPCR (TPML_PCR_SELECTION with count=0) */
    ret = heim_store_uint32(cmd, 0);
    if (ret) goto marshal_err;

    /* Execute */
    r = htpm2_command_execute(ctx, tp, cmd, &rsp, &rc);
    heim_storage_free(cmd);
    cmd = NULL;
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "CreatePrimary");

    /* Response: objectHandle */
    ret = heim_ret_uint32(rsp, &handle);
    if (ret) goto unmarshal_err;

    /* parameterSize (TPM_ST_SESSIONS response) */
    {
        uint32_t param_size;
        ret = heim_ret_uint32(rsp, &param_size);
        if (ret) goto unmarshal_err;
    }

    /* outPublic (TPM2B_PUBLIC) */
    ret = read_tpm2b_alloc(rsp, &pub_data, &pub_len);
    if (ret) goto unmarshal_err;

    /* creationData (skip) */
    ret = skip_tpm2b(rsp);
    if (ret) goto unmarshal_err;

    /* creationHash (skip) */
    ret = skip_tpm2b(rsp);
    if (ret) goto unmarshal_err;

    /* creationTicket: tag(uint16) + hierarchy(uint32) + digest(TPM2B) */
    {
        uint16_t ttag;
        uint32_t thier;
        ret = heim_ret_uint16(rsp, &ttag);
        if (ret) goto unmarshal_err;
        ret = heim_ret_uint32(rsp, &thier);
        if (ret) goto unmarshal_err;
        ret = skip_tpm2b(rsp);
        if (ret) goto unmarshal_err;
    }

    /* name (TPM2B_NAME) */
    ret = read_tpm2b_alloc(rsp, &name_data, &name_len);
    if (ret) goto unmarshal_err;

    heim_storage_free(rsp);

    /* Build object */
    obj = htpm2_object_alloc(tp, handle);
    if (obj == NULL) {
        free(pub_data);
        free(name_data);
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "CreatePrimary: alloc object");
    }

    htpm2_object_set_pub(obj, pub_data, pub_len);
    htpm2_object_set_name(obj, name_data, name_len);
    if (auth_value && auth_value_len > 0)
        htpm2_object_set_auth(obj, auth_value, auth_value_len);

    free(pub_data);
    free(name_data);

    *key = obj;
    return HTPM2_OK;

marshal_err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "CreatePrimary: marshal error");

unmarshal_err:
    free(pub_data);
    free(name_data);
    heim_storage_free(rsp);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "CreatePrimary: unmarshal error");
}

/*
 * TPM2_Create -- create a child key under a loaded parent.
 *
 * Command layout (no sessions):
 *   header:       tag=NO_SESSIONS, CC=Create
 *   parentHandle: uint32
 *   inSensitive:  TPM2B_SENSITIVE_CREATE
 *   inPublic:     TPM2B_PUBLIC
 *   outsideInfo:  TPM2B_DATA (empty)
 *   creationPCR:  TPML_PCR_SELECTION (count=0)
 *
 * Response:
 *   outPrivate:   TPM2B_PRIVATE
 *   outPublic:    TPM2B_PUBLIC
 *   creationData: TPM2B_CREATION_DATA
 *   creationHash: TPM2B_DIGEST
 *   creationTicket: TPMT_TK_CREATION
 */
htpm2_result
htpm2_create(const htpm2_context ctx,
             htpm2_transport tp,
             htpm2_result prior,
             htpm2_session auth_session,
             htpm2_object parent,
             htpm2_key_type type,
             const void *auth_value,
             size_t auth_value_len,
             const void *policy,
             size_t policy_len,
             htpm2_object *key)
{
    heim_storage *cmd, *rsp;
    uint32_t rc, parent_handle;
    htpm2_result r;
    htpm2_object obj;
    void *priv_data = NULL, *pub_data = NULL;
    size_t priv_len = 0, pub_len = 0;
    int ret;

    if (prior.code)
        return prior;

    if (parent == NULL)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "Create: NULL parent");
    *key = NULL;
    parent_handle = htpm2_object_get_handle(parent);

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "Create: alloc");

    /* Create requires authorization for the parent handle */
    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_SESSIONS, TPM2_CC_Create);
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

    ret = marshal_sensitive_create(cmd, auth_value, auth_value_len);
    if (ret) goto marshal_err;

    ret = marshal_inpublic(cmd, type, policy, policy_len);
    if (ret) goto marshal_err;

    ret = htpm2_marshal_tpm2b(cmd, NULL, 0);  /* outsideInfo */
    if (ret) goto marshal_err;

    ret = heim_store_uint32(cmd, 0);  /* creationPCR count=0 */
    if (ret) goto marshal_err;

    r = htpm2_command_execute(ctx, tp, cmd, &rsp, &rc);
    heim_storage_free(cmd);
    cmd = NULL;
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "Create");

    /* Create response (TPM_ST_SESSIONS): parameterSize then params */
    {
        uint32_t param_size;
        ret = heim_ret_uint32(rsp, &param_size);
        if (ret) goto unmarshal_err;
    }

    /* outPrivate (TPM2B_PRIVATE) */
    ret = read_tpm2b_alloc(rsp, &priv_data, &priv_len);
    if (ret) goto unmarshal_err;

    /* outPublic (TPM2B_PUBLIC) */
    ret = read_tpm2b_alloc(rsp, &pub_data, &pub_len);
    if (ret) goto unmarshal_err;

    /* Skip creationData, creationHash, creationTicket */
    heim_storage_free(rsp);

    /* Build object (not loaded yet -- no TPM handle) */
    obj = htpm2_object_alloc(tp, 0);
    if (obj == NULL) {
        free(priv_data);
        free(pub_data);
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "Create: alloc object");
    }

    htpm2_object_set_pub(obj, pub_data, pub_len);
    htpm2_object_set_priv(obj, priv_data, priv_len);
    if (auth_value && auth_value_len > 0)
        htpm2_object_set_auth(obj, auth_value, auth_value_len);

    free(priv_data);
    free(pub_data);

    *key = obj;
    return HTPM2_OK;

marshal_err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "Create: marshal error");

unmarshal_err:
    free(priv_data);
    free(pub_data);
    heim_storage_free(rsp);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "Create: unmarshal error");
}
