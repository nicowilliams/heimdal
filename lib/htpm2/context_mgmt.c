/*
 * Copyright (c) 2026 Kungliga Tekniska Högskolan
 * All rights reserved.  BSD 3-clause license.
 */

/*
 * TPM2_ContextSave and TPM2_ContextLoad -- save/load transient objects
 * to allow swapping when TPM memory is limited.
 *
 * ContextSave (no sessions):
 *   saveHandle: uint32
 * Response:
 *   context: TPMS_CONTEXT (blob of opaque TPM state)
 *
 * ContextLoad (no sessions):
 *   loadedContext: TPMS_CONTEXT
 * Response:
 *   loadedHandle: uint32
 */

#include "htpm2_locl.h"
#include "marshal.h"

htpm2_result
htpm2_context_save(const htpm2_context ctx,
                   htpm2_transport tp,
                   htpm2_result prior,
                   htpm2_object obj,
                   void **saved, size_t *saved_len)
{
    heim_storage *cmd, *rsp;
    uint32_t rc;
    htpm2_result r;
    int ret;

    if (prior.code)
        return prior;

    *saved = NULL;
    *saved_len = 0;

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "ContextSave: alloc");

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS,
                                   TPM2_CC_ContextSave);
    if (ret) goto marshal_err;
    ret = heim_store_uint32(cmd, htpm2_object_get_handle(obj));
    if (ret) goto marshal_err;

    r = htpm2_command_execute(ctx, tp, cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "ContextSave");

    /* Read the entire TPMS_CONTEXT as an opaque blob */
    {
        off_t pos = heim_storage_seek(rsp, 0, SEEK_CUR);
        off_t end = heim_storage_seek(rsp, 0, SEEK_END);
        size_t blob_len = end - pos;

        if (blob_len > 0) {
            *saved = malloc(blob_len);
            if (*saved == NULL) {
                heim_storage_free(rsp);
                return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                          "ContextSave: alloc blob");
            }
            heim_storage_seek(rsp, pos, SEEK_SET);
            heim_ret_bytes(rsp, *saved, blob_len);
            *saved_len = blob_len;
        }
    }

    heim_storage_free(rsp);
    return HTPM2_OK;

marshal_err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "ContextSave: marshal");
}

htpm2_result
htpm2_context_load(const htpm2_context ctx,
                   htpm2_transport tp,
                   htpm2_result prior,
                   const void *saved, size_t saved_len,
                   htpm2_object *obj)
{
    heim_storage *cmd, *rsp;
    uint32_t rc, handle;
    htpm2_result r;
    int ret;

    if (prior.code)
        return prior;

    *obj = NULL;

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "ContextLoad: alloc");

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS,
                                   TPM2_CC_ContextLoad);
    if (ret) goto marshal_err;
    ret = heim_store_bytes(cmd, saved, saved_len);
    if (ret) goto marshal_err;

    r = htpm2_command_execute(ctx, tp, cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "ContextLoad");

    ret = heim_ret_uint32(rsp, &handle);
    heim_storage_free(rsp);
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "ContextLoad: unmarshal handle");

    *obj = htpm2_object_alloc(tp, handle);
    if (*obj == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "ContextLoad: alloc object");

    return HTPM2_OK;

marshal_err:
    heim_storage_free(cmd);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "ContextLoad: marshal");
}
