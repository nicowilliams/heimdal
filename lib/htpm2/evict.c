/*
 * Copyright (c) 2026 Kungliga Tekniska Högskolan
 * All rights reserved.  BSD 3-clause license.
 */

/*
 * TPM2_EvictControl -- make a transient key persistent, or evict a
 * persistent key.
 *
 * Command (with session on auth -- the hierarchy owner):
 *   auth:             uint32 (hierarchy: OWNER or PLATFORM)
 *   objectHandle:     uint32 (transient or persistent handle)
 *   persistentHandle: uint32 (desired persistent handle 0x81xxxxxx)
 *
 * If objectHandle is transient and persistentHandle is in persistent
 * range: make persistent.
 * If objectHandle is persistent: evict (delete) it.
 */

#include "htpm2_locl.h"
#include "marshal.h"

htpm2_result
htpm2_evict_control(const htpm2_context ctx,
                    htpm2_transport tp,
                    htpm2_result prior,
                    htpm2_session auth_session,
                    htpm2_object key,
                    uint32_t persistent_handle)
{
    heim_storage *param_sp, *rsp;
    uint32_t rc, handles[2];
    void *param_data = NULL;
    size_t param_len = 0;
    htpm2_result r;
    int ret;

    if (prior.code)
        return prior;

    /* auth = OWNER hierarchy, objectHandle = the key */
    handles[0] = HTPM2_HIERARCHY_OWNER;
    handles[1] = htpm2_object_get_handle(key);

    /* The only parameter is the persistent handle */
    param_sp = heim_storage_emem();
    if (param_sp == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "EvictControl: alloc");

    ret = heim_store_uint32(param_sp, persistent_handle);
    if (ret) {
        heim_storage_free(param_sp);
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "EvictControl: marshal");
    }

    ret = heim_storage_to_data(param_sp, &param_data, &param_len);
    heim_storage_free(param_sp);
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "EvictControl: to_data");

    r = htpm2_command_execute_with_auth(ctx, tp, TPM2_CC_EvictControl,
                                        handles, 2, auth_session,
                                        param_data, param_len, &rsp, &rc);
    free(param_data);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "EvictControl");

    heim_storage_free(rsp);
    return HTPM2_OK;
}
