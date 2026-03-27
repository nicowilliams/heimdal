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
 * Basic TPM 2.0 commands that don't require sessions or loaded objects.
 */

#include "htpm2_locl.h"
#include "marshal.h"

/*
 * TPM2_Startup -- must be called once after TPM reset.
 * Not exposed in the public API; called internally when needed.
 *
 * Command: tag=TPM_ST_NO_SESSIONS, CC=TPM2_CC_Startup, startupType=uint16
 * Response: tag, size, rc (no parameters on success)
 */
htpm2_result
htpm2_startup(const htpm2_context ctx, htpm2_transport tp,
              htpm2_result prior, uint16_t startup_type)
{
    heim_storage *cmd, *rsp;
    uint32_t rc;
    htpm2_result r;
    int ret;

    if (prior.code)
        return prior;

    cmd = heim_storage_emem();
    if (cmd == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "Startup: alloc");

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS, TPM2_CC_Startup);
    if (ret == 0)
        ret = heim_store_uint16(cmd, startup_type);
    if (ret) {
        heim_storage_free(cmd);
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "Startup: marshal");
    }

    r = htpm2_command_execute(ctx, tp, cmd, &rsp, &rc);
    heim_storage_free(cmd);
    if (htpm2_is_ok(r))
        heim_storage_free(rsp);
    return r;
}
