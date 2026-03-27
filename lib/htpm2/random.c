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
 * TPM2_GetRandom -- request random bytes from the TPM.
 *
 * Command:
 *   tag:         TPM_ST_NO_SESSIONS (0x8001)
 *   size:        14 (header=10 + bytesRequested=2)
 *   commandCode: TPM2_CC_GetRandom (0x0000017B)
 *   bytesRequested: uint16
 *
 * Response:
 *   tag:         TPM_ST_NO_SESSIONS
 *   size:        12 + randomBytes.size
 *   responseCode: uint32
 *   randomBytes: TPM2B_DIGEST (uint16 size + bytes)
 */

#include "htpm2_locl.h"
#include "marshal.h"

htpm2_result
htpm2_get_random(const htpm2_context ctx,
                 htpm2_transport tp,
                 htpm2_result prior,
                 void *buf, size_t len)
{
    size_t done = 0;

    if (prior.code)
        return prior;

    if (buf == NULL || len == 0)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "GetRandom: invalid arguments");

    /*
     * TPM2_GetRandom can return at most ~48 bytes per call (TPM-dependent),
     * so we loop to fill the buffer.
     */
    while (done < len) {
        heim_storage *cmd, *rsp;
        uint32_t rc;
        uint16_t request, got;
        void *random_data = NULL;
        htpm2_result r;
        int ret;

        request = (uint16_t)((len - done) > 48 ? 48 : (len - done));

        cmd = heim_storage_emem();
        if (cmd == NULL)
            return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                      "GetRandom: alloc");

        ret = htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS,
                                       TPM2_CC_GetRandom);
        if (ret == 0)
            ret = heim_store_uint16(cmd, request);
        if (ret) {
            heim_storage_free(cmd);
            return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                      "GetRandom: marshal");
        }

        r = htpm2_command_execute(ctx, tp, cmd, &rsp, &rc);
        heim_storage_free(cmd);
        if (htpm2_is_err(r))
            return htpm2_result_prepend(r, "GetRandom");

        /* Unmarshal TPM2B_DIGEST response */
        ret = htpm2_unmarshal_tpm2b(rsp, &random_data, &got);
        heim_storage_free(rsp);
        if (ret)
            return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                      "GetRandom: unmarshal response");

        if (got == 0 || random_data == NULL) {
            free(random_data);
            return htpm2_result_local(EIO, HTPM2_F_TRANSPORT, EIO,
                                      "GetRandom: TPM returned 0 bytes");
        }

        if (got > request)
            got = request;
        if (done + got > len)
            got = len - done;

        memcpy((unsigned char *)buf + done, random_data, got);
        free(random_data);
        done += got;
    }

    return HTPM2_OK;
}
