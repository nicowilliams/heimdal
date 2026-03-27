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
 * TPM 2.0 command/response marshalling.
 * Uses heim_storage for big-endian serialization.
 */

#include "htpm2_locl.h"
#include "marshal.h"

int
htpm2_marshal_tpm2b(heim_storage *sp, const void *data, size_t len)
{
    int ret;

    if (len > UINT16_MAX)
        return ERANGE;
    ret = heim_store_uint16(sp, (uint16_t)len);
    if (ret)
        return ret;
    if (len > 0 && data != NULL)
        return heim_store_bytes(sp, data, len);
    if (len > 0 && data == NULL) {
        /* Write zero bytes */
        unsigned char zero[256];
        size_t done = 0;

        memset(zero, 0, sizeof(zero));
        while (done < len) {
            size_t chunk = len - done;
            if (chunk > sizeof(zero))
                chunk = sizeof(zero);
            ret = heim_store_bytes(sp, zero, chunk);
            if (ret)
                return ret;
            done += chunk;
        }
    }
    return 0;
}

int
htpm2_unmarshal_tpm2b(heim_storage *sp, void **data, uint16_t *len)
{
    uint16_t size;
    void *buf;
    int ret;

    *data = NULL;
    *len = 0;

    ret = heim_ret_uint16(sp, &size);
    if (ret)
        return ret;

    if (size == 0) {
        *len = 0;
        return 0;
    }

    buf = malloc(size);
    if (buf == NULL)
        return ENOMEM;

    ret = heim_ret_bytes(sp, buf, size);
    if (ret) {
        free(buf);
        return ret;
    }

    *data = buf;
    *len = size;
    return 0;
}

int
htpm2_marshal_cmd_header(heim_storage *sp, uint16_t tag, uint32_t cc)
{
    int ret;

    ret = heim_store_uint16(sp, tag);
    if (ret) return ret;
    /* Size placeholder -- will be fixed up later */
    ret = heim_store_uint32(sp, 0);
    if (ret) return ret;
    ret = heim_store_uint32(sp, cc);
    return ret;
}

int
htpm2_marshal_fixup_size(heim_storage *sp)
{
    off_t end, saved;
    uint32_t size;
    int ret;

    saved = heim_storage_seek(sp, 0, SEEK_CUR);
    end = saved;
    size = (uint32_t)end;

    /* Seek to offset 2 (after the tag) to patch the size field */
    heim_storage_seek(sp, 2, SEEK_SET);
    ret = heim_store_uint32(sp, size);
    heim_storage_seek(sp, end, SEEK_SET);
    return ret;
}

int
htpm2_unmarshal_rsp_header(heim_storage *sp, uint16_t *tag,
                           uint32_t *size, uint32_t *rc)
{
    int ret;

    ret = heim_ret_uint16(sp, tag);
    if (ret) return ret;
    ret = heim_ret_uint32(sp, size);
    if (ret) return ret;
    ret = heim_ret_uint32(sp, rc);
    return ret;
}

/*
 * Internal transport send_recv -- we need access to the transport internals
 * which are defined in transport.c.  For now we declare the function pointer
 * approach: the transport ops have a send_recv that we invoke.
 *
 * Actually, the transport structure and ops are internal to transport.c
 * but we need to call send_recv from here.  We expose a minimal internal
 * function in the transport.
 */

/* Declared in htpm2_locl.h or forward-declared here */
htpm2_result htpm2_transport_send_recv(htpm2_transport tp,
                                       const void *cmd, size_t cmd_len,
                                       void *rsp, size_t *rsp_len);

htpm2_result
htpm2_command_execute(const htpm2_context ctx,
                      htpm2_transport tp,
                      heim_storage *cmd_sp,
                      heim_storage **rsp_sp,
                      uint32_t *rc)
{
    void *cmd_data = NULL;
    size_t cmd_len = 0;
    unsigned char rsp_buf[4096];
    size_t rsp_len = sizeof(rsp_buf);
    heim_storage *rsp;
    uint16_t tag;
    uint32_t size;
    htpm2_result r;
    int ret;

    *rsp_sp = NULL;
    *rc = 0;

    /* Fix up command size */
    ret = htpm2_marshal_fixup_size(cmd_sp);
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "command: fixup_size failed");

    /* Extract command bytes */
    ret = heim_storage_to_data(cmd_sp, &cmd_data, &cmd_len);
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "command: storage_to_data failed");

    /* Send and receive */
    r = htpm2_transport_send_recv(tp, cmd_data, cmd_len, rsp_buf, &rsp_len);
    free(cmd_data);
    if (htpm2_is_err(r))
        return r;

    /* Parse response into a new storage */
    rsp = heim_storage_from_readonly_mem(rsp_buf, rsp_len);
    if (rsp == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "command: alloc response storage");

    ret = htpm2_unmarshal_rsp_header(rsp, &tag, &size, rc);
    if (ret) {
        heim_storage_free(rsp);
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "command: unmarshal response header");
    }

    if (*rc != TPM2_RC_SUCCESS) {
        heim_storage_free(rsp);
        return htpm2_result_tpm(*rc, "TPM error 0x%08x", *rc);
    }

    *rsp_sp = rsp;
    return HTPM2_OK;
}
