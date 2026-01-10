/*
 * Copyright (c) 2024, Heimdal project
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

#include "tls_locl.h"

#include <errno.h>

/*
 * GSS-API wrap for TLS mechanism
 *
 * Encrypts message data using TLS and returns raw TLS application
 * data records as the output token.
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_wrap(OM_uint32 *minor,
              gss_const_ctx_id_t context_handle,
              int conf_req,
              gss_qop_t qop,
              const gss_buffer_t input,
              int *conf_state,
              gss_buffer_t output)
{
    /* Cast away const - we need to modify I/O buffers */
    gss_tls_ctx ctx = (gss_tls_ctx)(uintptr_t)context_handle;
    tls_backend_status status;

    (void)conf_req; /* TLS always encrypts */

    *minor = 0;
    output->length = 0;
    output->value = NULL;

    if (conf_state)
        *conf_state = 1; /* TLS always encrypts */

    /* Validate context */
    if (ctx == NULL || !ctx->open) {
        *minor = EINVAL;
        return GSS_S_NO_CONTEXT;
    }

    /* TLS always provides confidentiality */
    if (qop != GSS_C_QOP_DEFAULT) {
        *minor = EINVAL;
        return GSS_S_BAD_QOP;
    }

    /* Clear output buffer for this operation */
    tls_iobuf_reset(&ctx->send_buf);

    /* Send data through TLS - this will encrypt and buffer records */
    status = tls_backend_encrypt(ctx->backend, input->value, input->length);
    if (status != TLS_BACKEND_OK) {
        *minor = EPROTO;
        return GSS_S_FAILURE;
    }

    /* Copy buffered TLS records to output token */
    if (ctx->send_buf.len > 0) {
        output->value = malloc(ctx->send_buf.len);
        if (output->value == NULL) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }
        memcpy(output->value, ctx->send_buf.data, ctx->send_buf.len);
        output->length = ctx->send_buf.len;
    }

    return GSS_S_COMPLETE;
}

/*
 * GSS-API get_mic for TLS mechanism
 *
 * TLS does not support standalone MIC tokens - integrity protection
 * is always combined with confidentiality. This returns an error.
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_get_mic(OM_uint32 *minor,
                 gss_const_ctx_id_t context_handle,
                 gss_qop_t qop,
                 const gss_buffer_t message,
                 gss_buffer_t token)
{
    (void)context_handle;
    (void)qop;
    (void)message;
    (void)token;

    /* TLS does not support standalone MIC tokens */
    *minor = ENOTSUP;
    return GSS_S_UNAVAILABLE;
}

/*
 * GSS-API wrap_size_limit for TLS mechanism
 *
 * Returns the maximum input message size that will fit in an output
 * token of the specified size, accounting for TLS record overhead.
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_wrap_size_limit(OM_uint32 *minor,
                         gss_const_ctx_id_t context_handle,
                         int conf_req,
                         gss_qop_t qop_req,
                         OM_uint32 req_output_size,
                         OM_uint32 *max_input_size)
{
    const struct gss_tls_ctx_desc *ctx =
        (const struct gss_tls_ctx_desc *)context_handle;

    (void)conf_req;
    (void)qop_req;

    *minor = 0;

    if (ctx == NULL || !ctx->open) {
        *minor = EINVAL;
        return GSS_S_NO_CONTEXT;
    }

    /*
     * TLS record overhead:
     * - 5 bytes record header
     * - Up to 256 bytes padding (TLS 1.3)
     * - 16 bytes AEAD tag (typical for modern ciphers)
     *
     * Conservative estimate: 300 bytes overhead per record
     * TLS maximum record size: 16384 bytes
     */
    if (req_output_size <= 300) {
        *max_input_size = 0;
    } else if (req_output_size > 16384) {
        /* Can't exceed TLS record size */
        *max_input_size = 16384 - 300;
    } else {
        *max_input_size = req_output_size - 300;
    }

    return GSS_S_COMPLETE;
}
