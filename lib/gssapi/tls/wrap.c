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

#ifdef HAVE_S2N
#include <s2n.h>
#endif

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
#ifdef HAVE_S2N
    gss_tls_ctx ctx = (gss_tls_ctx)context_handle;
    s2n_blocked_status blocked;
    ssize_t written;
    size_t total_written = 0;

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
    ctx->send_buf.len = 0;

    /* Send data through TLS - this will encrypt and buffer records */
    while (total_written < input->length) {
        written = s2n_send(ctx->conn,
                          (uint8_t *)input->value + total_written,
                          input->length - total_written,
                          &blocked);
        if (written < 0) {
            if (s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED) {
                /* Would block - but we're using memory I/O, so this
                 * means output buffer is full. Return what we have. */
                break;
            }
            *minor = s2n_errno;
            return GSS_S_FAILURE;
        }
        total_written += written;
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

#else /* !HAVE_S2N */
    (void)context_handle;
    (void)conf_req;
    (void)qop;
    (void)input;
    (void)conf_state;
    (void)output;

    *minor = ENOTSUP;
    return GSS_S_UNAVAILABLE;
#endif /* HAVE_S2N */
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
    gss_tls_ctx ctx = (gss_tls_ctx)context_handle;

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
