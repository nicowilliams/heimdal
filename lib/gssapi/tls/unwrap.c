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
 * GSS-API unwrap for TLS mechanism
 *
 * Decrypts TLS application data records and returns the plaintext.
 * Input token must be raw TLS records.
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_unwrap(OM_uint32 *minor,
                gss_const_ctx_id_t context_handle,
                const gss_buffer_t input,
                gss_buffer_t output,
                int *conf_state,
                gss_qop_t *qop_state)
{
#ifdef HAVE_S2N
    gss_tls_ctx ctx = (gss_tls_ctx)context_handle;
    s2n_blocked_status blocked;
    uint8_t *out_buf = NULL;
    size_t out_capacity = 0;
    size_t out_len = 0;
    ssize_t received;

    *minor = 0;
    output->length = 0;
    output->value = NULL;

    if (conf_state)
        *conf_state = 1; /* TLS always encrypts */
    if (qop_state)
        *qop_state = GSS_C_QOP_DEFAULT;

    /* Validate context */
    if (ctx == NULL || !ctx->open) {
        *minor = EINVAL;
        return GSS_S_NO_CONTEXT;
    }

    /* Must have input */
    if (input == GSS_C_NO_BUFFER || input->length == 0) {
        *minor = EINVAL;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    /* Provide input token to recv callback */
    ctx->recv_buf.data = input->value;
    ctx->recv_buf.len = input->length;
    ctx->recv_buf.pos = 0;

    /* Initial output buffer - will grow as needed */
    out_capacity = input->length; /* Plaintext is smaller than ciphertext */
    out_buf = malloc(out_capacity);
    if (out_buf == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    /* Read decrypted data from TLS */
    do {
        /* Ensure we have space */
        if (out_len >= out_capacity) {
            size_t new_cap = out_capacity * 2;
            uint8_t *new_buf = realloc(out_buf, new_cap);
            if (new_buf == NULL) {
                free(out_buf);
                *minor = ENOMEM;
                return GSS_S_FAILURE;
            }
            out_buf = new_buf;
            out_capacity = new_cap;
        }

        received = s2n_recv(ctx->conn,
                           out_buf + out_len,
                           out_capacity - out_len,
                           &blocked);

        if (received > 0) {
            out_len += received;
        } else if (received == 0) {
            /* Connection closed */
            ctx->closed = 1;
            break;
        } else {
            if (s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED) {
                /* Would block - no more data available */
                break;
            }
            /* Check for close_notify */
            if (s2n_error_get_type(s2n_errno) == S2N_ERR_T_CLOSED) {
                ctx->closed = 1;
                break;
            }
            /* Other error */
            free(out_buf);
            *minor = s2n_errno;
            return GSS_S_FAILURE;
        }
    } while (ctx->recv_buf.pos < ctx->recv_buf.len);

    if (out_len > 0) {
        output->value = out_buf;
        output->length = out_len;
    } else {
        free(out_buf);
        /* No data extracted - might be just TLS control records */
        if (ctx->closed) {
            return GSS_S_CONTEXT_EXPIRED;
        }
    }

    return GSS_S_COMPLETE;

#else /* !HAVE_S2N */
    (void)context_handle;
    (void)input;
    (void)output;
    (void)conf_state;
    (void)qop_state;

    *minor = ENOTSUP;
    return GSS_S_UNAVAILABLE;
#endif /* HAVE_S2N */
}

/*
 * GSS-API verify_mic for TLS mechanism
 *
 * TLS does not support standalone MIC tokens - integrity protection
 * is always combined with confidentiality. This returns an error.
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_verify_mic(OM_uint32 *minor,
                    gss_const_ctx_id_t context_handle,
                    const gss_buffer_t message,
                    const gss_buffer_t token,
                    gss_qop_t *qop_state)
{
    (void)context_handle;
    (void)message;
    (void)token;
    (void)qop_state;

    /* TLS does not support standalone MIC tokens */
    *minor = ENOTSUP;
    return GSS_S_UNAVAILABLE;
}
