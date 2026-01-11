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
 * Configure TLS backend for client mode
 */
static OM_uint32
configure_client(OM_uint32 *minor, gss_tls_ctx ctx,
                 const struct gss_tls_cred_desc *cred,
                 gss_const_name_t target_name)
{
    tls_backend_config config;
    tls_backend_status status;

    memset(&config, 0, sizeof(config));
    config.hctx = ctx->hctx;
    config.hx509ctx = ctx->hx509ctx;
    config.mode = TLS_BACKEND_CLIENT;
    config.verify_peer = 1;

    if (cred) {
        config.certs = cred->certs;
        config.key = cred->key;
        config.trust_anchors = cred->trust_anchors;
        config.revoke = cred->revoke;
    }

    /* Set SNI hostname if we have a hostbased target name */
    if (target_name != GSS_C_NO_NAME) {
        const struct gss_tls_name_desc *name =
            (const struct gss_tls_name_desc *)target_name;
        if (name->type == GSS_TLS_NAME_HOSTBASED && name->u.hostbased.hostname) {
            config.hostname = name->u.hostbased.hostname;
            heim_debug(ctx->hctx, 5, "GSS-TLS: SNI hostname: %s", config.hostname);
        }
    }

    /* Initialize I/O buffers */
    if (tls_iobuf_init(&ctx->recv_buf, GSS_TLS_SEND_BUF_INITIAL_CAPACITY) != 0) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    if (tls_iobuf_init(&ctx->send_buf, GSS_TLS_SEND_BUF_INITIAL_CAPACITY) != 0) {
        tls_iobuf_free(&ctx->recv_buf);
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    /* Initialize TLS backend */
    status = tls_backend_init(&ctx->backend, &config,
                              &ctx->recv_buf, &ctx->send_buf);
    if (status != TLS_BACKEND_OK) {
        tls_iobuf_free(&ctx->recv_buf);
        tls_iobuf_free(&ctx->send_buf);
        *minor = EINVAL;
        return GSS_S_FAILURE;
    }

    return GSS_S_COMPLETE;
}

/*
 * Extract peer identity after successful handshake
 */
static void
extract_peer_identity(gss_tls_ctx ctx)
{
    tls_backend_status status;
    hx509_cert peer_cert = NULL;
    OM_uint32 minor;

    /* Get peer certificate from backend */
    status = tls_backend_get_peer_cert(ctx->backend, ctx->hx509ctx, &peer_cert);
    if (status == TLS_BACKEND_OK && peer_cert != NULL) {
        ctx->peer_cert = peer_cert;

        /* Create name from certificate */
        if (_gss_tls_name_from_cert(&minor, ctx->hx509ctx, peer_cert,
                                     &ctx->peer_name) == GSS_S_COMPLETE) {
            heim_debug(ctx->hctx, 5, "GSS-TLS: extracted server identity from certificate");
        } else {
            /* Failed to extract name - shouldn't happen */
            heim_debug(ctx->hctx, 1, "GSS-TLS: failed to extract server identity");
            ctx->peer_name = _gss_tls_anonymous_identity;
        }
    } else {
        /* Anonymous peer (shouldn't happen for TLS server) */
        ctx->peer_name = _gss_tls_anonymous_identity;
    }
}

/*
 * GSS-API init_sec_context for TLS mechanism
 *
 * Initiates a TLS handshake as a client. Input/output tokens
 * are raw TLS records.
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_init_sec_context(OM_uint32 *minor,
                          gss_const_cred_id_t cred_handle,
                          gss_ctx_id_t *context_handle,
                          gss_const_name_t target_name,
                          const gss_OID mech_type,
                          OM_uint32 req_flags,
                          OM_uint32 time_req,
                          const gss_channel_bindings_t input_chan_bindings,
                          const gss_buffer_t input_token,
                          gss_OID *actual_mech_type,
                          gss_buffer_t output_token,
                          OM_uint32 *ret_flags,
                          OM_uint32 *time_rec)
{
    gss_tls_ctx ctx;
    const struct gss_tls_cred_desc *cred =
        (const struct gss_tls_cred_desc *)cred_handle;
    OM_uint32 major = GSS_S_COMPLETE;
    tls_backend_status status;

    (void)mech_type;
    (void)req_flags;
    (void)time_req;
    (void)input_chan_bindings; /* TODO: TLS channel bindings */

    *minor = 0;
    if (output_token != GSS_C_NO_BUFFER) {
        output_token->length = 0;
        output_token->value = NULL;
    }

    ctx = (gss_tls_ctx)*context_handle;

    /* First call: allocate context and configure TLS backend */
    if (ctx == NULL) {
        /* Validate: first call should have no input token */
        if (input_token != GSS_C_NO_BUFFER && input_token->length != 0) {
            *minor = EINVAL;
            return GSS_S_DEFECTIVE_TOKEN;
        }

        ctx = calloc(1, sizeof(*ctx));
        if (ctx == NULL) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }

        ctx->is_initiator = 1;
        ctx->cred = cred;

        /* Initialize tracing context */
        gss_tls_trace_init(&ctx->hctx);
        heim_debug(ctx->hctx, 5, "GSS-TLS: initiating context (client)");

        /* Initialize hx509 context */
        if (hx509_context_init(&ctx->hx509ctx) != 0) {
            *minor = ENOMEM;
            free(ctx);
            return GSS_S_FAILURE;
        }

        /* Configure TLS backend for client mode */
        major = configure_client(minor, ctx, cred, target_name);
        if (major != GSS_S_COMPLETE) {
            hx509_context_free(&ctx->hx509ctx);
            free(ctx);
            return major;
        }

        *context_handle = (gss_ctx_id_t)ctx;
    }

    /* Provide input token data to recv buffer */
    if (input_token != GSS_C_NO_BUFFER && input_token->length > 0) {
        heim_debug(ctx->hctx, 10, "GSS-TLS: received %zu bytes", input_token->length);
        tls_iobuf_reset(&ctx->recv_buf);
        if (tls_iobuf_append(&ctx->recv_buf, input_token->value,
                             input_token->length) != 0) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }
    }

    /* Clear output buffer for this round */
    tls_iobuf_reset(&ctx->send_buf);

    /* Drive TLS handshake */
    status = tls_backend_handshake(ctx->backend);

    /* Return any TLS records that were generated */
    if (ctx->send_buf.len > 0 && output_token != GSS_C_NO_BUFFER) {
        heim_debug(ctx->hctx, 10, "GSS-TLS: sending %zu bytes", ctx->send_buf.len);
        output_token->value = malloc(ctx->send_buf.len);
        if (output_token->value == NULL) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }
        memcpy(output_token->value, ctx->send_buf.data, ctx->send_buf.len);
        output_token->length = ctx->send_buf.len;
    }

    if (status == TLS_BACKEND_OK) {
        /* Handshake complete */
        heim_debug(ctx->hctx, 5, "GSS-TLS: handshake complete");
        ctx->handshake_done = 1;
        ctx->open = 1;
        ctx->established_time = time(NULL);

        /* Extract peer identity from certificate */
        extract_peer_identity(ctx);

        /* Set return flags */
        ctx->flags = GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG |
                     GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG |
                     GSS_C_TRANS_FLAG;

        if (ctx->peer_name == _gss_tls_anonymous_identity ||
            ctx->peer_name == GSS_C_NO_NAME) {
            /* Server didn't authenticate (shouldn't happen in TLS) */
        } else {
            ctx->flags |= GSS_C_MUTUAL_FLAG;
        }

        if (ret_flags)
            *ret_flags = ctx->flags;
        if (time_rec)
            *time_rec = GSS_C_INDEFINITE;

        major = GSS_S_COMPLETE;
    } else if (status == TLS_BACKEND_WANT_READ ||
               status == TLS_BACKEND_WANT_WRITE) {
        /* Need more data - continue handshake */
        heim_debug(ctx->hctx, 10, "GSS-TLS: handshake continue needed (want %s)",
                   status == TLS_BACKEND_WANT_READ ? "read" : "write");
        if (ret_flags)
            *ret_flags = 0;
        if (time_rec)
            *time_rec = 0;

        major = GSS_S_CONTINUE_NEEDED;
    } else {
        /* Error */
        heim_debug(ctx->hctx, 1, "GSS-TLS: handshake error: %s",
                   tls_backend_get_error(ctx->backend));
        *minor = EPROTO;
        major = GSS_S_FAILURE;
    }

    if (actual_mech_type)
        *actual_mech_type = GSS_TLS_MECHANISM;

    return major;
}
