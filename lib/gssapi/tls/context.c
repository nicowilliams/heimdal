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
 * GSS-API delete_sec_context for TLS mechanism
 *
 * Closes the TLS connection and frees the context.
 * If output_token is provided, generates a TLS close_notify alert.
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_delete_sec_context(OM_uint32 *minor,
                            gss_ctx_id_t *context_handle,
                            gss_buffer_t output_token)
{
    gss_tls_ctx ctx;

    *minor = 0;

    if (output_token != GSS_C_NO_BUFFER) {
        output_token->length = 0;
        output_token->value = NULL;
    }

    if (context_handle == NULL || *context_handle == GSS_C_NO_CONTEXT)
        return GSS_S_COMPLETE;

    ctx = (gss_tls_ctx)*context_handle;

    heim_debug(ctx->hctx, 5, "GSS-TLS: deleting context");

    /* Generate close_notify if output token requested and connection is open */
    if (output_token != GSS_C_NO_BUFFER && ctx->backend && ctx->open && !ctx->closed) {
        /* Clear output buffer */
        tls_iobuf_reset(&ctx->send_buf);

        /* Send TLS close_notify */
        tls_backend_close(ctx->backend);

        /* Return any generated TLS records */
        if (ctx->send_buf.len > 0) {
            output_token->value = malloc(ctx->send_buf.len);
            if (output_token->value != NULL) {
                memcpy(output_token->value, ctx->send_buf.data, ctx->send_buf.len);
                output_token->length = ctx->send_buf.len;
            }
        }
    }

    /* Clean up TLS backend */
    if (ctx->backend) {
        tls_backend_destroy(ctx->backend);
        ctx->backend = NULL;
    }

    /* Clean up I/O buffers */
    tls_iobuf_free(&ctx->send_buf);
    tls_iobuf_free(&ctx->recv_buf);

    /* Clean up hx509 resources */
    if (ctx->peer_cert)
        hx509_cert_free(ctx->peer_cert);
    if (ctx->hx509ctx)
        hx509_context_free(&ctx->hx509ctx);

    /* Release peer name if not the anonymous singleton */
    if (ctx->peer_name && ctx->peer_name != _gss_tls_anonymous_identity) {
        gss_release_name(minor, &ctx->peer_name);
    }

    /* Don't free ctx->cred - it's borrowed */

    /* Clean up tracing context */
    if (ctx->hctx)
        heim_context_free(&ctx->hctx);

    memset(ctx, 0, sizeof(*ctx));
    free(ctx);
    *context_handle = GSS_C_NO_CONTEXT;

    return GSS_S_COMPLETE;
}

/*
 * GSS-API process_context_token for TLS mechanism
 *
 * Processes incoming TLS alert records (like close_notify from peer).
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_process_context_token(OM_uint32 *minor,
                               gss_const_ctx_id_t context_handle,
                               const gss_buffer_t token)
{
    gss_tls_ctx ctx;
    tls_backend_status status;
    uint8_t buf[1];
    size_t len = sizeof(buf);

    *minor = 0;

    if (context_handle == GSS_C_NO_CONTEXT) {
        *minor = EINVAL;
        return GSS_S_NO_CONTEXT;
    }

    /* Cast away const - we need to modify state */
    ctx = (gss_tls_ctx)(uintptr_t)context_handle;

    if (token == GSS_C_NO_BUFFER || token->length == 0) {
        *minor = EINVAL;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    /* Provide token to recv buffer */
    tls_iobuf_reset(&ctx->recv_buf);
    if (tls_iobuf_append(&ctx->recv_buf, token->value, token->length) != 0) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    /* Try to read - this will process any TLS records including alerts */
    status = tls_backend_decrypt(ctx->backend, buf, &len);

    /* Check if connection was closed */
    if (status == TLS_BACKEND_CLOSED || status == TLS_BACKEND_EOF) {
        ctx->closed = 1;
    }

    return GSS_S_COMPLETE;
}

/*
 * GSS-API context_time for TLS mechanism
 *
 * TLS contexts don't have a built-in expiration time.
 * Returns GSS_C_INDEFINITE for established contexts.
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_context_time(OM_uint32 *minor,
                      gss_const_ctx_id_t context_handle,
                      OM_uint32 *time_rec)
{
    const struct gss_tls_ctx_desc *ctx =
        (const struct gss_tls_ctx_desc *)context_handle;

    *minor = 0;

    if (ctx == NULL) {
        *minor = EINVAL;
        return GSS_S_NO_CONTEXT;
    }

    if (!ctx->open) {
        *time_rec = 0;
        return GSS_S_NO_CONTEXT;
    }

    if (ctx->closed) {
        *time_rec = 0;
        return GSS_S_CONTEXT_EXPIRED;
    }

    *time_rec = GSS_C_INDEFINITE;
    return GSS_S_COMPLETE;
}

/*
 * GSS-API inquire_context for TLS mechanism
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_inquire_context(OM_uint32 *minor,
                         gss_const_ctx_id_t context_handle,
                         gss_name_t *src_name,
                         gss_name_t *targ_name,
                         OM_uint32 *lifetime_rec,
                         gss_OID *mech_type,
                         OM_uint32 *ctx_flags,
                         int *locally_initiated,
                         int *open)
{
    const struct gss_tls_ctx_desc *ctx =
        (const struct gss_tls_ctx_desc *)context_handle;
    OM_uint32 major;

    *minor = 0;

    if (src_name)
        *src_name = GSS_C_NO_NAME;
    if (targ_name)
        *targ_name = GSS_C_NO_NAME;
    if (lifetime_rec)
        *lifetime_rec = 0;
    if (mech_type)
        *mech_type = GSS_C_NO_OID;
    if (ctx_flags)
        *ctx_flags = 0;
    if (locally_initiated)
        *locally_initiated = 0;
    if (open)
        *open = 0;

    if (ctx == NULL) {
        *minor = EINVAL;
        return GSS_S_NO_CONTEXT;
    }

    /* Source name - for initiator this is our identity, for acceptor it's peer */
    if (src_name) {
        if (ctx->is_initiator) {
            /* TODO: Extract from our credential */
        } else {
            /* Client identity from certificate */
            if (ctx->peer_name) {
                major = _gss_tls_duplicate_name(minor, ctx->peer_name, src_name);
                if (major != GSS_S_COMPLETE)
                    return major;
            }
        }
    }

    /* Target name - for initiator this is peer, for acceptor it's us */
    if (targ_name) {
        if (ctx->is_initiator) {
            /* Server identity from certificate */
            if (ctx->peer_name) {
                major = _gss_tls_duplicate_name(minor, ctx->peer_name, targ_name);
                if (major != GSS_S_COMPLETE) {
                    if (src_name && *src_name != GSS_C_NO_NAME)
                        _gss_tls_release_name(minor, src_name);
                    return major;
                }
            }
        } else {
            /* TODO: Extract from our credential */
        }
    }

    if (lifetime_rec) {
        if (ctx->open && !ctx->closed)
            *lifetime_rec = GSS_C_INDEFINITE;
        else
            *lifetime_rec = 0;
    }

    if (mech_type)
        *mech_type = GSS_TLS_MECHANISM;

    if (ctx_flags)
        *ctx_flags = ctx->flags;

    if (locally_initiated)
        *locally_initiated = ctx->is_initiator;

    if (open)
        *open = ctx->open && !ctx->closed;

    return GSS_S_COMPLETE;
}

/*
 * GSS-API display_status for TLS mechanism
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_display_status(OM_uint32 *minor,
                        OM_uint32 status_value,
                        int status_type,
                        const gss_OID mech_type,
                        OM_uint32 *message_context,
                        gss_buffer_t status_string)
{
    const char *msg;

    (void)mech_type;

    *minor = 0;
    status_string->length = 0;
    status_string->value = NULL;

    if (message_context)
        *message_context = 0;

    if (status_type == GSS_C_GSS_CODE) {
        /* Major status codes handled by GSS-API layer */
        return GSS_S_UNAVAILABLE;
    }

    /* Minor status - try strerror for system errors */
    msg = strerror((int)status_value);
    if (msg) {
        status_string->value = strdup(msg);
        if (status_string->value == NULL) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }
        status_string->length = strlen(msg);
        return GSS_S_COMPLETE;
    }

    return GSS_S_UNAVAILABLE;
}

/*
 * GSS-API inquire_sec_context_by_oid for TLS mechanism
 *
 * Supports channel binding extraction OIDs:
 *   GSS_C_INQ_CB_TLS_SERVER_END_POINT - RFC 5929 tls-server-end-point
 *   GSS_C_INQ_CB_TLS_UNIQUE           - RFC 5929 tls-unique (TLS 1.2 only)
 *   GSS_C_INQ_CB_TLS_EXPORTER         - RFC 9266 tls-exporter
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_inquire_sec_context_by_oid(OM_uint32 *minor,
                                    gss_const_ctx_id_t context_handle,
                                    const gss_OID desired_object,
                                    gss_buffer_set_t *data_set)
{
    const struct gss_tls_ctx_desc *ctx =
        (const struct gss_tls_ctx_desc *)context_handle;
    uint8_t cb_buf[64];  /* Max size: SHA-512 hash (64 bytes) */
    size_t cb_len = sizeof(cb_buf);
    tls_backend_status status;
    gss_buffer_desc buf;
    OM_uint32 major;

    *minor = 0;
    *data_set = GSS_C_NO_BUFFER_SET;

    if (ctx == NULL) {
        *minor = EINVAL;
        return GSS_S_NO_CONTEXT;
    }

    if (!ctx->open) {
        *minor = EINVAL;
        return GSS_S_NO_CONTEXT;
    }

    if (desired_object == GSS_C_NO_OID) {
        *minor = EINVAL;
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    /* Check for channel binding extraction OIDs */
    if (gss_oid_equal(desired_object, GSS_C_INQ_CB_TLS_SERVER_END_POINT)) {
        heim_debug(ctx->hctx, 5, "GSS-TLS: inquire tls-server-end-point CB");
        status = tls_backend_get_cb_server_end_point(ctx->backend,
                                                     !ctx->is_initiator,
                                                     cb_buf, &cb_len);
    } else if (gss_oid_equal(desired_object, GSS_C_INQ_CB_TLS_UNIQUE)) {
        heim_debug(ctx->hctx, 5, "GSS-TLS: inquire tls-unique CB");
        status = tls_backend_get_cb_unique(ctx->backend, cb_buf, &cb_len);
    } else if (gss_oid_equal(desired_object, GSS_C_INQ_CB_TLS_EXPORTER)) {
        heim_debug(ctx->hctx, 5, "GSS-TLS: inquire tls-exporter CB");
        status = tls_backend_get_cb_exporter(ctx->backend, cb_buf, &cb_len);
    } else {
        /* Unknown OID */
        *minor = EINVAL;
        return GSS_S_UNAVAILABLE;
    }

    if (status != TLS_BACKEND_OK) {
        heim_debug(ctx->hctx, 1, "GSS-TLS: CB extraction failed: %s",
                   tls_backend_get_error(ctx->backend));
        *minor = ENOENT;
        return GSS_S_UNAVAILABLE;
    }

    /* Create buffer set with single buffer containing the CB value */
    major = gss_create_empty_buffer_set(minor, data_set);
    if (major != GSS_S_COMPLETE)
        return major;

    buf.length = cb_len;
    buf.value = cb_buf;

    major = gss_add_buffer_set_member(minor, &buf, data_set);
    if (major != GSS_S_COMPLETE) {
        gss_release_buffer_set(minor, data_set);
        return major;
    }

    return GSS_S_COMPLETE;
}
