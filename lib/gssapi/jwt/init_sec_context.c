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

#include "jwt_locl.h"

#include <errno.h>

/*
 * GSS-JWT context establishment - initiator side
 *
 * Protocol (without TLS protection):
 * 1. Initiator (first call, no input token):
 *    - Derive audience from target name
 *    - Obtain JWT from STS using configured credentials
 *    - Return JWT as output token
 *    - Return GSS_S_CONTINUE_NEEDED
 *
 * 2. Initiator (second call, with server acknowledgment):
 *    - Verify acknowledgment
 *    - Derive session keys from JWT
 *    - Return GSS_S_COMPLETE
 *
 * Protocol (with TLS protection - CONF_FLAG, INTEG_FLAG, or MUTUAL_FLAG):
 * 1. TLS handshake is performed first (multiple round trips)
 * 2. After TLS handshake completes, JWT is sent as TLS application data
 * 3. Server response is received as TLS application data
 * 4. wrap/unwrap operations use TLS encrypt/decrypt
 *
 * Token format:
 *   Without TLS: Raw JWT string / "OK" or error message
 *   With TLS: TLS records containing the above
 */

/* Default send buffer capacity for TLS */
#define JWT_TLS_BUF_INITIAL_CAPACITY 4096

/*
 * Tracing support via GSS_JWT_TRACE environment variable
 */
static inline void
gss_jwt_trace_init(heim_context *hctx)
{
    const char *trace;

    *hctx = NULL;
    trace = secure_getenv("GSS_JWT_TRACE");
    if (trace && *trace) {
        *hctx = heim_context_init();
        if (*hctx)
            heim_add_debug_dest(*hctx, "gss-jwt", trace);
    }
}

/*
 * Derive audience from GSS target name
 *
 * For hostbased service names (service@host), the audience is:
 *   "gss:<service>@<host>" or just "<service>@<host>"
 *
 * This should match what the server expects in the JWT "aud" claim.
 */
static OM_uint32
derive_audience(OM_uint32 *minor,
                gss_const_name_t target_name,
                char **audience_out)
{
    OM_uint32 major, tmp_minor;
    gss_buffer_desc name_buf = GSS_C_EMPTY_BUFFER;
    gss_OID name_type = GSS_C_NO_OID;

    *audience_out = NULL;

    if (target_name == GSS_C_NO_NAME) {
        *minor = EINVAL;
        return GSS_S_BAD_NAME;
    }

    major = gss_display_name(minor, target_name, &name_buf, &name_type);
    if (major != GSS_S_COMPLETE)
        return major;

    /* Use the display name as the audience */
    *audience_out = malloc(name_buf.length + 1);
    if (*audience_out == NULL) {
        gss_release_buffer(&tmp_minor, &name_buf);
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }
    memcpy(*audience_out, name_buf.value, name_buf.length);
    (*audience_out)[name_buf.length] = '\0';

    gss_release_buffer(&tmp_minor, &name_buf);
    return GSS_S_COMPLETE;
}

/*
 * Check if protection flags require TLS
 */
static int
needs_tls_protection(OM_uint32 req_flags)
{
    return (req_flags & (GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG | GSS_C_MUTUAL_FLAG)) != 0;
}

/*
 * Check if we have a cached session ticket for this audience
 */
static int
has_cached_session_ticket(const struct gss_jwt_cred_desc *cred,
                          const char *audience)
{
    if (cred == NULL || cred->cached_session_ticket == NULL)
        return 0;
    if (cred->cached_ticket_audience == NULL)
        return 0;
    if (strcmp(cred->cached_ticket_audience, audience) != 0)
        return 0;
    return 1;
}

/*
 * Initialize TLS backend for client mode
 *
 * If we have a cached session ticket for this audience, we'll:
 * 1. Acquire the JWT early (before TLS handshake)
 * 2. Configure the JWT as 0-RTT early data
 * 3. Let TLS send it with the ClientHello
 */
static OM_uint32
init_tls_client(OM_uint32 *minor, gss_jwt_ctx ctx,
                const struct gss_jwt_cred_desc *cred)
{
    tls_backend_config config;
    tls_backend_status status;
    char *jwt = NULL;
    OM_uint32 major;

    /* Initialize hx509 context for TLS */
    if (hx509_context_init(&ctx->tls_hx509ctx) != 0) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    /* Initialize I/O buffers */
    if (tls_iobuf_init(&ctx->tls_recv_buf, JWT_TLS_BUF_INITIAL_CAPACITY) != 0) {
        hx509_context_free(&ctx->tls_hx509ctx);
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    if (tls_iobuf_init(&ctx->tls_send_buf, JWT_TLS_BUF_INITIAL_CAPACITY) != 0) {
        tls_iobuf_free(&ctx->tls_recv_buf);
        hx509_context_free(&ctx->tls_hx509ctx);
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    /*
     * If we have a cached session ticket, acquire JWT early for 0-RTT.
     * The JWT will be sent as early data with the ClientHello.
     */
    if (has_cached_session_ticket(cred, ctx->audience)) {
        heim_debug(ctx->hctx, 5, "JWT-TLS: have session ticket, acquiring JWT for 0-RTT");

        if (ctx->have_cb_hash) {
            major = _gss_jwt_acquire_token(minor, cred, ctx->audience,
                                           ctx->cb_hash, sizeof(ctx->cb_hash),
                                           ctx->cb_type, &jwt);
        } else {
            major = _gss_jwt_acquire_token(minor, cred, ctx->audience,
                                           NULL, 0, NULL, &jwt);
        }

        if (major == GSS_S_COMPLETE && jwt != NULL) {
            ctx->jwt_token = jwt;
            ctx->have_jwt = 1;
            ctx->early_data_sent = 1;
            heim_debug(ctx->hctx, 5, "JWT-TLS: will send JWT (%zu bytes) as 0-RTT early data",
                       strlen(jwt));
        } else {
            /* JWT acquisition failed - proceed without early data */
            heim_debug(ctx->hctx, 5, "JWT-TLS: failed to acquire JWT for 0-RTT, will send after handshake");
        }
    }

    /* Configure TLS backend */
    memset(&config, 0, sizeof(config));
    config.hctx = ctx->hctx;
    config.hx509ctx = ctx->tls_hx509ctx;
    config.mode = TLS_BACKEND_CLIENT;
    config.verify_peer = 1;

    /* Use credential's trust anchors if available */
    if (cred) {
        config.trust_anchors = cred->trust_anchors;
        /* Client can use its own certificate for mutual auth if configured */
        config.certs = cred->client_certs;
        config.key = cred->client_key;

        /* Configure session resumption and 0-RTT early data */
        if (has_cached_session_ticket(cred, ctx->audience)) {
            config.session_ticket = cred->cached_session_ticket;
            config.session_ticket_len = cred->cached_session_ticket_len;
            heim_debug(ctx->hctx, 10, "JWT-TLS: using cached session ticket (%zu bytes)",
                       cred->cached_session_ticket_len);

            /*
             * Configure early data (flags + CB + JWT) if we acquired a JWT.
             * Format: <flags:8 bytes, network order>[<cb_data>]<JWT string>
             */
            if (ctx->jwt_token != NULL) {
                size_t jwt_len = strlen(ctx->jwt_token);
                size_t cb_type_len = 0;
                size_t offset;
                int include_cb = (ctx->flags & GSS_JWT_FLAG_CB_PRESENT) && ctx->have_cb_hash;

                if (include_cb && ctx->cb_type)
                    cb_type_len = strlen(ctx->cb_type);

                ctx->early_data_len = 8 + jwt_len;
                if (include_cb)
                    ctx->early_data_len += 1 + cb_type_len + 32;

                ctx->early_data_buf = malloc(ctx->early_data_len);
                if (ctx->early_data_buf != NULL) {
                    /* Encode 64-bit flags in network byte order */
                    ctx->early_data_buf[0] = 0;  /* Reserved */
                    ctx->early_data_buf[1] = 0;
                    ctx->early_data_buf[2] = 0;
                    ctx->early_data_buf[3] = 0;
                    ctx->early_data_buf[4] = (ctx->flags >> 24) & 0xFF;
                    ctx->early_data_buf[5] = (ctx->flags >> 16) & 0xFF;
                    ctx->early_data_buf[6] = (ctx->flags >> 8) & 0xFF;
                    ctx->early_data_buf[7] = ctx->flags & 0xFF;
                    offset = 8;

                    /* Include CB data if flag is set */
                    if (include_cb) {
                        ctx->early_data_buf[offset++] = (uint8_t)cb_type_len;
                        if (cb_type_len > 0) {
                            memcpy(ctx->early_data_buf + offset, ctx->cb_type, cb_type_len);
                            offset += cb_type_len;
                        }
                        memcpy(ctx->early_data_buf + offset, ctx->cb_hash, 32);
                        offset += 32;
                    }

                    /* Append JWT */
                    memcpy(ctx->early_data_buf + offset, ctx->jwt_token, jwt_len);

                    config.early_data = ctx->early_data_buf;
                    config.early_data_len = ctx->early_data_len;

                    heim_debug(ctx->hctx, 10, "JWT-TLS: 0-RTT early data with flags=0x%x%s",
                               ctx->flags, include_cb ? " (with CB)" : "");
                }
            }
        }
    }

    /* Initialize TLS backend */
    status = tls_backend_init(&ctx->tls_backend, &config,
                              &ctx->tls_recv_buf, &ctx->tls_send_buf);
    if (status != TLS_BACKEND_OK) {
        heim_debug(ctx->hctx, 1, "JWT-TLS: failed to initialize TLS backend");
        tls_iobuf_free(&ctx->tls_recv_buf);
        tls_iobuf_free(&ctx->tls_send_buf);
        hx509_context_free(&ctx->tls_hx509ctx);
        *minor = EINVAL;
        return GSS_S_FAILURE;
    }

    ctx->use_tls = 1;
    heim_debug(ctx->hctx, 5, "JWT-TLS: initialized TLS client");
    return GSS_S_COMPLETE;
}

/*
 * Drive TLS handshake
 *
 * Returns:
 *   GSS_S_COMPLETE - handshake done
 *   GSS_S_CONTINUE_NEEDED - more handshake data needed
 *   GSS_S_FAILURE - error
 */
static OM_uint32
drive_tls_handshake(OM_uint32 *minor, gss_jwt_ctx ctx,
                    const gss_buffer_t input_token,
                    gss_buffer_t output_token)
{
    tls_backend_status status;

    /* Provide input token data to recv buffer */
    if (input_token != GSS_C_NO_BUFFER && input_token->length > 0) {
        heim_debug(ctx->hctx, 10, "JWT-TLS: received %zu bytes for handshake",
                   input_token->length);
        tls_iobuf_reset(&ctx->tls_recv_buf);
        if (tls_iobuf_append(&ctx->tls_recv_buf, input_token->value,
                             input_token->length) != 0) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }
    }

    /* Clear output buffer for this round */
    tls_iobuf_reset(&ctx->tls_send_buf);

    /* Drive TLS handshake */
    status = tls_backend_handshake(ctx->tls_backend);

    /* Return any TLS records that were generated */
    if (ctx->tls_send_buf.len > 0) {
        heim_debug(ctx->hctx, 10, "JWT-TLS: sending %zu bytes",
                   ctx->tls_send_buf.len);
        output_token->value = malloc(ctx->tls_send_buf.len);
        if (output_token->value == NULL) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }
        memcpy(output_token->value, ctx->tls_send_buf.data, ctx->tls_send_buf.len);
        output_token->length = ctx->tls_send_buf.len;
    }

    if (status == TLS_BACKEND_OK) {
        heim_debug(ctx->hctx, 5, "JWT-TLS: handshake complete");
        ctx->tls_handshake_done = 1;
        return GSS_S_COMPLETE;
    } else if (status == TLS_BACKEND_WANT_READ ||
               status == TLS_BACKEND_WANT_WRITE) {
        heim_debug(ctx->hctx, 10, "JWT-TLS: handshake continue needed");
        return GSS_S_CONTINUE_NEEDED;
    } else {
        heim_debug(ctx->hctx, 1, "JWT-TLS: handshake error: %s",
                   tls_backend_get_error(ctx->tls_backend));
        *minor = EPROTO;
        return GSS_S_FAILURE;
    }
}

/*
 * Send JWT over TLS (as application data)
 *
 * For protected mode, the wire format is:
 *   <flags:8 bytes, network order>[<cb_data>]<JWT string>
 *
 * The flags field is 64 bits (network byte order) for future expansion.
 * Currently only the lower 32 bits are used (matching the GSS-API flags).
 * If GSS_JWT_FLAG_CB_PRESENT is set, the CB data follows the flags:
 *   - 1 byte: cb_type_len (0 if no type)
 *   - cb_type_len bytes: cb_type string (no null terminator)
 *   - 32 bytes: cb_hash
 */
static OM_uint32
send_jwt_over_tls(OM_uint32 *minor, gss_jwt_ctx ctx,
                  const char *jwt, gss_buffer_t output_token)
{
    tls_backend_status status;
    size_t jwt_len = strlen(jwt);
    size_t msg_len;
    size_t offset;
    uint8_t *msg;
    int include_cb = (ctx->flags & GSS_JWT_FLAG_CB_PRESENT) && ctx->have_cb_hash;
    size_t cb_type_len = 0;

    if (include_cb && ctx->cb_type)
        cb_type_len = strlen(ctx->cb_type);

    /* Calculate message length */
    msg_len = 8 + jwt_len;  /* 64-bit flags */
    if (include_cb)
        msg_len += 1 + cb_type_len + 32; /* type_len + type + hash */

    msg = malloc(msg_len);
    if (msg == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    /* Encode flags as 64 bits in network byte order (upper 32 bits reserved) */
    msg[0] = 0;  /* Reserved for future use */
    msg[1] = 0;
    msg[2] = 0;
    msg[3] = 0;
    msg[4] = (ctx->flags >> 24) & 0xFF;
    msg[5] = (ctx->flags >> 16) & 0xFF;
    msg[6] = (ctx->flags >> 8) & 0xFF;
    msg[7] = ctx->flags & 0xFF;
    offset = 8;

    /* Include CB data if flag is set */
    if (include_cb) {
        /* CB type length (1 byte) */
        msg[offset++] = (uint8_t)cb_type_len;

        /* CB type string (if present) */
        if (cb_type_len > 0) {
            memcpy(msg + offset, ctx->cb_type, cb_type_len);
            offset += cb_type_len;
            heim_debug(ctx->hctx, 10, "JWT-TLS: CB type=%s", ctx->cb_type);
        }

        /* CB hash (32 bytes) */
        memcpy(msg + offset, ctx->cb_hash, 32);
        offset += 32;
        heim_debug(ctx->hctx, 10, "JWT-TLS: including CB in message");
    }

    /* Append JWT */
    memcpy(msg + offset, jwt, jwt_len);

    heim_debug(ctx->hctx, 10, "JWT-TLS: sending flags=0x%x with JWT%s",
               ctx->flags, include_cb ? " (with CB)" : "");

    tls_iobuf_reset(&ctx->tls_send_buf);

    status = tls_backend_encrypt(ctx->tls_backend, msg, msg_len);
    free(msg);

    if (status != TLS_BACKEND_OK) {
        heim_debug(ctx->hctx, 1, "JWT-TLS: failed to encrypt JWT");
        *minor = EPROTO;
        return GSS_S_FAILURE;
    }

    if (ctx->tls_send_buf.len > 0) {
        output_token->value = malloc(ctx->tls_send_buf.len);
        if (output_token->value == NULL) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }
        memcpy(output_token->value, ctx->tls_send_buf.data, ctx->tls_send_buf.len);
        output_token->length = ctx->tls_send_buf.len;
    }

    heim_debug(ctx->hctx, 5, "JWT-TLS: sent JWT (%zu bytes encrypted)",
               output_token->length);
    return GSS_S_COMPLETE;
}

/*
 * Save session ticket for future 0-RTT
 *
 * Called after successful context establishment to cache the session
 * ticket for use in future connections to the same audience.
 */
static void
save_session_ticket(gss_jwt_ctx ctx)
{
    struct gss_jwt_cred_desc *cred;
    uint8_t ticket_buf[4096];
    size_t ticket_len = sizeof(ticket_buf);
    tls_backend_status status;

    if (ctx->tls_backend == NULL)
        return;

    /* Get mutable reference to credential (for caching) */
    cred = rk_UNCONST(ctx->cred);
    if (cred == NULL)
        return;

    /* Get session ticket from TLS backend */
    status = tls_backend_get_session_ticket(ctx->tls_backend,
                                            ticket_buf, &ticket_len);
    if (status != TLS_BACKEND_OK) {
        heim_debug(ctx->hctx, 10, "JWT-TLS: no session ticket available to cache");
        return;
    }

    /* Free old cached ticket if any */
    free(cred->cached_ticket_audience);
    free(cred->cached_session_ticket);

    /* Cache the new ticket */
    cred->cached_ticket_audience = strdup(ctx->audience);
    cred->cached_session_ticket = malloc(ticket_len);

    if (cred->cached_ticket_audience && cred->cached_session_ticket) {
        memcpy(cred->cached_session_ticket, ticket_buf, ticket_len);
        cred->cached_session_ticket_len = ticket_len;
        heim_debug(ctx->hctx, 5, "JWT-TLS: cached session ticket (%zu bytes) for %s",
                   ticket_len, ctx->audience);
    } else {
        /* Allocation failed - clean up */
        free(cred->cached_ticket_audience);
        free(cred->cached_session_ticket);
        cred->cached_ticket_audience = NULL;
        cred->cached_session_ticket = NULL;
        cred->cached_session_ticket_len = 0;
    }
}

/*
 * Receive response over TLS
 *
 * For protected mode, the wire format is:
 *   <flags:4 bytes, network order><status string>
 *
 * The flags field contains the ret_flags from the acceptor.
 * Parses the flags and updates ctx->flags with the intersection.
 */
static OM_uint32
recv_response_over_tls(OM_uint32 *minor, gss_jwt_ctx ctx,
                       const gss_buffer_t input_token,
                       uint8_t *response, size_t *response_len)
{
    tls_backend_status status;
    OM_uint32 recv_flags;

    if (input_token == GSS_C_NO_BUFFER || input_token->length == 0) {
        *minor = EINVAL;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    tls_iobuf_reset(&ctx->tls_recv_buf);
    if (tls_iobuf_append(&ctx->tls_recv_buf, input_token->value,
                         input_token->length) != 0) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    status = tls_backend_decrypt(ctx->tls_backend, response, response_len);
    if (status != TLS_BACKEND_OK) {
        heim_debug(ctx->hctx, 1, "JWT-TLS: failed to decrypt response");
        *minor = EPROTO;
        return GSS_S_FAILURE;
    }

    /* Parse flags from response */
    if (*response_len < 4) {
        heim_debug(ctx->hctx, 1, "JWT-TLS: response too short for flags");
        *minor = EPROTO;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    recv_flags = ((OM_uint32)response[0] << 24) |
                 ((OM_uint32)response[1] << 16) |
                 ((OM_uint32)response[2] << 8) |
                 ((OM_uint32)response[3]);

    heim_debug(ctx->hctx, 10, "JWT-TLS: received flags=0x%x", recv_flags);

    /* Flags are intersection of what we requested and what acceptor supports */
    ctx->flags &= recv_flags;

    /* Shift response to skip flags */
    *response_len -= 4;
    memmove(response, response + 4, *response_len);

    heim_debug(ctx->hctx, 5, "JWT-TLS: received response (%zu bytes)",
               *response_len);
    return GSS_S_COMPLETE;
}

/*
 * Derive per-message sequence numbers from TLS exporter
 *
 * Uses the TLS keying material exporter (RFC 5705/8446) to derive
 * deterministic initial sequence numbers for both parties.
 *
 * The exporter output is 32 bytes:
 *   - Bytes 0-7: Initiator's initial send sequence number
 *   - Bytes 8-15: Acceptor's initial send sequence number
 *
 * Both parties derive the same values from the shared TLS session.
 */
static OM_uint32
derive_sequence_numbers(OM_uint32 *minor, gss_jwt_ctx ctx)
{
    uint8_t exported[32];
    size_t exported_len = sizeof(exported);
    tls_backend_status status;

    if (!ctx->tls_backend) {
        *minor = EINVAL;
        return GSS_S_FAILURE;
    }

    /* Use TLS exporter to get keying material */
    status = tls_backend_get_cb_exporter(ctx->tls_backend, exported, &exported_len);
    if (status != TLS_BACKEND_OK) {
        heim_debug(ctx->hctx, 1, "JWT-TLS: failed to derive sequence numbers from exporter");
        *minor = EPROTO;
        return GSS_S_FAILURE;
    }

    /*
     * Derive sequence numbers from exporter output:
     *   - Initiator's send_seq = first 8 bytes (big endian)
     *   - Acceptor's send_seq = next 8 bytes (big endian)
     *
     * For initiator: send_seq = initiator's, recv_seq = acceptor's
     * For acceptor: send_seq = acceptor's, recv_seq = initiator's
     */
    if (ctx->is_initiator) {
        ctx->send_seq = ((uint64_t)exported[0] << 56) |
                        ((uint64_t)exported[1] << 48) |
                        ((uint64_t)exported[2] << 40) |
                        ((uint64_t)exported[3] << 32) |
                        ((uint64_t)exported[4] << 24) |
                        ((uint64_t)exported[5] << 16) |
                        ((uint64_t)exported[6] << 8) |
                        ((uint64_t)exported[7]);

        ctx->recv_seq = ((uint64_t)exported[8] << 56) |
                        ((uint64_t)exported[9] << 48) |
                        ((uint64_t)exported[10] << 40) |
                        ((uint64_t)exported[11] << 32) |
                        ((uint64_t)exported[12] << 24) |
                        ((uint64_t)exported[13] << 16) |
                        ((uint64_t)exported[14] << 8) |
                        ((uint64_t)exported[15]);
    } else {
        ctx->send_seq = ((uint64_t)exported[8] << 56) |
                        ((uint64_t)exported[9] << 48) |
                        ((uint64_t)exported[10] << 40) |
                        ((uint64_t)exported[11] << 32) |
                        ((uint64_t)exported[12] << 24) |
                        ((uint64_t)exported[13] << 16) |
                        ((uint64_t)exported[14] << 8) |
                        ((uint64_t)exported[15]);

        ctx->recv_seq = ((uint64_t)exported[0] << 56) |
                        ((uint64_t)exported[1] << 48) |
                        ((uint64_t)exported[2] << 40) |
                        ((uint64_t)exported[3] << 32) |
                        ((uint64_t)exported[4] << 24) |
                        ((uint64_t)exported[5] << 16) |
                        ((uint64_t)exported[6] << 8) |
                        ((uint64_t)exported[7]);
    }

    heim_debug(ctx->hctx, 5, "JWT-TLS: derived sequence numbers: send=%llu recv=%llu",
               (unsigned long long)ctx->send_seq,
               (unsigned long long)ctx->recv_seq);

    memset(exported, 0, sizeof(exported));
    return GSS_S_COMPLETE;
}

/*
 * Allocate and initialize a new JWT context
 */
static OM_uint32
alloc_jwt_context(OM_uint32 *minor,
                  const struct gss_jwt_cred_desc *cred,
                  gss_jwt_ctx *ctx_out)
{
    gss_jwt_ctx ctx;

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    gss_jwt_trace_init(&ctx->hctx);
    ctx->is_initiator = 1;
    ctx->state = JWT_STATE_INITIAL;
    ctx->cred = cred;

    *ctx_out = ctx;
    return GSS_S_COMPLETE;
}

/*
 * GSS-API init_sec_context for JWT mechanism
 */
OM_uint32 GSSAPI_CALLCONV
_gss_jwt_init_sec_context(OM_uint32 *minor,
                          gss_const_cred_id_t cred_handle,
                          gss_ctx_id_t *context_handle,
                          gss_const_name_t target_name,
                          const gss_OID mech_type,
                          OM_uint32 req_flags,
                          OM_uint32 time_req,
                          const gss_channel_bindings_t bindings,
                          const gss_buffer_t input_token,
                          gss_OID *actual_mech,
                          gss_buffer_t output_token,
                          OM_uint32 *ret_flags,
                          OM_uint32 *time_rec)
{
    OM_uint32 major, tmp_minor;
    gss_jwt_ctx ctx;
    const struct gss_jwt_cred_desc *cred = (const void *)cred_handle;
    char *audience = NULL;
    char *jwt = NULL;

    (void)mech_type;
    (void)time_req;

    *minor = 0;

    /* Initialize output parameters */
    output_token->length = 0;
    output_token->value = NULL;
    if (actual_mech)
        *actual_mech = GSS_JWT_MECHANISM;
    if (ret_flags)
        *ret_flags = 0;
    if (time_rec)
        *time_rec = GSS_C_INDEFINITE;

    /* Credential is required */
    if (cred == NULL) {
        *minor = EINVAL;
        return GSS_S_NO_CRED;
    }

    /* First call - create new context */
    if (*context_handle == GSS_C_NO_CONTEXT) {
        major = alloc_jwt_context(minor, cred, &ctx);
        if (major != GSS_S_COMPLETE)
            return major;

        *context_handle = (gss_ctx_id_t)ctx;

        heim_debug(ctx->hctx, 5, "JWT: initiating context");

        /* Derive audience from target name */
        major = derive_audience(minor, target_name, &audience);
        if (major != GSS_S_COMPLETE) {
            heim_debug(ctx->hctx, 1, "JWT: failed to derive audience from target");
            _gss_jwt_delete_sec_context(&tmp_minor, context_handle, NULL);
            return major;
        }

        ctx->audience = audience;
        heim_debug(ctx->hctx, 5, "JWT: audience: %s", audience);

        /* Store target name */
        major = gss_duplicate_name(minor, target_name, &ctx->target_name);
        if (major != GSS_S_COMPLETE) {
            _gss_jwt_delete_sec_context(&tmp_minor, context_handle, NULL);
            return major;
        }

        /* Set flags we support */
        ctx->flags = req_flags & (GSS_C_MUTUAL_FLAG |
                                  GSS_C_REPLAY_FLAG |
                                  GSS_C_SEQUENCE_FLAG |
                                  GSS_C_CONF_FLAG |
                                  GSS_C_INTEG_FLAG);

        /*
         * Compute and store channel bindings hash if provided.
         * This will be included in the JWT request to the STS, which
         * should add a "cb" claim to the JWT.
         *
         * If the application_data contains a CB type prefix (e.g.,
         * "tls-server-end-point:"), it is extracted and stored separately.
         */
        if (bindings != GSS_C_NO_CHANNEL_BINDINGS) {
            major = _gss_jwt_compute_cb_hash(minor, bindings, ctx->cb_hash,
                                             &ctx->cb_type);
            if (major != GSS_S_COMPLETE) {
                heim_debug(ctx->hctx, 1, "JWT: failed to compute channel bindings hash");
                _gss_jwt_delete_sec_context(&tmp_minor, context_handle, NULL);
                return major;
            }
            ctx->have_cb_hash = 1;
            if (ctx->cb_type) {
                ctx->have_cb_type = 1;
                heim_debug(ctx->hctx, 5, "JWT: CB type=%s", ctx->cb_type);
            }
            heim_debug(ctx->hctx, 5, "JWT: computed channel bindings hash");
        }

        /* Check if TLS protection is requested */
        if (needs_tls_protection(req_flags)) {
            gss_buffer_desc inner_token = GSS_C_EMPTY_BUFFER;

            heim_debug(ctx->hctx, 5, "JWT: protection flags set, using TLS");

            major = init_tls_client(minor, ctx, cred);
            if (major != GSS_S_COMPLETE) {
                _gss_jwt_delete_sec_context(&tmp_minor, context_handle, NULL);
                return major;
            }

            ctx->state = JWT_STATE_TLS_HANDSHAKE;

            /* Start TLS handshake */
            major = drive_tls_handshake(minor, ctx, NULL, &inner_token);
            if (major == GSS_S_FAILURE) {
                gss_release_buffer(&tmp_minor, &inner_token);
                _gss_jwt_delete_sec_context(&tmp_minor, context_handle, NULL);
                return major;
            }

            /*
             * Wrap first output token with RFC 2743 header.
             * This distinguishes GSS-JWT from GSS-TLS (which sends raw TLS).
             */
            if (inner_token.length > 0) {
                major = gss_encapsulate_token(&inner_token, GSS_JWT_MECHANISM,
                                              output_token);
                gss_release_buffer(&tmp_minor, &inner_token);
                if (major != GSS_S_COMPLETE) {
                    _gss_jwt_delete_sec_context(&tmp_minor, context_handle, NULL);
                    return major;
                }
                heim_debug(ctx->hctx, 10, "JWT: wrapped initial token with RFC 2743 header");
            }

            if (ret_flags)
                *ret_flags = ctx->flags;
            return GSS_S_CONTINUE_NEEDED;
        }

        /* No TLS protection requested - try to send JWT directly */
        ctx->state = JWT_STATE_ACQUIRING_TOKEN;
        heim_debug(ctx->hctx, 5, "JWT: acquiring token from STS");

        /* Use stored channel bindings hash if available */
        if (ctx->have_cb_hash) {
            major = _gss_jwt_acquire_token(minor, cred, audience,
                                           ctx->cb_hash, sizeof(ctx->cb_hash),
                                           ctx->cb_type, &jwt);
        } else {
            major = _gss_jwt_acquire_token(minor, cred, audience,
                                           NULL, 0, NULL, &jwt);
        }

        if (major != GSS_S_COMPLETE) {
            heim_debug(ctx->hctx, 1, "JWT: failed to acquire token from STS");
            _gss_jwt_delete_sec_context(&tmp_minor, context_handle, NULL);
            return major;
        }

        ctx->jwt_token = jwt;
        ctx->have_jwt = 1;

        /*
         * If channel bindings were provided, check if the STS included
         * them in the JWT. If not, we need to fall back to TLS to convey
         * the channel bindings in the protocol.
         */
        if (ctx->have_cb_hash) {
            int has_cb = 0, cb_matches = 0;

            major = _gss_jwt_check_cb_claim(minor, jwt,
                                            ctx->cb_hash, sizeof(ctx->cb_hash),
                                            &has_cb, &cb_matches);
            if (major != GSS_S_COMPLETE) {
                heim_debug(ctx->hctx, 1, "JWT: failed to check CB claim in JWT");
                _gss_jwt_delete_sec_context(&tmp_minor, context_handle, NULL);
                return major;
            }

            if (!has_cb) {
                /*
                 * STS did not include CB claim in JWT.
                 * Fall back to TLS to convey channel bindings.
                 */
                gss_buffer_desc inner_token = GSS_C_EMPTY_BUFFER;

                heim_debug(ctx->hctx, 5, "JWT: STS did not include CB claim, falling back to TLS");

                major = init_tls_client(minor, ctx, cred);
                if (major != GSS_S_COMPLETE) {
                    _gss_jwt_delete_sec_context(&tmp_minor, context_handle, NULL);
                    return major;
                }

                ctx->use_tls = 1;
                ctx->state = JWT_STATE_TLS_HANDSHAKE;

                /* Set CB flag to indicate we're sending CB in protocol */
                ctx->flags |= GSS_JWT_FLAG_CB_PRESENT;

                /* Start TLS handshake */
                major = drive_tls_handshake(minor, ctx, NULL, &inner_token);
                if (major == GSS_S_FAILURE) {
                    gss_release_buffer(&tmp_minor, &inner_token);
                    _gss_jwt_delete_sec_context(&tmp_minor, context_handle, NULL);
                    return major;
                }

                /* Wrap with RFC 2743 header */
                if (inner_token.length > 0) {
                    major = gss_encapsulate_token(&inner_token, GSS_JWT_MECHANISM,
                                                  output_token);
                    gss_release_buffer(&tmp_minor, &inner_token);
                    if (major != GSS_S_COMPLETE) {
                        _gss_jwt_delete_sec_context(&tmp_minor, context_handle, NULL);
                        return major;
                    }
                }

                if (ret_flags)
                    *ret_flags = ctx->flags;
                return GSS_S_CONTINUE_NEEDED;
            }

            /* JWT has CB claim - verify it matches */
            if (!cb_matches) {
                heim_debug(ctx->hctx, 1, "JWT: CB claim in JWT does not match!");
                _gss_jwt_delete_sec_context(&tmp_minor, context_handle, NULL);
                *minor = EACCES;
                return GSS_S_BAD_BINDINGS;
            }

            heim_debug(ctx->hctx, 5, "JWT: CB claim in JWT matches");
        }

        heim_debug(ctx->hctx, 5, "JWT: obtained token, sending to acceptor");

        /* Return JWT as output token */
        output_token->length = strlen(jwt);
        output_token->value = malloc(output_token->length);
        if (output_token->value == NULL) {
            *minor = ENOMEM;
            _gss_jwt_delete_sec_context(&tmp_minor, context_handle, NULL);
            return GSS_S_FAILURE;
        }
        memcpy(output_token->value, jwt, output_token->length);

        ctx->state = JWT_STATE_TOKEN_SENT;

        if (ret_flags)
            *ret_flags = ctx->flags;

        return GSS_S_CONTINUE_NEEDED;
    }

    /* Subsequent call - process server response */
    ctx = (gss_jwt_ctx)*context_handle;

    /* TLS handshake in progress */
    if (ctx->state == JWT_STATE_TLS_HANDSHAKE) {
        major = drive_tls_handshake(minor, ctx, input_token, output_token);
        if (major == GSS_S_FAILURE) {
            return major;
        }

        if (major == GSS_S_CONTINUE_NEEDED) {
            if (ret_flags)
                *ret_flags = ctx->flags;
            return GSS_S_CONTINUE_NEEDED;
        }

        /* TLS handshake complete */
        heim_debug(ctx->hctx, 5, "JWT-TLS: handshake done");

        /*
         * Check if 0-RTT early data (JWT) was accepted.
         * If so, we already sent the JWT with the ClientHello and
         * can skip to waiting for the server's response.
         */
        if (ctx->early_data_sent) {
            tls_early_data_status early_status;

            early_status = tls_backend_get_early_data_status(ctx->tls_backend);

            if (early_status == TLS_EARLY_DATA_ACCEPTED) {
                heim_debug(ctx->hctx, 5, "JWT-TLS: 0-RTT early data accepted, JWT already sent");
                ctx->early_data_accepted = 1;
                ctx->state = JWT_STATE_TOKEN_SENT;

                if (ret_flags)
                    *ret_flags = ctx->flags;

                /* Return empty token - we're waiting for server response */
                output_token->length = 0;
                output_token->value = NULL;

                return GSS_S_CONTINUE_NEEDED;
            }

            /* Early data was rejected or not used - need to re-send JWT */
            if (early_status == TLS_EARLY_DATA_REJECTED) {
                heim_debug(ctx->hctx, 5, "JWT-TLS: 0-RTT early data rejected, re-sending JWT");
            } else {
                heim_debug(ctx->hctx, 5, "JWT-TLS: 0-RTT not used, sending JWT normally");
            }
        }

        /* Need to acquire and send JWT over TLS */
        ctx->state = JWT_STATE_ACQUIRING_TOKEN;

        /* Acquire JWT if we don't already have one (no early data attempt) */
        if (!ctx->have_jwt) {
            heim_debug(ctx->hctx, 5, "JWT-TLS: acquiring token");

            if (ctx->have_cb_hash) {
                major = _gss_jwt_acquire_token(minor, cred, ctx->audience,
                                               ctx->cb_hash, sizeof(ctx->cb_hash),
                                               ctx->cb_type, &jwt);
            } else {
                major = _gss_jwt_acquire_token(minor, cred, ctx->audience,
                                               NULL, 0, NULL, &jwt);
            }

            if (major != GSS_S_COMPLETE) {
                heim_debug(ctx->hctx, 1, "JWT: failed to acquire token from STS");
                return major;
            }

            ctx->jwt_token = jwt;
            ctx->have_jwt = 1;
        }

        /* Send JWT over TLS */
        major = send_jwt_over_tls(minor, ctx, ctx->jwt_token, output_token);
        if (major != GSS_S_COMPLETE) {
            return major;
        }

        ctx->state = JWT_STATE_TOKEN_SENT;

        if (ret_flags)
            *ret_flags = ctx->flags;

        return GSS_S_CONTINUE_NEEDED;
    }

    /* Waiting for server response */
    if (ctx->state != JWT_STATE_TOKEN_SENT) {
        heim_debug(ctx->hctx, 1, "JWT: unexpected state %d", ctx->state);
        *minor = EINVAL;
        return GSS_S_FAILURE;
    }

    if (input_token == NULL || input_token->length == 0) {
        heim_debug(ctx->hctx, 1, "JWT: expected response token");
        *minor = EINVAL;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    /* Process response */
    if (ctx->use_tls) {
        /* Decrypt response over TLS */
        uint8_t response[256];
        size_t response_len = sizeof(response);

        major = recv_response_over_tls(minor, ctx, input_token,
                                       response, &response_len);
        if (major != GSS_S_COMPLETE) {
            return major;
        }

        if (response_len >= 2 && memcmp(response, "OK", 2) == 0) {
            heim_debug(ctx->hctx, 5, "JWT-TLS: context established%s",
                       ctx->early_data_accepted ? " (0-RTT)" : "");

            ctx->state = JWT_STATE_ESTABLISHED;
            ctx->open = 1;
            ctx->established_time = time(NULL);

            /* Derive per-message sequence numbers from TLS exporter */
            major = derive_sequence_numbers(minor, ctx);
            if (major != GSS_S_COMPLETE) {
                heim_debug(ctx->hctx, 1, "JWT-TLS: failed to derive sequence numbers");
                /* Non-fatal - context still works, just no sequence protection */
            }

            /* Save session ticket for future 0-RTT connections */
            save_session_ticket(ctx);

            if (ret_flags)
                *ret_flags = ctx->flags;
            if (time_rec) {
                if (ctx->expiry > 0) {
                    time_t now = time(NULL);
                    if (ctx->expiry > now)
                        *time_rec = (OM_uint32)(ctx->expiry - now);
                    else
                        *time_rec = 0;
                } else {
                    *time_rec = GSS_C_INDEFINITE;
                }
            }

            return GSS_S_COMPLETE;
        }

        /* Error response */
        heim_debug(ctx->hctx, 1, "JWT-TLS: acceptor returned error: %.*s",
                   (int)response_len, (char *)response);
        *minor = EACCES;
        return GSS_S_FAILURE;
    }

    /* Non-TLS response */
    heim_debug(ctx->hctx, 5, "JWT: received response from acceptor (%zu bytes)",
               input_token->length);

    /* Check for "OK" acknowledgment */
    if (input_token->length >= 2 &&
        memcmp(input_token->value, "OK", 2) == 0) {
        heim_debug(ctx->hctx, 5, "JWT: context established");

        ctx->state = JWT_STATE_ESTABLISHED;
        ctx->open = 1;
        ctx->established_time = time(NULL);

        if (ret_flags)
            *ret_flags = ctx->flags;
        if (time_rec) {
            /* Return time until JWT expires */
            if (ctx->expiry > 0) {
                time_t now = time(NULL);
                if (ctx->expiry > now)
                    *time_rec = (OM_uint32)(ctx->expiry - now);
                else
                    *time_rec = 0;
            } else {
                *time_rec = GSS_C_INDEFINITE;
            }
        }

        return GSS_S_COMPLETE;
    }

    /* Error response */
    heim_debug(ctx->hctx, 1, "JWT: acceptor returned error: %.*s",
               (int)input_token->length, (char *)input_token->value);
    *minor = EACCES;
    return GSS_S_FAILURE;
}
