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
 * GSS-JWT context establishment - acceptor side
 *
 * Protocol (without TLS):
 * 1. Acceptor (first call, with JWT from initiator):
 *    - Validate JWT (signature, expiry, audience, issuer)
 *    - Extract subject as peer identity
 *    - Return "OK" as output token
 *    - Return GSS_S_COMPLETE
 *
 * Protocol (with TLS - detected by first byte 0x16 for TLS handshake):
 * 1. Acceptor receives TLS ClientHello, starts TLS handshake as server
 * 2. Multiple handshake round trips
 * 3. After TLS handshake completes, receives JWT as TLS application data
 * 4. Validates JWT and sends "OK" as TLS application data
 * 5. wrap/unwrap use TLS encrypt/decrypt
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
 * Token type detection for GSS-JWT
 *
 * Initial context tokens can be:
 * 1. RFC 2743 framed (0x60 APPLICATION tag) - protected mode with TLS
 * 2. Raw JWT (starts with "eyJ" - base64 of '{"') - unprotected mode
 * 3. Raw TLS ClientHello (0x16 0x03) - this is GSS-TLS, not GSS-JWT
 */
typedef enum {
    JWT_TOKEN_RFC2743_FRAMED,   /* 0x60 ... - GSS-JWT with TLS protection */
    JWT_TOKEN_RAW_JWT,          /* eyJ... - GSS-JWT without protection */
    JWT_TOKEN_RAW_TLS,          /* 0x16 0x03 - GSS-TLS (not us) */
    JWT_TOKEN_UNKNOWN
} jwt_token_type;

static jwt_token_type
detect_token_type(const gss_buffer_t token)
{
    const uint8_t *data = token->value;

    if (token->length < 3)
        return JWT_TOKEN_UNKNOWN;

    /* RFC 2743 framed token - APPLICATION 0 tag */
    if (data[0] == 0x60) {
        return JWT_TOKEN_RFC2743_FRAMED;
    }

    /* Raw JWT - starts with "eyJ" (base64 of '{"') */
    if (data[0] == 'e' && data[1] == 'y' && data[2] == 'J') {
        return JWT_TOKEN_RAW_JWT;
    }

    /* Raw TLS ClientHello */
    if (token->length >= 6 &&
        data[0] == 0x16 &&     /* Handshake */
        data[1] == 0x03 &&     /* TLS major version */
        data[5] == 0x01) {     /* ClientHello */
        return JWT_TOKEN_RAW_TLS;
    }

    return JWT_TOKEN_UNKNOWN;
}

/*
 * Check if input token looks like TLS handshake (ClientHello)
 * Used for subsequent tokens during TLS handshake.
 */
static int
is_tls_handshake(const gss_buffer_t token)
{
    const uint8_t *data = token->value;

    if (token->length < 6)
        return 0;

    /* Check for TLS handshake record */
    if (data[0] == 0x16 &&     /* Handshake */
        data[1] == 0x03 &&     /* TLS major version */
        data[5] == 0x01) {     /* ClientHello */
        return 1;
    }

    return 0;
}

/*
 * Allocate and initialize a new JWT context for acceptor
 */
static OM_uint32
alloc_jwt_context_acceptor(OM_uint32 *minor,
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
    ctx->is_initiator = 0;
    ctx->state = JWT_STATE_INITIAL;
    ctx->cred = cred;

    *ctx_out = ctx;
    return GSS_S_COMPLETE;
}

/*
 * Maximum size of JWT to accept as 0-RTT early data
 * JWTs can be fairly large (~2-4KB depending on claims), so we allow 8KB
 */
#define JWT_MAX_EARLY_DATA_SIZE 8192

/*
 * Initialize TLS backend for server mode
 */
static OM_uint32
init_tls_server(OM_uint32 *minor, gss_jwt_ctx ctx,
                const struct gss_jwt_cred_desc *cred)
{
    tls_backend_config config;
    tls_backend_status status;

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

    /* Configure TLS backend */
    memset(&config, 0, sizeof(config));
    config.hctx = ctx->hctx;
    config.hx509ctx = ctx->tls_hx509ctx;
    config.mode = TLS_BACKEND_SERVER;
    config.verify_peer = 0;  /* Don't require client certificate */

    /* Use credential's TLS certificate and key */
    if (cred) {
        config.certs = cred->tls_certs;
        config.key = cred->tls_key;
        config.trust_anchors = cred->trust_anchors;
    }

    /*
     * Enable 0-RTT early data reception
     *
     * Set max_early_data_size to allow clients to send the JWT as
     * early data with their ClientHello when resuming a session.
     */
    config.max_early_data_size = JWT_MAX_EARLY_DATA_SIZE;
    heim_debug(ctx->hctx, 10, "JWT-TLS: server accepting up to %zu bytes early data",
               config.max_early_data_size);

    /* Server must have a certificate */
    if (config.certs == NULL || config.key == NULL) {
        heim_debug(ctx->hctx, 1, "JWT-TLS: server requires TLS certificate and key");
        tls_iobuf_free(&ctx->tls_recv_buf);
        tls_iobuf_free(&ctx->tls_send_buf);
        hx509_context_free(&ctx->tls_hx509ctx);
        *minor = EINVAL;
        return GSS_S_DEFECTIVE_CREDENTIAL;
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
    heim_debug(ctx->hctx, 5, "JWT-TLS: initialized TLS server");
    return GSS_S_COMPLETE;
}

/*
 * Drive TLS handshake (server side)
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
 * Receive JWT over TLS (as application data)
 *
 * For protected mode, the wire format is:
 *   <flags:8 bytes, network order>[<cb_data>]<JWT string>
 *
 * The flags field is 64 bits for future expansion. Currently only the
 * lower 32 bits are used (matching the GSS-API flags).
 *
 * If GSS_JWT_FLAG_CB_PRESENT is set, cb_data contains:
 *   - 1 byte: cb_type_len (0 if no type)
 *   - cb_type_len bytes: cb_type string (no null terminator)
 *   - 32 bytes: cb_hash
 *
 * Parses the flags and stores them in ctx->flags (as requested flags).
 * If CB data is present, extracts the type and hash.
 */
static OM_uint32
recv_jwt_over_tls(OM_uint32 *minor, gss_jwt_ctx ctx,
                  const gss_buffer_t input_token,
                  char **jwt_out)
{
    tls_backend_status status;
    uint8_t *data;
    size_t data_len;
    size_t offset;
    uint64_t flags64;
    OM_uint32 req_flags;

    if (input_token == GSS_C_NO_BUFFER || input_token->length == 0) {
        *minor = EINVAL;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    /* Allocate buffer for decrypted data */
    data_len = input_token->length;  /* Will be smaller after decryption */
    data = malloc(data_len + 1);
    if (data == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    tls_iobuf_reset(&ctx->tls_recv_buf);
    if (tls_iobuf_append(&ctx->tls_recv_buf, input_token->value,
                         input_token->length) != 0) {
        free(data);
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    status = tls_backend_decrypt(ctx->tls_backend, data, &data_len);
    if (status != TLS_BACKEND_OK) {
        heim_debug(ctx->hctx, 1, "JWT-TLS: failed to decrypt JWT");
        free(data);
        *minor = EPROTO;
        return GSS_S_FAILURE;
    }

    /* Parse 64-bit flags from message */
    if (data_len < 8) {
        heim_debug(ctx->hctx, 1, "JWT-TLS: message too short for flags");
        free(data);
        *minor = EPROTO;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    /* Parse 64-bit flags (upper 32 bits reserved for future use) */
    flags64 = ((uint64_t)data[0] << 56) |
              ((uint64_t)data[1] << 48) |
              ((uint64_t)data[2] << 40) |
              ((uint64_t)data[3] << 32) |
              ((uint64_t)data[4] << 24) |
              ((uint64_t)data[5] << 16) |
              ((uint64_t)data[6] << 8) |
              ((uint64_t)data[7]);
    req_flags = (OM_uint32)(flags64 & 0xFFFFFFFF);
    offset = 8;

    heim_debug(ctx->hctx, 10, "JWT-TLS: received flags64=0x%llx req_flags=0x%x",
               (unsigned long long)flags64, req_flags);

    /* Store requested flags for response calculation */
    ctx->flags = req_flags;

    /* Check for CB data in message */
    if (req_flags & GSS_JWT_FLAG_CB_PRESENT) {
        uint8_t cb_type_len;

        /* Need at least 1 byte for type_len + 32 bytes for hash */
        if (data_len < offset + 1 + 32) {
            heim_debug(ctx->hctx, 1, "JWT-TLS: message too short for CB data");
            free(data);
            *minor = EPROTO;
            return GSS_S_DEFECTIVE_TOKEN;
        }

        /* Parse CB type length */
        cb_type_len = data[offset++];

        /* Check we have room for type + hash */
        if (data_len < offset + cb_type_len + 32) {
            heim_debug(ctx->hctx, 1, "JWT-TLS: message too short for CB type+hash");
            free(data);
            *minor = EPROTO;
            return GSS_S_DEFECTIVE_TOKEN;
        }

        /* Extract CB type if present */
        if (cb_type_len > 0) {
            ctx->cb_type = malloc(cb_type_len + 1);
            if (ctx->cb_type == NULL) {
                free(data);
                *minor = ENOMEM;
                return GSS_S_FAILURE;
            }
            memcpy(ctx->cb_type, data + offset, cb_type_len);
            ctx->cb_type[cb_type_len] = '\0';
            ctx->have_cb_type = 1;
            offset += cb_type_len;
            heim_debug(ctx->hctx, 10, "JWT-TLS: received CB type=%s", ctx->cb_type);
        }

        /* Extract CB hash */
        memcpy(ctx->cb_hash, data + offset, 32);
        ctx->have_cb_hash = 1;
        offset += 32;

        heim_debug(ctx->hctx, 10, "JWT-TLS: received CB from initiator");
    }

    /* Extract JWT (skip header) */
    data_len -= offset;
    memmove(data, data + offset, data_len);
    data[data_len] = '\0';
    *jwt_out = (char *)data;

    heim_debug(ctx->hctx, 5, "JWT-TLS: received JWT (%zu bytes)", data_len);
    return GSS_S_COMPLETE;
}

/*
 * Send response over TLS
 *
 * For protected mode, the wire format is:
 *   <flags:4 bytes, network order><status string>
 *
 * The flags field contains the ret_flags (what the acceptor supports).
 */
static OM_uint32
send_response_over_tls(OM_uint32 *minor, gss_jwt_ctx ctx,
                       const char *response, gss_buffer_t output_token)
{
    tls_backend_status status;
    size_t response_len = strlen(response);
    size_t msg_len = 4 + response_len;
    uint8_t *msg;

    msg = malloc(msg_len);
    if (msg == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    /* Encode flags in network byte order */
    msg[0] = (ctx->flags >> 24) & 0xFF;
    msg[1] = (ctx->flags >> 16) & 0xFF;
    msg[2] = (ctx->flags >> 8) & 0xFF;
    msg[3] = ctx->flags & 0xFF;

    /* Append response */
    memcpy(msg + 4, response, response_len);

    heim_debug(ctx->hctx, 10, "JWT-TLS: sending flags=0x%x with response", ctx->flags);

    tls_iobuf_reset(&ctx->tls_send_buf);

    status = tls_backend_encrypt(ctx->tls_backend, msg, msg_len);
    free(msg);

    if (status != TLS_BACKEND_OK) {
        heim_debug(ctx->hctx, 1, "JWT-TLS: failed to encrypt response");
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

    heim_debug(ctx->hctx, 5, "JWT-TLS: sent response (%zu bytes encrypted)",
               output_token->length);
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
 * Verify channel bindings
 *
 * Compares the initiator's channel bindings (from wire format or JWT claim)
 * against the acceptor's channel bindings.
 *
 * For TLS protected mode:
 *   - Initiator's CB comes from ctx->cb_hash (sent in wire format)
 *
 * For unprotected mode (raw JWT):
 *   - Initiator's CB comes from the JWT "cb" claim
 *
 * Returns GSS_S_COMPLETE if CB matches (or no CB was provided by either side)
 * Returns GSS_S_BAD_BINDINGS if CB mismatch
 */
static OM_uint32
verify_channel_bindings(OM_uint32 *minor, gss_jwt_ctx ctx,
                        const char *jwt,
                        const uint8_t *acceptor_cb_hash,
                        int acceptor_has_cb)
{
    int initiator_has_cb = 0;
    uint8_t initiator_cb_hash[32];

    *minor = 0;

    /*
     * Get initiator's CB hash from either wire format or JWT claim
     */
    if (ctx->have_cb_hash) {
        /* TLS mode: CB came from wire format */
        memcpy(initiator_cb_hash, ctx->cb_hash, 32);
        initiator_has_cb = 1;
        heim_debug(ctx->hctx, 10, "JWT: initiator CB from wire format");
    } else if (jwt != NULL) {
        /* Check for CB claim in JWT */
        int has_cb = 0, cb_matches = 0;
        OM_uint32 major;

        major = _gss_jwt_check_cb_claim(minor, jwt,
                                        acceptor_has_cb ? acceptor_cb_hash : NULL,
                                        acceptor_has_cb ? 32 : 0,
                                        &has_cb, &cb_matches);
        if (major != GSS_S_COMPLETE) {
            heim_debug(ctx->hctx, 1, "JWT: failed to parse CB claim");
            return major;
        }

        if (has_cb) {
            /*
             * If JWT has CB claim and acceptor has CB, the check_cb_claim
             * already compared them. If they matched, cb_matches is true.
             * If acceptor doesn't have CB, we just note that initiator has CB.
             */
            initiator_has_cb = 1;
            if (acceptor_has_cb && !cb_matches) {
                heim_debug(ctx->hctx, 1, "JWT: channel bindings mismatch (JWT claim vs acceptor)");
                *minor = EACCES;
                return GSS_S_BAD_BINDINGS;
            }
            heim_debug(ctx->hctx, 10, "JWT: initiator CB from JWT claim");
        }
    }

    /*
     * Verify CB match
     *
     * RFC 2743 semantics:
     * - If initiator provides CB and acceptor provides CB, they must match
     * - If only one side provides CB, that's an error
     * - If neither side provides CB, that's OK
     */
    if (initiator_has_cb && acceptor_has_cb) {
        /* Both sides have CB - compare (already done for JWT claim above) */
        if (ctx->have_cb_hash) {
            /* TLS mode: compare wire format CB with acceptor's CB */
            if (memcmp(initiator_cb_hash, acceptor_cb_hash, 32) != 0) {
                heim_debug(ctx->hctx, 1, "JWT: channel bindings mismatch");
                *minor = EACCES;
                return GSS_S_BAD_BINDINGS;
            }
        }
        heim_debug(ctx->hctx, 5, "JWT: channel bindings verified");
    } else if (initiator_has_cb && !acceptor_has_cb) {
        /* Initiator has CB but acceptor doesn't */
        heim_debug(ctx->hctx, 1, "JWT: initiator provided CB but acceptor did not");
        *minor = EACCES;
        return GSS_S_BAD_BINDINGS;
    } else if (!initiator_has_cb && acceptor_has_cb) {
        /* Acceptor has CB but initiator doesn't */
        heim_debug(ctx->hctx, 1, "JWT: acceptor provided CB but initiator did not");
        *minor = EACCES;
        return GSS_S_BAD_BINDINGS;
    }
    /* else: neither side has CB, that's fine */

    return GSS_S_COMPLETE;
}

/*
 * Validate JWT and extract claims
 *
 * Uses hx509_jwt_verify_jwk for JWK-based validation or
 * hx509_jwt_verify for PEM key-based validation.
 */
OM_uint32
_gss_jwt_validate_token(OM_uint32 *minor,
                        gss_jwt_cred cred,
                        const char *jwt,
                        const char *expected_audience,
                        char **subject_out,
                        char **issuer_out,
                        time_t *expiry_out)
{
    hx509_context hx509ctx = NULL;
    heim_dict_t claims = NULL;
    heim_string_t str;
    heim_number_t num;
    int ret;

    *minor = 0;
    if (subject_out)
        *subject_out = NULL;
    if (issuer_out)
        *issuer_out = NULL;
    if (expiry_out)
        *expiry_out = 0;

    /* Need hx509 context for validation */
    if (cred->hx509ctx) {
        hx509ctx = cred->hx509ctx;
    } else {
        ret = hx509_context_init(&hx509ctx);
        if (ret) {
            *minor = ret;
            return GSS_S_FAILURE;
        }
    }

    /* Validate JWT */
    if (cred->jwks_cache) {
        /* Use cached JWK for validation */
        const char *jwk_json = heim_string_get_utf8(
            heim_dict_get_value(cred->jwks_cache, HSTR("jwk")));
        if (jwk_json == NULL) {
            heim_debug(cred->hctx, 1, "JWT: no JWK in cache");
            if (hx509ctx != cred->hx509ctx)
                hx509_context_free(&hx509ctx);
            *minor = EINVAL;
            return GSS_S_FAILURE;
        }

        ret = hx509_jwt_verify_jwk(hx509ctx, jwt, jwk_json,
                                   expected_audience, 0, &claims);
    } else {
        /* No JWK cache - can't validate signature */
        heim_debug(cred->hctx, 1, "JWT: no signing key configured for validation");
        if (hx509ctx != cred->hx509ctx)
            hx509_context_free(&hx509ctx);
        *minor = EINVAL;
        return GSS_S_DEFECTIVE_CREDENTIAL;
    }

    if (hx509ctx != cred->hx509ctx)
        hx509_context_free(&hx509ctx);

    if (ret) {
        heim_debug(cred->hctx, 1, "JWT: validation failed: %d", ret);
        *minor = ret;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    /* Extract subject */
    if (subject_out) {
        str = heim_dict_get_value(claims, HSTR("sub"));
        if (str && heim_get_tid(str) == HEIM_TID_STRING) {
            *subject_out = strdup(heim_string_get_utf8(str));
            if (*subject_out == NULL) {
                heim_release(claims);
                *minor = ENOMEM;
                return GSS_S_FAILURE;
            }
        }
    }

    /* Extract issuer */
    if (issuer_out) {
        str = heim_dict_get_value(claims, HSTR("iss"));
        if (str && heim_get_tid(str) == HEIM_TID_STRING) {
            *issuer_out = strdup(heim_string_get_utf8(str));
            if (*issuer_out == NULL) {
                free(*subject_out);
                if (subject_out)
                    *subject_out = NULL;
                heim_release(claims);
                *minor = ENOMEM;
                return GSS_S_FAILURE;
            }
        }
    }

    /* Extract expiry */
    if (expiry_out) {
        num = heim_dict_get_value(claims, HSTR("exp"));
        if (num && heim_get_tid(num) == HEIM_TID_NUMBER) {
            *expiry_out = (time_t)heim_number_get_long(num);
        }
    }

    /* Verify issuer if expected */
    if (cred->expected_issuer) {
        str = heim_dict_get_value(claims, HSTR("iss"));
        if (str == NULL || heim_get_tid(str) != HEIM_TID_STRING) {
            heim_debug(cred->hctx, 1, "JWT: missing issuer claim");
            heim_release(claims);
            free(*subject_out);
            free(*issuer_out);
            if (subject_out)
                *subject_out = NULL;
            if (issuer_out)
                *issuer_out = NULL;
            *minor = EACCES;
            return GSS_S_DEFECTIVE_TOKEN;
        }
        if (strcmp(heim_string_get_utf8(str), cred->expected_issuer) != 0) {
            heim_debug(cred->hctx, 1, "JWT: issuer mismatch: got %s, expected %s",
                       heim_string_get_utf8(str), cred->expected_issuer);
            heim_release(claims);
            free(*subject_out);
            free(*issuer_out);
            if (subject_out)
                *subject_out = NULL;
            if (issuer_out)
                *issuer_out = NULL;
            *minor = EACCES;
            return GSS_S_DEFECTIVE_TOKEN;
        }
    }

    heim_release(claims);
    return GSS_S_COMPLETE;
}

/*
 * Process JWT and complete context establishment
 */
static OM_uint32
process_jwt(OM_uint32 *minor, gss_jwt_ctx ctx,
            const struct gss_jwt_cred_desc *cred,
            const char *jwt,
            const uint8_t *acceptor_cb_hash,
            int acceptor_has_cb,
            gss_name_t *src_name,
            OM_uint32 *ret_flags,
            OM_uint32 *time_rec)
{
    OM_uint32 major;
    char *subject = NULL;
    char *issuer = NULL;
    time_t expiry = 0;

    /* Verify channel bindings before processing JWT */
    major = verify_channel_bindings(minor, ctx, jwt, acceptor_cb_hash, acceptor_has_cb);
    if (major != GSS_S_COMPLETE) {
        return major;
    }

    /* Store JWT */
    ctx->jwt_token = strdup(jwt);
    if (ctx->jwt_token == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }
    ctx->have_jwt = 1;

    heim_debug(ctx->hctx, 5, "JWT: validating token (%zu bytes)", strlen(jwt));

    /* Validate JWT */
    ctx->state = JWT_STATE_TOKEN_RECEIVED;

    major = _gss_jwt_validate_token(minor,
                                    (gss_jwt_cred)rk_UNCONST(cred),
                                    jwt,
                                    NULL,  /* expected_audience - TODO */
                                    &subject,
                                    &issuer,
                                    &expiry);
    if (major != GSS_S_COMPLETE) {
        heim_debug(ctx->hctx, 1, "JWT: token validation failed");
        return major;
    }

    ctx->subject = subject;
    ctx->issuer = issuer;
    ctx->expiry = expiry;

    heim_debug(ctx->hctx, 5, "JWT: validated token, subject=%s issuer=%s",
               subject ? subject : "(none)",
               issuer ? issuer : "(none)");

    /* Create peer name from subject */
    if (subject) {
        gss_buffer_desc name_buf;
        name_buf.value = subject;
        name_buf.length = strlen(subject);
        major = gss_import_name(minor, &name_buf, GSS_C_NT_USER_NAME,
                                &ctx->peer_name);
        if (major != GSS_S_COMPLETE) {
            heim_debug(ctx->hctx, 1, "JWT: failed to import peer name");
            return major;
        }
    }

    /* Context established */
    ctx->state = JWT_STATE_ESTABLISHED;
    ctx->open = 1;
    ctx->established_time = time(NULL);

    /* Set flags */
    ctx->flags = GSS_C_MUTUAL_FLAG |
                 GSS_C_REPLAY_FLAG |
                 GSS_C_SEQUENCE_FLAG;
    if (ctx->use_tls) {
        ctx->flags |= GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG;
    }

    /* Return source name if requested */
    if (src_name && ctx->peer_name) {
        major = gss_duplicate_name(minor, ctx->peer_name, src_name);
        if (major != GSS_S_COMPLETE) {
            return major;
        }
    }

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

/*
 * GSS-API accept_sec_context for JWT mechanism
 */
OM_uint32 GSSAPI_CALLCONV
_gss_jwt_accept_sec_context(OM_uint32 *minor,
                            gss_ctx_id_t *context_handle,
                            gss_const_cred_id_t cred_handle,
                            const gss_buffer_t input_token,
                            const gss_channel_bindings_t bindings,
                            gss_name_t *src_name,
                            gss_OID *mech_type,
                            gss_buffer_t output_token,
                            OM_uint32 *ret_flags,
                            OM_uint32 *time_rec,
                            gss_cred_id_t *delegated_cred)
{
    OM_uint32 major, tmp_minor;
    gss_jwt_ctx ctx;
    const struct gss_jwt_cred_desc *cred = (const void *)cred_handle;
    char *jwt = NULL;
    uint8_t acceptor_cb_hash[32];
    char *acceptor_cb_type = NULL;
    int acceptor_has_cb = 0;

    *minor = 0;

    /* Compute acceptor's channel bindings hash if provided */
    if (bindings != GSS_C_NO_CHANNEL_BINDINGS) {
        major = _gss_jwt_compute_cb_hash(minor, bindings, acceptor_cb_hash,
                                         &acceptor_cb_type);
        if (major != GSS_S_COMPLETE) {
            return major;
        }
        acceptor_has_cb = 1;
        /* Free CB type - we only needed it for consistent hash computation */
        free(acceptor_cb_type);
        acceptor_cb_type = NULL;
    }

    /* Initialize output parameters */
    output_token->length = 0;
    output_token->value = NULL;
    if (src_name)
        *src_name = GSS_C_NO_NAME;
    if (mech_type)
        *mech_type = GSS_JWT_MECHANISM;
    if (ret_flags)
        *ret_flags = 0;
    if (time_rec)
        *time_rec = GSS_C_INDEFINITE;
    if (delegated_cred)
        *delegated_cred = GSS_C_NO_CREDENTIAL;

    /* Credential is required */
    if (cred == NULL) {
        *minor = EINVAL;
        return GSS_S_NO_CRED;
    }

    /* Input token is required */
    if (input_token == NULL || input_token->length == 0) {
        *minor = EINVAL;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    /* First call - create new context */
    if (*context_handle == GSS_C_NO_CONTEXT) {
        jwt_token_type token_type;
        gss_buffer_desc inner_token = GSS_C_EMPTY_BUFFER;
        gss_buffer_t work_token;

        major = alloc_jwt_context_acceptor(minor, cred, &ctx);
        if (major != GSS_S_COMPLETE)
            return major;

        *context_handle = (gss_ctx_id_t)ctx;

        heim_debug(ctx->hctx, 5, "JWT: accepting context");

        /* Detect token type */
        token_type = detect_token_type(input_token);

        switch (token_type) {
        case JWT_TOKEN_RFC2743_FRAMED:
            /*
             * RFC 2743 framed token - GSS-JWT with TLS protection.
             * Decapsulate to get inner TLS ClientHello.
             */
            heim_debug(ctx->hctx, 5, "JWT: RFC 2743 framed token (protected mode)");

            major = gss_decapsulate_token(input_token, GSS_JWT_MECHANISM,
                                          &inner_token);
            if (major != GSS_S_COMPLETE) {
                heim_debug(ctx->hctx, 1, "JWT: failed to decapsulate token");
                _gss_jwt_delete_sec_context(&tmp_minor, context_handle, NULL);
                *minor = EINVAL;
                return GSS_S_DEFECTIVE_TOKEN;
            }

            /* Inner token should be TLS ClientHello */
            if (!is_tls_handshake(&inner_token)) {
                heim_debug(ctx->hctx, 1, "JWT: inner token is not TLS ClientHello");
                free(inner_token.value);
                _gss_jwt_delete_sec_context(&tmp_minor, context_handle, NULL);
                *minor = EINVAL;
                return GSS_S_DEFECTIVE_TOKEN;
            }

            work_token = &inner_token;
            goto process_tls;

        case JWT_TOKEN_RAW_TLS:
            /*
             * Raw TLS ClientHello - this could be GSS-TLS or legacy GSS-JWT.
             * For backwards compatibility, accept it as GSS-JWT with TLS.
             */
            heim_debug(ctx->hctx, 5, "JWT-TLS: detected raw TLS ClientHello");
            work_token = input_token;

        process_tls:
            major = init_tls_server(minor, ctx, cred);
            if (major != GSS_S_COMPLETE) {
                if (inner_token.value)
                    free(inner_token.value);
                _gss_jwt_delete_sec_context(&tmp_minor, context_handle, NULL);
                return major;
            }

            ctx->state = JWT_STATE_TLS_HANDSHAKE;

            /* Process TLS handshake */
            major = drive_tls_handshake(minor, ctx, work_token, output_token);
            if (inner_token.value)
                free(inner_token.value);

            if (major == GSS_S_FAILURE) {
                _gss_jwt_delete_sec_context(&tmp_minor, context_handle, NULL);
                return major;
            }

            if (ret_flags)
                *ret_flags = 0;
            return GSS_S_CONTINUE_NEEDED;

        case JWT_TOKEN_RAW_JWT:
            /* Raw JWT - unprotected mode (no security services) */
            heim_debug(ctx->hctx, 5, "JWT: raw JWT token (unprotected mode)");

            jwt = malloc(input_token->length + 1);
            if (jwt == NULL) {
                *minor = ENOMEM;
                _gss_jwt_delete_sec_context(&tmp_minor, context_handle, NULL);
                return GSS_S_FAILURE;
            }
            memcpy(jwt, input_token->value, input_token->length);
            jwt[input_token->length] = '\0';

            major = process_jwt(minor, ctx, cred, jwt,
                                acceptor_cb_hash, acceptor_has_cb,
                                src_name, ret_flags, time_rec);
            free(jwt);

            if (major != GSS_S_COMPLETE) {
                /* Send error response with specific message for CB mismatch */
                if (major == GSS_S_BAD_BINDINGS)
                    output_token->value = strdup("ERROR: Channel bindings mismatch");
                else
                    output_token->value = strdup("ERROR: Invalid JWT");
                if (output_token->value)
                    output_token->length = strlen(output_token->value);
                _gss_jwt_delete_sec_context(&tmp_minor, context_handle, NULL);
                return major;
            }

            /* Return "OK" acknowledgment */
            output_token->value = strdup("OK");
            if (output_token->value == NULL) {
                *minor = ENOMEM;
                _gss_jwt_delete_sec_context(&tmp_minor, context_handle, NULL);
                return GSS_S_FAILURE;
            }
            output_token->length = 2;

            heim_debug(ctx->hctx, 5, "JWT: context established (unprotected)");
            return GSS_S_COMPLETE;

        case JWT_TOKEN_UNKNOWN:
        default:
            heim_debug(ctx->hctx, 1, "JWT: unrecognized token format");
            _gss_jwt_delete_sec_context(&tmp_minor, context_handle, NULL);
            *minor = EINVAL;
            return GSS_S_DEFECTIVE_TOKEN;
        }

        /* NOT REACHED - all cases return */
    }

    /* Subsequent call - process ongoing TLS or JWT */
    ctx = (gss_jwt_ctx)*context_handle;

    /* TLS handshake in progress */
    if (ctx->state == JWT_STATE_TLS_HANDSHAKE) {
        major = drive_tls_handshake(minor, ctx, input_token, output_token);
        if (major == GSS_S_FAILURE) {
            return major;
        }

        if (major == GSS_S_CONTINUE_NEEDED) {
            if (ret_flags)
                *ret_flags = 0;
            return GSS_S_CONTINUE_NEEDED;
        }

        /* TLS handshake complete - check for 0-RTT early data (JWT) */
        heim_debug(ctx->hctx, 5, "JWT-TLS: handshake done");

        /*
         * Check if client sent JWT as 0-RTT early data.
         * If so, we can process it immediately without another round trip.
         *
         * Early data format: <flags:8 bytes, network order>[<cb_data>]<JWT string>
         */
        {
            uint8_t early_data_buf[JWT_MAX_EARLY_DATA_SIZE + 1];
            size_t early_data_len = sizeof(early_data_buf) - 1;
            tls_backend_status status;
            uint64_t flags64;
            OM_uint32 req_flags;

            status = tls_backend_get_early_data(ctx->tls_backend,
                                                 early_data_buf, &early_data_len);
            if (status == TLS_BACKEND_OK && early_data_len > 8) {
                size_t offset = 0;

                heim_debug(ctx->hctx, 5, "JWT-TLS: received %zu bytes as 0-RTT early data",
                           early_data_len);
                ctx->early_data_accepted = 1;

                /* Parse 64-bit flags from early data */
                flags64 = ((uint64_t)early_data_buf[0] << 56) |
                          ((uint64_t)early_data_buf[1] << 48) |
                          ((uint64_t)early_data_buf[2] << 40) |
                          ((uint64_t)early_data_buf[3] << 32) |
                          ((uint64_t)early_data_buf[4] << 24) |
                          ((uint64_t)early_data_buf[5] << 16) |
                          ((uint64_t)early_data_buf[6] << 8) |
                          ((uint64_t)early_data_buf[7]);
                req_flags = (OM_uint32)(flags64 & 0xFFFFFFFF);
                offset = 8;

                heim_debug(ctx->hctx, 10, "JWT-TLS: 0-RTT flags64=0x%llx req_flags=0x%x",
                           (unsigned long long)flags64, req_flags);
                ctx->flags = req_flags;

                /* Check for CB data in early data */
                if (req_flags & GSS_JWT_FLAG_CB_PRESENT) {
                    uint8_t cb_type_len;

                    /* Need at least 1 byte for type_len + 32 bytes for hash */
                    if (early_data_len < offset + 1 + 32) {
                        heim_debug(ctx->hctx, 1, "JWT-TLS: 0-RTT data too short for CB data");
                        *minor = EPROTO;
                        return GSS_S_DEFECTIVE_TOKEN;
                    }

                    /* Parse CB type length */
                    cb_type_len = early_data_buf[offset++];

                    /* Check we have room for type + hash */
                    if (early_data_len < offset + cb_type_len + 32) {
                        heim_debug(ctx->hctx, 1, "JWT-TLS: 0-RTT data too short for CB type+hash");
                        *minor = EPROTO;
                        return GSS_S_DEFECTIVE_TOKEN;
                    }

                    /* Extract CB type if present */
                    if (cb_type_len > 0) {
                        ctx->cb_type = malloc(cb_type_len + 1);
                        if (ctx->cb_type == NULL) {
                            *minor = ENOMEM;
                            return GSS_S_FAILURE;
                        }
                        memcpy(ctx->cb_type, early_data_buf + offset, cb_type_len);
                        ctx->cb_type[cb_type_len] = '\0';
                        ctx->have_cb_type = 1;
                        offset += cb_type_len;
                        heim_debug(ctx->hctx, 10, "JWT-TLS: 0-RTT CB type=%s", ctx->cb_type);
                    }

                    /* Extract CB hash */
                    memcpy(ctx->cb_hash, early_data_buf + offset, 32);
                    ctx->have_cb_hash = 1;
                    offset += 32;
                    heim_debug(ctx->hctx, 10, "JWT-TLS: 0-RTT CB received");
                }

                /* Process JWT from early data (skip header) */
                early_data_buf[early_data_len] = '\0';
                jwt = strdup((char *)(early_data_buf + offset));
                if (jwt == NULL) {
                    *minor = ENOMEM;
                    return GSS_S_FAILURE;
                }

                major = process_jwt(minor, ctx, cred, jwt,
                                    acceptor_cb_hash, acceptor_has_cb,
                                    src_name, ret_flags, time_rec);
                free(jwt);

                if (major != GSS_S_COMPLETE) {
                    /* Send error response over TLS with specific CB message */
                    if (major == GSS_S_BAD_BINDINGS)
                        send_response_over_tls(&tmp_minor, ctx, "ERROR: Channel bindings mismatch",
                                               output_token);
                    else
                        send_response_over_tls(&tmp_minor, ctx, "ERROR: Invalid JWT",
                                               output_token);
                    return major;
                }

                /* Derive per-message sequence numbers from TLS exporter */
                major = derive_sequence_numbers(minor, ctx);
                if (major != GSS_S_COMPLETE) {
                    heim_debug(ctx->hctx, 1, "JWT-TLS: failed to derive sequence numbers");
                    /* Non-fatal - context still works, just no sequence protection */
                }

                /* Send "OK" response over TLS */
                major = send_response_over_tls(minor, ctx, "OK", output_token);
                if (major != GSS_S_COMPLETE) {
                    return major;
                }

                heim_debug(ctx->hctx, 5, "JWT-TLS: context established (0-RTT)");
                return GSS_S_COMPLETE;
            }
        }

        /* No early data - wait for JWT as application data */
        heim_debug(ctx->hctx, 5, "JWT-TLS: waiting for JWT (no early data)");
        ctx->state = JWT_STATE_TOKEN_RECEIVED;

        if (ret_flags)
            *ret_flags = 0;
        return GSS_S_CONTINUE_NEEDED;
    }

    /* TLS established, waiting for JWT */
    if (ctx->state == JWT_STATE_TOKEN_RECEIVED && ctx->use_tls) {
        /* Receive JWT over TLS */
        major = recv_jwt_over_tls(minor, ctx, input_token, &jwt);
        if (major != GSS_S_COMPLETE) {
            /* Send error response */
            send_response_over_tls(&tmp_minor, ctx, "ERROR: Failed to decrypt JWT",
                                   output_token);
            return major;
        }

        /* Process JWT */
        major = process_jwt(minor, ctx, cred, jwt,
                            acceptor_cb_hash, acceptor_has_cb,
                            src_name, ret_flags, time_rec);
        free(jwt);

        if (major != GSS_S_COMPLETE) {
            /* Send error response over TLS with specific CB message */
            if (major == GSS_S_BAD_BINDINGS)
                send_response_over_tls(&tmp_minor, ctx, "ERROR: Channel bindings mismatch",
                                       output_token);
            else
                send_response_over_tls(&tmp_minor, ctx, "ERROR: Invalid JWT",
                                       output_token);
            return major;
        }

        /* Derive per-message sequence numbers from TLS exporter */
        major = derive_sequence_numbers(minor, ctx);
        if (major != GSS_S_COMPLETE) {
            heim_debug(ctx->hctx, 1, "JWT-TLS: failed to derive sequence numbers");
            /* Non-fatal - context still works, just no sequence protection */
        }

        /* Send "OK" response over TLS */
        major = send_response_over_tls(minor, ctx, "OK", output_token);
        if (major != GSS_S_COMPLETE) {
            return major;
        }

        heim_debug(ctx->hctx, 5, "JWT-TLS: context established");
        return GSS_S_COMPLETE;
    }

    /* Unexpected state */
    heim_debug(ctx->hctx, 1, "JWT: unexpected state %d", ctx->state);
    *minor = EINVAL;
    return GSS_S_FAILURE;
}
