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
 * Custom send callback for s2n-tls
 *
 * Captures TLS records that would be sent over the wire
 * and buffers them for return as GSS output tokens.
 */
int
_gss_tls_send_cb(void *io_context, const uint8_t *buf, uint32_t len)
{
    gss_tls_ctx ctx = (gss_tls_ctx)io_context;

    /* Grow buffer if needed */
    if (ctx->send_buf.len + len > ctx->send_buf.capacity) {
        size_t new_cap = ctx->send_buf.capacity * 2;
        uint8_t *new_data;

        if (new_cap < ctx->send_buf.len + len)
            new_cap = ctx->send_buf.len + len;
        if (new_cap < GSS_TLS_SEND_BUF_INITIAL_CAPACITY)
            new_cap = GSS_TLS_SEND_BUF_INITIAL_CAPACITY;

        new_data = realloc(ctx->send_buf.data, new_cap);
        if (new_data == NULL) {
            errno = ENOMEM;
            return -1;
        }
        ctx->send_buf.data = new_data;
        ctx->send_buf.capacity = new_cap;
    }

    memcpy(ctx->send_buf.data + ctx->send_buf.len, buf, len);
    ctx->send_buf.len += len;
    return (int)len;
}

/*
 * Custom receive callback for s2n-tls
 *
 * Provides GSS input tokens to s2n-tls as if they
 * were received from the network.
 */
int
_gss_tls_recv_cb(void *io_context, uint8_t *buf, uint32_t len)
{
    gss_tls_ctx ctx = (gss_tls_ctx)io_context;
    size_t available;
    size_t to_copy;

    available = ctx->recv_buf.len - ctx->recv_buf.pos;
    if (available == 0) {
        /* No more data - tell s2n-tls we would block */
        errno = EWOULDBLOCK;
        return -1;
    }

    to_copy = (len < available) ? len : available;
    memcpy(buf, ctx->recv_buf.data + ctx->recv_buf.pos, to_copy);
    ctx->recv_buf.pos += to_copy;
    return (int)to_copy;
}

#ifdef HAVE_S2N

/*
 * Async private key callback for s2n-tls
 *
 * Delegates private key operations to hx509, which supports
 * PKCS#11 tokens, HSMs, and other key storage backends.
 */
static int
gss_tls_pkey_callback(struct s2n_connection *conn, struct s2n_async_pkey_op *op)
{
    /* TODO: Implement hx509 private key integration */
    /* For now, return failure - real implementation will use hx509 */
    return S2N_FAILURE;
}

/*
 * Certificate validation callback for s2n-tls
 *
 * Delegates certificate validation to hx509.
 */
static int
gss_tls_cert_validator(struct s2n_connection *conn,
                       struct s2n_cert_validation_info *info,
                       void *context)
{
    /* TODO: Implement hx509 certificate validation */
    /* For now, accept all - real implementation will validate with hx509 */
    s2n_cert_validation_accept(info);
    return S2N_SUCCESS;
}

/*
 * Configure s2n-tls for client mode
 */
static OM_uint32
configure_client(OM_uint32 *minor, gss_tls_ctx ctx, gss_tls_cred cred,
                 gss_const_name_t target_name)
{
    int rc;

    ctx->config = s2n_config_new();
    if (ctx->config == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    /* Set up custom I/O callbacks */
    ctx->conn = s2n_connection_new(S2N_CLIENT);
    if (ctx->conn == NULL) {
        *minor = ENOMEM;
        s2n_config_free(ctx->config);
        ctx->config = NULL;
        return GSS_S_FAILURE;
    }

    rc = s2n_connection_set_config(ctx->conn, ctx->config);
    if (rc != S2N_SUCCESS) {
        *minor = s2n_errno;
        return GSS_S_FAILURE;
    }

    rc = s2n_connection_set_send_cb(ctx->conn, _gss_tls_send_cb);
    if (rc != S2N_SUCCESS) {
        *minor = s2n_errno;
        return GSS_S_FAILURE;
    }

    rc = s2n_connection_set_send_ctx(ctx->conn, ctx);
    if (rc != S2N_SUCCESS) {
        *minor = s2n_errno;
        return GSS_S_FAILURE;
    }

    rc = s2n_connection_set_recv_cb(ctx->conn, _gss_tls_recv_cb);
    if (rc != S2N_SUCCESS) {
        *minor = s2n_errno;
        return GSS_S_FAILURE;
    }

    rc = s2n_connection_set_recv_ctx(ctx->conn, ctx);
    if (rc != S2N_SUCCESS) {
        *minor = s2n_errno;
        return GSS_S_FAILURE;
    }

    /* Set SNI if we have a hostname target */
    if (target_name != GSS_C_NO_NAME) {
        gss_tls_name name = (gss_tls_name)target_name;
        if (name->type == GSS_TLS_NAME_HOSTBASED && name->u.hostbased.hostname) {
            s2n_set_server_name(ctx->conn, name->u.hostbased.hostname);
        }
    }

    /* Configure certificate validation callback */
    /* TODO: s2n_config_set_cert_validation_cb is unstable API */

    /* Configure private key callback if we have a credential with a key */
    if (cred && cred->key) {
        s2n_config_set_async_pkey_callback(ctx->config, gss_tls_pkey_callback);
        /* TODO: Load certificate chain from cred->certs */
    }

    return GSS_S_COMPLETE;
}

/*
 * Extract peer identity after successful handshake
 */
static void
extract_peer_identity(gss_tls_ctx ctx)
{
    struct s2n_cert_chain_and_key *peer_chain;
    uint32_t cert_count;

    peer_chain = s2n_cert_chain_and_key_new();
    if (peer_chain == NULL)
        return;

    if (s2n_connection_get_peer_cert_chain(ctx->conn, peer_chain) != S2N_SUCCESS)
        goto out;

    if (s2n_cert_chain_get_length(peer_chain, &cert_count) != S2N_SUCCESS)
        goto out;

    if (cert_count > 0) {
        struct s2n_cert *leaf;
        const uint8_t *der_data;
        uint32_t der_length;

        if (s2n_cert_chain_get_cert(peer_chain, &leaf, 0) != S2N_SUCCESS)
            goto out;

        if (s2n_cert_get_der(leaf, &der_data, &der_length) != S2N_SUCCESS)
            goto out;

        /* Parse with hx509 and create GSS name */
        if (ctx->hx509ctx) {
            hx509_cert hxcert;
            if (hx509_cert_init_data(ctx->hx509ctx, der_data, der_length,
                                     &hxcert) == 0) {
                ctx->peer_cert = hxcert;
                /* TODO: Create gss_tls_name from certificate subject */
            }
        }
    } else {
        /* Anonymous peer */
        ctx->peer_name = _gss_tls_anonymous_identity;
    }

out:
    s2n_cert_chain_and_key_free(peer_chain);
}

#endif /* HAVE_S2N */

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
#ifdef HAVE_S2N
    gss_tls_ctx ctx = (gss_tls_ctx)*context_handle;
    gss_tls_cred cred = (gss_tls_cred)cred_handle;
    OM_uint32 major = GSS_S_COMPLETE;
    s2n_blocked_status blocked;
    int rc;

    *minor = 0;
    if (output_token != GSS_C_NO_BUFFER) {
        output_token->length = 0;
        output_token->value = NULL;
    }

    /* First call: allocate context and configure s2n-tls */
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

        /* Initialize hx509 context */
        if (hx509_context_init(&ctx->hx509ctx) != 0) {
            *minor = ENOMEM;
            free(ctx);
            return GSS_S_FAILURE;
        }

        /* Configure s2n-tls for client mode */
        major = configure_client(minor, ctx, cred, target_name);
        if (major != GSS_S_COMPLETE) {
            hx509_context_free(&ctx->hx509ctx);
            free(ctx);
            return major;
        }

        *context_handle = (gss_ctx_id_t)ctx;
    }

    /* Provide input token data to recv callback */
    if (input_token != GSS_C_NO_BUFFER && input_token->length > 0) {
        ctx->recv_buf.data = input_token->value;
        ctx->recv_buf.len = input_token->length;
        ctx->recv_buf.pos = 0;
    } else {
        ctx->recv_buf.data = NULL;
        ctx->recv_buf.len = 0;
        ctx->recv_buf.pos = 0;
    }

    /* Clear output buffer for this round */
    ctx->send_buf.len = 0;

    /* Drive TLS handshake */
    rc = s2n_negotiate(ctx->conn, &blocked);

    /* Return any TLS records that were generated */
    if (ctx->send_buf.len > 0 && output_token != GSS_C_NO_BUFFER) {
        output_token->value = malloc(ctx->send_buf.len);
        if (output_token->value == NULL) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }
        memcpy(output_token->value, ctx->send_buf.data, ctx->send_buf.len);
        output_token->length = ctx->send_buf.len;
    }

    if (rc == S2N_SUCCESS) {
        /* Handshake complete */
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
    } else if (s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED) {
        /* Need more data - continue handshake */
        if (ret_flags)
            *ret_flags = 0;
        if (time_rec)
            *time_rec = 0;

        major = GSS_S_CONTINUE_NEEDED;
    } else {
        /* Error */
        *minor = s2n_errno;
        major = GSS_S_FAILURE;
    }

    if (actual_mech_type)
        *actual_mech_type = GSS_TLS_MECHANISM;

    return major;

#else /* !HAVE_S2N */
    (void)cred_handle;
    (void)context_handle;
    (void)target_name;
    (void)mech_type;
    (void)req_flags;
    (void)time_req;
    (void)input_chan_bindings;
    (void)input_token;
    (void)actual_mech_type;
    (void)output_token;
    (void)ret_flags;
    (void)time_rec;

    *minor = ENOTSUP;
    return GSS_S_UNAVAILABLE;
#endif /* HAVE_S2N */
}
