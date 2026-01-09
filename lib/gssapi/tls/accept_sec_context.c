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

/*
 * Configure s2n-tls for server mode
 */
static OM_uint32
configure_server(OM_uint32 *minor, gss_tls_ctx ctx, gss_tls_cred cred)
{
    int rc;

    ctx->config = s2n_config_new();
    if (ctx->config == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    /* Set up connection in server mode */
    ctx->conn = s2n_connection_new(S2N_SERVER);
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

    /* Set up custom I/O callbacks */
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

    /* Configure client certificate requirements */
    if (cred && cred->require_client_cert) {
        s2n_config_set_client_auth_type(ctx->config, S2N_CERT_AUTH_REQUIRED);
    } else {
        s2n_config_set_client_auth_type(ctx->config, S2N_CERT_AUTH_OPTIONAL);
    }

    /* TODO: Load server certificate and key from cred */
    /* TODO: Set up certificate validation callback */
    /* TODO: Set up async private key callback */

    return GSS_S_COMPLETE;
}

/*
 * Extract client identity after successful handshake
 */
static void
extract_client_identity(gss_tls_ctx ctx, gss_name_t *src_name)
{
    struct s2n_cert_chain_and_key *client_chain;
    uint32_t cert_count;

    if (src_name)
        *src_name = GSS_C_NO_NAME;

    client_chain = s2n_cert_chain_and_key_new();
    if (client_chain == NULL)
        return;

    if (s2n_connection_get_peer_cert_chain(ctx->conn, client_chain) != S2N_SUCCESS)
        goto out;

    if (s2n_cert_chain_get_length(client_chain, &cert_count) != S2N_SUCCESS)
        goto out;

    if (cert_count > 0) {
        struct s2n_cert *leaf;
        const uint8_t *der_data;
        uint32_t der_length;

        if (s2n_cert_chain_get_cert(client_chain, &leaf, 0) != S2N_SUCCESS)
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
                /* ctx->peer_name = ... */
            }
        }

        if (src_name && ctx->peer_name)
            *src_name = ctx->peer_name;
    } else {
        /* Anonymous client (no client certificate) */
        ctx->peer_name = _gss_tls_anonymous_identity;
        if (src_name)
            *src_name = _gss_tls_anonymous_identity;
    }

out:
    s2n_cert_chain_and_key_free(client_chain);
}

#endif /* HAVE_S2N */

/*
 * GSS-API accept_sec_context for TLS mechanism
 *
 * Accepts a TLS handshake as a server. Input/output tokens
 * are raw TLS records.
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_accept_sec_context(OM_uint32 *minor,
                            gss_ctx_id_t *context_handle,
                            gss_const_cred_id_t verifier_cred_handle,
                            const gss_buffer_t input_token,
                            const gss_channel_bindings_t input_chan_bindings,
                            gss_name_t *src_name,
                            gss_OID *mech_type,
                            gss_buffer_t output_token,
                            OM_uint32 *ret_flags,
                            OM_uint32 *time_rec,
                            gss_cred_id_t *delegated_cred_handle)
{
#ifdef HAVE_S2N
    gss_tls_ctx ctx = (gss_tls_ctx)*context_handle;
    gss_tls_cred cred = (gss_tls_cred)verifier_cred_handle;
    OM_uint32 major = GSS_S_COMPLETE;
    s2n_blocked_status blocked;
    int rc;

    *minor = 0;

    /* Initialize output parameters */
    if (output_token != GSS_C_NO_BUFFER) {
        output_token->length = 0;
        output_token->value = NULL;
    }
    if (src_name)
        *src_name = GSS_C_NO_NAME;
    if (delegated_cred_handle)
        *delegated_cred_handle = GSS_C_NO_CREDENTIAL;

    /* Must have input token */
    if (input_token == GSS_C_NO_BUFFER || input_token->length == 0) {
        *minor = EINVAL;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    /* First call: allocate context and configure s2n-tls */
    if (ctx == NULL) {
        ctx = calloc(1, sizeof(*ctx));
        if (ctx == NULL) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }

        ctx->is_initiator = 0; /* Server */
        ctx->cred = cred;

        /* Initialize hx509 context */
        if (hx509_context_init(&ctx->hx509ctx) != 0) {
            *minor = ENOMEM;
            free(ctx);
            return GSS_S_FAILURE;
        }

        /* Configure s2n-tls for server mode */
        major = configure_server(minor, ctx, cred);
        if (major != GSS_S_COMPLETE) {
            hx509_context_free(&ctx->hx509ctx);
            free(ctx);
            return major;
        }

        *context_handle = (gss_ctx_id_t)ctx;
    }

    /* Provide input token data to recv callback */
    ctx->recv_buf.data = input_token->value;
    ctx->recv_buf.len = input_token->length;
    ctx->recv_buf.pos = 0;

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

        /* Extract client identity from certificate */
        extract_client_identity(ctx, src_name);

        /* Set return flags */
        ctx->flags = GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG |
                     GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG |
                     GSS_C_TRANS_FLAG;

        if (ctx->peer_name != _gss_tls_anonymous_identity &&
            ctx->peer_name != GSS_C_NO_NAME) {
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

    if (mech_type)
        *mech_type = GSS_TLS_MECHANISM;

    return major;

#else /* !HAVE_S2N */
    (void)context_handle;
    (void)verifier_cred_handle;
    (void)input_token;
    (void)input_chan_bindings;
    (void)src_name;
    (void)mech_type;
    (void)output_token;
    (void)ret_flags;
    (void)time_rec;
    (void)delegated_cred_handle;

    *minor = ENOTSUP;
    return GSS_S_UNAVAILABLE;
#endif /* HAVE_S2N */
}
