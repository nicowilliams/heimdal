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
 * GSS-JWT mechanism stub implementations
 *
 * These are placeholder implementations that return GSS_S_UNAVAILABLE
 * until the mechanism is fully implemented.
 *
 * Implemented elsewhere:
 *   - _gss_jwt_acquire_cred_from: cred.c
 *   - _gss_jwt_init_sec_context: init_sec_context.c
 *   - _gss_jwt_accept_sec_context: accept_sec_context.c
 *   - _gss_jwt_acquire_token: sts.c
 *   - _gss_jwt_validate_token: accept_sec_context.c
 */

#define JWT_NOT_IMPLEMENTED() do { \
    *minor = 0; \
    return GSS_S_UNAVAILABLE; \
} while (0)

/*
 * Context establishment
 *
 * Note: _gss_jwt_accept_sec_context is implemented in accept_sec_context.c
 */

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_delete_sec_context(OM_uint32 *minor,
                            gss_ctx_id_t *context_handle,
                            gss_buffer_t output_token)
{
    OM_uint32 tmp_minor;

    *minor = 0;
    if (context_handle && *context_handle) {
        gss_jwt_ctx ctx = (gss_jwt_ctx)*context_handle;

        /* Clean up TLS resources */
        if (ctx->use_tls) {
            if (ctx->tls_backend)
                tls_backend_destroy(ctx->tls_backend);
            tls_iobuf_free(&ctx->tls_recv_buf);
            tls_iobuf_free(&ctx->tls_send_buf);
            if (ctx->tls_hx509ctx)
                hx509_context_free(&ctx->tls_hx509ctx);
        }

        /* Clean up names (these are owned, not borrowed) */
        if (ctx->peer_name && ctx->peer_name != _gss_jwt_anonymous_identity)
            gss_release_name(&tmp_minor, &ctx->peer_name);
        if (ctx->target_name)
            gss_release_name(&tmp_minor, &ctx->target_name);

        /* Clean up heim context */
        if (ctx->hctx)
            heim_context_free(&ctx->hctx);

        free(ctx->jwt_token);
        free(ctx->subject);
        free(ctx->issuer);
        free(ctx->audience);
        free(ctx->early_data_buf);
        free(ctx->cb_type);
        free(ctx);
        *context_handle = GSS_C_NO_CONTEXT;
    }
    if (output_token) {
        output_token->length = 0;
        output_token->value = NULL;
    }
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_process_context_token(OM_uint32 *minor,
                               gss_const_ctx_id_t context_handle,
                               const gss_buffer_t token)
{
    JWT_NOT_IMPLEMENTED();
}

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_context_time(OM_uint32 *minor,
                      gss_const_ctx_id_t context_handle,
                      OM_uint32 *time_rec)
{
    const struct gss_jwt_ctx_desc *ctx = (const void *)context_handle;

    *minor = 0;
    if (ctx == NULL || !ctx->open) {
        *time_rec = 0;
        return GSS_S_NO_CONTEXT;
    }

    if (ctx->expiry == 0) {
        *time_rec = GSS_C_INDEFINITE;
    } else {
        time_t now = time(NULL);
        if (ctx->expiry <= now) {
            *time_rec = 0;
            return GSS_S_CONTEXT_EXPIRED;
        }
        *time_rec = (OM_uint32)(ctx->expiry - now);
    }
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_inquire_context(OM_uint32 *minor,
                         gss_const_ctx_id_t context_handle,
                         gss_name_t *src_name,
                         gss_name_t *targ_name,
                         OM_uint32 *lifetime_rec,
                         gss_OID *mech_type,
                         OM_uint32 *ctx_flags,
                         int *locally_initiated,
                         int *open)
{
    const struct gss_jwt_ctx_desc *ctx = (const void *)context_handle;

    *minor = 0;
    if (ctx == NULL)
        return GSS_S_NO_CONTEXT;

    if (src_name)
        *src_name = ctx->peer_name;
    if (targ_name)
        *targ_name = ctx->target_name;
    if (lifetime_rec) {
        OM_uint32 maj = _gss_jwt_context_time(minor, context_handle, lifetime_rec);
        if (GSS_ERROR(maj) && maj != GSS_S_CONTEXT_EXPIRED)
            return maj;
    }
    if (mech_type)
        *mech_type = GSS_JWT_MECHANISM;
    if (ctx_flags)
        *ctx_flags = ctx->flags;
    if (locally_initiated)
        *locally_initiated = ctx->is_initiator;
    if (open)
        *open = ctx->open;

    return GSS_S_COMPLETE;
}

/*
 * Per-message operations
 */

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_wrap(OM_uint32 *minor,
              gss_const_ctx_id_t context_handle,
              int conf_req,
              gss_qop_t qop,
              const gss_buffer_t input,
              int *conf_state,
              gss_buffer_t output)
{
    /* Cast away const - we need to modify I/O buffers */
    gss_jwt_ctx ctx = (gss_jwt_ctx)(uintptr_t)context_handle;
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

    /* TLS wrap requires TLS protection to be active */
    if (!ctx->use_tls || !ctx->tls_handshake_done) {
        *minor = ENOTSUP;
        return GSS_S_UNAVAILABLE;
    }

    if (qop != GSS_C_QOP_DEFAULT) {
        *minor = EINVAL;
        return GSS_S_BAD_QOP;
    }

    /* Clear output buffer for this operation */
    tls_iobuf_reset(&ctx->tls_send_buf);

    /* Encrypt data through TLS */
    status = tls_backend_encrypt(ctx->tls_backend, input->value, input->length);
    if (status != TLS_BACKEND_OK) {
        *minor = EPROTO;
        return GSS_S_FAILURE;
    }

    /* Copy TLS records to output token */
    if (ctx->tls_send_buf.len > 0) {
        output->value = malloc(ctx->tls_send_buf.len);
        if (output->value == NULL) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }
        memcpy(output->value, ctx->tls_send_buf.data, ctx->tls_send_buf.len);
        output->length = ctx->tls_send_buf.len;
    }

    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_unwrap(OM_uint32 *minor,
                gss_const_ctx_id_t context_handle,
                const gss_buffer_t input,
                gss_buffer_t output,
                int *conf_state,
                gss_qop_t *qop_state)
{
    /* Cast away const - we need to modify I/O buffers */
    gss_jwt_ctx ctx = (gss_jwt_ctx)(uintptr_t)context_handle;
    tls_backend_status status;
    uint8_t *plaintext;
    size_t plaintext_len;

    *minor = 0;
    output->length = 0;
    output->value = NULL;

    if (conf_state)
        *conf_state = 1; /* TLS always decrypts */
    if (qop_state)
        *qop_state = GSS_C_QOP_DEFAULT;

    /* Validate context */
    if (ctx == NULL || !ctx->open) {
        *minor = EINVAL;
        return GSS_S_NO_CONTEXT;
    }

    /* TLS unwrap requires TLS protection to be active */
    if (!ctx->use_tls || !ctx->tls_handshake_done) {
        *minor = ENOTSUP;
        return GSS_S_UNAVAILABLE;
    }

    if (input == NULL || input->length == 0) {
        *minor = EINVAL;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    /* Allocate buffer for decrypted data */
    plaintext_len = input->length; /* Will be smaller after decryption */
    plaintext = malloc(plaintext_len);
    if (plaintext == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    /* Provide input to recv buffer */
    tls_iobuf_reset(&ctx->tls_recv_buf);
    if (tls_iobuf_append(&ctx->tls_recv_buf, input->value, input->length) != 0) {
        free(plaintext);
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    /* Decrypt through TLS */
    status = tls_backend_decrypt(ctx->tls_backend, plaintext, &plaintext_len);
    if (status != TLS_BACKEND_OK) {
        free(plaintext);
        *minor = EPROTO;
        return GSS_S_FAILURE;
    }

    output->value = plaintext;
    output->length = plaintext_len;

    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_wrap_size_limit(OM_uint32 *minor,
                         gss_const_ctx_id_t context_handle,
                         int conf_req,
                         gss_qop_t qop_req,
                         OM_uint32 req_output_size,
                         OM_uint32 *max_input_size)
{
    *minor = 0;
    /* Conservative estimate - leave room for overhead */
    if (req_output_size > 64)
        *max_input_size = req_output_size - 64;
    else
        *max_input_size = 0;
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_get_mic(OM_uint32 *minor,
                 gss_const_ctx_id_t context_handle,
                 gss_qop_t qop,
                 const gss_buffer_t message,
                 gss_buffer_t token)
{
    JWT_NOT_IMPLEMENTED();
}

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_verify_mic(OM_uint32 *minor,
                    gss_const_ctx_id_t context_handle,
                    const gss_buffer_t message,
                    const gss_buffer_t token,
                    gss_qop_t *qop_state)
{
    JWT_NOT_IMPLEMENTED();
}

/*
 * Credential operations
 *
 * Note: _gss_jwt_acquire_cred_from is implemented in cred.c
 */

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_release_cred(OM_uint32 *minor,
                      gss_cred_id_t *cred_handle)
{
    *minor = 0;
    if (cred_handle && *cred_handle) {
        gss_jwt_cred cred = (gss_jwt_cred)*cred_handle;

        if (cred->hctx)
            heim_context_free(&cred->hctx);
        free(cred->sts_endpoint);
        free(cred->username);
        if (cred->password) {
            memset(cred->password, 0, strlen(cred->password));
            free(cred->password);
        }
        free(cred->password_file);
        free(cred->ccache);
        free(cred->token_file);
        if (cred->token) {
            memset(cred->token, 0, strlen(cred->token));
            free(cred->token);
        }
        if (cred->hx509ctx) {
            if (cred->client_certs)
                hx509_certs_free(&cred->client_certs);
            if (cred->client_key)
                hx509_private_key_free(&cred->client_key);
            if (cred->trust_anchors)
                hx509_certs_free(&cred->trust_anchors);
            if (cred->tls_certs)
                hx509_certs_free(&cred->tls_certs);
            if (cred->tls_key)
                hx509_private_key_free(&cred->tls_key);
            hx509_context_free(&cred->hx509ctx);
        }
        free(cred->jwks_uri);
        free(cred->expected_issuer);
        if (cred->jwks_cache)
            heim_release(cred->jwks_cache);

        /* Free cached session ticket for 0-RTT */
        free(cred->cached_ticket_audience);
        if (cred->cached_session_ticket) {
            memset(cred->cached_session_ticket, 0, cred->cached_session_ticket_len);
            free(cred->cached_session_ticket);
        }

        free(cred);
        *cred_handle = GSS_C_NO_CREDENTIAL;
    }
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_inquire_cred(OM_uint32 *minor,
                      gss_const_cred_id_t cred_handle,
                      gss_name_t *name,
                      OM_uint32 *lifetime,
                      gss_cred_usage_t *cred_usage,
                      gss_OID_set *mechanisms)
{
    const struct gss_jwt_cred_desc *cred = (const void *)cred_handle;
    OM_uint32 major;

    *minor = 0;

    if (cred == NULL)
        return GSS_S_NO_CRED;

    if (name)
        *name = GSS_C_NO_NAME;
    if (lifetime)
        *lifetime = GSS_C_INDEFINITE;
    if (cred_usage)
        *cred_usage = cred->usage;
    if (mechanisms) {
        major = gss_create_empty_oid_set(minor, mechanisms);
        if (major != GSS_S_COMPLETE)
            return major;
        major = gss_add_oid_set_member(minor, GSS_JWT_MECHANISM, mechanisms);
        if (major != GSS_S_COMPLETE) {
            gss_release_oid_set(minor, mechanisms);
            return major;
        }
    }

    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_inquire_cred_by_mech(OM_uint32 *minor,
                              gss_const_cred_id_t cred_handle,
                              const gss_OID mech_type,
                              gss_name_t *name,
                              OM_uint32 *initiator_lifetime,
                              OM_uint32 *acceptor_lifetime,
                              gss_cred_usage_t *cred_usage)
{
    const struct gss_jwt_cred_desc *cred = (const void *)cred_handle;

    *minor = 0;

    if (cred == NULL)
        return GSS_S_NO_CRED;

    if (!gss_oid_equal(mech_type, GSS_JWT_MECHANISM))
        return GSS_S_BAD_MECH;

    if (name)
        *name = GSS_C_NO_NAME;
    if (initiator_lifetime)
        *initiator_lifetime = GSS_C_INDEFINITE;
    if (acceptor_lifetime)
        *acceptor_lifetime = GSS_C_INDEFINITE;
    if (cred_usage)
        *cred_usage = cred->usage;

    return GSS_S_COMPLETE;
}

/*
 * Name operations
 */

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_import_name(OM_uint32 *minor,
                     const gss_buffer_t input_name,
                     const gss_OID name_type,
                     gss_name_t *output_name)
{
    char *name;

    *minor = 0;

    if (input_name == NULL || input_name->length == 0) {
        *output_name = _gss_jwt_anonymous_identity;
        return GSS_S_COMPLETE;
    }

    /* For now, just store the name as a string */
    name = malloc(input_name->length + 1);
    if (name == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }
    memcpy(name, input_name->value, input_name->length);
    name[input_name->length] = '\0';

    *output_name = (gss_name_t)name;
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_export_name(OM_uint32 *minor,
                     gss_const_name_t input_name,
                     gss_buffer_t output_name)
{
    *minor = 0;

    if (input_name == _gss_jwt_anonymous_identity) {
        output_name->length = 0;
        output_name->value = NULL;
        return GSS_S_COMPLETE;
    }

    /* Export as string */
    output_name->length = strlen((const char *)input_name);
    output_name->value = malloc(output_name->length);
    if (output_name->value == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }
    memcpy(output_name->value, input_name, output_name->length);
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_display_name(OM_uint32 *minor,
                      gss_const_name_t input_name,
                      gss_buffer_t output_name,
                      gss_OID *output_type)
{
    *minor = 0;

    if (input_name == _gss_jwt_anonymous_identity) {
        output_name->value = strdup("ANONYMOUS");
        if (output_name->value == NULL) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }
        output_name->length = strlen(output_name->value);
        if (output_type)
            *output_type = GSS_C_NT_ANONYMOUS;
        return GSS_S_COMPLETE;
    }

    output_name->length = strlen((const char *)input_name);
    output_name->value = malloc(output_name->length + 1);
    if (output_name->value == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }
    memcpy(output_name->value, input_name, output_name->length + 1);
    if (output_type)
        *output_type = GSS_C_NT_USER_NAME;
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_compare_name(OM_uint32 *minor,
                      gss_const_name_t name1,
                      gss_const_name_t name2,
                      int *name_equal)
{
    *minor = 0;

    if (name1 == name2) {
        *name_equal = 1;
        return GSS_S_COMPLETE;
    }

    if (name1 == _gss_jwt_anonymous_identity ||
        name2 == _gss_jwt_anonymous_identity) {
        *name_equal = 0;
        return GSS_S_COMPLETE;
    }

    *name_equal = (strcmp((const char *)name1, (const char *)name2) == 0);
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_release_name(OM_uint32 *minor,
                      gss_name_t *name)
{
    *minor = 0;

    if (name && *name && *name != _gss_jwt_anonymous_identity) {
        free(*name);
        *name = GSS_C_NO_NAME;
    }
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_duplicate_name(OM_uint32 *minor,
                        gss_const_name_t src_name,
                        gss_name_t *dest_name)
{
    *minor = 0;

    if (src_name == _gss_jwt_anonymous_identity) {
        *dest_name = _gss_jwt_anonymous_identity;
        return GSS_S_COMPLETE;
    }

    *dest_name = (gss_name_t)strdup((const char *)src_name);
    if (*dest_name == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_canonicalize_name(OM_uint32 *minor,
                           gss_const_name_t input_name,
                           const gss_OID mech_type,
                           gss_name_t *output_name)
{
    if (!gss_oid_equal(mech_type, GSS_JWT_MECHANISM)) {
        *minor = 0;
        return GSS_S_BAD_MECH;
    }
    return _gss_jwt_duplicate_name(minor, input_name, output_name);
}

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_inquire_names_for_mech(OM_uint32 *minor,
                                const gss_OID mechanism,
                                gss_OID_set *name_types)
{
    OM_uint32 major;

    *minor = 0;

    major = gss_create_empty_oid_set(minor, name_types);
    if (major != GSS_S_COMPLETE)
        return major;

    /* JWT mechanism supports these name types */
    gss_add_oid_set_member(minor, GSS_C_NT_USER_NAME, name_types);
    gss_add_oid_set_member(minor, GSS_C_NT_HOSTBASED_SERVICE, name_types);
    gss_add_oid_set_member(minor, GSS_C_NT_ANONYMOUS, name_types);

    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_inquire_mechs_for_name(OM_uint32 *minor,
                                gss_const_name_t input_name,
                                gss_OID_set *mech_types)
{
    OM_uint32 major;

    *minor = 0;

    major = gss_create_empty_oid_set(minor, mech_types);
    if (major != GSS_S_COMPLETE)
        return major;

    return gss_add_oid_set_member(minor, GSS_JWT_MECHANISM, mech_types);
}

/*
 * Misc
 */

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_display_status(OM_uint32 *minor,
                        OM_uint32 status_value,
                        int status_type,
                        const gss_OID mech_type,
                        OM_uint32 *message_context,
                        gss_buffer_t status_string)
{
    *minor = 0;
    *message_context = 0;

    if (status_type == GSS_C_GSS_CODE) {
        /* GSS major status - let the mech layer handle it */
        return GSS_S_BAD_STATUS;
    }

    /* Minor status */
    status_string->value = strdup("GSS-JWT mechanism error");
    if (status_string->value == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }
    status_string->length = strlen(status_string->value);
    return GSS_S_COMPLETE;
}
