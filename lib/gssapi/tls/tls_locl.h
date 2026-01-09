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

#ifndef GSS_TLS_LOCL_H
#define GSS_TLS_LOCL_H 1

#include <config.h>

#include <hx509.h>
#include <gssapi.h>

#include "mech/mech_locl.h"
#include "tls_backend.h"

/*
 * GSS-TLS credential structure
 *
 * Contains hx509 certificate stores for:
 * - Our certificate chain (optional for anonymous clients)
 * - Private key (optional for anonymous clients)
 * - Trust anchors for peer validation
 * - Revocation information
 */
typedef struct gss_tls_cred_desc {
    hx509_context hx509ctx;        /* hx509 context */
    hx509_certs certs;             /* Our certificate(s) - may be empty for anonymous */
    hx509_private_key key;         /* Private key - NULL for anonymous */
    hx509_certs trust_anchors;     /* CAs we trust for peer validation */
    hx509_revoke_ctx revoke;       /* Revocation context (CRLs, OCSP) */

    /* Policy flags */
    unsigned int anonymous : 1;           /* No client cert (initiator only) */
    unsigned int require_client_cert : 1; /* Require client cert (acceptor only) */

    /* Usage */
    gss_cred_usage_t usage;        /* INITIATE, ACCEPT, or BOTH */
} *gss_tls_cred;

/*
 * GSS-TLS security context structure
 *
 * Wraps a TLS backend (s2n-tls or OpenSSL) with memory-based I/O
 * for GSS token exchange.
 */
typedef struct gss_tls_ctx_desc {
    tls_backend_ctx backend;       /* TLS backend context (s2n or OpenSSL) */

    /* I/O buffers for GSS token exchange */
    tls_backend_iobuf recv_buf;    /* Input tokens (from peer) */
    tls_backend_iobuf send_buf;    /* Output tokens (to peer) */

    /* hx509 context for certificate operations */
    hx509_context hx509ctx;

    /* State tracking */
    unsigned int is_initiator : 1;   /* Client (1) or server (0) */
    unsigned int handshake_done : 1; /* TLS handshake completed */
    unsigned int open : 1;           /* Context is established and open */
    unsigned int closed : 1;         /* Connection has been closed */

    /* Flags negotiated during handshake */
    OM_uint32 flags;

    /* Peer identity (from certificate) */
    gss_name_t peer_name;
    hx509_cert peer_cert;          /* Peer's leaf certificate */

    /* Our credential */
    gss_tls_cred cred;

    /* Time context was established */
    time_t established_time;
} *gss_tls_ctx;

/*
 * GSS-TLS name structure
 *
 * Can represent:
 * - Hostname (for SNI / server identity)
 * - X.509 Distinguished Name
 * - Anonymous identity
 */
typedef struct gss_tls_name_desc {
    enum {
        GSS_TLS_NAME_ANONYMOUS,
        GSS_TLS_NAME_HOSTBASED,
        GSS_TLS_NAME_X509_DN
    } type;

    union {
        struct {
            char *service;         /* Service name (may be NULL) */
            char *hostname;        /* Hostname */
        } hostbased;
        hx509_name x509_name;      /* X.509 Distinguished Name */
    } u;
} *gss_tls_name;

/* Well-known names */
extern gss_name_t _gss_tls_anonymous_identity;

/* Mechanism OID - TODO: get a real OID assigned */
extern gss_OID GSS_TLS_MECHANISM;

/* Default send buffer capacity */
#define GSS_TLS_SEND_BUF_INITIAL_CAPACITY 4096

/*
 * Function prototypes - mechanism SPI
 */

/* Context establishment */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_init_sec_context(OM_uint32 *minor,
                          gss_const_cred_id_t cred,
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
                          OM_uint32 *time_rec);

OM_uint32 GSSAPI_CALLCONV
_gss_tls_accept_sec_context(OM_uint32 *minor,
                            gss_ctx_id_t *context_handle,
                            gss_const_cred_id_t cred,
                            const gss_buffer_t input_token,
                            const gss_channel_bindings_t bindings,
                            gss_name_t *src_name,
                            gss_OID *mech_type,
                            gss_buffer_t output_token,
                            OM_uint32 *ret_flags,
                            OM_uint32 *time_rec,
                            gss_cred_id_t *delegated_cred);

OM_uint32 GSSAPI_CALLCONV
_gss_tls_delete_sec_context(OM_uint32 *minor,
                            gss_ctx_id_t *context_handle,
                            gss_buffer_t output_token);

OM_uint32 GSSAPI_CALLCONV
_gss_tls_process_context_token(OM_uint32 *minor,
                               gss_const_ctx_id_t context_handle,
                               const gss_buffer_t token);

OM_uint32 GSSAPI_CALLCONV
_gss_tls_context_time(OM_uint32 *minor,
                      gss_const_ctx_id_t context_handle,
                      OM_uint32 *time_rec);

OM_uint32 GSSAPI_CALLCONV
_gss_tls_inquire_context(OM_uint32 *minor,
                         gss_const_ctx_id_t context_handle,
                         gss_name_t *src_name,
                         gss_name_t *targ_name,
                         OM_uint32 *lifetime_rec,
                         gss_OID *mech_type,
                         OM_uint32 *ctx_flags,
                         int *locally_initiated,
                         int *open);

/* Per-message operations */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_wrap(OM_uint32 *minor,
              gss_const_ctx_id_t context_handle,
              int conf_req,
              gss_qop_t qop,
              const gss_buffer_t input,
              int *conf_state,
              gss_buffer_t output);

OM_uint32 GSSAPI_CALLCONV
_gss_tls_unwrap(OM_uint32 *minor,
                gss_const_ctx_id_t context_handle,
                const gss_buffer_t input,
                gss_buffer_t output,
                int *conf_state,
                gss_qop_t *qop_state);

OM_uint32 GSSAPI_CALLCONV
_gss_tls_wrap_size_limit(OM_uint32 *minor,
                         gss_const_ctx_id_t context_handle,
                         int conf_req,
                         gss_qop_t qop_req,
                         OM_uint32 req_output_size,
                         OM_uint32 *max_input_size);

OM_uint32 GSSAPI_CALLCONV
_gss_tls_get_mic(OM_uint32 *minor,
                 gss_const_ctx_id_t context_handle,
                 gss_qop_t qop,
                 const gss_buffer_t message,
                 gss_buffer_t token);

OM_uint32 GSSAPI_CALLCONV
_gss_tls_verify_mic(OM_uint32 *minor,
                    gss_const_ctx_id_t context_handle,
                    const gss_buffer_t message,
                    const gss_buffer_t token,
                    gss_qop_t *qop_state);

/* Credential operations */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_acquire_cred_from(OM_uint32 *minor,
                           gss_const_name_t desired_name,
                           OM_uint32 time_req,
                           gss_OID_set desired_mechs,
                           gss_cred_usage_t cred_usage,
                           gss_const_key_value_set_t cred_store,
                           gss_cred_id_t *output_cred,
                           gss_OID_set *actual_mechs,
                           OM_uint32 *time_rec);

OM_uint32 GSSAPI_CALLCONV
_gss_tls_release_cred(OM_uint32 *minor,
                      gss_cred_id_t *cred_handle);

OM_uint32 GSSAPI_CALLCONV
_gss_tls_inquire_cred(OM_uint32 *minor,
                      gss_const_cred_id_t cred_handle,
                      gss_name_t *name,
                      OM_uint32 *lifetime,
                      gss_cred_usage_t *cred_usage,
                      gss_OID_set *mechanisms);

OM_uint32 GSSAPI_CALLCONV
_gss_tls_inquire_cred_by_mech(OM_uint32 *minor,
                              gss_const_cred_id_t cred_handle,
                              const gss_OID mech_type,
                              gss_name_t *name,
                              OM_uint32 *initiator_lifetime,
                              OM_uint32 *acceptor_lifetime,
                              gss_cred_usage_t *cred_usage);

/* Name operations */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_import_name(OM_uint32 *minor,
                     const gss_buffer_t input_name,
                     const gss_OID name_type,
                     gss_name_t *output_name);

OM_uint32 GSSAPI_CALLCONV
_gss_tls_export_name(OM_uint32 *minor,
                     gss_const_name_t input_name,
                     gss_buffer_t output_name);

OM_uint32 GSSAPI_CALLCONV
_gss_tls_display_name(OM_uint32 *minor,
                      gss_const_name_t input_name,
                      gss_buffer_t output_name,
                      gss_OID *output_type);

OM_uint32 GSSAPI_CALLCONV
_gss_tls_compare_name(OM_uint32 *minor,
                      gss_const_name_t name1,
                      gss_const_name_t name2,
                      int *name_equal);

OM_uint32 GSSAPI_CALLCONV
_gss_tls_release_name(OM_uint32 *minor,
                      gss_name_t *name);

OM_uint32 GSSAPI_CALLCONV
_gss_tls_duplicate_name(OM_uint32 *minor,
                        gss_const_name_t src_name,
                        gss_name_t *dest_name);

OM_uint32 GSSAPI_CALLCONV
_gss_tls_canonicalize_name(OM_uint32 *minor,
                           gss_const_name_t input_name,
                           const gss_OID mech_type,
                           gss_name_t *output_name);

OM_uint32 GSSAPI_CALLCONV
_gss_tls_inquire_names_for_mech(OM_uint32 *minor,
                                const gss_OID mechanism,
                                gss_OID_set *name_types);

OM_uint32 GSSAPI_CALLCONV
_gss_tls_inquire_mechs_for_name(OM_uint32 *minor,
                                gss_const_name_t input_name,
                                gss_OID_set *mech_types);

/* Misc */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_display_status(OM_uint32 *minor,
                        OM_uint32 status_value,
                        int status_type,
                        const gss_OID mech_type,
                        OM_uint32 *message_context,
                        gss_buffer_t status_string);

#include "tls-private.h"

#endif /* GSS_TLS_LOCL_H */
