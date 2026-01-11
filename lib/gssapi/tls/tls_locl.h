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
#include <heimbase.h>

#include "mech/mech_locl.h"
#include "tls_backend.h"

/*
 * Tracing support via GSS_TLS_TRACE environment variable
 *
 * Set GSS_TLS_TRACE to a log specification (e.g., "STDERR", "FILE:/tmp/trace.log")
 * to enable debug tracing of the GSS-TLS mechanism.
 */
static inline void
gss_tls_trace_init(heim_context *hctx)
{
    const char *trace;

    *hctx = NULL;
    trace = secure_getenv("GSS_TLS_TRACE");
    if (trace && *trace) {
        *hctx = heim_context_init();
        if (*hctx)
            heim_add_debug_dest(*hctx, "gss-tls", trace);
    }
}

/*
 * GSS-TLS credential structure
 *
 * Contains hx509 certificate stores for:
 * - Our certificate chain (optional for anonymous clients)
 * - Private key (optional for anonymous clients)
 * - Trust anchors for peer validation
 * - Revocation information
 *
 * Configuration is done via gss_acquire_cred_from() cred_store keys.
 * See cred.c for the list of supported keys.
 */
typedef struct gss_tls_cred_desc {
    heim_context hctx;             /* Debug/trace context */
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

    /*
     * TODO: Add ALPN/NPN protocol negotiation support
     *
     * char **alpn_protocols;      // NULL-terminated list of ALPN protocols
     * size_t alpn_count;          // Number of ALPN protocols
     * char **npn_protocols;       // NULL-terminated list of NPN protocols (legacy)
     * size_t npn_count;           // Number of NPN protocols
     *
     * For initiator: these are offered to the server
     * For acceptor: these are the protocols the server supports
     * After handshake, the negotiated protocol is available via context inquiry
     */
} *gss_tls_cred;

/*
 * GSS-TLS security context structure
 *
 * Wraps a TLS backend (s2n-tls or OpenSSL) with memory-based I/O
 * for GSS token exchange.
 */
typedef struct gss_tls_ctx_desc {
    heim_context hctx;             /* Debug/trace context */
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

    /* Our credential (borrowed, not owned) */
    const struct gss_tls_cred_desc *cred;

    /* Time context was established */
    time_t established_time;
} *gss_tls_ctx;

/*
 * GSS-TLS name structure
 *
 * Can represent:
 * - Hostname (for SNI / server identity)
 * - X.509 Distinguished Name (Subject DN)
 * - X.509 Subject Alternative Name (various types)
 * - Anonymous identity
 *
 * For certificate SANs, we support:
 * - OtherName: PKINIT (Kerberos), MS UPN, XMPP, etc.
 * - rfc822Name: email address
 * - dNSName: DNS hostname
 * - directoryName: X.500 DN
 * - uniformResourceIdentifier: URI
 * - iPAddress: IPv4 or IPv6 address
 * - registeredID: OID
 */
typedef struct gss_tls_name_desc {
    enum {
        GSS_TLS_NAME_ANONYMOUS,
        GSS_TLS_NAME_HOSTBASED,
        GSS_TLS_NAME_X509_DN,          /* Subject DN */
        GSS_TLS_NAME_X509_SAN          /* Subject Alternative Name */
    } type;

    union {
        struct {
            char *service;             /* Service name (may be NULL) */
            char *hostname;            /* Hostname */
        } hostbased;
        hx509_name x509_dn;            /* X.509 Distinguished Name */
        struct {
            gss_OID_desc san_type;     /* SAN type OID (for OtherName or our allocated OIDs) */
            union {
                char *string;          /* rfc822Name, dNSName, URI, xmppAddr, UPN */
                hx509_name dirname;    /* directoryName */
                struct {
                    uint8_t *data;     /* iPAddress: 4 bytes (v4) or 16 bytes (v6) */
                    size_t len;
                } ipaddr;
                struct {
                    uint8_t *data;     /* PKINIT SAN: DER-encoded KRB5PrincipalName */
                    size_t len;        /* or registeredID: DER-encoded OID */
                } der;
            } value;
        } san;
    } u;

    /*
     * Certificate for composite name export.
     * When a name is extracted from a peer certificate during handshake,
     * the certificate is stored here to support gss_export_name_composite().
     * The exported composite name is the DER-encoded certificate.
     */
    hx509_cert cert;
} *gss_tls_name;

/* Well-known names */
extern gss_name_t _gss_tls_anonymous_identity;

/* Mechanism OID */
extern gss_OID GSS_TLS_MECHANISM;

/* Channel binding extraction OIDs for gss_inquire_sec_context_by_oid() */
extern gss_OID GSS_C_INQ_CB_TLS_SERVER_END_POINT;
extern gss_OID GSS_C_INQ_CB_TLS_UNIQUE;
extern gss_OID GSS_C_INQ_CB_TLS_EXPORTER;

/* Name type OIDs for X.509 SANs */

/* OtherName type-id OIDs (used directly) */
extern gss_OID GSS_C_NT_PKINIT_SAN;       /* 1.3.6.1.5.2.2 - PKINIT (KRB5PrincipalName) */
extern gss_OID GSS_C_NT_MS_UPN_SAN;       /* 1.3.6.1.4.1.311.20.2.3 - Microsoft UPN */
extern gss_OID GSS_C_NT_XMPP_SAN;         /* 1.3.6.1.5.5.7.8.5 - XMPP address */
extern gss_OID GSS_C_NT_DNSSRV_SAN;       /* 1.3.6.1.5.5.7.8.7 - DNS SRV */
extern gss_OID GSS_C_NT_SMTP_SAN;         /* 1.3.6.1.5.5.7.8.9 - SMTP UTF8 mailbox */

/* Allocated name type OIDs for non-OtherName SANs */
extern gss_OID GSS_C_NT_X509_RFC822NAME;  /* 1.3.6.1.4.1.40402.1.3.1 - email */
extern gss_OID GSS_C_NT_X509_DNSNAME;     /* 1.3.6.1.4.1.40402.1.3.2 - DNS */
extern gss_OID GSS_C_NT_X509_DIRNAME;     /* 1.3.6.1.4.1.40402.1.3.4 - directoryName */
extern gss_OID GSS_C_NT_X509_URI;         /* 1.3.6.1.4.1.40402.1.3.6 - URI */
extern gss_OID GSS_C_NT_X509_IPADDRESS;   /* 1.3.6.1.4.1.40402.1.3.7 - IP address */
extern gss_OID GSS_C_NT_X509_REGID;       /* 1.3.6.1.4.1.40402.1.3.8 - registered OID */

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

OM_uint32 GSSAPI_CALLCONV
_gss_tls_export_name_composite(OM_uint32 *minor,
                               gss_name_t name,
                               gss_buffer_t exported_composite_name);

/* Helper to create name from certificate */
OM_uint32
_gss_tls_name_from_cert(OM_uint32 *minor,
                        hx509_context hx509ctx,
                        hx509_cert cert,
                        gss_name_t *output_name);

/* Misc */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_display_status(OM_uint32 *minor,
                        OM_uint32 status_value,
                        int status_type,
                        const gss_OID mech_type,
                        OM_uint32 *message_context,
                        gss_buffer_t status_string);

OM_uint32 GSSAPI_CALLCONV
_gss_tls_inquire_sec_context_by_oid(OM_uint32 *minor,
                                    gss_const_ctx_id_t context_handle,
                                    const gss_OID desired_object,
                                    gss_buffer_set_t *data_set);

#include "tls-private.h"

#endif /* GSS_TLS_LOCL_H */
