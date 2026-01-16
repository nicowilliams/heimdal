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

#ifndef GSS_JWT_LOCL_H
#define GSS_JWT_LOCL_H 1

#include <config.h>

#include <gssapi.h>
#include <heimbase.h>
#include <hx509.h>

#include "mech/mech_locl.h"
#include "tls/tls_backend.h"

/*
 * GSS-JWT Mechanism
 *
 * A GSS-API mechanism for JWT-based authentication as an alternative
 * to Kerberos. The client obtains a JWT from an STS (Security Token
 * Service) using various credential types, then presents it to the
 * server for authentication.
 *
 * Credential exchange flow:
 * 1. Client has initial credential (password, Kerberos ticket, KSAT, GSAT, cert)
 * 2. Client contacts STS over TLS to exchange credential for JWT
 * 3. Client sends JWT to server in GSS token
 * 4. Server validates JWT (signature, audience, expiry, issuer)
 * 5. Server extracts subject as authenticated identity
 *
 * The audience is ALWAYS derived from the GSS target name, never defaulted.
 */

/*
 * Credential types for obtaining a JWT from the STS
 */
typedef enum {
    JWT_CRED_AUTO = 0,       /* Try all credential types until one works */
    JWT_CRED_PASSWORD,       /* Username/password authentication */
    JWT_CRED_KERBEROS,       /* Kerberos (via GSS-API Negotiate) */
    JWT_CRED_JWT,            /* JWT token (KSAT, GSAT, etc.) */
    JWT_CRED_CERTIFICATE     /* X.509 client certificate */
} jwt_cred_type;

/*
 * STS request method for obtaining a JWT
 */
typedef enum {
    JWT_STS_METHOD_AUTO = 0, /* Try GET first, fall back to POST */
    JWT_STS_METHOD_GET,      /* GET request (metadata service style) */
    JWT_STS_METHOD_POST      /* POST request (OAuth 2.0 style, RFC 8693) */
} jwt_sts_method;

/*
 * GSS-JWT credential structure
 *
 * Contains the configuration for obtaining a JWT from the STS.
 * The actual JWT is obtained during context establishment, not here.
 *
 * Configuration is done via gss_acquire_cred_from() cred_store keys:
 *   - "sts-endpoint"     STS token endpoint URL (required)
 *   - "sts-method"       STS request method: "auto", "get", "post" (default: auto)
 *   - "cred-type"        Credential type: "auto", "password", "kerberos", "jwt", "certificate"
 *   - "username"         Username for password auth
 *   - "password"         Password (inline - NOT RECOMMENDED)
 *   - "password-file"    File containing password
 *   - "ccache"           Kerberos ccache name for Negotiate auth
 *   - "token-file"       File containing JWT (KSAT)
 *   - "certificate"      Certificate file/store for client cert auth
 *   - "private-key"      Private key file for client cert auth
 *   - "jwks-uri"         JWKS endpoint for server-side JWT validation
 *   - "issuer"           Expected JWT issuer (server-side)
 *   - "trust-anchors"    CA certificates for validating STS/peer TLS connection
 *   - "tls-certificate"  Our TLS certificate (for acceptor-side TLS)
 *   - "tls-private-key"  Our TLS private key (for acceptor-side TLS)
 */
typedef struct gss_jwt_cred_desc {
    heim_context hctx;             /* Debug/trace context */

    /* STS endpoint (required for initiator) */
    char *sts_endpoint;

    /* STS request method selection */
    jwt_sts_method sts_method;

    /* Credential type selection */
    jwt_cred_type cred_type;

    /*
     * Password-based authentication
     */
    char *username;
    char *password;                /* From inline config or password_file */
    char *password_file;           /* File containing password */

    /*
     * Kerberos authentication (via GSS-API Negotiate to STS)
     * ccache is just a name string - we'll use it to set up GSS credentials
     */
    char *ccache;

    /*
     * JWT-based authentication (KSAT, GSAT, or pre-obtained JWT)
     * For KSAT: token_file points to the Kubernetes service account token
     * For GSAT: we'll implement metadata service access later
     */
    char *token_file;
    char *token;                   /* Cached token contents */

    /*
     * Certificate-based authentication
     * Uses hx509 certificate stores (same format as GSS-TLS)
     */
    hx509_context hx509ctx;
    hx509_certs client_certs;      /* Client certificate chain */
    hx509_private_key client_key;  /* Client private key */

    /*
     * TLS configuration for STS connection and protected mode
     */
    hx509_certs trust_anchors;     /* CAs trusted for STS/peer TLS connection */
    hx509_certs tls_certs;         /* Our TLS certificate chain (acceptor) */
    hx509_private_key tls_key;     /* Our TLS private key (acceptor) */

    /*
     * Server-side JWT validation configuration
     */
    char *jwks_uri;                /* JWKS endpoint for public keys */
    char *expected_issuer;         /* Expected "iss" claim */
    heim_dict_t jwks_cache;        /* Cached JWKS keys */

    /* Usage */
    gss_cred_usage_t usage;        /* INITIATE, ACCEPT, or BOTH */

    /*
     * TLS session ticket cache for 0-RTT early data support
     *
     * After a successful TLS connection to a target, we store the session
     * ticket here. On subsequent connections to the same target, we use
     * it for resumption and can send the JWT as 0-RTT early data.
     *
     * Note: This is a simple single-ticket cache. A production implementation
     * might use a per-audience cache (heim_dict) or external storage.
     */
    char *cached_ticket_audience;      /* Audience for cached ticket */
    uint8_t *cached_session_ticket;    /* Session ticket data */
    size_t cached_session_ticket_len;  /* Session ticket length */
} *gss_jwt_cred;

/*
 * GSS-JWT security context structure
 *
 * Tracks the state of JWT-based authentication.
 *
 * For initiator:
 * - Obtain JWT from STS (using configured credentials)
 * - Send JWT to acceptor
 * - Receive acknowledgment
 *
 * For acceptor:
 * - Receive JWT
 * - Validate signature, audience, expiry, issuer
 * - Extract subject as peer identity
 * - Send acknowledgment
 */
typedef struct gss_jwt_ctx_desc {
    heim_context hctx;             /* Debug/trace context */

    /* State tracking */
    unsigned int is_initiator : 1;   /* Client (1) or server (0) */
    unsigned int open : 1;           /* Context is established */
    unsigned int have_jwt : 1;       /* JWT has been obtained/received */
    unsigned int use_tls : 1;        /* TLS protection requested */
    unsigned int tls_handshake_done : 1; /* TLS handshake completed */
    unsigned int early_data_sent : 1;    /* JWT sent as 0-RTT early data */
    unsigned int early_data_accepted : 1; /* 0-RTT early data was accepted */
    unsigned int have_cb_hash : 1;       /* Channel bindings hash computed */
    unsigned int have_cb_type : 1;       /* Channel bindings type extracted */

    /* Context establishment state machine */
    enum {
        JWT_STATE_INITIAL,           /* Context not yet started */
        JWT_STATE_TLS_HANDSHAKE,     /* TLS handshake in progress */
        JWT_STATE_ACQUIRING_TOKEN,   /* Obtaining JWT from STS (initiator) */
        JWT_STATE_TOKEN_SENT,        /* JWT sent, awaiting ack (initiator) */
        JWT_STATE_TOKEN_RECEIVED,    /* JWT received, validating (acceptor) */
        JWT_STATE_ESTABLISHED        /* Context fully established */
    } state;

    /* Flags negotiated during handshake */
    OM_uint32 flags;

    /* The JWT (initiator: obtained from STS; acceptor: received from peer) */
    char *jwt_token;

    /* Parsed JWT claims (after validation) */
    char *subject;                 /* "sub" claim - authenticated identity */
    char *issuer;                  /* "iss" claim */
    char *audience;                /* "aud" claim (derived from target) */
    time_t expiry;                 /* "exp" claim */

    /* Peer identity (from JWT subject) */
    gss_name_t peer_name;

    /* Target service (for audience derivation) */
    gss_name_t target_name;

    /* Our credential (borrowed, not owned) */
    const struct gss_jwt_cred_desc *cred;

    /* Time context was established */
    time_t established_time;

    /*
     * Per-message protection
     *
     * After context establishment, we need to protect messages.
     * Options:
     * 1. Derive keys from JWT claims + shared secret
     * 2. Use TLS for the application connection
     * 3. Hybrid: JWT for auth, then establish TLS/ECDH for messages
     *
     * For now, we'll use a simple approach: derive keys from
     * the JWT token itself (HMAC-based KDF) for wrap/unwrap.
     * This provides message authentication but relies on the
     * JWT's secrecy for confidentiality of keys.
     *
     * TODO: Consider switching to a proper key exchange after auth.
     */
    uint8_t send_key[32];          /* Key for wrapping messages we send */
    uint8_t recv_key[32];          /* Key for unwrapping received messages */
    uint64_t send_seq;             /* Sequence number for sends */
    uint64_t recv_seq;             /* Sequence number for receives */
    uint8_t cb_hash[32];           /* Channel bindings hash for JWT claim */
    char *cb_type;                 /* Channel bindings type (e.g., "tls-server-end-point") */

    /* Early data buffer for 0-RTT (flags + JWT) */
    uint8_t *early_data_buf;       /* Buffer for 0-RTT early data */
    size_t early_data_len;         /* Length of early data */

    /*
     * TLS protection (when CONF_FLAG, INTEG_FLAG, or MUTUAL_FLAG requested)
     *
     * When protection flags are requested, we establish a TLS channel and
     * piggyback the JWT onto the TLS handshake. This provides:
     * - Confidentiality and integrity for the JWT token
     * - Per-message protection via TLS records
     * - Mutual authentication (TLS server cert + JWT)
     *
     * The protocol is:
     * 1. Initiator starts TLS handshake as client
     * 2. After handshake completes, JWT is sent as TLS application data
     * 3. Acceptor validates JWT and sends "OK" as application data
     * 4. wrap/unwrap use TLS encrypt/decrypt
     */
    tls_backend_ctx tls_backend;   /* TLS backend context */
    tls_backend_iobuf tls_recv_buf; /* TLS receive buffer */
    tls_backend_iobuf tls_send_buf; /* TLS send buffer */
    hx509_context tls_hx509ctx;    /* hx509 context for TLS */
} *gss_jwt_ctx;

/* Mechanism OID */
extern gss_OID GSS_JWT_MECHANISM;

/* Well-known names */
extern gss_name_t _gss_jwt_anonymous_identity;

/*
 * Function prototypes - mechanism SPI
 */

/* Context establishment */
OM_uint32 GSSAPI_CALLCONV
_gss_jwt_init_sec_context(OM_uint32 *minor,
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
_gss_jwt_accept_sec_context(OM_uint32 *minor,
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
_gss_jwt_delete_sec_context(OM_uint32 *minor,
                            gss_ctx_id_t *context_handle,
                            gss_buffer_t output_token);

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_process_context_token(OM_uint32 *minor,
                               gss_const_ctx_id_t context_handle,
                               const gss_buffer_t token);

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_context_time(OM_uint32 *minor,
                      gss_const_ctx_id_t context_handle,
                      OM_uint32 *time_rec);

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_inquire_context(OM_uint32 *minor,
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
_gss_jwt_wrap(OM_uint32 *minor,
              gss_const_ctx_id_t context_handle,
              int conf_req,
              gss_qop_t qop,
              const gss_buffer_t input,
              int *conf_state,
              gss_buffer_t output);

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_unwrap(OM_uint32 *minor,
                gss_const_ctx_id_t context_handle,
                const gss_buffer_t input,
                gss_buffer_t output,
                int *conf_state,
                gss_qop_t *qop_state);

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_wrap_size_limit(OM_uint32 *minor,
                         gss_const_ctx_id_t context_handle,
                         int conf_req,
                         gss_qop_t qop_req,
                         OM_uint32 req_output_size,
                         OM_uint32 *max_input_size);

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_get_mic(OM_uint32 *minor,
                 gss_const_ctx_id_t context_handle,
                 gss_qop_t qop,
                 const gss_buffer_t message,
                 gss_buffer_t token);

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_verify_mic(OM_uint32 *minor,
                    gss_const_ctx_id_t context_handle,
                    const gss_buffer_t message,
                    const gss_buffer_t token,
                    gss_qop_t *qop_state);

/* Credential operations */
OM_uint32 GSSAPI_CALLCONV
_gss_jwt_acquire_cred_from(OM_uint32 *minor,
                           gss_const_name_t desired_name,
                           OM_uint32 time_req,
                           gss_OID_set desired_mechs,
                           gss_cred_usage_t cred_usage,
                           gss_const_key_value_set_t cred_store,
                           gss_cred_id_t *output_cred,
                           gss_OID_set *actual_mechs,
                           OM_uint32 *time_rec);

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_release_cred(OM_uint32 *minor,
                      gss_cred_id_t *cred_handle);

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_inquire_cred(OM_uint32 *minor,
                      gss_const_cred_id_t cred_handle,
                      gss_name_t *name,
                      OM_uint32 *lifetime,
                      gss_cred_usage_t *cred_usage,
                      gss_OID_set *mechanisms);

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_inquire_cred_by_mech(OM_uint32 *minor,
                              gss_const_cred_id_t cred_handle,
                              const gss_OID mech_type,
                              gss_name_t *name,
                              OM_uint32 *initiator_lifetime,
                              OM_uint32 *acceptor_lifetime,
                              gss_cred_usage_t *cred_usage);

/* Name operations */
OM_uint32 GSSAPI_CALLCONV
_gss_jwt_import_name(OM_uint32 *minor,
                     const gss_buffer_t input_name,
                     const gss_OID name_type,
                     gss_name_t *output_name);

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_export_name(OM_uint32 *minor,
                     gss_const_name_t input_name,
                     gss_buffer_t output_name);

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_display_name(OM_uint32 *minor,
                      gss_const_name_t input_name,
                      gss_buffer_t output_name,
                      gss_OID *output_type);

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_compare_name(OM_uint32 *minor,
                      gss_const_name_t name1,
                      gss_const_name_t name2,
                      int *name_equal);

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_release_name(OM_uint32 *minor,
                      gss_name_t *name);

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_duplicate_name(OM_uint32 *minor,
                        gss_const_name_t src_name,
                        gss_name_t *dest_name);

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_canonicalize_name(OM_uint32 *minor,
                           gss_const_name_t input_name,
                           const gss_OID mech_type,
                           gss_name_t *output_name);

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_inquire_names_for_mech(OM_uint32 *minor,
                                const gss_OID mechanism,
                                gss_OID_set *name_types);

OM_uint32 GSSAPI_CALLCONV
_gss_jwt_inquire_mechs_for_name(OM_uint32 *minor,
                                gss_const_name_t input_name,
                                gss_OID_set *mech_types);

/* Misc */
OM_uint32 GSSAPI_CALLCONV
_gss_jwt_display_status(OM_uint32 *minor,
                        OM_uint32 status_value,
                        int status_type,
                        const gss_OID mech_type,
                        OM_uint32 *message_context,
                        gss_buffer_t status_string);

/*
 * Internal helpers for STS communication
 */

/*
 * Compute channel bindings hash for inclusion in JWT.
 *
 * Uses SHA-256 over the channel bindings structure (similar to RFC 4121
 * but with a stronger hash). The hash covers:
 *   - initiator_addrtype (4 bytes, network order)
 *   - initiator_address (length + data)
 *   - acceptor_addrtype (4 bytes, network order)
 *   - acceptor_address (length + data)
 *   - application_data (length + data)
 *
 * If application_data starts with a known channel binding type prefix
 * (e.g., "tls-server-end-point:", "tls-unique:", "tls-exporter:"),
 * the prefix is extracted separately and only the data after the colon
 * is included in the hash. This allows observers to see which CB type
 * is being used.
 *
 * @param bindings     Channel bindings structure
 * @param cb_hash_out  Output: hash (32 bytes for SHA-256)
 * @param cb_type_out  Output: CB type string (allocated, caller frees) or NULL
 *
 * Returns hash in cb_hash_out (32 bytes for SHA-256).
 */
OM_uint32
_gss_jwt_compute_cb_hash(OM_uint32 *minor,
                         const gss_channel_bindings_t bindings,
                         uint8_t cb_hash_out[32],
                         char **cb_type_out);

/* Obtain JWT from STS using configured credentials
 * If cb_hash/cb_hash_len are provided, the STS should include them
 * in the JWT as a channel bindings claim. If cb_type is provided,
 * it is included as a prefix in the claim (e.g., "tls-server-end-point:<hash>"). */
OM_uint32
_gss_jwt_acquire_token(OM_uint32 *minor,
                       const struct gss_jwt_cred_desc *cred,
                       const char *audience,
                       const uint8_t *cb_hash,
                       size_t cb_hash_len,
                       const char *cb_type,
                       char **jwt_out);

/* Validate JWT and extract claims */
OM_uint32
_gss_jwt_validate_token(OM_uint32 *minor,
                        gss_jwt_cred cred,
                        const char *jwt,
                        const char *expected_audience,
                        char **subject_out,
                        char **issuer_out,
                        time_t *expiry_out);

/*
 * Check if a JWT contains a channel bindings claim.
 *
 * Parses the JWT payload and looks for a "cb" claim (base64url-encoded hash).
 * If found, extracts the hash and compares with expected value.
 *
 * @param jwt           The JWT string to check
 * @param expected_hash The expected CB hash (32 bytes for SHA-256), or NULL
 * @param hash_len      Length of expected hash
 * @param has_cb_out    Output: 1 if JWT has CB claim, 0 if not
 * @param matches_out   Output: 1 if CB claim matches expected, 0 if not
 *                      (only meaningful if has_cb_out is 1 and expected_hash != NULL)
 *
 * @return GSS_S_COMPLETE on success (parsing succeeded),
 *         GSS_S_FAILURE on parse error
 */
OM_uint32
_gss_jwt_check_cb_claim(OM_uint32 *minor,
                        const char *jwt,
                        const uint8_t *expected_hash,
                        size_t hash_len,
                        int *has_cb_out,
                        int *matches_out);

/*
 * Flag bit indicating channel bindings present in wire format.
 * Used in the flags field of protected mode messages.
 */
#define GSS_JWT_FLAG_CB_PRESENT  0x80000000

#endif /* GSS_JWT_LOCL_H */
