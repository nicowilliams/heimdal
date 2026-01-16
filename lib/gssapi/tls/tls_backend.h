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

#ifndef GSS_TLS_BACKEND_H
#define GSS_TLS_BACKEND_H 1

#include <config.h>
#include <stdint.h>
#include <stddef.h>
#include <hx509.h>
#include <heimbase.h>

/*
 * TLS Backend Abstraction
 *
 * This provides a common interface for TLS operations used by the GSS-TLS
 * mechanism. Two backends are supported:
 *   - s2n-tls (preferred, better API for memory-based I/O)
 *   - OpenSSL (fallback, works on Windows)
 *
 * The abstraction handles:
 *   - Memory-based I/O (no sockets, tokens are passed in/out as buffers)
 *   - Certificate/key configuration via hx509
 *   - TLS handshake as a state machine
 *   - Record encryption/decryption for wrap/unwrap
 */

/* Opaque backend handle */
typedef struct tls_backend_ctx *tls_backend_ctx;

/* Forward declaration for vtable */
typedef struct tls_backend_ops tls_backend_ops;

/* Backend status codes */
typedef enum {
    TLS_BACKEND_OK = 0,           /* Operation completed successfully */
    TLS_BACKEND_WANT_READ = 1,    /* Need more input data */
    TLS_BACKEND_WANT_WRITE = 2,   /* Have output data to send */
    TLS_BACKEND_ERROR = -1,       /* Fatal error */
    TLS_BACKEND_CLOSED = -2,      /* Connection closed */
    TLS_BACKEND_EOF = -3          /* End of data stream */
} tls_backend_status;

/* Connection mode */
typedef enum {
    TLS_BACKEND_CLIENT = 0,
    TLS_BACKEND_SERVER = 1
} tls_backend_mode;

/*
 * I/O buffer for memory-based TLS
 *
 * Input: Caller writes received TLS records here, backend reads from it
 * Output: Backend writes TLS records here, caller reads and sends them
 */
typedef struct tls_backend_iobuf {
    uint8_t *data;      /* Buffer data */
    size_t len;         /* Current data length */
    size_t pos;         /* Read position (for input buffers) */
    size_t capacity;    /* Allocated capacity */
} tls_backend_iobuf;

/*
 * Configuration for TLS backend
 */
typedef struct tls_backend_config {
    heim_context hctx;            /* Debug/trace context */
    hx509_context hx509ctx;       /* hx509 context */
    hx509_certs certs;            /* Our certificate chain (may be NULL) */
    hx509_private_key key;        /* Our private key (may be NULL) */
    hx509_certs trust_anchors;    /* Trust anchors for peer validation */
    hx509_revoke_ctx revoke;      /* Revocation context (may be NULL) */

    tls_backend_mode mode;        /* Client or server */
    const char *hostname;         /* Server hostname (for SNI, client mode) */

    unsigned int require_client_cert : 1;  /* Server: require client cert */
    unsigned int verify_peer : 1;          /* Verify peer certificate */

    /*
     * Session resumption and 0-RTT early data
     *
     * For TLS 1.3 session resumption:
     * - Client provides session_ticket from previous connection
     * - If resumption succeeds, client can send early_data with ClientHello
     *
     * Security considerations for 0-RTT early data:
     * - Not forward-secret (uses PSK-derived keys)
     * - Replayable by network attacker (server must handle idempotency)
     * - For JWT, replay protection comes from exp/jti claims
     */
    const uint8_t *session_ticket;         /* Session ticket for resumption */
    size_t session_ticket_len;             /* Length of session ticket */

    const uint8_t *early_data;             /* Data to send as 0-RTT (client) */
    size_t early_data_len;                 /* Length of early data */

    size_t max_early_data_size;            /* Max early data to accept (server) */
} tls_backend_config;

/*
 * Backend operations
 */

/*
 * Initialize a TLS backend context
 *
 * @param ctx         Output: new backend context
 * @param config      Configuration
 * @param recv_buf    Input buffer (caller writes received data here)
 * @param send_buf    Output buffer (backend writes outgoing data here)
 * @return TLS_BACKEND_OK on success, TLS_BACKEND_ERROR on failure
 */
tls_backend_status
tls_backend_init(tls_backend_ctx *ctx,
                 const tls_backend_config *config,
                 tls_backend_iobuf *recv_buf,
                 tls_backend_iobuf *send_buf);

/*
 * Perform a handshake step
 *
 * Call this repeatedly until it returns TLS_BACKEND_OK (handshake complete)
 * or TLS_BACKEND_ERROR (failure).
 *
 * When it returns TLS_BACKEND_WANT_WRITE, send the data in send_buf.
 * When it returns TLS_BACKEND_WANT_READ, receive data into recv_buf.
 *
 * @param ctx         Backend context
 * @return Status code
 */
tls_backend_status
tls_backend_handshake(tls_backend_ctx ctx);

/*
 * Check if handshake is complete
 *
 * @param ctx         Backend context
 * @return 1 if handshake is complete, 0 otherwise
 */
int
tls_backend_handshake_done(tls_backend_ctx ctx);

/*
 * Encrypt application data (for GSS wrap)
 *
 * Writes TLS application data record to send_buf.
 *
 * @param ctx         Backend context
 * @param data        Plaintext data to encrypt
 * @param len         Length of data
 * @return TLS_BACKEND_OK on success
 */
tls_backend_status
tls_backend_encrypt(tls_backend_ctx ctx,
                    const uint8_t *data,
                    size_t len);

/*
 * Decrypt application data (for GSS unwrap)
 *
 * Reads TLS application data record from recv_buf.
 *
 * @param ctx         Backend context
 * @param data        Output buffer for decrypted data
 * @param len         Input: buffer size; Output: bytes written
 * @return TLS_BACKEND_OK on success, TLS_BACKEND_WANT_READ if more data needed
 */
tls_backend_status
tls_backend_decrypt(tls_backend_ctx ctx,
                    uint8_t *data,
                    size_t *len);

/*
 * Send close_notify alert
 *
 * @param ctx         Backend context
 * @return TLS_BACKEND_OK on success
 */
tls_backend_status
tls_backend_close(tls_backend_ctx ctx);

/*
 * Get peer certificate
 *
 * @param ctx         Backend context
 * @param hx509ctx    hx509 context for creating cert
 * @param cert        Output: peer certificate (caller must free)
 * @return TLS_BACKEND_OK if peer cert available, TLS_BACKEND_ERROR if not
 */
tls_backend_status
tls_backend_get_peer_cert(tls_backend_ctx ctx,
                          hx509_context hx509ctx,
                          hx509_cert *cert);

/*
 * Get negotiated TLS version
 *
 * @param ctx         Backend context
 * @return Version string (e.g., "TLSv1.3") or NULL
 */
const char *
tls_backend_get_version(tls_backend_ctx ctx);

/*
 * Get negotiated cipher suite
 *
 * @param ctx         Backend context
 * @return Cipher suite name or NULL
 */
const char *
tls_backend_get_cipher(tls_backend_ctx ctx);

/*
 * Get last error message
 *
 * @param ctx         Backend context
 * @return Error message string (valid until next backend call)
 */
const char *
tls_backend_get_error(tls_backend_ctx ctx);

/*
 * Destroy backend context
 *
 * @param ctx         Backend context to destroy
 */
void
tls_backend_destroy(tls_backend_ctx ctx);

/*
 * 0-RTT Early Data and Session Resumption
 *
 * These functions support TLS 1.3 session resumption and 0-RTT early data.
 * Early data allows sending application data with the ClientHello, reducing
 * latency for resumed sessions.
 */

/* Early data status */
typedef enum {
    TLS_EARLY_DATA_NOT_REQUESTED = 0, /* No early data was offered */
    TLS_EARLY_DATA_REJECTED = 1,      /* Early data was rejected by peer */
    TLS_EARLY_DATA_ACCEPTED = 2       /* Early data was accepted */
} tls_early_data_status;

/*
 * Check early data status after handshake
 *
 * Call after handshake completes to determine if early data was accepted.
 * If rejected, the application should re-send the data normally.
 *
 * @param ctx         Backend context
 * @return Early data status
 */
tls_early_data_status
tls_backend_get_early_data_status(tls_backend_ctx ctx);

/*
 * Get received early data (server side)
 *
 * After handshake completes on server, retrieve any early data sent by client.
 * Should be called before processing normal application data.
 *
 * @param ctx         Backend context
 * @param data        Output buffer for early data
 * @param len         Input: buffer size; Output: bytes written
 * @return TLS_BACKEND_OK if early data available, TLS_BACKEND_EOF if none
 */
tls_backend_status
tls_backend_get_early_data(tls_backend_ctx ctx,
                           uint8_t *data,
                           size_t *len);

/*
 * Get session ticket for future resumption
 *
 * After handshake completes, retrieve the session ticket (if any).
 * Store this and provide it in tls_backend_config.session_ticket
 * for future connections to enable resumption and 0-RTT.
 *
 * @param ctx         Backend context
 * @param ticket      Output buffer for session ticket
 * @param len         Input: buffer size; Output: bytes written
 * @return TLS_BACKEND_OK on success, TLS_BACKEND_ERROR if no ticket
 */
tls_backend_status
tls_backend_get_session_ticket(tls_backend_ctx ctx,
                               uint8_t *ticket,
                               size_t *len);

/*
 * I/O buffer helper functions
 */

/* Initialize an I/O buffer */
int tls_iobuf_init(tls_backend_iobuf *buf, size_t initial_capacity);

/* Free an I/O buffer */
void tls_iobuf_free(tls_backend_iobuf *buf);

/* Ensure capacity for writing */
int tls_iobuf_ensure_capacity(tls_backend_iobuf *buf, size_t needed);

/* Append data to buffer */
int tls_iobuf_append(tls_backend_iobuf *buf, const uint8_t *data, size_t len);

/* Get available data for reading */
size_t tls_iobuf_available(const tls_backend_iobuf *buf);

/* Read data from buffer (advances position) */
size_t tls_iobuf_read(tls_backend_iobuf *buf, uint8_t *data, size_t len);

/* Peek at data without advancing position */
size_t tls_iobuf_peek(const tls_backend_iobuf *buf, uint8_t *data, size_t len);

/* Reset buffer (clear all data) */
void tls_iobuf_reset(tls_backend_iobuf *buf);

/* Compact buffer (move unread data to start) */
void tls_iobuf_compact(tls_backend_iobuf *buf);

/*
 * Backend name (for diagnostics)
 */
const char *tls_backend_name(void);

/*
 * Backend operations vtable
 *
 * When GSS_TLS_BOTH is defined, both backends are compiled and this
 * vtable allows runtime selection via the GSS_TLS_BACKEND environment
 * variable. Valid values are "openssl" and "s2n" (or "s2n-tls").
 * Default is s2n-tls if available.
 */
struct tls_backend_ops {
    const char *name;

    tls_backend_status (*init)(tls_backend_ctx *ctx,
                               const tls_backend_config *config,
                               tls_backend_iobuf *recv_buf,
                               tls_backend_iobuf *send_buf);
    tls_backend_status (*handshake)(tls_backend_ctx ctx);
    int (*handshake_done)(tls_backend_ctx ctx);
    tls_backend_status (*encrypt)(tls_backend_ctx ctx,
                                  const uint8_t *data, size_t len);
    tls_backend_status (*decrypt)(tls_backend_ctx ctx,
                                  uint8_t *data, size_t *len);
    tls_backend_status (*close)(tls_backend_ctx ctx);
    tls_backend_status (*get_peer_cert)(tls_backend_ctx ctx,
                                        hx509_context hx509ctx,
                                        hx509_cert *cert);
    const char *(*get_version)(tls_backend_ctx ctx);
    const char *(*get_cipher)(tls_backend_ctx ctx);
    const char *(*get_error)(tls_backend_ctx ctx);
    void (*destroy)(tls_backend_ctx ctx);
    tls_backend_status (*get_cb_server_end_point)(tls_backend_ctx ctx,
                                                  int is_server,
                                                  uint8_t *cb_data,
                                                  size_t *cb_len);
    tls_backend_status (*get_cb_unique)(tls_backend_ctx ctx,
                                        uint8_t *cb_data,
                                        size_t *cb_len);
    tls_backend_status (*get_cb_exporter)(tls_backend_ctx ctx,
                                          uint8_t *cb_data,
                                          size_t *cb_len);

    /* 0-RTT early data and session resumption */
    tls_early_data_status (*get_early_data_status)(tls_backend_ctx ctx);
    tls_backend_status (*get_early_data)(tls_backend_ctx ctx,
                                         uint8_t *data, size_t *len);
    tls_backend_status (*get_session_ticket)(tls_backend_ctx ctx,
                                             uint8_t *ticket, size_t *len);
};

/*
 * Backend registration (called by each backend implementation)
 */
#ifdef GSS_TLS_OPENSSL
extern const tls_backend_ops tls_backend_openssl_ops;
#endif
#ifdef GSS_TLS_S2N
extern const tls_backend_ops tls_backend_s2n_ops;
#endif

/*
 * Get the selected backend ops (based on GSS_TLS_BACKEND env var)
 */
const tls_backend_ops *tls_backend_get_ops(void);

/*
 * Channel Binding Extraction
 *
 * These functions extract channel binding values from an established
 * TLS connection for use with higher-level protocols.
 */

/*
 * Get tls-server-end-point channel binding (RFC 5929)
 *
 * Returns hash of the server's certificate. Hash algorithm is SHA-256
 * unless the certificate signature uses SHA-384/512.
 *
 * @param ctx         Backend context
 * @param is_server   1 if we are the server, 0 if client
 * @param cb_data     Output buffer for channel binding data
 * @param cb_len      Input: buffer size; Output: bytes written
 * @return TLS_BACKEND_OK on success, TLS_BACKEND_ERROR if unavailable
 */
tls_backend_status
tls_backend_get_cb_server_end_point(tls_backend_ctx ctx,
                                    int is_server,
                                    uint8_t *cb_data,
                                    size_t *cb_len);

/*
 * Get tls-unique channel binding (RFC 5929)
 *
 * Returns the first Finished message of the TLS handshake.
 * WARNING: Broken for TLS 1.3 - will return TLS_BACKEND_ERROR.
 *
 * @param ctx         Backend context
 * @param cb_data     Output buffer for channel binding data
 * @param cb_len      Input: buffer size; Output: bytes written
 * @return TLS_BACKEND_OK on success, TLS_BACKEND_ERROR if unavailable
 */
tls_backend_status
tls_backend_get_cb_unique(tls_backend_ctx ctx,
                          uint8_t *cb_data,
                          size_t *cb_len);

/*
 * Get tls-exporter channel binding (RFC 9266)
 *
 * Uses TLS keying material exporter with label "EXPORTER-Channel-Binding".
 * This is the recommended channel binding for TLS 1.3 and works with
 * all TLS versions that support exporters.
 *
 * @param ctx         Backend context
 * @param cb_data     Output buffer for channel binding data (32 bytes)
 * @param cb_len      Input: buffer size; Output: bytes written
 * @return TLS_BACKEND_OK on success, TLS_BACKEND_ERROR if unavailable
 */
tls_backend_status
tls_backend_get_cb_exporter(tls_backend_ctx ctx,
                            uint8_t *cb_data,
                            size_t *cb_len);

#endif /* GSS_TLS_BACKEND_H */
