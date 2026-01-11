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

/*
 * s2n-tls backend for GSS-TLS mechanism
 *
 * Uses s2n-tls callbacks for memory-based I/O (no sockets).
 * s2n-tls provides a cleaner API for this use case than OpenSSL.
 */

#include <config.h>

#ifdef GSS_TLS_S2N

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <s2n.h>

/* For channel binding hash computation (libcrypto only, not libssl) */
#include <openssl/evp.h>

#include "tls_backend.h"
#include <der.h>
#include <roken.h>
#include <base64.h>
#include <heimbase.h>
#include <rfc2459_asn1.h>   /* For Certificate type and signature OIDs */

/*
 * When both backends are compiled, rename functions to avoid symbol conflicts.
 * The dispatcher in tls_backend.c will call the appropriate backend via vtable.
 * Functions are made static since they're only accessed via the vtable.
 */
#ifdef GSS_TLS_BOTH
#define BACKEND_STATIC static __attribute__((unused))
#define tls_backend_name         tls_backend_s2n_name
#define tls_backend_init         tls_backend_s2n_init
#define tls_backend_handshake    tls_backend_s2n_handshake
#define tls_backend_handshake_done tls_backend_s2n_handshake_done
#define tls_backend_encrypt      tls_backend_s2n_encrypt
#define tls_backend_decrypt      tls_backend_s2n_decrypt
#define tls_backend_close        tls_backend_s2n_close
#define tls_backend_get_peer_cert tls_backend_s2n_get_peer_cert
#define tls_backend_get_version  tls_backend_s2n_get_version
#define tls_backend_get_cipher   tls_backend_s2n_get_cipher
#define tls_backend_get_error    tls_backend_s2n_get_error
#define tls_backend_destroy      tls_backend_s2n_destroy
#define tls_backend_get_cb_server_end_point tls_backend_s2n_get_cb_server_end_point
#define tls_backend_get_cb_unique tls_backend_s2n_get_cb_unique
#define tls_backend_get_cb_exporter tls_backend_s2n_get_cb_exporter
#else
#define BACKEND_STATIC
#endif

/* Forward declarations for hx509 private APIs we need */
HX509_LIB_FUNCTION int HX509_LIB_CALL
_hx509_private_key_export(hx509_context, const hx509_private_key,
                          hx509_key_format_t, heim_octet_string *);

HX509_LIB_FUNCTION const Certificate * HX509_LIB_CALL
_hx509_get_cert(hx509_cert);

/*
 * s2n-tls backend context
 */
struct tls_backend_ctx {
    heim_context hctx;            /* Debug/trace context */

    struct s2n_config *config;    /* s2n configuration */
    struct s2n_connection *conn;  /* s2n connection */

    /* Store our cert chain for tls-server-end-point CB */
    struct s2n_cert_chain_and_key *our_chain;

    tls_backend_iobuf *recv_buf;  /* GSS input buffer */
    tls_backend_iobuf *send_buf;  /* GSS output buffer */

    char *expected_hostname;      /* Expected server hostname (for verification) */

    tls_backend_mode mode;        /* Client or server */
    unsigned int handshake_done : 1;
    unsigned int closed : 1;

    char error_buf[256];          /* Last error message */
};

/*
 * s2n send callback - writes to our send buffer
 */
static int
s2n_send_cb(void *io_context, const uint8_t *buf, uint32_t len)
{
    tls_backend_ctx ctx = (tls_backend_ctx)io_context;

    if (tls_iobuf_append(ctx->send_buf, buf, len) != 0) {
        errno = ENOMEM;
        return -1;
    }

    return (int)len;
}

/*
 * s2n recv callback - reads from our recv buffer
 */
static int
s2n_recv_cb(void *io_context, uint8_t *buf, uint32_t len)
{
    tls_backend_ctx ctx = (tls_backend_ctx)io_context;
    size_t avail = tls_iobuf_available(ctx->recv_buf);

    if (avail == 0) {
        errno = EAGAIN;
        return -1;
    }

    if (len > avail)
        len = (uint32_t)avail;

    return (int)tls_iobuf_read(ctx->recv_buf, buf, len);
}

/*
 * Set error from s2n
 */
static void
set_s2n_error(tls_backend_ctx ctx, const char *prefix)
{
    int s2n_err = s2n_errno;
    const char *s2n_msg = s2n_strerror(s2n_err, "EN");

    snprintf(ctx->error_buf, sizeof(ctx->error_buf), "%s: %s (error %d)",
             prefix, s2n_msg ? s2n_msg : "unknown", s2n_err);
}

/*
 * Hostname verification callback
 * Returns 1 if hostname is acceptable
 *
 * The callback receives the hostname from the certificate's SAN or CN,
 * and we compare it against the expected target hostname.
 */
static uint8_t
s2n_verify_host_cb(const char *host_name, size_t host_name_len, void *user_data)
{
    tls_backend_ctx ctx = (tls_backend_ctx)user_data;
    size_t expected_len;

    if (ctx == NULL || ctx->expected_hostname == NULL) {
        /* No expected hostname configured - accept any */
        return 1;
    }

    expected_len = strlen(ctx->expected_hostname);

    /*
     * Compare hostnames.
     * For simplicity, we do case-insensitive exact match.
     * A more complete implementation would handle wildcards.
     */
    if (host_name_len == expected_len &&
        strncasecmp(host_name, ctx->expected_hostname, host_name_len) == 0) {
        heim_debug(ctx->hctx, 10, "TLS: hostname verification passed for %s",
                   ctx->expected_hostname);
        return 1;
    }

    heim_debug(ctx->hctx, 5, "TLS: hostname mismatch: cert has '%.*s', expected '%s'",
               (int)host_name_len, host_name, ctx->expected_hostname);
    return 0;
}

/*
 * Load certificate chain from hx509 to s2n
 * If chain_out is non-NULL, returns the chain for later use (channel bindings)
 */
static int
load_cert_chain(struct s2n_config *config, hx509_context hx509ctx,
                hx509_certs certs, hx509_private_key key,
                struct s2n_cert_chain_and_key **chain_out)
{
    struct s2n_cert_chain_and_key *chain = NULL;
    hx509_cursor cursor = NULL;
    hx509_cert hxcert;
    heim_octet_string cert_data, key_data;
    char *cert_pem = NULL;
    char *key_pem = NULL;
    size_t cert_pem_len = 0;
    int ret = -1;

    memset(&cert_data, 0, sizeof(cert_data));
    memset(&key_data, 0, sizeof(key_data));

    /* Build PEM chain from certificates */
    ret = hx509_certs_start_seq(hx509ctx, certs, &cursor);
    if (ret != 0)
        goto out;

    while (hx509_certs_next_cert(hx509ctx, certs, cursor, &hxcert) == 0 &&
           hxcert != NULL) {

        ret = hx509_cert_binary(hx509ctx, hxcert, &cert_data);
        hx509_cert_free(hxcert);
        if (ret != 0)
            goto out;

        /* Convert DER to PEM format using base64 encoding */
        char *b64 = NULL;
        if (rk_base64_encode(cert_data.data, cert_data.length, &b64) < 0) {
            der_free_octet_string(&cert_data);
            ret = ENOMEM;
            goto out;
        }

        size_t pem_size = strlen(b64) + 100;
        char *new_pem = realloc(cert_pem, cert_pem_len + pem_size);
        if (new_pem == NULL) {
            free(b64);
            der_free_octet_string(&cert_data);
            ret = ENOMEM;
            goto out;
        }
        cert_pem = new_pem;

        /* Add PEM header/base64/footer */
        int written = snprintf(cert_pem + cert_pem_len, pem_size,
                              "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n",
                              b64);
        cert_pem_len += written;

        free(b64);
        der_free_octet_string(&cert_data);
    }
    hx509_certs_end_seq(hx509ctx, certs, cursor);
    cursor = NULL;

    /* Export private key as PEM */
    if (key != NULL) {
        ret = _hx509_private_key_export(hx509ctx, key,
                                        HX509_KEY_FORMAT_DER, &key_data);
        if (ret != 0)
            goto out;

        /* Base64 encode the key */
        char *key_b64 = NULL;
        if (rk_base64_encode(key_data.data, key_data.length, &key_b64) < 0) {
            ret = ENOMEM;
            goto out;
        }

        size_t key_pem_size = strlen(key_b64) + 100;
        key_pem = malloc(key_pem_size);
        if (key_pem == NULL) {
            free(key_b64);
            ret = ENOMEM;
            goto out;
        }
        snprintf(key_pem, key_pem_size,
                "-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----\n",
                key_b64);
        free(key_b64);
    }

    /* Create s2n cert chain */
    chain = s2n_cert_chain_and_key_new();
    if (chain == NULL) {
        ret = -1;
        goto out;
    }

    if (s2n_cert_chain_and_key_load_pem(chain, cert_pem, key_pem) != 0) {
        ret = -1;
        goto out;
    }

    if (s2n_config_add_cert_chain_and_key_to_store(config, chain) != 0) {
        ret = -1;
        goto out;
    }

    ret = 0;
    /* Return chain pointer if requested (for channel bindings) */
    if (chain_out != NULL)
        *chain_out = chain;
    chain = NULL;  /* Owned by config now (or by caller via chain_out) */

out:
    if (cursor)
        hx509_certs_end_seq(hx509ctx, certs, cursor);
    if (chain)
        s2n_cert_chain_and_key_free(chain);
    free(cert_pem);
    free(key_pem);
    der_free_octet_string(&cert_data);
    der_free_octet_string(&key_data);
    return ret;
}

/*
 * Load trust anchors from hx509 to s2n
 */
static int
load_trust_anchors(struct s2n_config *config, hx509_context hx509ctx,
                   hx509_certs trust_anchors)
{
    hx509_cursor cursor = NULL;
    hx509_cert cert = NULL;

    if (hx509_certs_start_seq(hx509ctx, trust_anchors, &cursor) != 0)
        return -1;

    while (hx509_certs_next_cert(hx509ctx, trust_anchors, cursor, &cert) == 0 &&
           cert != NULL) {
        heim_octet_string cert_data = { 0 };
        char *b64 = NULL;
        char *pem = NULL;
        size_t pem_len;

        /* Get DER encoded certificate */
        if (hx509_cert_binary(hx509ctx, cert, &cert_data) != 0) {
            hx509_cert_free(cert);
            continue;
        }

        /* Convert to base64 */
        if (rk_base64_encode(cert_data.data, cert_data.length, &b64) < 0) {
            der_free_octet_string(&cert_data);
            hx509_cert_free(cert);
            continue;
        }

        /* Build PEM format */
        pem_len = strlen(b64) + 64;  /* base64 + headers */
        pem = malloc(pem_len);
        if (pem == NULL) {
            free(b64);
            der_free_octet_string(&cert_data);
            hx509_cert_free(cert);
            continue;
        }

        snprintf(pem, pem_len, "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n", b64);

        /* Add to s2n trust store */
        if (s2n_config_add_pem_to_trust_store(config, pem) != 0) {
            /* Log error but continue - other certs might work */
        }

        free(pem);
        free(b64);
        der_free_octet_string(&cert_data);
        hx509_cert_free(cert);
    }

    hx509_certs_end_seq(hx509ctx, trust_anchors, cursor);
    return 0;
}

BACKEND_STATIC const char *
tls_backend_name(void)
{
    return "s2n-tls";
}

BACKEND_STATIC tls_backend_status
tls_backend_init(tls_backend_ctx *pctx,
                 const tls_backend_config *config,
                 tls_backend_iobuf *recv_buf,
                 tls_backend_iobuf *send_buf)
{
    tls_backend_ctx ctx;
    s2n_mode mode;

    *pctx = NULL;

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL)
        return TLS_BACKEND_ERROR;

    ctx->hctx = config->hctx;
    ctx->recv_buf = recv_buf;
    ctx->send_buf = send_buf;
    ctx->mode = config->mode;

    heim_debug(ctx->hctx, 10, "TLS: creating SSL context (s2n-tls %s mode)",
               config->mode == TLS_BACKEND_CLIENT ? "client" : "server");

    /* Initialize s2n (safe to call multiple times) */
    if (s2n_init() != 0) {
        set_s2n_error(ctx, "s2n_init");
        goto fail;
    }

    /* Create s2n config */
    ctx->config = s2n_config_new();
    if (ctx->config == NULL) {
        set_s2n_error(ctx, "s2n_config_new");
        goto fail;
    }

    /* Set minimum TLS version to 1.2 */
    if (s2n_config_set_cipher_preferences(ctx->config, "default_tls13") != 0) {
        set_s2n_error(ctx, "s2n_config_set_cipher_preferences");
        goto fail;
    }

    /* Load certificates and key if present */
    if (config->certs != NULL) {
        heim_debug(ctx->hctx, 10, "TLS: loading certificate chain");
        if (load_cert_chain(ctx->config, config->hx509ctx,
                           config->certs, config->key, &ctx->our_chain) != 0) {
            snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                    "Failed to load certificate chain");
            heim_debug(ctx->hctx, 1, "TLS: failed to load certificate chain");
            goto fail;
        }
        heim_debug(ctx->hctx, 10, "TLS: certificate chain loaded");
    }

    /* Load trust anchors */
    if (config->trust_anchors != NULL && config->verify_peer) {
        if (load_trust_anchors(ctx->config, config->hx509ctx,
                              config->trust_anchors) != 0) {
            snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                    "Failed to load trust anchors");
            goto fail;
        }
        s2n_config_set_verify_host_callback(ctx->config, s2n_verify_host_cb, ctx);
    } else {
        /* Disable certificate verification */
        s2n_config_disable_x509_verification(ctx->config);
    }

    /* Server: client cert requirement */
    if (config->mode == TLS_BACKEND_SERVER) {
        s2n_config_set_client_auth_type(ctx->config,
            config->require_client_cert ? S2N_CERT_AUTH_REQUIRED
                                        : S2N_CERT_AUTH_OPTIONAL);
    }

    /* Create connection */
    mode = (config->mode == TLS_BACKEND_CLIENT) ? S2N_CLIENT : S2N_SERVER;
    ctx->conn = s2n_connection_new(mode);
    if (ctx->conn == NULL) {
        set_s2n_error(ctx, "s2n_connection_new");
        goto fail;
    }

    if (s2n_connection_set_config(ctx->conn, ctx->config) != 0) {
        set_s2n_error(ctx, "s2n_connection_set_config");
        goto fail;
    }

    /* Set up I/O callbacks with their contexts */
    if (s2n_connection_set_send_cb(ctx->conn, s2n_send_cb) != 0 ||
        s2n_connection_set_recv_cb(ctx->conn, s2n_recv_cb) != 0) {
        set_s2n_error(ctx, "s2n_connection_set_*_cb");
        goto fail;
    }

    if (s2n_connection_set_send_ctx(ctx->conn, ctx) != 0 ||
        s2n_connection_set_recv_ctx(ctx->conn, ctx) != 0) {
        set_s2n_error(ctx, "s2n_connection_set_*_ctx");
        goto fail;
    }

    /* Set SNI for client and store expected hostname for verification */
    if (config->mode == TLS_BACKEND_CLIENT && config->hostname != NULL) {
        if (s2n_set_server_name(ctx->conn, config->hostname) != 0) {
            set_s2n_error(ctx, "s2n_set_server_name");
            goto fail;
        }
        ctx->expected_hostname = strdup(config->hostname);
        if (ctx->expected_hostname == NULL) {
            snprintf(ctx->error_buf, sizeof(ctx->error_buf), "strdup failed");
            goto fail;
        }
    }

    /* Set non-blocking mode */
    if (s2n_connection_set_blinding(ctx->conn, S2N_SELF_SERVICE_BLINDING) != 0) {
        set_s2n_error(ctx, "s2n_connection_set_blinding");
        goto fail;
    }

    heim_debug(ctx->hctx, 10, "TLS: backend initialized successfully");

    *pctx = ctx;
    return TLS_BACKEND_OK;

fail:
    heim_debug(ctx->hctx, 1, "TLS: backend initialization failed");
    if (ctx->conn)
        s2n_connection_free(ctx->conn);
    if (ctx->config)
        s2n_config_free(ctx->config);
    free(ctx->expected_hostname);
    free(ctx);
    return TLS_BACKEND_ERROR;
}

BACKEND_STATIC tls_backend_status
tls_backend_handshake(tls_backend_ctx ctx)
{
    s2n_blocked_status blocked;
    int ret;

    if (ctx->handshake_done)
        return TLS_BACKEND_OK;

    ret = s2n_negotiate(ctx->conn, &blocked);
    heim_debug(ctx->hctx, 15, "TLS: s2n_negotiate returned %d", ret);

    if (ret == 0) {
        ctx->handshake_done = 1;
        heim_debug(ctx->hctx, 5, "TLS: handshake complete, version=%s cipher=%s",
                   s2n_connection_get_actual_protocol_version(ctx->conn) >= S2N_TLS13
                       ? "TLSv1.3" : "TLSv1.2",
                   s2n_connection_get_cipher(ctx->conn));
        return TLS_BACKEND_OK;
    }

    if (s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED) {
        switch (blocked) {
        case S2N_BLOCKED_ON_READ:
            heim_debug(ctx->hctx, 15, "TLS: handshake wants read");
            if (ctx->send_buf->len > 0)
                return TLS_BACKEND_WANT_WRITE;
            return TLS_BACKEND_WANT_READ;

        case S2N_BLOCKED_ON_WRITE:
            heim_debug(ctx->hctx, 15, "TLS: handshake wants write");
            return TLS_BACKEND_WANT_WRITE;

        case S2N_BLOCKED_ON_EARLY_DATA:
            /* Early data not supported - treat as want read */
            return TLS_BACKEND_WANT_READ;

        case S2N_BLOCKED_ON_APPLICATION_INPUT:
            /* Application callback blocking - shouldn't happen with our setup */
            snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                     "Unexpected S2N_BLOCKED_ON_APPLICATION_INPUT");
            return TLS_BACKEND_ERROR;

        default:
            snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                     "Unknown s2n blocked status: %d", blocked);
            return TLS_BACKEND_ERROR;
        }
    }

    if (s2n_connection_get_alert(ctx->conn) != 0) {
        heim_debug(ctx->hctx, 5, "TLS: connection closed during handshake");
        ctx->closed = 1;
        return TLS_BACKEND_CLOSED;
    }

    set_s2n_error(ctx, "s2n_negotiate");
    heim_debug(ctx->hctx, 1, "TLS: handshake error: %s", ctx->error_buf);
    return TLS_BACKEND_ERROR;
}

BACKEND_STATIC int
tls_backend_handshake_done(tls_backend_ctx ctx)
{
    return ctx->handshake_done ? 1 : 0;
}

BACKEND_STATIC tls_backend_status
tls_backend_encrypt(tls_backend_ctx ctx,
                    const uint8_t *data,
                    size_t len)
{
    s2n_blocked_status blocked;
    ssize_t ret;

    if (!ctx->handshake_done) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Handshake not complete");
        return TLS_BACKEND_ERROR;
    }

    ret = s2n_send(ctx->conn, data, len, &blocked);
    if (ret > 0)
        return TLS_BACKEND_OK;

    if (s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED &&
        blocked == S2N_BLOCKED_ON_WRITE) {
        return TLS_BACKEND_WANT_WRITE;
    }

    set_s2n_error(ctx, "s2n_send");
    return TLS_BACKEND_ERROR;
}

BACKEND_STATIC tls_backend_status
tls_backend_decrypt(tls_backend_ctx ctx,
                    uint8_t *data,
                    size_t *len)
{
    s2n_blocked_status blocked;
    ssize_t ret;
    size_t buflen = *len;

    *len = 0;

    if (!ctx->handshake_done) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Handshake not complete");
        return TLS_BACKEND_ERROR;
    }

    ret = s2n_recv(ctx->conn, data, buflen, &blocked);
    if (ret > 0) {
        *len = ret;
        return TLS_BACKEND_OK;
    }

    if (ret == 0) {
        ctx->closed = 1;
        return TLS_BACKEND_EOF;
    }

    if (s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED &&
        blocked == S2N_BLOCKED_ON_READ) {
        return TLS_BACKEND_WANT_READ;
    }

    set_s2n_error(ctx, "s2n_recv");
    return TLS_BACKEND_ERROR;
}

BACKEND_STATIC tls_backend_status
tls_backend_close(tls_backend_ctx ctx)
{
    s2n_blocked_status blocked;

    if (ctx->closed)
        return TLS_BACKEND_OK;

    s2n_shutdown(ctx->conn, &blocked);
    ctx->closed = 1;

    return TLS_BACKEND_OK;
}

BACKEND_STATIC tls_backend_status
tls_backend_get_peer_cert(tls_backend_ctx ctx,
                          hx509_context hx509ctx,
                          hx509_cert *cert)
{
    struct s2n_cert_chain_and_key *peer_chain = NULL;
    struct s2n_cert *s2n_cert = NULL;
    const uint8_t *cert_der = NULL;
    uint32_t cert_len = 0;
    uint32_t chain_len = 0;

    *cert = NULL;

    /* Allocate a cert chain structure to receive the peer chain */
    peer_chain = s2n_cert_chain_and_key_new();
    if (peer_chain == NULL) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Failed to allocate peer cert chain");
        return TLS_BACKEND_ERROR;
    }

    /* Get peer certificate chain from s2n */
    if (s2n_connection_get_peer_cert_chain(ctx->conn, peer_chain) != 0) {
        s2n_cert_chain_and_key_free(peer_chain);
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "No peer certificate available");
        return TLS_BACKEND_ERROR;
    }

    /* Get chain length */
    if (s2n_cert_chain_get_length(peer_chain, &chain_len) != 0 || chain_len == 0) {
        s2n_cert_chain_and_key_free(peer_chain);
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Empty peer certificate chain");
        return TLS_BACKEND_ERROR;
    }

    /* Get the leaf certificate (index 0) */
    if (s2n_cert_chain_get_cert(peer_chain, &s2n_cert, 0) != 0) {
        s2n_cert_chain_and_key_free(peer_chain);
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Failed to get leaf certificate");
        return TLS_BACKEND_ERROR;
    }

    /* Get DER encoding of the certificate */
    if (s2n_cert_get_der(s2n_cert, &cert_der, &cert_len) != 0) {
        s2n_cert_chain_and_key_free(peer_chain);
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Failed to get certificate DER");
        return TLS_BACKEND_ERROR;
    }

    /* Create hx509 cert from DER */
    *cert = hx509_cert_init_data(hx509ctx, cert_der, cert_len, NULL);
    s2n_cert_chain_and_key_free(peer_chain);

    if (*cert == NULL) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "hx509_cert_init_data failed");
        return TLS_BACKEND_ERROR;
    }

    return TLS_BACKEND_OK;
}

BACKEND_STATIC const char *
tls_backend_get_version(tls_backend_ctx ctx)
{
    return s2n_connection_get_actual_protocol_version(ctx->conn) >= S2N_TLS13
           ? "TLSv1.3" : "TLSv1.2";
}

BACKEND_STATIC const char *
tls_backend_get_cipher(tls_backend_ctx ctx)
{
    return s2n_connection_get_cipher(ctx->conn);
}

BACKEND_STATIC const char *
tls_backend_get_error(tls_backend_ctx ctx)
{
    return ctx->error_buf;
}

BACKEND_STATIC void
tls_backend_destroy(tls_backend_ctx ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->conn)
        s2n_connection_free(ctx->conn);
    if (ctx->config)
        s2n_config_free(ctx->config);
    free(ctx->expected_hostname);
    free(ctx);
}

/*
 * Channel Binding Extraction
 */

/*
 * Helper: Get the server's certificate DER for channel binding.
 * For server: get our own certificate from our_chain
 * For client: get peer certificate
 */
static int
get_server_cert_der(tls_backend_ctx ctx, int is_server,
                    const uint8_t **cert_der, uint32_t *cert_len,
                    struct s2n_cert_chain_and_key **to_free)
{
    struct s2n_cert *s2n_cert = NULL;
    uint32_t chain_len = 0;

    *to_free = NULL;

    if (is_server) {
        /* Server: use our own certificate */
        if (ctx->our_chain == NULL) {
            return -1;
        }
        if (s2n_cert_chain_get_cert(ctx->our_chain, &s2n_cert, 0) != 0) {
            return -1;
        }
    } else {
        /* Client: get peer (server) certificate */
        struct s2n_cert_chain_and_key *peer_chain = s2n_cert_chain_and_key_new();
        if (peer_chain == NULL) {
            return -1;
        }

        if (s2n_connection_get_peer_cert_chain(ctx->conn, peer_chain) != 0) {
            s2n_cert_chain_and_key_free(peer_chain);
            return -1;
        }

        if (s2n_cert_chain_get_length(peer_chain, &chain_len) != 0 || chain_len == 0) {
            s2n_cert_chain_and_key_free(peer_chain);
            return -1;
        }

        if (s2n_cert_chain_get_cert(peer_chain, &s2n_cert, 0) != 0) {
            s2n_cert_chain_and_key_free(peer_chain);
            return -1;
        }

        *to_free = peer_chain;
    }

    if (s2n_cert_get_der(s2n_cert, cert_der, cert_len) != 0) {
        if (*to_free) {
            s2n_cert_chain_and_key_free(*to_free);
            *to_free = NULL;
        }
        return -1;
    }

    return 0;
}

BACKEND_STATIC tls_backend_status
tls_backend_get_cb_server_end_point(tls_backend_ctx ctx,
                                    int is_server,
                                    uint8_t *cb_data,
                                    size_t *cb_len)
{
    const uint8_t *cert_der = NULL;
    uint32_t cert_der_len = 0;
    struct s2n_cert_chain_and_key *to_free = NULL;
    hx509_cert hx_cert = NULL;
    const Certificate *cert;
    const heim_oid *sig_oid;
    const EVP_MD *md;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    if (!ctx->handshake_done) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Handshake not complete");
        return TLS_BACKEND_ERROR;
    }

    /* Get the server certificate DER */
    if (get_server_cert_der(ctx, is_server, &cert_der, &cert_der_len, &to_free) != 0) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "No server certificate available");
        return TLS_BACKEND_ERROR;
    }

    /* Parse DER to hx509 cert to get signature algorithm */
    hx_cert = hx509_cert_init_data(NULL, cert_der, cert_der_len, NULL);
    if (hx_cert == NULL) {
        if (to_free)
            s2n_cert_chain_and_key_free(to_free);
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Failed to parse certificate");
        return TLS_BACKEND_ERROR;
    }

    /* Get the Certificate structure to access signature algorithm */
    cert = _hx509_get_cert(hx_cert);
    sig_oid = &cert->signatureAlgorithm.algorithm;

    /*
     * RFC 5929 section 4.1:
     * Select hash based on certificate signature algorithm.
     * MD5/SHA-1 -> SHA-256, otherwise use the signature's hash.
     */
    if (der_heim_oid_cmp(sig_oid, ASN1_OID_ID_PKCS1_SHA384WITHRSAENCRYPTION) == 0 ||
        der_heim_oid_cmp(sig_oid, ASN1_OID_ID_ECDSA_WITH_SHA384) == 0) {
        md = EVP_sha384();
        hash_len = 48;
    } else if (der_heim_oid_cmp(sig_oid, ASN1_OID_ID_PKCS1_SHA512WITHRSAENCRYPTION) == 0 ||
               der_heim_oid_cmp(sig_oid, ASN1_OID_ID_ECDSA_WITH_SHA512) == 0) {
        md = EVP_sha512();
        hash_len = 64;
    } else {
        /* SHA-256 for MD5, SHA-1, SHA-256, and unknown */
        md = EVP_sha256();
        hash_len = 32;
    }

    hx509_cert_free(hx_cert);

    /* Hash the raw DER certificate data */
    if (EVP_Digest(cert_der, cert_der_len, hash, &hash_len, md, NULL) != 1) {
        if (to_free)
            s2n_cert_chain_and_key_free(to_free);
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Failed to hash certificate");
        return TLS_BACKEND_ERROR;
    }

    if (to_free)
        s2n_cert_chain_and_key_free(to_free);

    if (*cb_len < hash_len) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Buffer too small for channel binding");
        return TLS_BACKEND_ERROR;
    }

    memcpy(cb_data, hash, hash_len);
    *cb_len = hash_len;

    heim_debug(ctx->hctx, 10, "TLS: tls-server-end-point CB length=%u", hash_len);

    return TLS_BACKEND_OK;
}

BACKEND_STATIC tls_backend_status
tls_backend_get_cb_unique(tls_backend_ctx ctx,
                          uint8_t *cb_data,
                          size_t *cb_len)
{
    (void)cb_data;
    (void)cb_len;

    if (!ctx->handshake_done) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Handshake not complete");
        return TLS_BACKEND_ERROR;
    }

    /*
     * s2n-tls does not expose the TLS Finished messages, which are needed
     * for tls-unique channel binding (RFC 5929).
     *
     * For TLS 1.3, tls-unique is deprecated anyway - use tls-exporter instead.
     * For TLS 1.2, this is a limitation of the s2n backend.
     */
    if (s2n_connection_get_actual_protocol_version(ctx->conn) >= S2N_TLS13) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "tls-unique not available for TLS 1.3, use tls-exporter");
    } else {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "tls-unique not supported by s2n-tls (Finished messages not exposed)");
    }
    return TLS_BACKEND_ERROR;
}

BACKEND_STATIC tls_backend_status
tls_backend_get_cb_exporter(tls_backend_ctx ctx,
                            uint8_t *cb_data,
                            size_t *cb_len)
{
    /*
     * RFC 9266: tls-exporter channel binding
     *
     * Label: "EXPORTER-Channel-Binding"
     * Context: empty (zero-length)
     * Length: 32 bytes
     */
    static const uint8_t label[] = "EXPORTER-Channel-Binding";
    const size_t export_len = 32;

    if (!ctx->handshake_done) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Handshake not complete");
        return TLS_BACKEND_ERROR;
    }

    if (*cb_len < export_len) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Buffer too small for tls-exporter (need 32 bytes)");
        return TLS_BACKEND_ERROR;
    }

    /*
     * s2n_connection_tls_exporter implements RFC 5705 (TLS 1.2) and
     * RFC 8446 (TLS 1.3) key material export.
     */
    if (s2n_connection_tls_exporter(ctx->conn,
                                     label, sizeof(label) - 1,
                                     NULL, 0,
                                     cb_data, export_len) != 0) {
        set_s2n_error(ctx, "s2n_connection_tls_exporter");
        return TLS_BACKEND_ERROR;
    }

    *cb_len = export_len;

    heim_debug(ctx->hctx, 10, "TLS: tls-exporter CB length=%zu", export_len);

    return TLS_BACKEND_OK;
}

/*
 * Backend vtable for runtime dispatch
 */
const tls_backend_ops tls_backend_s2n_ops = {
    .name = "s2n-tls",
    .init = tls_backend_init,
    .handshake = tls_backend_handshake,
    .handshake_done = tls_backend_handshake_done,
    .encrypt = tls_backend_encrypt,
    .decrypt = tls_backend_decrypt,
    .close = tls_backend_close,
    .get_peer_cert = tls_backend_get_peer_cert,
    .get_version = tls_backend_get_version,
    .get_cipher = tls_backend_get_cipher,
    .get_error = tls_backend_get_error,
    .destroy = tls_backend_destroy,
    .get_cb_server_end_point = tls_backend_get_cb_server_end_point,
    .get_cb_unique = tls_backend_get_cb_unique,
    .get_cb_exporter = tls_backend_get_cb_exporter,
};

#endif /* GSS_TLS_S2N */
