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
 * OpenSSL backend for GSS-TLS mechanism
 *
 * Uses memory BIOs for token-based I/O (no sockets).
 */

#include <config.h>

#ifdef GSS_TLS_OPENSSL

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "tls_backend.h"
#include <der.h>

/*
 * When both backends are compiled, rename functions to avoid symbol conflicts.
 * The dispatcher in tls_backend.c will call the appropriate backend via vtable.
 * Functions are made static since they're only accessed via the vtable.
 */
#ifdef GSS_TLS_BOTH
#define BACKEND_STATIC static __attribute__((unused))
#define tls_backend_name         tls_backend_openssl_name
#define tls_backend_init         tls_backend_openssl_init
#define tls_backend_handshake    tls_backend_openssl_handshake
#define tls_backend_handshake_done tls_backend_openssl_handshake_done
#define tls_backend_encrypt      tls_backend_openssl_encrypt
#define tls_backend_decrypt      tls_backend_openssl_decrypt
#define tls_backend_close        tls_backend_openssl_close
#define tls_backend_get_peer_cert tls_backend_openssl_get_peer_cert
#define tls_backend_get_version  tls_backend_openssl_get_version
#define tls_backend_get_cipher   tls_backend_openssl_get_cipher
#define tls_backend_get_error    tls_backend_openssl_get_error
#define tls_backend_destroy      tls_backend_openssl_destroy
#define tls_backend_get_cb_server_end_point tls_backend_openssl_get_cb_server_end_point
#define tls_backend_get_cb_unique tls_backend_openssl_get_cb_unique
#define tls_backend_get_cb_exporter tls_backend_openssl_get_cb_exporter
#else
#define BACKEND_STATIC
#endif

/* Forward declaration for hx509 private API we need */
HX509_LIB_FUNCTION int HX509_LIB_CALL
_hx509_private_key_export(hx509_context, const hx509_private_key,
                          hx509_key_format_t, heim_octet_string *);

/*
 * OpenSSL backend context
 */
struct tls_backend_ctx {
    heim_context hctx;            /* Debug/trace context */

    SSL_CTX *ssl_ctx;             /* SSL context */
    SSL *ssl;                     /* SSL connection */
    BIO *rbio;                    /* Read BIO (input from peer) */
    BIO *wbio;                    /* Write BIO (output to peer) */

    tls_backend_iobuf *recv_buf;  /* GSS input buffer */
    tls_backend_iobuf *send_buf;  /* GSS output buffer */

    tls_backend_mode mode;        /* Client or server */
    unsigned int handshake_done : 1;
    unsigned int closed : 1;

    char error_buf[256];          /* Last error message */
};

/*
 * Get last OpenSSL error as string
 */
static void
set_openssl_error(tls_backend_ctx ctx, const char *prefix)
{
    unsigned long err = ERR_peek_last_error();
    if (err) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf), "%s: %s",
                 prefix, ERR_error_string(err, NULL));
    } else {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf), "%s", prefix);
    }
    ERR_clear_error();
}

/*
 * Transfer data from GSS recv_buf to SSL read BIO
 */
static int
feed_input(tls_backend_ctx ctx)
{
    BIO *rbio;
    size_t avail = tls_iobuf_available(ctx->recv_buf);
    int written;

    if (avail == 0)
        return 0;

    /* Get read BIO from SSL (SSL owns the BIO after SSL_set_bio) */
    rbio = SSL_get_rbio(ctx->ssl);
    if (rbio == NULL)
        return 0;

    written = BIO_write(rbio,
                        ctx->recv_buf->data + ctx->recv_buf->pos,
                        (int)avail);
    if (written > 0) {
        ctx->recv_buf->pos += written;
        return written;
    }
    return 0;
}

/*
 * Transfer data from SSL write BIO to GSS send_buf
 */
static int
drain_output(tls_backend_ctx ctx)
{
    BIO *wbio;
    char buf[4096];
    int total = 0;
    int n;

    /* Get write BIO from SSL (SSL owns the BIO after SSL_set_bio) */
    wbio = SSL_get_wbio(ctx->ssl);
    if (wbio == NULL)
        return 0;

    while ((n = BIO_read(wbio, buf, sizeof(buf))) > 0) {
        if (tls_iobuf_append(ctx->send_buf, (uint8_t *)buf, n) != 0)
            return -1;
        total += n;
    }
    return total;
}

/*
 * Load hx509 certificate into OpenSSL X509
 */
static X509 *
hx509_cert_to_openssl(hx509_context hx509ctx, hx509_cert cert)
{
    X509 *x509 = NULL;
    heim_octet_string data;
    const unsigned char *p;
    int ret;

    memset(&data, 0, sizeof(data));
    ret = hx509_cert_binary(hx509ctx, cert, &data);
    if (ret != 0)
        return NULL;

    p = (const unsigned char *)data.data;
    x509 = d2i_X509(NULL, &p, data.length);
    der_free_octet_string(&data);

    return x509;
}

/*
 * Load hx509 private key into OpenSSL EVP_PKEY
 */
static EVP_PKEY *
hx509_key_to_openssl(hx509_context hx509ctx, hx509_private_key key)
{
    EVP_PKEY *pkey = NULL;
    heim_octet_string data;
    const unsigned char *p;
    int ret;

    memset(&data, 0, sizeof(data));
    /* Export key in PKCS#8 DER format */
    ret = _hx509_private_key_export(hx509ctx, key,
                                    HX509_KEY_FORMAT_DER, &data);
    if (ret != 0)
        return NULL;

    p = (const unsigned char *)data.data;
    pkey = d2i_AutoPrivateKey(NULL, &p, data.length);
    der_free_octet_string(&data);

    return pkey;
}

/*
 * Configure SSL_CTX with certificates and trust anchors from hx509
 */
static int
configure_ssl_ctx(tls_backend_ctx ctx, const tls_backend_config *config)
{
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    X509_STORE *store;
    hx509_cursor cursor = NULL;
    hx509_cert hxcert;
    int ret = -1;

    /* Load our certificate if present */
    if (config->certs != NULL) {
        heim_debug(ctx->hctx, 10, "TLS: loading certificate chain");
        ret = hx509_certs_start_seq(config->hx509ctx, config->certs, &cursor);
        if (ret == 0) {
            /* First cert is our leaf certificate */
            if (hx509_certs_next_cert(config->hx509ctx, config->certs,
                                      cursor, &hxcert) == 0 && hxcert != NULL) {
                cert = hx509_cert_to_openssl(config->hx509ctx, hxcert);
                if (cert == NULL) {
                    set_openssl_error(ctx, "Failed to convert certificate");
                    heim_debug(ctx->hctx, 1, "TLS: failed to convert certificate to OpenSSL format");
                    hx509_cert_free(hxcert);
                    goto out;
                }

                if (SSL_CTX_use_certificate(ctx->ssl_ctx, cert) != 1) {
                    set_openssl_error(ctx, "SSL_CTX_use_certificate");
                    heim_debug(ctx->hctx, 1, "TLS: SSL_CTX_use_certificate failed");
                    hx509_cert_free(hxcert);
                    goto out;
                }
                heim_debug(ctx->hctx, 10, "TLS: loaded leaf certificate");
                hx509_cert_free(hxcert);

                /* Add remaining certs as chain */
                while (hx509_certs_next_cert(config->hx509ctx, config->certs,
                                             cursor, &hxcert) == 0 && hxcert != NULL) {
                    X509 *chain_cert = hx509_cert_to_openssl(config->hx509ctx, hxcert);
                    hx509_cert_free(hxcert);
                    if (chain_cert == NULL)
                        continue;
                    /* SSL_CTX_add1_chain_cert increases refcount */
                    if (SSL_CTX_add1_chain_cert(ctx->ssl_ctx, chain_cert) != 1) {
                        X509_free(chain_cert);
                    }
                    X509_free(chain_cert);
                }
            }
            hx509_certs_end_seq(config->hx509ctx, config->certs, cursor);
            cursor = NULL;
        }
    }

    /* Load our private key if present */
    if (config->key != NULL) {
        heim_debug(ctx->hctx, 10, "TLS: loading private key");
        pkey = hx509_key_to_openssl(config->hx509ctx, config->key);
        if (pkey == NULL) {
            set_openssl_error(ctx, "Failed to convert private key");
            heim_debug(ctx->hctx, 1, "TLS: failed to convert private key to OpenSSL format");
            goto out;
        }

        if (SSL_CTX_use_PrivateKey(ctx->ssl_ctx, pkey) != 1) {
            set_openssl_error(ctx, "SSL_CTX_use_PrivateKey");
            heim_debug(ctx->hctx, 1, "TLS: SSL_CTX_use_PrivateKey failed");
            goto out;
        }

        if (SSL_CTX_check_private_key(ctx->ssl_ctx) != 1) {
            set_openssl_error(ctx, "SSL_CTX_check_private_key");
            heim_debug(ctx->hctx, 1, "TLS: SSL_CTX_check_private_key failed");
            goto out;
        }
        heim_debug(ctx->hctx, 10, "TLS: private key loaded and verified");
    }

    /* Configure trust anchors */
    if (config->trust_anchors != NULL && config->verify_peer) {
        store = SSL_CTX_get_cert_store(ctx->ssl_ctx);

        ret = hx509_certs_start_seq(config->hx509ctx, config->trust_anchors, &cursor);
        if (ret == 0) {
            while (hx509_certs_next_cert(config->hx509ctx, config->trust_anchors,
                                         cursor, &hxcert) == 0 && hxcert != NULL) {
                X509 *ta_cert = hx509_cert_to_openssl(config->hx509ctx, hxcert);
                hx509_cert_free(hxcert);
                if (ta_cert != NULL) {
                    X509_STORE_add_cert(store, ta_cert);
                    X509_free(ta_cert);
                }
            }
            hx509_certs_end_seq(config->hx509ctx, config->trust_anchors, cursor);
            cursor = NULL;
        }

        SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER, NULL);
    } else {
        SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_NONE, NULL);
    }

    /* Server: optionally require client certificate */
    if (config->mode == TLS_BACKEND_SERVER && config->require_client_cert) {
        SSL_CTX_set_verify(ctx->ssl_ctx,
                           SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                           NULL);
    }

    ret = 0;

out:
    if (cert)
        X509_free(cert);
    if (pkey)
        EVP_PKEY_free(pkey);
    return ret;
}

BACKEND_STATIC const char *
tls_backend_name(void)
{
    return "OpenSSL";
}

BACKEND_STATIC tls_backend_status
tls_backend_init(tls_backend_ctx *pctx,
                 const tls_backend_config *config,
                 tls_backend_iobuf *recv_buf,
                 tls_backend_iobuf *send_buf)
{
    tls_backend_ctx ctx;
    const SSL_METHOD *method;

    *pctx = NULL;

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL)
        return TLS_BACKEND_ERROR;

    ctx->hctx = config->hctx;
    ctx->recv_buf = recv_buf;
    ctx->send_buf = send_buf;
    ctx->mode = config->mode;

    heim_debug(ctx->hctx, 10, "TLS: creating SSL context (OpenSSL %s mode)",
               config->mode == TLS_BACKEND_CLIENT ? "client" : "server");

    /* Create SSL context */
    if (config->mode == TLS_BACKEND_CLIENT) {
        method = TLS_client_method();
    } else {
        method = TLS_server_method();
    }

    ctx->ssl_ctx = SSL_CTX_new(method);
    if (ctx->ssl_ctx == NULL) {
        set_openssl_error(ctx, "SSL_CTX_new");
        goto fail;
    }

    /* Require TLS 1.2 minimum */
    SSL_CTX_set_min_proto_version(ctx->ssl_ctx, TLS1_2_VERSION);

    /* Configure certificates and trust */
    if (configure_ssl_ctx(ctx, config) != 0)
        goto fail;

    /* Create SSL connection */
    ctx->ssl = SSL_new(ctx->ssl_ctx);
    if (ctx->ssl == NULL) {
        set_openssl_error(ctx, "SSL_new");
        goto fail;
    }

    /* Create memory BIOs */
    ctx->rbio = BIO_new(BIO_s_mem());
    ctx->wbio = BIO_new(BIO_s_mem());
    if (ctx->rbio == NULL || ctx->wbio == NULL) {
        set_openssl_error(ctx, "BIO_new");
        goto fail;
    }

    /* Make BIOs non-blocking */
    BIO_set_nbio(ctx->rbio, 1);
    BIO_set_nbio(ctx->wbio, 1);

    /* Attach BIOs to SSL (SSL takes ownership) */
    SSL_set_bio(ctx->ssl, ctx->rbio, ctx->wbio);
    ctx->rbio = NULL;  /* Owned by SSL now */
    ctx->wbio = NULL;

    /* Set SNI for client */
    if (config->mode == TLS_BACKEND_CLIENT && config->hostname != NULL) {
        /* Cast through uintptr_t to avoid OpenSSL macro's const discard warning */
        SSL_set_tlsext_host_name(ctx->ssl, (char *)(uintptr_t)config->hostname);
    }

    /* Set connection mode */
    if (config->mode == TLS_BACKEND_CLIENT) {
        SSL_set_connect_state(ctx->ssl);
    } else {
        SSL_set_accept_state(ctx->ssl);
    }

    heim_debug(ctx->hctx, 10, "TLS: backend initialized successfully");

    *pctx = ctx;
    return TLS_BACKEND_OK;

fail:
    heim_debug(ctx->hctx, 1, "TLS: backend initialization failed");
    if (ctx->rbio)
        BIO_free(ctx->rbio);
    if (ctx->wbio)
        BIO_free(ctx->wbio);
    if (ctx->ssl)
        SSL_free(ctx->ssl);
    if (ctx->ssl_ctx)
        SSL_CTX_free(ctx->ssl_ctx);
    free(ctx);
    return TLS_BACKEND_ERROR;
}

BACKEND_STATIC tls_backend_status
tls_backend_handshake(tls_backend_ctx ctx)
{
    int ret, err;

    if (ctx->handshake_done)
        return TLS_BACKEND_OK;

    /* Feed any pending input to SSL */
    feed_input(ctx);

    /* Try handshake */
    ret = SSL_do_handshake(ctx->ssl);
    heim_debug(ctx->hctx, 15, "TLS: SSL_do_handshake returned %d", ret);

    /* Drain any output from SSL */
    drain_output(ctx);

    if (ret == 1) {
        ctx->handshake_done = 1;
        heim_debug(ctx->hctx, 5, "TLS: handshake complete, version=%s cipher=%s",
                   SSL_get_version(ctx->ssl), SSL_get_cipher_name(ctx->ssl));
        return TLS_BACKEND_OK;
    }

    err = SSL_get_error(ctx->ssl, ret);
    switch (err) {
    case SSL_ERROR_WANT_READ:
        /* Need more input data */
        heim_debug(ctx->hctx, 15, "TLS: handshake wants read");
        if (ctx->send_buf->len > 0)
            return TLS_BACKEND_WANT_WRITE;
        return TLS_BACKEND_WANT_READ;

    case SSL_ERROR_WANT_WRITE:
        /* Have output data */
        heim_debug(ctx->hctx, 15, "TLS: handshake wants write");
        return TLS_BACKEND_WANT_WRITE;

    case SSL_ERROR_ZERO_RETURN:
        heim_debug(ctx->hctx, 5, "TLS: connection closed during handshake");
        ctx->closed = 1;
        return TLS_BACKEND_CLOSED;

    default:
        set_openssl_error(ctx, "SSL_do_handshake");
        heim_debug(ctx->hctx, 1, "TLS: handshake error: %s", ctx->error_buf);
        return TLS_BACKEND_ERROR;
    }
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
    int ret, err;

    if (!ctx->handshake_done) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Handshake not complete");
        return TLS_BACKEND_ERROR;
    }

    heim_debug(ctx->hctx, 15, "TLS: encrypting %zu bytes", len);
    ret = SSL_write(ctx->ssl, data, (int)len);

    /* Drain output */
    drain_output(ctx);

    if (ret > 0)
        return TLS_BACKEND_OK;

    err = SSL_get_error(ctx->ssl, ret);
    if (err == SSL_ERROR_WANT_WRITE)
        return TLS_BACKEND_WANT_WRITE;

    set_openssl_error(ctx, "SSL_write");
    heim_debug(ctx->hctx, 1, "TLS: encrypt failed: %s", ctx->error_buf);
    return TLS_BACKEND_ERROR;
}

BACKEND_STATIC tls_backend_status
tls_backend_decrypt(tls_backend_ctx ctx,
                    uint8_t *data,
                    size_t *len)
{
    int ret, err;
    size_t buflen = *len;

    *len = 0;

    if (!ctx->handshake_done) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Handshake not complete");
        return TLS_BACKEND_ERROR;
    }

    /* Feed input */
    feed_input(ctx);

    ret = SSL_read(ctx->ssl, data, (int)buflen);
    if (ret > 0) {
        *len = ret;
        heim_debug(ctx->hctx, 15, "TLS: decrypted %d bytes", ret);
        return TLS_BACKEND_OK;
    }

    err = SSL_get_error(ctx->ssl, ret);
    switch (err) {
    case SSL_ERROR_WANT_READ:
        return TLS_BACKEND_WANT_READ;

    case SSL_ERROR_ZERO_RETURN:
        heim_debug(ctx->hctx, 5, "TLS: connection closed by peer");
        ctx->closed = 1;
        return TLS_BACKEND_EOF;

    default:
        set_openssl_error(ctx, "SSL_read");
        heim_debug(ctx->hctx, 1, "TLS: decrypt failed: %s", ctx->error_buf);
        return TLS_BACKEND_ERROR;
    }
}

BACKEND_STATIC tls_backend_status
tls_backend_close(tls_backend_ctx ctx)
{
    if (ctx->closed)
        return TLS_BACKEND_OK;

    heim_debug(ctx->hctx, 10, "TLS: sending close_notify");
    SSL_shutdown(ctx->ssl);
    drain_output(ctx);
    ctx->closed = 1;

    return TLS_BACKEND_OK;
}

BACKEND_STATIC tls_backend_status
tls_backend_get_peer_cert(tls_backend_ctx ctx,
                          hx509_context hx509ctx,
                          hx509_cert *cert)
{
    X509 *peer_cert;
    unsigned char *der = NULL;
    int der_len;

    *cert = NULL;

    peer_cert = SSL_get_peer_certificate(ctx->ssl);
    if (peer_cert == NULL)
        return TLS_BACKEND_ERROR;

    /* Convert to DER */
    der_len = i2d_X509(peer_cert, &der);
    X509_free(peer_cert);

    if (der_len <= 0 || der == NULL) {
        set_openssl_error(ctx, "i2d_X509");
        return TLS_BACKEND_ERROR;
    }

    /* Create hx509 cert from DER */
    *cert = hx509_cert_init_data(hx509ctx, der, der_len, NULL);
    OPENSSL_free(der);

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
    return SSL_get_version(ctx->ssl);
}

BACKEND_STATIC const char *
tls_backend_get_cipher(tls_backend_ctx ctx)
{
    return SSL_get_cipher_name(ctx->ssl);
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

    if (ctx->ssl)
        SSL_free(ctx->ssl);  /* Also frees the BIOs */
    if (ctx->ssl_ctx)
        SSL_CTX_free(ctx->ssl_ctx);
    free(ctx);
}

/*
 * Channel Binding Extraction
 */

BACKEND_STATIC tls_backend_status
tls_backend_get_cb_server_end_point(tls_backend_ctx ctx,
                                    int is_server,
                                    uint8_t *cb_data,
                                    size_t *cb_len)
{
    X509 *cert;
    const EVP_MD *md;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    int sig_nid;

    if (!ctx->handshake_done) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Handshake not complete");
        return TLS_BACKEND_ERROR;
    }

    /*
     * RFC 5929: The hash is of the server's certificate.
     * If we are the server, get our own cert; if client, get peer cert.
     */
    if (is_server) {
        /* Get our certificate from SSL_CTX */
        cert = SSL_CTX_get0_certificate(ctx->ssl_ctx);
        if (cert == NULL) {
            snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                     "No server certificate available");
            return TLS_BACKEND_ERROR;
        }
        /* SSL_CTX_get0_certificate doesn't increment refcount, don't free */
    } else {
        /* Get peer (server) certificate */
        cert = SSL_get_peer_certificate(ctx->ssl);
        if (cert == NULL) {
            snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                     "No peer certificate available");
            return TLS_BACKEND_ERROR;
        }
    }

    /*
     * RFC 5929 section 4.1:
     * "The hash function is selected as follows:
     *  - If the certificate's signatureAlgorithm uses a single hash function,
     *    and that hash function is either MD5 or SHA-1, then use SHA-256;
     *  - If the certificate's signatureAlgorithm uses a single hash function
     *    and that hash function is neither MD5 nor SHA-1, then use the
     *    certificate's signatureAlgorithm hash function;
     *  - If the certificate's signatureAlgorithm uses no hash functions or
     *    uses multiple hash functions, then this channel binding type's
     *    channel bindings are undefined."
     */
    sig_nid = X509_get_signature_nid(cert);

    switch (sig_nid) {
    case NID_sha384WithRSAEncryption:
    case NID_ecdsa_with_SHA384:
        md = EVP_sha384();
        break;
    case NID_sha512WithRSAEncryption:
    case NID_ecdsa_with_SHA512:
        md = EVP_sha512();
        break;
    default:
        /* SHA-256 for MD5, SHA-1, SHA-256, and unknown */
        md = EVP_sha256();
        break;
    }

    if (X509_digest(cert, md, hash, &hash_len) != 1) {
        if (!is_server)
            X509_free(cert);
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Failed to hash certificate");
        return TLS_BACKEND_ERROR;
    }

    if (!is_server)
        X509_free(cert);

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
    size_t finished_len;

    if (!ctx->handshake_done) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Handshake not complete");
        return TLS_BACKEND_ERROR;
    }

    /*
     * RFC 5929: tls-unique is broken for TLS 1.3 because the Finished
     * messages are encrypted and the semantics changed. Return error
     * and let caller use tls-exporter instead.
     */
    if (SSL_version(ctx->ssl) >= TLS1_3_VERSION) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "tls-unique not available for TLS 1.3, use tls-exporter");
        return TLS_BACKEND_ERROR;
    }

    /*
     * RFC 5929 section 3:
     * "The tls-unique channel binding value is the first Finished message
     *  sent, i.e., the client's Finished message for initial handshakes
     *  and the server's Finished message for session resumption."
     *
     * For simplicity, we always return our Finished message.
     * SSL_get_finished returns what we sent.
     */
    finished_len = SSL_get_finished(ctx->ssl, cb_data, *cb_len);
    if (finished_len == 0) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "No Finished message available");
        return TLS_BACKEND_ERROR;
    }

    if (finished_len > *cb_len) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Buffer too small for tls-unique");
        return TLS_BACKEND_ERROR;
    }

    *cb_len = finished_len;

    heim_debug(ctx->hctx, 10, "TLS: tls-unique CB length=%zu", finished_len);

    return TLS_BACKEND_OK;
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
    static const char label[] = "EXPORTER-Channel-Binding";
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
     * SSL_export_keying_material works for TLS 1.2 (with EMS) and TLS 1.3.
     * For TLS 1.2 without Extended Master Secret, it may not be available.
     */
    if (SSL_export_keying_material(ctx->ssl, cb_data, export_len,
                                   label, sizeof(label) - 1,
                                   NULL, 0, 0) != 1) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "SSL_export_keying_material failed");
        return TLS_BACKEND_ERROR;
    }

    *cb_len = export_len;

    heim_debug(ctx->hctx, 10, "TLS: tls-exporter CB length=%zu", export_len);

    return TLS_BACKEND_OK;
}

/*
 * Backend vtable for runtime dispatch
 */
const tls_backend_ops tls_backend_openssl_ops = {
    .name = "openssl",
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

#endif /* GSS_TLS_OPENSSL */
