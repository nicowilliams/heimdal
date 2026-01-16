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
 * TLS Backend dispatcher and shared utilities
 *
 * When GSS_TLS_BOTH is defined, this file provides:
 * - Runtime backend selection via GSS_TLS_BACKEND environment variable
 * - Dispatcher functions that call the selected backend
 * - Shared I/O buffer helper functions
 */

#include <config.h>

#if defined(GSS_TLS_S2N) || defined(GSS_TLS_OPENSSL)

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "tls_backend.h"

/*
 * I/O buffer helper functions (shared between backends)
 */

int
tls_iobuf_init(tls_backend_iobuf *buf, size_t initial_capacity)
{
    buf->data = malloc(initial_capacity);
    if (buf->data == NULL)
        return ENOMEM;

    buf->len = 0;
    buf->pos = 0;
    buf->capacity = initial_capacity;
    return 0;
}

void
tls_iobuf_free(tls_backend_iobuf *buf)
{
    free(buf->data);
    buf->data = NULL;
    buf->len = 0;
    buf->pos = 0;
    buf->capacity = 0;
}

int
tls_iobuf_ensure_capacity(tls_backend_iobuf *buf, size_t needed)
{
    if (needed <= buf->capacity)
        return 0;

    size_t new_capacity = buf->capacity * 2;
    if (new_capacity < needed)
        new_capacity = needed;

    uint8_t *new_data = realloc(buf->data, new_capacity);
    if (new_data == NULL)
        return ENOMEM;

    buf->data = new_data;
    buf->capacity = new_capacity;
    return 0;
}

int
tls_iobuf_append(tls_backend_iobuf *buf, const uint8_t *data, size_t len)
{
    if (tls_iobuf_ensure_capacity(buf, buf->len + len) != 0)
        return ENOMEM;

    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    return 0;
}

size_t
tls_iobuf_available(const tls_backend_iobuf *buf)
{
    return buf->len - buf->pos;
}

size_t
tls_iobuf_read(tls_backend_iobuf *buf, uint8_t *data, size_t len)
{
    size_t avail = tls_iobuf_available(buf);
    if (len > avail)
        len = avail;

    memcpy(data, buf->data + buf->pos, len);
    buf->pos += len;
    return len;
}

size_t
tls_iobuf_peek(const tls_backend_iobuf *buf, uint8_t *data, size_t len)
{
    size_t avail = tls_iobuf_available(buf);
    if (len > avail)
        len = avail;

    memcpy(data, buf->data + buf->pos, len);
    return len;
}

void
tls_iobuf_reset(tls_backend_iobuf *buf)
{
    buf->len = 0;
    buf->pos = 0;
}

void
tls_iobuf_compact(tls_backend_iobuf *buf)
{
    if (buf->pos == 0)
        return;

    size_t remaining = tls_iobuf_available(buf);
    if (remaining > 0)
        memmove(buf->data, buf->data + buf->pos, remaining);

    buf->len = remaining;
    buf->pos = 0;
}

#ifdef GSS_TLS_BOTH
/*
 * When both backends are compiled, select based on GSS_TLS_BACKEND env var.
 * Valid values: "openssl", "s2n", "s2n-tls"
 * Default: s2n-tls
 */

static const tls_backend_ops *selected_ops = NULL;

const tls_backend_ops *
tls_backend_get_ops(void)
{
    if (selected_ops == NULL) {
        const char *backend = secure_getenv("GSS_TLS_BACKEND");

        if (backend && (strcasecmp(backend, "openssl") == 0)) {
            selected_ops = &tls_backend_openssl_ops;
        } else if (backend && (strcasecmp(backend, "s2n") == 0 ||
                               strcasecmp(backend, "s2n-tls") == 0)) {
            selected_ops = &tls_backend_s2n_ops;
        } else {
            /* Default to s2n-tls */
            selected_ops = &tls_backend_s2n_ops;
        }
    }
    return selected_ops;
}

const char *
tls_backend_name(void)
{
    return tls_backend_get_ops()->name;
}

tls_backend_status
tls_backend_init(tls_backend_ctx *ctx,
                 const tls_backend_config *config,
                 tls_backend_iobuf *recv_buf,
                 tls_backend_iobuf *send_buf)
{
    return tls_backend_get_ops()->init(ctx, config, recv_buf, send_buf);
}

tls_backend_status
tls_backend_handshake(tls_backend_ctx ctx)
{
    return tls_backend_get_ops()->handshake(ctx);
}

int
tls_backend_handshake_done(tls_backend_ctx ctx)
{
    return tls_backend_get_ops()->handshake_done(ctx);
}

tls_backend_status
tls_backend_encrypt(tls_backend_ctx ctx, const uint8_t *data, size_t len)
{
    return tls_backend_get_ops()->encrypt(ctx, data, len);
}

tls_backend_status
tls_backend_decrypt(tls_backend_ctx ctx, uint8_t *data, size_t *len)
{
    return tls_backend_get_ops()->decrypt(ctx, data, len);
}

tls_backend_status
tls_backend_close(tls_backend_ctx ctx)
{
    return tls_backend_get_ops()->close(ctx);
}

tls_backend_status
tls_backend_get_peer_cert(tls_backend_ctx ctx,
                          hx509_context hx509ctx,
                          hx509_cert *cert)
{
    return tls_backend_get_ops()->get_peer_cert(ctx, hx509ctx, cert);
}

const char *
tls_backend_get_version(tls_backend_ctx ctx)
{
    return tls_backend_get_ops()->get_version(ctx);
}

const char *
tls_backend_get_cipher(tls_backend_ctx ctx)
{
    return tls_backend_get_ops()->get_cipher(ctx);
}

const char *
tls_backend_get_error(tls_backend_ctx ctx)
{
    return tls_backend_get_ops()->get_error(ctx);
}

void
tls_backend_destroy(tls_backend_ctx ctx)
{
    tls_backend_get_ops()->destroy(ctx);
}

tls_backend_status
tls_backend_get_cb_server_end_point(tls_backend_ctx ctx,
                                    int is_server,
                                    uint8_t *cb_data,
                                    size_t *cb_len)
{
    return tls_backend_get_ops()->get_cb_server_end_point(ctx, is_server, cb_data, cb_len);
}

tls_backend_status
tls_backend_get_cb_unique(tls_backend_ctx ctx,
                          uint8_t *cb_data,
                          size_t *cb_len)
{
    return tls_backend_get_ops()->get_cb_unique(ctx, cb_data, cb_len);
}

tls_backend_status
tls_backend_get_cb_exporter(tls_backend_ctx ctx,
                            uint8_t *cb_data,
                            size_t *cb_len)
{
    return tls_backend_get_ops()->get_cb_exporter(ctx, cb_data, cb_len);
}

tls_early_data_status
tls_backend_get_early_data_status(tls_backend_ctx ctx)
{
    const tls_backend_ops *ops = tls_backend_get_ops();
    if (ops->get_early_data_status == NULL)
        return TLS_EARLY_DATA_NOT_REQUESTED;
    return ops->get_early_data_status(ctx);
}

tls_backend_status
tls_backend_get_early_data(tls_backend_ctx ctx,
                           uint8_t *data,
                           size_t *len)
{
    const tls_backend_ops *ops = tls_backend_get_ops();
    if (ops->get_early_data == NULL) {
        *len = 0;
        return TLS_BACKEND_EOF;
    }
    return ops->get_early_data(ctx, data, len);
}

tls_backend_status
tls_backend_get_session_ticket(tls_backend_ctx ctx,
                               uint8_t *ticket,
                               size_t *len)
{
    const tls_backend_ops *ops = tls_backend_get_ops();
    if (ops->get_session_ticket == NULL) {
        *len = 0;
        return TLS_BACKEND_ERROR;
    }
    return ops->get_session_ticket(ctx, ticket, len);
}

#else /* !GSS_TLS_BOTH */

/*
 * When only one backend is compiled, tls_backend_get_ops returns that backend.
 */
const tls_backend_ops *
tls_backend_get_ops(void)
{
#ifdef GSS_TLS_S2N
    return &tls_backend_s2n_ops;
#else
    return &tls_backend_openssl_ops;
#endif
}

#endif /* GSS_TLS_BOTH */

#endif /* GSS_TLS_S2N || GSS_TLS_OPENSSL */
