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

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>

#include <openssl/evp.h>

/*
 * STS (Security Token Service) communication
 *
 * This module handles obtaining JWTs from an STS endpoint.
 * It uses GSS-TLS for the HTTPS connection and open-codes HTTP/1.1.
 *
 * Supported authentication methods to the STS:
 * - Password (client_credentials grant with Basic auth)
 * - Kerberos (Negotiate auth via GSS-API)
 * - JWT exchange (token exchange grant)
 * - Certificate (mTLS - client cert in TLS handshake)
 */

/* External mechanism OID for GSS-TLS */
extern gss_OID GSS_TLS_MECHANISM;

/*
 * Parsed URL structure
 */
typedef struct {
    char *scheme;       /* "https" */
    char *host;         /* hostname */
    char *port;         /* port string (default "443") */
    char *path;         /* path including query string */
} parsed_url;

/*
 * Parse a URL into components
 * Only supports https:// URLs
 */
static int
parse_url(const char *url, parsed_url *out)
{
    const char *p, *host_start, *host_end, *port_start, *path_start;
    size_t len;

    memset(out, 0, sizeof(*out));

    /* Check scheme */
    if (strncmp(url, "https://", 8) != 0)
        return EINVAL;

    out->scheme = strdup("https");
    if (out->scheme == NULL)
        return ENOMEM;

    p = url + 8;  /* Skip "https://" */
    host_start = p;

    /* Find end of host (could be :port or /path or end of string) */
    host_end = p;
    while (*host_end && *host_end != ':' && *host_end != '/')
        host_end++;

    len = host_end - host_start;
    if (len == 0) {
        free(out->scheme);
        return EINVAL;
    }

    out->host = malloc(len + 1);
    if (out->host == NULL) {
        free(out->scheme);
        return ENOMEM;
    }
    memcpy(out->host, host_start, len);
    out->host[len] = '\0';

    /* Check for port */
    if (*host_end == ':') {
        port_start = host_end + 1;
        path_start = port_start;
        while (*path_start && *path_start != '/')
            path_start++;

        len = path_start - port_start;
        if (len > 0) {
            out->port = malloc(len + 1);
            if (out->port == NULL) {
                free(out->host);
                free(out->scheme);
                return ENOMEM;
            }
            memcpy(out->port, port_start, len);
            out->port[len] = '\0';
        }
    } else {
        path_start = host_end;
    }

    /* Default port for https */
    if (out->port == NULL) {
        out->port = strdup("443");
        if (out->port == NULL) {
            free(out->host);
            free(out->scheme);
            return ENOMEM;
        }
    }

    /* Path (default to "/" if not specified) */
    if (*path_start == '/') {
        out->path = strdup(path_start);
    } else {
        out->path = strdup("/");
    }
    if (out->path == NULL) {
        free(out->port);
        free(out->host);
        free(out->scheme);
        return ENOMEM;
    }

    return 0;
}

static void
free_parsed_url(parsed_url *url)
{
    free(url->scheme);
    free(url->host);
    free(url->port);
    free(url->path);
    memset(url, 0, sizeof(*url));
}

/*
 * Connect to a host:port
 * Returns socket fd on success, -1 on failure
 */
static int
connect_to_host(heim_context hctx, const char *host, const char *port)
{
    struct addrinfo hints, *res, *res0;
    int fd = -1;
    int error;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    heim_debug(hctx, 10, "STS: resolving %s:%s", host, port);

    error = getaddrinfo(host, port, &hints, &res0);
    if (error) {
        heim_debug(hctx, 1, "STS: getaddrinfo failed: %s", gai_strerror(error));
        return -1;
    }

    for (res = res0; res; res = res->ai_next) {
        fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd < 0)
            continue;

        heim_debug(hctx, 10, "STS: connecting to %s:%s", host, port);

        if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
            close(fd);
            fd = -1;
            continue;
        }

        /* Success */
        break;
    }

    freeaddrinfo(res0);

    if (fd < 0) {
        heim_debug(hctx, 1, "STS: failed to connect to %s:%s", host, port);
    } else {
        heim_debug(hctx, 5, "STS: connected to %s:%s (fd=%d)", host, port, fd);
    }

    return fd;
}

/*
 * Perform GSS-TLS handshake over socket
 * Returns GSS_S_COMPLETE on success with established context
 */
static OM_uint32
do_tls_handshake(OM_uint32 *minor,
                 heim_context hctx,
                 int fd,
                 const char *hostname,
                 gss_cred_id_t tls_cred,
                 gss_ctx_id_t *tls_ctx)
{
    OM_uint32 major, tmp_minor;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    gss_name_t target_name = GSS_C_NO_NAME;
    gss_buffer_desc name_buf;
    char *target_str;
    int ret;

    *tls_ctx = GSS_C_NO_CONTEXT;

    /* Create target name for TLS (host@hostname) */
    ret = asprintf(&target_str, "host@%s", hostname);
    if (ret < 0) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    name_buf.value = target_str;
    name_buf.length = strlen(target_str);
    major = gss_import_name(minor, &name_buf, GSS_C_NT_HOSTBASED_SERVICE,
                            &target_name);
    free(target_str);
    if (major != GSS_S_COMPLETE)
        return major;

    heim_debug(hctx, 5, "STS: starting TLS handshake with %s", hostname);

    /* TLS handshake loop */
    do {
        major = gss_init_sec_context(minor,
                                     tls_cred,
                                     tls_ctx,
                                     target_name,
                                     GSS_TLS_MECHANISM,
                                     GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG,
                                     0,
                                     GSS_C_NO_CHANNEL_BINDINGS,
                                     &input_token,
                                     NULL,
                                     &output_token,
                                     NULL,
                                     NULL);

        /* Free previous input token if any */
        if (input_token.value) {
            free(input_token.value);
            input_token.value = NULL;
            input_token.length = 0;
        }

        if (GSS_ERROR(major)) {
            heim_debug(hctx, 1, "STS: TLS handshake failed: major=%u minor=%u",
                       (unsigned)major, (unsigned)*minor);
            gss_release_name(&tmp_minor, &target_name);
            return major;
        }

        /* Send output token to server */
        if (output_token.length > 0) {
            ssize_t n;
            size_t sent = 0;

            heim_debug(hctx, 10, "STS: sending %zu bytes TLS data",
                       output_token.length);

            while (sent < output_token.length) {
                n = write(fd, (char *)output_token.value + sent,
                          output_token.length - sent);
                if (n < 0) {
                    if (errno == EINTR)
                        continue;
                    *minor = errno;
                    gss_release_buffer(&tmp_minor, &output_token);
                    gss_release_name(&tmp_minor, &target_name);
                    gss_delete_sec_context(&tmp_minor, tls_ctx, NULL);
                    return GSS_S_FAILURE;
                }
                sent += n;
            }
            gss_release_buffer(&tmp_minor, &output_token);
        }

        /* If handshake not complete, read response */
        if (major == GSS_S_CONTINUE_NEEDED) {
            /* Read TLS records from server */
            char buf[16384];
            ssize_t n;
            struct pollfd pfd;

            pfd.fd = fd;
            pfd.events = POLLIN;

            /* Wait for data with timeout */
            ret = poll(&pfd, 1, 30000);
            if (ret <= 0) {
                *minor = ret == 0 ? ETIMEDOUT : errno;
                gss_release_name(&tmp_minor, &target_name);
                gss_delete_sec_context(&tmp_minor, tls_ctx, NULL);
                return GSS_S_FAILURE;
            }

            n = read(fd, buf, sizeof(buf));
            if (n <= 0) {
                *minor = n == 0 ? ECONNRESET : errno;
                gss_release_name(&tmp_minor, &target_name);
                gss_delete_sec_context(&tmp_minor, tls_ctx, NULL);
                return GSS_S_FAILURE;
            }

            heim_debug(hctx, 10, "STS: received %zd bytes TLS data", n);

            input_token.value = malloc(n);
            if (input_token.value == NULL) {
                *minor = ENOMEM;
                gss_release_name(&tmp_minor, &target_name);
                gss_delete_sec_context(&tmp_minor, tls_ctx, NULL);
                return GSS_S_FAILURE;
            }
            memcpy(input_token.value, buf, n);
            input_token.length = n;
        }
    } while (major == GSS_S_CONTINUE_NEEDED);

    gss_release_name(&tmp_minor, &target_name);
    heim_debug(hctx, 5, "STS: TLS handshake complete");

    return GSS_S_COMPLETE;
}

/*
 * Send data over TLS connection using gss_wrap
 */
static OM_uint32
tls_send(OM_uint32 *minor,
         heim_context hctx,
         int fd,
         gss_ctx_id_t tls_ctx,
         const void *data,
         size_t len)
{
    OM_uint32 major, tmp_minor;
    gss_buffer_desc input_buf, output_buf;
    ssize_t n;
    size_t sent = 0;

    input_buf.value = rk_UNCONST(data);
    input_buf.length = len;

    major = gss_wrap(minor, tls_ctx, 1, GSS_C_QOP_DEFAULT,
                     &input_buf, NULL, &output_buf);
    if (major != GSS_S_COMPLETE) {
        heim_debug(hctx, 1, "STS: gss_wrap failed: %u", (unsigned)major);
        return major;
    }

    heim_debug(hctx, 10, "STS: sending %zu bytes wrapped (%zu plaintext)",
               output_buf.length, len);

    while (sent < output_buf.length) {
        n = write(fd, (char *)output_buf.value + sent, output_buf.length - sent);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            *minor = errno;
            gss_release_buffer(&tmp_minor, &output_buf);
            return GSS_S_FAILURE;
        }
        sent += n;
    }

    gss_release_buffer(&tmp_minor, &output_buf);
    return GSS_S_COMPLETE;
}

/*
 * Receive data over TLS connection using gss_unwrap
 * Caller must free *data
 */
static OM_uint32
tls_recv(OM_uint32 *minor,
         heim_context hctx,
         int fd,
         gss_ctx_id_t tls_ctx,
         char **data,
         size_t *len)
{
    OM_uint32 major, tmp_minor;
    gss_buffer_desc input_buf, output_buf;
    char buf[16384];
    ssize_t n;
    struct pollfd pfd;
    int ret;

    *data = NULL;
    *len = 0;

    pfd.fd = fd;
    pfd.events = POLLIN;

    /* Wait for data with timeout */
    ret = poll(&pfd, 1, 30000);
    if (ret <= 0) {
        *minor = ret == 0 ? ETIMEDOUT : errno;
        return GSS_S_FAILURE;
    }

    n = read(fd, buf, sizeof(buf));
    if (n <= 0) {
        *minor = n == 0 ? ECONNRESET : errno;
        return GSS_S_FAILURE;
    }

    heim_debug(hctx, 10, "STS: received %zd bytes wrapped data", n);

    input_buf.value = buf;
    input_buf.length = n;

    major = gss_unwrap(minor, tls_ctx, &input_buf, &output_buf, NULL, NULL);
    if (major != GSS_S_COMPLETE) {
        heim_debug(hctx, 1, "STS: gss_unwrap failed: %u", (unsigned)major);
        return major;
    }

    heim_debug(hctx, 10, "STS: unwrapped to %zu bytes plaintext", output_buf.length);

    *data = malloc(output_buf.length + 1);
    if (*data == NULL) {
        gss_release_buffer(&tmp_minor, &output_buf);
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }
    memcpy(*data, output_buf.value, output_buf.length);
    (*data)[output_buf.length] = '\0';
    *len = output_buf.length;

    gss_release_buffer(&tmp_minor, &output_buf);
    return GSS_S_COMPLETE;
}

/*
 * Base64 encode for Basic auth
 */
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *
base64_encode(const char *input, size_t len)
{
    size_t out_len = ((len + 2) / 3) * 4 + 1;
    char *output = malloc(out_len);
    char *p;
    size_t i;

    if (output == NULL)
        return NULL;

    p = output;
    for (i = 0; i < len; i += 3) {
        unsigned int n = (unsigned char)input[i] << 16;
        if (i + 1 < len)
            n |= (unsigned char)input[i + 1] << 8;
        if (i + 2 < len)
            n |= (unsigned char)input[i + 2];

        *p++ = base64_chars[(n >> 18) & 0x3f];
        *p++ = base64_chars[(n >> 12) & 0x3f];
        *p++ = (i + 1 < len) ? base64_chars[(n >> 6) & 0x3f] : '=';
        *p++ = (i + 2 < len) ? base64_chars[n & 0x3f] : '=';
    }
    *p = '\0';
    return output;
}

/*
 * URL-encode a string for form data
 */
static char *
url_encode(const char *input)
{
    size_t len = strlen(input);
    size_t out_len = len * 3 + 1;
    char *output = malloc(out_len);
    char *p;
    size_t i;

    if (output == NULL)
        return NULL;

    p = output;
    for (i = 0; i < len; i++) {
        unsigned char c = input[i];
        if ((c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            *p++ = c;
        } else {
            sprintf(p, "%%%02X", c);
            p += 3;
        }
    }
    *p = '\0';
    return output;
}

/*
 * Base64url encode for channel bindings claim (no padding, URL-safe)
 */
static char *
base64url_encode(const uint8_t *input, size_t len)
{
    static const char base64url_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t out_len = ((len + 2) / 3) * 4 + 1;
    char *output = malloc(out_len);
    char *p;
    size_t i;

    if (output == NULL)
        return NULL;

    p = output;
    for (i = 0; i < len; i += 3) {
        unsigned int n = input[i] << 16;
        if (i + 1 < len)
            n |= input[i + 1] << 8;
        if (i + 2 < len)
            n |= input[i + 2];

        *p++ = base64url_chars[(n >> 18) & 0x3f];
        *p++ = base64url_chars[(n >> 12) & 0x3f];
        if (i + 1 < len)
            *p++ = base64url_chars[(n >> 6) & 0x3f];
        if (i + 2 < len)
            *p++ = base64url_chars[n & 0x3f];
    }
    *p = '\0';
    return output;
}

/*
 * Compute channel bindings hash for inclusion in JWT.
 *
 * Uses SHA-256 over the channel bindings structure (similar to RFC 4121
 * but with a stronger hash). The hash covers:
 *   - initiator_addrtype (4 bytes, network order)
 *   - initiator_address (length + data)
 *   - acceptor_addrtype (4 bytes, network order)
 *   - acceptor_address (length + data)
 *   - application_data (length + data, with CB type prefix stripped if present)
 *
 * If application_data starts with a known CB type prefix (e.g.,
 * "tls-server-end-point:", "tls-unique:", "tls-exporter:"), the prefix
 * is extracted and returned separately. The hash includes only the data
 * after the colon, and the length field reflects this shorter length.
 */

/* Known channel binding type prefixes per RFC 5929 / RFC 9266 */
static const char *known_cb_types[] = {
    "tls-server-end-point:",
    "tls-unique:",
    "tls-exporter:",
    NULL
};

/*
 * Check if application_data starts with a known CB type prefix.
 * Returns pointer to data after colon if found, NULL otherwise.
 * Sets *cb_type to the type name (without colon) if found.
 */
static const uint8_t *
extract_cb_type(const gss_buffer_t app_data, const char **cb_type_out,
                size_t *data_len_out)
{
    const char *data = app_data->value;
    size_t len = app_data->length;
    const char **type;

    *cb_type_out = NULL;
    *data_len_out = len;

    if (data == NULL || len == 0)
        return app_data->value;

    for (type = known_cb_types; *type != NULL; type++) {
        size_t prefix_len = strlen(*type);
        if (len > prefix_len && memcmp(data, *type, prefix_len) == 0) {
            /* Found a known prefix - return type without the colon */
            *cb_type_out = *type;
            *data_len_out = len - prefix_len;
            return (const uint8_t *)(data + prefix_len);
        }
    }

    /* No known prefix found */
    return app_data->value;
}

OM_uint32
_gss_jwt_compute_cb_hash(OM_uint32 *minor,
                         const gss_channel_bindings_t bindings,
                         uint8_t cb_hash_out[32],
                         char **cb_type_out)
{
    EVP_MD_CTX *ctx;
    uint8_t buf[4];
    unsigned int hash_len;
    const char *cb_type_prefix = NULL;
    const uint8_t *app_data_value;
    size_t app_data_len;

    *minor = 0;
    if (cb_type_out)
        *cb_type_out = NULL;

    if (bindings == GSS_C_NO_CHANNEL_BINDINGS) {
        *minor = EINVAL;
        return GSS_S_BAD_BINDINGS;
    }

    /* Check for CB type prefix in application_data */
    app_data_value = extract_cb_type(&bindings->application_data,
                                     &cb_type_prefix, &app_data_len);

    /* If we found a CB type prefix, return it (without trailing colon) */
    if (cb_type_prefix != NULL && cb_type_out != NULL) {
        size_t type_len = strlen(cb_type_prefix) - 1; /* exclude colon */
        *cb_type_out = malloc(type_len + 1);
        if (*cb_type_out == NULL) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }
        memcpy(*cb_type_out, cb_type_prefix, type_len);
        (*cb_type_out)[type_len] = '\0';
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        if (cb_type_out && *cb_type_out) {
            free(*cb_type_out);
            *cb_type_out = NULL;
        }
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        if (cb_type_out && *cb_type_out) {
            free(*cb_type_out);
            *cb_type_out = NULL;
        }
        *minor = EINVAL;
        return GSS_S_FAILURE;
    }

    /* initiator_addrtype (network byte order) */
    buf[0] = (bindings->initiator_addrtype >> 24) & 0xFF;
    buf[1] = (bindings->initiator_addrtype >> 16) & 0xFF;
    buf[2] = (bindings->initiator_addrtype >> 8) & 0xFF;
    buf[3] = bindings->initiator_addrtype & 0xFF;
    EVP_DigestUpdate(ctx, buf, 4);

    /* initiator_address length and data */
    buf[0] = (bindings->initiator_address.length >> 24) & 0xFF;
    buf[1] = (bindings->initiator_address.length >> 16) & 0xFF;
    buf[2] = (bindings->initiator_address.length >> 8) & 0xFF;
    buf[3] = bindings->initiator_address.length & 0xFF;
    EVP_DigestUpdate(ctx, buf, 4);
    if (bindings->initiator_address.length > 0)
        EVP_DigestUpdate(ctx, bindings->initiator_address.value,
                         bindings->initiator_address.length);

    /* acceptor_addrtype (network byte order) */
    buf[0] = (bindings->acceptor_addrtype >> 24) & 0xFF;
    buf[1] = (bindings->acceptor_addrtype >> 16) & 0xFF;
    buf[2] = (bindings->acceptor_addrtype >> 8) & 0xFF;
    buf[3] = bindings->acceptor_addrtype & 0xFF;
    EVP_DigestUpdate(ctx, buf, 4);

    /* acceptor_address length and data */
    buf[0] = (bindings->acceptor_address.length >> 24) & 0xFF;
    buf[1] = (bindings->acceptor_address.length >> 16) & 0xFF;
    buf[2] = (bindings->acceptor_address.length >> 8) & 0xFF;
    buf[3] = bindings->acceptor_address.length & 0xFF;
    EVP_DigestUpdate(ctx, buf, 4);
    if (bindings->acceptor_address.length > 0)
        EVP_DigestUpdate(ctx, bindings->acceptor_address.value,
                         bindings->acceptor_address.length);

    /*
     * application_data length and data
     * If a CB type prefix was found, use the adjusted length and data
     * (excluding the prefix). This ensures both sides compute the same
     * hash as long as they use the same CB type prefix convention.
     */
    buf[0] = (app_data_len >> 24) & 0xFF;
    buf[1] = (app_data_len >> 16) & 0xFF;
    buf[2] = (app_data_len >> 8) & 0xFF;
    buf[3] = app_data_len & 0xFF;
    EVP_DigestUpdate(ctx, buf, 4);
    if (app_data_len > 0)
        EVP_DigestUpdate(ctx, app_data_value, app_data_len);

    if (EVP_DigestFinal_ex(ctx, cb_hash_out, &hash_len) != 1 ||
        hash_len != 32) {
        EVP_MD_CTX_free(ctx);
        if (cb_type_out && *cb_type_out) {
            free(*cb_type_out);
            *cb_type_out = NULL;
        }
        *minor = EINVAL;
        return GSS_S_FAILURE;
    }

    EVP_MD_CTX_free(ctx);
    return GSS_S_COMPLETE;
}

/*
 * Base64url decode (no padding required)
 * Returns allocated buffer, caller must free
 */
static uint8_t *
base64url_decode(const char *input, size_t input_len, size_t *out_len)
{
    static const int8_t decode_table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,63,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    size_t olen = (input_len * 3) / 4 + 1;
    uint8_t *output = malloc(olen);
    uint8_t *p = output;
    size_t i;
    int32_t accum = 0;
    int bits = 0;

    if (output == NULL)
        return NULL;

    for (i = 0; i < input_len; i++) {
        int8_t val = decode_table[(unsigned char)input[i]];
        if (val < 0)
            continue; /* Skip invalid chars (including padding '=') */

        accum = (accum << 6) | val;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            *p++ = (accum >> bits) & 0xFF;
        }
    }

    *out_len = p - output;
    return output;
}

/*
 * Check if a JWT contains a channel bindings claim.
 *
 * JWT format: header.payload.signature (each base64url-encoded)
 * We decode the payload and look for a "cb" claim.
 */
OM_uint32
_gss_jwt_check_cb_claim(OM_uint32 *minor,
                        const char *jwt,
                        const uint8_t *expected_hash,
                        size_t hash_len,
                        int *has_cb_out,
                        int *matches_out)
{
    const char *payload_start, *payload_end;
    uint8_t *payload_decoded = NULL;
    size_t payload_len;
    heim_object_t json_obj = NULL;
    heim_object_t cb_value;
    const char *cb_str;
    uint8_t *cb_decoded = NULL;
    size_t cb_decoded_len;

    *minor = 0;
    *has_cb_out = 0;
    if (matches_out)
        *matches_out = 0;

    if (jwt == NULL) {
        *minor = EINVAL;
        return GSS_S_FAILURE;
    }

    /* Find payload section (between first and second '.') */
    payload_start = strchr(jwt, '.');
    if (payload_start == NULL) {
        *minor = EINVAL;
        return GSS_S_DEFECTIVE_TOKEN;
    }
    payload_start++; /* Skip the '.' */

    payload_end = strchr(payload_start, '.');
    if (payload_end == NULL) {
        *minor = EINVAL;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    /* Base64url-decode the payload */
    payload_decoded = base64url_decode(payload_start, payload_end - payload_start,
                                       &payload_len);
    if (payload_decoded == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    /* Parse as JSON */
    json_obj = heim_json_create((char *)payload_decoded, payload_len, 0, NULL);
    free(payload_decoded);

    if (json_obj == NULL || heim_get_tid(json_obj) != HEIM_TID_DICT) {
        if (json_obj)
            heim_release(json_obj);
        *minor = EINVAL;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    /* Look for "cb" claim */
    cb_value = heim_dict_get_value(json_obj, HSTR("cb"));
    if (cb_value == NULL || heim_get_tid(cb_value) != HEIM_TID_STRING) {
        /* No CB claim in JWT */
        heim_release(json_obj);
        *has_cb_out = 0;
        return GSS_S_COMPLETE;
    }

    /* JWT has CB claim */
    *has_cb_out = 1;
    cb_str = heim_string_get_utf8(cb_value);

    /* If no expected hash provided, just report presence */
    if (expected_hash == NULL || hash_len == 0) {
        heim_release(json_obj);
        return GSS_S_COMPLETE;
    }

    /*
     * CB claim format: "<type>:<base64url-hash>" or "<base64url-hash>"
     *
     * If the claim contains a colon, the part before is the CB type
     * (e.g., "tls-server-end-point") and the part after is the hash.
     * The type allows observers to see which channel binding is used.
     */
    {
        const char *colon = strchr(cb_str, ':');
        const char *hash_str;
        size_t hash_str_len;

        if (colon != NULL) {
            /* Format: <type>:<hash> - skip the type prefix */
            hash_str = colon + 1;
            hash_str_len = strlen(hash_str);
        } else {
            /* Format: <hash> - no type prefix */
            hash_str = cb_str;
            hash_str_len = strlen(cb_str);
        }

        cb_decoded = base64url_decode(hash_str, hash_str_len, &cb_decoded_len);
    }

    if (cb_decoded == NULL) {
        heim_release(json_obj);
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    if (cb_decoded_len == hash_len &&
        memcmp(cb_decoded, expected_hash, hash_len) == 0) {
        *matches_out = 1;
    } else {
        *matches_out = 0;
    }

    free(cb_decoded);
    heim_release(json_obj);
    return GSS_S_COMPLETE;
}

/*
 * Build HTTP GET request for metadata-style token endpoint
 *
 * Metadata service style (Kubernetes, AWS IMDS, GCP):
 *   GET /v1/get-token?audience=<audience> HTTP/1.1
 *   Host: sts.example.com
 *
 * Query parameters are appended to the path. If the path already has
 * a query string (contains '?'), parameters are appended with '&'.
 *
 * Channel bindings are not typically supported with GET requests,
 * but we include them as query params if provided for completeness.
 */
static char *
build_get_request(heim_context hctx,
                  const char *host,
                  const char *path,
                  const char *audience,
                  const uint8_t *cb_hash,
                  size_t cb_hash_len,
                  const char *cb_type)
{
    char *request = NULL;
    char *full_path = NULL;
    char *encoded_audience = NULL;
    char *encoded_cb = NULL;
    char *encoded_hash = NULL;
    const char *sep;
    int ret;

    encoded_audience = url_encode(audience);
    if (encoded_audience == NULL)
        return NULL;

    /* Determine query string separator */
    sep = strchr(path, '?') ? "&" : "?";

    /* Encode channel bindings if provided */
    if (cb_hash != NULL && cb_hash_len > 0) {
        encoded_hash = base64url_encode(cb_hash, cb_hash_len);
        if (encoded_hash == NULL) {
            free(encoded_audience);
            return NULL;
        }

        if (cb_type != NULL) {
            ret = asprintf(&encoded_cb, "%s:%s", cb_type, encoded_hash);
            free(encoded_hash);
            if (ret < 0) {
                free(encoded_audience);
                return NULL;
            }
        } else {
            encoded_cb = encoded_hash;
        }
    }

    /* Build full path with query parameters */
    if (encoded_cb) {
        ret = asprintf(&full_path, "%s%saudience=%s&cb=%s",
                       path, sep, encoded_audience, encoded_cb);
    } else {
        ret = asprintf(&full_path, "%s%saudience=%s",
                       path, sep, encoded_audience);
    }

    free(encoded_cb);
    free(encoded_audience);

    if (ret < 0)
        return NULL;

    /* Build HTTP request */
    ret = asprintf(&request,
                   "GET %s HTTP/1.1\r\n"
                   "Host: %s\r\n"
                   "Accept: application/json\r\n"
                   "Connection: close\r\n"
                   "\r\n",
                   full_path, host);

    free(full_path);

    if (ret < 0)
        return NULL;

    heim_debug(hctx, 5, "STS: using GET request for token endpoint");

    return request;
}

/*
 * Build HTTP POST request for token endpoint (OAuth 2.0 style)
 *
 * For password auth (OAuth2 client_credentials):
 *   POST /token HTTP/1.1
 *   Host: sts.example.com
 *   Content-Type: application/x-www-form-urlencoded
 *   Authorization: Basic base64(username:password)
 *
 *   grant_type=client_credentials&audience=<audience>
 *
 * For JWT exchange (token exchange per RFC 8693):
 *   POST /token HTTP/1.1
 *   Host: sts.example.com
 *   Content-Type: application/x-www-form-urlencoded
 *
 *   grant_type=urn:ietf:params:oauth:grant-type:token-exchange&
 *   subject_token=<jwt>&
 *   subject_token_type=urn:ietf:params:oauth:token-type:jwt&
 *   audience=<audience>
 *
 * If channel_bindings_hash is provided, adds:
 *   &cb=<base64url-encoded-hash>
 *
 * The STS should include this in the JWT as a claim (e.g., "cb" or "cnf").
 */
static char *
build_post_request(heim_context hctx,
                   const struct gss_jwt_cred_desc *cred,
                   const char *host,
                   const char *path,
                   const char *audience,
                   const uint8_t *cb_hash,
                   size_t cb_hash_len,
                   const char *cb_type,
                   char **auth_header)
{
    char *request = NULL;
    char *body = NULL;
    char *encoded_audience = NULL;
    char *encoded_cb = NULL;
    char *encoded_hash = NULL;
    int ret;

    *auth_header = NULL;

    encoded_audience = url_encode(audience);
    if (encoded_audience == NULL)
        return NULL;

    /*
     * Encode channel bindings if provided.
     * Format: cb=<type>:<base64url-hash> or cb=<base64url-hash>
     *
     * If cb_type is provided, prefix the hash with the type and colon.
     * This allows the STS to include the type in the JWT claim for
     * observers to see which channel binding type is being used.
     */
    if (cb_hash != NULL && cb_hash_len > 0) {
        encoded_hash = base64url_encode(cb_hash, cb_hash_len);
        if (encoded_hash == NULL) {
            free(encoded_audience);
            return NULL;
        }

        if (cb_type != NULL) {
            ret = asprintf(&encoded_cb, "%s:%s", cb_type, encoded_hash);
            free(encoded_hash);
            if (ret < 0) {
                free(encoded_audience);
                return NULL;
            }
            heim_debug(hctx, 10, "STS: CB type=%s", cb_type);
        } else {
            encoded_cb = encoded_hash;
        }
        heim_debug(hctx, 10, "STS: including channel bindings in request");
    }

    switch (cred->cred_type) {
    case JWT_CRED_PASSWORD:
    case JWT_CRED_AUTO:
        if (cred->username && cred->password) {
            /* OAuth2 client_credentials with Basic auth */
            char *creds;
            char *encoded;

            ret = asprintf(&creds, "%s:%s", cred->username, cred->password);
            if (ret < 0) {
                free(encoded_cb);
                free(encoded_audience);
                return NULL;
            }
            encoded = base64_encode(creds, strlen(creds));
            memset(creds, 0, strlen(creds));
            free(creds);
            if (encoded == NULL) {
                free(encoded_cb);
                free(encoded_audience);
                return NULL;
            }
            ret = asprintf(auth_header, "Authorization: Basic %s\r\n", encoded);
            memset(encoded, 0, strlen(encoded));
            free(encoded);
            if (ret < 0) {
                free(encoded_cb);
                free(encoded_audience);
                return NULL;
            }

            if (encoded_cb) {
                ret = asprintf(&body, "grant_type=client_credentials&audience=%s&cb=%s",
                               encoded_audience, encoded_cb);
            } else {
                ret = asprintf(&body, "grant_type=client_credentials&audience=%s",
                               encoded_audience);
            }
            if (ret < 0) {
                free(*auth_header);
                *auth_header = NULL;
                free(encoded_cb);
                free(encoded_audience);
                return NULL;
            }

            heim_debug(hctx, 5, "STS: using client_credentials grant with Basic auth");
            break;
        }
        /* Fall through to try other methods in auto mode */
        if (cred->cred_type != JWT_CRED_AUTO)
            break;
        /* FALLTHROUGH */

    case JWT_CRED_JWT:
        if (cred->token) {
            /* Token exchange */
            char *encoded_token = url_encode(cred->token);
            if (encoded_token == NULL) {
                free(encoded_cb);
                free(encoded_audience);
                return NULL;
            }

            if (encoded_cb) {
                ret = asprintf(&body,
                               "grant_type=urn%%3Aietf%%3Aparams%%3Aoauth%%3Agrant-type%%3Atoken-exchange&"
                               "subject_token=%s&"
                               "subject_token_type=urn%%3Aietf%%3Aparams%%3Aoauth%%3Atoken-type%%3Ajwt&"
                               "audience=%s&cb=%s",
                               encoded_token, encoded_audience, encoded_cb);
            } else {
                ret = asprintf(&body,
                               "grant_type=urn%%3Aietf%%3Aparams%%3Aoauth%%3Agrant-type%%3Atoken-exchange&"
                               "subject_token=%s&"
                               "subject_token_type=urn%%3Aietf%%3Aparams%%3Aoauth%%3Atoken-type%%3Ajwt&"
                               "audience=%s",
                               encoded_token, encoded_audience);
            }
            free(encoded_token);
            if (ret < 0) {
                free(encoded_cb);
                free(encoded_audience);
                return NULL;
            }

            heim_debug(hctx, 5, "STS: using token_exchange grant");
            break;
        }
        if (cred->cred_type != JWT_CRED_AUTO)
            break;
        /* FALLTHROUGH */

    case JWT_CRED_KERBEROS:
        /* TODO: Implement Negotiate auth - requires multi-round-trip */
        heim_debug(hctx, 1, "STS: Kerberos/Negotiate auth not yet implemented");
        free(encoded_cb);
        free(encoded_audience);
        return NULL;

    case JWT_CRED_CERTIFICATE:
        /* Certificate auth uses mTLS - creds sent in TLS handshake */
        if (encoded_cb) {
            ret = asprintf(&body, "grant_type=client_credentials&audience=%s&cb=%s",
                           encoded_audience, encoded_cb);
        } else {
            ret = asprintf(&body, "grant_type=client_credentials&audience=%s",
                           encoded_audience);
        }
        if (ret < 0) {
            free(encoded_cb);
            free(encoded_audience);
            return NULL;
        }
        heim_debug(hctx, 5, "STS: using client_credentials grant with mTLS");
        break;

    default:
        free(encoded_cb);
        free(encoded_audience);
        return NULL;
    }

    free(encoded_cb);
    free(encoded_audience);

    if (body == NULL)
        return NULL;

    /* Build full HTTP request */
    ret = asprintf(&request,
                   "POST %s HTTP/1.1\r\n"
                   "Host: %s\r\n"
                   "Content-Type: application/x-www-form-urlencoded\r\n"
                   "Content-Length: %zu\r\n"
                   "Connection: close\r\n"
                   "%s"
                   "\r\n"
                   "%s",
                   path, host, strlen(body),
                   *auth_header ? *auth_header : "",
                   body);

    free(body);
    if (ret < 0) {
        free(*auth_header);
        *auth_header = NULL;
        return NULL;
    }

    return request;
}

/*
 * Parse HTTP response to extract JWT
 *
 * Expected response:
 *   HTTP/1.1 200 OK
 *   Content-Type: application/json
 *
 *   {"access_token":"<jwt>","token_type":"Bearer",...}
 */
static int
parse_http_response(heim_context hctx,
                    const char *response,
                    size_t len,
                    char **jwt_out)
{
    const char *p, *body;
    int status;
    const char *access_token_start, *access_token_end;

    *jwt_out = NULL;

    /* Parse status line */
    if (len < 12 || strncmp(response, "HTTP/1.", 7) != 0)
        return EINVAL;

    p = response + 9;  /* Skip "HTTP/1.x " */
    status = atoi(p);

    heim_debug(hctx, 5, "STS: HTTP response status: %d", status);

    if (status != 200) {
        heim_debug(hctx, 1, "STS: token request failed with status %d", status);
        return EACCES;
    }

    /* Find body (after double CRLF) */
    body = strstr(response, "\r\n\r\n");
    if (body == NULL)
        return EINVAL;
    body += 4;

    /* Simple JSON parsing - find access_token field */
    access_token_start = strstr(body, "\"access_token\"");
    if (access_token_start == NULL) {
        heim_debug(hctx, 1, "STS: no access_token in response");
        return EINVAL;
    }

    /* Skip to the value */
    access_token_start = strchr(access_token_start, ':');
    if (access_token_start == NULL)
        return EINVAL;
    access_token_start++;

    /* Skip whitespace */
    while (*access_token_start == ' ' || *access_token_start == '\t')
        access_token_start++;

    /* Expect quoted string */
    if (*access_token_start != '"')
        return EINVAL;
    access_token_start++;

    /* Find end quote */
    access_token_end = access_token_start;
    while (*access_token_end && *access_token_end != '"') {
        if (*access_token_end == '\\' && access_token_end[1])
            access_token_end++;  /* Skip escaped char */
        access_token_end++;
    }

    if (*access_token_end != '"')
        return EINVAL;

    /* Extract token */
    len = access_token_end - access_token_start;
    *jwt_out = malloc(len + 1);
    if (*jwt_out == NULL)
        return ENOMEM;
    memcpy(*jwt_out, access_token_start, len);
    (*jwt_out)[len] = '\0';

    heim_debug(hctx, 5, "STS: extracted JWT (%zu bytes)", len);

    return 0;
}

/*
 * Acquire JWT from STS using configured credentials
 *
 * This function either:
 * - Returns a pre-configured direct token (for testing without STS)
 * - Or contacts the STS to obtain a JWT:
 *   1. Parses the STS endpoint URL
 *   2. Connects to the STS server
 *   3. Performs TLS handshake using GSS-TLS
 *   4. Sends OAuth2 token request over HTTP/1.1
 *   5. Parses response to extract JWT
 *
 * If channel bindings are provided (cb_hash/cb_hash_len), they are
 * passed to the STS which should include them in a JWT claim (e.g., "cb").
 * The acceptor can then verify the channel bindings by checking this claim.
 *
 * If cb_type is provided, it is included as a prefix in the CB value
 * (e.g., "tls-server-end-point:<hash>") so the STS can include it in the
 * JWT claim for observers to see which channel binding type is used.
 */
OM_uint32
_gss_jwt_acquire_token(OM_uint32 *minor,
                       const struct gss_jwt_cred_desc *cred,
                       const char *audience,
                       const uint8_t *cb_hash,
                       size_t cb_hash_len,
                       const char *cb_type,
                       char **jwt_out)
{
    OM_uint32 major, tmp_minor;
    parsed_url url;
    int fd = -1;
    gss_cred_id_t tls_cred = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t tls_ctx = GSS_C_NO_CONTEXT;
    char *request = NULL;
    char *auth_header = NULL;
    char *response = NULL;
    size_t response_len = 0;
    int ret;

    *minor = 0;
    *jwt_out = NULL;

    heim_debug(cred->hctx, 5, "STS: acquiring JWT for audience: %s", audience);

    /*
     * If no STS endpoint is configured but we have a direct token,
     * return that token directly. This is useful for testing without
     * a real STS, or when the JWT is pre-obtained by other means.
     */
    if (cred->sts_endpoint == NULL && cred->token != NULL) {
        heim_debug(cred->hctx, 5, "STS: using direct token (no STS endpoint)");
        *jwt_out = strdup(cred->token);
        if (*jwt_out == NULL) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }
        return GSS_S_COMPLETE;
    }

    if (cred->sts_endpoint == NULL) {
        heim_debug(cred->hctx, 1, "STS: no STS endpoint configured");
        *minor = EINVAL;
        return GSS_S_FAILURE;
    }

    /* Parse STS endpoint URL */
    ret = parse_url(cred->sts_endpoint, &url);
    if (ret) {
        heim_debug(cred->hctx, 1, "STS: failed to parse URL: %s",
                   cred->sts_endpoint);
        *minor = ret;
        return GSS_S_FAILURE;
    }

    heim_debug(cred->hctx, 5, "STS: endpoint host=%s port=%s path=%s",
               url.host, url.port, url.path);

    /* Connect to STS */
    fd = connect_to_host(cred->hctx, url.host, url.port);
    if (fd < 0) {
        *minor = errno;
        free_parsed_url(&url);
        return GSS_S_FAILURE;
    }

    /* Acquire GSS-TLS credential for the connection */
    {
        gss_key_value_set_desc cred_store;
        gss_key_value_element_desc elements[2];
        size_t count = 0;

        /* If we have trust anchors, pass them to GSS-TLS */
        if (cred->trust_anchors) {
            /* TODO: Pass trust anchors to GSS-TLS credential
             * For now, use default trust store */
        }

        /* For certificate auth, pass client cert to GSS-TLS */
        if (cred->cred_type == JWT_CRED_CERTIFICATE &&
            cred->client_certs && cred->client_key) {
            /* TODO: Pass client cert/key to GSS-TLS credential */
        }

        cred_store.count = count;
        cred_store.elements = elements;

        /* Acquire anonymous TLS credential (server validates us via HTTP auth) */
        elements[count].key = "anonymous";
        elements[count].value = "true";
        count++;
        cred_store.count = count;

        major = gss_acquire_cred_from(minor,
                                      GSS_C_NO_NAME,
                                      GSS_C_INDEFINITE,
                                      GSS_C_NO_OID_SET,
                                      GSS_C_INITIATE,
                                      &cred_store,
                                      &tls_cred,
                                      NULL,
                                      NULL);
        if (major != GSS_S_COMPLETE) {
            heim_debug(cred->hctx, 1, "STS: failed to acquire TLS credential");
            close(fd);
            free_parsed_url(&url);
            return major;
        }
    }

    /* Perform TLS handshake */
    major = do_tls_handshake(minor, cred->hctx, fd, url.host, tls_cred, &tls_ctx);
    if (major != GSS_S_COMPLETE) {
        heim_debug(cred->hctx, 1, "STS: TLS handshake failed");
        gss_release_cred(&tmp_minor, &tls_cred);
        close(fd);
        free_parsed_url(&url);
        return major;
    }

    /*
     * Build and send HTTP request based on configured STS method.
     *
     * AUTO mode: Try GET first (metadata service style), fall back to POST
     *            if GET fails with a method-related error (405 Method Not Allowed).
     * GET mode:  GET request only (for metadata services like K8s, AWS, GCP).
     * POST mode: POST request only (OAuth 2.0 token exchange, RFC 8693).
     */
    {
        jwt_sts_method method = cred->sts_method;
        int try_post = 0;

try_request:
        if (method == JWT_STS_METHOD_GET ||
            (method == JWT_STS_METHOD_AUTO && !try_post)) {
            /* Try GET request */
            request = build_get_request(cred->hctx, url.host, url.path,
                                        audience, cb_hash, cb_hash_len, cb_type);
        } else {
            /* Use POST request */
            request = build_post_request(cred->hctx, cred, url.host, url.path,
                                         audience, cb_hash, cb_hash_len, cb_type,
                                         &auth_header);
        }

        if (request == NULL) {
            heim_debug(cred->hctx, 1, "STS: failed to build HTTP request");
            *minor = ENOMEM;
            major = GSS_S_FAILURE;
            goto cleanup;
        }

        heim_debug(cred->hctx, 10, "STS: sending HTTP request (%zu bytes)",
                   strlen(request));

        /* Send HTTP request over TLS */
        major = tls_send(minor, cred->hctx, fd, tls_ctx, request, strlen(request));
        if (major != GSS_S_COMPLETE) {
            heim_debug(cred->hctx, 1, "STS: failed to send HTTP request");
            goto cleanup;
        }

        /* Receive HTTP response */
        major = tls_recv(minor, cred->hctx, fd, tls_ctx, &response, &response_len);
        if (major != GSS_S_COMPLETE) {
            heim_debug(cred->hctx, 1, "STS: failed to receive HTTP response");
            goto cleanup;
        }

        heim_debug(cred->hctx, 10, "STS: received HTTP response (%zu bytes)",
                   response_len);

        /* Parse response and extract JWT */
        ret = parse_http_response(cred->hctx, response, response_len, jwt_out);

        /*
         * In AUTO mode, if GET failed with a method-not-allowed style error
         * (EACCES from a 405 response), try POST instead.
         */
        if (ret != 0 && method == JWT_STS_METHOD_AUTO && !try_post) {
            /* Check if response indicates method not allowed (HTTP 405) */
            if (response != NULL && strstr(response, "405") != NULL) {
                heim_debug(cred->hctx, 5, "STS: GET failed with 405, trying POST");

                /* Clean up for retry */
                memset(request, 0, strlen(request));
                free(request);
                request = NULL;
                free(response);
                response = NULL;
                response_len = 0;

                /*
                 * Need to reconnect for POST since we already consumed
                 * the response from the GET request.
                 */
                gss_delete_sec_context(&tmp_minor, &tls_ctx, NULL);
                tls_ctx = GSS_C_NO_CONTEXT;
                close(fd);

                fd = connect_to_host(cred->hctx, url.host, url.port);
                if (fd < 0) {
                    *minor = errno;
                    major = GSS_S_FAILURE;
                    goto cleanup;
                }

                major = do_tls_handshake(minor, cred->hctx, fd, url.host,
                                         tls_cred, &tls_ctx);
                if (major != GSS_S_COMPLETE) {
                    heim_debug(cred->hctx, 1, "STS: TLS reconnect failed");
                    goto cleanup;
                }

                try_post = 1;
                goto try_request;
            }
        }

        if (ret) {
            heim_debug(cred->hctx, 1, "STS: failed to parse HTTP response");
            *minor = ret;
            major = GSS_S_FAILURE;
            goto cleanup;
        }
    }

    heim_debug(cred->hctx, 5, "STS: successfully acquired JWT");
    major = GSS_S_COMPLETE;

cleanup:
    /* Clear sensitive data */
    if (request) {
        memset(request, 0, strlen(request));
        free(request);
    }
    if (auth_header) {
        memset(auth_header, 0, strlen(auth_header));
        free(auth_header);
    }
    free(response);

    /* Clean up TLS context */
    if (tls_ctx != GSS_C_NO_CONTEXT)
        gss_delete_sec_context(&tmp_minor, &tls_ctx, NULL);
    if (tls_cred != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&tmp_minor, &tls_cred);

    close(fd);
    free_parsed_url(&url);

    return major;
}
