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
 * gss - GSS-API client/server tool
 *
 * A generic GSS-API client and server for testing mechanisms.
 * Exchanges GSS tokens over TCP with length-prefix framing.
 * Works with any GSS mechanism (Kerberos, TLS, SAnon, etc.)
 *
 * Usage:
 *   gss -c hostname:port [options]   # client mode
 *   gss -s port [options]            # server mode
 */

#include <config.h>
#include <roken.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <poll.h>

#include <gssapi/gssapi.h>
#include <getarg.h>
#include <err.h>
#include <vers.h>

/* Command line options */
static int client_mode = 0;
static int server_mode = 0;
static char *mechanism_name = NULL;
static char *certificate_store = NULL;
static char *private_key_store = NULL;
static char *trust_anchors = NULL;
static char *revocation_store = NULL;
static char *connect_to_addr = NULL;  /* --connect-to: actual address to connect to */
static int anonymous_client = 0;
static int require_client_cert = 0;
static int verbose = 0;
static int help_flag = 0;
static int version_flag = 0;

static struct getargs args[] = {
    { "client", 'c', arg_flag, &client_mode,
      "Run in client mode", NULL },
    { "server", 's', arg_flag, &server_mode,
      "Run in server mode", NULL },
    { "mechanism", 'm', arg_string, &mechanism_name,
      "GSS mechanism (krb5, spnego, sanon, tls, or OID)", "MECH" },
    { "certificate", 'C', arg_string, &certificate_store,
      "Certificate store URI for TLS (e.g., FILE:cert.pem)", "URI" },
    { "private-key", 'K', arg_string, &private_key_store,
      "Private key store URI for TLS (e.g., FILE:key.pem)", "URI" },
    { "anchors", 'A', arg_string, &trust_anchors,
      "Trust anchor store URI for TLS peer validation", "URI" },
    { "revoke", 'R', arg_string, &revocation_store,
      "Revocation info store URI for TLS (CRL)", "URI" },
    { "connect-to", 'T', arg_string, &connect_to_addr,
      "Connect to HOST:PORT instead of target (for SNI/name testing)", "HOST:PORT" },
    { "anonymous", 'a', arg_flag, &anonymous_client,
      "Use anonymous mode (no client certificate for TLS)", NULL },
    { "require-client-cert", 'r', arg_flag, &require_client_cert,
      "Require client certificate (TLS server mode)", NULL },
    { "verbose", 'v', arg_flag, &verbose,
      "Verbose output", NULL },
    { "help", 'h', arg_flag, &help_flag,
      "Print help", NULL },
    { "version", 0, arg_flag, &version_flag,
      "Print version", NULL },
};

static int num_args = sizeof(args) / sizeof(args[0]);

/* Selected mechanism OID */
static gss_OID selected_mech = GSS_C_NO_OID;

static void
usage(int exit_code)
{
    arg_printusage(args, num_args, NULL,
                   "[-c | -s] [-m mech] [options] host:port | port");
    fprintf(stderr, "\nMechanisms:\n");
    fprintf(stderr, "  krb5, spnego, sanon, tls, or OID (e.g., 1.2.840.113554.1.2.2)\n");
    fprintf(stderr, "  Use -m '?' to list available mechanisms\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  Kerberos client:\n");
    fprintf(stderr, "    gss -c -m krb5 host/server.example.com@REALM:8080\n");
    fprintf(stderr, "\n  TLS client with trust anchors (anonymous):\n");
    fprintf(stderr, "    gss -c -m tls -A FILE:/path/to/ca.pem localhost:4433\n");
    fprintf(stderr, "\n  TLS client with certificate:\n");
    fprintf(stderr, "    gss -c -m tls -C FILE:client.pem -K FILE:client-key.pem \\\n");
    fprintf(stderr, "        -A FILE:ca.pem localhost:4433\n");
    fprintf(stderr, "\n  TLS server:\n");
    fprintf(stderr, "    gss -s -m tls -C FILE:server.pem -K FILE:server-key.pem 4433\n");
    fprintf(stderr, "\n  TLS client with --connect-to (connect to 127.0.0.1 but use server.example.com for SNI):\n");
    fprintf(stderr, "    gss -c -m tls -A FILE:ca.pem -T 127.0.0.1:4433 server.example.com:4433\n");
    fprintf(stderr, "\n  SAnon client:\n");
    fprintf(stderr, "    gss -c -m sanon localhost:8080\n");
    exit(exit_code);
}

/*
 * List available GSS mechanisms
 */
static void
list_mechanisms(void)
{
    OM_uint32 maj, min;
    gss_OID_set mechs;
    size_t i;

    maj = gss_indicate_mechs(&min, &mechs);
    if (GSS_ERROR(maj)) {
        fprintf(stderr, "gss_indicate_mechs failed\n");
        exit(1);
    }

    fprintf(stderr, "Available mechanisms:\n");
    for (i = 0; i < mechs->count; i++) {
        gss_buffer_desc name;
        gss_OID oid = &mechs->elements[i];

        maj = gss_oid_to_str(&min, oid, &name);
        if (!GSS_ERROR(maj)) {
            fprintf(stderr, "  %.*s\n", (int)name.length, (char *)name.value);
            gss_release_buffer(&min, &name);
        }
    }

    gss_release_oid_set(&min, &mechs);
    exit(0);
}

/*
 * TLS mechanism OID (not yet registered with gss_name_to_oid)
 * OID: 1.3.6.1.4.1.40402.1.1 (PEN 40402, arc 1 = heimdal)
 */
static gss_OID_desc tls_mech_oid = {
    10, rk_UNCONST("\x2b\x06\x01\x04\x01\x82\xbb\x52\x01\x01")
};

/*
 * Mechanism attribute: self-framed tokens
 * OID: 1.3.6.1.4.1.40402.1.2
 *
 * Mechanisms with this attribute have tokens that are self-delimiting -
 * all tokens include embedded length information, so no external framing
 * (like length-prefix) is needed.
 */
static gss_OID_desc gss_c_ma_self_framed_oid = {
    10, rk_UNCONST("\x2b\x06\x01\x04\x01\x82\xbb\x52\x01\x02")
};

/*
 * Parse mechanism name or OID string
 *
 * Uses gss_name_to_oid() which accepts:
 * - Short names like "krb5", "spnego", "sanon"
 * - OID strings like "1.2.840.113554.1.2.2"
 */
static gss_OID
parse_mechanism(const char *name)
{
    gss_OID oid;

    if (name == NULL)
        return GSS_C_NO_OID;

    /* Check for "?" to list mechanisms */
    if (strcmp(name, "?") == 0)
        list_mechanisms();

    /* Special case: "tls" is our new mechanism */
    if (strcasecmp(name, "tls") == 0)
        return &tls_mech_oid;

    /* Use gss_name_to_oid for everything else */
    oid = gss_name_to_oid(name);
    if (oid != GSS_C_NO_OID)
        return oid;

    fprintf(stderr, "Unknown mechanism: %s\n", name);
    fprintf(stderr, "Use -m '?' to list available mechanisms\n");
    exit(1);
}

/*
 * Check if selected mechanism is the TLS mechanism
 */
static int
is_tls_mechanism(void)
{
    if (selected_mech == NULL)
        return 0;
    return (selected_mech->length == tls_mech_oid.length &&
            memcmp(selected_mech->elements, tls_mech_oid.elements,
                   tls_mech_oid.length) == 0);
}

/*
 * Check if mechanism has the self-framed attribute
 *
 * Self-framed mechanisms have tokens that include embedded length
 * information, so they don't need external length-prefix framing.
 */
static int
is_self_framed_mechanism(void)
{
    OM_uint32 maj, min;
    gss_OID_set attrs = GSS_C_NO_OID_SET;
    int self_framed = 0;
    size_t i;

    if (selected_mech == NULL)
        return 0;

    maj = gss_inquire_attrs_for_mech(&min, selected_mech, &attrs, NULL);
    if (GSS_ERROR(maj) || attrs == GSS_C_NO_OID_SET)
        return 0;

    for (i = 0; i < attrs->count; i++) {
        if (attrs->elements[i].length == gss_c_ma_self_framed_oid.length &&
            memcmp(attrs->elements[i].elements, gss_c_ma_self_framed_oid.elements,
                   gss_c_ma_self_framed_oid.length) == 0) {
            self_framed = 1;
            break;
        }
    }

    gss_release_oid_set(&min, &attrs);
    return self_framed;
}

static void
gss_print_errors(const char *msg, OM_uint32 maj, OM_uint32 min)
{
    OM_uint32 disp_maj, disp_min;
    OM_uint32 msg_ctx = 0;
    gss_buffer_desc status_string;

    fprintf(stderr, "%s: ", msg);

    /* Display major status */
    do {
        disp_maj = gss_display_status(&disp_min, maj, GSS_C_GSS_CODE,
                                      GSS_C_NO_OID, &msg_ctx, &status_string);
        if (GSS_ERROR(disp_maj))
            break;
        fprintf(stderr, "%.*s", (int)status_string.length,
                (char *)status_string.value);
        gss_release_buffer(&disp_min, &status_string);
        if (msg_ctx)
            fprintf(stderr, "; ");
    } while (msg_ctx);

    /* Display minor status */
    if (min) {
        msg_ctx = 0;
        fprintf(stderr, " (");
        do {
            disp_maj = gss_display_status(&disp_min, min, GSS_C_MECH_CODE,
                                          selected_mech, &msg_ctx, &status_string);
            if (GSS_ERROR(disp_maj))
                break;
            fprintf(stderr, "%.*s", (int)status_string.length,
                    (char *)status_string.value);
            gss_release_buffer(&disp_min, &status_string);
            if (msg_ctx)
                fprintf(stderr, "; ");
        } while (msg_ctx);
        fprintf(stderr, ")");
    }

    fprintf(stderr, "\n");
}

/*
 * Build credential store key-value set from command line options
 */
static OM_uint32
build_cred_store(OM_uint32 *minor, gss_key_value_set_desc *store,
                 gss_cred_usage_t usage)
{
    gss_key_value_element_desc *elements = NULL;
    size_t count = 0;
    size_t i = 0;

    /* Count how many elements we need */
    if (certificate_store) count++;
    if (private_key_store) count++;
    if (trust_anchors) count++;
    if (revocation_store) count++;
    if (anonymous_client && usage == GSS_C_INITIATE) count++;
    if (require_client_cert && usage == GSS_C_ACCEPT) count++;

    if (count == 0) {
        store->count = 0;
        store->elements = NULL;
        return GSS_S_COMPLETE;
    }

    elements = calloc(count, sizeof(*elements));
    if (elements == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    if (certificate_store) {
        elements[i].key = "certificate";
        elements[i].value = certificate_store;
        i++;
    }

    if (private_key_store) {
        elements[i].key = "private-key";
        elements[i].value = private_key_store;
        i++;
    }

    if (trust_anchors) {
        elements[i].key = "anchors";
        elements[i].value = trust_anchors;
        i++;
    }

    if (revocation_store) {
        elements[i].key = "revoke";
        elements[i].value = revocation_store;
        i++;
    }

    if (anonymous_client && usage == GSS_C_INITIATE) {
        elements[i].key = "anonymous";
        elements[i].value = "true";
        i++;
    }

    if (require_client_cert && usage == GSS_C_ACCEPT) {
        elements[i].key = "require-client-cert";
        elements[i].value = "true";
        i++;
    }

    store->count = count;
    store->elements = elements;
    return GSS_S_COMPLETE;
}

static void
free_cred_store(gss_key_value_set_desc *store)
{
    free(store->elements);
    store->elements = NULL;
    store->count = 0;
}

/*
 * Connect to server (client mode)
 */
static int
connect_to_server(const char *hostport)
{
    struct addrinfo hints, *res, *res0;
    char *host, *port;
    char *copy;
    int fd = -1;
    int error;

    copy = strdup(hostport);
    if (copy == NULL)
        err(1, "strdup");

    /* Parse host:port */
    port = strrchr(copy, ':');
    if (port == NULL) {
        fprintf(stderr, "Invalid address format, expected host:port\n");
        free(copy);
        return -1;
    }
    *port++ = '\0';
    host = copy;

    /* Handle [IPv6]:port format */
    if (host[0] == '[') {
        host++;
        char *bracket = strchr(host, ']');
        if (bracket)
            *bracket = '\0';
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    error = getaddrinfo(host, port, &hints, &res0);
    if (error) {
        fprintf(stderr, "getaddrinfo(%s, %s): %s\n", host, port,
                gai_strerror(error));
        free(copy);
        return -1;
    }

    for (res = res0; res; res = res->ai_next) {
        fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd < 0)
            continue;

        if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
            close(fd);
            fd = -1;
            continue;
        }

        break; /* Success */
    }

    freeaddrinfo(res0);
    free(copy);

    if (fd < 0)
        fprintf(stderr, "Failed to connect to %s\n", hostport);

    return fd;
}

/*
 * Create listening socket (server mode)
 */
static int
create_listener(const char *port)
{
    struct addrinfo hints, *res, *res0;
    int fd = -1;
    int error;
    int on = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    error = getaddrinfo(NULL, port, &hints, &res0);
    if (error) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
        return -1;
    }

    for (res = res0; res; res = res->ai_next) {
        fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd < 0)
            continue;

        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

        if (bind(fd, res->ai_addr, res->ai_addrlen) < 0) {
            close(fd);
            fd = -1;
            continue;
        }

        if (listen(fd, 5) < 0) {
            close(fd);
            fd = -1;
            continue;
        }

        break; /* Success */
    }

    freeaddrinfo(res0);

    if (fd < 0)
        fprintf(stderr, "Failed to create listener on port %s\n", port);

    return fd;
}

/*
 * Send a GSS token over the socket
 *
 * For non-self-framed mechanisms: 4-byte big-endian length prefix, then token data
 * For self-framed mechanisms (TLS): raw token data (TLS records are self-delimiting)
 */
static int
send_token(int fd, gss_buffer_t token)
{
    ssize_t n;

    if (token->length == 0)
        return 0;

    /* For non-self-framed mechanisms, prepend 4-byte length */
    if (!is_self_framed_mechanism()) {
        uint32_t len = (uint32_t)token->length;
        uint8_t lenbuf[4];

        lenbuf[0] = (len >> 24) & 0xff;
        lenbuf[1] = (len >> 16) & 0xff;
        lenbuf[2] = (len >> 8) & 0xff;
        lenbuf[3] = len & 0xff;

        n = write(fd, lenbuf, 4);
        if (n != 4) {
            fprintf(stderr, "Failed to send token length\n");
            return -1;
        }
    }

    n = write(fd, token->value, token->length);
    if (n != (ssize_t)token->length) {
        fprintf(stderr, "Failed to send token data\n");
        return -1;
    }

    if (verbose)
        fprintf(stderr, "Sent %zu bytes\n", token->length);

    return 0;
}

/*
 * Receive a GSS token from the socket
 *
 * For non-self-framed mechanisms: read 4-byte big-endian length prefix, then token data
 * For self-framed mechanisms (TLS): read TLS record header (5 bytes), then payload
 *
 * TLS record format:
 *   byte 0: content type (20=CCS, 21=alert, 22=handshake, 23=app_data)
 *   bytes 1-2: version (0x0303 for TLS 1.2/1.3)
 *   bytes 3-4: payload length (big-endian)
 *   remaining: payload
 */
static int
recv_token(int fd, gss_buffer_t token)
{
    ssize_t n;

    token->length = 0;
    token->value = NULL;

    if (is_self_framed_mechanism()) {
        /*
         * TLS: read 5-byte record header, then payload
         * Return complete record (header + payload) as the token
         */
        uint8_t header[5];
        size_t payload_len;
        size_t total_len;

        n = read(fd, header, 5);
        if (n == 0)
            return 0; /* EOF */
        if (n != 5) {
            fprintf(stderr, "Failed to receive TLS record header\n");
            return -1;
        }

        /* Extract payload length from header bytes 3-4 (big-endian) */
        payload_len = ((size_t)header[3] << 8) | (size_t)header[4];

        /* TLS record payload max is 16KB + some overhead */
        if (payload_len > 18 * 1024) {
            fprintf(stderr, "TLS record too large: %zu bytes\n", payload_len);
            return -1;
        }

        total_len = 5 + payload_len;
        token->value = malloc(total_len);
        if (token->value == NULL) {
            fprintf(stderr, "Out of memory\n");
            return -1;
        }

        /* Copy header into token */
        memcpy(token->value, header, 5);

        /* Read payload */
        if (payload_len > 0) {
            n = read(fd, (uint8_t *)token->value + 5, payload_len);
            if (n != (ssize_t)payload_len) {
                fprintf(stderr, "Failed to receive TLS record payload\n");
                free(token->value);
                token->value = NULL;
                return -1;
            }
        }

        token->length = total_len;
    } else {
        /*
         * Non-self-framed: read 4-byte length prefix, then token data
         */
        uint8_t lenbuf[4];
        uint32_t len;

        n = read(fd, lenbuf, 4);
        if (n == 0)
            return 0; /* EOF */
        if (n != 4) {
            fprintf(stderr, "Failed to receive token length\n");
            return -1;
        }

        len = ((uint32_t)lenbuf[0] << 24) |
              ((uint32_t)lenbuf[1] << 16) |
              ((uint32_t)lenbuf[2] << 8) |
              (uint32_t)lenbuf[3];

        if (len > 64 * 1024 * 1024) {
            fprintf(stderr, "Token too large: %u bytes\n", len);
            return -1;
        }

        token->value = malloc(len);
        if (token->value == NULL) {
            fprintf(stderr, "Out of memory\n");
            return -1;
        }

        n = read(fd, token->value, len);
        if (n != (ssize_t)len) {
            fprintf(stderr, "Failed to receive token data\n");
            free(token->value);
            token->value = NULL;
            return -1;
        }

        token->length = len;
    }

    if (verbose)
        fprintf(stderr, "Received %zu bytes\n", token->length);

    return 0;
}

/*
 * Run TLS client
 */
static int
run_client(const char *hostport)
{
    OM_uint32 maj, min;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_name_t target_name = GSS_C_NO_NAME;
    gss_buffer_desc in_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc out_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc name_buf;
    gss_key_value_set_desc cred_store;
    gss_OID_set mechs = GSS_C_NO_OID_SET;
    char *hostname;
    char *colon;
    int fd = -1;
    int ret = 1;

    /* Extract hostname for target name */
    hostname = strdup(hostport);
    if (hostname == NULL)
        err(1, "strdup");
    colon = strrchr(hostname, ':');
    if (colon)
        *colon = '\0';
    /* Handle [IPv6] format */
    if (hostname[0] == '[') {
        memmove(hostname, hostname + 1, strlen(hostname));
        char *bracket = strchr(hostname, ']');
        if (bracket)
            *bracket = '\0';
    }

    /* Import target name */
    name_buf.value = hostname;
    name_buf.length = strlen(hostname);
    maj = gss_import_name(&min, &name_buf, GSS_C_NT_HOSTBASED_SERVICE,
                          &target_name);
    if (GSS_ERROR(maj)) {
        gss_print_errors("gss_import_name", maj, min);
        goto out;
    }

    /* Build credential store */
    maj = build_cred_store(&min, &cred_store, GSS_C_INITIATE);
    if (GSS_ERROR(maj)) {
        gss_print_errors("build_cred_store", maj, min);
        goto out;
    }

    /* Acquire credentials */
    maj = gss_create_empty_oid_set(&min, &mechs);
    if (GSS_ERROR(maj)) {
        gss_print_errors("gss_create_empty_oid_set", maj, min);
        goto out;
    }
    maj = gss_add_oid_set_member(&min, selected_mech, &mechs);
    if (GSS_ERROR(maj)) {
        gss_print_errors("gss_add_oid_set_member", maj, min);
        goto out;
    }

    maj = gss_acquire_cred_from(&min, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                                mechs, GSS_C_INITIATE, &cred_store,
                                &cred, NULL, NULL);
    if (GSS_ERROR(maj)) {
        gss_print_errors("gss_acquire_cred_from", maj, min);
        goto out;
    }

    if (verbose)
        fprintf(stderr, "Credentials acquired\n");

    /* Connect to server (use --connect-to address if specified) */
    {
        const char *addr = connect_to_addr ? connect_to_addr : hostport;
        fd = connect_to_server(addr);
        if (fd < 0)
            goto out;

        if (verbose) {
            if (connect_to_addr)
                fprintf(stderr, "Connected to %s (target name: %s)\n",
                        connect_to_addr, hostname);
            else
                fprintf(stderr, "Connected to %s\n", hostport);
        }
    }

    /* GSS handshake loop */
    do {
        maj = gss_init_sec_context(&min, cred, &ctx, target_name,
                                   selected_mech, 0, GSS_C_INDEFINITE,
                                   GSS_C_NO_CHANNEL_BINDINGS,
                                   &in_token, NULL, &out_token,
                                   NULL, NULL);

        if (in_token.value) {
            free(in_token.value);
            in_token.value = NULL;
            in_token.length = 0;
        }

        if (GSS_ERROR(maj)) {
            gss_print_errors("gss_init_sec_context", maj, min);
            goto out;
        }

        /* Send output token if any */
        if (out_token.length > 0) {
            if (send_token(fd, &out_token) < 0)
                goto out;
            gss_release_buffer(&min, &out_token);
        }

        /* Receive input token if more needed */
        if (maj == GSS_S_CONTINUE_NEEDED) {
            if (recv_token(fd, &in_token) < 0)
                goto out;
            if (in_token.length == 0) {
                fprintf(stderr, "Unexpected EOF during handshake\n");
                goto out;
            }
        }
    } while (maj == GSS_S_CONTINUE_NEEDED);

    fprintf(stderr, "GSS handshake complete!\n");

    /* Display peer identity */
    {
        gss_name_t peer_name = GSS_C_NO_NAME;
        gss_buffer_desc peer_name_buf;
        OM_uint32 flags;

        maj = gss_inquire_context(&min, ctx, NULL, &peer_name,
                                  NULL, NULL, &flags, NULL, NULL);
        if (!GSS_ERROR(maj) && peer_name != GSS_C_NO_NAME) {
            maj = gss_display_name(&min, peer_name, &peer_name_buf, NULL);
            if (!GSS_ERROR(maj)) {
                fprintf(stderr, "Peer: %.*s\n",
                        (int)peer_name_buf.length, (char *)peer_name_buf.value);
                gss_release_buffer(&min, &peer_name_buf);
            }
            gss_release_name(&min, &peer_name);
        }
        fprintf(stderr, "Flags: 0x%x\n", flags);
    }

    /* Interactive mode: relay stdin/stdout through TLS */
    fprintf(stderr, "Enter text to send (Ctrl-D to quit):\n");
    {
        struct pollfd fds[2];
        char buf[4096];

        fds[0].fd = STDIN_FILENO;
        fds[0].events = POLLIN;
        fds[1].fd = fd;
        fds[1].events = POLLIN;

        for (;;) {
            int n = poll(fds, 2, -1);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }

            /* Data from stdin -> wrap and send */
            if (fds[0].revents & POLLIN) {
                ssize_t len = read(STDIN_FILENO, buf, sizeof(buf));
                if (len <= 0)
                    break;

                gss_buffer_desc msg = { .length = len, .value = buf };
                gss_buffer_desc wrapped;
                int conf_state;

                maj = gss_wrap(&min, ctx, 1, GSS_C_QOP_DEFAULT,
                               &msg, &conf_state, &wrapped);
                if (GSS_ERROR(maj)) {
                    gss_print_errors("gss_wrap", maj, min);
                    break;
                }

                if (send_token(fd, &wrapped) < 0) {
                    gss_release_buffer(&min, &wrapped);
                    break;
                }
                gss_release_buffer(&min, &wrapped);
            }

            /* Data from socket -> unwrap and print */
            if (fds[1].revents & POLLIN) {
                gss_buffer_desc wrapped, unwrapped;
                int conf_state;

                if (recv_token(fd, &wrapped) < 0 || wrapped.length == 0)
                    break;

                maj = gss_unwrap(&min, ctx, &wrapped, &unwrapped,
                                 &conf_state, NULL);
                free(wrapped.value);

                if (GSS_ERROR(maj)) {
                    gss_print_errors("gss_unwrap", maj, min);
                    break;
                }

                write(STDOUT_FILENO, unwrapped.value, unwrapped.length);
                gss_release_buffer(&min, &unwrapped);
            }

            if (fds[0].revents & (POLLHUP | POLLERR) ||
                fds[1].revents & (POLLHUP | POLLERR))
                break;
        }
    }

    ret = 0;

out:
    if (in_token.value)
        free(in_token.value);
    gss_release_buffer(&min, &out_token);
    if (ctx != GSS_C_NO_CONTEXT)
        gss_delete_sec_context(&min, &ctx, NULL);
    if (cred != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&min, &cred);
    if (target_name != GSS_C_NO_NAME)
        gss_release_name(&min, &target_name);
    if (mechs != GSS_C_NO_OID_SET)
        gss_release_oid_set(&min, &mechs);
    free_cred_store(&cred_store);
    free(hostname);
    if (fd >= 0)
        close(fd);
    return ret;
}

/*
 * Run TLS server
 *
 * TODO: Add command execution mode (like CGI/stunnel)
 *
 * When a command is specified (e.g., gss -s -m tls [...] 4433 -- /path/to/handler args...):
 *   1. After successful handshake, execute the command using lib/roken's
 *      simple_execve() or simple_execvp() API (portable to Windows!)
 *   2. Set environment variables with connection metadata:
 *      - GSS_CLIENT_NAME       - Display name of authenticated client
 *      - GSS_CLIENT_DN         - X.509 Subject DN (for TLS)
 *      - GSS_CLIENT_SANS       - Comma-separated list of SANs (for TLS)
 *      - GSS_CLIENT_CERT_DER   - Path to temp file with DER-encoded certificate
 *      - GSS_CLIENT_CERT_PEM   - Path to temp file with PEM-encoded certificate
 *      - GSS_CLIENT_CERT_JSON  - Path to temp file with certificate as JSON
 *      - GSS_MECH_OID          - Mechanism OID used
 *      - GSS_TLS_CIPHER        - TLS cipher suite negotiated
 *      - GSS_TLS_VERSION       - TLS version (TLSv1.2, TLSv1.3)
 *      - GSS_TLS_ALPN          - Negotiated ALPN protocol (if any)
 *      - GSS_CONF_STATE        - "1" if confidentiality is available
 *      - GSS_INTEG_STATE       - "1" if integrity is available
 *   3. Connect stdin/stdout of command to the unwrapped data stream
 *   4. Data from client -> unwrap -> command stdin
 *      Command stdout -> wrap -> send to client
 *
 * When no command is given (current behavior or new header mode):
 *   Option A (current): Echo mode - just echo back wrapped data
 *   Option B (new): Header mode - output metadata header, then sentinel, then client data
 *      Header format (one KEY=VALUE per line):
 *        GSS_CLIENT_NAME=...
 *        GSS_CLIENT_DN=...
 *        ...
 *        ---BEGIN DATA---
 *        <unwrapped client data follows>
 *
 * Additional options needed:
 *   --exec / -e              Enable command execution mode
 *   --header-mode            Output header + sentinel + data instead of echo
 *   --sentinel STRING        Custom sentinel (default: "---BEGIN DATA---")
 *   --cert-dir PATH          Directory for temp certificate files
 */
static int
run_server(const char *port)
{
    OM_uint32 maj, min;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_key_value_set_desc cred_store;
    gss_OID_set mechs = GSS_C_NO_OID_SET;
    int listener = -1;
    int ret = 1;

    /* Build credential store */
    maj = build_cred_store(&min, &cred_store, GSS_C_ACCEPT);
    if (GSS_ERROR(maj)) {
        gss_print_errors("build_cred_store", maj, min);
        goto out;
    }

    /* Acquire credentials */
    maj = gss_create_empty_oid_set(&min, &mechs);
    if (GSS_ERROR(maj)) {
        gss_print_errors("gss_create_empty_oid_set", maj, min);
        goto out;
    }
    maj = gss_add_oid_set_member(&min, selected_mech, &mechs);
    if (GSS_ERROR(maj)) {
        gss_print_errors("gss_add_oid_set_member", maj, min);
        goto out;
    }

    maj = gss_acquire_cred_from(&min, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                                mechs, GSS_C_ACCEPT, &cred_store,
                                &cred, NULL, NULL);
    if (GSS_ERROR(maj)) {
        gss_print_errors("gss_acquire_cred_from", maj, min);
        goto out;
    }

    if (verbose)
        fprintf(stderr, "Server credentials acquired\n");

    /* Create listener */
    listener = create_listener(port);
    if (listener < 0)
        goto out;

    fprintf(stderr, "Listening on port %s...\n", port);

    /* Accept one connection */
    {
        gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
        gss_buffer_desc in_token = GSS_C_EMPTY_BUFFER;
        gss_buffer_desc out_token = GSS_C_EMPTY_BUFFER;
        gss_name_t client_name = GSS_C_NO_NAME;
        int client_fd;
        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof(addr);

        client_fd = accept(listener, (struct sockaddr *)&addr, &addrlen);
        if (client_fd < 0) {
            perror("accept");
            goto out;
        }

        fprintf(stderr, "Client connected\n");

        /* GSS handshake loop */
        do {
            /* Receive input token */
            if (recv_token(client_fd, &in_token) < 0) {
                close(client_fd);
                goto out;
            }
            if (in_token.length == 0) {
                fprintf(stderr, "Unexpected EOF during handshake\n");
                close(client_fd);
                goto out;
            }

            maj = gss_accept_sec_context(&min, &ctx, cred, &in_token,
                                         GSS_C_NO_CHANNEL_BINDINGS,
                                         &client_name, NULL, &out_token,
                                         NULL, NULL, NULL);

            free(in_token.value);
            in_token.value = NULL;
            in_token.length = 0;

            if (GSS_ERROR(maj)) {
                gss_print_errors("gss_accept_sec_context", maj, min);
                close(client_fd);
                goto out;
            }

            /* Send output token if any */
            if (out_token.length > 0) {
                if (send_token(client_fd, &out_token) < 0) {
                    gss_release_buffer(&min, &out_token);
                    close(client_fd);
                    goto out;
                }
                gss_release_buffer(&min, &out_token);
            }
        } while (maj == GSS_S_CONTINUE_NEEDED);

        fprintf(stderr, "GSS handshake complete!\n");

        /* Display client identity */
        if (client_name != GSS_C_NO_NAME) {
            gss_buffer_desc name_buf;
            maj = gss_display_name(&min, client_name, &name_buf, NULL);
            if (!GSS_ERROR(maj)) {
                fprintf(stderr, "Client: %.*s\n",
                        (int)name_buf.length, (char *)name_buf.value);
                gss_release_buffer(&min, &name_buf);
            }
            gss_release_name(&min, &client_name);
        }

        /* Echo mode: relay data back */
        fprintf(stderr, "Echoing data (Ctrl-C to quit)...\n");
        for (;;) {
            gss_buffer_desc wrapped, unwrapped;
            int conf_state;

            if (recv_token(client_fd, &wrapped) < 0 || wrapped.length == 0)
                break;

            maj = gss_unwrap(&min, ctx, &wrapped, &unwrapped,
                             &conf_state, NULL);
            free(wrapped.value);

            if (GSS_ERROR(maj)) {
                gss_print_errors("gss_unwrap", maj, min);
                break;
            }

            /* Echo back */
            gss_buffer_desc echo_wrapped;
            maj = gss_wrap(&min, ctx, 1, GSS_C_QOP_DEFAULT,
                           &unwrapped, &conf_state, &echo_wrapped);
            gss_release_buffer(&min, &unwrapped);

            if (GSS_ERROR(maj)) {
                gss_print_errors("gss_wrap", maj, min);
                break;
            }

            if (send_token(client_fd, &echo_wrapped) < 0) {
                gss_release_buffer(&min, &echo_wrapped);
                break;
            }
            gss_release_buffer(&min, &echo_wrapped);
        }

        gss_delete_sec_context(&min, &ctx, NULL);
        close(client_fd);
    }

    ret = 0;

out:
    if (cred != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&min, &cred);
    if (mechs != GSS_C_NO_OID_SET)
        gss_release_oid_set(&min, &mechs);
    free_cred_store(&cred_store);
    if (listener >= 0)
        close(listener);
    return ret;
}

int
main(int argc, char *argv[])
{
    int optidx = 0;

    setprogname(argv[0]);

    if (getarg(args, num_args, argc, argv, &optidx))
        usage(1);

    if (help_flag)
        usage(0);

    if (version_flag) {
        print_version(NULL);
        return 0;
    }

    if (client_mode && server_mode) {
        fprintf(stderr, "Cannot specify both -c and -s\n");
        usage(1);
    }

    if (!client_mode && !server_mode) {
        fprintf(stderr, "Must specify either -c (client) or -s (server)\n");
        usage(1);
    }

    argc -= optidx;
    argv += optidx;

    if (argc != 1) {
        fprintf(stderr, "Expected one argument: %s\n",
                client_mode ? "host:port" : "port");
        usage(1);
    }

    /* Parse mechanism */
    selected_mech = parse_mechanism(mechanism_name);

    /* Validate TLS-specific options */
    if (is_tls_mechanism()) {
        if (server_mode && !certificate_store) {
            fprintf(stderr, "TLS server mode requires --certificate\n");
            usage(1);
        }

        if (client_mode && !trust_anchors) {
            fprintf(stderr, "Warning: No trust anchors specified, "
                    "server certificate will not be validated\n");
        }
    }

    if (client_mode)
        return run_client(argv[0]);
    else
        return run_server(argv[0]);
}
