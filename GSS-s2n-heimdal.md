# GSS-TLS Mechanism Design Sketch

## Overview

The goal is to implement a GSS-API mechanism where **GSS tokens are raw TLS records** with no additional framing. This means:

- **Security context tokens** (`gss_init_sec_context`/`gss_accept_sec_context`) = TLS handshake records
- **Per-message tokens** (`gss_wrap`/`gss_unwrap`) = TLS application data records
- **Context deletion tokens** (`gss_delete_sec_context`) = TLS close_notify/alert records

## Key Insight: Memory-Based I/O via Custom Callbacks

s2n-tls supports custom I/O callbacks via:
- `s2n_connection_set_send_cb()` / `s2n_connection_set_send_ctx()`
- `s2n_connection_set_recv_cb()` / `s2n_connection_set_recv_ctx()`

Callback signatures:
```c
typedef int s2n_recv_fn(void *io_context, uint8_t *buf, uint32_t len);
typedef int s2n_send_fn(void *io_context, const uint8_t *buf, uint32_t len);
```

These callbacks receive/send the **raw bytes that would go over the wire** - i.e., complete TLS records. This is exactly what we need.

## Mechanism Architecture

### 1. Context Structure

```c
typedef struct gss_tls_ctx_desc {
    struct s2n_config *config;       /* s2n-tls configuration */
    struct s2n_connection *conn;     /* s2n-tls connection */

    /* I/O buffers for token exchange */
    struct {
        uint8_t *data;               /* Buffer for input token data */
        size_t len;                  /* Total length of input data */
        size_t pos;                  /* Current read position */
    } recv_buf;

    struct {
        uint8_t *data;               /* Buffer for output token data */
        size_t len;                  /* Total length of output data */
        size_t capacity;             /* Allocated capacity */
    } send_buf;

    /* State tracking */
    unsigned int is_initiator : 1;   /* Client or server */
    unsigned int handshake_done : 1; /* Handshake completed */
    unsigned int closed : 1;         /* Connection closed */

    /* Peer identity (from certificate) */
    gss_name_t peer_name;

    /* Credentials (certificate + private key) */
    gss_cred_id_t cred;
} *gss_tls_ctx;
```

### 2. Custom I/O Callbacks

```c
/* Send callback: captures TLS records as GSS output tokens */
static int gss_tls_send_cb(void *io_context, const uint8_t *buf, uint32_t len)
{
    gss_tls_ctx ctx = (gss_tls_ctx)io_context;

    /* Grow buffer if needed */
    if (ctx->send_buf.len + len > ctx->send_buf.capacity) {
        size_t new_cap = ctx->send_buf.capacity * 2;
        if (new_cap < ctx->send_buf.len + len)
            new_cap = ctx->send_buf.len + len;
        ctx->send_buf.data = realloc(ctx->send_buf.data, new_cap);
        ctx->send_buf.capacity = new_cap;
    }

    memcpy(ctx->send_buf.data + ctx->send_buf.len, buf, len);
    ctx->send_buf.len += len;
    return len;
}

/* Recv callback: provides GSS input tokens to TLS */
static int gss_tls_recv_cb(void *io_context, uint8_t *buf, uint32_t len)
{
    gss_tls_ctx ctx = (gss_tls_ctx)io_context;

    size_t available = ctx->recv_buf.len - ctx->recv_buf.pos;
    if (available == 0) {
        errno = EWOULDBLOCK;  /* Tell s2n-tls we're blocked */
        return -1;
    }

    size_t to_copy = (len < available) ? len : available;
    memcpy(buf, ctx->recv_buf.data + ctx->recv_buf.pos, to_copy);
    ctx->recv_buf.pos += to_copy;
    return to_copy;
}
```

### 3. GSS Operation Mapping

#### `gss_init_sec_context` (Client)

```c
OM_uint32 _gss_tls_init_sec_context(
    OM_uint32 *minor,
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
    OM_uint32 *time_rec)
{
    gss_tls_ctx ctx = (gss_tls_ctx)*context_handle;

    /* First call: allocate context, create s2n connection */
    if (ctx == NULL) {
        ctx = calloc(1, sizeof(*ctx));
        ctx->is_initiator = 1;
        ctx->config = s2n_config_new();
        /* Configure certificates from cred */
        configure_client_cert(ctx->config, cred);

        ctx->conn = s2n_connection_new(S2N_CLIENT);
        s2n_connection_set_config(ctx->conn, ctx->config);

        /* Set up custom I/O */
        s2n_connection_set_send_cb(ctx->conn, gss_tls_send_cb);
        s2n_connection_set_send_ctx(ctx->conn, ctx);
        s2n_connection_set_recv_cb(ctx->conn, gss_tls_recv_cb);
        s2n_connection_set_recv_ctx(ctx->conn, ctx);

        *context_handle = (gss_ctx_id_t)ctx;
    }

    /* Provide input token (TLS records from acceptor) */
    if (input_token && input_token->length > 0) {
        ctx->recv_buf.data = input_token->value;
        ctx->recv_buf.len = input_token->length;
        ctx->recv_buf.pos = 0;
    }

    /* Clear output buffer */
    ctx->send_buf.len = 0;

    /* Drive handshake */
    s2n_blocked_status blocked;
    int rc = s2n_negotiate(ctx->conn, &blocked);

    /* Return whatever TLS records were generated */
    if (ctx->send_buf.len > 0) {
        output_token->length = ctx->send_buf.len;
        output_token->value = malloc(ctx->send_buf.len);
        memcpy(output_token->value, ctx->send_buf.data, ctx->send_buf.len);
    }

    if (rc == S2N_SUCCESS) {
        ctx->handshake_done = 1;
        /* Extract peer identity from certificate */
        extract_peer_name(ctx);
        return GSS_S_COMPLETE;
    }

    if (s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED)
        return GSS_S_CONTINUE_NEEDED;

    return GSS_S_FAILURE;
}
```

#### `gss_accept_sec_context` (Server)

Similar structure but with `S2N_SERVER` mode and server certificate configuration.

#### `gss_wrap` (Encrypt + Send)

```c
OM_uint32 _gss_tls_wrap(
    OM_uint32 *minor,
    gss_const_ctx_id_t context_handle,
    int conf_req,
    gss_qop_t qop,
    const gss_buffer_t input,
    int *conf_state,
    gss_buffer_t output)
{
    gss_tls_ctx ctx = (gss_tls_ctx)context_handle;

    /* Clear output buffer */
    ctx->send_buf.len = 0;

    /* s2n_send encrypts and writes TLS application data records */
    s2n_blocked_status blocked;
    ssize_t written = s2n_send(ctx->conn, input->value, input->length, &blocked);

    if (written < 0)
        return GSS_S_FAILURE;

    /* Output is the raw TLS application data record(s) */
    output->length = ctx->send_buf.len;
    output->value = malloc(ctx->send_buf.len);
    memcpy(output->value, ctx->send_buf.data, ctx->send_buf.len);

    *conf_state = 1; /* TLS always encrypts */
    return GSS_S_COMPLETE;
}
```

#### `gss_unwrap` (Receive + Decrypt)

```c
OM_uint32 _gss_tls_unwrap(
    OM_uint32 *minor,
    gss_const_ctx_id_t context_handle,
    const gss_buffer_t input,
    gss_buffer_t output,
    int *conf_state,
    gss_qop_t *qop_state)
{
    gss_tls_ctx ctx = (gss_tls_ctx)context_handle;

    /* Provide input TLS records */
    ctx->recv_buf.data = input->value;
    ctx->recv_buf.len = input->length;
    ctx->recv_buf.pos = 0;

    /* s2n_recv decrypts TLS application data records */
    uint8_t buf[16384];
    s2n_blocked_status blocked;
    ssize_t read = s2n_recv(ctx->conn, buf, sizeof(buf), &blocked);

    if (read < 0)
        return GSS_S_FAILURE;

    output->length = read;
    output->value = malloc(read);
    memcpy(output->value, buf, read);

    *conf_state = 1;
    return GSS_S_COMPLETE;
}
```

#### `gss_delete_sec_context` (Close)

```c
OM_uint32 _gss_tls_delete_sec_context(
    OM_uint32 *minor,
    gss_ctx_id_t *context_handle,
    gss_buffer_t output_token)
{
    gss_tls_ctx ctx = (gss_tls_ctx)*context_handle;

    if (output_token != GSS_C_NO_BUFFER) {
        /* s2n_shutdown sends close_notify alert */
        ctx->send_buf.len = 0;
        s2n_blocked_status blocked;
        s2n_shutdown(ctx->conn, &blocked);

        /* Return the close_notify alert record */
        output_token->length = ctx->send_buf.len;
        output_token->value = malloc(ctx->send_buf.len);
        memcpy(output_token->value, ctx->send_buf.data, ctx->send_buf.len);
    }

    /* Cleanup */
    s2n_connection_free(ctx->conn);
    s2n_config_free(ctx->config);
    free(ctx->send_buf.data);
    free(ctx);

    *context_handle = GSS_C_NO_CONTEXT;
    return GSS_S_COMPLETE;
}
```

### 4. Credential Handling

GSS credentials for TLS would contain:
- X.509 certificate chain (for authentication) - **optional for clients**
- Private key (for signing/key agreement) - **optional for clients**
- Trust anchors (CA certificates for peer verification)

```c
typedef struct gss_tls_cred_desc {
    hx509_context hx509ctx;   /* hx509 context */
    hx509_certs certs;        /* Our certificate(s) - may be empty for anonymous */
    hx509_private_key key;    /* Private key (may be in PKCS#11/HSM) - NULL for anonymous */
    hx509_certs trust_anchors;/* CAs we trust for peer validation */
    hx509_revoke_ctx revoke;  /* Revocation context (CRLs, OCSP) */

    /* Policy flags */
    unsigned int anonymous : 1;        /* No client cert (initiator only) */
    unsigned int require_client_cert : 1; /* Require client cert (acceptor only) */
} *gss_tls_cred;
```

### 4.1 Anonymous vs Authenticated Clients

The mechanism supports two modes for initiators (clients):

1. **Anonymous mode**: No client certificate presented. Server authenticates to client only.
2. **Authenticated mode**: Client presents a certificate. Mutual authentication.

For acceptors (servers):
- Can **require** client certificates (`GSS_C_MUTUAL_FLAG`)
- Can **optionally accept** client certificates
- Can operate with **no client auth** (server-only auth)

```c
/* Anonymous initiator - no client cert */
gss_cred_id_t anon_cred;
gss_key_value_element_desc anon_elems[] = {
    { "x509anchors", "FILE:/etc/ssl/certs/ca-certificates.crt" }
};
gss_key_value_set_desc anon_store = { 1, anon_elems };
gss_acquire_cred_from(&minor, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                      GSS_C_NO_OID_SET, GSS_C_INITIATE,
                      &anon_store, &anon_cred, NULL, NULL);

/* Authenticated initiator - with client cert */
gss_cred_id_t auth_cred;
gss_key_value_element_desc auth_elems[] = {
    { "x509certificate", "FILE:/path/to/client.crt" },
    { "x509privatekey",  "FILE:/path/to/client.key" },
    { "x509anchors",     "FILE:/etc/ssl/certs/ca-certificates.crt" }
};
gss_key_value_set_desc auth_store = { 3, auth_elems };
gss_acquire_cred_from(&minor, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                      GSS_C_NO_OID_SET, GSS_C_INITIATE,
                      &auth_store, &auth_cred, NULL, NULL);
```

### 4.2 `gss_acquire_cred_from()` Key-Value Parameters

The mechanism uses hx509 certificate store URIs, providing flexibility for file-based,
PKCS#11, PKCS#12, keychain, and other backends.

| Key | Description | Example Values |
|-----|-------------|----------------|
| `x509certificate` | Our certificate(s) | `FILE:/path/to/cert.pem`, `PKCS12:/path/to/bundle.p12`, `PKCS11:/path/to/module.so` |
| `x509privatekey` | Private key | `FILE:/path/to/key.pem`, `PKCS11:`, `PKCS12:/path/to/bundle.p12` |
| `x509anchors` | Trust anchors (CAs) | `FILE:/etc/ssl/certs/ca-certificates.crt`, `DIR:/etc/ssl/certs`, `KEYCHAIN:` |
| `x509crls` | CRL store | `FILE:/path/to/crl.pem`, `DIR:/var/lib/crls` |
| `x509requireclientcert` | Require client cert (acceptor) | `true`, `false` |
| `password` | Password for encrypted keys/PKCS#12 | (string value) |
| `prompter` | Password prompter type | `none`, `tty`, `gui` |

#### hx509 Store URI Examples

```c
/* File-based certificate and key */
{ "x509certificate", "FILE:/etc/ssl/server.crt" },
{ "x509privatekey",  "FILE:/etc/ssl/private/server.key" },

/* PKCS#12 bundle (cert + key + chain) */
{ "x509certificate", "PKCS12:/path/to/bundle.p12" },
{ "x509privatekey",  "PKCS12:/path/to/bundle.p12" },
{ "password",        "bundle-password" },

/* PKCS#11 token (HSM/smartcard) */
{ "x509certificate", "PKCS11:/usr/lib/pkcs11/opensc-pkcs11.so" },
{ "x509privatekey",  "PKCS11:/usr/lib/pkcs11/opensc-pkcs11.so" },

/* macOS Keychain */
{ "x509certificate", "KEYCHAIN:" },
{ "x509privatekey",  "KEYCHAIN:" },

/* Directory of CA certificates */
{ "x509anchors", "DIR:/etc/ssl/certs" },

/* PEM file with multiple CAs */
{ "x509anchors", "FILE:/etc/ssl/certs/ca-certificates.crt" },
```

### 4.3 Implementation of `gss_acquire_cred_from()`

```c
OM_uint32 _gss_tls_acquire_cred_from(
    OM_uint32 *minor,
    gss_const_name_t desired_name,
    OM_uint32 time_req,
    gss_OID_set desired_mechs,
    gss_cred_usage_t cred_usage,
    gss_const_key_value_set_t cred_store,
    gss_cred_id_t *output_cred,
    gss_OID_set *actual_mechs,
    OM_uint32 *time_rec)
{
    gss_tls_cred cred;
    const char *cert_store = NULL;
    const char *key_store = NULL;
    const char *anchor_store = NULL;
    const char *crl_store = NULL;
    const char *password = NULL;
    int require_client_cert = 0;

    *minor = 0;

    cred = calloc(1, sizeof(*cred));
    if (cred == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    hx509_context_init(&cred->hx509ctx);

    /* Parse key-value store options */
    for (size_t i = 0; cred_store && i < cred_store->count; i++) {
        const char *key = cred_store->elements[i].key;
        const char *val = cred_store->elements[i].value;

        if (strcmp(key, "x509certificate") == 0)
            cert_store = val;
        else if (strcmp(key, "x509privatekey") == 0)
            key_store = val;
        else if (strcmp(key, "x509anchors") == 0)
            anchor_store = val;
        else if (strcmp(key, "x509crls") == 0)
            crl_store = val;
        else if (strcmp(key, "x509requireclientcert") == 0)
            require_client_cert = (strcmp(val, "true") == 0);
        else if (strcmp(key, "password") == 0)
            password = val;
    }

    /* Load our certificate(s) - optional for initiators */
    if (cert_store) {
        hx509_certs_init(cred->hx509ctx, cert_store, 0, NULL, &cred->certs);
    } else {
        /* No certificate = anonymous mode for initiators */
        cred->anonymous = 1;
        hx509_certs_init(cred->hx509ctx, "MEMORY:empty", 0, NULL, &cred->certs);
    }

    /* Load private key - optional for initiators */
    if (key_store) {
        hx509_private_key_init(&cred->key);
        /* Use password callback or provided password */
        hx509_certs keys;
        hx509_certs_init(cred->hx509ctx, key_store, 0, NULL, &keys);
        /* Extract first private key from store */
        hx509_certs_iter iter;
        hx509_cert cert;
        hx509_certs_start_seq(cred->hx509ctx, keys, &iter);
        if (hx509_certs_next_cert(cred->hx509ctx, keys, iter, &cert) == 0) {
            cred->key = hx509_cert_get_private_key(cert);
            hx509_cert_free(cert);
        }
        hx509_certs_end_seq(cred->hx509ctx, keys, iter);
        hx509_certs_free(&keys);
    }

    /* Load trust anchors - required */
    if (anchor_store) {
        hx509_certs_init(cred->hx509ctx, anchor_store, 0, NULL, &cred->trust_anchors);
    } else {
        /* Use system default trust store */
        hx509_certs_init(cred->hx509ctx, "SYSTEM:", 0, NULL, &cred->trust_anchors);
    }

    /* Load CRLs if specified */
    if (crl_store) {
        hx509_revoke_init(cred->hx509ctx, &cred->revoke);
        hx509_revoke_add_crl(cred->hx509ctx, cred->revoke, crl_store);
    }

    cred->require_client_cert = require_client_cert;

    *output_cred = (gss_cred_id_t)cred;

    if (actual_mechs) {
        gss_create_empty_oid_set(minor, actual_mechs);
        gss_add_oid_set_member(minor, GSS_TLS_MECHANISM, actual_mechs);
    }

    if (time_rec)
        *time_rec = GSS_C_INDEFINITE;

    return GSS_S_COMPLETE;
}
```

### 4.4 Server-Side Client Authentication Configuration

```c
/* In accept_sec_context setup */
static int configure_server(gss_tls_ctx ctx, gss_tls_cred cred)
{
    /* Configure client certificate mode */
    if (cred->require_client_cert) {
        /* Mutual auth required - fail if no client cert */
        s2n_config_set_client_auth_type(ctx->config, S2N_CERT_AUTH_REQUIRED);
    } else {
        /* Optional - accept clients with or without certs */
        s2n_config_set_client_auth_type(ctx->config, S2N_CERT_AUTH_OPTIONAL);
    }

    /* Set up certificate validation callback for client certs */
    s2n_config_set_cert_validation_cb(ctx->config, gss_tls_cert_validator, ctx);

    return 0;
}
```

### 4.5 Peer Identity After Handshake

After handshake completion, the peer's identity is extracted:

```c
static void extract_peer_identity(gss_tls_ctx ctx)
{
    struct s2n_cert_chain_and_key *peer_chain = s2n_cert_chain_and_key_new();

    if (s2n_connection_get_peer_cert_chain(ctx->conn, peer_chain) == S2N_SUCCESS) {
        uint32_t cert_count;
        s2n_cert_chain_get_length(peer_chain, &cert_count);

        if (cert_count > 0) {
            /* Get leaf certificate */
            struct s2n_cert *leaf;
            s2n_cert_chain_get_cert(peer_chain, &leaf, 0);

            const uint8_t *der_data;
            uint32_t der_length;
            s2n_cert_get_der(leaf, &der_data, &der_length);

            /* Parse with hx509 and extract subject */
            hx509_cert hxcert;
            hx509_cert_init_data(ctx->hx509ctx, der_data, der_length, &hxcert);

            /* Create GSS name from certificate subject */
            ctx->peer_name = create_gss_name_from_cert(hxcert);
            ctx->peer_cert = hxcert;
        } else {
            /* Anonymous peer (no client certificate) */
            ctx->peer_name = GSS_C_NO_NAME;  /* or anonymous name */
            ctx->peer_cert = NULL;
        }
    }

    s2n_cert_chain_and_key_free(peer_chain);
}
```

### 4.6 Private Key Offloading (hx509 Integration)

s2n-tls supports offloading private key operations via `s2n_config_set_async_pkey_callback()`.
This is perfect for integrating with hx509 private keys, which may be backed by PKCS#11 tokens or HSMs.

```c
static int gss_tls_pkey_callback(struct s2n_connection *conn,
                                  struct s2n_async_pkey_op *op)
{
    gss_tls_ctx ctx = s2n_connection_get_ctx(conn);
    gss_tls_cred cred = (gss_tls_cred)ctx->cred;

    /* Get operation type */
    s2n_async_pkey_op_type op_type;
    s2n_async_pkey_op_get_op_type(op, &op_type);

    /* Get input data */
    uint32_t input_size;
    s2n_async_pkey_op_get_input_size(op, &input_size);
    uint8_t *input = malloc(input_size);
    s2n_async_pkey_op_get_input(op, input, input_size);

    /* Perform operation using hx509 private key */
    heim_octet_string in_data = { .data = input, .length = input_size };
    heim_octet_string out_data = { 0 };

    if (op_type == S2N_ASYNC_SIGN) {
        /* Use hx509 to sign - works with PKCS#11, HSM, etc. */
        hx509_private_key_sign(cred->hx509ctx, cred->key,
                               /* algorithm from TLS */, &in_data, &out_data);
    } else if (op_type == S2N_ASYNC_DECRYPT) {
        hx509_private_key_decrypt(cred->hx509ctx, cred->key,
                                  &in_data, &out_data);
    }

    /* Return result to s2n-tls */
    s2n_async_pkey_op_set_output(op, out_data.data, out_data.length);
    s2n_async_pkey_op_apply(op, conn);

    free(input);
    der_free_octet_string(&out_data);
    return S2N_SUCCESS;
}

/* Configure during context setup */
s2n_config_set_async_pkey_callback(ctx->config, gss_tls_pkey_callback);
```

Key benefit: Private keys never leave hx509 - PKCS#11 tokens and HSMs work transparently.

### 4.7 Custom Certificate Validation (hx509 Integration)

s2n-tls supports custom certificate validation via `s2n_config_set_cert_validation_cb()`.
This allows delegating all certificate validation to hx509:

```c
static int gss_tls_cert_validator(struct s2n_connection *conn,
                                   struct s2n_cert_validation_info *info,
                                   void *context)
{
    gss_tls_ctx ctx = (gss_tls_ctx)context;
    gss_tls_cred cred = (gss_tls_cred)ctx->cred;
    hx509_verify_ctx verify_ctx = NULL;
    int ret;

    /* Get peer's certificate chain */
    struct s2n_cert_chain_and_key *peer_chain = s2n_cert_chain_and_key_new();
    s2n_connection_get_peer_cert_chain(conn, peer_chain);

    /* Convert to hx509 certs */
    hx509_certs chain;
    hx509_certs_init(cred->hx509ctx, "MEMORY:peer", 0, NULL, &chain);

    uint32_t cert_count;
    s2n_cert_chain_get_length(peer_chain, &cert_count);

    for (uint32_t i = 0; i < cert_count; i++) {
        struct s2n_cert *cert;
        s2n_cert_chain_get_cert(peer_chain, &cert, i);

        const uint8_t *der_data;
        uint32_t der_length;
        s2n_cert_get_der(cert, &der_data, &der_length);

        /* Add DER cert to hx509 chain */
        hx509_cert hxcert;
        hx509_cert_init_data(cred->hx509ctx, der_data, der_length, &hxcert);
        hx509_certs_add(cred->hx509ctx, chain, hxcert);
        hx509_cert_free(hxcert);
    }

    /* Validate using hx509 */
    hx509_verify_init_ctx(cred->hx509ctx, &verify_ctx);
    hx509_verify_set_time(verify_ctx, time(NULL));
    hx509_verify_attach_anchors(verify_ctx, cred->trust_anchors);

    ret = hx509_certs_verify(cred->hx509ctx, verify_ctx, chain, NULL, 0, NULL);

    if (ret == 0) {
        s2n_cert_validation_accept(info);
        /* Extract peer name from leaf certificate for GSS */
        extract_peer_name_from_chain(ctx, chain);
    } else {
        s2n_cert_validation_reject(info);
    }

    hx509_verify_destroy_ctx(verify_ctx);
    hx509_certs_free(&chain);
    s2n_cert_chain_and_key_free(peer_chain);

    return S2N_SUCCESS;
}

/* Configure during context setup */
s2n_config_set_cert_validation_cb(ctx->config, gss_tls_cert_validator, ctx);
```

### 4.8 Loading Certificates into s2n-tls

For s2n-tls to send our certificate, we need to provide it in PEM format.
We can export from hx509:

```c
static int configure_our_cert(struct s2n_config *config, gss_tls_cred cred)
{
    /* Export certificate chain to PEM */
    hx509_certs_iter iter;
    hx509_cert cert;
    struct rk_membuf *buf = rk_membuf_init(NULL);

    hx509_certs_start_seq(cred->hx509ctx, cred->chain, &iter);
    while (hx509_certs_next_cert(cred->hx509ctx, cred->chain, iter, &cert) == 0) {
        /* Append PEM to buffer */
        hx509_cert_write_pem(cert, buf, "CERTIFICATE");
        hx509_cert_free(cert);
    }
    hx509_certs_end_seq(cred->hx509ctx, cred->chain, iter);

    /* Load into s2n-tls (private key handled via async callback) */
    struct s2n_cert_chain_and_key *chain = s2n_cert_chain_and_key_new();
    s2n_cert_chain_and_key_load_pem(chain, rk_membuf_data(buf), NULL);
    s2n_config_add_cert_chain_and_key_to_store(config, chain);

    rk_membuf_free(buf);
    return 0;
}
```

### 5. Name Handling

GSS names for TLS could be:
- **GSS_C_NT_HOSTBASED_SERVICE**: `service@host` -> TLS SNI hostname
- **GSS_C_NT_USER_NAME**: Distinguished Name from certificate
- **GSS_TLS_NT_X509_NAME**: Raw X.509 subject DN

### 6. OID Allocations

OID arc: `1.3.6.1.4.1.40402.1` (PEN 40402, arc 1 = heimdal)

```
1.3.6.1.4.1.40402.1.1    GSS-TLS mechanism OID
1.3.6.1.4.1.40402.1.2    GSS_C_MA_SELF_FRAMED (mechanism attribute)
1.3.6.1.4.1.40402.1.3    GSS name types arc (for X.509 SAN types)
```

#### GSS Name Types for X.509 SANs

For **OtherName SANs**, the OID is embedded in the SAN, so use the OtherName type-id directly:

| Name Type | OID | Description |
|-----------|-----|-------------|
| GSS_KRB5_NT_PRINCIPAL_NAME | 1.2.840.113554.1.2.2.1 | Kerberos principal (existing) |
| id-pkinit-san | 1.3.6.1.5.2.2 | PKINIT SAN (KRB5PrincipalName) |
| id-ms-san-upn | 1.3.6.1.4.1.311.20.2.3 | Microsoft UPN SAN |
| id-on-xmppAddr | 1.3.6.1.5.5.7.8.5 | XMPP address |
| id-on-dnsSRV | 1.3.6.1.5.5.7.8.7 | DNS SRV name |
| id-on-SmtpUTF8Mailbox | 1.3.6.1.5.5.7.8.9 | SMTP UTF8 mailbox |

For **non-OtherName SANs** (GeneralName choices without embedded OIDs), allocate under `.3`:

| Name Type | OID | GeneralName | Description |
|-----------|-----|-------------|-------------|
| GSS_C_NT_X509_RFC822NAME | 1.3.6.1.4.1.40402.1.3.1 | [1] rfc822Name | Email address |
| GSS_C_NT_X509_DNSNAME | 1.3.6.1.4.1.40402.1.3.2 | [2] dNSName | DNS hostname |
| GSS_C_NT_X509_DIRNAME | 1.3.6.1.4.1.40402.1.3.4 | [4] directoryName | X.500 DN |
| GSS_C_NT_X509_URI | 1.3.6.1.4.1.40402.1.3.6 | [6] URI | Uniform Resource Identifier |
| GSS_C_NT_X509_IPADDRESS | 1.3.6.1.4.1.40402.1.3.7 | [7] iPAddress | IP address |
| GSS_C_NT_X509_REGID | 1.3.6.1.4.1.40402.1.3.8 | [8] registeredID | Registered OID |

Note: The `.3.N` values match the GeneralName CHOICE tag numbers for easy mapping.

#### Name Import/Export

For `gss_import_name()`:
- OtherName types: Import the OtherName value (e.g., KRB5PrincipalName encoding)
- rfc822Name: Import as UTF-8 string (e.g., "user@example.com")
- dNSName: Import as UTF-8 string (e.g., "host.example.com")
- directoryName: Import as DER-encoded Name or RFC 4514 string
- URI: Import as UTF-8 string
- iPAddress: Import as 4 bytes (IPv4) or 16 bytes (IPv6)

For `gss_export_name()`:
- Canonical export includes name type OID + value

### 7. Token Format

The key requirement is that tokens **are raw TLS records**:

```
TLS Record Format:
+-------------+------------------+-----------------+
| ContentType | ProtocolVersion  | Length | Data   |
| (1 byte)    | (2 bytes)        | (2 bytes)      |
+-------------+------------------+-----------------+

ContentType values:
  20 = ChangeCipherSpec
  21 = Alert
  22 = Handshake
  23 = ApplicationData
```

**No GSS token framing** (no OID prefix) - tokens are passed directly to/from the transport.

### 8. Files to Create

```
lib/gssapi/tls/
├── Makefile.am
├── tls_locl.h           # Internal definitions
├── external.c           # Mechanism interface definition
├── init_sec_context.c   # gss_init_sec_context
├── accept_sec_context.c # gss_accept_sec_context
├── wrap.c               # gss_wrap
├── unwrap.c             # gss_unwrap
├── delete_sec_context.c # gss_delete_sec_context
├── acquire_cred.c       # Credential acquisition
├── release_cred.c       # Credential release
├── import_name.c        # Name import
├── display_name.c       # Name display
├── compare_name.c       # Name comparison
├── release_name.c       # Name release
├── inquire_context.c    # Context inquiry
├── context_time.c       # Context lifetime
└── display_status.c     # Error messages
```

### 9. Integration

Register in `_gss_load_mech()` (lib/gssapi/mech/gss_mech_switch.c):
```c
if (add_builtin(__gss_tls_initialize()))
    _gss_mg_log(1, "Out of memory while adding builtin TLS mechanism");
```

### 10. Open Questions

1. **MIC operations**: TLS doesn't have a separate MIC mechanism. Options:
   - Return `GSS_S_UNAVAILABLE` for `gss_get_mic`/`gss_verify_mic`
   - Use HMAC derived from TLS session keys

2. **Multiple records per call**: TLS may generate multiple records for large messages. The wrap output could be multiple records concatenated.

3. **Partial reads**: If `gss_unwrap` receives only part of a TLS record, we need to handle buffering across calls.

4. **PRF**: `gss_pseudo_random` could use TLS 1.3 exporter or TLS 1.2 PRF.

5. **Channel bindings**: TLS 1.3 has a channel binding exporter mechanism.

---

This design ensures that if you strip away the GSS-API layer and just pass the tokens, you have valid TLS traffic on the wire.

## References

- `s2n-tls/GSS-S2N.md` - Notes on s2n-tls certificate extraction, private key offloading, and custom validation APIs
- `s2n-tls/GSS-S2N-build.md` - Building s2n-tls with custom OpenSSL
- `s2n-tls/docs/usage-guide/topics/ch07-io.md` - Custom I/O callbacks documentation
- `s2n-tls/docs/usage-guide/topics/ch13-private-key-ops.md` - Private key offloading documentation
- `lib/gssapi/sanon/` - Reference GSS mechanism implementation in Heimdal

---

## Implementation Status

### Completed

- [x] Core mechanism skeleton files (`lib/gssapi/tls/*.c`)
- [x] Mechanism OID allocation (`1.3.6.1.4.1.40402.1.1`)
- [x] GSS_C_MA_SELF_FRAMED attribute (`1.3.6.1.4.1.40402.1.2`)
- [x] Backend abstraction (`tls_backend.h`)
- [x] OpenSSL backend (`tls_openssl.c`)
- [x] s2n-tls backend (`tls_s2n.c`)
- [x] Configure option `--with-gss-tls=auto|s2n-tls|openssl|no`
- [x] Configure option `--with-s2n` for s2n-tls library detection
- [x] Generic GSS test tool (`lib/gssapi/gss.c`) with self-framing detection

### TODO Items

#### High Priority

1. **PEM encoding in s2n backend** (`tls_s2n.c:load_cert_chain()`)
   - The function has placeholder code for converting hx509 DER certificates to PEM format
   - Need proper base64 encoding implementation
   - Consider using hx509's PEM export if available, or rk_base64 from roken

2. **Peer certificate retrieval in s2n backend** (`tls_s2n.c:tls_backend_get_peer_cert()`)
   - Currently returns `TLS_BACKEND_ERROR` - not implemented
   - s2n-tls doesn't have a simple API for extracting peer cert after handshake
   - Options:
     - Use verification callback to capture peer cert during handshake
     - Use `s2n_connection_get_peer_cert_chain()` (TLS 1.3 only?)

3. **Trust anchor loading in s2n backend** (`tls_s2n.c:load_trust_anchors()`)
   - Currently a stub that does nothing
   - Need to use `s2n_config_set_verification_ca_location()` for file/directory
   - Or implement custom verification callback that uses hx509

#### Medium Priority

4. **Verify `_hx509_private_key_export()` exists** (`tls_openssl.c:hx509_key_to_openssl()`)
   - Uses internal hx509 function to export private key as DER
   - May need to add this API to hx509 or find alternative

5. **Revocation checking integration** (both backends)
   - `tls_backend_config` has `hx509_revoke_ctx revoke` but it's unused
   - Should integrate with hx509 revocation checking (CRL, OCSP)
   - For OpenSSL: could use `X509_STORE_set_flags()` with `X509_V_FLAG_CRL_CHECK`
   - For s2n: use custom verification callback

6. **Channel bindings support**
   - TLS 1.3 supports channel bindings via RFC 9266 exporter
   - Should implement `gss_inquire_sec_context_by_oid` for `GSS_C_INQ_SSPI_SESSION_KEY`
   - Use `s2n_connection_get_key_bytes()` or `SSL_export_keying_material()`

7. **Multiple TLS records per GSS token**
   - TLS handshake may produce multiple records in one direction
   - Current `recv_token()` in `gss.c` only reads one TLS record
   - May need to read multiple records until handshake step complete

#### Low Priority

8. **TLS session resumption**
   - Could improve performance for repeated connections
   - s2n supports session tickets via `s2n_config_set_session_tickets_onoff()`
   - OpenSSL: `SSL_CTX_set_session_cache_mode()`

9. **ALPN support**
   - Application-Layer Protocol Negotiation
   - s2n: `s2n_config_set_protocol_preferences()`
   - OpenSSL: `SSL_CTX_set_alpn_protos()`

10. **Export/import security context**
    - Currently returns NULL (not implemented)
    - Would allow context migration between processes
    - Complex: need to serialize TLS session state

11. **gss_get_mic / gss_verify_mic**
    - TLS doesn't have separate MIC mechanism
    - Options:
      - Return `GSS_S_UNAVAILABLE`
      - Derive HMAC from TLS session keys using exporter

### Configure Options

```bash
# s2n-tls library detection
./configure --with-s2n=/path/to/s2n          # Specify s2n-tls location
./configure --with-s2n-lib=/path/to/lib      # Specify library directory
./configure --with-s2n-include=/path/to/inc  # Specify include directory

# GSS-TLS backend selection
./configure --with-gss-tls=auto      # Default: prefer s2n-tls, fall back to OpenSSL
./configure --with-gss-tls=s2n-tls   # Require s2n-tls
./configure --with-gss-tls=openssl   # Use OpenSSL's libssl
./configure --with-gss-tls=no        # Disable GSS-TLS mechanism
```

### Testing

Use the `gss` tool in `lib/gssapi/`:

```bash
# Build
cd build && make lib/gssapi/gss

# Server (with certificate)
./lib/gssapi/gss -s -p 4433 -m tls \
    --certificate server.pem \
    --private-key server-key.pem \
    --trust-anchors ca.pem

# Client (anonymous, just verifies server)
./lib/gssapi/gss -c localhost -p 4433 -m tls \
    --trust-anchors ca.pem

# Client (with certificate for mutual auth)
./lib/gssapi/gss -c localhost -p 4433 -m tls \
    --certificate client.pem \
    --private-key client-key.pem \
    --trust-anchors ca.pem

# Test with other mechanisms (uses length-prefix framing)
./lib/gssapi/gss -s -p 4433 -m krb5
./lib/gssapi/gss -c localhost -p 4433 -m krb5
```
