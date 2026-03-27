# htpm2 API Design

## Overview

`lib/htpm2/` is a C library providing a simple, self-contained interface to
TPM 2.0 hardware and software TPMs.  Its dependencies are `lib/roken/`,
`lib/base/`, and OpenSSL's `libcrypto` (used directly, just as `lib/hx509/`
and `lib/krb5/` each use `libcrypto` directly).  OpenSSL 3.0+ is required.

The library handles TPM 2.0 command marshalling/unmarshalling, transport I/O,
session management (HMAC, policy, trial), encrypted and authenticated sessions,
and exposes high-level operations for key management, attestation, credential
activation, and TPM-based certificate issuance.

## Design Principles

1. **Minimal dependencies** -- `lib/roken/`, `lib/base/`, and OpenSSL's
   `libcrypto` (directly).  No Intel TSS, no dependency on `lib/hx509/` or
   `lib/krb5/`.  This allows `lib/hx509/` to depend on `lib/htpm2/` for
   TPM-backed certificate operations (e.g., `TPM2_CertifyX509()`).

2. **Structured errors returned by value** -- functions return an
   `htpm2_result` struct by value, carrying multi-dimensional error codes
   and a heap-allocated message.  This is a departure from Heimdal's
   traditional integer-return-code pattern, inspired by GSS-API's multi-code
   approach but using a struct instead of bit-packing into an integer.

3. **Read-only context** -- `htpm2_context` is immutable after initialization
   (a Reader monad, not a State monad).  All mutable state lives in
   transports, sessions, and objects.  Error messages are carried in the
   result struct, not on the context.  This makes the context inherently
   thread-safe: multiple threads can share one `const htpm2_context`.

4. **Monadic error chaining** -- every function takes a prior `htpm2_result`
   by value as its first argument after the context.  If the prior result is
   an error, the function short-circuits and returns it unchanged.  This
   enables goto-free, linear error propagation.

5. **Opaque types** -- all public types are `typedef`'d pointers to internal
   structures.  Users never see structure layouts.

6. **Synchronous with future-async readiness** -- all I/O is synchronous
   today.  The result struct has a `HTPM2_F_WOULDBLOCK` flag; callers can
   obtain file descriptors to poll via accessors on the transport, enabling
   a future async path without ABI breakage.

7. **Encrypted + authenticated sessions by default** -- the API makes it
   easy (and the default) to use HMAC sessions with parameter encryption to
   defeat active bus-level attackers.

8. **Software-only where possible** -- operations like `MakeCredential` that
   don't require TPM secrets are implemented in software using `libcrypto`,
   avoiding a round-trip to the TPM.

9. **No locking** -- thread safety of mutable objects (transports, sessions,
   object handles) is the caller's responsibility.  The read-only context
   needs no locking.

## Public Header: `<htpm2.h>`

### Result Type

Functions return `htpm2_result` by value.  On success, `code == 0` and
`message == NULL` (no allocation).  On error, `code != 0`, flags indicate
which error dimensions are populated, and `message` is a heap-allocated
human-readable description.

```c
typedef struct htpm2_result {
    int32_t  code;       /* 0 = success, nonzero = error */
    uint32_t flags;      /* bitfield: which error fields are populated */
    uint32_t tpm_rc;     /* raw TPM_RC when HTPM2_F_TPM_RC is set */
    int32_t  local_err;  /* errno / library error when HTPM2_F_LOCAL is set */
    uint32_t ossl_err;   /* OpenSSL error code when HTPM2_F_OSSL is set */
    char    *message;    /* heap-allocated on error, NULL on success */
} htpm2_result;

/* Error dimension flags */
#define HTPM2_F_TPM_RC      0x01  /* tpm_rc field is valid */
#define HTPM2_F_LOCAL       0x02  /* local_err field is valid */
#define HTPM2_F_OSSL        0x04  /* ossl_err field is valid */
#define HTPM2_F_TRANSPORT   0x08  /* error originated in transport layer */
#define HTPM2_F_MARSHAL     0x10  /* error originated in marshalling */
#define HTPM2_F_SESSION     0x20  /* session/auth verification failed */
#define HTPM2_F_WOULDBLOCK  0x40  /* async: retry after poll */

/* The zero-value result: success, no allocation. */
#define HTPM2_OK ((htpm2_result){0, 0, 0, 0, 0, NULL})

static inline int htpm2_is_ok(htpm2_result r) { return r.code == 0; }
static inline int htpm2_is_err(htpm2_result r) { return r.code != 0; }

/* Free the heap-allocated message (if any) and zero the struct. */
void htpm2_result_free(htpm2_result *r);

/* Prepend context to an existing error.  Takes ownership of `old`,
 * returns a new result with message "prefix: old_message".
 * If `old` is OK, returns it unchanged (no allocation). */
htpm2_result htpm2_result_prepend(htpm2_result old, const char *fmt, ...);
```

### Monadic Error Chaining

Every function (except context init and pure accessors) takes the prior
result as its first argument after the context.  If the prior result is
an error, the function is a no-op and returns it unchanged -- the error
propagates automatically.

```c
/* Example: full key creation + signing with no gotos */
htpm2_result r = HTPM2_OK;
htpm2_object parent = NULL, key = NULL;
void *sig = NULL;
size_t sig_len = 0;

r = htpm2_create_primary(ctx, tp, r, session, HTPM2_HIERARCHY_OWNER,
                         HTPM2_KEY_RSA_2048_STORAGE, NULL, 0, NULL, 0,
                         &parent);
r = htpm2_create(ctx, tp, r, session, parent,
                 HTPM2_KEY_RSA_2048_SIGN, NULL, 0, NULL, 0, &key);
r = htpm2_sign(ctx, tp, r, session, key, digest, digest_len,
               &sig, &sig_len);
if (htpm2_is_err(r))
    fprintf(stderr, "failed: %s\n", r.message);

/* Cleanup */
htpm2_free(ctx, sig);
htpm2_object_close(&key);
htpm2_object_close(&parent);
htpm2_result_free(&r);
```

Internally, every function begins with:

```c
htpm2_result
htpm2_sign(const htpm2_context ctx, htpm2_transport tp,
           htpm2_result prior, ...)
{
    if (prior.code)
        return prior;  /* short-circuit: propagate error */
    /* ... actual work ... */
}
```

Note: `htpm2_context` is `const` in all function signatures (except
`htpm2_context_init` / `htpm2_context_free`).

### Context

```c
typedef struct htpm2_context_data *htpm2_context;

/* These two are the only functions that don't take a prior result,
 * since they bootstrap / tear down the context itself. */
htpm2_result htpm2_context_init(htpm2_context *ctx);
void         htpm2_context_free(htpm2_context *ctx);
```

The context is **read-only after initialization**.  It holds:
- Configuration (default hash algorithm, logging settings)
- Cached OpenSSL `EVP_MD` / `EVP_CIPHER` pointers
- Transport type registry

It does NOT hold error state, mutable session state, or any per-operation
data.

### Transport

```c
typedef struct htpm2_transport_data *htpm2_transport;

/* Open a transport by URI-style string:
 *   "device:/dev/tpmrm0"
 *   "socket:/run/swtpm-sock"
 *   "pipe:swtpm socket --tpmstate dir=..."
 *   "pipe:ssh remotehost swtpm socket ..."
 *   "tcp:host:port"
 */
htpm2_result htpm2_transport_open(const htpm2_context ctx,
                                  htpm2_result prior,
                                  const char *uri,
                                  htpm2_transport *tp);
void         htpm2_transport_close(htpm2_transport *tp);

/* For future async I/O: retrieve fd(s) to poll when WOULDBLOCK. */
int htpm2_transport_get_read_fd(htpm2_transport tp);
int htpm2_transport_get_write_fd(htpm2_transport tp);
```

Pluggable transport vtable:

```c
typedef struct htpm2_transport_ops {
    const char *name;
    htpm2_result (*open)(const htpm2_context, const char *arg,
                         htpm2_transport *);
    htpm2_result (*send_recv)(htpm2_transport,
                              const void *cmd, size_t cmd_len,
                              void *rsp, size_t *rsp_len);
    int          (*get_read_fd)(htpm2_transport);
    int          (*get_write_fd)(htpm2_transport);
    void         (*close)(htpm2_transport *);
} htpm2_transport_ops;

htpm2_result htpm2_transport_register(htpm2_context ctx,
                                      const htpm2_transport_ops *ops);
```

Note: `htpm2_transport_register()` is called during context init and is the
one mutation of the context during setup.

### Sessions

```c
typedef struct htpm2_session_data *htpm2_session;

typedef enum {
    HTPM2_SESSION_HMAC    = 0,
    HTPM2_SESSION_POLICY  = 1,
    HTPM2_SESSION_TRIAL   = 2
} htpm2_session_type;

#define HTPM2_SESSION_ENCRYPT       0x01
#define HTPM2_SESSION_DECRYPT       0x02
#define HTPM2_SESSION_AUDIT         0x04
#define HTPM2_SESSION_CONTINUE      0x08
#define HTPM2_SESSION_ENC_DEC       (HTPM2_SESSION_ENCRYPT | HTPM2_SESSION_DECRYPT)

htpm2_result htpm2_session_start(const htpm2_context ctx,
                                 htpm2_transport tp,
                                 htpm2_result prior,
                                 htpm2_session_type type,
                                 htpm2_object salt_key,
                                 htpm2_object bind,
                                 unsigned int flags,
                                 htpm2_session *session);

void htpm2_session_close(htpm2_session *session);

htpm2_result htpm2_session_get_policy_digest(htpm2_session session,
                                             htpm2_result prior,
                                             void *digest,
                                             size_t *digest_len);
```

### Policy Commands

```c
htpm2_result htpm2_policy_pcr(const htpm2_context ctx,
                              htpm2_session session,
                              htpm2_result prior,
                              const uint8_t *pcr_selections,
                              size_t pcr_selections_len,
                              const void *pcr_digest,
                              size_t pcr_digest_len);

htpm2_result htpm2_policy_command_code(const htpm2_context ctx,
                                       htpm2_session session,
                                       htpm2_result prior,
                                       uint32_t command_code);

htpm2_result htpm2_policy_authorize(const htpm2_context ctx,
                                    htpm2_session session,
                                    htpm2_result prior,
                                    const void *approved_policy,
                                    size_t approved_policy_len,
                                    const void *policy_ref,
                                    size_t policy_ref_len,
                                    const void *key_sign_name,
                                    size_t key_sign_name_len,
                                    const void *ticket,
                                    size_t ticket_len,
                                    const void *signature,
                                    size_t signature_len);

htpm2_result htpm2_policy_signed(const htpm2_context ctx,
                                 htpm2_session session,
                                 htpm2_result prior,
                                 htpm2_object auth_key,
                                 const void *policy_ref,
                                 size_t policy_ref_len,
                                 int32_t expiration,
                                 const void *signature,
                                 size_t signature_len);

htpm2_result htpm2_policy_secret(const htpm2_context ctx,
                                 htpm2_session session,
                                 htpm2_result prior,
                                 htpm2_object auth_entity,
                                 const void *policy_ref,
                                 size_t policy_ref_len,
                                 int32_t expiration);

htpm2_result htpm2_policy_or(const htpm2_context ctx,
                             htpm2_session session,
                             htpm2_result prior,
                             const void **digests,
                             const size_t *digest_lens,
                             size_t num_digests);
```

### Key / Object Management

```c
typedef struct htpm2_object_data *htpm2_object;

typedef enum {
    HTPM2_KEY_RSA_2048_SIGN     = 0,
    HTPM2_KEY_RSA_2048_DECRYPT  = 1,
    HTPM2_KEY_RSA_2048_STORAGE  = 2,
    HTPM2_KEY_RSA_3072_SIGN     = 3,
    HTPM2_KEY_RSA_3072_DECRYPT  = 4,
    HTPM2_KEY_RSA_3072_STORAGE  = 5,
    HTPM2_KEY_ECC_P256_SIGN     = 10,
    HTPM2_KEY_ECC_P256_DECRYPT  = 11,
    HTPM2_KEY_ECC_P256_STORAGE  = 12,
    HTPM2_KEY_ECC_P384_SIGN     = 13,
    HTPM2_KEY_ECC_P384_DECRYPT  = 14,
    HTPM2_KEY_ECC_P384_STORAGE  = 15,
    HTPM2_KEY_HMAC_SHA256       = 20,
    HTPM2_KEY_KEYEDHASH         = 21
} htpm2_key_type;

#define HTPM2_HIERARCHY_OWNER       0x40000001
#define HTPM2_HIERARCHY_ENDORSEMENT 0x4000000B
#define HTPM2_HIERARCHY_PLATFORM    0x4000000C
#define HTPM2_HIERARCHY_NULL        0x40000007

htpm2_result htpm2_create_primary(const htpm2_context ctx,
                                  htpm2_transport tp,
                                  htpm2_result prior,
                                  htpm2_session auth_session,
                                  uint32_t hierarchy,
                                  htpm2_key_type type,
                                  const void *auth_value,
                                  size_t auth_value_len,
                                  const void *policy,
                                  size_t policy_len,
                                  htpm2_object *key);

htpm2_result htpm2_create(const htpm2_context ctx,
                          htpm2_transport tp,
                          htpm2_result prior,
                          htpm2_session auth_session,
                          htpm2_object parent,
                          htpm2_key_type type,
                          const void *auth_value,
                          size_t auth_value_len,
                          const void *policy,
                          size_t policy_len,
                          htpm2_object *key);

htpm2_result htpm2_load(const htpm2_context ctx,
                        htpm2_transport tp,
                        htpm2_result prior,
                        htpm2_session auth_session,
                        htpm2_object parent,
                        const void *pub_blob, size_t pub_blob_len,
                        const void *priv_blob, size_t priv_blob_len,
                        htpm2_object *key);

htpm2_result htpm2_read_public(const htpm2_context ctx,
                               htpm2_transport tp,
                               htpm2_result prior,
                               htpm2_object key,
                               void **pub_blob, size_t *pub_blob_len,
                               void **name, size_t *name_len);

/* Pure accessors -- no prior result, no TPM round-trip. */
htpm2_result htpm2_object_get_public(htpm2_object obj,
                                     const void **pub, size_t *pub_len);
htpm2_result htpm2_object_get_private(htpm2_object obj,
                                      const void **priv, size_t *priv_len);
htpm2_result htpm2_object_get_name(htpm2_object obj,
                                   const void **name, size_t *name_len);

htpm2_result htpm2_evict_control(const htpm2_context ctx,
                                 htpm2_transport tp,
                                 htpm2_result prior,
                                 htpm2_session auth_session,
                                 htpm2_object key,
                                 uint32_t persistent_handle);

htpm2_result htpm2_context_save(const htpm2_context ctx,
                                htpm2_transport tp,
                                htpm2_result prior,
                                htpm2_object obj,
                                void **saved, size_t *saved_len);

htpm2_result htpm2_context_load(const htpm2_context ctx,
                                htpm2_transport tp,
                                htpm2_result prior,
                                const void *saved, size_t saved_len,
                                htpm2_object *obj);

void htpm2_object_close(htpm2_object *obj);

htpm2_result htpm2_import(const htpm2_context ctx,
                          htpm2_transport tp,
                          htpm2_result prior,
                          htpm2_session auth_session,
                          htpm2_object parent,
                          const void *pub_blob, size_t pub_blob_len,
                          const void *duplicate, size_t duplicate_len,
                          const void *encrypted_seed,
                          size_t encrypted_seed_len,
                          const void *sym_seed, size_t sym_seed_len,
                          void **priv_blob, size_t *priv_blob_len);

htpm2_result htpm2_duplicate(const htpm2_context ctx,
                             htpm2_transport tp,
                             htpm2_result prior,
                             htpm2_session auth_session,
                             htpm2_object key,
                             htpm2_object new_parent,
                             void **duplicate, size_t *duplicate_len,
                             void **encrypted_seed,
                             size_t *encrypted_seed_len);
```

### Cryptographic Operations

```c
/* --- Attestation --- */

htpm2_result htpm2_quote(const htpm2_context ctx,
                         htpm2_transport tp,
                         htpm2_result prior,
                         htpm2_session auth_session,
                         htpm2_object sign_key,
                         const uint8_t *pcr_selections,
                         size_t pcr_selections_len,
                         const void *qualifying_data,
                         size_t qualifying_data_len,
                         void **quoted, size_t *quoted_len,
                         void **signature, size_t *signature_len);

htpm2_result htpm2_certify(const htpm2_context ctx,
                           htpm2_transport tp,
                           htpm2_result prior,
                           htpm2_session auth_session,
                           htpm2_object object,
                           htpm2_object sign_key,
                           const void *qualifying_data,
                           size_t qualifying_data_len,
                           void **certify_info, size_t *certify_info_len,
                           void **signature, size_t *signature_len);

htpm2_result htpm2_certify_creation(const htpm2_context ctx,
                                    htpm2_transport tp,
                                    htpm2_result prior,
                                    htpm2_session auth_session,
                                    htpm2_object object,
                                    htpm2_object sign_key,
                                    const void *qualifying_data,
                                    size_t qualifying_data_len,
                                    const void *creation_ticket,
                                    size_t creation_ticket_len,
                                    void **certify_info,
                                    size_t *certify_info_len,
                                    void **signature,
                                    size_t *signature_len);

/* Issue an X.509 certificate signed by a TPM key (TPM2_CertifyX509).
 * `partial_cert` is a DER-encoded TBSCertificate with an empty
 * signature field; the TPM completes and signs it.
 * Requires lib/asn1 for DER encoding.
 */
htpm2_result htpm2_certify_x509(const htpm2_context ctx,
                                htpm2_transport tp,
                                htpm2_result prior,
                                htpm2_session auth_session,
                                htpm2_object object,
                                htpm2_object sign_key,
                                const void *partial_cert,
                                size_t partial_cert_len,
                                void **added_to_cert,
                                size_t *added_to_cert_len,
                                void **tbs_digest,
                                size_t *tbs_digest_len,
                                void **signature,
                                size_t *signature_len);

/* --- Signing / Verification --- */

htpm2_result htpm2_sign(const htpm2_context ctx,
                        htpm2_transport tp,
                        htpm2_result prior,
                        htpm2_session auth_session,
                        htpm2_object sign_key,
                        const void *digest, size_t digest_len,
                        void **signature, size_t *signature_len);

htpm2_result htpm2_verify_signature(const htpm2_context ctx,
                                    htpm2_transport tp,
                                    htpm2_result prior,
                                    htpm2_object verify_key,
                                    const void *digest, size_t digest_len,
                                    const void *signature,
                                    size_t signature_len,
                                    void **validation_ticket,
                                    size_t *validation_ticket_len);

/* --- Decryption --- */

htpm2_result htpm2_rsa_decrypt(const htpm2_context ctx,
                               htpm2_transport tp,
                               htpm2_result prior,
                               htpm2_session auth_session,
                               htpm2_object key,
                               const void *ciphertext,
                               size_t ciphertext_len,
                               void **plaintext,
                               size_t *plaintext_len);

htpm2_result htpm2_ecdh_zgen(const htpm2_context ctx,
                             htpm2_transport tp,
                             htpm2_result prior,
                             htpm2_session auth_session,
                             htpm2_object key,
                             const void *peer_point,
                             size_t peer_point_len,
                             void **shared_secret,
                             size_t *shared_secret_len);

/* --- Credential --- */

/* Software-only MakeCredential (no TPM round-trip needed).
 * No transport required.  No prior result chaining (pure computation).
 */
htpm2_result htpm2_make_credential(const htpm2_context ctx,
                                   const void *ek_pub,
                                   size_t ek_pub_len,
                                   const void *credential,
                                   size_t credential_len,
                                   const void *key_name,
                                   size_t key_name_len,
                                   void **credential_blob,
                                   size_t *credential_blob_len,
                                   void **encrypted_secret,
                                   size_t *encrypted_secret_len);

htpm2_result htpm2_activate_credential(const htpm2_context ctx,
                                       htpm2_transport tp,
                                       htpm2_result prior,
                                       htpm2_session auth_session_ak,
                                       htpm2_session auth_session_ek,
                                       htpm2_object activate_key,
                                       htpm2_object key_handle,
                                       const void *credential_blob,
                                       size_t credential_blob_len,
                                       const void *encrypted_secret,
                                       size_t encrypted_secret_len,
                                       void **credential,
                                       size_t *credential_len);
```

### PCR Operations

```c
htpm2_result htpm2_pcr_read(const htpm2_context ctx,
                            htpm2_transport tp,
                            htpm2_result prior,
                            const uint8_t *pcr_selections,
                            size_t pcr_selections_len,
                            void **pcr_values,
                            size_t *pcr_values_len,
                            uint32_t *update_counter);

htpm2_result htpm2_pcr_extend(const htpm2_context ctx,
                              htpm2_transport tp,
                              htpm2_result prior,
                              htpm2_session auth_session,
                              uint32_t pcr_index,
                              uint16_t hash_alg,
                              const void *digest,
                              size_t digest_len);
```

### Utility Operations

```c
htpm2_result htpm2_get_random(const htpm2_context ctx,
                              htpm2_transport tp,
                              htpm2_result prior,
                              void *buf, size_t len);

htpm2_result htpm2_hash(const htpm2_context ctx,
                        htpm2_transport tp,
                        htpm2_result prior,
                        uint16_t hash_alg,
                        const void *data, size_t data_len,
                        void *digest, size_t *digest_len,
                        void **validation_ticket,
                        size_t *validation_ticket_len);
```

### PCR Selection Helpers

```c
typedef struct htpm2_pcr_selection_data *htpm2_pcr_selection;

htpm2_result htpm2_pcr_selection_create(const htpm2_context ctx,
                                        uint16_t hash_alg,
                                        htpm2_pcr_selection *sel);
htpm2_result htpm2_pcr_selection_add(htpm2_pcr_selection sel,
                                     uint32_t pcr_index);
htpm2_result htpm2_pcr_selection_encode(htpm2_pcr_selection sel,
                                        void **encoded,
                                        size_t *encoded_len);
void         htpm2_pcr_selection_free(htpm2_pcr_selection *sel);
```

### Memory Management

```c
void htpm2_free(const htpm2_context ctx, void *ptr);
```

## Internal Architecture (Not Exposed in Public API)

### Cryptographic Primitives (`crypto.c`)

`lib/htpm2/` uses OpenSSL's `libcrypto` directly (OpenSSL 3.0+), following
the same pattern as `lib/hx509/` and `lib/krb5/`.

The internal crypto module provides:

| Primitive | OpenSSL API | Used For |
|-----------|-------------|----------|
| SHA-256/384/512 | `EVP_DigestInit/Update/Final` | Object names, policy digests, KDFa |
| HMAC-SHA-256/384/512 | `EVP_MAC` | Session auth, KDFa, credential HMAC |
| KDFa (SP 800-108 counter HMAC-KDF) | Built on `EVP_MAC` | Session key derivation, param encrypt keys |
| AES-128/256-CFB | `EVP_EncryptInit` with `EVP_aes_*_cfb128()` | Parameter encryption, credential encryption |
| RSA OAEP | `EVP_PKEY_encrypt` with `RSA_PKCS1_OAEP_PADDING` | Software MakeCredential |
| ECDH key agreement | `EVP_PKEY_derive` | Salted sessions with ECC EK |
| Random bytes | `RAND_bytes()` | Nonce generation |

The context caches `EVP_MD` / `EVP_CIPHER` pointers, following the same
pattern as `hx509_context` and `krb5_context`.  Since the context is
read-only after init, these cached pointers are safe for concurrent access.

### Marshalling Layer (`marshal.c`)

Uses `heim_storage` from `lib/base/` (a copy of `krb5_storage` with the
prefix replaced).  All TPM structures are big-endian packed:

- `heim_store_uint8/16/32()`, `heim_ret_uint8/16/32()`
- `htpm2_store_tpm2b()`, `htpm2_ret_tpm2b()` (TPM-specific wrappers)
- Per-structure marshal/unmarshal functions

### Command Layer (`command.c`)

Constructs full TPM command packets:
1. Marshal header (tag, size, command code)
2. Marshal handles
3. Marshal authorization area (if sessions present)
4. Marshal command parameters
5. Send via transport, receive response
6. Unmarshal response, verify authorization HMACs
7. Return `htpm2_result` with appropriate error dimension flags

### Session Crypto (`session_crypto.c`)

Uses the internal crypto module for all session crypto:
- KDFa for session key derivation
- HMAC for command/response authorization
- AES-CFB for parameter encryption/decryption
- `RAND_bytes()` for nonce generation

### Software Implementations (`soft.c`)

- `htpm2_make_credential()` -- RSA OAEP + KDFa + AES-CFB + HMAC
- Any other operations that can be done without TPM secrets

## Async I/O Future Path

The design accommodates future async I/O without ABI breakage:

1. Any function may return a result with `HTPM2_F_WOULDBLOCK` set.
2. Caller retrieves fds via `htpm2_transport_get_{read,write}_fd()`.
3. After poll/select indicates readiness, caller retries the same call.
4. Internal state machines track in-progress operations on the transport.

Today, all transports block, so `HTPM2_F_WOULDBLOCK` is never set.
