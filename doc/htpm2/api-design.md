# htpm2 API Design

## Overview

`lib/htpm2/` is a C library providing a simple, self-contained interface to
TPM 2.0 hardware and software TPMs.  It follows Heimdal's library conventions:
opaque context objects, integer error codes with context-stored error strings,
explicit resource management.  Its dependencies are `lib/roken/`, `lib/base/`,
and OpenSSL's `libcrypto` (used directly for cryptographic primitives, just as
`lib/hx509/` and `lib/krb5/` each use `libcrypto` directly).

The library handles TPM 2.0 command marshalling/unmarshalling, transport I/O,
session management (HMAC, policy, trial), encrypted and authenticated sessions,
and exposes high-level operations for key management, attestation, and
credential activation.

## Design Principles

1. **Minimal dependencies** -- `lib/roken/`, `lib/base/`, and OpenSSL's
   `libcrypto` (directly, for cryptographic primitives).  No Intel TSS, no
   dependency on `lib/hx509/` or `lib/krb5/`.  This follows the same pattern
   as `lib/hx509/` and `lib/krb5/`, which each have their own direct
   `libcrypto` usage for the primitives they need.  The crypto primitives
   needed (HMAC, AES-CFB, RSA OAEP, ECDH, SHA-2, KDFa) are implemented in
   `lib/htpm2/` itself using OpenSSL's EVP APIs.

2. **Opaque types** -- all public types are `typedef`'d pointers to internal
   structures.  Users never see structure layouts.

3. **Context-centric** -- every function takes an `htpm2_context` (or a
   session/object derived from one).  Error messages are stored on the context.

4. **Synchronous with future-async readiness** -- all I/O is synchronous today.
   Functions may return `HTPM2_ERR_WOULDBLOCK`; callers can obtain file
   descriptors to poll via accessors on the context/transport, enabling a
   future async path without ABI breakage.

5. **Encrypted + authenticated sessions by default** -- the API makes it easy
   (and the default) to use HMAC sessions with parameter encryption to defeat
   active bus-level attackers.

6. **Software-only where possible** -- operations like `MakeCredential` that
   don't require TPM secrets are implemented in software using `libcrypto`
   primitives directly, avoiding a round-trip to the TPM.

## Public Header: `<htpm2.h>`

### Error Codes

```c
/* All functions return htpm2_error_code (int32_t).  0 = success. */
typedef int32_t htpm2_error_code;

#define HTPM2_ERR_WOULDBLOCK    (-1)   /* retry after poll */
#define HTPM2_ERR_TPM_BASE      0x100  /* TPM RC codes offset */
```

Error messages are retrievable from the context:

```c
const char *htpm2_get_error_string(htpm2_context, htpm2_error_code);
void        htpm2_free_error_string(htpm2_context, const char *);
void        htpm2_clear_error_string(htpm2_context);
```

### Context

```c
typedef struct htpm2_context_data *htpm2_context;

htpm2_error_code htpm2_context_init(htpm2_context *ctx);
void             htpm2_context_free(htpm2_context *ctx);
```

The context owns global state: configuration, error strings, default hash
algorithm, logging.

### Transport

The transport abstraction decouples command execution from the physical
channel.  Built-in transports:

- **device** -- `/dev/tpm0`, `/dev/tpmrm0` (Linux), or the Windows TBS API.
- **socket** -- AF_LOCAL / AF_INET stream socket (for `swtpm` in socket mode).
- **pipe** -- stdin/stdout pair connected to a child process (for `swtpm`,
  or `ssh host swtpm socket ...`).

```c
typedef struct htpm2_transport_data *htpm2_transport;

/* Open a transport by URI-style string:
 *   "device:/dev/tpmrm0"
 *   "socket:/run/swtpm-sock"
 *   "pipe:swtpm socket --tpmstate dir=..."
 *   "pipe:ssh remotehost swtpm socket ..."
 *   "tcp:host:port"
 */
htpm2_error_code htpm2_transport_open(htpm2_context ctx,
                                      const char *uri,
                                      htpm2_transport *tp);
void             htpm2_transport_close(htpm2_transport *tp);

/* For future async I/O: retrieve fd(s) to poll when WOULDBLOCK. */
htpm2_error_code htpm2_transport_get_read_fd(htpm2_transport tp, int *fd);
htpm2_error_code htpm2_transport_get_write_fd(htpm2_transport tp, int *fd);
```

A pluggable transport vtable is available for custom transports:

```c
typedef struct htpm2_transport_ops {
    const char *name;
    htpm2_error_code (*open)(htpm2_context, const char *arg,
                             htpm2_transport *);
    htpm2_error_code (*send_recv)(htpm2_transport,
                                  const void *cmd, size_t cmd_len,
                                  void *rsp, size_t *rsp_len);
    htpm2_error_code (*get_read_fd)(htpm2_transport, int *fd);
    htpm2_error_code (*get_write_fd)(htpm2_transport, int *fd);
    void             (*close)(htpm2_transport *);
} htpm2_transport_ops;

htpm2_error_code htpm2_transport_register(htpm2_context ctx,
                                          const htpm2_transport_ops *ops);
```

### Sessions

Sessions are first-class objects bound to a transport (and thus a TPM).

```c
typedef struct htpm2_session_data *htpm2_session;

/* Session types */
typedef enum {
    HTPM2_SESSION_HMAC    = 0,  /* HMAC authorization session */
    HTPM2_SESSION_POLICY  = 1,  /* Policy session */
    HTPM2_SESSION_TRIAL   = 2   /* Trial policy session (compute digest only) */
} htpm2_session_type;

/* Session flags */
#define HTPM2_SESSION_ENCRYPT       0x01  /* Parameter encryption */
#define HTPM2_SESSION_DECRYPT       0x02  /* Parameter decryption */
#define HTPM2_SESSION_AUDIT         0x04  /* Audit session */
#define HTPM2_SESSION_CONTINUE      0x08  /* Keep session alive after use */
#define HTPM2_SESSION_ENC_DEC       (HTPM2_SESSION_ENCRYPT | HTPM2_SESSION_DECRYPT)

/* Start a session.
 * `bind` may be NULL (unbound session).
 * `salt_key` may be NULL (no salting -- less secure).
 * Default flags include ENCRYPT|DECRYPT for HMAC sessions.
 */
htpm2_error_code htpm2_session_start(htpm2_context ctx,
                                     htpm2_transport tp,
                                     htpm2_session_type type,
                                     htpm2_object salt_key,    /* optional EK for salting */
                                     htpm2_object bind,        /* optional bind entity */
                                     unsigned int flags,
                                     htpm2_session *session);

/* Flush a session (releases TPM handle). */
void htpm2_session_close(htpm2_session *session);

/* Retrieve the policy digest from a trial or policy session. */
htpm2_error_code htpm2_session_get_policy_digest(htpm2_session session,
                                                 void *digest,
                                                 size_t *digest_len);
```

### Policy Commands

Policy commands operate on policy or trial sessions to build a policy digest.

```c
/* Bind session to PCR values. `pcr_digest` may be NULL to read current. */
htpm2_error_code htpm2_policy_pcr(htpm2_session session,
                                  const uint8_t *pcr_selections,
                                  size_t pcr_selections_len,
                                  const void *pcr_digest,
                                  size_t pcr_digest_len);

/* Restrict to a specific command code. */
htpm2_error_code htpm2_policy_command_code(htpm2_session session,
                                           uint32_t command_code);

/* Authorize policy via a signing key. */
htpm2_error_code htpm2_policy_authorize(htpm2_session session,
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

/* Authorize via an external signature. */
htpm2_error_code htpm2_policy_signed(htpm2_session session,
                                     htpm2_object auth_key,
                                     const void *policy_ref,
                                     size_t policy_ref_len,
                                     int32_t expiration,
                                     const void *signature,
                                     size_t signature_len);

/* Authorize via entity's authValue (password/secret). */
htpm2_error_code htpm2_policy_secret(htpm2_session session,
                                     htpm2_object auth_entity,
                                     const void *policy_ref,
                                     size_t policy_ref_len,
                                     int32_t expiration);

/* Logical OR of multiple policy branches. */
htpm2_error_code htpm2_policy_or(htpm2_session session,
                                 const void **digests,
                                 const size_t *digest_lens,
                                 size_t num_digests);
```

### Key / Object Management

Objects represent TPM keys and other entities.

```c
typedef struct htpm2_object_data *htpm2_object;

/* Key types for creation */
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

/* Well-known hierarchies */
#define HTPM2_HIERARCHY_OWNER       0x40000001
#define HTPM2_HIERARCHY_ENDORSEMENT 0x4000000B
#define HTPM2_HIERARCHY_PLATFORM    0x4000000C
#define HTPM2_HIERARCHY_NULL        0x40000007

/* Create a primary key under a hierarchy.
 * `auth_session` is the authorization session for the hierarchy.
 * `auth_value` is the new key's password (may be NULL).
 * `policy` is the new key's authorization policy digest (may be NULL).
 */
htpm2_error_code htpm2_create_primary(htpm2_context ctx,
                                      htpm2_transport tp,
                                      htpm2_session auth_session,
                                      uint32_t hierarchy,
                                      htpm2_key_type type,
                                      const void *auth_value,
                                      size_t auth_value_len,
                                      const void *policy,
                                      size_t policy_len,
                                      htpm2_object *key);

/* Create a child key under a parent.
 * Returns public+private blobs that can be persisted to disk.
 */
htpm2_error_code htpm2_create(htpm2_context ctx,
                              htpm2_transport tp,
                              htpm2_session auth_session,
                              htpm2_object parent,
                              htpm2_key_type type,
                              const void *auth_value,
                              size_t auth_value_len,
                              const void *policy,
                              size_t policy_len,
                              htpm2_object *key);

/* Load a previously created key. */
htpm2_error_code htpm2_load(htpm2_context ctx,
                            htpm2_transport tp,
                            htpm2_session auth_session,
                            htpm2_object parent,
                            const void *pub_blob, size_t pub_blob_len,
                            const void *priv_blob, size_t priv_blob_len,
                            htpm2_object *key);

/* Read the public area of a loaded object. */
htpm2_error_code htpm2_read_public(htpm2_context ctx,
                                   htpm2_transport tp,
                                   htpm2_object key,
                                   void **pub_blob, size_t *pub_blob_len,
                                   void **name, size_t *name_len);

/* Retrieve the serialized public/private blobs from an object.
 * (Available after htpm2_create; the blobs are cached on the object.) */
htpm2_error_code htpm2_object_get_public(htpm2_object obj,
                                         const void **pub, size_t *pub_len);
htpm2_error_code htpm2_object_get_private(htpm2_object obj,
                                          const void **priv, size_t *priv_len);
htpm2_error_code htpm2_object_get_name(htpm2_object obj,
                                       const void **name, size_t *name_len);

/* Make a persistent key (TPM2_EvictControl). */
htpm2_error_code htpm2_evict_control(htpm2_context ctx,
                                     htpm2_transport tp,
                                     htpm2_session auth_session,
                                     htpm2_object key,
                                     uint32_t persistent_handle);

/* Context save/load for swapping objects. */
htpm2_error_code htpm2_context_save(htpm2_context ctx,
                                    htpm2_transport tp,
                                    htpm2_object obj,
                                    void **saved, size_t *saved_len);
htpm2_error_code htpm2_context_load(htpm2_context ctx,
                                    htpm2_transport tp,
                                    const void *saved, size_t saved_len,
                                    htpm2_object *obj);

/* Flush an object's TPM handle. */
void htpm2_object_close(htpm2_object *obj);

/* Import an external key into the TPM under a parent. */
htpm2_error_code htpm2_import(htpm2_context ctx,
                              htpm2_transport tp,
                              htpm2_session auth_session,
                              htpm2_object parent,
                              const void *pub_blob, size_t pub_blob_len,
                              const void *duplicate, size_t duplicate_len,
                              const void *encrypted_seed,
                              size_t encrypted_seed_len,
                              const void *sym_seed, size_t sym_seed_len,
                              void **priv_blob, size_t *priv_blob_len);

/* Duplicate a key for use under a different parent. */
htpm2_error_code htpm2_duplicate(htpm2_context ctx,
                                 htpm2_transport tp,
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

/* Create a PCR quote signed by `sign_key`. */
htpm2_error_code htpm2_quote(htpm2_context ctx,
                             htpm2_transport tp,
                             htpm2_session auth_session,
                             htpm2_object sign_key,
                             const uint8_t *pcr_selections,
                             size_t pcr_selections_len,
                             const void *qualifying_data,
                             size_t qualifying_data_len,
                             void **quoted, size_t *quoted_len,
                             void **signature, size_t *signature_len);

/* Certify that an object is loaded and genuine. */
htpm2_error_code htpm2_certify(htpm2_context ctx,
                               htpm2_transport tp,
                               htpm2_session auth_session,
                               htpm2_object object,
                               htpm2_object sign_key,
                               const void *qualifying_data,
                               size_t qualifying_data_len,
                               void **certify_info, size_t *certify_info_len,
                               void **signature, size_t *signature_len);

/* Certify the creation data of an object. */
htpm2_error_code htpm2_certify_creation(htpm2_context ctx,
                                        htpm2_transport tp,
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

/* --- Signing / Verification --- */

htpm2_error_code htpm2_sign(htpm2_context ctx,
                            htpm2_transport tp,
                            htpm2_session auth_session,
                            htpm2_object sign_key,
                            const void *digest, size_t digest_len,
                            void **signature, size_t *signature_len);

htpm2_error_code htpm2_verify_signature(htpm2_context ctx,
                                        htpm2_transport tp,
                                        htpm2_object verify_key,
                                        const void *digest, size_t digest_len,
                                        const void *signature,
                                        size_t signature_len,
                                        void **validation_ticket,
                                        size_t *validation_ticket_len);

/* --- Decryption --- */

htpm2_error_code htpm2_rsa_decrypt(htpm2_context ctx,
                                   htpm2_transport tp,
                                   htpm2_session auth_session,
                                   htpm2_object key,
                                   const void *ciphertext,
                                   size_t ciphertext_len,
                                   void **plaintext,
                                   size_t *plaintext_len);

htpm2_error_code htpm2_ecdh_zgen(htpm2_context ctx,
                                 htpm2_transport tp,
                                 htpm2_session auth_session,
                                 htpm2_object key,
                                 const void *peer_point,
                                 size_t peer_point_len,
                                 void **shared_secret,
                                 size_t *shared_secret_len);

/* --- Credential --- */

/* Software-only MakeCredential (no TPM round-trip needed).
 * Encrypts `credential` for the EK whose public area is `ek_pub`,
 * binding it to the object whose name is `key_name`.
 */
htpm2_error_code htpm2_make_credential(htpm2_context ctx,
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

/* ActivateCredential -- requires TPM (needs EK and AK). */
htpm2_error_code htpm2_activate_credential(htpm2_context ctx,
                                           htpm2_transport tp,
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
htpm2_error_code htpm2_pcr_read(htpm2_context ctx,
                                htpm2_transport tp,
                                const uint8_t *pcr_selections,
                                size_t pcr_selections_len,
                                void **pcr_values,
                                size_t *pcr_values_len,
                                uint32_t *update_counter);

htpm2_error_code htpm2_pcr_extend(htpm2_context ctx,
                                  htpm2_transport tp,
                                  htpm2_session auth_session,
                                  uint32_t pcr_index,
                                  uint16_t hash_alg,
                                  const void *digest,
                                  size_t digest_len);
```

### Utility Operations

```c
/* TPM random number generation. */
htpm2_error_code htpm2_get_random(htpm2_context ctx,
                                  htpm2_transport tp,
                                  void *buf, size_t len);

/* TPM-based hashing. */
htpm2_error_code htpm2_hash(htpm2_context ctx,
                            htpm2_transport tp,
                            uint16_t hash_alg,
                            const void *data, size_t data_len,
                            void *digest, size_t *digest_len,
                            void **validation_ticket,
                            size_t *validation_ticket_len);
```

### PCR Selection Helpers

```c
/* Helper to build PCR selection bitmasks. */
typedef struct htpm2_pcr_selection_data *htpm2_pcr_selection;

htpm2_error_code htpm2_pcr_selection_create(htpm2_context ctx,
                                            uint16_t hash_alg,
                                            htpm2_pcr_selection *sel);
htpm2_error_code htpm2_pcr_selection_add(htpm2_pcr_selection sel,
                                         uint32_t pcr_index);
htpm2_error_code htpm2_pcr_selection_encode(htpm2_pcr_selection sel,
                                            void **encoded,
                                            size_t *encoded_len);
void             htpm2_pcr_selection_free(htpm2_pcr_selection *sel);
```

### Memory Management

```c
/* Free a buffer allocated by htpm2 functions. */
void htpm2_free(htpm2_context ctx, void *ptr);
```

## Internal Architecture (Not Exposed in Public API)

### Cryptographic Primitives (`crypto.c`)

`lib/htpm2/` uses OpenSSL's `libcrypto` directly for all cryptographic
operations, following the same pattern as `lib/hx509/` and `lib/krb5/`.
This avoids creating a dependency on `lib/hx509/` (which is a PKI library,
not a general crypto wrapper) and keeps `lib/htpm2/` self-contained.

The internal crypto module (`lib/htpm2/crypto.c`) provides:

| Primitive | OpenSSL API | Used For |
|-----------|-------------|----------|
| SHA-256/384/512 | `EVP_DigestInit/Update/Final` | Object names, policy digests, KDFa |
| HMAC-SHA-256/384/512 | `EVP_MAC` or `HMAC()` | Session auth, KDFa, credential HMAC |
| KDFa (SP 800-108 counter HMAC-KDF) | Built on HMAC | Session key derivation, param encrypt keys |
| AES-128/256-CFB | `EVP_EncryptInit` with `EVP_aes_*_cfb128()` | Parameter encryption, credential encryption |
| RSA OAEP | `EVP_PKEY_encrypt` with `RSA_PKCS1_OAEP_PADDING` | Software MakeCredential (encrypt seed to EK) |
| ECDH key agreement | `EVP_PKEY_derive` | Salted sessions with ECC EK |
| Random bytes | `RAND_bytes()` | Nonce generation |

The context (`htpm2_context`) caches OpenSSL objects (like `EVP_MD` pointers)
following the same pattern as `hx509_context` and `krb5_context`.

### Marshalling Layer (`marshal.c`)

Uses a `krb5_storage`-style marshalling abstraction (moved to or duplicated in
`lib/base/` as `heim_storage`).  All TPM structures are big-endian packed:

- `htpm2_store_uint8/16/32()`, `htpm2_ret_uint8/16/32()`
- `htpm2_store_tpm2b()`, `htpm2_ret_tpm2b()`
- Per-structure marshal/unmarshal functions

### Command Layer (`command.c`)

Constructs full TPM command packets:
1. Marshal header (tag, size, command code)
2. Marshal handles
3. Marshal authorization area (if sessions present)
4. Marshal command parameters
5. Send via transport, receive response
6. Unmarshal response, verify authorization HMACs

### Session Crypto (`session_crypto.c`)

Uses the internal crypto module (`crypto.c`) for all session crypto:
- KDFa for session key derivation
- HMAC for command/response authorization
- AES-CFB for parameter encryption/decryption
- `RAND_bytes()` for nonce generation

### Software Implementations (`soft.c`)

- `htpm2_make_credential()` -- RSA OAEP encrypt + KDFa + AES-CFB + HMAC,
  all via the internal crypto module using `libcrypto` directly
- Any other operations that can be done without TPM secrets

## Async I/O Future Path

The design accommodates future async I/O without ABI breakage:

1. Any function may return `HTPM2_ERR_WOULDBLOCK`.
2. Caller retrieves fds via `htpm2_transport_get_{read,write}_fd()`.
3. After poll/select indicates readiness, caller retries the same call.
4. Internal state machines track in-progress operations on the transport.

Today, all transports block, so `HTPM2_ERR_WOULDBLOCK` is never returned.
