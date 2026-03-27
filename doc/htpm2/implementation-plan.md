# htpm2 Implementation Plan

## Phase 0: Infrastructure and Build System

### 0.1 Directory and Build Setup

Create:
```
lib/htpm2/
  Makefile.am
  htpm2.h              -- public API header
  htpm2_locl.h         -- internal header
  htpm2_err.et         -- error table (com_err)
  version-script.map   -- symbol versioning
```

Wire into:
- `lib/Makefile.am` -- add `htpm2` to `SUBDIRS`
- `configure.ac` -- add `lib/htpm2/Makefile` to `AC_CONFIG_FILES`, add
  `--enable-tpm2` / `--disable-tpm2` configure flag (default auto based on
  platform)

Library target: `libhtpm2.la` linking against `libheimbase.la`,
`$(LIBADD_roken)`, and `$(LIB_openssl_crypto)`.  No Intel TSS, no dependency
on `lib/hx509/`.  `lib/htpm2/` uses OpenSSL's `libcrypto` directly for its
cryptographic primitives, following the same pattern as `lib/hx509/` and
`lib/krb5/`.

### 0.2 Storage/Marshalling Primitives

Evaluate whether to:
- **(a)** Move `krb5_storage` APIs to `lib/base/` as `heim_storage`, or
- **(b)** Write a minimal marshalling layer directly in `lib/htpm2/`.

Option (b) is simpler and avoids cross-library churn.  The marshalling needs
are limited: big-endian `uint8/16/32`, sized byte buffers (`TPM2B`), and
composite structure pack/unpack.  Recommend **(b)** initially, with the option
to refactor to a shared `heim_storage` later if other new libraries need the
same thing.

Files:
```
lib/htpm2/marshal.c     -- marshalling primitives
lib/htpm2/marshal.h     -- internal marshalling header
```

### 0.3 Crypto Primitives (Internal to `lib/htpm2/`)

`lib/htpm2/` uses OpenSSL's `libcrypto` directly for all cryptographic
primitives, following the same pattern as `lib/hx509/` and `lib/krb5/`.
This is cleaner than routing through `lib/hx509/` (which is a PKI library,
not a general crypto wrapper) and avoids creating an unnecessary dependency.

Implement in `lib/htpm2/crypto.c` (internal, not part of the public API):

- **SHA-256/384/512** via `EVP_DigestInit/Update/Final` with `EVP_sha256()`
  etc.  Cache `EVP_MD` pointers on the `htpm2_context`, same as hx509 and
  krb5 do.  ~40 lines.

- **Standalone HMAC** via OpenSSL's `EVP_MAC` API (OpenSSL 3.x) or the
  legacy `HMAC()` function.  ~30 lines.

- **AES-128/256-CFB** via `EVP_EncryptInit_ex`/`EVP_DecryptInit_ex` with
  `EVP_aes_128_cfb128()` / `EVP_aes_256_cfb128()`.  ~80 lines.

- **RSA OAEP encryption** via `EVP_PKEY_encrypt()` with
  `EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING)` and
  `EVP_PKEY_CTX_set_rsa_oaep_md()`.  The TPM uses OAEP with SHA-256 and
  a label of `"IDENTITY\0"` for MakeCredential.  Need to parse the EK's
  `TPM2B_PUBLIC` to construct an `EVP_PKEY` from the raw RSA modulus/exponent.
  ~100 lines.

- **ECDH key agreement** via `EVP_PKEY_derive()`.  Need to construct
  `EVP_PKEY` from raw ECC point in `TPM2B_PUBLIC`.  ~60 lines.

- **KDFa** (TPM 2.0's NIST SP 800-108 counter-mode HMAC-KDF).  Built on
  top of the HMAC primitive above.  ~40 lines.

- **Random bytes** via `RAND_bytes()`.  Trivial wrapper.

Files:
```
lib/htpm2/crypto.c      -- all crypto primitives (internal)
lib/htpm2/crypto.h      -- internal crypto header
```

## Phase 1: Transport Layer

### 1.1 Transport Abstraction

Implement the transport vtable and dispatching.

Files:
```
lib/htpm2/transport.c   -- transport open/close, registry, dispatch
```

### 1.2 Device Transport (Linux)

Simple `open()` / `read()` / `write()` on `/dev/tpm0` or `/dev/tpmrm0`.
The kernel TPM driver expects: write full command, read full response.

```
lib/htpm2/transport_device.c
```

### 1.3 Socket Transport

AF_LOCAL and AF_INET stream sockets.  `swtpm` in socket mode listens on a
Unix domain socket.  Protocol: 4-byte big-endian length prefix, then TPM
command bytes.  (Note: `swtpm` socket mode uses a slightly different protocol
than raw TPM; we'll handle this with a flag or auto-detection.)

```
lib/htpm2/transport_socket.c
```

### 1.4 Pipe Transport

`fork()` + `exec()` a child process (e.g., `swtpm socket --server type=pipe`),
communicating via `stdin`/`stdout` pipes.  On Windows, use `CreateProcess`
with redirected handles.

```
lib/htpm2/transport_pipe.c
```

### 1.5 Windows TBS Transport

Use the Windows TPM Base Services (TBS) API: `Tbsi_Context_Create()`,
`Tbsi_Submit_Command()`.

```
lib/htpm2/transport_tbs.c   -- #ifdef _WIN32
```

## Phase 2: Core Command Infrastructure

### 2.1 Command Execution Engine

The core loop for executing TPM commands:

1. Build command buffer (header + handles + auth area + parameters)
2. Send via transport
3. Receive response
4. Parse response header, check RC
5. Verify response auth area HMAC (if session present)
6. Decrypt response parameters (if encrypted session)
7. Unmarshal response parameters

Files:
```
lib/htpm2/command.c      -- command build/execute/parse
```

### 2.2 Session Management

Internal tracking of session state:
- Session handle (TPM handle)
- Session type
- nonceCaller, nonceTPM (updated each exchange)
- Session key (derived from authValue + salt via KDFa)
- Symmetric algorithm for parameter encryption
- Session attributes (encrypt, decrypt, continue, audit)
- Bound entity (if any)

Files:
```
lib/htpm2/session.c      -- session start/close, HMAC compute, nonce mgmt
lib/htpm2/session_crypto.c -- KDFa, param encrypt/decrypt, HMAC (via crypto.c)
```

### 2.3 Object Management

Internal tracking of loaded objects:
- TPM handle
- Public area (cached `TPM2B_PUBLIC`)
- Private area (cached `TPM2B_PRIVATE`, for objects we created)
- Name (hash of public area)
- Auth value
- Creation data / ticket (for objects we created)

Files:
```
lib/htpm2/object.c       -- object lifecycle, accessors
```

## Phase 3: Key Operations

### 3.1 CreatePrimary

`TPM2_CreatePrimary` -- create primary keys under Owner, Endorsement,
Platform, or Null hierarchies.  Requires building `TPMT_PUBLIC` (the
template) from the `htpm2_key_type` enum plus optional policy digest.

Build standard templates for:
- RSA-2048 / RSA-3072 signing, decryption, storage keys
- ECC P-256 / P-384 signing, decryption, storage keys
- HMAC-SHA256 keyed-hash keys

Files:
```
lib/htpm2/key_templates.c  -- standard TPMT_PUBLIC templates
lib/htpm2/create.c          -- CreatePrimary, Create
```

### 3.2 Create (Child Keys)

`TPM2_Create` under a loaded parent.  Returns `TPM2B_PUBLIC` + `TPM2B_PRIVATE`
blobs that the caller can persist.

### 3.3 Load

`TPM2_Load` -- load a key from public+private blobs under its parent.

### 3.4 Import / Duplicate

`TPM2_Import` -- import externally-created keys.
`TPM2_Duplicate` -- re-wrap a key for a different parent.

### 3.5 EvictControl

`TPM2_EvictControl` -- make transient keys persistent (or evict persistent
keys).

### 3.6 ContextSave / ContextLoad / FlushContext

Context management for swapping objects in and out of TPM memory.

## Phase 4: Cryptographic Operations

### 4.1 Quote

`TPM2_Quote` -- PCR attestation.  Takes signing key + PCR selection +
qualifying data, returns `TPMS_ATTEST` + signature.

### 4.2 Sign / VerifySignature

`TPM2_Sign` -- sign a digest.
`TPM2_VerifySignature` -- verify with a loaded TPM key (returns ticket).

### 4.3 RSA_Decrypt / ECDH_ZGen

`TPM2_RSA_Decrypt` -- RSA decryption.
`TPM2_ECDH_ZGen` -- ECDH shared secret computation.

### 4.4 Certify / CertifyCreation

`TPM2_Certify` -- prove an object is loaded.
`TPM2_CertifyCreation` -- prove creation data matches.

### 4.5 MakeCredential (Software)

Implement in software using the internal crypto module (`crypto.c`):
1. Generate random seed via `RAND_bytes()`
2. RSA-OAEP encrypt seed with EK public key, label `"IDENTITY\0"`
   (via `EVP_PKEY_encrypt` with OAEP padding)
3. Derive symmetric key and HMAC key from seed via KDFa
4. Encrypt credential with AES-CFB
5. Compute HMAC over encrypted credential and object name

### 4.6 ActivateCredential

`TPM2_ActivateCredential` -- requires both EK and AK sessions, policy
session for EK if the EK has a policy (standard EK templates do).

## Phase 5: PCR and Utility Operations

### 5.1 PCR Read / Extend

`TPM2_PCR_Read`, `TPM2_PCR_Extend`.

### 5.2 GetRandom / Hash

`TPM2_GetRandom`, `TPM2_Hash`.

### 5.3 ReadPublic

`TPM2_ReadPublic` -- read public area of any loaded handle.

## Phase 6: Policy Operations

### 6.1 PolicyPCR

Bind a policy session to specific PCR values.

### 6.2 PolicyCommandCode

Restrict policy to specific command(s).

### 6.3 PolicyAuthorize

Enable authorized policy updates (flexible policies).

### 6.4 PolicySigned / PolicySecret

External signer authorization and TPM-entity-secret authorization.

### 6.5 PolicyOR

Logical OR of policy branches.

## Phase 7: Error Handling and Diagnostics

### 7.1 Error Table

Define `htpm2_err.et` with error codes using Heimdal's `com_err` system:
- Transport errors
- Marshalling errors
- Session errors
- TPM response code translation

### 7.2 TPM RC Decoding

Translate TPM2 response codes into human-readable error strings stored on
the context via `heim_set_error_message()`.

### 7.3 Logging

Use `heim_log_facility` for debug/trace logging of:
- Commands sent (command code, handles)
- Responses received (RC, timing)
- Session state transitions

## Phase 8: Documentation

### 8.1 Man Pages

One man page per public function (or grouped by topic), in the style of
Heimdal's existing `lib/krb5/` and `lib/hx509/` man pages.

### 8.2 Doxygen

Add doxygen comments to `htpm2.h` and generate API reference.

## Estimated File Count

All files are in `lib/htpm2/` (no changes to `lib/hx509/` needed):

```
lib/htpm2/
  Makefile.am
  htpm2.h                 -- public header
  htpm2_locl.h            -- internal header
  htpm2_err.et            -- error table
  version-script.map      -- symbol export map
  crypto.c / crypto.h     -- internal crypto (SHA, HMAC, AES-CFB, RSA OAEP,
                              ECDH, KDFa) using libcrypto directly
  marshal.c / marshal.h   -- TPM2 structure marshalling
  soft.c                  -- software MakeCredential (uses crypto.c)
  transport.c             -- transport abstraction
  transport_device.c      -- /dev/tpm* transport
  transport_socket.c      -- Unix/TCP socket transport
  transport_pipe.c        -- pipe/subprocess transport
  transport_tbs.c         -- Windows TBS transport
  command.c               -- command build/execute/parse
  session.c               -- session lifecycle
  session_crypto.c        -- session HMAC, param encrypt (uses crypto.c)
  object.c                -- object lifecycle, accessors
  key_templates.c         -- standard key templates
  create.c                -- CreatePrimary, Create
  load.c                  -- Load, ReadPublic
  import.c                -- Import, Duplicate
  evict.c                 -- EvictControl
  context_mgmt.c          -- ContextSave/Load, FlushContext
  sign.c                  -- Sign, VerifySignature
  quote.c                 -- Quote
  certify.c               -- Certify, CertifyCreation
  decrypt.c               -- RSA_Decrypt, ECDH_ZGen
  credential.c            -- ActivateCredential
  pcr.c                   -- PCR_Read, PCR_Extend
  random.c                -- GetRandom, Hash
  policy.c                -- all Policy* commands
  error.c                 -- error handling, RC decoding
  context.c               -- htpm2_context init/free
```

## Implementation Order (Recommended)

Implement in this order so each phase can be tested before moving on:

1. **Phase 0.1-0.2**: Build system, marshalling
2. **Phase 0.3**: Internal crypto module (HMAC, AES-CFB, RSA OAEP, ECDH,
   KDFa, SHA-2) using `libcrypto` directly -- with unit tests
3. **Phase 1**: Transport (device + socket -- enough to talk to `swtpm`)
4. **Phase 2**: Command infrastructure + sessions (test with `TPM2_GetRandom`)
5. **Phase 3**: Key creation (test `CreatePrimary` + `Create` + `Load`)
6. **Phase 4**: Crypto operations (test `Sign` + `Quote`)
7. **Phase 5**: PCR + utility ops
8. **Phase 6**: Policy operations (test trial + real policy sessions)
9. **Phase 4 cont.**: `MakeCredential` / `ActivateCredential` (depends on
   policy for EK)
10. **Phase 7**: Error handling polish, logging
11. **Phase 8**: Documentation

## Open Questions

1. **heim_storage**: Should we invest in moving `krb5_storage` to `lib/base/`
   now, or just write a small marshalling layer in `lib/htpm2/`?

2. **ASN.1**: Some TPM attestation output may need to be wrapped in ASN.1
   (e.g., for X.509 certificate issuance).  Should `lib/asn1/` be an optional
   dependency?

3. **Thread safety**: Per Heimdal convention, contexts are single-threaded.
   Should we document this or provide any locking?

4. **OpenSSL version floor**: The crypto module uses EVP APIs.  Should we
   require OpenSSL 3.x (for `EVP_MAC`) or also support OpenSSL 1.1.x (using
   the legacy `HMAC()` API)?  Heimdal currently supports both, so we should
   probably `#ifdef` for both as `lib/hx509/` does.
