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

Library target: `libhtpm2.la` linking against `libhx509.la`,
`libheimbase.la`, and `$(LIBADD_roken)`.  No Intel TSS.  All crypto goes
through `lib/hx509/` (which wraps OpenSSL `libcrypto`); `lib/htpm2/` never
calls OpenSSL directly.

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

### 0.3 Crypto Primitives (Extensions to `lib/hx509/`)

All cryptographic primitives needed by `lib/htpm2/` are provided through
`lib/hx509/`, which wraps OpenSSL's `libcrypto`.  Several primitives that
`lib/hx509/` currently lacks must be added there first.

**Already available in `lib/hx509/`:**
- SHA-256/384/512 (via cached `EVP_MD` objects on `hx509_context`)
- Random bytes (via `RAND_bytes()`)
- RSA PKCS#1 v1.5 encrypt/decrypt
- ECDSA sign/verify
- AES-CBC encrypt/decrypt

**Must be added to `lib/hx509/`** (new file `lib/hx509/crypto-tpm.c` or
extensions to existing `crypto.c`):

- **Standalone HMAC** (`hx509_hmac()`): Currently HMAC is only used
  internally for PBKDF2.  Expose a public standalone HMAC function using
  OpenSSL's `HMAC()` or `EVP_MAC` API.  ~30 lines.

- **AES-CFB mode** (`hx509_aes_cfb_encrypt/decrypt()`): Currently only
  AES-CBC is available.  Add AES-128-CFB and AES-256-CFB using
  `EVP_aes_128_cfb128()` / `EVP_aes_256_cfb128()`.  Extend the existing
  cipher table in `crypto.c` or add dedicated functions.  ~80 lines.

- **RSA OAEP encryption** (`hx509_rsa_oaep_encrypt()`): The existing
  `_hx509_public_encrypt()` uses `RSA_PKCS1_PADDING`; it even has a
  `// XXX Want OEAP instead pls` comment.  Add OAEP support by using
  `EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING)` and
  `EVP_PKEY_CTX_set_rsa_oaep_md()`.  The TPM uses OAEP with SHA-256 and
  a label of `"IDENTITY\0"` for MakeCredential.  ~60 lines.

- **ECDH key agreement** (`hx509_ecdh_derive()`): EC key operations exist
  but ECDH shared-secret derivation is not exposed.  Add a wrapper around
  `EVP_PKEY_derive()`.  ~50 lines.

- **KDFa** (`hx509_kdfa()`): TPM 2.0's key derivation function (NIST
  SP 800-108 counter-mode HMAC-KDF).  Implemented on top of the new
  `hx509_hmac()`.  ~40 lines.  This could alternatively live in
  `lib/htpm2/` since it's TPM-specific, but putting it in `lib/hx509/`
  keeps all crypto in one place.

Files to modify/create in `lib/hx509/`:
```
lib/hx509/crypto.c      -- extend with OAEP, standalone HMAC, AES-CFB
lib/hx509/crypto-ec.c   -- add ECDH derive
lib/hx509/hx509.h       -- declare new public functions
```

No new files are needed in `lib/htpm2/` for crypto -- it all comes from
`lib/hx509/`.

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
lib/htpm2/session_crypto.c -- calls hx509 for KDFa, param encrypt/decrypt, HMAC
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

Implement in software using `lib/hx509/` primitives:
1. Generate random seed (`RAND_bytes()` via hx509)
2. RSA-OAEP encrypt seed with EK public key, label `"IDENTITY\0"`
   (`hx509_rsa_oaep_encrypt()`)
3. Derive symmetric key and HMAC key from seed via KDFa
   (`hx509_kdfa()`)
4. Encrypt credential with AES-CFB (`hx509_aes_cfb_encrypt()`)
5. Compute HMAC over encrypted credential and object name
   (`hx509_hmac()`)

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

Changes to `lib/hx509/` (crypto primitive additions):
```
lib/hx509/
  crypto.c               -- extend: standalone HMAC, AES-CFB, RSA OAEP, KDFa
  crypto-ec.c            -- extend: ECDH key agreement
  hx509.h                -- extend: declare new public functions
```

New files in `lib/htpm2/`:
```
lib/htpm2/
  Makefile.am
  htpm2.h                 -- public header
  htpm2_locl.h            -- internal header
  htpm2_err.et            -- error table
  version-script.map      -- symbol export map
  marshal.c / marshal.h   -- TPM2 structure marshalling
  soft.c                  -- software MakeCredential (uses hx509 crypto)
  transport.c             -- transport abstraction
  transport_device.c      -- /dev/tpm* transport
  transport_socket.c      -- Unix/TCP socket transport
  transport_pipe.c        -- pipe/subprocess transport
  transport_tbs.c         -- Windows TBS transport
  command.c               -- command build/execute/parse
  session.c               -- session lifecycle
  session_crypto.c        -- session HMAC, param encrypt (via hx509)
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
2. **Phase 0.3**: Add missing crypto primitives to `lib/hx509/` (HMAC,
   AES-CFB, RSA OAEP, ECDH, KDFa) -- with unit tests in `lib/hx509/`
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

4. **KDFa location**: KDFa is TPM-specific but is a pure crypto function.
   Should it live in `lib/hx509/` (keeping all crypto together) or in
   `lib/htpm2/` (since it's TPM-specific)?  Leaning toward `lib/hx509/`
   since it's just HMAC-based KDF and could be useful elsewhere.

5. **hx509 API surface**: The new hx509 crypto functions (HMAC, AES-CFB,
   RSA OAEP, ECDH) should be public API or private (`_hx509_` prefix)?
   Public is cleaner for `lib/htpm2/` consumption and may be useful to
   other Heimdal consumers.  Recommend public.
