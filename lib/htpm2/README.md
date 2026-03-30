# lib/htpm2 -- TPM 2.0 Library for Heimdal

`libhtpm2` is a self-contained TPM 2.0 library that provides a simple C
interface to TPM 2.0 hardware and software TPMs.  It is designed for use
in Heimdal's attestation and enrollment protocols (Safeboot-style), but
is general enough for any TPM 2.0 application.

## Key Design Decisions

- **No Intel TSS dependency**.  Talks to TPMs directly via `/dev/tpmrm0`,
  Unix sockets (for `swtpm`), TCP, or pipes (for `ssh` tunnels).

- **No `lib/hx509` dependency**.  Uses OpenSSL `libcrypto` directly
  (3.0+).  This allows `lib/hx509` to depend on `lib/htpm2` for
  TPM-backed certificate signing, not the other way around.

- **Structured errors returned by value** (`htpm2_result`).  Multi-dimensional
  error codes (TPM RC, errno, OpenSSL error) with heap-allocated messages.
  Monadic chaining: every function takes a prior result and short-circuits
  on error -- enables goto-free linear error propagation.

- **Read-only context**.  `htpm2_context` is immutable after init (caches
  OpenSSL `EVP_MD` pointers).  All mutable state lives in transports,
  sessions, and objects.  Thread-safe by construction.

- **Encrypted + authenticated sessions**.  Salted sessions (RSA OAEP to
  salt key), session key derivation via KDFa, HMAC command/response
  binding, AES-128-CFB parameter encryption/decryption, response HMAC
  verification.

- **JSON policy language**.  All 19 `TPM2_Policy*()` commands.  Parse,
  compile (trial session → `policyDigest`), evaluate (real session →
  satisfied authorization).

## Dependencies

- `lib/roken/` -- portability
- `lib/base/` -- `heimbase` (JSON parser, heim objects), `heim_storage`
  (marshalling)
- OpenSSL `libcrypto` 3.0+ -- SHA-2, HMAC (`EVP_MAC`), AES-CFB,
  RSA OAEP, ECDH, `RAND_bytes`
- SQLite3 -- PCR extension database (for eventlog validation)
- `lib/com_err/` -- error tables

## Building

```sh
autoreconf -fi
mkdir build && cd build
../configure --enable-maintainer-mode --enable-developer
make -j$(nproc)
cd lib/htpm2 && make check
```

Tests: `test_result` (unit), `test_crypto` (unit), `test_policy_parse`
(unit), `test_swtpm` (integration, needs `swtpm` installed).

## CLI Tool

`htpm2tool` is built in `appl/htpm2/` and links both `libhtpm2` and
`libhx509`:

```
htpm2tool timestamp     -- generate/verify signed nonces for quotes
htpm2tool encrypt-to    -- encrypt a file to a target TPM
htpm2tool envelope-open  -- decrypt using the local TPM
htpm2tool quote-verify  -- validate a TPM quote + eventlog
```

## File Layout

```
lib/htpm2/
  htpm2.h              -- public API (all function declarations)
  htpm2_locl.h         -- internal header
  htpm2_err.et         -- error table (com_err)
  result.c             -- htpm2_result type
  context.c            -- context init/free, error constructors
  crypto.c / crypto.h  -- SHA-256, HMAC, KDFa, AES-CFB, RSA OAEP, ECDH
  marshal.c / marshal.h -- TPM2B, command headers, command execute
  transport.c          -- device, socket, pipe transports
  session.c            -- StartAuthSession, session state
  session_crypto.c     -- cpHash, rpHash, session HMAC, auth area
  object.c             -- object lifecycle, accessors
  key_templates.c      -- TPMT_PUBLIC for RSA/ECC key types
  create.c             -- CreatePrimary, Create
  load.c               -- Load, ReadPublic
  sign.c               -- Sign, VerifySignature
  quote.c              -- Quote
  quote_verify.c       -- TPMS_ATTEST parsing, signature verification
  certify.c            -- Certify, CertifyCreation, CertifyX509 (stub)
  decrypt.c            -- RSA_Decrypt, ECDH_ZGen
  pcr.c                -- PCR_Read, PCR_Extend, selection helpers
  random.c             -- GetRandom
  command.c            -- Startup
  policy.c             -- all 19 TPM2_Policy* commands
  policy_parse.c       -- JSON → internal structures
  policy_compile.c     -- trial compilation + evaluation
  policy_p.h           -- parsed policy structures
  credential.c         -- ActivateCredential
  soft.c               -- software MakeCredential
  enrollment.c         -- well-known key, owner key
  encrypt_to.c         -- EncryptTo/EnvelopeOpen with key splitting
  import.c             -- Import, Duplicate (TPM + software)
  evict.c              -- EvictControl
  context_mgmt.c       -- ContextSave, ContextLoad
  pcrdb.c / pcrdb.h    -- PCR extension DB + eventlog replay
  error.c              -- (reserved)
  version-script.map   -- symbol versioning

lib/base/
  heim_storage.c/.h    -- storage/marshalling abstraction

appl/htpm2/
  htpm2tool.c          -- CLI tool

doc/htpm2/
  api-design.md
  implementation-plan.md
  test-plan.md
  policy-language-design.md
```
