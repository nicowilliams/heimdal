# htpm2 Test Plan

## Test Infrastructure

### swtpm (Software TPM)

All tests run against `swtpm` (the libtpms-based software TPM 2.0 emulator).
This provides a deterministic, reproducible, and safe test environment --
no risk of disrupting a real TPM, no hardware dependency, and tests can run
in CI.

`swtpm` will be started in one of two modes depending on the transport under
test:

- **Socket mode**: `swtpm socket --tpmstate dir=STATE --ctrl type=tcp,...`
- **Pipe mode**: launched as a child process via the pipe transport.

Test fixtures will:
1. Create a temporary directory for TPM state.
2. Start `swtpm` with manufacturing (so it has an EK seed, SRK seed, etc.).
3. Run test cases.
4. Shut down `swtpm` and clean up.

### Test Framework

Tests are written as C programs (one per test group) following Heimdal's
pattern (cf. `lib/hx509/test_name.c`) plus shell-script wrappers for
integration tests (cf. `lib/hx509/test_ca.in`).

Each C test program uses a simple pass/fail model:
```c
static int test_foo(htpm2_context ctx, htpm2_transport tp) {
    /* ... */
    if (error) { fprintf(stderr, "FAIL: ...\n"); return 1; }
    return 0;
}
```

A shell wrapper (`test_htpm2.in`) handles `swtpm` lifecycle and runs the
test binaries.

### Conditional Execution

Tests are skipped (exit 77, autotools convention) if `swtpm` is not installed.
A configure check (`AC_CHECK_PROG([SWTPM], [swtpm], [swtpm])`) gates the
tests.

## Test Categories

### T1. Marshalling Unit Tests

**File**: `test_marshal.c`

These tests do NOT require a TPM.  They validate the marshalling layer in
isolation.

| Test | Description |
|------|-------------|
| T1.1 | Marshal/unmarshal `uint8`, `uint16`, `uint32` -- verify big-endian encoding |
| T1.2 | Marshal/unmarshal `TPM2B` buffers -- verify size prefix and data |
| T1.3 | Marshal `TPMT_PUBLIC` for RSA-2048 signing key -- compare against known-good byte sequence |
| T1.4 | Marshal `TPMT_PUBLIC` for ECC P-256 signing key -- compare against known-good byte sequence |
| T1.5 | Marshal `TPMS_AUTH_COMMAND` with HMAC session -- verify structure layout |
| T1.6 | Marshal full `TPM2_GetRandom` command packet -- verify header, tag, size, CC |
| T1.7 | Unmarshal a canned `TPM2_GetRandom` response -- verify extracted random bytes |
| T1.8 | Round-trip: marshal then unmarshal every key template type |
| T1.9 | Error cases: truncated input, oversized `TPM2B`, invalid sizes |

### T2. Crypto Primitives Tests (hx509 extensions)

New crypto primitives are added to `lib/hx509/` for use by `lib/htpm2/`.
These tests validate those additions against known test vectors.

**File**: `lib/hx509/test_tpm_crypto.c` (tests for the new hx509 primitives)
**File**: `lib/htpm2/test_crypto.c` (tests for htpm2's use of them, e.g. KDFa)

No TPM required.

| Test | Description |
|------|-------------|
| T2.1 | `hx509_hmac()` with SHA-256: RFC 4231 test vectors |
| T2.2 | `hx509_hmac()` with SHA-384: RFC 4231 test vectors |
| T2.3 | `hx509_hmac()` with SHA-512: RFC 4231 test vectors |
| T2.4 | `hx509_kdfa()`: TPM 2.0 Part 4 sample vectors (derive session key) |
| T2.5 | `hx509_aes_cfb_encrypt/decrypt()` AES-128-CFB: NIST SP 800-38A test vectors |
| T2.6 | `hx509_aes_cfb_encrypt/decrypt()` AES-256-CFB: NIST SP 800-38A test vectors |
| T2.7 | AES-CFB round-trip: encrypt then decrypt, verify plaintext matches |
| T2.8 | `hx509_rsa_oaep_encrypt()`: encrypt with known key, verify format; round-trip with `hx509_private_key_private_decrypt()` using OAEP |
| T2.9 | `hx509_ecdh_derive()`: derive shared secret from two key pairs, verify both sides agree |
| T2.10 | Parameter encryption round-trip: KDFa-derived key + AES-CFB encrypt/decrypt |

### T3. Transport Tests

**File**: `test_transport.c` + `test_transport.in` (shell wrapper)

| Test | Description |
|------|-------------|
| T3.1 | Socket transport: connect to `swtpm` in socket mode, send `TPM2_Startup`, verify success RC |
| T3.2 | Pipe transport: launch `swtpm` via pipe, send `TPM2_Startup`, verify success RC |
| T3.3 | Device transport: open `/dev/tpmrm0` if available, send `TPM2_GetRandom`, verify response (skip if no device) |
| T3.4 | Invalid URI: `htpm2_transport_open` returns error for "bogus:foo" |
| T3.5 | Connection refused: socket transport to non-listening port returns error |
| T3.6 | Pipe to non-existent binary: returns error |
| T3.7 | Get fd accessors: verify `htpm2_transport_get_read_fd` returns valid fd for socket transport |

### T4. Basic Command Tests

**File**: `test_commands.c`

Requires `swtpm`.  Tests the command execution engine with simple commands.

| Test | Description |
|------|-------------|
| T4.1 | `TPM2_Startup(CLEAR)` -- verify success |
| T4.2 | `TPM2_GetRandom(32)` -- verify 32 bytes returned, not all zero |
| T4.3 | `TPM2_GetRandom` twice -- verify different results (probabilistic) |
| T4.4 | `TPM2_Hash(SHA256, "abc")` -- verify matches software SHA-256 of "abc" |
| T4.5 | `TPM2_SelfTest(fullTest)` -- verify success |
| T4.6 | Invalid command code -- verify TPM RC error is properly decoded |

### T5. Session Tests

**File**: `test_sessions.c`

Requires `swtpm`.

| Test | Description |
|------|-------------|
| T5.1 | Start unbound, unsalted HMAC session -- verify session handle returned |
| T5.2 | Start salted HMAC session (using EK as salt key) -- verify handle |
| T5.3 | Use HMAC session to authorize `TPM2_GetRandom` -- verify response HMAC validates |
| T5.4 | Start encrypted session -- send `TPM2_GetRandom`, verify param encryption (by checking that the on-wire bytes differ from plaintext) |
| T5.5 | Start trial policy session -- run `PolicyPCR` + `PolicyCommandCode` -- retrieve digest |
| T5.6 | Start real policy session -- run same policy commands -- use to authorize an operation |
| T5.7 | Session flush -- close session, verify handle is invalid |
| T5.8 | Multiple concurrent sessions (up to 3) -- verify independent state |
| T5.9 | Session with `continueSession` flag -- use same session for two commands |

### T6. Key Creation and Management Tests

**File**: `test_keys.c`

Requires `swtpm`.

| Test | Description |
|------|-------------|
| T6.1 | `CreatePrimary` RSA-2048 signing key under Owner hierarchy |
| T6.2 | `CreatePrimary` ECC P-256 signing key under Owner hierarchy |
| T6.3 | `CreatePrimary` RSA-2048 storage key under Owner hierarchy |
| T6.4 | `Create` RSA-2048 signing child key under storage parent |
| T6.5 | `Create` ECC P-256 signing child key under storage parent |
| T6.6 | `Load` previously created child key -- verify handle |
| T6.7 | `ReadPublic` on loaded key -- verify matches creation output |
| T6.8 | `Create` + `Load` key with auth value -- verify auth required |
| T6.9 | `Create` key with policy -- verify policy session required |
| T6.10 | `FlushContext` on loaded key -- verify handle becomes invalid |
| T6.11 | `ContextSave` + `ContextLoad` -- verify key is usable after reload |
| T6.12 | `EvictControl` to make key persistent -- reload `swtpm`, verify key still present |
| T6.13 | Create all supported key types (RSA-2048/3072, ECC P-256/P-384, HMAC) |

### T7. Signing and Verification Tests

**File**: `test_sign.c`

Requires `swtpm`.

| Test | Description |
|------|-------------|
| T7.1 | RSA-2048 sign + verify round-trip |
| T7.2 | ECC P-256 sign + verify round-trip |
| T7.3 | Sign with wrong key type (storage key) -- verify error |
| T7.4 | Verify with wrong key -- verify failure |
| T7.5 | Verify with tampered digest -- verify failure |
| T7.6 | Sign with encrypted session -- verify correctness |
| T7.7 | Sign with policy-restricted key using policy session |

### T8. Quote and Attestation Tests

**File**: `test_quote.c`

Requires `swtpm`.

| Test | Description |
|------|-------------|
| T8.1 | Create AK (attestation key), quote PCRs 0-7, verify signature over `TPMS_ATTEST` |
| T8.2 | Extend PCR, re-quote, verify digest changed |
| T8.3 | Quote with qualifying data -- verify it appears in `TPMS_ATTEST.extraData` |
| T8.4 | `Certify` one key with another -- verify attestation structure |
| T8.5 | `CertifyCreation` -- verify creation ticket validates |
| T8.6 | Quote with encrypted session |

### T9. Decryption Tests

**File**: `test_decrypt.c`

Requires `swtpm`.

| Test | Description |
|------|-------------|
| T9.1 | RSA-2048 OAEP: encrypt in software with public key, decrypt via TPM |
| T9.2 | RSA-2048 OAEP: verify decrypted plaintext matches original |
| T9.3 | ECDH: generate ephemeral key pair, `ECDH_ZGen` for shared secret |
| T9.4 | Decrypt with wrong key -- verify error |
| T9.5 | Decrypt with encrypted session |

### T10. Credential Tests (MakeCredential / ActivateCredential)

**File**: `test_credential.c`

Requires `swtpm`.  This is the critical test for Safeboot-style attestation.

| Test | Description |
|------|-------------|
| T10.1 | Software `MakeCredential`: create credential blob for EK + AK name |
| T10.2 | `ActivateCredential` on TPM: decrypt and recover credential -- verify matches original |
| T10.3 | `MakeCredential` with wrong AK name -- `ActivateCredential` must fail |
| T10.4 | `MakeCredential` with wrong EK public key -- `ActivateCredential` must fail |
| T10.5 | Full attestation round-trip: create EK, create AK, `MakeCredential` (software), `ActivateCredential` (TPM), verify secret matches |
| T10.6 | Attestation with EK policy session (standard EK templates require `PolicySecret(ENDORSEMENT)`) |

### T11. PCR Tests

**File**: `test_pcr.c`

Requires `swtpm`.

| Test | Description |
|------|-------------|
| T11.1 | `PCR_Read` all banks -- verify initial values (all zeros or all 0xFF depending on algorithm) |
| T11.2 | `PCR_Extend` PCR 16 (resettable) with known digest -- `PCR_Read` and verify |
| T11.3 | Extend PCR twice -- verify cumulative hash matches `Hash(Hash(init \|\| ext1) \|\| ext2)` |
| T11.4 | Read PCR selection with multiple PCRs |

### T12. Policy Tests

**File**: `test_policy.c`

Requires `swtpm`.

| Test | Description |
|------|-------------|
| T12.1 | Trial session: `PolicyPCR` -- compute expected digest in software, compare |
| T12.2 | Trial session: `PolicyCommandCode(Sign)` -- verify digest |
| T12.3 | Trial session: `PolicyPCR` + `PolicyCommandCode` -- verify combined digest |
| T12.4 | Trial session: `PolicyOR` with two branches -- verify digest |
| T12.5 | Create key with PCR policy -- sign with policy session after satisfying PCR policy |
| T12.6 | Create key with PCR policy -- fail to sign without policy session |
| T12.7 | Create key with PCR policy -- fail after PCR extend changes values |
| T12.8 | `PolicyAuthorize`: create authorizing key, sign a policy, use `PolicyAuthorize` to satisfy key's auth policy |
| T12.9 | `PolicySecret(ENDORSEMENT)`: authorize with endorsement hierarchy (needed for standard EK) |

### T13. Import / Duplicate Tests

**File**: `test_import.c`

Requires `swtpm`.

| Test | Description |
|------|-------------|
| T13.1 | `Import` an externally-generated RSA key -- load and use for signing |
| T13.2 | `Duplicate` a key to a new parent -- `Import` under new parent, verify usable |
| T13.3 | `Import` with wrong parent -- verify failure |

### T14. Error Handling Tests

**File**: `test_errors.c`

Mix of with and without `swtpm`.

| Test | Description |
|------|-------------|
| T14.1 | NULL context -- verify graceful failure |
| T14.2 | Use object after flush -- verify error (not crash) |
| T14.3 | Use session after close -- verify error |
| T14.4 | Transport disconnected mid-operation -- verify error propagation |
| T14.5 | TPM authorization failure -- verify meaningful error string |
| T14.6 | Error string retrieval and clearing |

### T15. Integration / Scenario Tests

**File**: `test_scenarios.in` (shell script)

End-to-end scenarios using the C test harness or a small CLI tool.

| Test | Description |
|------|-------------|
| T15.1 | **Safeboot enrollment**: create EK, create AK under SRK, quote PCRs, `MakeCredential`, `ActivateCredential`, verify secret -- full protocol |
| T15.2 | **Sealed secret**: create storage key with PCR policy, create sealed data object, unseal with correct PCRs, fail to unseal after PCR extend |
| T15.3 | **Key migration**: create key under parent A, duplicate to parent B, import under parent B, verify usable |
| T15.4 | **Multiple sessions**: simultaneous HMAC + policy sessions for `ActivateCredential` |
| T15.5 | **Encrypted session end-to-end**: all operations in T15.1 using encrypted sessions |

## Test Matrix

| Transport | Session Type | Key Type | Test Coverage |
|-----------|-------------|----------|---------------|
| Socket (swtpm) | None (password) | RSA-2048 | T4, T6 |
| Socket (swtpm) | HMAC unbound | RSA-2048 | T5, T7 |
| Socket (swtpm) | HMAC salted | ECC P-256 | T5, T7 |
| Socket (swtpm) | HMAC encrypted | RSA-2048, ECC | T5, T7, T8, T9 |
| Socket (swtpm) | Policy | RSA-2048 | T5, T10, T12 |
| Socket (swtpm) | Trial | -- | T5, T12 |
| Pipe (swtpm) | HMAC encrypted | RSA-2048 | T3, T15 |
| Device (/dev/tpmrm0) | HMAC encrypted | RSA-2048 | T3 (manual/opt-in) |

## CI Integration

### Required Packages

- `swtpm` and `libtpms` -- available in Debian/Ubuntu (`apt install swtpm`),
  Fedora (`dnf install swtpm`).
- No other external dependencies.

### CI Script

```sh
#!/bin/sh
# test_htpm2.in -- autotools test wrapper

if ! command -v swtpm >/dev/null 2>&1; then
    echo "swtpm not found, skipping htpm2 tests"
    exit 77  # autotools skip
fi

TPMSTATE=$(mktemp -d)
trap "rm -rf $TPMSTATE" EXIT

# Initialize swtpm
swtpm_setup --tpmstate "$TPMSTATE" --tpm2 --createek

# Start swtpm in socket mode
SOCKET="$TPMSTATE/sock"
swtpm socket \
    --tpmstate dir="$TPMSTATE" \
    --tpm2 \
    --ctrl type=unixio,path="$SOCKET.ctrl" \
    --server type=unixio,path="$SOCKET" \
    --flags startup-clear &
SWTPM_PID=$!
trap "kill $SWTPM_PID 2>/dev/null; rm -rf $TPMSTATE" EXIT

# Wait for socket
for i in 1 2 3 4 5; do
    [ -S "$SOCKET" ] && break
    sleep 0.2
done

# Run tests
HTPM2_TEST_TRANSPORT="socket:$SOCKET" \
    ./test_marshal && \
    ./test_crypto && \
    ./test_transport && \
    ./test_commands && \
    ./test_sessions && \
    ./test_keys && \
    ./test_sign && \
    ./test_quote && \
    ./test_decrypt && \
    ./test_credential && \
    ./test_pcr && \
    ./test_policy && \
    ./test_import && \
    ./test_errors
```

## Files

```
lib/hx509/
  test_tpm_crypto.c    -- T2: tests for new hx509 crypto primitives (HMAC,
                           AES-CFB, RSA OAEP, ECDH)

lib/htpm2/
  test_marshal.c       -- T1: marshalling unit tests
  test_crypto.c        -- T2: KDFa and htpm2-level crypto integration tests
  test_transport.c     -- T3: transport tests
  test_commands.c      -- T4: basic command tests
  test_sessions.c      -- T5: session tests
  test_keys.c          -- T6: key management tests
  test_sign.c          -- T7: signing/verification tests
  test_quote.c         -- T8: quote/attestation tests
  test_decrypt.c       -- T9: decryption tests
  test_credential.c    -- T10: credential tests
  test_pcr.c           -- T11: PCR tests
  test_policy.c        -- T12: policy tests
  test_import.c        -- T13: import/duplicate tests
  test_errors.c        -- T14: error handling tests
  test_htpm2.in        -- shell wrapper for swtpm lifecycle
```
