# Code Review: htpm2 TPM 2.0 Library

**Branch**: `origin/master..origin/claude/plan-tpm2-library-QL1tO`
**Scope**: 71 files changed, ~22,400 lines added
**Date**: 2026-03-31

---

## CRITICAL BUGS

### 1. Use-after-free: every TPM response reads freed stack memory

**`lib/htpm2/marshal.c:~180`**

`htpm2_command_execute` allocates `unsigned char rsp_buf[4096]` on the stack,
then creates `heim_storage_from_readonly_mem(rsp_buf, rsp_len)` which stores a
**raw pointer** (no copy).  After the function returns, `rsp_buf` is
deallocated but the returned `heim_storage` still references it.  Every caller
reading from `*rsp_sp` triggers undefined behavior.  This affects **every TPM
command in the library**.

**Fix**: Copy into a `heim_storage_emem()`, or heap-allocate the response
buffer.

### 2. Stack buffer overflow in `htpm2_kdfa()`

**`lib/htpm2/crypto.c:~145`**

```c
unsigned char buf[4 + 256 + 1 + 256 + 256 + 4]; /* worst case */
```

771-byte stack buffer, but `label`, `context_u`, `context_v` are
arbitrary-length with **no bounds checking** before the `memcpy` calls.
Context data comes from TPM responses or peer inputs.  Exploitable buffer
overflow.

### 3. PolicyOr evaluation passes NULL digest pointers

**`lib/htpm2/policy_compile.c:~371-430`**

In the evaluate path, `alt_digests[]` is zeroed, `alt_digest_bufs[j]` is
populated by `htpm2_policy_compile`, but the assignment
`alt_digests[j] = alt_digest_bufs[j]` is **missing** (contrast with the
compile path at line ~235 which correctly includes it).
`htpm2_policy_or()` receives all-NULL digest pointers.

### 4. ~~PolicyAuthorize sends wrong ticket tag~~ (NOT A BUG -- misleading comment)

**`lib/htpm2/policy.c:~540-541`**

```c
/* NULL ticket: tag=0x8000(TPM_ST_NULL), ... */
ret = heim_store_uint16(cmd, 0x8014);  /* TPM_ST_VERIFIED */
```

The **code is correct**: TPM 2.0 Part 2 (Table 92) requires the `tag`
field of `TPMT_TK_VERIFIED` to always be `TPM_ST_VERIFIED` (0x8014), even
for a NULL ticket.  A NULL ticket is `tag=0x8014`, `hierarchy=TPM_RH_NULL`,
`digest=empty`.  The **comment** is wrong and should be fixed -- it
incorrectly says `tag=0x8000(TPM_ST_NULL)`.

### 5. Transport dispatch is broken -- device framing never used

**`lib/htpm2/transport.c:~550-567`**

`htpm2_transport_send_recv()` unconditionally calls `tpm_send_recv()`
(stream-based header framing), ignoring `device_send_recv()` and the `ops`
vtable.  For `/dev/tpm*` devices, the Linux kernel requires single
`write()`/`read()` syscalls for command/response framing; the stream-based
approach will fail.  `device_send_recv` and `device_ops` are dead code.

Additionally, none of the transport open functions (`device_open`,
`socket_open`, `pipe_open`) set `t->ops` in the allocated struct.  The `ops`
field exists but is always NULL.

`htpm2_transport_close` also doesn't dispatch through `ops->close`, using
`child_pid > 0` as a heuristic instead.

### 6. Eventlog validation always uses SHA-256 regardless of algorithm

**`lib/htpm2/pcrdb.c:~581`**

```c
r = htpm2_sha256(ctx, extend_buf, digest_len + e->digest_len,
                 pcr_state[e->pcr_index]);
```

When `hash_alg` is SHA-384 (`digest_len=48`) or SHA-512 (`digest_len=64`),
`htpm2_sha256` still produces only 32 bytes, but `pcr_state` is
read/written at the full digest length.  PCR replay is silently corrupted
for all non-SHA-256 algorithms.

### 7. Double-free of `pub_sp` in `htpm2_session_start()` RSA path

**`lib/htpm2/session.c:242,261`**

`pub_sp` is freed at line 242 after parsing the RSA modulus.  If
`modulus == NULL || mod_size == 0`, the else branch at line 261 frees
`pub_sp` again.  This is a double-free triggered by malformed or empty RSA
key blobs from the TPM.

---

## HIGH SEVERITY BUGS

### 8. `htpm2_sign` and `htpm2_certify` read past parameters into auth area

**`lib/htpm2/sign.c:~130-145`, `lib/htpm2/certify.c:~100-112`**

Both functions use `SEEK_END` to determine how many bytes to read from the
response storage as the signature/certifyInfo:

```c
off_t end = heim_storage_seek(rsp, 0, SEEK_END);
sig_bytes = end - pos;
```

`htpm2_command_execute_with_auth` does parse and verify the response auth
area, then seeks the storage back to the start of the parameter area.  But
the auth area bytes are still present in the buffer -- they are not removed.
`SEEK_END` goes to the end of the entire buffer (parameters + auth area),
so the returned blob includes the trailing auth area bytes as garbage.

**Fix**: In `htpm2_command_execute_with_auth`, after parsing and verifying
the response auth area and seeking back to `param_start`, truncate the
storage to remove the auth area:

```c
heim_storage_seek(rsp, param_start, SEEK_SET);
heim_storage_truncate(rsp, param_start + param_size);
```

This way callers can use `SEEK_END` naturally and get only the parameter
bytes.  No API changes or caller modifications needed.  The same fix should
apply to `htpm2_command_execute_with_auths` once it gets response auth
verification.

Note: `htpm2_verify_signature` uses `htpm2_command_execute` (no auth,
`TPM_ST_NO_SESSIONS`) and has no trailing auth area -- it is not affected.

### 9. `heim_storage` is a copy-paste of `krb5_storage` with security regression

**`lib/base/heim_storage.c` (entire file, ~620 lines)**

Near-verbatim copy of `lib/krb5/store_emem.c`/`store_mem.c`/`store.c`.
Critical regression: `emem_free` uses `memset()` instead of `memset_s()`
(which the `krb5` version uses), so the compiler may optimize away secure
erasure of TPM credentials.

**Fix**: Refactor the core storage abstraction from `lib/krb5` into
`lib/base` and have `lib/krb5` wrap it, rather than maintaining two
parallel implementations.

### 10. Unchecked return values parsing TPM2B_PUBLIC in 3 files

**`lib/htpm2/quote_verify.c` (`ak_pub_to_evp_pkey`),
`lib/htpm2/import.c` (`htpm2_duplicate_software`),
`lib/htpm2/soft.c` (`parse_ek_rsa_pubkey`)**

After the initial `heim_ret_uint16` check, all subsequent
`heim_ret_uint16/uint32` calls discard return values.  If input is
truncated, reads silently fail leaving variables uninitialized, and parsing
continues with garbage values to construct cryptographic keys.

The same issue exists in `session.c` for the RSA and ECC parsing blocks in
`htpm2_session_start()`.

### 11. PolicyNV sends wrong handle count

**`lib/htpm2/policy.c`, `htpm2_policy_nv()`**

TPM2_PolicyNV requires 3 handles per the TCG spec (`authHandle`, `nvIndex`,
`policySession`).  The code only passes 2 handles, producing a malformed
command.

### 12. Timing side-channel in response HMAC verification

**`lib/htpm2/marshal.c:700`**

```c
memcmp(rsp_hmac_data, expected_hmac, expected_hmac_len)
```

`memcmp` leaks timing information proportional to the number of matching
prefix bytes.  This enables an attacker who can observe response timing to
forge HMACs incrementally.  Must use `CRYPTO_memcmp()` from OpenSSL.

### 13. Use-after-free in policy parse error path

**`lib/htpm2/policy_parse.c`, `parse_policy_dict()`**

The error message for "missing 'policy' array" references `d->name`, but
`d->name` was already freed by `htpm2_policy_doc_free(d)` on the preceding
line.

### 14. Thread-unsafe `gmtime()` in pcrdb

**`lib/htpm2/pcrdb.c:~176`**

`gmtime()` returns a pointer to a static internal buffer.  Must use
`gmtime_r()`.

### 15. Dangling pointers in `htpm2_pcr_lookup_result`

**`lib/htpm2/pcrdb.c`, `htpm2_pcrdb_lookup()`**

Result struct stores pointers from `sqlite3_column_text()`.  These become
invalid after the next `sqlite3_step()`/`sqlite3_reset()` on the reused
prepared statement.  Callers holding results across multiple lookups access
stale memory.  Should `strdup()` the strings.

### 16. Sensitive key material not cleared on all error paths

**`lib/htpm2/session.c`**

`salt[32]` and `kdf_key[96]` contain secret material.  `memset` clears them
on the success path, but early returns (e.g., from `htpm2_rsa_oaep_encrypt`
failure) skip the clearing.  Also, `memset` before scope exit may be
optimized away by the compiler.  Should use `OPENSSL_cleanse()` or
`explicit_bzero()`.

### 17. Multi-session response HMAC verification not implemented

**`lib/htpm2/marshal.c`, `htpm2_command_execute_with_auths()`**

The function has `/* TODO: parse and verify response auth area for each
session */` and skips response HMAC verification entirely.  Multi-session
commands have no response integrity protection.

---

## MEDIUM SEVERITY BUGS

### 18. Hardcoded well-known key Name length

**`lib/htpm2/encrypt_to.c`**

`htpm2_make_credential(..., wk_name, 34, ...)` hardcodes 34 instead of
using `wk_name_len`.  If the computed name length differs from 34,
MakeCredential reads uninitialized stack bytes.

### 19. Silent OOM produces false success

**`lib/htpm2/certify.c:~105`, `lib/htpm2/sign.c:~163`**

When `malloc` fails for signature/ticket data, functions return `HTPM2_OK`
with NULL output pointers.  Callers cannot distinguish success from
out-of-memory.

### 20. Static mutable buffers shared across threads

**`lib/htpm2/crypto.c:~110`**

```c
static char sha256_name[] = "SHA256";
```

`OSSL_PARAM_construct_utf8_string` takes mutable `char *`.  Same for
`p256_name[]`/`p384_name[]` in `htpm2_ecc_salt()`.  Concurrent calls could
corrupt if OpenSSL writes to the buffer.

### 21. Missing HMAC/KEYEDHASH key template cases

**`lib/htpm2/key_templates.c`**

`HTPM2_KEY_HMAC_SHA256` (20) and `HTPM2_KEY_KEYEDHASH` (21) are in the
public enum but have no `case` in `htpm2_marshal_key_template_attrs()` --
they fall to `default: return EINVAL`.

### 22. NULL context passed to `htpm2_command_execute`

**`lib/htpm2/object.c:~242`, `lib/htpm2/session.c` (`htpm2_session_close`)**

Both destructors call `htpm2_command_execute(NULL, ...)`.  Currently safe
because `ctx` isn't dereferenced in that path, but fragile.

### 23. Creation tickets silently discarded

**`lib/htpm2/create.c`**

Neither `htpm2_create_primary()` nor `htpm2_create()` saves
`creationData`/`creationHash`/`creationTicket`, even though
`htpm2_object_set_creation_ticket()` exists.  Makes `CertifyCreation`
unusable.

### 24. Integer overflow in `emem_store` growth (32-bit)

**`lib/base/heim_storage.c:~100-118`**

`off + size` can overflow to a small value on 32-bit platforms.  `realloc`
succeeds undersized; subsequent `memmove` causes a heap overflow.

### 25. `iv_len` not validated in `htpm2_aes_cfb_encrypt()`

**`lib/htpm2/crypto.c:~135`**

Parameter accepted but never used or validated.  No check that
`iv_len >= 16`.  Short IV causes OpenSSL to read past the buffer.

### 26. `time_t` shift UB on 32-bit systems

**`appl/htpm2/htpm2tool.c:~410-411`**

```c
ts_buf[4] = (now >> 56) & 0xff;
```

On 32-bit systems where `time_t` is 32 bits, shifting by 56 is undefined
behavior.  Must cast to `uint64_t` first (as the decode path already does).

### 27. `realloc` without NULL check in `parse_policy_inputs`

**`appl/htpm2/htpm2tool.c:~133-136`**

Classic realloc leak: if `realloc()` returns NULL, the original pointer is
lost.  Next line dereferences NULL.

### 28. Memory leak of `out_pub_data` in `cmd_key_create`

**`appl/htpm2/htpm2tool.c:~1196-1215`**

`out_pub_data` is reused for multiple TPM2B fields.  The original
`outPublic` allocation is never freed (leaked).  The variable name reuse
makes the logic error-prone.

### 29. Uninitialized `ts_len` used in error message

**`appl/htpm2/htpm2tool.c:~304-308`**

If `read_file` returns NULL, `ts_len` was never set, but the error message
formats it with `%zu`.

### 30. Substring attribute matching in `parse_attrs_string`

**`appl/htpm2/htpm2tool.c:~1009-1023`**

`strstr(s, "sign")` matches strings containing "sign" as a substring (e.g.,
"designate").  Should use token-based parsing.

### 31. `heim_ret_bytes` return value unchecked in `htpm2_context_save`

**`lib/htpm2/context_mgmt.c`**

The `heim_ret_bytes(rsp, *saved, blob_len)` return value is ignored.  If
the read fails, stale/uninitialized data is returned as the "saved" context
blob.

---

## CODE DUPLICATION

### 32. `heim_storage` duplicates `krb5_storage` (~620 lines)

**`lib/base/heim_storage.c`**

Should refactor the core from `lib/krb5` into `lib/base` and have
`lib/krb5` wrap it.

### 33. Password auth area marshalling duplicated 3+ times

**`lib/htpm2/create.c`, `lib/htpm2/load.c`**

Identical 5-call `TPM_RS_PW` auth sequence.  `htpm2_marshal_auth_area` is
declared in `htpm2_locl.h` but not used here.

### 34. RSA public key parsing duplicated across 3 files

**`lib/htpm2/soft.c`, `lib/htpm2/quote_verify.c`, `lib/htpm2/import.c`**

Same TPMT_PUBLIC RSA parsing logic open-coded three times with varying error
handling quality.

### 35. "Read remaining response bytes" pattern duplicated

**`lib/htpm2/sign.c`, `lib/htpm2/certify.c`, `lib/htpm2/context_mgmt.c`**

Seek-current/end, malloc, read sequence.  Should be a shared helper.

### 36. Policy command boilerplate repeated 10+ times

**`lib/htpm2/policy.c`**

~40 lines of identical alloc/marshal/execute/free for each policy command.
A `policy_simple_command()` helper would eliminate hundreds of lines.

### 37. cpHash computation duplicated between `_with_auth` and `_with_auths`

**`lib/htpm2/marshal.c`**

The cpHash computation block (building `name_bufs`, `names`, `name_lens`
from handles and calling `htpm2_compute_cp_hash`) is copy-pasted
identically in both functions.

### 38. FlushContext send logic duplicated

**`lib/htpm2/session.c`, `lib/htpm2/object.c`**

Both destructors contain identical FlushContext command marshalling and
execution code.  Should be a shared `htpm2_flush_context()` helper.

### 39. `htpm2_object_set_*` all follow identical alloc-copy pattern

**`lib/htpm2/object.c`**

`set_pub`, `set_priv`, `set_name`, `set_auth`, `set_creation_ticket` are
all identical except for the field name.  A macro would eliminate the
duplication.

### 40. Test macro `CHECK`/`CHECK_OK` copy-pasted across 4 test files

**`lib/htpm2/test_*.c`**

Should be in a shared `test_common.h`.

---

## THREAD SAFETY / NON-REENTRANT

### 41. No transport serialization

Multiple threads sharing `htpm2_transport` will interleave send/recv,
corrupting the TPM channel.  No mutex or documented threading model.

### 42. No thread-safety documentation for `heim_storage`

Exposed as public `lib/base` API with no guidance that objects must not be
shared across threads.

### 43. `builtin_ops` array has no locking for future registration

**`lib/htpm2/transport.c`**

The `builtin_ops` array is file-static.  Once `htpm2_transport_register` is
implemented, concurrent registration and lookup will be a data race.

---

## STYLE ISSUES

### 44. Magic numbers in policy.c

Raw hex command codes (`0x0000017D`, etc.) instead of `TPM2_CC_*` constants
defined in `marshal.h`.

### 45. Inconsistent license headers

Some files have full BSD 3-clause text, others a one-line abbreviation.

### 46. Ad-hoc error codes in `heim_storage.c`

`#define HEIM_ERR_EOF (-1553)` -- hardcoded magic numbers rather than
Heimdal's `.et` error table mechanism.

### 47. PolicyOr inline policy parsing is a no-op

**`lib/htpm2/policy_parse.c`, `parse_node()`**

The `if (inline_pol) { ... }` block is empty.  Inline sub-policies are
parsed structurally but the `inline_policy` field remains NULL.

### 48. `--disable-tpm2` has no effect

**`configure.ac`**

`AM_CONDITIONAL(TPM2, ...)` is defined but never checked in Makefiles.
Both `lib/htpm2/Makefile.am` and `appl/htpm2/Makefile.am` build
unconditionally.

### 49. `system()` in test code for cleanup

**`lib/htpm2/test_swtpm.c:~59`**

Uses `system("rm -rf ...")` instead of `nftw()`/recursive-unlink.
Inconsistent with the same file using `fork()/exec()` for `swtpm` itself.

### 50. Unquoted variable expansions in shell test

**`appl/htpm2/check-htpm2tool.sh`**

`${HTPM2TOOL}` is unquoted throughout.  Breaks if path contains spaces.

### 51. Error result constructors defined in wrong file

**`lib/htpm2/context.c`**

`htpm2_result_local`, `htpm2_result_tpm`, `htpm2_result_ossl` are
general-purpose result builders defined in `context.c`.  They belong in
`result.c` alongside `htpm2_result_free` and `htpm2_result_prepend`.

### 52. `result.c` does not include `htpm2_locl.h`

**`lib/htpm2/result.c`**

Includes `"htpm2.h"` directly, bypassing `htpm2_locl.h`.  Inconsistent
with all other `.c` files in the library.

---

## NOT A BUG (good decisions)

- **Policy parser correctly uses `heim_json_create()`** and heim base types
  rather than open-coding JSON parsing.
- **`pcrdb.c` uses parameterized SQL** (`sqlite3_bind_*`), avoiding SQL
  injection.
- **Monadic error chaining** follows linear ownership (each result returned
  or freed, never aliased).  Correct today but fragile -- document the
  ownership invariant.

---

## Summary

| Severity | Count | Key examples |
|----------|------:|-------------|
| Critical | 6 | Use-after-free (#1), stack overflow (#2), double-free (#7) |
| High | 10 | Malformed signatures (#8), timing side-channel (#12), unchecked parse (#10) |
| Medium | 14 | OOM false-success (#19), UB on 32-bit (#26), NULL deref (#27) |
| Duplication | 9 | `heim_storage` (#32), RSA parsing x3 (#34), policy boilerplate (#36) |
| Thread safety | 3 | No transport locking (#41), no `heim_storage` docs (#42) |
| Style | 9 | Magic numbers (#44), inconsistent licenses (#45), dead configure (#48) |
