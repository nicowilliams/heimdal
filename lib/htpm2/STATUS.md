# lib/htpm2 Implementation Status

## Summary

~14,300 lines of C across 44 files in `lib/htpm2/`, plus ~800 lines in
`appl/htpm2/htpm2tool.c`, ~550 lines in `lib/base/heim_storage.c`,
and ~1,500 lines of design documents.

30+ integration tests against `swtpm`, 15+ unit tests.

## TPM Commands -- Implemented

| Command | File | Status |
|---------|------|--------|
| TPM2_Startup | command.c | Done |
| TPM2_GetRandom | random.c | Done |
| TPM2_Hash | -- | Not implemented |
| TPM2_CreatePrimary | create.c | Done |
| TPM2_Create | create.c | Done |
| TPM2_Load | load.c | Done |
| TPM2_ReadPublic | load.c | Done |
| TPM2_FlushContext | object.c | Done (auto on close) |
| TPM2_ContextSave | context_mgmt.c | Done |
| TPM2_ContextLoad | context_mgmt.c | Done |
| TPM2_EvictControl | evict.c | Done |
| TPM2_StartAuthSession | session.c | Done (HMAC, policy, trial) |
| TPM2_Sign | sign.c | Done |
| TPM2_VerifySignature | sign.c | Done |
| TPM2_Quote | quote.c | Done |
| TPM2_Certify | certify.c | Done |
| TPM2_CertifyCreation | certify.c | Stub (ENOSYS) |
| TPM2_CertifyX509 | certify.c | Stub (needs lib/asn1) |
| TPM2_RSA_Decrypt | decrypt.c | Done |
| TPM2_ECDH_ZGen | decrypt.c | Done |
| TPM2_MakeCredential | soft.c | Done (software-only) |
| TPM2_ActivateCredential | credential.c | Done (password auth) |
| TPM2_Import | import.c | Done |
| TPM2_Duplicate | import.c | Done (TPM + software) |
| TPM2_PCR_Read | pcr.c | Done |
| TPM2_PCR_Extend | pcr.c | Done |

## Policy Commands -- All 19 Implemented

| Command | Status | Notes |
|---------|--------|-------|
| TPM2_PolicyPCR | Done | |
| TPM2_PolicyCommandCode | Done | |
| TPM2_PolicyAuthValue | Done | |
| TPM2_PolicyPassword | Done | |
| TPM2_PolicySigned | Done | Object loading needed for compiler |
| TPM2_PolicySecret | Done | |
| TPM2_PolicyAuthorize | Done | Must be first in policy doc |
| TPM2_PolicyOR | Done | With inline + named reference alternatives |
| TPM2_PolicyLocality | Done | |
| TPM2_PolicyNV | Done | |
| TPM2_PolicyCounterTimer | Done | |
| TPM2_PolicyPhysicalPresence | Done | |
| TPM2_PolicyCpHash | Done | |
| TPM2_PolicyNameHash | Done | |
| TPM2_PolicyDuplicationSelect | Done | |
| TPM2_PolicyTicket | Done | |
| TPM2_PolicyNvWritten | Done | |
| TPM2_PolicyTemplate | Done | |
| TPM2_PolicyAuthorizeNV | Done | Must be first in policy doc |

## Session Features

| Feature | Status |
|---------|--------|
| Unbound unsalted HMAC | Done |
| Salted HMAC (RSA OAEP) | Done |
| Bound sessions (authValue) | Done |
| Session key derivation (KDFa) | Done |
| Command HMAC | Done |
| Response HMAC verification | Done |
| Parameter encryption (AES-128-CFB) | Done |
| Parameter decryption | Done |
| Policy sessions | Done |
| Trial policy sessions | Done |
| Encrypted policy sessions | Not implemented |
| Multi-auth (2+ sessions per command) | Partial (ActivateCredential only) |
| ECC salted sessions (ECDH) | Not implemented |

## Higher-Level Features

| Feature | Status |
|---------|--------|
| JSON policy language parser | Done (all 19 commands) |
| Policy compiler (JSON → policyDigest) | Done |
| Policy evaluator (JSON → satisfied session) | Done |
| PolicyOr reference resolution (name/URI) | Not implemented |
| EncryptTo (1-3 way key split) | Done |
| EnvelopeOpen (manual share assembly) | Done |
| EnvelopeOpen (TPM-side, ActivateCredential) | Done |
| Well-known key (hardcoded template) | Done |
| Owner hierarchy key (decommissioning) | Done |
| Quote verification (signature + nonce) | Done (RSA + ECC) |
| Eventlog parsing (TCG PC Client) | Done (legacy + crypto-agile) |
| PCR extension database (SQLite3) | Done |
| Eventlog validation (replay + DB check) | Done |
| IMA eventlog parsing | Not implemented |

## CLI Tool (appl/htpm2/htpm2tool)

| Sub-command | Status |
|-------------|--------|
| `timestamp` | Done (generate + verify) |
| `encrypt-to` | Done |
| `envelope-open` | Done |
| `quote-verify` | Done (eventlog + DB; no quote signature check yet) |
| `policy compile` | Not implemented |
| `policy evaluate` | Not implemented |
| `policy info` | Not implemented |

## Transport Backends

| Backend | Status |
|---------|--------|
| Device (`/dev/tpmrm0`) | Done |
| Socket (AF_UNIX) | Done |
| TCP | Done |
| Pipe (fork+exec) | Done |
| Windows TBS | Not implemented |
| Custom (pluggable vtable) | Stub |

## Test Coverage

| Test File | Tests | Needs TPM |
|-----------|-------|-----------|
| test_result.c | 8 | No |
| test_crypto.c | 5 | No |
| test_policy_parse.c | 7 | No |
| test_swtpm.c | 30+ | Yes (swtpm) |

swtpm tests cover: GetRandom, key creation (RSA + ECC), Load,
ReadPublic, sessions (HMAC, encrypted, salted, trial), Sign, Quote,
PCR_Read, policy trial (PolicyPCR + PolicyCommandCode + GetDigest),
policy compilation (deterministic digests), policy evaluation
(end-to-end: compile → create key → evaluate → sign), MakeCredential,
EncryptTo, EnvelopeOpen, encrypted GetRandom (parameter decryption).

## Known Limitations

1. **CertifyCreation and CertifyX509** are stubs.  CertifyX509
   requires `lib/asn1` for DER encoding.

2. **PolicySigned/PolicySecret/PolicyAuthorize** in the policy
   compiler need object loading to compute key Names.  Works in
   the evaluator but the compiler returns ENOSYS for these.

3. **ECC salted sessions** (ECDH key agreement for session salting)
   not implemented.  RSA salting works.

4. **Multi-auth commands** (commands needing 2+ auth sessions):
   ActivateCredential uses hardcoded password auth for both sessions.
   Proper HMAC session support for multi-auth needs the command
   builder to accept an array of sessions.

5. **PolicyOr reference resolution**: named/URI references in
   PolicyOr alternatives are parsed but not resolved.  Only inline
   alternatives work.

6. **IMA eventlog format** not parsed (only TCG PC Client binary).

7. **Windows TBS transport** not implemented.

8. **TPM2_Hash** not implemented (GetRandom and Hash are the two
   simplest commands; Hash was skipped since it's rarely needed
   when you have OpenSSL).
