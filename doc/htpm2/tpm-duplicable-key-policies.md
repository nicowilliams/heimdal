# TPM 2.0 Duplicable Key Policy Specification

## Background and Conventions

### Key Attributes for Duplicable Keys

Any key intended to be duplicable must be created with:

- `fixedTPM = CLEAR` — key is not bound to the creating TPM
- `fixedParent = CLEAR` — key may be re-parented under duplication
- `encryptedDuplication = SET` — (recommended) key material is encrypted to the destination parent during duplication

Keys with `fixedTPM = SET` or `fixedParent = SET` cannot be duplicated regardless of policy.

### The PolicyCommandCode Problem

`TPM2_PolicyCommandCode` irreversibly extends the session digest toward a specific command
code. A session extended with `CC_Duplicate` cannot authorize any other command, and a
session not extended with `CC_Duplicate` cannot satisfy a flat policy that includes it.

Therefore, any key that must be both **usable** and **duplicable** requires a top-level
`PolicyOR` separating the duplication branch from the use branch(es). Keys that are
**duplication-only** (pure migration containers) may omit the `PolicyOR`.

### Policy Digest Computation

All policy digests are computed as iterative hash extensions over a zero-initialized
buffer of `nameAlg` length. The notation used throughout this document:

```
H(...)        — hash using the key's nameAlg
CC_Foo        — TPM_CC value for command Foo
||            — concatenation
len16(x)      — two-byte big-endian length prefix
zeros         — zero-filled buffer of nameAlg digest length
```

The starting digest for any branch computation is `zeros`.

---

## Policy 1: Static Ring — Duplication-Only Key

### Intent

A key that can be duplicated to any one of a fixed, enumerated set of destination TPMs,
and cannot be used for any other purpose. Suitable for pure key-migration containers
where the key has no direct cryptographic use on the source TPM.

### Policy Structure

```
authPolicy = PolicyOR(
    branch_0,   ← PolicyCommandCode(Duplicate) + PolicyDuplicationSelect(NP_0)
    branch_1,   ← PolicyCommandCode(Duplicate) + PolicyDuplicationSelect(NP_1)
    ...
    branch_n
)
```

### Branch Digest Computation

For each destination TPM *i* with migration parent Name `NP_i`:

```
d_0 = zeros
d_1 = H(d_0 || CC_PolicyCommandCode || CC_Duplicate)
d_2 = H(d_1 || CC_PolicyDuplicationSelect
             || len16(objectName) || objectName
             || len16(NP_i) || NP_i
             || 0x01)          ← includeObject = YES
branch_i = d_2
```

The `objectName` is the Name of the key being created. If computing this before key
creation (circularity), set `objectName` to `zeros` and `includeObject` to `0x00`,
accepting that the policy does not pin the specific key object.

### Top-Level PolicyOR Digest

```
authPolicy = H(zeros || CC_PolicyOR || branch_0 || branch_1 || ... || branch_n)
```

`PolicyOR` accepts at most 8 branches. For rings larger than 8, build a tree:

```
group_A = PolicyOR(branch_0 .. branch_7)
group_B = PolicyOR(branch_8 .. branch_15)
authPolicy = PolicyOR(group_A, group_B)
```

Each intermediate `PolicyOR` digest is computed the same way and treated as a branch
in the outer `PolicyOR`.

### Session Satisfaction

To duplicate to destination *j*:

1. `TPM2_StartAuthSession` → `session`
2. `TPM2_PolicyCommandCode(session, TPM2_CC_Duplicate)`
3. `TPM2_PolicyDuplicationSelect(session, objectName, NP_j, YES)`
   — session digest is now `branch_j`
4. `TPM2_PolicyOR(session, [branch_0, branch_1, ..., branch_n])`
   — TPM verifies current digest matches one listed branch; resets digest to `authPolicy`
5. `TPM2_Duplicate(objectHandle, NP_j, session)`

### Enrollment

For each ring member TPM *i*:

1. Create or identify a migration parent key on TPM *i* (typically a storage key under
   the owner hierarchy)
2. Record `NP_i = nameAlg || H(publicArea_i)`
3. Distribute the set `{NP_0, ..., NP_n}` to all ring participants
4. Compute branch and `authPolicy` digests offline
5. Create the duplicable key with the computed `authPolicy`

### Security Properties

- Destination is cryptographically pinned at key-creation time
- Adding or removing a ring member requires recreating the key
- No online service required at duplication time
- `includeObject = YES` prevents the policy from being satisfied for a different key
  object even with the same session state

---

## Policy 2: Static Ring — Usable and Duplicable Key

### Intent

A key that serves a normal cryptographic purpose (signing, decryption, sealing) on the
source TPM, but can also be duplicated to enumerated destination TPMs. The use and
duplication authorization paths are separated by a top-level `PolicyOR`.

### Policy Structure

```
authPolicy = PolicyOR(
    use_branch,           ← normal use policy, no PolicyCommandCode or with CC_Sign etc.
    dup_branch_0,         ← PolicyCommandCode(Duplicate) + PolicyDuplicationSelect(NP_0)
    dup_branch_1,
    ...
    dup_branch_n
)
```

Note the 8-branch `PolicyOR` limit applies to the total count of branches including the
use branch. For rings of 7 or more destinations, the duplication branches should be
grouped into a nested `PolicyOR` that occupies a single slot:

```
authPolicy = PolicyOR(
    use_branch,
    PolicyOR(dup_branch_0 .. dup_branch_6)   ← nested group
)
```

### Use Branch Digest Computation

The use branch encodes whatever authorization is appropriate for the key's purpose. It
must **not** include `PolicyCommandCode` unless you wish to restrict use to a specific
command. Example for a signing key requiring PCR state and auth value:

```
d_0 = zeros
d_1 = H(d_0 || CC_PolicyPCR || pcrSelectionDigest || pcrDigest)
d_2 = H(d_1 || CC_PolicyAuthValue)
use_branch = d_2
```

Or, for a key requiring only an auth value (simplest case):

```
d_0 = zeros
d_1 = H(d_0 || CC_PolicyAuthValue)
use_branch = d_1
```

### Duplication Branch Digest Computation

Same as Policy 1:

```
d_0 = zeros
d_1 = H(d_0 || CC_PolicyCommandCode || CC_Duplicate)
d_2 = H(d_1 || CC_PolicyDuplicationSelect || len16(objectName) || objectName
             || len16(NP_i) || NP_i || 0x01)
dup_branch_i = d_2
```

### Top-Level PolicyOR Digest

```
authPolicy = H(zeros || CC_PolicyOR || use_branch || dup_branch_0 || ... || dup_branch_n)
```

### Session Satisfaction for Use

1. `TPM2_StartAuthSession` → `session`
2. Execute the use branch assertions (e.g., `TPM2_PolicyPCR`, `TPM2_PolicyAuthValue`)
   — session digest is now `use_branch`
3. `TPM2_PolicyOR(session, [use_branch, dup_branch_0, ..., dup_branch_n])`
4. Issue the use command (e.g., `TPM2_Sign`) with `session`

### Session Satisfaction for Duplication

Same as Policy 1, with `TPM2_PolicyOR` listing all branches including `use_branch`.

---

## Policy 3: Dynamic Ring via PolicyAuthorize — Usable and Duplicable Key

### Intent

A key whose ring of valid duplication destinations is managed dynamically by an external
membership authority, without requiring the key to be recreated when the ring changes.
Destinations are authorized by the membership authority signing a per-destination policy
digest. Suitable when ring membership changes frequently or is not known at key-creation
time.

### Trust Model

A **membership authority** holds an asymmetric signing key `AK_auth`. Its public area is
fixed and known at key-creation time. The authority issues **authorization tickets**:
signatures over `(approved_policy_digest || policyRef)` for each approved destination.
Possession of a valid ticket, plus the ability to load `AK_auth` on the source TPM,
is sufficient to authorize duplication to that destination.

### Policy Structure

```
authPolicy = PolicyOR(
    use_branch,
    dup_branch     ← PolicyCommandCode(Duplicate)
                      + PolicyDuplicationSelect(object, NP_j, YES)   [computed at runtime]
                      + PolicyAuthorize(AK_auth_name, policyRef)
)
```

Because `PolicyDuplicationSelect` pins `NP_j` at session time (not at key-creation
time), the `dup_branch` digest itself is destination-dependent and computed fresh for
each duplication operation. The `PolicyAuthorize` digest subsumes it.

### PolicyAuthorize Digest Computation

The `dup_branch` stored in `authPolicy` is the `PolicyAuthorize` tail:

```
d_0 = zeros
d_1 = H(d_0 || CC_PolicyCommandCode || CC_Duplicate)
d_2 = H(d_1 || CC_PolicyAuthorize || len16(AK_auth_name) || AK_auth_name || len16(policyRef) || policyRef)
dup_branch = d_2
```

Note that `PolicyDuplicationSelect` does **not** appear in this digest — it appears only
in the approved policy that the authority signs, not in the key's `authPolicy`.

### Ticket Issuance (Out-of-Band)

For each candidate destination TPM *j*:

1. TPM *j* presents its migration parent public area and EK certificate chain to the
   authority
2. Authority verifies the EK chain against a trusted CA
3. Authority optionally requires TPM *j* to prove possession of a required resident key
   via `TPM2_Certify` (see Policy 4)
4. Authority computes the **approved policy** digest for destination *j*:

   ```
   ap_0 = zeros
   ap_1 = H(ap_0 || CC_PolicyCommandCode || CC_Duplicate)
   ap_2 = H(ap_1 || CC_PolicyDuplicationSelect
                  || len16(objectName) || objectName
                  || len16(NP_j) || NP_j || 0x01)
   approved_j = ap_2
   ```

5. Authority signs `(approved_j || policyRef)` with `AK_auth` → `ticket_j`
6. Issues `(approved_j, ticket_j, policyRef)` to TPM *j*

### Session Satisfaction for Duplication

1. `TPM2_StartAuthSession` → `session`
2. `TPM2_PolicyCommandCode(session, TPM2_CC_Duplicate)`
3. `TPM2_PolicyDuplicationSelect(session, objectName, NP_j, YES)`
   — session digest is now `approved_j`
4. Load `AK_auth` public key onto source TPM → `authKeyHandle`
5. `TPM2_VerifySignature(authKeyHandle, approved_j, ticket_j)` → `verificationTicket`
6. `TPM2_PolicyAuthorize(session, approvedPolicy=approved_j, policyRef, AK_auth_name, verificationTicket)`
   — TPM verifies session digest matches `approved_j`, then resets digest to `dup_branch`
7. `TPM2_PolicyOR(session, [use_branch, dup_branch])`
8. `TPM2_Duplicate(objectHandle, NP_j, session)`

### policyRef Design

`policyRef` is hashed into both `dup_branch` (baked into `authPolicy`) and the signed
ticket, scoping what `AK_auth` can approve. Recommended contents:

| policyRef Content | Effect |
|---|---|
| Empty | `AK_auth` can approve any policy; tickets are fully general |
| Fixed label (e.g., `"ring-v1"`) | Tickets are scoped to a named ring version; rotating the label invalidates all outstanding tickets |
| `objectName` of the duplicable key | Tickets are per-key; a ticket for key *K* cannot authorize duplication of key *K'* |
| Expiry timestamp | Tickets become invalid after the encoded time (enforced by the authority at issuance; the TPM does not parse `policyRef` content) |

### Revocation

`PolicyAuthorize` has no native revocation. Strategies:

- **Epoch rotation**: change `policyRef` (requires recreating the key, since `policyRef`
  is baked into `authPolicy`)
- **Short-lived tickets**: authority issues tickets with embedded expiry; the source TPM
  or application enforces expiry out-of-band before calling `TPM2_VerifySignature`
- **NV-backed revocation list**: combine with `PolicyNV` in the `dup_branch` that checks
  an NV index encoding revoked destinations; requires NV write access at revocation time

### Security Properties vs. Policy 1/2

| Property | Static Ring | Dynamic (PolicyAuthorize) |
|---|---|---|
| Destination pinned at key creation | Yes | No — pinned at session time |
| Ring changes require key recreation | Yes | No |
| Online authority required at duplication | No | No (ticket pre-issued) |
| Online authority required for membership | N/A | Yes |
| Revocation granularity | Per-key recreation | Per-ticket expiry or epoch |

---

## Policy 4: Self-Sovereign Ring via PolicySigned — Usable and Duplicable Key

### Intent

A key that can be duplicated to any TPM that possesses a specific **membership key**,
without an online membership authority at duplication time. Possession of the membership
key is the membership credential. Suitable for peer-to-peer rings where membership is
conferred by key possession rather than by a central authority's ongoing participation.

### Trust Model

A **membership key** `MK` is a signing key whose public area is fixed and known at
key-creation time. Any TPM that holds `MK` (or has it loaded) can authorize duplication
by signing the source TPM's session nonce. The membership key's `Name` is baked into
the `authPolicy`.

Membership is conferred by distributing `MK` to new ring members. If `MK` is itself
created with `fixedTPM = SET` on each member TPM, possession is hardware-bound.

### Policy Structure

```
authPolicy = PolicyOR(
    use_branch,
    dup_branch     ← PolicyCommandCode(Duplicate)
                      + PolicyDuplicationSelect(object, newParent, YES)
                      + PolicySigned(MK_name, policyRef)
)
```

If destinations need not be pinned (any member TPM can be the destination), omit
`PolicyDuplicationSelect` or use `includeObject = NO`. See the trade-off discussion
below.

### Dup Branch Digest Computation

Without destination pinning:

```
d_0 = zeros
d_1 = H(d_0 || CC_PolicyCommandCode || CC_Duplicate)
d_2 = H(d_1 || CC_PolicySigned || len16(MK_name) || MK_name || len16(policyRef) || policyRef)
dup_branch = d_2
```

With destination pinning (requires PolicyOR over destinations, or acceptance that the
destination is fixed at session time and membership key possession is the gate):

```
d_0 = zeros
d_1 = H(d_0 || CC_PolicyCommandCode || CC_Duplicate)
d_2 = H(d_1 || CC_PolicyDuplicationSelect || len16(objectName) || objectName
             || len16(NP_j) || NP_j || 0x01)
d_3 = H(d_2 || CC_PolicySigned || len16(MK_name) || MK_name || len16(policyRef) || policyRef)
dup_branch = d_3
```

In this variant, `dup_branch` is the same for all destinations (because `NP_j` is not
fixed in the `authPolicy` digest — it is applied to the session at runtime). The
`PolicySigned` assertion is destination-agnostic; destination identity comes from the
runtime `PolicyDuplicationSelect` call.

### Session Satisfaction for Duplication

The destination TPM *j* and source TPM cooperate:

1. Source TPM: `TPM2_StartAuthSession` → `session`, obtains `nonceTPM`
2. Source TPM: `TPM2_PolicyCommandCode(session, TPM2_CC_Duplicate)`
3. Source TPM: `TPM2_PolicyDuplicationSelect(session, objectName, NP_j, YES)`
4. **Destination TPM *j***: signs `(nonceTPM || expiration || cpHashA || policyRef)`
   with `MK` → `sig`
   - `expiration`: optional session expiry (0 for no expiry)
   - `cpHashA`: optional hash of the command parameters (0 to skip)
5. Source TPM: `TPM2_PolicySigned(session, authObject=MK_handle, nonceTPM, cpHashA, policyRef, expiration, sig)`
   — TPM verifies `sig` against `MK` public key and advances session digest to `dup_branch`
6. Source TPM: `TPM2_PolicyOR(session, [use_branch, dup_branch])`
7. Source TPM: `TPM2_Duplicate(objectHandle, NP_j, session)`

Step 4 requires the destination TPM to have `MK` loaded and to sign the nonce. The
signature is produced by the destination and transmitted to the source out-of-band (e.g.,
over a mutually authenticated channel).

### Membership Key Options

**Shared membership key (all members hold the same key pair)**

All ring members hold identical copies of `MK`. Any member can sign the nonce; the
policy cannot distinguish *which* member signed. Simpler to manage; compromise of `MK`
by any member compromises the ring.

**Per-member membership keys under a common template**

Each member TPM holds a unique `MK_i`, but all are created from the same template under
the same parent, producing the same `Name` (since `Name = nameAlg || H(publicArea)` and
public areas differ). This does not work — distinct key pairs have distinct public areas
and thus distinct Names. Cannot be used to produce a single `MK_name` in `authPolicy`.

**Per-member membership keys with PolicyOR**

Each member TPM *i* holds a unique `MK_i` with Name `MKN_i`. The `dup_branch` becomes:

```
authPolicy = PolicyOR(
    use_branch,
    PolicyOR(
        dup_branch_0,    ← ... + PolicySigned(MKN_0, policyRef)
        dup_branch_1,    ← ... + PolicySigned(MKN_1, policyRef)
        ...
    )
)
```

This recovers the static enumeration of Policy 1/2 but with possession-based
authorization rather than destination-name-based authorization. Ring changes require
key recreation.

### "Has a Particular Key Loaded" — Proving Possession at Enrollment

If membership requires a TPM to prove it holds a specific resident key `RK` (distinct
from `MK`), this proof occurs at membership key distribution time:

1. Candidate TPM *j* calls `TPM2_Certify(objectHandle=RK, signHandle=AK_j)` →
   `attestation, signature`
2. Distribute `(attestation, signature, AK_j certificate)` to the membership granting
   party
3. Granting party verifies:
   - `AK_j` certificate chains to TPM *j*'s EK certificate
   - `attestation` is a valid `TPM_ST_ATTEST_CERTIFY` structure signed by `AK_j`
   - `attestation.name` matches the expected `Name` of `RK`
4. Granting party distributes `MK` to TPM *j*

The TPM spec guarantees that `TPM2_Certify` with a loaded AK produces an attestation
binding the certified object's Name to the AK's TPM — so the `Certify` signature proves
`RK` is loaded on the same TPM as `AK_j`.

### Self-Reinforcing Bootstrap

If `MK` itself carries the same ring policy (i.e., `MK` is duplicable only within the
ring), the ring becomes self-reinforcing:

- You can only receive `MK` if you are already a ring member (have `MK` loaded, to
  satisfy `PolicySigned` for the duplication of `MK` itself)
- Except for the bootstrap member, who receives `MK` out-of-band during initial
  provisioning

This creates a closed membership graph with no external authority required after
provisioning.

### Destination Pinning Trade-Off

| Configuration | `PolicyDuplicationSelect` | Effect |
|---|---|---|
| Unpinned | Omitted or `includeObject = NO` | Any member can receive; destination identity not enforced by policy |
| Runtime-pinned | Present at session time, `NP_j` set at runtime | Specific destination per duplication operation; policy does not enumerate destinations |
| Statically pinned | `NP_j` fixed in `authPolicy` | Requires PolicyOR per destination; reverts toward Policy 1/2 structure |

Runtime-pinned is generally the right choice for Policy 4: the membership key gates
*who* can initiate receipt, and `PolicyDuplicationSelect` ensures the key goes to *that
specific TPM's parent* and not somewhere else, without enumerating all possible
destinations in the `authPolicy`.

---

## Comparison Summary

| | Policy 1 | Policy 2 | Policy 3 | Policy 4 |
|---|---|---|---|---|
| Key usable on source TPM | No | Yes | Yes | Yes |
| Destinations enumerated in authPolicy | Yes | Yes | No | No (shared MK) / Yes (per-member MK) |
| Ring changes require key recreation | Yes | Yes | No | No (shared MK) |
| Online authority at duplication time | No | No | No (ticket pre-issued) | No |
| Online authority for membership changes | N/A | N/A | Yes | Only for MK distribution |
| Membership credential | Destination parent Name | Destination parent Name | Authority-signed ticket | Possession of MK |
| Revocation mechanism | Key recreation | Key recreation | Ticket expiry / epoch | MK rotation |
| Suitable ring size | Small (≤ ~56 with nesting) | Small | Unbounded | Unbounded (shared MK) |
