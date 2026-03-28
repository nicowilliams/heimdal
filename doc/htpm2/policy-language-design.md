# TPM 2.0 Policy Language Design

## Overview

A JSON-based language for defining, compiling, and evaluating TPM 2.0
authorization policies.  A policy document describes a sequence of
`TPM2_Policy*()` commands that must be satisfied to authorize an
operation.

The same JSON document is used for:
1. **Compilation**: computing the `policyDigest` via a trial session
2. **Evaluation**: satisfying the policy via a real policy session
3. **Documentation**: human-readable description of what the policy requires

## Design Principles

1. **One JSON document = one policy**.  Alternatives (PolicyOr branches)
   can be inlined or referenced by name/URI.

2. **Inputs are explicit**.  Runtime values (signatures, tickets, NV
   values, user choices) are declared as named inputs with types.
   The evaluator must supply them.

   Some such inputs might have to be provided by users (e.g., via
   function arguments or command-line options, interactive prompts,
   or bath answers files).  Others will have to be obtained by code
   rather than from users, such as tickets for PolicySigned commands.

3. **Object references are descriptive**.  Any TPM object a policy
   command needs (for PolicySigned, PolicySecret, PolicyNV, etc.) is
   described by how to access or it: a persistent handle, primary
   template + hierarchy, or external pub/priv blobs.

4. **Trial compilation ignores runtime inputs**.  PolicySigned in
   trial mode only needs the signing key's Name, not an actual
   signature.  The compiler must be able to derive Names from
   object definitions.

5. **Composition via references**.  A policy can reference another
   policy by name and/or URI.  The resolver loads it and inlines it.
   This enables a library of reusable sub-policies.

## JSON Schema

### Top Level

```json
{
  "tpm2Policy": {
    "version": 1,
    "name": "my_policy",
    "description": "Human-readable description",
    "hashAlg": "sha256",
    "inputs": [ ... ],
    "policy": [ ... ]
  }
}
```

### Inputs

Inputs are runtime values that the policy evaluator must supply.
They are referenced by name (`$item_name`) in policy nodes.

```json
{
  "inputs": [
    {
      "input": "$signer_auth",
      "description": "Signature from the authorized signer",
      "valueType": "signature"
    },
    {
      "input": "$alt",
      "description": "Which PolicyOr branch to take",
      "valueType": "arrayIndex"
    },
    {
      "input": "$nv_value",
      "description": "Current NV index value",
      "valueType": "bytes"
    }
  ]
}
```

Value types:
- `"signature"` -- `TPMT_SIGNATURE` blob
- `"ticket"` -- `TPMT_TK_VERIFIED` blob
- `"bytes"` -- arbitrary byte string (hex-encoded)
- `"arrayIndex"` -- integer selecting a PolicyOr branch
- `"integer"` -- numeric value (for counter/timer comparisons)
- `"boolean"` -- true/false

### Policy Nodes

Each node in the `"policy"` array is one `TPM2_Policy*()` command.
The `"cc"` field identifies the command.

#### All 19 Policy Commands

```json
{ "cc": "PolicyPCR",
  "pcrs": {
    "hashAlg": "sha256",
    "selections": [
      { "pcr": 0 },
      { "pcr": 7 }
    ]
  },
  "pcrDigest": "hex..."  // optional: expected digest, empty = use current
}

{ "cc": "PolicyCommandCode",
  "commandCode": "Sign"  // or numeric: "0x0000015D"
}

{ "cc": "PolicyAuthValue" }
// No parameters -- just asserts the caller knows the object's authValue.

{ "cc": "PolicyPassword" }
// Like PolicyAuthValue but uses plaintext password in HMAC calc.

{ "cc": "PolicySigned",
  "authObject": { ... },  // object definition (see below)
  "policyRef": "hex...",  // optional
  "expiration": 0,        // int32, 0 = no expiry
  "auth": "$signer_auth"  // input reference for the signature
}

{ "cc": "PolicySecret",
  "authObject": { ... },  // entity whose secret authorizes
  "policyRef": "hex...",
  "expiration": 0
}

{ "cc": "PolicyAuthorize",
  "keySign": { ... },     // object definition for the authorizing key
  "approvedPolicy": "hex...",  // or "$input_ref"
  "policyRef": "hex...",
  "ticket": "$ticket_input"   // input reference
}

{ "cc": "PolicyOR",
  "alternatives": [
    { "reference": "policy_name_or_uri" },
    { "tpm2Policy": { "policy": [ ... ] } },
    ...
  ],
  "select": "$alt"  // input reference for which branch to evaluate
}

{ "cc": "PolicyLocality",
  "locality": 1  // bitmask: localities 0-4
}

{ "cc": "PolicyNV",
  "nvIndex": "0x01000001",
  "operandB": "hex...",    // comparison value
  "offset": 0,
  "operation": "eq"        // eq, neq, gt, lt, ge, le, bitset, bitclear
}

{ "cc": "PolicyCounterTimer",
  "operandB": "hex...",
  "offset": 0,
  "operation": "gt"
}

{ "cc": "PolicyPhysicalPresence" }
// No parameters.

{ "cc": "PolicyCpHash",
  "cpHash": "hex..."
}

{ "cc": "PolicyNameHash",
  "nameHash": "hex..."
}

{ "cc": "PolicyDuplicationSelect",
  "objectName": "hex...",
  "newParentName": "hex...",
  "includeObject": true
}

{ "cc": "PolicyTicket",
  "timeout": "hex...",
  "cpHashA": "hex...",
  "policyRef": "hex...",
  "authName": "hex...",
  "ticket": "$ticket_input"
}

{ "cc": "PolicyNvWritten",
  "writtenSet": true
}

{ "cc": "PolicyTemplate",
  "templateHash": "hex..."
}

{ "cc": "PolicyAuthorizeNV",
  "nvIndex": "0x01000001"
}
```

### Object Definitions

Objects referenced by policy commands (keys, NV indices, etc.) are
described by how to find/load them.  Multiple strategies:

```json
{
  "objectDef": {
    // Strategy 1: Persistent handle
    "persistent": "0x81000001"
  }
}

{
  "objectDef": {
    // Strategy 2: Primary key from template
    "primary": {
      "hierarchy": "endorsement",
      "template": "ek_rsa_2048_storage"  // template reference or an inlined template (see below)
    }
  }
}

{
  "objectDef": {
    // Strategy 3: Load from key save blobs
    "load": {
      "parent": { ... },  // recursive objectDef for parent
      "pub": "hex...",     // or file path
      "priv": "hex..."
    }
  }
}

{
  "objectDef": {
    // Strategy 4: NV index
    "nvIndex": "0x01000001"
  }
}

{
  "objectDef": {
    // Strategy 5: Well-known key (for our enrollment protocol)
    "wellKnown": {
      "policy": "hex..."  // the policy digest for the well-known key
    }
  }
}
```

### Named Templates

Standard key templates referenced by name:

```
"ek_rsa_2048_storage"   -- standard EK template (endorsement)
"ek_rsa_2048_decrypt"   -- EK for decryption
"srk_rsa_2048"          -- standard SRK (owner)
"ak_rsa_2048_sign"      -- attestation key
"wk_keyedhash"          -- well-known key
```

### Template Definitions

Alternatively a template object could be inlined, something like:

```
{
  "type": "ECC",
  "nameAlg": "...",
  "objectAttributes": ["fixedTPM", "fixedParent", "restricted"],
  "authPolicy": ..., // a policy reference or inlined policy
  "parameters": ...,
  "userAuth": "auth value",
  "data": "...", // for salting a primary key
  "pcr": ..., // PCR selection
}
```

### PolicyOr and Composition

PolicyOr alternatives are either inline or referenced:

```json
{ "cc": "PolicyOR",
  "alternatives": [
    {
      "reference": "ACME_boot_policy_linux",
      "uri": "https://policies.acme.com/linux/v2.json"
    },
    {
      "reference": "ACME_boot_policy_windows"
    },
    {
      "tpm2Policy": {
        "name": "inline_emergency_recovery",
        "policy": [
          { "cc": "PolicySigned",
            "authObject": {
              "objectDef": { "persistent": "0x81000002" }
            },
            "auth": "$recovery_sig"
          }
        ]
      }
    }
  ],
  "select": "$alt"
}
```

The resolver looks up references by:
1. Name in a local policy store (directory of JSON files)
2. URI fetch (with signature verification)

### Command Code Names

String names for TPM_CC values (case-insensitive):

```
Startup, GetRandom, CreatePrimary, Create, Load, Sign,
VerifySignature, Quote, Certify, CertifyCreation, CertifyX509,
RSA_Decrypt, ECDH_ZGen, MakeCredential, ActivateCredential,
Import, Duplicate, EvictControl, FlushContext, ContextSave,
ContextLoad, ReadPublic, PCR_Read, PCR_Extend, Hash, ...
```

### NV Comparison Operations

```
eq       -- equal
neq      -- not equal
gt       -- unsigned greater than
lt       -- unsigned less than
ge       -- unsigned greater or equal
le       -- unsigned less or equal
bitset   -- all bits in operandB are set in NV
bitclear -- all bits in operandB are clear in NV
```

## Implementation Plan

### Phase 1: Schema and Parsing

- Define C structures for parsed policy nodes
- JSON parser (using Heimdal's JSON parser in `lib/base`)
- Validate structure, resolve named templates

### Phase 2: Trial Compilation

- `htpm2_policy_compile(ctx, json, &digest)`:
  Start trial session, walk policy nodes, execute each
  `TPM2_Policy*()` command in trial mode, return policyDigest.
- For PolicySigned/PolicyAuthorize: compute key Name from
  objectDef, use in trial (no actual signature needed).
- For PolicyOr: compile each alternative, collect digests.

### Phase 3: Evaluation

- `htpm2_policy_evaluate(ctx, tp, json, inputs, &session)`:
  Start real policy session, walk policy nodes, execute each
  with real inputs.  For PolicyOr: use `select` input to pick
  the branch.  For PolicySigned: use signature from inputs.
- Object loading: resolve objectDefs, load keys, manage handles.
- Input validation: check all required inputs are provided.

Note that objects loaded for the purpose of executing a policy command
can then be flushed to make room for other objects needed subsequently.

### Phase 4: CLI Integration

- `htpm2tool policy compile --policy <json> [--transport <uri>]`
  Compute and print policyDigest.
- `htpm2tool policy evaluate --policy <json> --transport <uri> [--input key=value ...]`
  Evaluate policy, output satisfied session handle.
- `htpm2tool policy info --policy <json>`
  Print human-readable description of the policy and what inputs it
  requires.

## Open Questions / Guidance

1. **JSON library**: Use Heimdal's JSON parser from `lib/base/`.

2. **PolicyOr digest ordering**: The JSON alternatives array order
   corresponds to the order of the alternatives in the PolicyOr command,
   and the number of them is limited to the number that the TPM limits
   (typically 8).  In particular this compiler/evaluator will not
   compile a too-long set of alternatives into a tree of PolicyOr
   commands.

3. **Policy signing**: For PolicyAuthorize, the approved policy
   digest must be signed by the authorizing key.  These must be obtained
   interactively and must be be provided externally (i.e., by the
   caller/user).

4. **NV index authorization**: PolicyNV and PolicyAuthorizeNV may
   need their own auth sessions for the NV index.  How does this
   compose with the policy session?

   For PolicyNV there is no composition issue.  For PolicyAuthorizeNV
   the situation is the same as with PolicyAuthorize: a policy that uses
   either PolicyAuthorizeNV or PolicyAuthorize must start with that
   command, and the policy session's current `policyDigest` must be a
   policy that the TPM will accept because it's what is written in the
   NV or by the external authorization provider.

5. **Recursion depth**: PolicyOr, PolicyAuthorize, and PolicyAuthorizeNV
   can create recursive policy structures (the substituted policy itself
   can contain these commands).  Infinite cycles are possible, therefore
   we need a depth limit.  Eight is a reasonable depth limit.
