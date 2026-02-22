# ASN.1 Compiler and Codec Interface Revamp Plan

This document outlines a long-term plan for revamping Heimdal's ASN.1
compiler and generated codec interfaces.  Each section is a major work
area.  These are largely independent and can be tackled in any order
(though some have natural dependencies noted below).

---

## 1. New Codec Function Signatures (IMPLICIT Tag Parameter)

### Problem

The current `encode_T()` / `length_T()` / `decode_T()` functions have no
way to accept an implicit tag override.  This forces the codegen backend
to use a terrible hack: encode into a temp buffer, strip the tag the
encoder produced, and splice in the right tag.  This is the "HACK HACK
HACK" documented in `gen_encode.c` lines 416-439.

The hack:
- Allocates a temporary buffer for every implicitly-tagged value
- On decode, `der_replace_tag()` allocates another copy
- Requires compile-time `asn1_tag_length_T` / `asn1_tag_class_T` /
  `asn1_tag_tag_T` enums for each type
- Generates fragile pointer arithmetic that is hard to audit
- Tag lengths can differ between old and new tags, requiring careful
  size adjustments

The template backend avoids this via `A1_FLAG_IMPLICIT` at runtime, but
the generated per-type functions can't do that.

### Proposed New Signatures

```c
/* New: optional implicit tag via const struct pointer (NULL = no override) */
typedef struct asn1_tag_override {
    Der_class  tag_class;
    Der_type   tag_type;
    unsigned   tag_value;
} asn1_tag_override;

int    decode_T(const unsigned char *p, size_t len, T *data, size_t *size,
                const asn1_tag_override *implicit_tag);
int    encode_T(unsigned char *p, size_t len, const T *data, size_t *size,
                const asn1_tag_override *implicit_tag);
size_t length_T(const T *data,
                const asn1_tag_override *implicit_tag);
```

When `implicit_tag` is NULL, behavior is identical to today.  When
non-NULL, the encoder emits the override tag instead of the type's
natural outermost tag, the length function accounts for the override tag
size, and the decoder expects the override tag.

### Migration Strategy

The existing `decode_T(p, len, data, size)` 4-argument signatures are
effectively the ABI.  Options:

**Option A: Backwards-compatible stubs.** Generate new `_v2` functions
with the 5-argument signature.  Generate inline stubs for the old
4-argument names that call the `_v2` functions with `NULL`.  Old callers
still work; new callers (including the compiler's own generated code) use
the `_v2` interface.  The `asn1_tag_*` enums and `der_replace_tag()` hack
can be removed once all callers migrate.

**Option B: Break ABI immediately.** Change all signatures at once.  All
in-tree callers get updated.  Out-of-tree callers break.

**Option C (recommended): Versioned symbol maps.** Use symbol versioning
to export both the old and new signatures simultaneously.  Old binaries
link to the old version; new builds get the new version.

### Files Affected

- `gen.c` — prototype generation, `asn1_tag_*` enum generation
- `gen_encode.c` — the entire `replace_tag` machinery
- `gen_decode.c` — `der_replace_tag()` usage
- `gen_length.c` — tag length adjustment logic
- `der_put.c` — `der_replace_tag()` can eventually be removed
- `version-script.map` — symbol versioning

---

## 2. Function Naming / Prefixing

### Problem

Current naming: `decode_T`, `encode_T`, `length_T`, `copy_T`, `free_T`,
`print_T`, `asn1_parse_T`.  The unprefixed names (`decode_`, `encode_`,
`free_`, `copy_`) pollute the global namespace and can conflict with
application or library symbols.

### Proposal

Use a consistent `asn1_` prefix for all generated functions:

```c
asn1_decode_T()      /* was: decode_T() */
asn1_encode_T()      /* was: encode_T() */
asn1_length_T()      /* was: length_T() */
asn1_copy_T()        /* was: copy_T() */
asn1_free_T()        /* was: free_T() */
asn1_print_T()       /* was: print_T() — already consistent-ish */
asn1_parse_T()       /* was: asn1_parse_T() — already good */
```

### Migration Strategy

Generate `#define decode_T asn1_decode_T` compat macros in the header
(controlled by a `ASN1_COMPAT_NAMES` flag).  In-tree callers get updated
incrementally.  After a release cycle, the macros are removed.

Could be done in conjunction with the signature change in section 1
(rename + new signature at the same time, with stubs for the old names).

---

## 3. Encoding Rules Flag / Multi-ER Support

### Problem

Currently the codegen backend generates only DER codecs and the template
backend supports DER and has growing JER (JSON) support.  If we want to
support BER, CER, OER, PER, or other encoding rules, we need a way to
select which rules to use at runtime or compile time.

### Approaches

There are two fundamentally different ways to support multiple ERs,
each with distinct tradeoffs:

**Approach A: Flags argument (runtime selection).**  Add a `flags`
field to the codec context struct:

```c
typedef struct asn1_codec_ctx {
    unsigned              flags;        /* ASN1_DER, ASN1_BER, ASN1_JER, ... */
    const asn1_tag_override *implicit_tag;  /* From section 1 */
    /* Future: arena, error context, etc. */
} asn1_codec_ctx;

int asn1_decode_T(const unsigned char *p, size_t len, T *data, size_t *size,
                  const asn1_codec_ctx *ctx);
```

The template backend already works this way — `_asn1_decode()` takes a
`flags` parameter and branches internally.  This adds branches at
runtime, which is a performance cost.  But the whole point of the
template approach is trading branches for smaller I-cache footprint,
and that's supposedly a large win.  So for the template backend, flags
are the natural and consistent choice.

**Approach B: More symbols (compile-time selection).**  Generate
separate per-ER functions: `asn1_der_decode_T()`,
`asn1_ber_decode_T()`, `asn1_jer_decode_T()`, etc.  Each function is
specialized for one ER with no branches.  This is what the codegen
backend would naturally do — it already generates straight-line code
with no ER dispatch.

**Tradeoffs:**

| | Flags (A) | More symbols (B) |
|---|---|---|
| Branches | Yes, at every ER-dependent point | None within each function |
| Code size | One function per type | N functions per type (N = ERs) |
| I-cache | Smaller (shared code) | Larger (duplicated per ER) |
| Template backend | Natural fit | Unnatural (defeats the purpose) |
| Codegen backend | Adds branches to straight-line code | Natural fit |
| Stubs / ABI surface | One entry point | N entry points per type |

**Recommendation:** Use flags for the template backend (it already
does this internally) and generate separate per-ER functions in the
codegen backend.  The `asn1_codec_ctx` struct would carry flags for the
template path; callers using the codegen path would call the
ER-specific function directly.  The exported type descriptor (section 5)
could hold function pointers for each supported ER, unifying the two
approaches at the generic API level.

### Note

This is a "nice to have" — DER covers nearly all Kerberos and PKIX needs.
BER support already exists in the decoder (controlled by
`support_ber`).  JER is handled separately via `print_T()` /
`asn1_parse_T()`.  OER/PER would be a major undertaking.

---

## 4. Arena-Based Allocation

### Problem

The current decoders allocate memory per-field using `malloc()`/`calloc()`.
A typical X.509 certificate decode does dozens of allocations.  Freeing
requires walking the entire structure.  There's no way to say "free
everything decoded from this buffer" in one shot.

### Proposal

Add optional arena support.  An arena is a bump allocator — allocations
are fast (pointer increment) and freeing is O(1) (free the whole arena).

```c
typedef struct asn1_arena {
    unsigned char *base;
    size_t         size;
    size_t         used;
    struct asn1_arena *next; /* overflow chain */
} asn1_arena;

/* Could be part of asn1_codec_ctx from section 3 */
typedef struct asn1_codec_ctx {
    unsigned              flags;
    const asn1_tag_override *implicit_tag;
    asn1_arena           *arena;        /* NULL = use malloc */
} asn1_codec_ctx;
```

### Current Allocation Patterns

The codegen backend (`gen_decode.c`) and template runtime (`template.c`)
both use the same allocation strategy:

- **Optional members:** `calloc(1, sizeof(*ptr))` — allocate, then
  decode into the buffer.  On `ASN1_MISSING_FIELD`, free and set NULL.
- **SEQUENCE OF / SET OF:** `realloc()` to grow the `val` array, then
  decode each element in place.
- **Open type members:** `calloc(1, sizeof(T))` per decoded open type
  value; `calloc(len, sizeof(val[0]))` for array-of-open-type.
- **`_save` fields:** `malloc(ret)` + `memcpy()` for `--preserve-binary`
  types.
- **Strings / OCTET STRING:** `malloc(len)` for the data buffer.

In `template.c`, the runtime interpreter (`_asn1_decode()`) controls all
allocation centrally — making it the ideal place to route through an
arena.  The codegen backend scatters `calloc()`/`malloc()` calls
throughout generated code, so arena support there would require an
`asn1_arena_alloc()` wrapper called from every generated allocation site.

### Design Considerations

- **Arena must be optional.** Application code often constructs ASN.1
  values directly (not via decode), so `malloc`-based allocation must
  remain the default.

- **Mixed mode.** If a decoded-with-arena structure gets fields modified
  by the application (which uses `malloc`), freeing becomes complicated.
  The simplest policy: arena-decoded structures are **read-only**.
  Callers who want to modify must `copy_T()` into a `malloc`-based
  struct first.

- **Generated code changes.** The decoder's `calloc()` calls become
  `asn1_arena_alloc(ctx->arena, size)` which falls back to `calloc()`
  when `arena` is NULL.  The `free_T()` function becomes a no-op when
  the value was arena-allocated (or we add a flag to the struct).

- **Existing infrastructure.** Heimdal's `lib/base/` has
  `heim_auto_release` pools but those are reference-counted, not
  arena-style.  `lib/roken/strpool.c` has a simple string pool
  (`rk_strpool`) but it's append-only for strings.  A new lightweight
  arena allocator would be needed — something like:

  ```c
  asn1_arena *asn1_arena_new(size_t initial_size);
  void       *asn1_arena_alloc(asn1_arena *a, size_t size);
  void        asn1_arena_free(asn1_arena *a); /* frees everything */
  ```

### Impact

Arena allocation would primarily benefit decode-heavy paths like X.509
certificate chain validation and KDC ticket processing.  The template
backend would benefit most since the runtime interpreter controls all
allocation centrally (in `_asn1_decode()` in `template.c`).

---

## 5. Exported Type Descriptors (DATA Symbols)

### Problem

Currently every type `T` gets N function symbols exported
(`decode_T`, `encode_T`, ...).  The template backend already generates
`asn1_T[]` data arrays but they're internal to the template stubs.
Applications can't do generic ASN.1 operations like "decode this
DER blob given a type descriptor at runtime."

### Proposal

Export a per-type descriptor that bundles the template (or function
pointers for codegen) with metadata:

```c
typedef struct asn1_type_info {
    const char                  *name;      /* "Extension", etc. */
    size_t                       size;      /* sizeof(T) */
    const struct asn1_template  *tpl;       /* Template array (NULL for codegen) */
    const struct asn1_type_func *funcs;     /* Function pointers */
    const heim_oid              *oid;       /* NULL unless type has a canonical OID */
} asn1_type_info;

/* Exported per type */
extern const asn1_type_info asn1_typeinfo_Extension;
```

This enables:
- Generic decode/encode by passing a type descriptor
- Runtime type introspection
- Plugin-based type registration
- Simpler FFI for other languages

### Relationship to Template Backend

The template backend already has `asn1_extern_T` (of type
`asn1_type_func`) internally.  Making this public and enriching it
with the template pointer and metadata is straightforward.  The codegen
backend would generate the same struct, filling in the function pointers
and leaving `tpl` NULL.

---

## 6. OpenSSL-Compatible Template Generation

### Problem

OpenSSL has its own ASN.1 template system (`ASN1_ITEM`, `ASN1_TEMPLATE`,
the `IMPLEMENT_ASN1_FUNCTIONS` macro family).  OpenSSL's ASN.1 types are
defined by hand using these macros.  If Heimdal's compiler could generate
OpenSSL-style templates, it could serve as an ASN.1 compiler for
OpenSSL, replacing OpenSSL's hand-written template definitions.

### OpenSSL's Template System (Summary)

OpenSSL uses:
- `ASN1_ITEM` — type descriptor (analogous to Heimdal's `asn1_template[]`)
- `ASN1_TEMPLATE` — field descriptor within a SEQUENCE/SET
- `ASN1_ADB` / `ASN1_ADB_TABLE` — "ANY DEFINED BY" (open type) support
- Tag info encoded via `ASN1_TFLG_*` flags
- Template types: `ASN1_ITYPE_PRIMITIVE`, `ASN1_ITYPE_SEQUENCE`,
  `ASN1_ITYPE_CHOICE`, `ASN1_ITYPE_EXTERN`, etc.

### Key Differences from Heimdal Templates

| Aspect | Heimdal | OpenSSL |
|--------|---------|---------|
| Template struct | 12 bytes: `{uint32_t tt, int32_t offset, void *ptr}` | 40-48 bytes: `{ulong flags, long tag, ulong offset, char *name, ASN1_ITEM *item}` |
| Type descriptor | Flat `asn1_template[]` array, bytecode-like | `ASN1_ITEM_st` with `itype`, `utype`, pointer to member array |
| Field iteration | Sequential walk of flat array | Array of `ASN1_TEMPLATE` structs |
| Open types | `A1_OP_OPENTYPE_OBJSET` + sorted object arrays | `ASN1_ADB` / `ASN1_ADB_TABLE` |
| Tag handling | `A1_TAG_T()` packing class+type+tag in 20 bits | Separate `tag` long + `ASN1_TFLG_*` flags |
| OPTIONAL | `A1_FLAG_OPTIONAL` (bit in `tt`) | `ASN1_TFLG_OPTIONAL` |
| IMPLICIT | `A1_FLAG_IMPLICIT` (bit in `tt`) | `ASN1_TFLG_IMPTAG` |
| CHOICE | `A1_OP_CHOICE` | `ASN1_ITYPE_CHOICE` |
| Field names | Separate `A1_OP_NAME` entries | Embedded `field_name` in each template |
| Primitives | `enum asn1_template_prim` (A1T_*) | `utype` field (V_ASN1_*) |
| C types | Native C types (`heim_oid`, `heim_octet_string`) | OpenSSL wrappers (`ASN1_OBJECT *`, `ASN1_OCTET_STRING *`) |

OpenSSL's `ASN1_ITEM_st`:
```c
struct ASN1_ITEM_st {
    char itype;             /* PRIMITIVE, SEQUENCE, CHOICE, EXTERN */
    long utype;             /* Underlying universal type */
    const ASN1_TEMPLATE *templates;  /* Member array */
    long tcount;            /* Number of members */
    const void *funcs;      /* ASN1_PRIMITIVE_FUNCS or ASN1_AUX */
    long size;              /* sizeof(T) */
    const char *sname;      /* Structure name */
};
```

### Approach

Add a new backend (`--openssl-template`) that generates:
1. `ASN1_ITEM_st` structures for each type
2. `ASN1_TEMPLATE` arrays for SEQUENCE/SET members
3. `ASN1_ADB` tables for open types
4. `IMPLEMENT_ASN1_FUNCTIONS()` macro invocations (or the raw structs)

This is a separate backend, not a modification to the existing template
backend.  The C type definitions (structs) would also need an
OpenSSL-compatible layout mode since OpenSSL's type layouts differ
from Heimdal's (e.g., OpenSSL uses `ASN1_OBJECT *` for OIDs vs.
Heimdal's `heim_oid`; OpenSSL uses reference-counted `ASN1_STRING *`
vs. Heimdal's inline `heim_utf8_string`).

### Feasibility

Medium-hard.  The template concepts map reasonably well (both systems
have type descriptors, member arrays, tagging flags, and open type
tables), but OpenSSL's C type layouts are quite different.  OpenSSL
types are typically pointer-based and reference-counted (`ASN1_STRING *`,
`ASN1_OBJECT *`), while Heimdal uses inline value types.

**Pragmatic first step:** Generate just the OpenSSL template tables
(`ASN1_ITEM` + `ASN1_TEMPLATE` arrays) pointing to OpenSSL's own
built-in type items (like `ASN1_OCTET_STRING_it`, `ASN1_OBJECT_it`),
and let OpenSSL's existing runtime interpret them.  This avoids the
struct layout problem entirely — OpenSSL's runtime would allocate and
manage the structs its own way.

**Bigger effort:** Generate both templates and struct definitions in
OpenSSL's style.  This would require mapping Heimdal's `heim_oid` to
`ASN1_OBJECT *`, `heim_octet_string` to `ASN1_OCTET_STRING *`, etc.
throughout the code generator.

---

## 7. Extended Type Controls

### Problem

Currently, C type mapping for `INTEGER` is determined entirely by the
ASN.1 `range` constraint:

| Constraint | C type |
|-----------|--------|
| No range | `heim_integer` (bignum) |
| min < 0, fits int | `int` |
| min < 0, needs 64-bit | `int64_t` |
| min >= 0, fits uint | `unsigned int` |
| min >= 0, needs 64-bit | `uint64_t` |
| Has named values (enum) | `enum { ... }` |

There's no way to say "this INTEGER should be `uint8_t`" or "this
INTEGER should be `krb5_kvno`" independent of its ASN.1 range.

### Current Option File Controls

The `.opt` files (e.g., `rfc2459.opt`, `krb5.opt`, `test.opt`) support:

```
--preserve-binary=TypeName          # Keep raw DER for re-encoding
--sequence=TypeName                 # Generate SEQUENCE OF accessor helpers
--decorate=TypeName:FType:fname[?]:[copy]:[free]:[header]  # Add fields
--encode-rfc1510-bit-string         # Use RFC1510 BIT STRING encoding
--support-ber                       # Allow BER on decode
--prefix-enum                       # Prefix enum labels with type name
```

Examples from `krb5.opt`:
```
--sequence=Principals
--sequence=AuthorizationData
--preserve-binary=KDC-REQ-BODY
--decorate=PrincipalNameAttrs:void *:pac
--decorate=Principal:PrincipalNameAttrs:nameattrs?
```

### Current INTEGER Mapping (gen.c:1222-1262)

The `define_type()` function uses a fixed decision tree based on range
constraints.  This same logic is replicated in `gen_template.c`
(`integer_symbol()`) for the template backend.  There's no way to
override it.

### Proposed New Controls

```
# Map INTEGER member to specific C type
--integer-type=TypeName.fieldName AS uint8_t
--integer-type=TypeName.fieldName AS krb5_kvno

# Map entire INTEGER type alias
--integer-type=KerberosVersion AS uint8_t

# Map OCTET STRING to specific type
--octet-string-type=TypeName.fieldName AS krb5_data

# Override the CHOICE enum prefix
--choice-prefix=TypeName PREFIX krb5_authdata

# Custom allocator for a type
--allocator=TypeName ALLOC my_alloc FREE my_free
```

### Implementation

The option file parser in `gen.c` / `main.c` already handles
`--preserve`, `--sequence`, and `--decorate` via `getarg()` processing
in `main.c` lines 267-307 and decoration parsing in `gen.c`.  Adding
new `--integer-type` etc. directives would follow the same pattern:

1. Add new `getarg` entries in `main.c`
2. Store overrides in a lookup table (type name + optional field name →
   C type string)
3. In `define_type()` (`gen.c`) and `integer_symbol()` (`gen_template.c`),
   check the override table before falling through to the default
   range-based logic
4. For encode/decode, generate appropriate conversion code (e.g., cast
   from `uint8_t` to `unsigned int` for the DER encoder)

---

## 8. Parser Revamp (Multi-Pass, Context Resolution)

### Problem

ASN.1 is not context-free.  The same syntax can denote a type, a value,
an object, or an object set depending on context.  For example:

```asn1
Foo ::= Bar { Baz }
```

Is `Baz` a type?  An object set?  A value?  It depends on the
declaration of `Bar` (is it a parameterized type? which parameter kind?).
And `Bar` might be defined later in the module (ASN.1 does not require
forward declarations).

The current parser (`asn1parse.y`, ~2037 lines) handles this via:
- Yacc/bison LALR grammar with documented conflicts
- Forward references via `addsym()` in `symbol.c` (symbols start as
  `SUndefined` and get resolved when defined)
- IOS (Information Object System) entities only partially supported
- Type-vs-value ambiguities handled by hardcoding known cases

### Known Grammar Conflicts

The parser explicitly declares **2 conflicts** (documented at lines
304-354 of `asn1parse.y`):

1. **Shift/reduce:** `ObjectClassAssignment` vs. `TypeAssignment` — both
   compete at the assignment level.  Workaround: CLASS names must start
   with underscore to disambiguate.

2. **Reduce/reduce:** `ObjectAssignment` vs. `ValueAssignment` — both
   reduce ambiguously when seeing an identifier followed by content.
   Same underscore workaround.

The parser comments note (line 352-354):
> "Sadly, the extended syntax for ASN.1 (x.680 + x.681/2/3) appears to
> have ambiguities that cannot be resolved with bison/yacc."

### Known Limitations

From searching `asn1parse.y` for TODO/FIXME/XXX:

**Unsupported constructs:**
- `AUTOMATIC TAGS` (line 384, hard error)
- `EXTENSIBILITY IMPLIED` (line 389, hard error)
- `WITH SYNTAX` in CLASS definitions
- Object set extensibility
- `CLASS` field chains (link fields)
- Value notation for structured types

**Partially supported / limited:**
- Only **one** formal type parameter per parameterized type (line 1214:
  "Should be ActualParameterList, but we'll do just one for now")
- `IMPORTS` cannot distinguish symbol kinds — the parser assumes all
  imported symbols are types (line 409-432 FIXME: "Our sin of allowing
  type names to start with lower-case and values with upper-case means
  we can't tell")
- Only 2 of 7 CLASS field types supported: `TypeFieldSpec` and
  `FixedTypeValueFieldSpec`.  Unsupported: `VariableTypeValueFieldSpec`,
  `VariableTypeValueSetFieldSpec`, `FixedTypeValueSetFieldSpec`,
  `ObjectFieldSpec`, `ObjectSetFieldSpec`.
- `INSTANCE OF` only partially supported
- NULL is both a type and a value, causing reduce/reduce in
  `FieldSetting` — workaround uses `ValueExNull` production

**Architectural issues:**
- Module state is in globals (noted in `gen_locl.h` lines 58-77:
  "XXX We need to move all module state out of globals and into a
  struct")
- IMPLICIT tag logic mixed into parser actions instead of semantic
  phase (line 1419: "FIXME We shouldn't do this...")
- Symbol resolution is single-pass with dynamic registration; no
  multi-module import resolution

### Proposed Architecture

**Phase 1: Two-pass resolution.** Keep yacc/bison for the grammar but
add a second pass after parsing that resolves ambiguities:

1. **Parse pass:** Parse the entire module, creating AST nodes with
   `kind = UNKNOWN` for ambiguous references.  Use combined productions
   like `TypeOrValue`, `TypeOrObjectSet`, etc.  Symbols start as
   `SUndefined` (already the case in `symbol.c`).

2. **Resolution pass:** Walk the AST, resolving kinds based on
   declarations.  Since all declarations are now visible, every
   reference can be resolved.  Error on truly ambiguous cases.
   This also enables multi-module resolution — imported symbols from
   other `.asn1` files could have their kinds resolved by parsing
   the imported module first.

This is a moderate refactor — the parser doesn't change much, but a new
resolution pass is added.

**Phase 2 (future): PEG or hand-written recursive descent.** For full
ASN.1 compliance, replace bison with a parser that can handle the
context-sensitivity natively.  A PEG (Parsing Expression Grammar) or
hand-written recursive-descent parser with backtracking would be more
natural for ASN.1's grammar.  This is a much larger undertaking, but
would eliminate the need for the underscore-prefix hack for CLASS names
and allow all 7 CLASS field types to be distinguished syntactically.

### Files Affected

- `asn1parse.y` — grammar productions for ambiguous cases
- `symbol.h` — AST node types (already has `SUndefined`, `SValue`,
  `Stype`, `Sparamtype`, `Sclass`, `Sobj`, `Sobjset`)
- `symbol.c` — `addsym()` / `checkundefined()` resolution
- New: `resolve.c` — second-pass resolution logic
- `gen.c`, `gen_template.c` — remove ad-hoc resolution during codegen
- `gen_locl.h` — move module state from globals to struct

---

## Priority and Dependencies

| Section | Priority | Depends On | Effort |
|---------|----------|------------|--------|
| 1. Implicit tag parameter | High | — | Large |
| 2. Function naming | Medium | 1 (do together) | Small |
| 3. Multi-ER flags | Low | 1 | Medium |
| 4. Arena allocation | Medium | 1 (use ctx struct) | Large |
| 5. Type descriptors | Medium | — | Medium |
| 6. OpenSSL templates | Medium | — | Large |
| 7. Type controls | Medium | — | Small |
| 8. Parser revamp | Low | — | Very Large |

Recommended ordering:
1. **Sections 1+2** together (new signatures with new names)
2. **Section 7** (easy win, no ABI implications)
3. **Section 5** (enables generic APIs)
4. **Section 4** (arena, using ctx struct from 1)
5. **Section 6** (OpenSSL backend, standalone)
6. **Section 8** (parser, standalone, long-term)
7. **Section 3** (multi-ER, only when needed)
