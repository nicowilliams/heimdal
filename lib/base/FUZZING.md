# Fuzzing lib/base

This directory contains a fuzzer for the JSON parser (`json.c`).

## fuzz_json

Fuzzes `heim_json_create_with_bytes()` and `heim_json_copy_serialize()` with
various parsing flags and depth limits.

### Building

#### Standalone (for testing)

```bash
cd build
make -C lib/base fuzz_json
```

#### With libFuzzer + AddressSanitizer (recommended)

```bash
cd build
CC=clang CXX=clang++ \
  CFLAGS="-fsanitize=fuzzer-no-link,address -g -O1" \
  LDFLAGS="-fsanitize=fuzzer,address" \
  ../configure --enable-maintainer-mode --enable-developer

make -C lib/base fuzz_json
```

#### With AFL++

```bash
cd build
CC=afl-clang-fast CXX=afl-clang-fast++ \
  ../configure --enable-maintainer-mode --enable-developer

make -C lib/base fuzz_json
```

### Running

#### Standalone mode (reads from files or stdin)

```bash
# Test with corpus files
./lib/base/fuzz_json ../lib/base/fuzz_json_corpus/*.json

# Test single input
echo '{"test": [1,2,3]}' | ./lib/base/fuzz_json
```

#### libFuzzer mode

```bash
# Basic fuzzing
./lib/base/fuzz_json ../lib/base/fuzz_json_corpus/

# With options
./lib/base/fuzz_json ../lib/base/fuzz_json_corpus/ \
  -max_len=262144 \
  -timeout=10 \
  -jobs=4 \
  -workers=4
```

#### AFL++ mode

```bash
afl-fuzz -i ../lib/base/fuzz_json_corpus -o findings -- ./lib/base/fuzz_json @@
```

### Seed Corpus

The `fuzz_json_corpus/` directory contains seed inputs covering:

- Basic JSON types (null, true, false, numbers, strings)
- Unicode literals and escape sequences (`\uXXXX`)
- Arrays and objects (empty, nested, deep)
- Edge cases (empty keys, whitespace variations, huge integers)
- Malformed inputs (unclosed brackets, missing values, trailing commas)
- JWT-like payloads (common real-world use case)

### What it tests

1. **Default parsing** - `heim_json_create_with_bytes()` with depth limit 10
2. **Strict mode** - `HEIM_JSON_F_STRICT` flag (rejects some permissive inputs)
3. **Shallow depth** - Depth limit 2 (rejects deep nesting)
4. **Null handling** - `HEIM_JSON_F_NO_C_NULL` flag
5. **Round-trip** - Parse, serialize, re-parse to verify consistency
