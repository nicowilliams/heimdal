# Fuzzing lib/hx509

This directory contains a fuzzer for JWS/JWT parsing (`jose.c`).

## fuzz_jose

Fuzzes `hx509_jws_verify()` and `hx509_jwt_verify()` with various key types.

Note: This fuzzer primarily exercises the parsing paths (base64url decoding,
JSON header/payload parsing, signature format handling). Signature verification
itself will reject most mutations early, so this is less effective than fuzzing
pure codecs like the JSON parser.

### Building

#### Standalone (for testing)

```bash
cd build
make -C lib/hx509 fuzz_jose
```

#### With libFuzzer + AddressSanitizer (recommended)

```bash
cd build
CC=clang CXX=clang++ \
  CFLAGS="-fsanitize=fuzzer-no-link,address -g -O1" \
  LDFLAGS="-fsanitize=fuzzer,address" \
  ../configure --enable-maintainer-mode --enable-developer

make -C lib/hx509 fuzz_jose
```

#### With AFL++

```bash
cd build
CC=afl-clang-fast CXX=afl-clang-fast++ \
  ../configure --enable-maintainer-mode --enable-developer

make -C lib/hx509 fuzz_jose
```

### Running

#### Standalone mode (reads from files or stdin)

```bash
# Test with corpus files
./lib/hx509/fuzz_jose ../lib/hx509/fuzz_jose_corpus/*.txt

# Test single input
echo 'eyJhbGciOiJSUzI1NiJ9.e30.AA' | ./lib/hx509/fuzz_jose
```

#### libFuzzer mode

```bash
# Basic fuzzing
./lib/hx509/fuzz_jose ../lib/hx509/fuzz_jose_corpus/

# With options
./lib/hx509/fuzz_jose ../lib/hx509/fuzz_jose_corpus/ \
  -max_len=65536 \
  -timeout=10 \
  -jobs=4 \
  -workers=4
```

#### AFL++ mode

```bash
afl-fuzz -i ../lib/hx509/fuzz_jose_corpus -o findings -- ./lib/hx509/fuzz_jose @@
```

### Seed Corpus

The `fuzz_jose_corpus/` directory contains seed inputs covering:

- Valid RFC test vectors (RS256, ES256, EdDSA from RFC 7515/8037)
- Various algorithms (RS384, RS512, ES384, ES512, HS256, unknown)
- Edge cases (empty parts, minimal tokens, algorithm "none")
- Malformed inputs (bad base64, wrong signature lengths)
- Long headers, nested JSON, Unicode payloads

### What it tests

1. **JWS verification** with RSA, EC, and Ed25519 public keys
2. **JWT verification** including claims parsing
3. **Base64URL decoding** of header, payload, and signature
4. **JSON parsing** of header and claims
5. **ECDSA signature format** conversion (JWS r||s to DER)
6. **Key type matching** against declared algorithm
