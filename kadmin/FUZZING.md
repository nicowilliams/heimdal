# Fuzzing kadmin

Kadmind includes built-in fuzzing support via the `--fuzz-stdin` flag, which
processes a single RPC message from stdin without requiring network setup or
authentication.

## Running

### Standalone mode

```bash
# Process a single corpus file
./kadmind --fuzz-stdin < fuzz/get_existing_test.bin

# With a specific realm
./kadmind -r TEST.H5L.SE --fuzz-stdin < fuzz/create_new.bin
```

### With AFL++

```bash
# Build with AFL instrumentation
CC=afl-clang-fast CXX=afl-clang-fast++ \
  ../configure --enable-maintainer-mode --enable-developer
make

# Run fuzzer
afl-fuzz -i kadmin/fuzz -o findings -- ./kadmind --fuzz-stdin
```

### With libFuzzer

To use libFuzzer, create a harness that calls the internal fuzzing entry point:

```c
#include <stdint.h>
extern int kadmind_fuzz_input(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    kadmind_fuzz_input(data, size);
    return 0;
}
```

## Seed Corpus

The `fuzz/` directory contains seed inputs covering:

- All kadm_ops commands (GET, DELETE, CREATE, RENAME, CHPASS, MODIFY, RANDKEY, etc.)
- Edge cases (invalid commands, truncated data, malformed principals)
- Overflow tests (large/negative array counts)

See `fuzz/README` for detailed corpus file descriptions.

## Regenerating Corpus

```bash
cd fuzz
python3 gen_corpus.py
```

## Message Format

Each corpus file contains a length-prefixed message:

```
[4-byte big-endian length][message payload]
```

The payload starts with a 4-byte command number (see `kadm_ops` enum in
`lib/kadm5/kadm5-private.h`).
