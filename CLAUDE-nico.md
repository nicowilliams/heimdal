# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Heimdal is a comprehensive implementation of:
- ASN.1/DER encoding/decoding
- PKIX (X.509 certificates)
- Kerberos 5 authentication protocol

## Build Commands

Always do out-of-tree buils.  I use a directory called `build` at the top of
this codebase.

If the build/ directory has a build configured already, then just make in
there and `make` will re-run autoconf and `../configure` as needeed:

```bash
cd build && make -j8
```

(Add `V=1` to `make` commands to make the build verbose so you can build
commands executed by `make`.)

Otherwise you need to start from scratch like this:
Generate configure script (first time or after modifying .m4/.ac files)

```bash
./autogen.sh

# Configure and build (out-of-tree build recommended)
mkdir -p build && cd build
../configure --enable-maintainer-mode --enable-developer
make -j8
```

To run all tests:

```bash
make check
```

To run a specific test suite (from build directory)

```bash
cd tests/kdc && make check TESTS=check-kdc
```

To run a single test script directly without autoconf's harness:

```bash
cd tests/kdc && make ./tests/kdc/check-kdc && ./tests/kdc/check-kdc
```

Because we're working with OpenSSL 3.x, and this Ubuntu host is too old, make
sure to add `--with-openssl=/opt/ossl36` to the `./configure` command.  When
doing a MinGW build you should use `--with-openssl=/opt/openssl-mingw64/`.

## Use `make clean` over `rm` for removing build artifacts

Use `make clean` over `rm` for removing build artifacts

## Examining and debugging built executables

Because Heimdal uses `libtool` you can't just `gdb` the Heimdal executables
built with `make`.  Instead you should use `./libtool --mode=execute ...`.  For
example, `build/libtool --mode=execute gdb --args build/kuser/kinit ...`.

The same is true for `ldd`, `strace` and others.  You must run
`./libtool --mode=execute ldd ...` and so on.

## Standards

You can find copies of relevant RFCs in `doc/standardization/`.

## Architecture

### Core Libraries (lib/)

- **lib/krb5/**: Core Kerberos 5 library - ticket handling, encryption, credential caches
- **lib/gssapi/**: GSS-API implementation with multiple mechanisms:
  - `krb5/`: Kerberos 5 mechanism
  - `spnego/`: SPNEGO negotiation mechanism
  - `sanon/`: Simple Anonymous mechanism (X25519-based)
  - `mech/`: Mechanism dispatch layer
- **lib/hx509/**: X.509 certificate handling and PKI operations
- **lib/asn1/**: ASN.1 compiler and DER codec library. Generates C code from .asn1 files. Uses a template-based backend for encoding/decoding.
- **lib/hdb/**: Heimdal Database - KDC principal database abstraction
- **lib/kadm5/**: Kerberos administration library (client and server)
- **lib/base/**: Foundation library with JSON, arrays, dictionaries, error handling
- **lib/roken/**: Portability library for cross-platform compatibility
- **lib/wind/**: Unicode/IDN handling for internationalized names

### Daemons

- **kdc/**: Key Distribution Center daemon and related tools (kstash, string2key)
- **kadmin/**: Administration daemon and CLI tools
- **kcm/**: Kerberos Credential Manager daemon
- **kpasswd/**: Password change daemon

### User Tools (kuser/)

- **kinit**: Obtain Kerberos tickets
- **klist**: List cached tickets
- **kdestroy**: Destroy ticket cache
- **kgetcred**: Obtain service tickets

## Key Patterns

Whenever possible functionality that exists in this code base rather than
duplicate it.  For example: don't write code to read a private key from a PEM
file and use, instead use `lib/hx509` APIs to load a private key and use it, if
need be adding new primitives to `lib/hx509` -- this is important because
`lib/hx509`'s private key functionality includes support for password-protected
keys via PKCS#12 and for keys in hardware tokens via PKCS#11, not just PEM
files, and we want such functionality to always be available when using Heimdal
tools and libraries that deal with private keys.

### ASN.1 Compilation
ASN.1 modules in `*.asn1` files are compiled by `lib/asn1/asn1_compile` to generate C types and codec functions. The `--template` backend is preferred for new code.

### Test Infrastructure
Tests are shell scripts in `tests/*/check-*.in` that get processed by sed to substitute paths. They use a common setup from `tests/bin/setup-env`.

### Configuration
Runtime configuration via `krb5.conf`. KDC configuration in the `[kdc]` section, library options in `[libdefaults]`.

### Error Handling
Uses `com_err` library for error codes. Error tables defined in `*.et` files.

## Windows Build

Use `NTMakefile` files with `nmake`. See `windows/README.md` for details.
