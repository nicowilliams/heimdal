/*
 * Copyright (c) 2025 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * libFuzzer harness for JWS/JWT parsing in jose.c
 *
 * Build with:
 *   clang -g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer,address \
 *         -I... fuzz_jose.c -o fuzz_jose -lhx509 -lroken ...
 *
 * Run with:
 *   ./fuzz_jose corpus_dir/
 */

#include <config.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <hx509.h>

/* libFuzzer entry points */
int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* Test keys for signature verification fuzzing */

/* RSA-2048 public key */
static const char *rsa_pubkey_pem =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAofgWCuLjybRlzo0tZWJj\n"
    "NiuSfb4p4fAkd/wWJcyQoTbji9k0l8W26mPddxHmfHQp+Vaw+4qPCJrcS2mJPMEz\n"
    "P1Pt0Bm4d4QlL+yRT+SFd2lZS+pCgNMsD1W/YpRPEwOWvG6b32690r2jZ47soMZo\n"
    "9wGzjb/7OMg0LOL+bSf63kpaSHSXndS5z5rexMdbBYUsLA9e+KXBdQOS+UTo7WTB\n"
    "EMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6/I5IhlJH7aGhyxX\n"
    "FvUK+DWNmoudF8NAco9/h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXp\n"
    "oQIDAQAB\n"
    "-----END PUBLIC KEY-----\n";

/* EC P-256 public key */
static const char *ec_pubkey_pem =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEf83OJ3D2xF1Bg8vub9tLe1gHMzV7\n"
    "6e8Tus9uPHvRVEXH8UTNG72bfocs3+257rn0s2ldbqkLJK2KRiMohYjlrQ==\n"
    "-----END PUBLIC KEY-----\n";

/* Ed25519 public key */
static const char *ed25519_pubkey_pem =
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n"
    "-----END PUBLIC KEY-----\n";

static hx509_context ctx = NULL;

/*
 * Initialize hx509 context once.
 * Called by libFuzzer before fuzzing starts.
 */
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;

    if (hx509_context_init(&ctx) != 0) {
        ctx = NULL;
    }
    return 0;
}

/*
 * Main fuzzing entry point.
 * Input is treated as a potential JWS/JWT token.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *token = NULL;
    void *payload = NULL;
    size_t payload_len = 0;
    heim_dict_t claims = NULL;
    const char *keys[3];
    int ret;

    if (ctx == NULL)
        return 0;

    /* Need at least "a.b.c" for a valid JWS structure */
    if (size < 5)
        return 0;

    /* Limit input size to avoid OOM */
    if (size > 1024 * 1024)
        return 0;

    /* Make null-terminated copy */
    token = malloc(size + 1);
    if (token == NULL)
        return 0;
    memcpy(token, data, size);
    token[size] = '\0';

    /* Set up key array for verification attempts */
    keys[0] = rsa_pubkey_pem;
    keys[1] = ec_pubkey_pem;
    keys[2] = ed25519_pubkey_pem;

    /*
     * Test 1: JWS verification with multiple key types.
     * This exercises:
     *   - Base64URL decoding of header, payload, signature
     *   - JSON parsing of header
     *   - Algorithm detection and validation
     *   - Key type matching
     *   - Signature format handling (ECDSA JWS->DER conversion)
     */
    ret = hx509_jws_verify(ctx, token, keys, 3, &payload, &payload_len);
    if (ret == 0) {
        free(payload);
        payload = NULL;
    }

    /*
     * Test 2: JWT verification (includes claims parsing).
     * This exercises:
     *   - Everything from JWS verification
     *   - JSON parsing of claims payload
     *   - Claims validation (exp, nbf, aud)
     */
    ret = hx509_jwt_verify(ctx, token, keys, 3, NULL, 0, &claims);
    if (ret == 0 && claims) {
        heim_release(claims);
        claims = NULL;
    }

    /*
     * Test 3: Try with just one key at a time.
     * This ensures we hit different code paths for key type mismatches.
     */
    keys[0] = rsa_pubkey_pem;
    ret = hx509_jws_verify(ctx, token, keys, 1, &payload, &payload_len);
    if (ret == 0) {
        free(payload);
        payload = NULL;
    }

    keys[0] = ec_pubkey_pem;
    ret = hx509_jws_verify(ctx, token, keys, 1, &payload, &payload_len);
    if (ret == 0) {
        free(payload);
        payload = NULL;
    }

    keys[0] = ed25519_pubkey_pem;
    ret = hx509_jws_verify(ctx, token, keys, 1, &payload, &payload_len);
    if (ret == 0) {
        free(payload);
        payload = NULL;
    }

    /* Clear any error state */
    hx509_clear_error_string(ctx);

    free(token);
    return 0;
}

#ifndef HAS_LIBFUZZER_MAIN
/*
 * Standalone mode for testing without libFuzzer.
 * Reads input from stdin or file arguments.
 */
int main(int argc, char **argv)
{
    uint8_t buf[1024 * 1024];
    size_t len;
    FILE *fp;
    int i;

    LLVMFuzzerInitialize(&argc, &argv);

    if (argc < 2) {
        /* Read from stdin */
        len = fread(buf, 1, sizeof(buf), stdin);
        if (len > 0)
            LLVMFuzzerTestOneInput(buf, len);
    } else {
        /* Read from each file argument */
        for (i = 1; i < argc; i++) {
            fp = fopen(argv[i], "rb");
            if (fp == NULL)
                continue;
            len = fread(buf, 1, sizeof(buf), fp);
            fclose(fp);
            if (len > 0)
                LLVMFuzzerTestOneInput(buf, len);
        }
    }

    if (ctx)
        hx509_context_free(&ctx);

    return 0;
}
#endif
