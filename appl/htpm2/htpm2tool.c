/*
 * Copyright (c) 2026 Kungliga Tekniska Högskolan
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
 * htpm2tool -- command-line utility for TPM 2.0 operations.
 *
 * Sub-commands:
 *   timestamp     Generate a signed timestamp for use as a quote nonce
 *   encrypt-to    Encrypt a file to a target TPM (EncryptTo)
 *   envelope-open  Decrypt an EncryptTo ciphertext using the local TPM
 *   quote-verify  Validate a TPM quote (stub -- needs eventlog work)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "htpm2.h"
#include "htpm2_locl.h"
#include "marshal.h"
#include "crypto.h"
#include "pcrdb.h"
#include "policy_p.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

static void
die_result(htpm2_result r, const char *context)
{
    fprintf(stderr, "htpm2tool: %s: %s\n", context,
            r.message ? r.message : "(unknown error)");
    if (r.flags & HTPM2_F_TPM_RC)
        fprintf(stderr, "  TPM RC: 0x%08x\n", r.tpm_rc);
    if (r.flags & HTPM2_F_LOCAL)
        fprintf(stderr, "  local error: %d\n", r.local_err);
    htpm2_result_free(&r);
    exit(1);
}

static void *
read_file(const char *path, size_t *len)
{
    FILE *f;
    struct stat st;
    void *buf;

    if (stat(path, &st) < 0) {
        perror(path);
        return NULL;
    }

    buf = malloc(st.st_size > 0 ? st.st_size : 1);
    if (buf == NULL) {
        perror("malloc");
        return NULL;
    }

    f = fopen(path, "rb");
    if (f == NULL) {
        perror(path);
        free(buf);
        return NULL;
    }

    *len = fread(buf, 1, st.st_size, f);
    fclose(f);
    return buf;
}

static int
write_file(const char *path, const void *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        perror(path);
        return -1;
    }
    if (fwrite(data, 1, len, f) != len) {
        perror(path);
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

/*
 * Sub-command: timestamp
 *
 * Generate a signed timestamp for use as qualifying data (nonce) in a
 * TPM quote.  The timestamp prevents replay of old quotes.
 *
 * Output format: timestamp(8 bytes, big-endian Unix time) || HMAC-SHA-256
 *
 * The HMAC key is derived from a secret or read from a file.  For
 * simplicity, this initial implementation uses a random key written
 * to a file, and the verifier reads the same file to verify.
 *
 * Usage: htpm2tool timestamp --key <keyfile> --out <outfile>
 *        htpm2tool timestamp --key <keyfile> --verify <infile>
 *
 * Timestamp format (44 bytes):
 *   key_version (4 bytes, big-endian uint32)
 *   unix_time   (8 bytes, big-endian uint64)
 *   HMAC-SHA-256(key, key_version || unix_time) (32 bytes)
 */
#define TIMESTAMP_SIZE 44  /* 4 + 8 + 32 */
#define TIMESTAMP_HEADER_SIZE 12  /* 4 + 8 */

static int
cmd_timestamp(int argc, char **argv)
{
    const char *key_file = NULL;
    const char *out_file = NULL;
    const char *verify_file = NULL;
    uint32_t key_version = 1;
    htpm2_context ctx = NULL;
    htpm2_result r;
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)
            key_file = argv[++i];
        else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc)
            out_file = argv[++i];
        else if (strcmp(argv[i], "--verify") == 0 && i + 1 < argc)
            verify_file = argv[++i];
        else if (strcmp(argv[i], "--key-version") == 0 && i + 1 < argc)
            key_version = (uint32_t)atoi(argv[++i]);
    }

    if (key_file == NULL) {
        fprintf(stderr, "Usage: htpm2tool timestamp --key <keyfile> "
                "[--key-version <n>] "
                "[--out <outfile> | --verify <infile>]\n");
        return 1;
    }

    r = htpm2_context_init(&ctx);
    if (htpm2_is_err(r))
        die_result(r, "context_init");

    if (verify_file) {
        /* Verify a timestamp */
        void *key_data, *ts_data;
        size_t key_len, ts_len;
        uint8_t expected_hmac[32];
        size_t hmac_len = 32;
        time_t ts_time;

        ts_data = read_file(verify_file, &ts_len);
        if (!ts_data || ts_len != TIMESTAMP_SIZE) {
            fprintf(stderr, "htpm2tool: invalid timestamp file "
                    "(expected %d bytes, got %zu)\n",
                    TIMESTAMP_SIZE, ts_len);
            free(ts_data);
            htpm2_context_free(&ctx);
            return 1;
        }

        /*
         * Extract key version from the timestamp, then load the
         * corresponding key.  If --key is a directory, look for
         * <dir>/v<version>.  If it's a file, use it directly
         * (single-key mode).
         */
        {
            const uint8_t *p = ts_data;
            uint32_t ver = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                           ((uint32_t)p[2] << 8) | p[3];
            struct stat st;
            char versioned_path[1024];

            if (stat(key_file, &st) == 0 && S_ISDIR(st.st_mode)) {
                snprintf(versioned_path, sizeof(versioned_path),
                         "%s/v%u", key_file, ver);
                key_data = read_file(versioned_path, &key_len);
                if (!key_data) {
                    fprintf(stderr, "htpm2tool: no key for version %u "
                            "(tried %s)\n", ver, versioned_path);
                    free(ts_data);
                    htpm2_context_free(&ctx);
                    return 1;
                }
            } else {
                key_data = read_file(key_file, &key_len);
            }
        }

        if (!key_data) {
            free(ts_data);
            htpm2_context_free(&ctx);
            return 1;
        }

        r = htpm2_hmac_sha256(ctx, key_data, key_len,
                              ts_data, TIMESTAMP_HEADER_SIZE,
                              expected_hmac, &hmac_len);
        free(key_data);
        if (htpm2_is_err(r))
            die_result(r, "HMAC verify");

        if (memcmp(expected_hmac,
                   (uint8_t *)ts_data + TIMESTAMP_HEADER_SIZE, 32) != 0) {
            fprintf(stderr, "htpm2tool: timestamp HMAC verification FAILED\n");
            free(ts_data);
            htpm2_context_free(&ctx);
            return 1;
        }

        /* Decode key version and timestamp */
        {
            const uint8_t *p = ts_data;
            uint32_t ver = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                           ((uint32_t)p[2] << 8) | p[3];
            p += 4;
            ts_time = ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
                      ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
                      ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
                      ((uint64_t)p[6] << 8) | (uint64_t)p[7];
            printf("Timestamp valid (key version %u): %s",
                   ver, ctime(&ts_time));
        }

        free(ts_data);
    } else {
        /* Generate a timestamp */
        uint8_t ts_buf[TIMESTAMP_SIZE];
        void *key_data;
        size_t key_len;
        size_t hmac_len = 32;
        time_t now = time(NULL);

        /* Check if key file exists; if not, generate one */
        if (access(key_file, R_OK) != 0) {
            uint8_t new_key[32];
            r = htpm2_random_bytes(ctx, new_key, 32);
            if (htpm2_is_err(r))
                die_result(r, "generate key");
            if (write_file(key_file, new_key, 32) < 0) {
                htpm2_context_free(&ctx);
                return 1;
            }
            fprintf(stderr, "Generated new HMAC key: %s\n", key_file);
        }

        key_data = read_file(key_file, &key_len);
        if (!key_data) {
            htpm2_context_free(&ctx);
            return 1;
        }

        /* Encode key_version (4 bytes) + timestamp (8 bytes) */
        ts_buf[0] = (key_version >> 24) & 0xff;
        ts_buf[1] = (key_version >> 16) & 0xff;
        ts_buf[2] = (key_version >> 8) & 0xff;
        ts_buf[3] = key_version & 0xff;
        ts_buf[4] = (now >> 56) & 0xff;
        ts_buf[5] = (now >> 48) & 0xff;
        ts_buf[6] = (now >> 40) & 0xff;
        ts_buf[7] = (now >> 32) & 0xff;
        ts_buf[8] = (now >> 24) & 0xff;
        ts_buf[9] = (now >> 16) & 0xff;
        ts_buf[10] = (now >> 8) & 0xff;
        ts_buf[11] = now & 0xff;

        r = htpm2_hmac_sha256(ctx, key_data, key_len,
                              ts_buf, TIMESTAMP_HEADER_SIZE,
                              ts_buf + TIMESTAMP_HEADER_SIZE, &hmac_len);
        free(key_data);
        if (htpm2_is_err(r))
            die_result(r, "HMAC");

        if (out_file) {
            if (write_file(out_file, ts_buf, TIMESTAMP_SIZE) < 0) {
                htpm2_context_free(&ctx);
                return 1;
            }
        } else {
            /* Write to stdout */
            fwrite(ts_buf, 1, TIMESTAMP_SIZE, stdout);
        }
    }

    htpm2_context_free(&ctx);
    return 0;
}

/*
 * Sub-command: encrypt-to
 *
 * Encrypt a file to a target TPM.
 *
 * Usage: htpm2tool encrypt-to --ek-pub <file> --policy <file>
 *        [--iak-name <file>] [--owner-name <file>]
 *        --in <plaintext> --out <ciphertext>
 *        --cred-out <prefix>
 *
 * Outputs:
 *   <ciphertext>          -- encrypted data
 *   <prefix>.wk.blob      -- well-known credential blob
 *   <prefix>.wk.secret    -- well-known encrypted secret
 *   <prefix>.iak.blob     -- IAK credential blob (if --iak-name)
 *   <prefix>.iak.secret   -- IAK encrypted secret (if --iak-name)
 *   <prefix>.owner.blob   -- owner credential blob (if --owner-name)
 *   <prefix>.owner.secret -- owner encrypted secret (if --owner-name)
 */
static int
cmd_encrypt_to(int argc, char **argv)
{
    const char *ek_pub_file = NULL;
    const char *policy_file = NULL;
    const char *iak_name_file = NULL;
    const char *owner_name_file = NULL;
    const char *in_file = NULL;
    const char *out_file = NULL;
    const char *cred_prefix = NULL;
    void *ek_pub = NULL, *policy = NULL;
    void *iak_name = NULL, *owner_name = NULL;
    void *plaintext = NULL;
    size_t ek_pub_len, policy_len;
    size_t iak_name_len = 0, owner_name_len = 0;
    size_t plaintext_len;
    htpm2_encrypt_to_result result;
    htpm2_context ctx = NULL;
    htpm2_result r;
    char path[1024];
    int i, rc = 1;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--ek-pub") == 0 && i + 1 < argc)
            ek_pub_file = argv[++i];
        else if (strcmp(argv[i], "--policy") == 0 && i + 1 < argc)
            policy_file = argv[++i];
        else if (strcmp(argv[i], "--iak-name") == 0 && i + 1 < argc)
            iak_name_file = argv[++i];
        else if (strcmp(argv[i], "--owner-name") == 0 && i + 1 < argc)
            owner_name_file = argv[++i];
        else if (strcmp(argv[i], "--in") == 0 && i + 1 < argc)
            in_file = argv[++i];
        else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc)
            out_file = argv[++i];
        else if (strcmp(argv[i], "--cred-out") == 0 && i + 1 < argc)
            cred_prefix = argv[++i];
    }

    if (!ek_pub_file || !policy_file || !in_file || !out_file || !cred_prefix) {
        fprintf(stderr, "Usage: htpm2tool encrypt-to --ek-pub <file> "
                "--policy <file> --in <file> --out <file> "
                "--cred-out <prefix>\n"
                "  [--iak-name <file>] [--owner-name <file>]\n");
        return 1;
    }

    ek_pub = read_file(ek_pub_file, &ek_pub_len);
    policy = read_file(policy_file, &policy_len);
    plaintext = read_file(in_file, &plaintext_len);
    if (!ek_pub || !policy || !plaintext)
        goto out;

    if (iak_name_file) {
        iak_name = read_file(iak_name_file, &iak_name_len);
        if (!iak_name) goto out;
    }
    if (owner_name_file) {
        owner_name = read_file(owner_name_file, &owner_name_len);
        if (!owner_name) goto out;
    }

    r = htpm2_context_init(&ctx);
    if (htpm2_is_err(r))
        die_result(r, "context_init");

    memset(&result, 0, sizeof(result));
    r = htpm2_encrypt_to(ctx, plaintext, plaintext_len,
                         ek_pub, ek_pub_len,
                         policy, policy_len,
                         iak_name, iak_name_len,
                         owner_name, owner_name_len,
                         &result);
    if (htpm2_is_err(r))
        die_result(r, "encrypt_to");

    /* Write outputs */
    if (write_file(out_file, result.ciphertext, result.ciphertext_len) < 0)
        goto out;

    snprintf(path, sizeof(path), "%s.wk.blob", cred_prefix);
    if (write_file(path, result.wk_credential_blob,
                   result.wk_credential_blob_len) < 0)
        goto out;
    snprintf(path, sizeof(path), "%s.wk.secret", cred_prefix);
    if (write_file(path, result.wk_encrypted_secret,
                   result.wk_encrypted_secret_len) < 0)
        goto out;

    if (result.iak_credential_blob) {
        snprintf(path, sizeof(path), "%s.iak.blob", cred_prefix);
        if (write_file(path, result.iak_credential_blob,
                       result.iak_credential_blob_len) < 0)
            goto out;
        snprintf(path, sizeof(path), "%s.iak.secret", cred_prefix);
        if (write_file(path, result.iak_encrypted_secret,
                       result.iak_encrypted_secret_len) < 0)
            goto out;
    }

    if (result.owner_credential_blob) {
        snprintf(path, sizeof(path), "%s.owner.blob", cred_prefix);
        if (write_file(path, result.owner_credential_blob,
                       result.owner_credential_blob_len) < 0)
            goto out;
        snprintf(path, sizeof(path), "%s.owner.secret", cred_prefix);
        if (write_file(path, result.owner_encrypted_secret,
                       result.owner_encrypted_secret_len) < 0)
            goto out;
    }

    printf("Encrypted %zu bytes -> %zu bytes, %zu share(s)\n",
           plaintext_len, result.ciphertext_len, result.num_shares);
    rc = 0;

out:
    htpm2_encrypt_to_result_free(&result);
    free(ek_pub);
    free(policy);
    free(iak_name);
    free(owner_name);
    free(plaintext);
    htpm2_context_free(&ctx);
    return rc;
}

/*
 * Sub-command: envelope-open
 *
 * Decrypt an EncryptTo ciphertext using the local TPM.
 *
 * Usage: htpm2tool envelope-open --transport <uri>
 *        --cred-in <prefix> --in <ciphertext> --out <plaintext>
 *
 * The tool reads the credential blobs and secrets from files
 * produced by encrypt-to.  It connects to the TPM, creates the
 * necessary keys, runs ActivateCredential for each share, and
 * decrypts the ciphertext.
 *
 * This is currently a stub -- the full implementation requires
 * creating/loading the well-known key, EK, etc., which depends
 * on the enrollment flow.
 */
/*
 * Sub-command: envelope-open
 *
 * Decrypt an EncryptTo ciphertext using the local TPM.
 *
 * Usage: htpm2tool envelope-open --transport <uri> --policy <file>
 *        --cred-in <prefix> --in <ciphertext> --out <plaintext>
 *        [--with-iak] [--with-owner]
 *
 * The tool:
 *   1. Connects to the TPM
 *   2. Creates the EK (endorsement hierarchy, RSA-2048 decrypt)
 *   3. Creates the well-known key (NULL hierarchy, with policy)
 *   4. If --with-iak: reads IAK credential blobs
 *   5. If --with-owner: creates owner key and reads owner credential blobs
 *   6. ActivateCredential for each share (using password auth)
 *   7. XORs shares to recover AES-256 key
 *   8. Decrypts ciphertext
 *
 * Note: ActivateCredential on a real EK requires PolicySecret(ENDORSEMENT).
 * For now we use password auth which works when the endorsement hierarchy
 * has an empty password (typical for swtpm and many default configurations).
 */
static int
cmd_envelope_open(int argc, char **argv)
{
    const char *transport_uri = NULL;
    const char *policy_file = NULL;
    const char *cred_prefix = NULL;
    const char *in_file = NULL;
    const char *out_file = NULL;
    const char *iak_pub_file = NULL;
    const char *iak_priv_file = NULL;
    int with_owner = 0;
    htpm2_context ctx = NULL;
    htpm2_transport tp = NULL;
    htpm2_object ek = NULL, wk = NULL, owner = NULL, srk = NULL, iak = NULL;
    htpm2_result r;
    void *policy = NULL, *ciphertext = NULL;
    void *wk_blob = NULL, *wk_secret = NULL;
    void *iak_blob = NULL, *iak_secret = NULL;
    void *owner_blob = NULL, *owner_secret = NULL;
    void *plaintext = NULL;
    size_t policy_len, ciphertext_len;
    size_t wk_blob_len, wk_secret_len;
    size_t iak_blob_len = 0, iak_secret_len = 0;
    size_t owner_blob_len = 0, owner_secret_len = 0;
    size_t plaintext_len = 0;
    char path[1024];
    int i, rc = 1;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--transport") == 0 && i + 1 < argc)
            transport_uri = argv[++i];
        else if (strcmp(argv[i], "--policy") == 0 && i + 1 < argc)
            policy_file = argv[++i];
        else if (strcmp(argv[i], "--cred-in") == 0 && i + 1 < argc)
            cred_prefix = argv[++i];
        else if (strcmp(argv[i], "--in") == 0 && i + 1 < argc)
            in_file = argv[++i];
        else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc)
            out_file = argv[++i];
        else if (strcmp(argv[i], "--iak-pub") == 0 && i + 1 < argc)
            iak_pub_file = argv[++i];
        else if (strcmp(argv[i], "--iak-priv") == 0 && i + 1 < argc)
            iak_priv_file = argv[++i];
        else if (strcmp(argv[i], "--with-owner") == 0)
            with_owner = 1;
    }

    if (!transport_uri || !policy_file || !cred_prefix || !in_file || !out_file) {
        fprintf(stderr,
                "Usage: htpm2tool envelope-open --transport <uri> "
                "--policy <file>\n"
                "       --cred-in <prefix> --in <ciphertext> "
                "--out <plaintext>\n"
                "       [--iak-pub <file> --iak-priv <file>] "
                "[--with-owner]\n");
        return 1;
    }

    /* Read input files */
    policy = read_file(policy_file, &policy_len);
    ciphertext = read_file(in_file, &ciphertext_len);
    if (!policy || !ciphertext) goto out;

    snprintf(path, sizeof(path), "%s.wk.blob", cred_prefix);
    wk_blob = read_file(path, &wk_blob_len);
    snprintf(path, sizeof(path), "%s.wk.secret", cred_prefix);
    wk_secret = read_file(path, &wk_secret_len);
    if (!wk_blob || !wk_secret) goto out;

    if (iak_pub_file && iak_priv_file) {
        snprintf(path, sizeof(path), "%s.iak.blob", cred_prefix);
        iak_blob = read_file(path, &iak_blob_len);
        snprintf(path, sizeof(path), "%s.iak.secret", cred_prefix);
        iak_secret = read_file(path, &iak_secret_len);
        if (!iak_blob || !iak_secret) goto out;
    }

    if (with_owner) {
        snprintf(path, sizeof(path), "%s.owner.blob", cred_prefix);
        owner_blob = read_file(path, &owner_blob_len);
        snprintf(path, sizeof(path), "%s.owner.secret", cred_prefix);
        owner_secret = read_file(path, &owner_secret_len);
        if (!owner_blob || !owner_secret) goto out;
    }

    /* Initialize context and connect to TPM */
    r = htpm2_context_init(&ctx);
    if (htpm2_is_err(r)) die_result(r, "context_init");

    r = htpm2_transport_open(ctx, HTPM2_OK, transport_uri, &tp);
    if (htpm2_is_err(r)) die_result(r, "transport_open");

    /* Create EK */
    r = htpm2_create_primary(ctx, tp, HTPM2_OK, NULL,
                             HTPM2_HIERARCHY_ENDORSEMENT,
                             HTPM2_KEY_RSA_2048_DECRYPT,
                             NULL, 0, NULL, 0, &ek);
    if (htpm2_is_err(r)) die_result(r, "create EK");

    /* Create well-known key under NULL hierarchy */
    r = htpm2_wellknown_key_create(ctx, tp, HTPM2_OK,
                                   policy, policy_len, &wk);
    if (htpm2_is_err(r)) die_result(r, "create well-known key");

    /* Load IAK if provided */
    if (iak_pub_file && iak_priv_file) {
        void *iak_pub_data, *iak_priv_data;
        size_t iak_pub_len, iak_priv_len;

        iak_pub_data = read_file(iak_pub_file, &iak_pub_len);
        iak_priv_data = read_file(iak_priv_file, &iak_priv_len);
        if (!iak_pub_data || !iak_priv_data) {
            free(iak_pub_data);
            free(iak_priv_data);
            goto out;
        }

        /* Create SRK to load IAK under */
        r = htpm2_create_primary(ctx, tp, HTPM2_OK, NULL,
                                 HTPM2_HIERARCHY_OWNER,
                                 HTPM2_KEY_RSA_2048_STORAGE,
                                 NULL, 0, NULL, 0, &srk);
        if (htpm2_is_err(r)) {
            free(iak_pub_data);
            free(iak_priv_data);
            die_result(r, "create SRK for IAK");
        }

        r = htpm2_load(ctx, tp, HTPM2_OK, NULL, srk,
                       iak_pub_data, iak_pub_len,
                       iak_priv_data, iak_priv_len, &iak);
        free(iak_pub_data);
        free(iak_priv_data);
        if (htpm2_is_err(r)) die_result(r, "load IAK");
    }

    /* Create owner key if needed */
    if (with_owner) {
        r = htpm2_owner_key_create(ctx, tp, HTPM2_OK, &owner);
        if (htpm2_is_err(r)) die_result(r, "create owner key");
    }

    /* Decrypt using the TPM */
    r = htpm2_envelope_open_tpm(ctx, tp, HTPM2_OK,
                               ek,
                               wk,
                               wk_blob, wk_blob_len,
                               wk_secret, wk_secret_len,
                               iak,
                               iak_blob, iak_blob_len,
                               iak_secret, iak_secret_len,
                               owner,
                               owner_blob, owner_blob_len,
                               owner_secret, owner_secret_len,
                               ciphertext, ciphertext_len,
                               &plaintext, &plaintext_len);
    if (htpm2_is_err(r)) die_result(r, "decrypt_from_tpm");

    /* Write plaintext */
    if (write_file(out_file, plaintext, plaintext_len) < 0)
        goto out;

    printf("Decrypted %zu bytes -> %zu bytes\n",
           ciphertext_len, plaintext_len);
    rc = 0;

out:
    free(policy);
    free(ciphertext);
    free(wk_blob);
    free(wk_secret);
    free(iak_blob);
    free(iak_secret);
    free(owner_blob);
    free(owner_secret);
    free(plaintext);
    htpm2_object_close(&ek);
    htpm2_object_close(&wk);
    htpm2_object_close(&iak);
    htpm2_object_close(&srk);
    htpm2_object_close(&owner);
    htpm2_transport_close(&tp);
    htpm2_context_free(&ctx);
    return rc;
}

/*
 * Sub-command: quote-verify
 *
 * Validate a TPM quote.
 *
 * This requires:
 *   - The quote (TPMS_ATTEST) and signature
 *   - The AK's public key (for signature verification)
 *   - The expected PCR values (from eventlog analysis)
 *   - The qualifying data (timestamp nonce)
 *
 * The eventlog analysis part is complex and needs further design
 * discussion -- what format of eventlog, how to evaluate policy
 * against it, etc.
 */
/*
 * Sub-command: quote-verify
 *
 * Validate a TPM quote against an eventlog and PCR extension database.
 *
 * Usage: htpm2tool quote-verify --eventlog <file> --db <sqlite3-file>
 *        --pcr-policy <spec> --nonce <file>
 *        [--quote <file>] [--signature <file>] [--ak-pub <file>]
 *
 * Steps:
 *   1. Parse the eventlog (TCG binary format)
 *   2. Replay events to compute expected PCR values
 *   3. Check each extension against the DB (verdict, expiry, CVEs)
 *   4. Compare replayed PCR values against the quote
 *   5. (TODO) Verify quote signature with AK public key
 *   6. (TODO) Verify nonce in quote matches expected
 *   7. Print validation report
 *
 * PCR policy is a command-line argument:
 *   "0-7=validate,8=ignore,9=initial,10=validate,11-23=ignore"
 */
static int
cmd_quote_verify(int argc, char **argv)
{
    const char *eventlog_file = NULL;
    const char *db_file = NULL;
    const char *pcr_policy_spec = NULL;
    const char *nonce_file = NULL;
    const char *quote_file = NULL;
    const char *sig_file = NULL;
    const char *ak_pub_file = NULL;
    htpm2_context ctx = NULL;
    htpm2_pcrdb db = NULL;
    htpm2_eventlog_entry *events = NULL;
    size_t num_events = 0;
    htpm2_pcr_policy policy;
    htpm2_validation_report report;
    void *eventlog_data = NULL, *quote_data = NULL, *sig_data = NULL;
    void *ak_pub_data = NULL, *nonce_data = NULL;
    size_t eventlog_len, quote_len, sig_len, ak_pub_len, nonce_len;
    htpm2_result r;
    int i, rc = 1;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--eventlog") == 0 && i + 1 < argc)
            eventlog_file = argv[++i];
        else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc)
            db_file = argv[++i];
        else if (strcmp(argv[i], "--pcr-policy") == 0 && i + 1 < argc)
            pcr_policy_spec = argv[++i];
        else if (strcmp(argv[i], "--nonce") == 0 && i + 1 < argc)
            nonce_file = argv[++i];
        else if (strcmp(argv[i], "--quote") == 0 && i + 1 < argc)
            quote_file = argv[++i];
        else if (strcmp(argv[i], "--signature") == 0 && i + 1 < argc)
            sig_file = argv[++i];
        else if (strcmp(argv[i], "--ak-pub") == 0 && i + 1 < argc)
            ak_pub_file = argv[++i];
    }

    if (!eventlog_file && !quote_file) {
        fprintf(stderr,
                "Usage: htpm2tool quote-verify\n"
                "       [--eventlog <file>]  [--db <sqlite3-file>]\n"
                "       [--pcr-policy <spec>]\n"
                "       [--quote <file>] [--signature <file>]\n"
                "       [--ak-pub <file>] [--nonce <file>]\n"
                "\n"
                "PCR policy spec: \"0-7=validate,8=ignore,10=initial\"\n");
        return 1;
    }

    r = htpm2_context_init(&ctx);
    if (htpm2_is_err(r)) die_result(r, "context_init");

    /* Parse PCR policy */
    r = htpm2_pcr_policy_parse(pcr_policy_spec, &policy);
    if (htpm2_is_err(r)) die_result(r, "pcr_policy_parse");

    /* Verify quote signature if provided */
    if (quote_file && sig_file && ak_pub_file) {
        void *pcr_digest = NULL;
        size_t pcr_digest_len = 0;

        quote_data = read_file(quote_file, &quote_len);
        sig_data = read_file(sig_file, &sig_len);
        ak_pub_data = read_file(ak_pub_file, &ak_pub_len);
        if (!quote_data || !sig_data || !ak_pub_data) goto out;

        if (nonce_file) {
            nonce_data = read_file(nonce_file, &nonce_len);
            if (!nonce_data) goto out;
        }

        r = htpm2_quote_verify(ctx,
                               quote_data, quote_len,
                               sig_data, sig_len,
                               ak_pub_data, ak_pub_len,
                               nonce_data, nonce_data ? nonce_len : 0,
                               &pcr_digest, &pcr_digest_len);
        if (htpm2_is_err(r))
            die_result(r, "quote signature verification");

        printf("Quote signature: VALID\n");
        if (nonce_data)
            printf("Quote nonce:     VALID\n");
        free(pcr_digest);
    } else if (quote_file) {
        fprintf(stderr, "htpm2tool: --quote requires --signature and "
                "--ak-pub\n");
        goto out;
    }

    /* Open DB if specified */
    if (db_file) {
        r = htpm2_pcrdb_open(db_file, &db);
        if (htpm2_is_err(r)) die_result(r, "pcrdb_open");
    }

    /* Read and parse eventlog */
    if (eventlog_file) {
        eventlog_data = read_file(eventlog_file, &eventlog_len);
        if (!eventlog_data) goto out;

        r = htpm2_eventlog_parse_tcg(eventlog_data, eventlog_len,
                                      &events, &num_events);
        if (htpm2_is_err(r)) die_result(r, "eventlog_parse");

        printf("Parsed %zu eventlog entries\n", num_events);

        r = htpm2_eventlog_validate(ctx, events, num_events, &policy, db,
                                     0x000B, /* SHA-256 */
                                     NULL, 0, NULL, 0,
                                     &report);
        if (htpm2_is_err(r)) die_result(r, "eventlog_validate");

        printf("\nEventlog validation:\n");
        printf("  Status:   %s\n", report.ok ? "PASS" : "FAIL");
        printf("  Failures: %zu\n", report.num_failures);
        printf("  Warnings: %zu\n", report.num_warnings);
        printf("  Unknown:  %zu\n", report.num_unknown);

        for (i = 0; (size_t)i < report.num_messages; i++)
            printf("  %s\n", report.messages[i]);

        rc = report.ok ? 0 : 1;
        htpm2_validation_report_free(&report);
    } else {
        rc = 0; /* quote-only verification passed */
    }

out:
    htpm2_eventlog_free(events, num_events);
    free(eventlog_data);
    free(quote_data);
    free(sig_data);
    free(ak_pub_data);
    free(nonce_data);
    htpm2_pcrdb_close(&db);
    htpm2_context_free(&ctx);
    return rc;
}

/* ================================================================
 * Key management commands
 * ================================================================ */

static uint32_t
parse_attrs_string(const char *s)
{
    uint32_t attrs = 0;
    if (s == NULL) return 0;
    if (strstr(s, "fixedTPM")) attrs |= (1U << 1);
    if (strstr(s, "fixedParent")) attrs |= (1U << 4);
    if (strstr(s, "sensDataOrigin")) attrs |= (1U << 5);
    if (strstr(s, "userWithAuth")) attrs |= (1U << 6);
    if (strstr(s, "adminWithPolicy")) attrs |= (1U << 7);
    if (strstr(s, "noDA")) attrs |= (1U << 10);
    if (strstr(s, "encryptedDup")) attrs |= (1U << 11);
    if (strstr(s, "restricted")) attrs |= (1U << 16);
    if (strstr(s, "decrypt")) attrs |= (1U << 17);
    if (strstr(s, "sign")) attrs |= (1U << 18);
    return attrs;
}

static htpm2_key_type
parse_key_type(const char *s)
{
    if (s == NULL) return HTPM2_KEY_RSA_2048_SIGN;
    if (strcmp(s, "rsa-2048-sign") == 0) return HTPM2_KEY_RSA_2048_SIGN;
    if (strcmp(s, "rsa-2048-decrypt") == 0) return HTPM2_KEY_RSA_2048_DECRYPT;
    if (strcmp(s, "rsa-2048-storage") == 0) return HTPM2_KEY_RSA_2048_STORAGE;
    if (strcmp(s, "rsa-3072-sign") == 0) return HTPM2_KEY_RSA_3072_SIGN;
    if (strcmp(s, "rsa-3072-decrypt") == 0) return HTPM2_KEY_RSA_3072_DECRYPT;
    if (strcmp(s, "rsa-3072-storage") == 0) return HTPM2_KEY_RSA_3072_STORAGE;
    if (strcmp(s, "ecc-p256-sign") == 0) return HTPM2_KEY_ECC_P256_SIGN;
    if (strcmp(s, "ecc-p256-decrypt") == 0) return HTPM2_KEY_ECC_P256_DECRYPT;
    if (strcmp(s, "ecc-p256-storage") == 0) return HTPM2_KEY_ECC_P256_STORAGE;
    if (strcmp(s, "ecc-p384-sign") == 0) return HTPM2_KEY_ECC_P384_SIGN;
    if (strcmp(s, "ecc-p384-decrypt") == 0) return HTPM2_KEY_ECC_P384_DECRYPT;
    if (strcmp(s, "ecc-p384-storage") == 0) return HTPM2_KEY_ECC_P384_STORAGE;
    return HTPM2_KEY_RSA_2048_SIGN;
}

static uint32_t
parse_hierarchy_arg(const char *s)
{
    if (s == NULL) return 0;
    if (strcmp(s, "owner") == 0) return HTPM2_HIERARCHY_OWNER;
    if (strcmp(s, "endorsement") == 0) return HTPM2_HIERARCHY_ENDORSEMENT;
    if (strcmp(s, "platform") == 0) return HTPM2_HIERARCHY_PLATFORM;
    if (strcmp(s, "null") == 0) return HTPM2_HIERARCHY_NULL;
    return (uint32_t)strtoul(s, NULL, 0);
}

/*
 * htpm2tool key-create
 *
 * Create a key (primary or child) with optional policy and custom attributes.
 */
static int
cmd_key_create(int argc, char **argv)
{
    const char *transport_uri = NULL;
    const char *type_str = "rsa-2048-sign";
    const char *hierarchy_str = NULL;
    const char *parent_handle_str = NULL;
    const char *policy_file = NULL;
    const char *attrs_str = NULL;
    const char *out_pub = NULL;
    const char *out_priv = NULL;
    const char *out_name = NULL;
    htpm2_context ctx = NULL;
    htpm2_transport tp = NULL;
    htpm2_object key = NULL, parent = NULL;
    void *policy_data = NULL;
    size_t policy_len = 0;
    htpm2_result r;
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--transport") == 0 && i + 1 < argc)
            transport_uri = argv[++i];
        else if (strcmp(argv[i], "--type") == 0 && i + 1 < argc)
            type_str = argv[++i];
        else if (strcmp(argv[i], "--hierarchy") == 0 && i + 1 < argc)
            hierarchy_str = argv[++i];
        else if (strcmp(argv[i], "--parent-handle") == 0 && i + 1 < argc)
            parent_handle_str = argv[++i];
        else if (strcmp(argv[i], "--policy") == 0 && i + 1 < argc)
            policy_file = argv[++i];
        else if (strcmp(argv[i], "--attrs") == 0 && i + 1 < argc)
            attrs_str = argv[++i];
        else if (strcmp(argv[i], "--out-pub") == 0 && i + 1 < argc)
            out_pub = argv[++i];
        else if (strcmp(argv[i], "--out-priv") == 0 && i + 1 < argc)
            out_priv = argv[++i];
        else if (strcmp(argv[i], "--out-name") == 0 && i + 1 < argc)
            out_name = argv[++i];
    }

    if (!transport_uri || !out_pub || (!hierarchy_str && !parent_handle_str)) {
        fprintf(stderr,
            "Usage: htpm2tool key-create --transport <uri>\n"
            "       --type <key-type> --out-pub <file>\n"
            "       [--hierarchy owner|endorsement|null|platform]\n"
            "       [--parent-handle <handle>]\n"
            "       [--policy <policy-digest-file>]\n"
            "       [--attrs <attr-list>]\n"
            "       [--out-priv <file>] [--out-name <file>]\n"
            "\n"
            "Key types: rsa-2048-sign, rsa-2048-decrypt, rsa-2048-storage,\n"
            "           rsa-3072-{sign,decrypt,storage},\n"
            "           ecc-p256-{sign,decrypt,storage},\n"
            "           ecc-p384-{sign,decrypt,storage}\n"
            "\n"
            "Attrs: comma-separated: sensDataOrigin,userWithAuth,sign,\n"
            "       decrypt,restricted,fixedTPM,fixedParent,noDA,\n"
            "       adminWithPolicy,encryptedDup\n"
            "\n"
            "For duplicable keys, use:\n"
            "  --attrs sensDataOrigin,userWithAuth,sign,encryptedDup\n");
        return 1;
    }

    r = htpm2_context_init(&ctx);
    if (htpm2_is_err(r)) die_result(r, "context_init");

    r = htpm2_transport_open(ctx, HTPM2_OK, transport_uri, &tp);
    if (htpm2_is_err(r)) die_result(r, "transport_open");

    if (policy_file) {
        policy_data = read_file(policy_file, &policy_len);
        if (!policy_data) { r = htpm2_result_local(EIO, HTPM2_F_LOCAL, EIO, "read policy"); goto out; }
    }

    if (hierarchy_str) {
        /* CreatePrimary */
        /* For CreatePrimary with custom attrs, we need to build the
         * command ourselves since htpm2_create_primary uses the
         * standard template.  Use the same approach as enrollment.c. */
        heim_storage *cmd_sp, *rsp;
        uint32_t rc, handle, hierarchy;
        heim_storage *pub_sp, *sens_sp;
        void *pub_bytes, *sens_bytes;
        size_t pub_bytes_len, sens_bytes_len;
        int ret;
        uint32_t attrs_val = parse_attrs_string(attrs_str);

        hierarchy = parse_hierarchy_arg(hierarchy_str);

        /* Build inPublic (TPMT_PUBLIC wrapped in TPM2B) */
        pub_sp = heim_storage_emem();
        ret = htpm2_marshal_key_template_attrs(pub_sp,
            parse_key_type(type_str), attrs_val,
            policy_data, policy_len);
        if (ret) { heim_storage_free(pub_sp); die_result(htpm2_result_local(ret, HTPM2_F_MARSHAL, ret, "template"), "key-create"); }
        heim_storage_to_data(pub_sp, &pub_bytes, &pub_bytes_len);
        heim_storage_free(pub_sp);

        /* Build inSensitive */
        sens_sp = heim_storage_emem();
        htpm2_marshal_tpm2b(sens_sp, NULL, 0); /* userAuth */
        htpm2_marshal_tpm2b(sens_sp, NULL, 0); /* data */
        heim_storage_to_data(sens_sp, &sens_bytes, &sens_bytes_len);
        heim_storage_free(sens_sp);

        cmd_sp = heim_storage_emem();
        htpm2_marshal_cmd_header(cmd_sp, TPM_ST_NO_SESSIONS,
                                 TPM2_CC_CreatePrimary);
        heim_store_uint32(cmd_sp, hierarchy);
        htpm2_marshal_tpm2b(cmd_sp, sens_bytes, sens_bytes_len); /* inSensitive */
        free(sens_bytes);
        htpm2_marshal_tpm2b(cmd_sp, pub_bytes, pub_bytes_len); /* inPublic */
        free(pub_bytes);
        htpm2_marshal_tpm2b(cmd_sp, NULL, 0); /* outsideInfo */
        heim_store_uint32(cmd_sp, 0); /* creationPCR count=0 */

        r = htpm2_command_execute(ctx, tp, cmd_sp, &rsp, &rc);
        heim_storage_free(cmd_sp);
        if (htpm2_is_err(r)) die_result(r, "CreatePrimary");

        heim_ret_uint32(rsp, &handle);

        /* Read outPublic */
        {
            void *out_pub_data;
            uint16_t out_pub_size;
            htpm2_unmarshal_tpm2b(rsp, &out_pub_data, &out_pub_size);
            if (out_pub && out_pub_data)
                write_file(out_pub, out_pub_data, out_pub_size);

            /* Skip creationData, creationHash, creationTicket */
            /* Read name */
            { void *tmp; uint16_t tl; htpm2_unmarshal_tpm2b(rsp, &tmp, &tl); free(tmp); } /* creationData */
            { void *tmp; uint16_t tl; htpm2_unmarshal_tpm2b(rsp, &tmp, &tl); free(tmp); } /* creationHash */
            { uint16_t tt; uint32_t th; htpm2_unmarshal_tpm2b(rsp, &out_pub_data, &out_pub_size); /* ticket digest - skip structure */  }

            {
                void *name_data;
                uint16_t name_size;
                htpm2_unmarshal_tpm2b(rsp, &name_data, &name_size);
                if (out_name && name_data)
                    write_file(out_name, name_data, name_size);
                free(name_data);
            }

            free(out_pub_data);
        }
        heim_storage_free(rsp);

        printf("Created primary key: handle 0x%08x\n", handle);

    } else if (parent_handle_str) {
        /* Create child key under parent */
        uint32_t parent_handle = (uint32_t)strtoul(parent_handle_str, NULL, 0);
        const void *pub, *priv;
        size_t pub_len, priv_len;

        /* We need the parent loaded.  For simplicity, assume it's a
         * persistent handle or the caller has already loaded it. */
        parent = htpm2_object_alloc(tp, parent_handle);
        if (parent == NULL) die_result(htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM, "alloc"), "key-create");

        r = htpm2_create(ctx, tp, HTPM2_OK, NULL, parent,
                         parse_key_type(type_str),
                         NULL, 0,
                         policy_data, policy_len,
                         &key);
        if (htpm2_is_err(r)) die_result(r, "Create");

        htpm2_object_get_public(key, &pub, &pub_len);
        htpm2_object_get_private(key, &priv, &priv_len);

        if (out_pub && pub)
            write_file(out_pub, pub, pub_len);
        if (out_priv && priv)
            write_file(out_priv, priv, priv_len);

        printf("Created child key: %zu pub bytes, %zu priv bytes\n",
               pub_len, priv_len);
    }

out:
    free(policy_data);
    htpm2_object_close(&key);
    htpm2_object_close(&parent);
    htpm2_transport_close(&tp);
    htpm2_context_free(&ctx);
    return htpm2_is_err(r) ? 1 : 0;
}

/*
 * htpm2tool key-duplicate
 */
static int
cmd_key_duplicate(int argc, char **argv)
{
    const char *transport_uri = NULL;
    const char *key_pub_file = NULL;
    const char *key_priv_file = NULL;
    const char *parent_handle_str = NULL;
    const char *new_parent_pub_file = NULL;
    const char *policy_file = NULL;
    const char *out_dup = NULL;
    const char *out_seed = NULL;
    htpm2_context ctx = NULL;
    htpm2_transport tp = NULL;
    htpm2_result r;
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--transport") == 0 && i + 1 < argc)
            transport_uri = argv[++i];
        else if (strcmp(argv[i], "--key-pub") == 0 && i + 1 < argc)
            key_pub_file = argv[++i];
        else if (strcmp(argv[i], "--key-priv") == 0 && i + 1 < argc)
            key_priv_file = argv[++i];
        else if (strcmp(argv[i], "--parent-handle") == 0 && i + 1 < argc)
            parent_handle_str = argv[++i];
        else if (strcmp(argv[i], "--new-parent-pub") == 0 && i + 1 < argc)
            new_parent_pub_file = argv[++i];
        else if (strcmp(argv[i], "--out-dup") == 0 && i + 1 < argc)
            out_dup = argv[++i];
        else if (strcmp(argv[i], "--out-seed") == 0 && i + 1 < argc)
            out_seed = argv[++i];
    }

    if (!transport_uri || !new_parent_pub_file || !out_dup || !out_seed) {
        fprintf(stderr,
            "Usage: htpm2tool key-duplicate --transport <uri>\n"
            "       --new-parent-pub <file>\n"
            "       --out-dup <file> --out-seed <file>\n"
            "       [--key-pub <file> --key-priv <file> "
            "--parent-handle <handle>]\n"
            "\n"
            "If --key-pub and --key-priv are given, loads the key first.\n"
            "Otherwise performs software-only duplication using\n"
            "--new-parent-pub.\n");
        return 1;
    }

    r = htpm2_context_init(&ctx);
    if (htpm2_is_err(r)) die_result(r, "context_init");

    if (key_pub_file && new_parent_pub_file && !transport_uri) {
        /* Software-only duplicate */
        void *key_pub, *np_pub, *dup_data, *seed_data;
        size_t key_pub_len, np_pub_len, dup_len, seed_len;

        key_pub = read_file(key_pub_file, &key_pub_len);
        np_pub = read_file(new_parent_pub_file, &np_pub_len);
        if (!key_pub || !np_pub) goto sw_out;

        /* TODO: need key_name and sensitive for software duplicate */
        fprintf(stderr, "htpm2tool: software duplicate requires "
                "--key-sensitive (not yet implemented)\n");
    sw_out:
        htpm2_context_free(&ctx);
        return 1;
    }

    /* TPM-side duplicate */
    r = htpm2_transport_open(ctx, HTPM2_OK, transport_uri, &tp);
    if (htpm2_is_err(r)) die_result(r, "transport_open");

    {
        htpm2_object parent_obj, key_obj, np_obj;
        void *key_pub, *key_priv, *dup_out, *seed_out;
        size_t key_pub_len, key_priv_len, dup_len, seed_len;
        uint32_t parent_handle;

        if (!key_pub_file || !key_priv_file || !parent_handle_str) {
            fprintf(stderr, "htpm2tool: TPM duplicate requires "
                    "--key-pub, --key-priv, --parent-handle\n");
            htpm2_transport_close(&tp);
            htpm2_context_free(&ctx);
            return 1;
        }

        key_pub = read_file(key_pub_file, &key_pub_len);
        key_priv = read_file(key_priv_file, &key_priv_len);
        parent_handle = (uint32_t)strtoul(parent_handle_str, NULL, 0);

        parent_obj = htpm2_object_alloc(tp, parent_handle);
        r = htpm2_load(ctx, tp, HTPM2_OK, NULL, parent_obj,
                       key_pub, key_pub_len,
                       key_priv, key_priv_len, &key_obj);
        if (htpm2_is_err(r)) die_result(r, "load key for dup");

        /* TODO: load new parent, evaluate policy, duplicate */
        /* For now this is a placeholder */
        fprintf(stderr, "htpm2tool: TPM-side duplicate with policy evaluation "
                "not yet fully wired\n");

        htpm2_object_close(&key_obj);
        htpm2_object_close(&parent_obj);
        free(key_pub);
        free(key_priv);
    }

    htpm2_transport_close(&tp);
    htpm2_context_free(&ctx);
    return 1;
}

/*
 * htpm2tool key-import
 */
static int
cmd_key_import(int argc, char **argv)
{
    const char *transport_uri = NULL;
    const char *parent_handle_str = NULL;
    const char *dup_file = NULL;
    const char *seed_file = NULL;
    const char *pub_file = NULL;
    const char *out_priv = NULL;
    htpm2_context ctx = NULL;
    htpm2_transport tp = NULL;
    htpm2_object parent_obj = NULL;
    htpm2_result r;
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--transport") == 0 && i + 1 < argc)
            transport_uri = argv[++i];
        else if (strcmp(argv[i], "--parent-handle") == 0 && i + 1 < argc)
            parent_handle_str = argv[++i];
        else if (strcmp(argv[i], "--dup") == 0 && i + 1 < argc)
            dup_file = argv[++i];
        else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc)
            seed_file = argv[++i];
        else if (strcmp(argv[i], "--pub") == 0 && i + 1 < argc)
            pub_file = argv[++i];
        else if (strcmp(argv[i], "--out-priv") == 0 && i + 1 < argc)
            out_priv = argv[++i];
    }

    if (!transport_uri || !parent_handle_str || !dup_file ||
        !seed_file || !pub_file || !out_priv) {
        fprintf(stderr,
            "Usage: htpm2tool key-import --transport <uri>\n"
            "       --parent-handle <handle>\n"
            "       --dup <file> --seed <file> --pub <file>\n"
            "       --out-priv <file>\n");
        return 1;
    }

    r = htpm2_context_init(&ctx);
    if (htpm2_is_err(r)) die_result(r, "context_init");

    r = htpm2_transport_open(ctx, HTPM2_OK, transport_uri, &tp);
    if (htpm2_is_err(r)) die_result(r, "transport_open");

    {
        void *dup_data, *seed_data, *pub_data, *priv_out;
        size_t dup_len, seed_len, pub_len, priv_out_len;
        uint32_t parent_handle;

        dup_data = read_file(dup_file, &dup_len);
        seed_data = read_file(seed_file, &seed_len);
        pub_data = read_file(pub_file, &pub_len);
        parent_handle = (uint32_t)strtoul(parent_handle_str, NULL, 0);

        if (!dup_data || !seed_data || !pub_data) goto imp_out;

        parent_obj = htpm2_object_alloc(tp, parent_handle);

        r = htpm2_import(ctx, tp, HTPM2_OK, NULL, parent_obj,
                         pub_data, pub_len,
                         dup_data, dup_len,
                         seed_data, seed_len,
                         NULL, 0, /* sym_seed unused */
                         &priv_out, &priv_out_len);
        if (htpm2_is_err(r)) die_result(r, "Import");

        write_file(out_priv, priv_out, priv_out_len);
        printf("Imported key: %zu priv bytes written to %s\n",
               priv_out_len, out_priv);
        free(priv_out);

    imp_out:
        free(dup_data);
        free(seed_data);
        free(pub_data);
    }

    htpm2_object_close(&parent_obj);
    htpm2_transport_close(&tp);
    htpm2_context_free(&ctx);
    return htpm2_is_err(r) ? 1 : 0;
}

/*
 * htpm2tool key-load
 */
static int
cmd_key_load(int argc, char **argv)
{
    const char *transport_uri = NULL;
    const char *parent_handle_str = NULL;
    const char *pub_file = NULL;
    const char *priv_file = NULL;
    htpm2_context ctx = NULL;
    htpm2_transport tp = NULL;
    htpm2_object parent_obj = NULL, key_obj = NULL;
    htpm2_result r;
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--transport") == 0 && i + 1 < argc)
            transport_uri = argv[++i];
        else if (strcmp(argv[i], "--parent-handle") == 0 && i + 1 < argc)
            parent_handle_str = argv[++i];
        else if (strcmp(argv[i], "--pub") == 0 && i + 1 < argc)
            pub_file = argv[++i];
        else if (strcmp(argv[i], "--priv") == 0 && i + 1 < argc)
            priv_file = argv[++i];
    }

    if (!transport_uri || !parent_handle_str || !pub_file || !priv_file) {
        fprintf(stderr,
            "Usage: htpm2tool key-load --transport <uri>\n"
            "       --parent-handle <handle>\n"
            "       --pub <file> --priv <file>\n");
        return 1;
    }

    r = htpm2_context_init(&ctx);
    if (htpm2_is_err(r)) die_result(r, "context_init");

    r = htpm2_transport_open(ctx, HTPM2_OK, transport_uri, &tp);
    if (htpm2_is_err(r)) die_result(r, "transport_open");

    {
        void *pub_data, *priv_data;
        size_t pub_len, priv_len;
        uint32_t parent_handle;

        pub_data = read_file(pub_file, &pub_len);
        priv_data = read_file(priv_file, &priv_len);
        parent_handle = (uint32_t)strtoul(parent_handle_str, NULL, 0);

        if (!pub_data || !priv_data) goto ld_out;

        parent_obj = htpm2_object_alloc(tp, parent_handle);

        r = htpm2_load(ctx, tp, HTPM2_OK, NULL, parent_obj,
                       pub_data, pub_len,
                       priv_data, priv_len,
                       &key_obj);
        if (htpm2_is_err(r)) die_result(r, "Load");

        printf("Loaded key: handle 0x%08x\n",
               htpm2_object_get_handle(key_obj));

    ld_out:
        free(pub_data);
        free(priv_data);
    }

    /* Don't close key_obj -- leave it loaded */
    htpm2_object_close(&parent_obj);
    htpm2_transport_close(&tp);
    htpm2_context_free(&ctx);
    return htpm2_is_err(r) ? 1 : 0;
}

static void
usage(void)
{
    fprintf(stderr,
            "Usage: htpm2tool <command> [options]\n"
            "\n"
            "Commands:\n"
            "  timestamp      Generate/verify a signed timestamp for quote nonces\n"
            "  encrypt-to     Encrypt a file to a target TPM\n"
            "  envelope-open  Decrypt an EncryptTo ciphertext using the local TPM\n"
            "  quote-verify   Validate a TPM quote + eventlog\n"
            "  key-create     Create a key (primary or child) on the TPM\n"
            "  key-duplicate  Duplicate a key to a different parent/TPM\n"
            "  key-import     Import a duplicated key under a local parent\n"
            "  key-load       Load a key from pub/priv blobs\n"
            "\n"
            "Run 'htpm2tool <command> --help' for command-specific usage.\n");
}

int
main(int argc, char **argv)
{
    if (argc < 2) {
        usage();
        return 1;
    }

    if (strcmp(argv[1], "timestamp") == 0)
        return cmd_timestamp(argc - 2, argv + 2);
    if (strcmp(argv[1], "encrypt-to") == 0)
        return cmd_encrypt_to(argc - 2, argv + 2);
    if (strcmp(argv[1], "envelope-open") == 0)
        return cmd_envelope_open(argc - 2, argv + 2);
    if (strcmp(argv[1], "quote-verify") == 0)
        return cmd_quote_verify(argc - 2, argv + 2);
    if (strcmp(argv[1], "key-create") == 0)
        return cmd_key_create(argc - 2, argv + 2);
    if (strcmp(argv[1], "key-duplicate") == 0)
        return cmd_key_duplicate(argc - 2, argv + 2);
    if (strcmp(argv[1], "key-import") == 0)
        return cmd_key_import(argc - 2, argv + 2);
    if (strcmp(argv[1], "key-load") == 0)
        return cmd_key_load(argc - 2, argv + 2);

    fprintf(stderr, "htpm2tool: unknown command '%s'\n", argv[1]);
    usage();
    return 1;
}
