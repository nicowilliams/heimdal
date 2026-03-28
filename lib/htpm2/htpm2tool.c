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
 *   decrypt-from  Decrypt an EncryptTo ciphertext using the local TPM
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
 */
static int
cmd_timestamp(int argc, char **argv)
{
    const char *key_file = NULL;
    const char *out_file = NULL;
    const char *verify_file = NULL;
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
    }

    if (key_file == NULL) {
        fprintf(stderr, "Usage: htpm2tool timestamp --key <keyfile> "
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

        key_data = read_file(key_file, &key_len);
        ts_data = read_file(verify_file, &ts_len);
        if (!key_data || !ts_data || ts_len != 40) {
            fprintf(stderr, "htpm2tool: invalid timestamp file "
                    "(expected 40 bytes, got %zu)\n", ts_len);
            free(key_data);
            free(ts_data);
            htpm2_context_free(&ctx);
            return 1;
        }

        r = htpm2_hmac_sha256(ctx, key_data, key_len,
                              ts_data, 8, expected_hmac, &hmac_len);
        free(key_data);
        if (htpm2_is_err(r))
            die_result(r, "HMAC verify");

        if (memcmp(expected_hmac, (uint8_t *)ts_data + 8, 32) != 0) {
            fprintf(stderr, "htpm2tool: timestamp HMAC verification FAILED\n");
            free(ts_data);
            htpm2_context_free(&ctx);
            return 1;
        }

        /* Decode timestamp */
        {
            const uint8_t *p = ts_data;
            ts_time = ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
                      ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
                      ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
                      ((uint64_t)p[6] << 8) | (uint64_t)p[7];
        }

        printf("Timestamp valid: %s", ctime(&ts_time));
        free(ts_data);
    } else {
        /* Generate a timestamp */
        uint8_t ts_buf[40];  /* 8 bytes time + 32 bytes HMAC */
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

        /* Encode timestamp as big-endian uint64 */
        ts_buf[0] = (now >> 56) & 0xff;
        ts_buf[1] = (now >> 48) & 0xff;
        ts_buf[2] = (now >> 40) & 0xff;
        ts_buf[3] = (now >> 32) & 0xff;
        ts_buf[4] = (now >> 24) & 0xff;
        ts_buf[5] = (now >> 16) & 0xff;
        ts_buf[6] = (now >> 8) & 0xff;
        ts_buf[7] = now & 0xff;

        r = htpm2_hmac_sha256(ctx, key_data, key_len,
                              ts_buf, 8, ts_buf + 8, &hmac_len);
        free(key_data);
        if (htpm2_is_err(r))
            die_result(r, "HMAC");

        if (out_file) {
            if (write_file(out_file, ts_buf, 40) < 0) {
                htpm2_context_free(&ctx);
                return 1;
            }
        } else {
            /* Write to stdout */
            fwrite(ts_buf, 1, 40, stdout);
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
 * Sub-command: decrypt-from
 *
 * Decrypt an EncryptTo ciphertext using the local TPM.
 *
 * Usage: htpm2tool decrypt-from --transport <uri>
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
 * Sub-command: decrypt-from
 *
 * Decrypt an EncryptTo ciphertext using the local TPM.
 *
 * Usage: htpm2tool decrypt-from --transport <uri> --policy <file>
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
cmd_decrypt_from(int argc, char **argv)
{
    const char *transport_uri = NULL;
    const char *policy_file = NULL;
    const char *cred_prefix = NULL;
    const char *in_file = NULL;
    const char *out_file = NULL;
    int with_iak = 0, with_owner = 0;
    htpm2_context ctx = NULL;
    htpm2_transport tp = NULL;
    htpm2_object ek = NULL, wk = NULL, owner = NULL;
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
        else if (strcmp(argv[i], "--with-iak") == 0)
            with_iak = 1;
        else if (strcmp(argv[i], "--with-owner") == 0)
            with_owner = 1;
    }

    if (!transport_uri || !policy_file || !cred_prefix || !in_file || !out_file) {
        fprintf(stderr,
                "Usage: htpm2tool decrypt-from --transport <uri> "
                "--policy <file>\n"
                "       --cred-in <prefix> --in <ciphertext> "
                "--out <plaintext>\n"
                "       [--with-iak] [--with-owner]\n");
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

    if (with_iak) {
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

    /* Create owner key if needed */
    if (with_owner) {
        r = htpm2_owner_key_create(ctx, tp, HTPM2_OK, &owner);
        if (htpm2_is_err(r)) die_result(r, "create owner key");
    }

    /* Decrypt using the TPM */
    r = htpm2_decrypt_from_tpm(ctx, tp, HTPM2_OK,
                               ek, NULL, /* EK auth: password */
                               wk,
                               wk_blob, wk_blob_len,
                               wk_secret, wk_secret_len,
                               NULL, /* IAK: TODO load if --with-iak */
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
    htpm2_context ctx = NULL;
    htpm2_pcrdb db = NULL;
    htpm2_eventlog_entry *events = NULL;
    size_t num_events = 0;
    htpm2_pcr_policy policy;
    htpm2_validation_report report;
    void *eventlog_data = NULL;
    size_t eventlog_len;
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
    }

    if (!eventlog_file) {
        fprintf(stderr,
                "Usage: htpm2tool quote-verify --eventlog <file>\n"
                "       [--db <sqlite3-file>]\n"
                "       [--pcr-policy <spec>]  (default: all validate)\n"
                "       [--nonce <file>]\n"
                "\n"
                "PCR policy spec: \"0-7=validate,8=ignore,10=initial\"\n"
                "  validate: replay eventlog, check extensions against DB\n"
                "  initial:  PCR must be unextended (all zeros)\n"
                "  ignore:   don't check this PCR\n");
        return 1;
    }

    r = htpm2_context_init(&ctx);
    if (htpm2_is_err(r)) die_result(r, "context_init");

    /* Parse PCR policy */
    r = htpm2_pcr_policy_parse(pcr_policy_spec, &policy);
    if (htpm2_is_err(r)) die_result(r, "pcr_policy_parse");

    /* Open DB if specified */
    if (db_file) {
        r = htpm2_pcrdb_open(db_file, &db);
        if (htpm2_is_err(r)) die_result(r, "pcrdb_open");
    }

    /* Read and parse eventlog */
    eventlog_data = read_file(eventlog_file, &eventlog_len);
    if (!eventlog_data) goto out;

    r = htpm2_eventlog_parse_tcg(eventlog_data, eventlog_len,
                                  &events, &num_events);
    if (htpm2_is_err(r)) die_result(r, "eventlog_parse");

    printf("Parsed %zu eventlog entries\n", num_events);

    /* Validate -- for now without a quote (just eventlog + DB) */
    r = htpm2_eventlog_validate(ctx, events, num_events, &policy, db,
                                 0x000B, /* SHA-256 */
                                 NULL, 0, NULL, 0,  /* no quote data yet */
                                 &report);
    if (htpm2_is_err(r)) die_result(r, "eventlog_validate");

    /* Print report */
    printf("\nValidation report:\n");
    printf("  Status:   %s\n", report.ok ? "PASS" : "FAIL");
    printf("  Failures: %zu\n", report.num_failures);
    printf("  Warnings: %zu\n", report.num_warnings);
    printf("  Unknown:  %zu\n", report.num_unknown);

    for (i = 0; (size_t)i < report.num_messages; i++)
        printf("  %s\n", report.messages[i]);

    rc = report.ok ? 0 : 1;

    htpm2_validation_report_free(&report);

out:
    htpm2_eventlog_free(events, num_events);
    free(eventlog_data);
    htpm2_pcrdb_close(&db);
    htpm2_context_free(&ctx);
    return rc;
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
            "  decrypt-from   Decrypt an EncryptTo ciphertext using the local TPM\n"
            "  quote-verify   Validate a TPM quote (not yet implemented)\n"
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
    if (strcmp(argv[1], "decrypt-from") == 0)
        return cmd_decrypt_from(argc - 2, argv + 2);
    if (strcmp(argv[1], "quote-verify") == 0)
        return cmd_quote_verify(argc - 2, argv + 2);

    fprintf(stderr, "htpm2tool: unknown command '%s'\n", argv[1]);
    usage();
    return 1;
}
