/*
 * Tests for htpm2 internal crypto module.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "htpm2.h"
#include "crypto.h"

static int failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s: %s\n", __func__, msg); \
        failures++; \
    } \
} while (0)

static int
hexcmp(const void *buf, const char *hex, size_t len)
{
    const unsigned char *p = buf;
    size_t i;

    for (i = 0; i < len; i++) {
        unsigned int byte;
        sscanf(hex + i * 2, "%02x", &byte);
        if (p[i] != (unsigned char)byte)
            return 1;
    }
    return 0;
}

static void
test_sha256(htpm2_context ctx)
{
    /* SHA-256("abc") = ba7816bf 8f01cfea 414140de 5dae2223
     *                  b00361a3 96177a9c b410ff61 f20015ad */
    unsigned char digest[32];
    htpm2_result r;

    r = htpm2_sha256(ctx, "abc", 3, digest);
    CHECK(htpm2_is_ok(r), "sha256 should succeed");
    CHECK(hexcmp(digest, "ba7816bf8f01cfea414140de5dae2223"
                         "b00361a396177a9cb410ff61f20015ad", 32) == 0,
          "sha256(\"abc\") should match NIST vector");
    htpm2_result_free(&r);
}

static void
test_hmac_sha256(htpm2_context ctx)
{
    /* RFC 4231 Test Case 2:
     * Key  = "Jefe" (4 bytes)
     * Data = "what do ya want for nothing?" (28 bytes)
     * HMAC = 5bdcc146bf60754e6a042426089575c7
     *        5a003f089d2739839dec58b964ec3843
     */
    unsigned char mac[32];
    size_t mac_len = 32;
    htpm2_result r;

    r = htpm2_hmac_sha256(ctx, "Jefe", 4,
                          "what do ya want for nothing?", 28,
                          mac, &mac_len);
    CHECK(htpm2_is_ok(r), "hmac should succeed");
    CHECK(mac_len == 32, "mac length should be 32");
    CHECK(hexcmp(mac, "5bdcc146bf60754e6a042426089575c7"
                      "5a003f089d2739839dec58b964ec3843", 32) == 0,
          "HMAC-SHA-256 should match RFC 4231 test case 2");
    htpm2_result_free(&r);
}

static void
test_aes_cfb_roundtrip(htpm2_context ctx)
{
    unsigned char key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    unsigned char plain[32] = "Hello TPM 2.0 encrypted session";
    unsigned char cipher[32];
    unsigned char recovered[32];
    htpm2_result r;

    r = htpm2_aes_cfb_encrypt(ctx, key, 16, iv, 16, plain, 32, cipher);
    CHECK(htpm2_is_ok(r), "AES-CFB encrypt should succeed");
    CHECK(memcmp(cipher, plain, 32) != 0, "ciphertext should differ");

    r = htpm2_aes_cfb_decrypt(ctx, key, 16, iv, 16, cipher, 32, recovered);
    CHECK(htpm2_is_ok(r), "AES-CFB decrypt should succeed");
    CHECK(memcmp(recovered, plain, 32) == 0,
          "decrypted should match plaintext");
    htpm2_result_free(&r);
}

static void
test_kdfa(htpm2_context ctx)
{
    /* Basic KDFa test: derive some bytes and verify they're deterministic */
    unsigned char key[32] = {0};
    unsigned char out1[32], out2[32];
    htpm2_result r;

    memset(key, 0x42, sizeof(key));

    r = htpm2_kdfa(ctx, key, 32, "STORAGE",
                   "nonceTPM", 8, "nonceCaller", 11,
                   256, out1, 32);
    CHECK(htpm2_is_ok(r), "KDFa should succeed");

    r = htpm2_kdfa(ctx, key, 32, "STORAGE",
                   "nonceTPM", 8, "nonceCaller", 11,
                   256, out2, 32);
    CHECK(htpm2_is_ok(r), "KDFa should succeed again");
    CHECK(memcmp(out1, out2, 32) == 0,
          "KDFa should be deterministic");

    /* Different label should produce different output */
    r = htpm2_kdfa(ctx, key, 32, "INTEGRITY",
                   "nonceTPM", 8, "nonceCaller", 11,
                   256, out2, 32);
    CHECK(htpm2_is_ok(r), "KDFa with different label should succeed");
    CHECK(memcmp(out1, out2, 32) != 0,
          "different label should produce different output");
    htpm2_result_free(&r);
}

static void
test_random(htpm2_context ctx)
{
    unsigned char buf1[32] = {0};
    unsigned char buf2[32] = {0};
    htpm2_result r;

    r = htpm2_random_bytes(ctx, buf1, 32);
    CHECK(htpm2_is_ok(r), "random_bytes should succeed");

    r = htpm2_random_bytes(ctx, buf2, 32);
    CHECK(htpm2_is_ok(r), "random_bytes should succeed again");

    /* Probabilistically they should differ */
    CHECK(memcmp(buf1, buf2, 32) != 0,
          "two random buffers should differ (probabilistic)");
    htpm2_result_free(&r);
}

int
main(int argc, char **argv)
{
    htpm2_context ctx = NULL;
    htpm2_result r;

    (void)argc;
    (void)argv;

    r = htpm2_context_init(&ctx);
    if (htpm2_is_err(r)) {
        fprintf(stderr, "FATAL: htpm2_context_init failed: %s\n",
                r.message ? r.message : "(null)");
        htpm2_result_free(&r);
        return 1;
    }

    test_sha256(ctx);
    test_hmac_sha256(ctx);
    test_aes_cfb_roundtrip(ctx);
    test_kdfa(ctx);
    test_random(ctx);

    htpm2_context_free(&ctx);

    if (failures) {
        fprintf(stderr, "%d test(s) FAILED\n", failures);
        return 1;
    }
    printf("All htpm2 crypto tests passed.\n");
    return 0;
}
