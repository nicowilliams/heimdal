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
 * Internal crypto primitives for htpm2.
 * Uses OpenSSL 3.0+ EVP APIs directly.
 */

#include "htpm2_locl.h"
#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

htpm2_result
htpm2_sha256(const htpm2_context ctx,
             const void *data, size_t data_len,
             void *digest)
{
    EVP_MD_CTX *mdctx;
    unsigned int len = 32;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
        return htpm2_result_ossl(1, "SHA-256: failed to create context");

    if (EVP_DigestInit_ex(mdctx, ctx->md_sha256, NULL) != 1 ||
        EVP_DigestUpdate(mdctx, data, data_len) != 1 ||
        EVP_DigestFinal_ex(mdctx, digest, &len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return htpm2_result_ossl(1, "SHA-256: digest computation failed");
    }

    EVP_MD_CTX_free(mdctx);
    return HTPM2_OK;
}

htpm2_result
htpm2_hmac_sha256(const htpm2_context ctx,
                  const void *key, size_t key_len,
                  const void *data, size_t data_len,
                  void *mac, size_t *mac_len)
{
    EVP_MAC *evp_mac = NULL;
    EVP_MAC_CTX *mctx = NULL;
    OSSL_PARAM params[2];
    htpm2_result r = HTPM2_OK;

    (void)ctx;

    evp_mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (evp_mac == NULL) {
        r = htpm2_result_ossl(1, "HMAC-SHA-256: failed to fetch HMAC");
        goto out;
    }

    mctx = EVP_MAC_CTX_new(evp_mac);
    if (mctx == NULL) {
        r = htpm2_result_ossl(1, "HMAC-SHA-256: failed to create context");
        goto out;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                  "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(mctx, key, key_len, params) != 1) {
        r = htpm2_result_ossl(1, "HMAC-SHA-256: init failed");
        goto out;
    }

    if (EVP_MAC_update(mctx, data, data_len) != 1) {
        r = htpm2_result_ossl(1, "HMAC-SHA-256: update failed");
        goto out;
    }

    if (EVP_MAC_final(mctx, mac, mac_len, *mac_len) != 1) {
        r = htpm2_result_ossl(1, "HMAC-SHA-256: final failed");
        goto out;
    }

out:
    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(evp_mac);
    return r;
}

htpm2_result
htpm2_kdfa(const htpm2_context ctx,
           const void *key, size_t key_len,
           const char *label,
           const void *context_u, size_t context_u_len,
           const void *context_v, size_t context_v_len,
           uint32_t bits,
           void *out, size_t out_len)
{
    /*
     * TPM 2.0 KDFa (SP 800-108 counter mode):
     *   for counter = 1 to ceil(bits/256):
     *     HMAC-SHA-256(key, counter || label || 0x00 ||
     *                  contextU || contextV || bits)
     */
    uint32_t counter = 1;
    size_t label_len = label ? strlen(label) : 0;
    size_t done = 0;

    while (done < out_len) {
        unsigned char buf[4 + 256 + 1 + 256 + 256 + 4]; /* worst case */
        unsigned char hmac_out[32];
        size_t hmac_len = 32;
        size_t pos = 0;
        size_t chunk;
        htpm2_result r;

        /* counter (big-endian uint32) */
        buf[pos++] = (counter >> 24) & 0xff;
        buf[pos++] = (counter >> 16) & 0xff;
        buf[pos++] = (counter >> 8) & 0xff;
        buf[pos++] = counter & 0xff;

        /* label || 0x00 */
        if (label_len > 0) {
            memcpy(buf + pos, label, label_len);
            pos += label_len;
        }
        buf[pos++] = 0x00;

        /* contextU */
        if (context_u_len > 0) {
            memcpy(buf + pos, context_u, context_u_len);
            pos += context_u_len;
        }

        /* contextV */
        if (context_v_len > 0) {
            memcpy(buf + pos, context_v, context_v_len);
            pos += context_v_len;
        }

        /* bits (big-endian uint32) */
        buf[pos++] = (bits >> 24) & 0xff;
        buf[pos++] = (bits >> 16) & 0xff;
        buf[pos++] = (bits >> 8) & 0xff;
        buf[pos++] = bits & 0xff;

        r = htpm2_hmac_sha256(ctx, key, key_len, buf, pos,
                              hmac_out, &hmac_len);
        if (htpm2_is_err(r))
            return htpm2_result_prepend(r, "KDFa: HMAC failed at counter %u",
                                        counter);

        chunk = out_len - done;
        if (chunk > 32)
            chunk = 32;
        memcpy((unsigned char *)out + done, hmac_out, chunk);
        done += chunk;
        counter++;
    }
    return HTPM2_OK;
}

htpm2_result
htpm2_aes_cfb_encrypt(const htpm2_context ctx,
                      const void *key, size_t key_len,
                      const void *iv, size_t iv_len,
                      const void *in, size_t in_len,
                      void *out)
{
    EVP_CIPHER_CTX *cctx;
    const EVP_CIPHER *cipher;
    int outl = 0, final_outl = 0;
    htpm2_result r = HTPM2_OK;

    (void)ctx;

    if (key_len == 16)
        cipher = EVP_aes_128_cfb128();
    else if (key_len == 32)
        cipher = EVP_aes_256_cfb128();
    else
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "AES-CFB: unsupported key length %zu",
                                  key_len);

    cctx = EVP_CIPHER_CTX_new();
    if (cctx == NULL)
        return htpm2_result_ossl(1, "AES-CFB encrypt: context alloc failed");

    if (EVP_EncryptInit_ex(cctx, cipher, NULL, key, iv) != 1 ||
        EVP_EncryptUpdate(cctx, out, &outl, in, (int)in_len) != 1 ||
        EVP_EncryptFinal_ex(cctx, (unsigned char *)out + outl,
                            &final_outl) != 1) {
        r = htpm2_result_ossl(1, "AES-CFB encrypt failed");
    }

    EVP_CIPHER_CTX_free(cctx);
    return r;
}

htpm2_result
htpm2_aes_cfb_decrypt(const htpm2_context ctx,
                      const void *key, size_t key_len,
                      const void *iv, size_t iv_len,
                      const void *in, size_t in_len,
                      void *out)
{
    EVP_CIPHER_CTX *cctx;
    const EVP_CIPHER *cipher;
    int outl = 0, final_outl = 0;
    htpm2_result r = HTPM2_OK;

    (void)ctx;
    (void)iv_len;

    if (key_len == 16)
        cipher = EVP_aes_128_cfb128();
    else if (key_len == 32)
        cipher = EVP_aes_256_cfb128();
    else
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "AES-CFB: unsupported key length %zu",
                                  key_len);

    cctx = EVP_CIPHER_CTX_new();
    if (cctx == NULL)
        return htpm2_result_ossl(1, "AES-CFB decrypt: context alloc failed");

    if (EVP_DecryptInit_ex(cctx, cipher, NULL, key, iv) != 1 ||
        EVP_DecryptUpdate(cctx, out, &outl, in, (int)in_len) != 1 ||
        EVP_DecryptFinal_ex(cctx, (unsigned char *)out + outl,
                            &final_outl) != 1) {
        r = htpm2_result_ossl(1, "AES-CFB decrypt failed");
    }

    EVP_CIPHER_CTX_free(cctx);
    return r;
}

htpm2_result
htpm2_random_bytes(const htpm2_context ctx, void *buf, size_t len)
{
    (void)ctx;
    if (RAND_bytes(buf, (int)len) != 1)
        return htpm2_result_ossl(1, "RAND_bytes failed");
    return HTPM2_OK;
}

htpm2_result
htpm2_rsa_oaep_encrypt(const htpm2_context ctx,
                       const void *rsa_modulus, size_t rsa_modulus_len,
                       uint32_t exponent,
                       const char *label, size_t label_len,
                       const void *plaintext, size_t plaintext_len,
                       void **ciphertext, size_t *ciphertext_len)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *kctx = NULL, *ectx = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *n = NULL, *e = NULL;
    unsigned char *label_copy = NULL;
    size_t outlen;
    void *out = NULL;
    htpm2_result r = HTPM2_OK;

    (void)ctx;

    *ciphertext = NULL;
    *ciphertext_len = 0;

    if (exponent == 0)
        exponent = 65537;

    n = BN_bin2bn(rsa_modulus, rsa_modulus_len, NULL);
    e = BN_new();
    if (n == NULL || e == NULL || !BN_set_word(e, exponent)) {
        r = htpm2_result_ossl(1, "RSA-OAEP: BN setup");
        goto out;
    }

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e)) {
        r = htpm2_result_ossl(1, "RSA-OAEP: param build");
        goto out;
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL) {
        r = htpm2_result_ossl(1, "RSA-OAEP: to_param");
        goto out;
    }

    kctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (kctx == NULL ||
        EVP_PKEY_fromdata_init(kctx) != 1 ||
        EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        r = htpm2_result_ossl(1, "RSA-OAEP: fromdata");
        goto out;
    }

    /* Encrypt */
    ectx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ectx == NULL ||
        EVP_PKEY_encrypt_init(ectx) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(ectx, RSA_PKCS1_OAEP_PADDING) != 1 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ectx, EVP_sha256()) != 1) {
        r = htpm2_result_ossl(1, "RSA-OAEP: encrypt init");
        goto out;
    }

    /* Set label (OpenSSL takes ownership of this copy) */
    if (label && label_len > 0) {
        label_copy = OPENSSL_memdup(label, label_len);
        if (label_copy == NULL) {
            r = htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                   "RSA-OAEP: label alloc");
            goto out;
        }
        if (EVP_PKEY_CTX_set0_rsa_oaep_label(ectx, label_copy,
                                              label_len) != 1) {
            OPENSSL_free(label_copy);
            r = htpm2_result_ossl(1, "RSA-OAEP: set label");
            goto out;
        }
        label_copy = NULL;  /* ownership transferred */
    }

    if (EVP_PKEY_encrypt(ectx, NULL, &outlen, plaintext, plaintext_len) != 1) {
        r = htpm2_result_ossl(1, "RSA-OAEP: size query");
        goto out;
    }

    out = malloc(outlen);
    if (out == NULL) {
        r = htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                               "RSA-OAEP: alloc output");
        goto out;
    }

    if (EVP_PKEY_encrypt(ectx, out, &outlen, plaintext, plaintext_len) != 1) {
        free(out);
        out = NULL;
        r = htpm2_result_ossl(1, "RSA-OAEP: encrypt");
        goto out;
    }

    *ciphertext = out;
    *ciphertext_len = outlen;
    out = NULL;

out:
    BN_free(n);
    BN_free(e);
    OSSL_PARAM_BLD_free(bld);
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_free(pkey);
    return r;
}

htpm2_result
htpm2_derive_param_key(const htpm2_context ctx,
                       const uint8_t *session_key, size_t session_key_len,
                       const uint8_t *nonce_newer, size_t nonce_newer_len,
                       const uint8_t *nonce_older, size_t nonce_older_len,
                       uint16_t key_bits,
                       uint8_t *enc_key, size_t enc_key_len,
                       uint8_t *iv, size_t iv_len)
{
    htpm2_result r;

    /* Encryption key: KDFa(sessionKey, "CFB", nonceNewer, nonceOlder, keyBits) */
    r = htpm2_kdfa(ctx, session_key, session_key_len, "CFB",
                   nonce_newer, nonce_newer_len,
                   nonce_older, nonce_older_len,
                   key_bits, enc_key, enc_key_len);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "derive param key");

    /* IV: KDFa(sessionKey, "CFB", nonceOlder, nonceNewer, 128) */
    r = htpm2_kdfa(ctx, session_key, session_key_len, "CFB",
                   nonce_older, nonce_older_len,
                   nonce_newer, nonce_newer_len,
                   128, iv, iv_len);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "derive param IV");

    return HTPM2_OK;
}
