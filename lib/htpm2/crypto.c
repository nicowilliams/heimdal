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
