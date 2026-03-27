/*
 * Internal crypto primitives for htpm2.
 * Uses OpenSSL 3.0+ libcrypto directly.
 */

#ifndef __htpm2_crypto_h__
#define __htpm2_crypto_h__

#include <stdint.h>
#include <stddef.h>

#include "htpm2.h"

/* SHA-256 hash */
htpm2_result htpm2_sha256(const htpm2_context ctx,
                          const void *data, size_t data_len,
                          void *digest);  /* 32 bytes output */

/* HMAC-SHA-256 */
htpm2_result htpm2_hmac_sha256(const htpm2_context ctx,
                               const void *key, size_t key_len,
                               const void *data, size_t data_len,
                               void *mac, size_t *mac_len);  /* up to 32 bytes */

/* TPM 2.0 KDFa (SP 800-108 counter-mode HMAC-KDF) */
htpm2_result htpm2_kdfa(const htpm2_context ctx,
                        const void *key, size_t key_len,
                        const char *label,
                        const void *context_u, size_t context_u_len,
                        const void *context_v, size_t context_v_len,
                        uint32_t bits,
                        void *out, size_t out_len);

/* AES-CFB encrypt/decrypt */
htpm2_result htpm2_aes_cfb_encrypt(const htpm2_context ctx,
                                   const void *key, size_t key_len,
                                   const void *iv, size_t iv_len,
                                   const void *in, size_t in_len,
                                   void *out);
htpm2_result htpm2_aes_cfb_decrypt(const htpm2_context ctx,
                                   const void *key, size_t key_len,
                                   const void *iv, size_t iv_len,
                                   const void *in, size_t in_len,
                                   void *out);

/* Random bytes */
htpm2_result htpm2_random_bytes(const htpm2_context ctx,
                                void *buf, size_t len);

/*
 * RSA-OAEP encrypt with SHA-256 and a caller-specified label.
 * `rsa_pub` is a raw RSA modulus, `rsa_pub_len` is its length.
 * `exponent` is the public exponent (use 0 for default 65537).
 * Returns allocated ciphertext; caller frees with free().
 */
htpm2_result htpm2_rsa_oaep_encrypt(const htpm2_context ctx,
                                    const void *rsa_modulus,
                                    size_t rsa_modulus_len,
                                    uint32_t exponent,
                                    const char *label, size_t label_len,
                                    const void *plaintext,
                                    size_t plaintext_len,
                                    void **ciphertext,
                                    size_t *ciphertext_len);

/*
 * Derive parameter encryption key and IV from session key + nonces.
 *
 * For AES-128-CFB:
 *   key = KDFa(sessionKey, "CFB", nonceCaller || nonceTPM, 128)
 *   iv  = KDFa(sessionKey, "CFB", nonceTPM || nonceCaller, 128)
 *
 * Note: for command encryption, nonceNewer=nonceCaller, nonceOlder=nonceTPM.
 *       for response decryption, nonceNewer=nonceTPM, nonceOlder=nonceCaller.
 */
htpm2_result htpm2_derive_param_key(const htpm2_context ctx,
                                    const uint8_t *session_key,
                                    size_t session_key_len,
                                    const uint8_t *nonce_newer,
                                    size_t nonce_newer_len,
                                    const uint8_t *nonce_older,
                                    size_t nonce_older_len,
                                    uint16_t key_bits,
                                    uint8_t *enc_key, size_t enc_key_len,
                                    uint8_t *iv, size_t iv_len);

#endif /* __htpm2_crypto_h__ */
