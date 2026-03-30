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
 * ECC session salting: generate ephemeral key, compute ECDH shared secret,
 * derive salt, and encode the ephemeral public point for encryptedSalt.
 *
 * `peer_x`/`peer_y` are the salt key's public point coordinates.
 * Returns: salt (32 bytes), and the ephemeral public point encoded
 * as TPM2B_ECC_POINT for the encryptedSalt field.
 */
htpm2_result htpm2_ecc_salt(const htpm2_context ctx,
                            int nid,  /* OpenSSL NID for the curve */
                            const void *peer_x, size_t peer_x_len,
                            const void *peer_y, size_t peer_y_len,
                            const void *salt_key_x, size_t salt_key_x_len,
                            uint8_t salt[32],
                            void **encrypted_salt,
                            size_t *encrypted_salt_len);

/*
 * KDFe (ECDH key derivation per TPM 2.0 spec).
 * KDFe(hashAlg, Z, label, partyU, partyV, bits)
 * Uses HMAC counter-mode with an empty key for the first HMAC.
 * Actually KDFe is a simple hash-based KDF, not HMAC:
 *   for i = 1..:
 *     K(i) = Hash(counter || Z || label || 0x00 || partyU || partyV)
 */
htpm2_result htpm2_kdfe(const htpm2_context ctx,
                        const void *z, size_t z_len,
                        const char *label,
                        const void *party_u, size_t party_u_len,
                        const void *party_v, size_t party_v_len,
                        uint32_t bits,
                        void *out, size_t out_len);

/*
 * RSA OAEP encryption (for session salting).
 * `rsa_modulus` is a raw RSA modulus, `rsa_modulus_len` is its length.
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
