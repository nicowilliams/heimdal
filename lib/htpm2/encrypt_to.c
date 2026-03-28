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
 * EncryptTo -- encrypt data to a target TPM with key splitting.
 *
 * Encrypts plaintext under a random AES-256 key, then splits the key
 * into 1-3 shares, each wrapped via MakeCredential to the target's EK
 * bound to a different key name:
 *
 *   Share 1 (required): well-known key name
 *     This key has a policy attached, so activating this credential
 *     forces the caller to satisfy that policy (e.g., PCR values).
 *     This is the mechanism for enforcing boot integrity.
 *
 *   Share 2 (optional): IAK (Initial Attestation Key) name
 *     Binds the encrypted data to a specific TPM identity.  Not all
 *     hosts have IAK certificates; this share is omitted when the
 *     IAK is unknown.
 *
 *   Share 3 (optional): Owner hierarchy key name
 *     Enables decommissioning: changing the owner hierarchy seed
 *     invalidates this key, making the data unrecoverable.
 *
 * Splitting uses XOR:
 *   1 share:  K1 = K
 *   2 shares: K1 = random, K2 = K ^ K1
 *   3 shares: K1 = random, K2 = random, K3 = K ^ K1 ^ K2
 *
 * The recipient must ActivateCredential for each share, XOR them
 * together to recover K, then decrypt the ciphertext.
 *
 * The ciphertext format is:
 *   iv (16 bytes) || AES-256-CBC ciphertext (PKCS7 padded)
 *
 * This is a software-only operation -- no TPM round-trip needed.
 */

#include "htpm2_locl.h"
#include "marshal.h"
#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

/*
 * AES-256-CBC encrypt with random IV and PKCS7 padding.
 * Output: iv (16 bytes) || ciphertext
 */
static htpm2_result
aes256_cbc_encrypt(const htpm2_context ctx,
                   const uint8_t key[32],
                   const void *plaintext, size_t plaintext_len,
                   void **out, size_t *out_len)
{
    EVP_CIPHER_CTX *cctx;
    uint8_t iv[16];
    uint8_t *buf;
    int outl = 0, final_outl = 0;
    size_t max_ct_len;
    htpm2_result r;

    r = htpm2_random_bytes(ctx, iv, 16);
    if (htpm2_is_err(r))
        return r;

    /* Max ciphertext = plaintext + one block of padding */
    max_ct_len = plaintext_len + 16;
    buf = malloc(16 + max_ct_len);  /* iv + ciphertext */
    if (buf == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "EncryptTo: alloc ciphertext");

    memcpy(buf, iv, 16);

    cctx = EVP_CIPHER_CTX_new();
    if (cctx == NULL) {
        free(buf);
        return htpm2_result_ossl(1, "EncryptTo: cipher ctx");
    }

    if (EVP_EncryptInit_ex(cctx, EVP_aes_256_cbc(), NULL, key, iv) != 1 ||
        EVP_EncryptUpdate(cctx, buf + 16, &outl,
                          plaintext, (int)plaintext_len) != 1 ||
        EVP_EncryptFinal_ex(cctx, buf + 16 + outl, &final_outl) != 1) {
        EVP_CIPHER_CTX_free(cctx);
        free(buf);
        return htpm2_result_ossl(1, "EncryptTo: encrypt");
    }

    EVP_CIPHER_CTX_free(cctx);

    *out = buf;
    *out_len = 16 + outl + final_outl;
    return HTPM2_OK;
}

/*
 * AES-256-CBC decrypt.  Input: iv (16 bytes) || ciphertext.
 */
static htpm2_result
aes256_cbc_decrypt(const uint8_t key[32],
                   const void *in, size_t in_len,
                   void **out, size_t *out_len)
{
    EVP_CIPHER_CTX *cctx;
    const uint8_t *iv;
    const uint8_t *ct;
    size_t ct_len;
    uint8_t *buf;
    int outl = 0, final_outl = 0;

    if (in_len < 16 + 1)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "DecryptFrom: ciphertext too short");

    iv = in;
    ct = (const uint8_t *)in + 16;
    ct_len = in_len - 16;

    buf = malloc(ct_len);
    if (buf == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "DecryptFrom: alloc");

    cctx = EVP_CIPHER_CTX_new();
    if (cctx == NULL) {
        free(buf);
        return htpm2_result_ossl(1, "DecryptFrom: cipher ctx");
    }

    if (EVP_DecryptInit_ex(cctx, EVP_aes_256_cbc(), NULL, key, iv) != 1 ||
        EVP_DecryptUpdate(cctx, buf, &outl, ct, (int)ct_len) != 1 ||
        EVP_DecryptFinal_ex(cctx, buf + outl, &final_outl) != 1) {
        EVP_CIPHER_CTX_free(cctx);
        free(buf);
        return htpm2_result_ossl(1, "DecryptFrom: decrypt");
    }

    EVP_CIPHER_CTX_free(cctx);

    *out = buf;
    *out_len = outl + final_outl;
    return HTPM2_OK;
}

/*
 * Construct the well-known key's TPMT_PUBLIC and compute its Name.
 *
 * The well-known key is a fixed HMAC key template whose only varying
 * part is the authPolicy.  Its purpose is to be a vehicle for the
 * policy: whoever activates this credential must satisfy the policy.
 *
 * The key template is:
 *   type = KEYEDHASH
 *   nameAlg = SHA-256
 *   objectAttributes = userWithAuth | sign | fixedTPM | fixedParent
 *   authPolicy = <the caller's policy>
 *   scheme = HMAC-SHA-256
 *   unique = empty (32 zero bytes -- deterministic, "well-known")
 *
 * Name = 0x000B || SHA-256(TPMT_PUBLIC)
 *   (0x000B is the uint16 for TPM2_ALG_SHA256)
 */
static htpm2_result
make_well_known_key_name(const htpm2_context ctx,
                         const void *policy, size_t policy_len,
                         uint8_t *name, size_t *name_len)
{
    heim_storage *sp;
    void *pub_bytes = NULL;
    size_t pub_bytes_len = 0;
    uint8_t digest[32];
    htpm2_result r;
    int ret;

    sp = heim_storage_emem();
    if (sp == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "well-known key: alloc");

    /* type = KEYEDHASH */
    ret = heim_store_uint16(sp, TPM2_ALG_KEYEDHASH);
    if (ret) goto err;

    /* nameAlg = SHA-256 */
    ret = heim_store_uint16(sp, TPM2_ALG_SHA256);
    if (ret) goto err;

    /* objectAttributes:
     *   fixedTPM(1) | fixedParent(4) | userWithAuth(6) | sign(18)
     */
    ret = heim_store_uint32(sp, (1U << 1) | (1U << 4) | (1U << 6) | (1U << 18));
    if (ret) goto err;

    /* authPolicy (TPM2B_DIGEST) */
    ret = htpm2_marshal_tpm2b(sp, policy, policy_len);
    if (ret) goto err;

    /* TPMS_KEYEDHASH_PARMS: scheme = HMAC */
    ret = heim_store_uint16(sp, TPM2_ALG_HMAC);  /* scheme */
    if (ret) goto err;
    ret = heim_store_uint16(sp, TPM2_ALG_SHA256); /* hashAlg */
    if (ret) goto err;

    /* unique (TPM2B) = 32 zero bytes (deterministic, "well-known") */
    {
        uint8_t zeros[32];
        memset(zeros, 0, sizeof(zeros));
        ret = htpm2_marshal_tpm2b(sp, zeros, 32);
    }
    if (ret) goto err;

    ret = heim_storage_to_data(sp, &pub_bytes, &pub_bytes_len);
    heim_storage_free(sp);
    sp = NULL;
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "well-known key: to_data");

    /* Name = 0x000B || SHA-256(TPMT_PUBLIC) */
    r = htpm2_sha256(ctx, pub_bytes, pub_bytes_len, digest);
    free(pub_bytes);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "well-known key: hash");

    name[0] = 0x00;
    name[1] = 0x0B;  /* TPM2_ALG_SHA256 */
    memcpy(name + 2, digest, 32);
    *name_len = 34;
    return HTPM2_OK;

err:
    heim_storage_free(sp);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "well-known key: marshal");
}

htpm2_result
htpm2_encrypt_to(const htpm2_context ctx,
                 const void *plaintext, size_t plaintext_len,
                 const void *ek_pub, size_t ek_pub_len,
                 const void *policy, size_t policy_len,
                 const void *iak_name, size_t iak_name_len,
                 const void *owner_name, size_t owner_name_len,
                 htpm2_encrypt_to_result *result)
{
    uint8_t key[32];           /* AES-256 key */
    uint8_t shares[3][32];     /* up to 3 XOR shares */
    uint8_t wk_name[34];       /* well-known key Name */
    size_t wk_name_len = 0;
    size_t num_shares;
    htpm2_result r;
    size_t i;

    memset(result, 0, sizeof(*result));

    if (policy == NULL || policy_len == 0)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "EncryptTo: policy is required");

    /* Compute well-known key Name from the policy */
    r = make_well_known_key_name(ctx, policy, policy_len,
                                 wk_name, &wk_name_len);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "EncryptTo");

    /* Determine number of shares */
    num_shares = 1;
    if (iak_name && iak_name_len > 0)
        num_shares++;
    if (owner_name && owner_name_len > 0)
        num_shares++;

    /* Generate random AES-256 key */
    r = htpm2_random_bytes(ctx, key, 32);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "EncryptTo: generate key");

    /* Encrypt plaintext */
    r = aes256_cbc_encrypt(ctx, key, plaintext, plaintext_len,
                           &result->ciphertext, &result->ciphertext_len);
    if (htpm2_is_err(r)) {
        memset(key, 0, sizeof(key));
        return r;
    }

    /* Split key into shares */
    if (num_shares == 1) {
        memcpy(shares[0], key, 32);
    } else if (num_shares == 2) {
        r = htpm2_random_bytes(ctx, shares[0], 32);
        if (htpm2_is_err(r)) goto fail;
        for (i = 0; i < 32; i++)
            shares[1][i] = key[i] ^ shares[0][i];
    } else {
        r = htpm2_random_bytes(ctx, shares[0], 32);
        if (htpm2_is_err(r)) goto fail;
        r = htpm2_random_bytes(ctx, shares[1], 32);
        if (htpm2_is_err(r)) goto fail;
        for (i = 0; i < 32; i++)
            shares[2][i] = key[i] ^ shares[0][i] ^ shares[1][i];
    }
    memset(key, 0, sizeof(key));

    /* MakeCredential for each share */

    /* Share 0: well-known key (always -- Name computed from policy) */
    r = htpm2_make_credential(ctx, ek_pub, ek_pub_len,
                              shares[0], 32,
                              wk_name, 34,
                              &result->wk_credential_blob,
                              &result->wk_credential_blob_len,
                              &result->wk_encrypted_secret,
                              &result->wk_encrypted_secret_len);
    if (htpm2_is_err(r)) goto fail;

    /* Share 1: IAK (optional) */
    if (iak_name && iak_name_len > 0) {
        r = htpm2_make_credential(ctx, ek_pub, ek_pub_len,
                                  shares[1], 32,
                                  iak_name, iak_name_len,
                                  &result->iak_credential_blob,
                                  &result->iak_credential_blob_len,
                                  &result->iak_encrypted_secret,
                                  &result->iak_encrypted_secret_len);
        if (htpm2_is_err(r)) goto fail;
    }

    /* Share 2: Owner hierarchy key (optional) */
    if (owner_name && owner_name_len > 0) {
        size_t owner_share_idx = (iak_name && iak_name_len > 0) ? 2 : 1;
        r = htpm2_make_credential(ctx, ek_pub, ek_pub_len,
                                  shares[owner_share_idx], 32,
                                  owner_name, owner_name_len,
                                  &result->owner_credential_blob,
                                  &result->owner_credential_blob_len,
                                  &result->owner_encrypted_secret,
                                  &result->owner_encrypted_secret_len);
        if (htpm2_is_err(r)) goto fail;
    }

    result->num_shares = num_shares;
    memset(shares, 0, sizeof(shares));
    return HTPM2_OK;

fail:
    memset(key, 0, sizeof(key));
    memset(shares, 0, sizeof(shares));
    htpm2_encrypt_to_result_free(result);
    return r;
}

void
htpm2_encrypt_to_result_free(htpm2_encrypt_to_result *result)
{
    if (result == NULL)
        return;
    free(result->ciphertext);
    free(result->wk_credential_blob);
    free(result->wk_encrypted_secret);
    free(result->iak_credential_blob);
    free(result->iak_encrypted_secret);
    free(result->owner_credential_blob);
    free(result->owner_encrypted_secret);
    memset(result, 0, sizeof(*result));
}

/*
 * DecryptFrom -- recover plaintext from an EncryptTo envelope.
 *
 * The caller has already ActivateCredential'd each share and passes
 * the recovered shares.  This function XORs them together to recover
 * the AES-256 key and decrypts the ciphertext.
 *
 * shares[0] is always the well-known key share.
 * shares[1] is the IAK share (if present).
 * shares[2] is the owner share (if present).
 */
htpm2_result
htpm2_decrypt_from(const htpm2_context ctx,
                   const void *ciphertext, size_t ciphertext_len,
                   const void **shares, const size_t *share_lens,
                   size_t num_shares,
                   void **plaintext, size_t *plaintext_len)
{
    uint8_t key[32];
    size_t i;

    (void)ctx;

    *plaintext = NULL;
    *plaintext_len = 0;

    if (num_shares < 1 || num_shares > 3)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "DecryptFrom: need 1-3 shares, got %zu",
                                  num_shares);

    for (i = 0; i < num_shares; i++) {
        if (share_lens[i] != 32)
            return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                      "DecryptFrom: share %zu is %zu bytes, "
                                      "expected 32", i, share_lens[i]);
    }

    /* Reconstruct key by XORing shares */
    memcpy(key, shares[0], 32);
    for (i = 1; i < num_shares; i++) {
        const uint8_t *s = shares[i];
        size_t j;
        for (j = 0; j < 32; j++)
            key[j] ^= s[j];
    }

    htpm2_result r = aes256_cbc_decrypt(key, ciphertext, ciphertext_len,
                                         plaintext, plaintext_len);
    memset(key, 0, sizeof(key));
    return r;
}

/*
 * Activate one credential share via the TPM.
 */
static htpm2_result
activate_share(const htpm2_context ctx,
               htpm2_transport tp,
               htpm2_object ek,
               htpm2_session auth_session_ek,
               htpm2_object key,
               const void *credential_blob, size_t credential_blob_len,
               const void *encrypted_secret, size_t encrypted_secret_len,
               uint8_t share_out[32])
{
    void *cred = NULL;
    size_t cred_len = 0;
    htpm2_result r;

    r = htpm2_activate_credential(ctx, tp, HTPM2_OK,
                                  NULL, /* AK auth -- password for now */
                                  auth_session_ek,
                                  key, ek,
                                  credential_blob, credential_blob_len,
                                  encrypted_secret, encrypted_secret_len,
                                  &cred, &cred_len);
    if (htpm2_is_err(r))
        return r;

    if (cred_len != 32) {
        free(cred);
        return htpm2_result_local(ERANGE, HTPM2_F_LOCAL, ERANGE,
                                  "ActivateCredential: expected 32-byte share, "
                                  "got %zu", cred_len);
    }

    memcpy(share_out, cred, 32);
    free(cred);
    return HTPM2_OK;
}

htpm2_result
htpm2_decrypt_from_tpm(const htpm2_context ctx,
                       htpm2_transport tp,
                       htpm2_result prior,
                       htpm2_object ek,
                       htpm2_session auth_session_ek,
                       htpm2_object wk_key,
                       const void *wk_cred_blob, size_t wk_cred_blob_len,
                       const void *wk_enc_secret, size_t wk_enc_secret_len,
                       htpm2_object iak_key,
                       const void *iak_cred_blob, size_t iak_cred_blob_len,
                       const void *iak_enc_secret, size_t iak_enc_secret_len,
                       htpm2_object owner_key,
                       const void *owner_cred_blob, size_t owner_cred_blob_len,
                       const void *owner_enc_secret, size_t owner_enc_secret_len,
                       const void *ciphertext, size_t ciphertext_len,
                       void **plaintext, size_t *plaintext_len)
{
    uint8_t shares[3][32];
    const void *share_ptrs[3];
    size_t share_lens[3];
    size_t num_shares = 0;
    htpm2_result r;

    if (prior.code)
        return prior;

    *plaintext = NULL;
    *plaintext_len = 0;

    /* Share 0: well-known key (always required) */
    r = activate_share(ctx, tp, ek, auth_session_ek, wk_key,
                       wk_cred_blob, wk_cred_blob_len,
                       wk_enc_secret, wk_enc_secret_len,
                       shares[0]);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "DecryptFromTPM: wk share");
    share_ptrs[0] = shares[0];
    share_lens[0] = 32;
    num_shares = 1;

    /* Share 1: IAK (optional) */
    if (iak_key != NULL && iak_cred_blob != NULL) {
        r = activate_share(ctx, tp, ek, auth_session_ek, iak_key,
                           iak_cred_blob, iak_cred_blob_len,
                           iak_enc_secret, iak_enc_secret_len,
                           shares[1]);
        if (htpm2_is_err(r)) {
            memset(shares, 0, sizeof(shares));
            return htpm2_result_prepend(r, "DecryptFromTPM: iak share");
        }
        share_ptrs[num_shares] = shares[1];
        share_lens[num_shares] = 32;
        num_shares++;
    }

    /* Share 2: Owner hierarchy key (optional) */
    if (owner_key != NULL && owner_cred_blob != NULL) {
        size_t idx = num_shares;
        r = activate_share(ctx, tp, ek, auth_session_ek, owner_key,
                           owner_cred_blob, owner_cred_blob_len,
                           owner_enc_secret, owner_enc_secret_len,
                           shares[idx]);
        if (htpm2_is_err(r)) {
            memset(shares, 0, sizeof(shares));
            return htpm2_result_prepend(r, "DecryptFromTPM: owner share");
        }
        share_ptrs[num_shares] = shares[idx];
        share_lens[num_shares] = 32;
        num_shares++;
    }

    /* Reconstruct key and decrypt */
    r = htpm2_decrypt_from(ctx, ciphertext, ciphertext_len,
                           share_ptrs, share_lens, num_shares,
                           plaintext, plaintext_len);

    memset(shares, 0, sizeof(shares));
    return r;
}
