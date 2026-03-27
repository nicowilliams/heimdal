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
 * Software-only TPM operations.
 *
 * TPM2_MakeCredential -- implemented in software using libcrypto directly.
 * No TPM round-trip needed; this is the "challenger" side of the
 * attestation protocol.
 *
 * The algorithm (from TCG TPM 2.0 Part 1, Section 24):
 *   1. Generate random seed (32 bytes)
 *   2. encryptedSecret = RSA-OAEP-encrypt(EK_pub, seed, label="IDENTITY\0")
 *   3. symKey = KDFa(SHA256, seed, "STORAGE", name, NULL, 128)
 *   4. encIdentity = AES-128-CFB-encrypt(symKey, iv=0, credential)
 *   5. hmacKey = KDFa(SHA256, seed, "INTEGRITY", NULL, NULL, 256)
 *   6. outerHMAC = HMAC-SHA256(hmacKey, encIdentity || name)
 *   7. credentialBlob = TPM2B(outerHMAC || encIdentity)
 *   8. Return credentialBlob, encryptedSecret
 */

#include "htpm2_locl.h"
#include "marshal.h"
#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

/*
 * Parse a TPM2B_PUBLIC for an RSA key and extract the modulus and exponent.
 * The TPM2B_PUBLIC contains a TPMT_PUBLIC:
 *   type(2) + nameAlg(2) + attrs(4) + authPolicy(TPM2B) +
 *   [RSA params: sym(varies) + scheme(varies) + keyBits(2) + exponent(4)] +
 *   unique(TPM2B = modulus)
 *
 * This is simplified: we scan for the RSA unique field at the end.
 * For a proper implementation we'd fully parse TPMT_PUBLIC.
 *
 * Returns an EVP_PKEY with the RSA public key.
 */
static htpm2_result
parse_ek_rsa_pubkey(const void *ek_pub, size_t ek_pub_len, EVP_PKEY **pkey)
{
    /*
     * Simplified approach: the RSA modulus is in the last TPM2B of the
     * TPMT_PUBLIC structure.  We parse backwards to find it.
     *
     * Actually, let's parse forward properly enough to find the unique field.
     * TPMT_PUBLIC for RSA:
     *   type:       uint16 = 0x0001 (TPM2_ALG_RSA)
     *   nameAlg:    uint16
     *   attrs:      uint32
     *   authPolicy: TPM2B (uint16 size + data)
     *   symmetric:  TPMT_SYM_DEF_OBJECT (alg uint16 [+ keyBits uint16 + mode uint16 if not NULL])
     *   scheme:     TPMT_RSA_SCHEME (alg uint16 [+ hashAlg uint16 if not NULL])
     *   keyBits:    uint16
     *   exponent:   uint32
     *   unique:     TPM2B (uint16 size + modulus bytes)
     */
    heim_storage *sp;
    uint16_t type, name_alg, auth_size, sym_alg, scheme_alg, key_bits;
    uint32_t attrs, exponent;
    void *modulus = NULL;
    uint16_t mod_size;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    BIGNUM *n = NULL, *e = NULL;
    htpm2_result r;
    int ret;

    *pkey = NULL;

    sp = heim_storage_from_readonly_mem(ek_pub, ek_pub_len);
    if (sp == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "MakeCredential: alloc storage");

    ret = heim_ret_uint16(sp, &type);
    if (ret || type != 0x0001) { /* TPM2_ALG_RSA */
        heim_storage_free(sp);
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "MakeCredential: EK is not RSA (type=0x%04x)",
                                  type);
    }

    heim_ret_uint16(sp, &name_alg);     /* nameAlg */
    heim_ret_uint32(sp, &attrs);         /* objectAttributes */

    /* authPolicy (TPM2B) -- skip */
    heim_ret_uint16(sp, &auth_size);
    if (auth_size > 0)
        heim_storage_seek(sp, auth_size, SEEK_CUR);

    /* symmetric (TPMT_SYM_DEF_OBJECT) */
    heim_ret_uint16(sp, &sym_alg);
    if (sym_alg != 0x0010) { /* TPM2_ALG_NULL */
        uint16_t dummy;
        heim_ret_uint16(sp, &dummy); /* keyBits */
        heim_ret_uint16(sp, &dummy); /* mode */
    }

    /* scheme (TPMT_RSA_SCHEME) */
    heim_ret_uint16(sp, &scheme_alg);
    if (scheme_alg != 0x0010) { /* TPM2_ALG_NULL */
        uint16_t dummy;
        heim_ret_uint16(sp, &dummy); /* hashAlg */
    }

    /* keyBits, exponent */
    heim_ret_uint16(sp, &key_bits);
    heim_ret_uint32(sp, &exponent);
    if (exponent == 0)
        exponent = 65537;

    /* unique (TPM2B = modulus) */
    ret = htpm2_unmarshal_tpm2b(sp, &modulus, &mod_size);
    heim_storage_free(sp);
    if (ret || modulus == NULL)
        return htpm2_result_local(ret ? ret : EINVAL, HTPM2_F_MARSHAL,
                                  ret ? ret : EINVAL,
                                  "MakeCredential: parse RSA modulus");

    /* Build EVP_PKEY from modulus + exponent */
    n = BN_bin2bn(modulus, mod_size, NULL);
    e = BN_new();
    if (n == NULL || e == NULL || !BN_set_word(e, exponent)) {
        r = htpm2_result_ossl(1, "MakeCredential: BN setup");
        goto out;
    }

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e)) {
        r = htpm2_result_ossl(1, "MakeCredential: param build");
        goto out;
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL) {
        r = htpm2_result_ossl(1, "MakeCredential: to_param");
        goto out;
    }

    pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (pctx == NULL ||
        EVP_PKEY_fromdata_init(pctx) != 1 ||
        EVP_PKEY_fromdata(pctx, pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        r = htpm2_result_ossl(1, "MakeCredential: fromdata");
        goto out;
    }

    r = HTPM2_OK;

out:
    free(modulus);
    BN_free(n);
    BN_free(e);
    OSSL_PARAM_BLD_free(bld);
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(pctx);
    return r;
}

/*
 * RSA-OAEP encrypt with SHA-256 and label "IDENTITY\0".
 */
static htpm2_result
rsa_oaep_encrypt(EVP_PKEY *pkey,
                 const void *plaintext, size_t plaintext_len,
                 void **ciphertext, size_t *ciphertext_len)
{
    EVP_PKEY_CTX *ctx;
    unsigned char *label;
    size_t outlen;
    void *out;
    htpm2_result r = HTPM2_OK;

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL)
        return htpm2_result_ossl(1, "OAEP: ctx_new");

    if (EVP_PKEY_encrypt_init(ctx) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != 1 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) != 1) {
        r = htpm2_result_ossl(1, "OAEP: init");
        goto out;
    }

    /* Set OAEP label = "IDENTITY\0" (9 bytes including NUL) */
    label = OPENSSL_memdup("IDENTITY", 9);
    if (label == NULL) {
        r = htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM, "OAEP: label");
        goto out;
    }
    if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, label, 9) != 1) {
        OPENSSL_free(label);
        r = htpm2_result_ossl(1, "OAEP: set label");
        goto out;
    }

    /* Determine output size */
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, plaintext, plaintext_len) != 1) {
        r = htpm2_result_ossl(1, "OAEP: size query");
        goto out;
    }

    out = malloc(outlen);
    if (out == NULL) {
        r = htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM, "OAEP: alloc");
        goto out;
    }

    if (EVP_PKEY_encrypt(ctx, out, &outlen, plaintext, plaintext_len) != 1) {
        free(out);
        r = htpm2_result_ossl(1, "OAEP: encrypt");
        goto out;
    }

    *ciphertext = out;
    *ciphertext_len = outlen;

out:
    EVP_PKEY_CTX_free(ctx);
    return r;
}

htpm2_result
htpm2_make_credential(const htpm2_context ctx,
                      const void *ek_pub,
                      size_t ek_pub_len,
                      const void *credential,
                      size_t credential_len,
                      const void *key_name,
                      size_t key_name_len,
                      void **credential_blob,
                      size_t *credential_blob_len,
                      void **encrypted_secret,
                      size_t *encrypted_secret_len)
{
    EVP_PKEY *ek_pkey = NULL;
    uint8_t seed[32];
    uint8_t sym_key[16];  /* AES-128 */
    uint8_t hmac_key[32];
    uint8_t iv[16];
    uint8_t *enc_identity = NULL;
    uint8_t hmac_out[32];
    size_t hmac_len = 32;
    void *enc_secret = NULL;
    size_t enc_secret_len = 0;
    heim_storage *blob_sp;
    htpm2_result r;
    int ret;

    *credential_blob = NULL;
    *credential_blob_len = 0;
    *encrypted_secret = NULL;
    *encrypted_secret_len = 0;

    /* Step 1: Parse EK public key */
    r = parse_ek_rsa_pubkey(ek_pub, ek_pub_len, &ek_pkey);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "MakeCredential");

    /* Step 2: Generate random seed */
    r = htpm2_random_bytes(ctx, seed, 32);
    if (htpm2_is_err(r))
        goto out;

    /* Step 3: RSA-OAEP encrypt seed with EK public key */
    r = rsa_oaep_encrypt(ek_pkey, seed, 32, &enc_secret, &enc_secret_len);
    if (htpm2_is_err(r))
        goto out;

    /* Step 4: Derive symmetric key for encryption
     * symKey = KDFa(SHA256, seed, "STORAGE", name, "", 128) */
    r = htpm2_kdfa(ctx, seed, 32, "STORAGE",
                   key_name, key_name_len, NULL, 0,
                   128, sym_key, 16);
    if (htpm2_is_err(r))
        goto out;

    /* Step 5: Encrypt credential with AES-128-CFB (IV=0) */
    enc_identity = malloc(credential_len);
    if (enc_identity == NULL) {
        r = htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                               "MakeCredential: alloc");
        goto out;
    }
    memset(iv, 0, sizeof(iv));
    r = htpm2_aes_cfb_encrypt(ctx, sym_key, 16, iv, 16,
                               credential, credential_len,
                               enc_identity);
    if (htpm2_is_err(r))
        goto out;

    /* Step 6: Derive HMAC key
     * hmacKey = KDFa(SHA256, seed, "INTEGRITY", "", "", 256) */
    r = htpm2_kdfa(ctx, seed, 32, "INTEGRITY",
                   NULL, 0, NULL, 0,
                   256, hmac_key, 32);
    if (htpm2_is_err(r))
        goto out;

    /* Step 7: Compute outer HMAC over encIdentity || name */
    {
        size_t hmac_data_len = credential_len + key_name_len;
        uint8_t *hmac_data = malloc(hmac_data_len);
        if (hmac_data == NULL) {
            r = htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                   "MakeCredential: hmac alloc");
            goto out;
        }
        memcpy(hmac_data, enc_identity, credential_len);
        memcpy(hmac_data + credential_len, key_name, key_name_len);

        r = htpm2_hmac_sha256(ctx, hmac_key, 32,
                              hmac_data, hmac_data_len,
                              hmac_out, &hmac_len);
        free(hmac_data);
        if (htpm2_is_err(r))
            goto out;
    }

    /* Step 8: Build credentialBlob = TPM2B(HMAC_size(2) + HMAC + encIdentity)
     *
     * credentialBlob structure:
     *   uint16: overall size
     *   uint16: HMAC size (32)
     *   bytes:  HMAC (32 bytes)
     *   bytes:  encIdentity
     */
    blob_sp = heim_storage_emem();
    if (blob_sp == NULL) {
        r = htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                               "MakeCredential: blob alloc");
        goto out;
    }

    /* The TPM2B_ID_OBJECT contains: HMAC as TPM2B then encIdentity */
    ret = heim_store_uint16(blob_sp, (uint16_t)(2 + hmac_len + credential_len));
    if (ret == 0)
        ret = heim_store_uint16(blob_sp, (uint16_t)hmac_len);
    if (ret == 0)
        ret = heim_store_bytes(blob_sp, hmac_out, hmac_len);
    if (ret == 0)
        ret = heim_store_bytes(blob_sp, enc_identity, credential_len);

    if (ret) {
        heim_storage_free(blob_sp);
        r = htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                               "MakeCredential: blob marshal");
        goto out;
    }

    ret = heim_storage_to_data(blob_sp, credential_blob, credential_blob_len);
    heim_storage_free(blob_sp);
    if (ret) {
        r = htpm2_result_local(ret, HTPM2_F_LOCAL, ret,
                               "MakeCredential: blob to_data");
        goto out;
    }

    /* Build encrypted secret as TPM2B */
    {
        heim_storage *sec_sp = heim_storage_emem();
        if (sec_sp == NULL) {
            free(*credential_blob);
            *credential_blob = NULL;
            r = htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                   "MakeCredential: secret alloc");
            goto out;
        }
        ret = heim_store_uint16(sec_sp, (uint16_t)enc_secret_len);
        if (ret == 0)
            ret = heim_store_bytes(sec_sp, enc_secret, enc_secret_len);
        if (ret == 0)
            ret = heim_storage_to_data(sec_sp, encrypted_secret,
                                       encrypted_secret_len);
        heim_storage_free(sec_sp);
        if (ret) {
            free(*credential_blob);
            *credential_blob = NULL;
            r = htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                   "MakeCredential: secret marshal");
            goto out;
        }
    }

    r = HTPM2_OK;

out:
    memset(seed, 0, sizeof(seed));
    memset(sym_key, 0, sizeof(sym_key));
    memset(hmac_key, 0, sizeof(hmac_key));
    free(enc_identity);
    free(enc_secret);
    EVP_PKEY_free(ek_pkey);
    return r;
}
