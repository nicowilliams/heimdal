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
 * TPM2_Import -- import an externally-wrapped key into the TPM.
 * TPM2_Duplicate -- export a key for use under a different parent.
 * Software Duplicate -- create a Duplicate payload from a software key.
 *
 * TPM2_Import command (with session on parentHandle):
 *   parentHandle:    uint32
 *   encryptionKey:   TPM2B_DATA (symmetric key for inner wrapper, empty if none)
 *   objectPublic:    TPM2B_PUBLIC
 *   duplicate:       TPM2B_PRIVATE (outer wrapper)
 *   inSymSeed:       TPM2B_ENCRYPTED_SECRET (seed encrypted to parent)
 *
 * TPM2_Import response:
 *   outPrivate:      TPM2B_PRIVATE (re-wrapped for this parent)
 *
 * TPM2_Duplicate command (with session on objectHandle):
 *   objectHandle:    handle of key to duplicate
 *   newParentHandle: handle of new parent (or TPM_RH_NULL for no outer wrapper)
 *   encryptionKeyIn: TPM2B_DATA (inner symmetric key, empty = TPM generates)
 *   symmetricAlg:    TPMT_SYM_DEF_OBJECT (NULL or AES-128-CFB)
 *
 * TPM2_Duplicate response:
 *   encryptionKeyOut: TPM2B_DATA
 *   duplicate:        TPM2B_PRIVATE
 *   outSymSeed:       TPM2B_ENCRYPTED_SECRET
 */

#include "htpm2_locl.h"
#include "marshal.h"
#include "crypto.h"

htpm2_result
htpm2_import(const htpm2_context ctx,
             htpm2_transport tp,
             htpm2_result prior,
             htpm2_session auth_session,
             htpm2_object parent,
             const void *pub_blob, size_t pub_blob_len,
             const void *duplicate, size_t duplicate_len,
             const void *encrypted_seed, size_t encrypted_seed_len,
             const void *sym_seed, size_t sym_seed_len,
             void **priv_blob, size_t *priv_blob_len)
{
    heim_storage *param_sp, *rsp;
    uint32_t rc, handles[1];
    void *param_data = NULL;
    size_t param_len = 0;
    void *priv_data = NULL;
    uint16_t priv_size;
    htpm2_result r;
    int ret;

    if (prior.code)
        return prior;

    *priv_blob = NULL;
    *priv_blob_len = 0;

    handles[0] = htpm2_object_get_handle(parent);

    param_sp = heim_storage_emem();
    if (param_sp == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "Import: alloc");

    /* encryptionKey (TPM2B_DATA) -- inner wrapper key, empty if not used */
    ret = htpm2_marshal_tpm2b(param_sp, sym_seed, sym_seed_len);
    if (ret) goto marshal_err;

    /* objectPublic (TPM2B_PUBLIC) */
    ret = htpm2_marshal_tpm2b(param_sp, pub_blob, pub_blob_len);
    if (ret) goto marshal_err;

    /* duplicate (TPM2B_PRIVATE -- outer wrapper) */
    ret = htpm2_marshal_tpm2b(param_sp, duplicate, duplicate_len);
    if (ret) goto marshal_err;

    /* inSymSeed (TPM2B_ENCRYPTED_SECRET) */
    ret = htpm2_marshal_tpm2b(param_sp, encrypted_seed, encrypted_seed_len);
    if (ret) goto marshal_err;

    /* symmetricAlg = TPM_ALG_NULL (no inner wrapper) */
    ret = heim_store_uint16(param_sp, TPM2_ALG_NULL);
    if (ret) goto marshal_err;

    ret = heim_storage_to_data(param_sp, &param_data, &param_len);
    heim_storage_free(param_sp);
    param_sp = NULL;
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "Import: to_data");

    r = htpm2_command_execute_with_auth(ctx, tp, TPM2_CC_Import,
                                        handles, 1, auth_session,
                                        param_data, param_len, &rsp, &rc);
    free(param_data);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "Import");

    /* outPrivate (TPM2B_PRIVATE) */
    ret = htpm2_unmarshal_tpm2b(rsp, &priv_data, &priv_size);
    heim_storage_free(rsp);
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "Import: unmarshal");

    *priv_blob = priv_data;
    *priv_blob_len = priv_size;
    return HTPM2_OK;

marshal_err:
    heim_storage_free(param_sp);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret, "Import: marshal");
}

/*
 * TPM2_Duplicate -- ask the TPM to export a loaded key for a new parent.
 */
htpm2_result
htpm2_duplicate(const htpm2_context ctx,
                htpm2_transport tp,
                htpm2_result prior,
                htpm2_session auth_session,
                htpm2_object key,
                htpm2_object new_parent,
                void **duplicate_out, size_t *duplicate_out_len,
                void **encrypted_seed, size_t *encrypted_seed_len)
{
    heim_storage *param_sp, *rsp;
    uint32_t rc, handles[2];
    void *param_data = NULL;
    size_t param_len = 0;
    void *dup_data = NULL, *seed_data = NULL, *enc_key_data = NULL;
    uint16_t dup_size, seed_size, enc_key_size;
    htpm2_result r;
    int ret;

    if (prior.code)
        return prior;

    *duplicate_out = NULL;
    *duplicate_out_len = 0;
    *encrypted_seed = NULL;
    *encrypted_seed_len = 0;

    handles[0] = htpm2_object_get_handle(key);
    handles[1] = new_parent ?
        htpm2_object_get_handle(new_parent) : 0x40000007; /* TPM_RH_NULL */

    param_sp = heim_storage_emem();
    if (param_sp == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "Duplicate: alloc");

    /* encryptionKeyIn (empty = let TPM generate if needed) */
    ret = htpm2_marshal_tpm2b(param_sp, NULL, 0);
    if (ret) goto marshal_err;

    /* symmetricAlg = TPM_ALG_NULL */
    ret = heim_store_uint16(param_sp, TPM2_ALG_NULL);
    if (ret) goto marshal_err;

    ret = heim_storage_to_data(param_sp, &param_data, &param_len);
    heim_storage_free(param_sp);
    param_sp = NULL;
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "Duplicate: to_data");

    r = htpm2_command_execute_with_auth(ctx, tp, TPM2_CC_Duplicate,
                                        handles, 2, auth_session,
                                        param_data, param_len, &rsp, &rc);
    free(param_data);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "Duplicate");

    /* encryptionKeyOut (TPM2B_DATA) -- skip */
    ret = htpm2_unmarshal_tpm2b(rsp, &enc_key_data, &enc_key_size);
    free(enc_key_data);
    if (ret) goto unmarshal_err;

    /* duplicate (TPM2B_PRIVATE) */
    ret = htpm2_unmarshal_tpm2b(rsp, &dup_data, &dup_size);
    if (ret) goto unmarshal_err;

    /* outSymSeed (TPM2B_ENCRYPTED_SECRET) */
    ret = htpm2_unmarshal_tpm2b(rsp, &seed_data, &seed_size);
    if (ret) {
        free(dup_data);
        goto unmarshal_err;
    }

    heim_storage_free(rsp);

    *duplicate_out = dup_data;
    *duplicate_out_len = dup_size;
    *encrypted_seed = seed_data;
    *encrypted_seed_len = seed_size;
    return HTPM2_OK;

marshal_err:
    heim_storage_free(param_sp);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "Duplicate: marshal");

unmarshal_err:
    heim_storage_free(rsp);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "Duplicate: unmarshal");
}

/*
 * Software Duplicate -- create a Duplicate payload from a software key.
 *
 * This wraps a software-generated private key for import into a TPM
 * under a specific parent.  The key ends up as fixedTPM at the
 * destination even though it was originally a software key.
 *
 * The algorithm (outer wrapper only, no inner wrapper):
 *   1. Build TPMT_SENSITIVE from the private key material
 *   2. Generate random seed
 *   3. Encrypt seed to new parent's public key (RSA OAEP, label "DUPLICATE\0")
 *   4. Derive symmetric key: KDFa(SHA256, seed, "STORAGE", name, "", 128)
 *   5. Derive HMAC key: KDFa(SHA256, seed, "INTEGRITY", "", "", 256)
 *   6. Encrypt TPMT_SENSITIVE with AES-128-CFB
 *   7. Compute HMAC over encrypted sensitive || name
 *   8. Build TPM2B_PRIVATE = HMAC_size(2) + HMAC + encrypted_sensitive
 *   9. Return duplicate blob + encrypted seed
 *
 * The caller then uses htpm2_import() to load the key under the parent.
 *
 * Parameters:
 *   parent_pub:   TPM2B_PUBLIC of the new parent (for seed encryption)
 *   key_pub:      TPM2B_PUBLIC of the key being wrapped
 *   key_priv:     Raw private key material (TPMT_SENSITIVE contents)
 *   key_name:     Name of the key (hash of TPM2B_PUBLIC)
 */
htpm2_result
htpm2_duplicate_software(const htpm2_context ctx,
                         const void *parent_pub, size_t parent_pub_len,
                         const void *key_pub, size_t key_pub_len,
                         const void *sensitive, size_t sensitive_len,
                         const void *key_name, size_t key_name_len,
                         void **duplicate_out, size_t *duplicate_out_len,
                         void **encrypted_seed, size_t *encrypted_seed_len)
{
    uint8_t seed[32];
    uint8_t sym_key[16];
    uint8_t hmac_key[32];
    uint8_t iv[16];
    uint8_t hmac_out[32];
    size_t hmac_len = 32;
    uint8_t *enc_sensitive = NULL;
    void *enc_seed = NULL;
    size_t enc_seed_len = 0;
    heim_storage *dup_sp;
    htpm2_result r;
    int ret;

    *duplicate_out = NULL;
    *duplicate_out_len = 0;
    *encrypted_seed = NULL;
    *encrypted_seed_len = 0;

    /*
     * Parse parent's public key to get RSA modulus for seed encryption.
     * Reuse the same parsing logic as in soft.c / session.c.
     */
    {
        heim_storage *pub_sp;
        uint16_t alg_type, name_alg, auth_size, sym_alg, scheme_alg, key_bits;
        uint32_t obj_attrs, exp;
        void *modulus = NULL;
        uint16_t mod_size;

        pub_sp = heim_storage_from_readonly_mem(parent_pub, parent_pub_len);
        if (pub_sp == NULL)
            return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                      "duplicate_software: alloc");

        heim_ret_uint16(pub_sp, &alg_type);
        if (alg_type != TPM2_ALG_RSA) {
            heim_storage_free(pub_sp);
            return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                "duplicate_software: parent must be RSA (got 0x%04x)",
                alg_type);
        }

        heim_ret_uint16(pub_sp, &name_alg);
        heim_ret_uint32(pub_sp, &obj_attrs);
        heim_ret_uint16(pub_sp, &auth_size);
        if (auth_size > 0)
            heim_storage_seek(pub_sp, auth_size, SEEK_CUR);
        heim_ret_uint16(pub_sp, &sym_alg);
        if (sym_alg != TPM2_ALG_NULL) {
            uint16_t dummy;
            heim_ret_uint16(pub_sp, &dummy);
            heim_ret_uint16(pub_sp, &dummy);
        }
        heim_ret_uint16(pub_sp, &scheme_alg);
        if (scheme_alg != TPM2_ALG_NULL) {
            uint16_t dummy;
            heim_ret_uint16(pub_sp, &dummy);
        }
        heim_ret_uint16(pub_sp, &key_bits);
        heim_ret_uint32(pub_sp, &exp);
        htpm2_unmarshal_tpm2b(pub_sp, &modulus, &mod_size);
        heim_storage_free(pub_sp);

        if (modulus == NULL || mod_size == 0)
            return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                "duplicate_software: can't parse parent RSA key");

        /* Generate seed and encrypt to parent */
        r = htpm2_random_bytes(ctx, seed, 32);
        if (htpm2_is_ok(r)) {
            r = htpm2_rsa_oaep_encrypt(ctx, modulus, mod_size,
                                       exp == 0 ? 65537 : exp,
                                       "DUPLICATE", 10,
                                       seed, 32,
                                       &enc_seed, &enc_seed_len);
        }
        free(modulus);
        if (htpm2_is_err(r))
            return htpm2_result_prepend(r, "duplicate_software: seed");
    }

    /* Derive symmetric key: KDFa(SHA256, seed, "STORAGE", name, "", 128) */
    r = htpm2_kdfa(ctx, seed, 32, "STORAGE",
                   key_name, key_name_len, NULL, 0,
                   128, sym_key, 16);
    if (htpm2_is_err(r)) goto out;

    /* Derive HMAC key: KDFa(SHA256, seed, "INTEGRITY", "", "", 256) */
    r = htpm2_kdfa(ctx, seed, 32, "INTEGRITY",
                   NULL, 0, NULL, 0,
                   256, hmac_key, 32);
    if (htpm2_is_err(r)) goto out;

    /* Encrypt sensitive with AES-128-CFB (IV=0) */
    enc_sensitive = malloc(sensitive_len);
    if (enc_sensitive == NULL) {
        r = htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                               "duplicate_software: alloc enc");
        goto out;
    }
    memset(iv, 0, sizeof(iv));
    r = htpm2_aes_cfb_encrypt(ctx, sym_key, 16, iv, 16,
                               sensitive, sensitive_len, enc_sensitive);
    if (htpm2_is_err(r)) goto out;

    /* HMAC over encrypted_sensitive || name */
    {
        size_t hdata_len = sensitive_len + key_name_len;
        uint8_t *hdata = malloc(hdata_len);
        if (hdata == NULL) {
            r = htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                   "duplicate_software: alloc hmac");
            goto out;
        }
        memcpy(hdata, enc_sensitive, sensitive_len);
        memcpy(hdata + sensitive_len, key_name, key_name_len);
        r = htpm2_hmac_sha256(ctx, hmac_key, 32, hdata, hdata_len,
                              hmac_out, &hmac_len);
        free(hdata);
        if (htpm2_is_err(r)) goto out;
    }

    /* Build TPM2B_PRIVATE: size(2) + hmac_size(2) + hmac + enc_sensitive */
    dup_sp = heim_storage_emem();
    if (dup_sp == NULL) {
        r = htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                               "duplicate_software: alloc dup");
        goto out;
    }

    ret = heim_store_uint16(dup_sp,
                            (uint16_t)(2 + hmac_len + sensitive_len));
    if (ret == 0)
        ret = heim_store_uint16(dup_sp, (uint16_t)hmac_len);
    if (ret == 0)
        ret = heim_store_bytes(dup_sp, hmac_out, hmac_len);
    if (ret == 0)
        ret = heim_store_bytes(dup_sp, enc_sensitive, sensitive_len);

    if (ret) {
        heim_storage_free(dup_sp);
        r = htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                               "duplicate_software: marshal dup");
        goto out;
    }

    ret = heim_storage_to_data(dup_sp, duplicate_out, duplicate_out_len);
    heim_storage_free(dup_sp);
    if (ret) {
        r = htpm2_result_local(ret, HTPM2_F_LOCAL, ret,
                               "duplicate_software: to_data");
        goto out;
    }

    /* Build TPM2B_ENCRYPTED_SECRET */
    {
        heim_storage *seed_sp = heim_storage_emem();
        if (seed_sp == NULL) {
            free(*duplicate_out);
            *duplicate_out = NULL;
            r = htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                   "duplicate_software: alloc seed");
            goto out;
        }
        ret = heim_store_uint16(seed_sp, (uint16_t)enc_seed_len);
        if (ret == 0)
            ret = heim_store_bytes(seed_sp, enc_seed, enc_seed_len);
        if (ret == 0)
            ret = heim_storage_to_data(seed_sp, encrypted_seed,
                                       encrypted_seed_len);
        heim_storage_free(seed_sp);
        if (ret) {
            free(*duplicate_out);
            *duplicate_out = NULL;
            r = htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                   "duplicate_software: seed marshal");
            goto out;
        }
    }

    r = HTPM2_OK;

out:
    memset(seed, 0, sizeof(seed));
    memset(sym_key, 0, sizeof(sym_key));
    memset(hmac_key, 0, sizeof(hmac_key));
    free(enc_sensitive);
    free(enc_seed);
    return r;
}
