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
 * Quote verification -- verify a TPM quote's signature and contents.
 *
 * TPMS_ATTEST layout:
 *   magic:           uint32 = 0xff544347 ("TCG\xff")
 *   type:            uint16 (TPM_ST_ATTEST_QUOTE = 0x8018)
 *   qualifiedSigner: TPM2B_NAME
 *   extraData:       TPM2B_DATA (the qualifying data / nonce)
 *   clockInfo:       TPMS_CLOCK_INFO (17 bytes)
 *   firmwareVersion: uint64
 *   attested:        TPMS_QUOTE_INFO {
 *     pcrSelect:     TPML_PCR_SELECTION
 *     pcrDigest:     TPM2B_DIGEST
 *   }
 *
 * TPMT_SIGNATURE layout (for RSASSA):
 *   sigAlg:   uint16 (TPM2_ALG_RSASSA = 0x0014)
 *   hashAlg:  uint16
 *   sig:      TPM2B (raw RSA signature)
 *
 * TPMT_SIGNATURE layout (for ECDSA):
 *   sigAlg:   uint16 (TPM2_ALG_ECDSA = 0x0018)
 *   hashAlg:  uint16
 *   signatureR: TPM2B
 *   signatureS: TPM2B
 */

#include "htpm2_locl.h"
#include "marshal.h"
#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#define TPM_GENERATED_VALUE  0xff544347  /* "\xffTCG" */
#define TPM_ST_ATTEST_QUOTE  0x8018

/*
 * Parse the AK's TPM2B_PUBLIC to construct an EVP_PKEY for signature
 * verification.  Supports RSA and ECC keys.
 */
static htpm2_result
ak_pub_to_evp_pkey(const void *ak_pub, size_t ak_pub_len, EVP_PKEY **pkey)
{
    heim_storage *sp;
    uint16_t alg_type, name_alg, auth_size, sym_alg, scheme_alg, key_bits;
    uint32_t obj_attrs, exp;
    int ret;

    *pkey = NULL;

    sp = heim_storage_from_readonly_mem(ak_pub, ak_pub_len);
    if (sp == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "ak_pub_to_pkey: alloc");

    ret = heim_ret_uint16(sp, &alg_type);
    if (ret) { heim_storage_free(sp); return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret, "ak_pub: type"); }

    heim_ret_uint16(sp, &name_alg);
    heim_ret_uint32(sp, &obj_attrs);
    heim_ret_uint16(sp, &auth_size);
    if (auth_size > 0)
        heim_storage_seek(sp, auth_size, SEEK_CUR);

    /* symmetric */
    heim_ret_uint16(sp, &sym_alg);
    if (sym_alg != TPM2_ALG_NULL) {
        uint16_t dummy;
        heim_ret_uint16(sp, &dummy);
        heim_ret_uint16(sp, &dummy);
    }

    /* scheme */
    heim_ret_uint16(sp, &scheme_alg);
    if (scheme_alg != TPM2_ALG_NULL) {
        uint16_t dummy;
        heim_ret_uint16(sp, &dummy);
    }

    if (alg_type == TPM2_ALG_RSA) {
        void *modulus = NULL;
        uint16_t mod_size;
        OSSL_PARAM_BLD *bld;
        OSSL_PARAM *params;
        EVP_PKEY_CTX *kctx;
        BIGNUM *n, *e_bn;

        heim_ret_uint16(sp, &key_bits);
        heim_ret_uint32(sp, &exp);
        if (exp == 0) exp = 65537;
        htpm2_unmarshal_tpm2b(sp, &modulus, &mod_size);
        heim_storage_free(sp);

        if (!modulus)
            return htpm2_result_local(EINVAL, HTPM2_F_MARSHAL, EINVAL,
                                      "ak_pub: no RSA modulus");

        n = BN_bin2bn(modulus, mod_size, NULL);
        e_bn = BN_new();
        BN_set_word(e_bn, exp);
        free(modulus);

        bld = OSSL_PARAM_BLD_new();
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n);
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e_bn);
        params = OSSL_PARAM_BLD_to_param(bld);

        kctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        if (kctx && EVP_PKEY_fromdata_init(kctx) == 1)
            EVP_PKEY_fromdata(kctx, pkey, EVP_PKEY_PUBLIC_KEY, params);

        EVP_PKEY_CTX_free(kctx);
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
        BN_free(n);
        BN_free(e_bn);

        if (*pkey == NULL)
            return htpm2_result_ossl(1, "ak_pub: RSA key construction");
        return HTPM2_OK;

    } else if (alg_type == TPM2_ALG_ECC) {
        uint16_t curve_id;
        void *x_data = NULL, *y_data = NULL;
        uint16_t x_len, y_len;
        char group_name[8];
        OSSL_PARAM_BLD *bld;
        OSSL_PARAM *params;
        EVP_PKEY_CTX *kctx;
        uint8_t *pub_point;
        size_t pub_point_len;

        heim_ret_uint16(sp, &curve_id);
        /* kdf */
        { uint16_t dummy; heim_ret_uint16(sp, &dummy); }
        /* unique: x, y */
        htpm2_unmarshal_tpm2b(sp, &x_data, &x_len);
        htpm2_unmarshal_tpm2b(sp, &y_data, &y_len);
        heim_storage_free(sp);

        if (!x_data || !y_data) {
            free(x_data); free(y_data);
            return htpm2_result_local(EINVAL, HTPM2_F_MARSHAL, EINVAL,
                                      "ak_pub: no ECC point");
        }

        switch (curve_id) {
        case 0x0003: snprintf(group_name, sizeof(group_name), "P-256"); break;
        case 0x0004: snprintf(group_name, sizeof(group_name), "P-384"); break;
        default:
            free(x_data); free(y_data);
            return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                      "ak_pub: unsupported curve 0x%04x", curve_id);
        }

        /* Build uncompressed point: 0x04 || x || y */
        pub_point_len = 1 + x_len + y_len;
        pub_point = malloc(pub_point_len);
        if (!pub_point) { free(x_data); free(y_data); return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM, "ak_pub: alloc"); }
        pub_point[0] = 0x04;
        memcpy(pub_point + 1, x_data, x_len);
        memcpy(pub_point + 1 + x_len, y_data, y_len);
        free(x_data); free(y_data);

        bld = OSSL_PARAM_BLD_new();
        OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0);
        OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub_point, pub_point_len);
        params = OSSL_PARAM_BLD_to_param(bld);

        kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        if (kctx && EVP_PKEY_fromdata_init(kctx) == 1)
            EVP_PKEY_fromdata(kctx, pkey, EVP_PKEY_PUBLIC_KEY, params);

        EVP_PKEY_CTX_free(kctx);
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
        free(pub_point);

        if (*pkey == NULL)
            return htpm2_result_ossl(1, "ak_pub: ECC key construction");
        return HTPM2_OK;
    }

    heim_storage_free(sp);
    return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                              "ak_pub: unsupported algorithm 0x%04x", alg_type);
}

/*
 * Verify the signature over TPMS_ATTEST (the `quoted` blob).
 *
 * The signature is a TPMT_SIGNATURE.  For RSASSA:
 *   sigAlg(2) + hashAlg(2) + sig(TPM2B)
 * For ECDSA:
 *   sigAlg(2) + hashAlg(2) + r(TPM2B) + s(TPM2B)
 *
 * The data signed is SHA-256(quoted_blob).
 */
static htpm2_result
verify_quote_signature(const htpm2_context ctx,
                       EVP_PKEY *ak_pkey,
                       const void *quoted, size_t quoted_len,
                       const void *signature, size_t signature_len)
{
    heim_storage *sig_sp;
    uint16_t sig_alg, hash_alg;
    EVP_MD_CTX *mdctx = NULL;
    htpm2_result r = HTPM2_OK;

    sig_sp = heim_storage_from_readonly_mem(signature, signature_len);
    if (sig_sp == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "verify_quote_sig: alloc");

    heim_ret_uint16(sig_sp, &sig_alg);
    heim_ret_uint16(sig_sp, &hash_alg);

    if (sig_alg == TPM2_ALG_RSASSA) {
        void *sig_data = NULL;
        uint16_t sig_size;

        htpm2_unmarshal_tpm2b(sig_sp, &sig_data, &sig_size);
        heim_storage_free(sig_sp);

        if (!sig_data)
            return htpm2_result_local(EINVAL, HTPM2_F_MARSHAL, EINVAL,
                                      "verify_quote_sig: no RSA sig data");

        mdctx = EVP_MD_CTX_new();
        if (mdctx == NULL) {
            free(sig_data);
            return htpm2_result_ossl(1, "verify_quote_sig: ctx");
        }

        if (EVP_DigestVerifyInit(mdctx, NULL, ctx->md_sha256, NULL,
                                 ak_pkey) != 1 ||
            EVP_DigestVerify(mdctx, sig_data, sig_size,
                             quoted, quoted_len) != 1) {
            r = htpm2_result_local(EACCES, HTPM2_F_SESSION, EACCES,
                                   "verify_quote_sig: RSA signature verification FAILED");
        }

        EVP_MD_CTX_free(mdctx);
        free(sig_data);
        return r;

    } else if (sig_alg == TPM2_ALG_ECDSA) {
        void *r_data = NULL, *s_data = NULL;
        uint16_t r_size, s_size;
        ECDSA_SIG *ecdsa_sig = NULL;
        BIGNUM *bn_r, *bn_s;
        unsigned char *der_sig = NULL;
        int der_len;

        htpm2_unmarshal_tpm2b(sig_sp, &r_data, &r_size);
        htpm2_unmarshal_tpm2b(sig_sp, &s_data, &s_size);
        heim_storage_free(sig_sp);

        if (!r_data || !s_data) {
            free(r_data); free(s_data);
            return htpm2_result_local(EINVAL, HTPM2_F_MARSHAL, EINVAL,
                                      "verify_quote_sig: no ECDSA sig");
        }

        /* Build DER-encoded ECDSA signature */
        bn_r = BN_bin2bn(r_data, r_size, NULL);
        bn_s = BN_bin2bn(s_data, s_size, NULL);
        free(r_data); free(s_data);

        ecdsa_sig = ECDSA_SIG_new();
        ECDSA_SIG_set0(ecdsa_sig, bn_r, bn_s); /* takes ownership */
        der_len = i2d_ECDSA_SIG(ecdsa_sig, &der_sig);
        ECDSA_SIG_free(ecdsa_sig);

        if (der_len <= 0)
            return htpm2_result_ossl(1, "verify_quote_sig: DER encode ECDSA");

        mdctx = EVP_MD_CTX_new();
        if (mdctx == NULL) {
            OPENSSL_free(der_sig);
            return htpm2_result_ossl(1, "verify_quote_sig: ctx");
        }

        if (EVP_DigestVerifyInit(mdctx, NULL, ctx->md_sha256, NULL,
                                 ak_pkey) != 1 ||
            EVP_DigestVerify(mdctx, der_sig, der_len,
                             quoted, quoted_len) != 1) {
            r = htpm2_result_local(EACCES, HTPM2_F_SESSION, EACCES,
                                   "verify_quote_sig: ECDSA signature verification FAILED");
        }

        EVP_MD_CTX_free(mdctx);
        OPENSSL_free(der_sig);
        return r;
    }

    heim_storage_free(sig_sp);
    return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                              "verify_quote_sig: unsupported sig alg 0x%04x",
                              sig_alg);
}

/*
 * htpm2_quote_verify -- verify a TPM quote.
 *
 * Verifies:
 *   1. TPMS_ATTEST magic value (0xff544347)
 *   2. type == TPM_ST_ATTEST_QUOTE
 *   3. Signature over the TPMS_ATTEST blob using the AK's public key
 *   4. extraData (qualifying data / nonce) matches expected value
 *
 * Returns the PCR digest from the quote for comparison with replayed
 * eventlog values.
 */
htpm2_result
htpm2_quote_verify(const htpm2_context ctx,
                   const void *quoted, size_t quoted_len,
                   const void *signature, size_t signature_len,
                   const void *ak_pub, size_t ak_pub_len,
                   const void *expected_nonce, size_t expected_nonce_len,
                   void **pcr_digest, size_t *pcr_digest_len)
{
    heim_storage *sp;
    uint32_t magic;
    uint16_t type;
    void *extra_data = NULL;
    uint16_t extra_len;
    EVP_PKEY *ak_pkey = NULL;
    htpm2_result r;
    int ret;

    if (pcr_digest) {
        *pcr_digest = NULL;
        *pcr_digest_len = 0;
    }

    /* Parse TPMS_ATTEST header */
    sp = heim_storage_from_readonly_mem(quoted, quoted_len);
    if (sp == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "quote_verify: alloc");

    ret = heim_ret_uint32(sp, &magic);
    if (ret || magic != TPM_GENERATED_VALUE) {
        heim_storage_free(sp);
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "quote_verify: bad magic 0x%08x "
                                  "(expected 0x%08x)", magic,
                                  TPM_GENERATED_VALUE);
    }

    ret = heim_ret_uint16(sp, &type);
    if (ret || type != TPM_ST_ATTEST_QUOTE) {
        heim_storage_free(sp);
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "quote_verify: bad type 0x%04x "
                                  "(expected 0x%04x)", type,
                                  TPM_ST_ATTEST_QUOTE);
    }

    /* qualifiedSigner (TPM2B_NAME) -- skip */
    { void *tmp; uint16_t tl; htpm2_unmarshal_tpm2b(sp, &tmp, &tl); free(tmp); }

    /* extraData (TPM2B_DATA) -- this is the nonce */
    htpm2_unmarshal_tpm2b(sp, &extra_data, &extra_len);

    /* clockInfo (17 bytes): clock(8) + resetCount(4) + restartCount(4) + safe(1) */
    heim_storage_seek(sp, 17, SEEK_CUR);

    /* firmwareVersion (8 bytes) */
    heim_storage_seek(sp, 8, SEEK_CUR);

    /* attested: TPMS_QUOTE_INFO { pcrSelect, pcrDigest } */
    /* pcrSelect: TPML_PCR_SELECTION -- skip for now */
    {
        uint32_t count;
        uint32_t i;
        heim_ret_uint32(sp, &count);
        for (i = 0; i < count; i++) {
            uint8_t size_of_select;
            heim_storage_seek(sp, 2, SEEK_CUR); /* hash alg */
            heim_ret_uint8(sp, &size_of_select);
            heim_storage_seek(sp, size_of_select, SEEK_CUR);
        }
    }

    /* pcrDigest (TPM2B_DIGEST) */
    if (pcr_digest) {
        uint16_t pd_len;
        htpm2_unmarshal_tpm2b(sp, pcr_digest, &pd_len);
        *pcr_digest_len = pd_len;
    }

    heim_storage_free(sp);

    /* Verify nonce */
    if (expected_nonce && expected_nonce_len > 0) {
        if (extra_len != expected_nonce_len ||
            !extra_data ||
            memcmp(extra_data, expected_nonce, expected_nonce_len) != 0) {
            free(extra_data);
            return htpm2_result_local(EACCES, HTPM2_F_SESSION, EACCES,
                                      "quote_verify: nonce mismatch "
                                      "(replay attack?)");
        }
    }
    free(extra_data);

    /* Verify signature */
    if (ak_pub && ak_pub_len > 0) {
        r = ak_pub_to_evp_pkey(ak_pub, ak_pub_len, &ak_pkey);
        if (htpm2_is_err(r))
            return htpm2_result_prepend(r, "quote_verify");

        r = verify_quote_signature(ctx, ak_pkey, quoted, quoted_len,
                                   signature, signature_len);
        EVP_PKEY_free(ak_pkey);
        if (htpm2_is_err(r))
            return r;
    }

    return HTPM2_OK;
}
