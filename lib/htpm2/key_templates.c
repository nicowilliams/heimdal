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
 * Standard TPMT_PUBLIC templates for common key types.
 *
 * TPMT_PUBLIC layout (big-endian):
 *   type:             uint16 (algorithm: RSA, ECC, KEYEDHASH, SYMCIPHER)
 *   nameAlg:          uint16 (hash algorithm for object name)
 *   objectAttributes: uint32 (usage flags)
 *   authPolicy:       TPM2B_DIGEST (policy digest, empty for no policy)
 *   parameters:       algorithm-specific
 *   unique:           algorithm-specific (public key material; empty for Create)
 */

#include "htpm2_locl.h"
#include "marshal.h"

/* Object attribute bits */
#define TPMA_OBJECT_FIXEDTPM            (1U << 1)
#define TPMA_OBJECT_STCLEAR             (1U << 2)
#define TPMA_OBJECT_FIXEDPARENT         (1U << 4)
#define TPMA_OBJECT_SENSITIVEDATAORIGIN (1U << 5)
#define TPMA_OBJECT_USERWITHAUTH        (1U << 6)
#define TPMA_OBJECT_ADMINWITHPOLICY     (1U << 7)
#define TPMA_OBJECT_NODA                (1U << 10)
#define TPMA_OBJECT_ENCRYPTEDDUPLICATION (1U << 11)
#define TPMA_OBJECT_RESTRICTED          (1U << 16)
#define TPMA_OBJECT_DECRYPT             (1U << 17)
#define TPMA_OBJECT_SIGN_ENCRYPT        (1U << 18)

/* Common attribute sets */
#define ATTRS_STORAGE \
    (TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | \
     TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH | \
     TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT | TPMA_OBJECT_NODA)

#define ATTRS_SIGNING \
    (TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | \
     TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH | \
     TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_NODA)

#define ATTRS_DECRYPT \
    (TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | \
     TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH | \
     TPMA_OBJECT_DECRYPT | TPMA_OBJECT_NODA)

/*
 * Marshal an RSA TPMT_PUBLIC into storage.
 *
 * RSA parameters:
 *   symmetric:   TPMT_SYM_DEF_OBJECT (for storage: AES-128-CFB; for others: NULL)
 *   scheme:      TPMT_RSA_SCHEME (RSASSA for sign, OAEP for decrypt, NULL for storage)
 *   keyBits:     uint16
 *   exponent:    uint32 (0 = default 65537)
 *
 * RSA unique:
 *   TPM2B buffer of keyBits/8 bytes (zeros for Create template)
 */
static int
marshal_rsa_template(heim_storage *sp, uint16_t key_bits,
                     uint32_t attrs, uint16_t scheme_alg,
                     const void *policy, size_t policy_len)
{
    int ret;

    /* type = TPM2_ALG_RSA */
    ret = heim_store_uint16(sp, TPM2_ALG_RSA);
    if (ret) return ret;

    /* nameAlg = SHA-256 */
    ret = heim_store_uint16(sp, TPM2_ALG_SHA256);
    if (ret) return ret;

    /* objectAttributes */
    ret = heim_store_uint32(sp, attrs);
    if (ret) return ret;

    /* authPolicy (TPM2B_DIGEST) */
    ret = htpm2_marshal_tpm2b(sp, policy, policy_len);
    if (ret) return ret;

    /* --- parameters (TPMS_RSA_PARMS) --- */

    /* symmetric (TPMT_SYM_DEF_OBJECT) */
    if (attrs & TPMA_OBJECT_RESTRICTED && attrs & TPMA_OBJECT_DECRYPT) {
        /* Storage key: AES-128-CFB */
        ret = heim_store_uint16(sp, TPM2_ALG_AES);   /* algorithm */
        if (ret) return ret;
        ret = heim_store_uint16(sp, 128);             /* keyBits */
        if (ret) return ret;
        ret = heim_store_uint16(sp, TPM2_ALG_CFB);   /* mode */
        if (ret) return ret;
    } else {
        /* Non-storage: TPM_ALG_NULL */
        ret = heim_store_uint16(sp, TPM2_ALG_NULL);
        if (ret) return ret;
    }

    /* scheme (TPMT_RSA_SCHEME) */
    ret = heim_store_uint16(sp, scheme_alg);
    if (ret) return ret;
    if (scheme_alg != TPM2_ALG_NULL) {
        /* hashAlg for the scheme */
        ret = heim_store_uint16(sp, TPM2_ALG_SHA256);
        if (ret) return ret;
    }

    /* keyBits */
    ret = heim_store_uint16(sp, key_bits);
    if (ret) return ret;

    /* exponent (0 = default) */
    ret = heim_store_uint32(sp, 0);
    if (ret) return ret;

    /* --- unique (TPM2B_PUBLIC_KEY_RSA) --- */
    /* Empty for creation template (TPM generates the key) */
    ret = htpm2_marshal_tpm2b(sp, NULL, 0);
    return ret;
}

/*
 * Marshal an ECC TPMT_PUBLIC into storage.
 *
 * ECC parameters:
 *   symmetric:   TPMT_SYM_DEF_OBJECT
 *   scheme:      TPMT_ECC_SCHEME
 *   curveID:     uint16
 *   kdf:         TPMT_KDF_SCHEME (usually NULL)
 *
 * ECC unique:
 *   TPMS_ECC_POINT { TPM2B x, TPM2B y } (zeros for Create)
 */
static int
marshal_ecc_template(heim_storage *sp, uint16_t curve_id,
                     uint32_t attrs, uint16_t scheme_alg,
                     const void *policy, size_t policy_len)
{
    int ret;
    /* type = TPM2_ALG_ECC */
    ret = heim_store_uint16(sp, TPM2_ALG_ECC);
    if (ret) return ret;

    /* nameAlg = SHA-256 */
    ret = heim_store_uint16(sp, TPM2_ALG_SHA256);
    if (ret) return ret;

    /* objectAttributes */
    ret = heim_store_uint32(sp, attrs);
    if (ret) return ret;

    /* authPolicy */
    ret = htpm2_marshal_tpm2b(sp, policy, policy_len);
    if (ret) return ret;

    /* --- parameters (TPMS_ECC_PARMS) --- */

    /* symmetric */
    if (attrs & TPMA_OBJECT_RESTRICTED && attrs & TPMA_OBJECT_DECRYPT) {
        ret = heim_store_uint16(sp, TPM2_ALG_AES);
        if (ret) return ret;
        ret = heim_store_uint16(sp, 128);
        if (ret) return ret;
        ret = heim_store_uint16(sp, TPM2_ALG_CFB);
        if (ret) return ret;
    } else {
        ret = heim_store_uint16(sp, TPM2_ALG_NULL);
        if (ret) return ret;
    }

    /* scheme */
    ret = heim_store_uint16(sp, scheme_alg);
    if (ret) return ret;
    if (scheme_alg != TPM2_ALG_NULL) {
        ret = heim_store_uint16(sp, TPM2_ALG_SHA256);
        if (ret) return ret;
    }

    /* curveID */
    ret = heim_store_uint16(sp, curve_id);
    if (ret) return ret;

    /* kdf = TPM_ALG_NULL */
    ret = heim_store_uint16(sp, TPM2_ALG_NULL);
    if (ret) return ret;

    /* --- unique (TPMS_ECC_POINT) --- */
    /* Empty x and y for creation template */
    ret = htpm2_marshal_tpm2b(sp, NULL, 0);  /* x */
    if (ret) return ret;
    ret = htpm2_marshal_tpm2b(sp, NULL, 0);  /* y */
    return ret;
}

/* ECC curve IDs */
#define TPM2_ECC_NIST_P256  0x0003
#define TPM2_ECC_NIST_P384  0x0004

/*
 * Marshal a TPMT_PUBLIC for the given key type into storage.
 * This is the inPublic.publicArea for CreatePrimary/Create.
 */
int
htpm2_marshal_key_template(heim_storage *sp, htpm2_key_type type,
                           const void *policy, size_t policy_len)
{
    return htpm2_marshal_key_template_attrs(sp, type, 0, policy, policy_len);
}

/*
 * Like htpm2_marshal_key_template but with explicit attribute overrides.
 *
 * If attrs_override is non-zero, it replaces the default attributes
 * for the key type entirely.
 */
int
htpm2_marshal_key_template_attrs(heim_storage *sp, htpm2_key_type type,
                                 uint32_t attrs_override,
                                 const void *policy, size_t policy_len)
{
    uint32_t attrs;

    switch (type) {
    case HTPM2_KEY_RSA_2048_SIGN:
        attrs = attrs_override ? attrs_override : ATTRS_SIGNING;
        return marshal_rsa_template(sp, 2048, attrs,
                                    TPM2_ALG_RSASSA, policy, policy_len);
    case HTPM2_KEY_RSA_2048_DECRYPT:
        attrs = attrs_override ? attrs_override : ATTRS_DECRYPT;
        return marshal_rsa_template(sp, 2048, attrs,
                                    TPM2_ALG_OAEP, policy, policy_len);
    case HTPM2_KEY_RSA_2048_STORAGE:
        attrs = attrs_override ? attrs_override : ATTRS_STORAGE;
        return marshal_rsa_template(sp, 2048, attrs,
                                    TPM2_ALG_NULL, policy, policy_len);
    case HTPM2_KEY_RSA_3072_SIGN:
        attrs = attrs_override ? attrs_override : ATTRS_SIGNING;
        return marshal_rsa_template(sp, 3072, attrs,
                                    TPM2_ALG_RSASSA, policy, policy_len);
    case HTPM2_KEY_RSA_3072_DECRYPT:
        attrs = attrs_override ? attrs_override : ATTRS_DECRYPT;
        return marshal_rsa_template(sp, 3072, attrs,
                                    TPM2_ALG_OAEP, policy, policy_len);
    case HTPM2_KEY_RSA_3072_STORAGE:
        attrs = attrs_override ? attrs_override : ATTRS_STORAGE;
        return marshal_rsa_template(sp, 3072, attrs,
                                    TPM2_ALG_NULL, policy, policy_len);
    case HTPM2_KEY_ECC_P256_SIGN:
        attrs = attrs_override ? attrs_override : ATTRS_SIGNING;
        return marshal_ecc_template(sp, TPM2_ECC_NIST_P256, attrs,
                                    TPM2_ALG_ECDSA, policy, policy_len);
    case HTPM2_KEY_ECC_P256_DECRYPT:
        attrs = attrs_override ? attrs_override : ATTRS_DECRYPT;
        return marshal_ecc_template(sp, TPM2_ECC_NIST_P256, attrs,
                                    TPM2_ALG_ECDH, policy, policy_len);
    case HTPM2_KEY_ECC_P256_STORAGE:
        attrs = attrs_override ? attrs_override : ATTRS_STORAGE;
        return marshal_ecc_template(sp, TPM2_ECC_NIST_P256, attrs,
                                    TPM2_ALG_NULL, policy, policy_len);
    case HTPM2_KEY_ECC_P384_SIGN:
        attrs = attrs_override ? attrs_override : ATTRS_SIGNING;
        return marshal_ecc_template(sp, TPM2_ECC_NIST_P384, attrs,
                                    TPM2_ALG_ECDSA, policy, policy_len);
    case HTPM2_KEY_ECC_P384_DECRYPT:
        attrs = attrs_override ? attrs_override : ATTRS_DECRYPT;
        return marshal_ecc_template(sp, TPM2_ECC_NIST_P384, attrs,
                                    TPM2_ALG_ECDH, policy, policy_len);
    case HTPM2_KEY_ECC_P384_STORAGE:
        attrs = attrs_override ? attrs_override : ATTRS_STORAGE;
        return marshal_ecc_template(sp, TPM2_ECC_NIST_P384, attrs,
                                    TPM2_ALG_NULL, policy, policy_len);
    default:
        return EINVAL;
    }
}
