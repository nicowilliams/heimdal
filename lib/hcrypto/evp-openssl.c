/*
 * Copyright (c) 2015, Secure Endpoints Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* OpenSSL provider */

#include "config.h"
#include <roken.h>
#include <heimbase.h>

#include <assert.h>

#ifdef HAVE_HCRYPTO_W_OPENSSL

/*
 * This is the OpenSSL 1.x backend for hcrypto.  It has been tested with
 * OpenSSL 1.0.1f and OpenSSL 1.1.0-pre3-dev.
 *
 * NOTE: In order for this to work with OpenSSL 1.1.x and up, it is
 *       critical to use opaque OpenSSL type accessors everywhere /
 *       never use knowledge of opaque OpenSSL type internals.
 */

/*
 * XXX These symbol renamings belong in bn.h and elsewhere.  It is a bug
 * elsewhere in hcrypto that we need them here at all.  See below.
 */
#define BIGNUM hc_BIGNUM
#define BN_CTX hc_BN_CTX
#define BN_BLINDING hc_BN_BLINDING
#define BN_MONT_CTX hc_BN_MONT_CTX
#define BN_GENCB hc_BN_GENCB
#define DH hc_DH

#define DH_METHOD hc_DH_METHOD
#define DSA hc_DSA
#define DSA_METHOD hc_DSA_METHOD
#define RSA hc_RSA
#define RSA_METHOD hc_RSA_METHOD
#define RAND_METHOD hc_RAND_METHOD
#define ENGINE hc_ENGINE

#include <evp.h>
#include <evp-hcrypto.h>
#include <evp-openssl.h>

/*
 * This being an OpenSSL backend for hcrypto... we need to be able to
 * refer to types and objects (functions) from both, OpenSSL and
 * hcrypto.  
 * 
 * The hcrypto API is *very* similar to the OpenSSL 1.0.x API, with the
 * same type and symbol names in many cases, except that the hcrypto
 * names are prefixed with hc_*.  hcrypto has convenience macros that
 * provide OpenSSL aliases for the hcrypto interfaces, and hcrypto
 * applications are expected to use the OpenSSL names.
 *
 * Since here we must be able to refer to types and objects from both
 * OpenSSL and from hcrypto, we disable the hcrypto renaming for the
 * rest of this file.  These #undefs could be collected into an
 * <hcrypto/undef.h> for the purpose of permitting other applications to
 * use both, hcrypto and OpenSSL in the same source files (provided that
 * such applications refer to hcrypto types and objects by their proper
 * hc_-prefixed names).
 */
#undef BIGNUM
#undef BN_CTX
#undef BN_BLINDING
#undef BN_MONT_CTX
#undef BN_GENCB
#undef DH
#undef DH_METHOD
#undef DSA
#undef DSA_METHOD
#undef RSA
#undef RSA_METHOD
#undef RAND_METHOD
#undef ENGINE

#undef BN_GENCB_call
#undef BN_GENCB_set
#undef BN_CTX_new
#undef BN_CTX_free
#undef BN_CTX_start
#undef BN_CTX_get
#undef BN_CTX_end
#undef BN_is_negative
#undef BN_rand
#undef BN_num_bits
#undef BN_num_bytes
#undef BN_new
#undef BN_clear_free
#undef BN_bin2bn
#undef BN_bn2bin
#undef BN_uadd
#undef BN_set_negative
#undef BN_set_word
#undef BN_get_word
#undef BN_cmp
#undef BN_free
#undef BN_is_bit_set
#undef BN_clear
#undef BN_dup
#undef BN_set_bit
#undef BN_clear_bit
#undef BN_bn2hex
#undef BN_hex2bn

#undef EVP_CIPHER_CTX_block_size
#undef EVP_CIPHER_CTX_cipher
#undef EVP_CIPHER_CTX_cleanup
#undef EVP_CIPHER_CTX_flags
#undef EVP_CIPHER_CTX_get_app_data
#undef EVP_CIPHER_CTX_init
#undef EVP_CIPHER_CTX_iv_length
#undef EVP_CIPHER_CTX_key_length
#undef EVP_CIPHER_CTX_mode
#undef EVP_CIPHER_CTX_set_app_data
#undef EVP_CIPHER_CTX_set_key_length
#undef EVP_CIPHER_CTX_set_padding
#undef EVP_CIPHER_block_size
#undef EVP_CIPHER_iv_length
#undef EVP_CIPHER_key_length
#undef EVP_Cipher
#undef EVP_CipherInit_ex
#undef EVP_CipherUpdate
#undef EVP_CipherFinal_ex
#undef EVP_Digest
#undef EVP_DigestFinal_ex
#undef EVP_DigestInit_ex
#undef EVP_DigestUpdate
#undef EVP_MD_CTX_block_size
#undef EVP_MD_CTX_cleanup
#undef EVP_MD_CTX_create
#undef EVP_MD_CTX_init
#undef EVP_MD_CTX_destroy
#undef EVP_MD_CTX_md
#undef EVP_MD_CTX_size
#undef EVP_MD_block_size
#undef EVP_MD_size
#undef EVP_aes_128_cbc
#undef EVP_aes_192_cbc
#undef EVP_aes_256_cbc
#undef EVP_aes_128_cfb8
#undef EVP_aes_192_cfb8
#undef EVP_aes_256_cfb8

#undef EVP_des_cbc
#undef EVP_des_ede3_cbc
#undef EVP_enc_null
#undef EVP_md2
#undef EVP_md4
#undef EVP_md5
#undef EVP_md_null
#undef EVP_rc2_40_cbc
#undef EVP_rc2_64_cbc
#undef EVP_rc2_cbc
#undef EVP_rc4
#undef EVP_rc4_40
#undef EVP_camellia_128_cbc
#undef EVP_camellia_192_cbc
#undef EVP_camellia_256_cbc
#undef EVP_sha
#undef EVP_sha1
#undef EVP_sha256
#undef EVP_sha384
#undef EVP_sha512
#undef PKCS5_PBKDF2_HMAC_SHA1
#undef EVP_BytesToKey
#undef EVP_get_cipherbyname
#undef OpenSSL_add_all_algorithms
#undef OpenSSL_add_all_algorithms_conf
#undef OpenSSL_add_all_algorithms_noconf
#undef EVP_CIPHER_CTX_ctrl
#undef EVP_CIPHER_CTX_rand_key
#undef hcrypto_validate

#undef EVP_MD_CTX
#undef EVP_PKEY
#undef EVP_MD
#undef EVP_CIPHER
#undef EVP_CIPHER_CTX

#undef EVP_CIPH_STREAM_CIPHER
#undef EVP_CIPH_CBC_MODE
#undef EVP_CIPH_CFB8_MODE
#undef EVP_CIPH_MODE
#undef EVP_CIPH_CTRL_INIT

#undef EVP_CTRL_INIT

#undef EVP_CIPH_VARIABLE_LENGTH
#undef EVP_CIPH_ALWAYS_CALL_INIT
#undef EVP_CIPH_RAND_KEY

#undef EVP_CTRL_RAND_KEY

#undef NID_md2
#undef NID_md4
#undef NID_md5
#undef NID_sha1
#undef NID_sha256
#undef NID_sha384
#undef NID_sha512


/* Now it's safe to include OpenSSL headers */
#include <openssl/evp.h>

/* A HEIM_BASE_ONCE argument struct for per-EVP one-time initialization */
struct once_init_cipher_ctx {
    hc_EVP_CIPHER **hc_memoizep;    /* ptr to static ptr to hc_EVP_CIPHER */
    hc_EVP_CIPHER *hc_memoize;      /* ptr to static hc_EVP_CIPHER */
    unsigned long flags;
    const EVP_CIPHER *(*f)(void);
};

/* Our wrapper for OpenSSL EVP_CIPHER_CTXs */
struct ossl_cipher_ctx {
    EVP_CIPHER_CTX      *ossl_cipher_ctx;   /* OpenSSL cipher ctx */
    const EVP_CIPHER    *ossl_cipher;       /* OpenSSL cipher */
    int                 initialized;
};

/*
 * Our hc_EVP_CIPHER init() method; wraps around OpenSSL
 * EVP_CipherInit_ex().
 *
 * This is very similar to the init() function pointer in an OpenSSL
 * EVP_CIPHER, but a) we can't access them in 1.1, and b) the method
 * invocation protocols in hcrypto and OpenSSL are similar but not the
 * same, thus we must have this wrapper.
 */
static int
cipher_ctx_init(hc_EVP_CIPHER_CTX *ctx, const unsigned char *key,
                const unsigned char *iv, int enc)
{
    struct ossl_cipher_ctx *ossl_ctx = ctx->cipher_data; /* EVP_CIPHER_CTX wrapper */
    const EVP_CIPHER *c;

    assert(ossl_ctx != NULL);
    assert(ctx->cipher != NULL);
    assert(ctx->cipher->app_data != NULL);

    /*
     * Here be dragons.
     *
     * We need to make sure that the OpenSSL EVP_CipherInit_ex() is
     * called with cipher!=NULL just once per EVP_CIPHER_CTX, otherwise
     * state in the OpenSSL EVP_CIPHER_CTX will get cleaned up and then
     * we'll segfault.
     *
     * hcrypto applications can re-initialize an (hc_)EVP_CIPHER_CTX as
     * usual by calling (hc)EVP_CipherInit_ex() with a non-NULL cipher
     * argument, and that will cause cipher_cleanup() (below) to be
     * called.
     */
    c = ossl_ctx->ossl_cipher = ctx->cipher->app_data; /* OpenSSL's EVP_CIPHER * */
    if (!ossl_ctx->initialized) {
        ossl_ctx->ossl_cipher_ctx = EVP_CIPHER_CTX_new();
        if (ossl_ctx->ossl_cipher_ctx == NULL)
            return 0;
        /*
         * So we always call EVP_CipherInit_ex() with c!=NULL, but other
         * things NULL...
         */
        if (!EVP_CipherInit_ex(ossl_ctx->ossl_cipher_ctx, c, NULL, NULL, NULL, enc))
            return 0;
        ossl_ctx->initialized = 1;
    }

    /* ...and from here on always call EVP_CipherInit_ex() with c=NULL */
    if ((ctx->cipher->flags & hc_EVP_CIPH_VARIABLE_LENGTH) &&
        ctx->key_len > 0)
        EVP_CIPHER_CTX_set_key_length(ossl_ctx->ossl_cipher_ctx, ctx->key_len);

    return EVP_CipherInit_ex(ossl_ctx->ossl_cipher_ctx, NULL, NULL, key, iv, enc);
}

static int
cipher_do_cipher(hc_EVP_CIPHER_CTX *ctx, unsigned char *out,
                 const unsigned char *in, unsigned int len)
{
    struct ossl_cipher_ctx *ossl_ctx = ctx->cipher_data;
    int ret;

    assert(ossl_ctx != NULL);
    ret = EVP_Cipher(ossl_ctx->ossl_cipher_ctx, out, in, len);
    return ret;
}

static int
cipher_cleanup(hc_EVP_CIPHER_CTX *ctx)
{
    struct ossl_cipher_ctx *ossl_ctx = ctx->cipher_data;

    if (ossl_ctx == NULL || !ossl_ctx->initialized)
        return 1;

    if (ossl_ctx->ossl_cipher_ctx != NULL)
        EVP_CIPHER_CTX_free(ossl_ctx->ossl_cipher_ctx);

    ossl_ctx->ossl_cipher_ctx = NULL;
    ossl_ctx->ossl_cipher = NULL;
    ossl_ctx->initialized = 0;
    return 1;
}

static int
cipher_ctrl(hc_EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    struct ossl_cipher_ctx *ossl_ctx = ctx->cipher_data;
    const EVP_CIPHER *c;

    assert(ossl_ctx != NULL);
    assert(ctx->cipher != NULL);
    assert(ctx->cipher->app_data != NULL);

    c = ctx->cipher->app_data;

    return EVP_CIPHER_CTX_ctrl(ossl_ctx->ossl_cipher_ctx, type, arg, ptr);
}


static void
get_EVP_CIPHER_once_cb(void *d)
{
    struct once_init_cipher_ctx *arg = d;
    const EVP_CIPHER *ossl_evp;
    hc_EVP_CIPHER *hc_evp;

    hc_evp = arg->hc_memoize;

    /*
     * XXX This can cause dynamic linking to fail when using LD_LIBRARY_PATH/
     * LD_PRELOAD, or on update, when the libcrypto chosen at run-time does not
     * have a given EVP_CIPHER.
     *
     * XXX Use an EVP lookup by name/OID/NID with EVP_get_cipherbyname(),
     * EVP_get_cipherbyobj(), or EVP_get_cipherbynid().  NIDs and OIDs seem to
     * be the most stable interfaces to EVPs.  (Even though internally these
     * may get mapped to names then to EVP_CIPHERs.)
     */
    ossl_evp = arg->f();

    if (ossl_evp == NULL) {
        (void) memset(hc_evp, 0, sizeof(*hc_evp));
        *arg->hc_memoizep = NULL;
        return;
    }

    /* Build the hc_EVP_CIPHER */
    hc_evp->nid = EVP_CIPHER_nid(ossl_evp); /* We would an hcrypto NIDs if we had them */
    hc_evp->block_size = EVP_CIPHER_block_size(ossl_evp);
    hc_evp->key_len = EVP_CIPHER_key_length(ossl_evp);
    hc_evp->iv_len = EVP_CIPHER_iv_length(ossl_evp);

    /*
     * We force hc_EVP_CipherInit_ex to always call our init() function,
     * otherwise we don't get a chance to call EVP_CipherInit_ex()
     * correctly.
     */
    hc_evp->flags = hc_EVP_CIPH_ALWAYS_CALL_INIT | arg->flags;

    /* Our cipher context */
    hc_evp->ctx_size = sizeof(struct ossl_cipher_ctx);

    /* Our wrappers */
    hc_evp->init = cipher_ctx_init;
    hc_evp->do_cipher = cipher_do_cipher;
    hc_evp->cleanup = cipher_cleanup;
    hc_evp->set_asn1_parameters = NULL;
    hc_evp->get_asn1_parameters = NULL;
    hc_evp->ctrl = cipher_ctrl;

    /* Our link to the OpenSSL EVP_CIPHER */
    hc_evp->app_data = (void *)ossl_evp;

    /* Finally, set the static hc_EVP_CIPHER * to the one we just built */
    *arg->hc_memoizep = hc_evp;
}

static hc_EVP_CIPHER *
get_EVP_CIPHER(heim_base_once_t *once, hc_EVP_CIPHER *hc_memoize,
               hc_EVP_CIPHER **hc_memoizep, unsigned long flags,
               const EVP_CIPHER *(*f)(void))
{
    struct once_init_cipher_ctx arg;

    arg.flags = flags;
    arg.hc_memoizep = hc_memoizep;
    arg.hc_memoize = hc_memoize;
    arg.f = f;
    heim_base_once_f(once, &arg, get_EVP_CIPHER_once_cb);
    return *hc_memoizep; /* May be NULL */
}

/* XXX Pass in the NID or construct it via token pasting */
#define OSSL_CIPHER_ALGORITHM(name, flags)                              \
    const hc_EVP_CIPHER *hc_EVP_ossl_##name(void)                       \
    {                                                                   \
        static hc_EVP_CIPHER ossl_##name##_st;                          \
        static hc_EVP_CIPHER *ossl_##name;                              \
        static heim_base_once_t once = HEIM_BASE_ONCE_INIT;             \
        if (ossl_##name != NULL)                                        \
            return ossl_##name;                                         \
        return get_EVP_CIPHER(&once, &ossl_##name##_st, &ossl_##name,   \
                              flags, EVP_##name);                       \
    }

#define OSSL_CIPHER_ALGORITHM_UNAVAILABLE(name)                         \
    const hc_EVP_CIPHER *hc_EVP_ossl_##name(void)                       \
    {                                                                   \
        return NULL;                                                    \
    }

/* As above, but for EVP_MDs */

struct ossl_md_ctx {
    EVP_MD_CTX          *ossl_md_ctx;       /* OpenSSL md ctx */
    const EVP_MD        *ossl_md;           /* OpenSSL md */
    int                 initialized;
};

static int
ossl_md_init(struct ossl_md_ctx *ctx, const EVP_MD *md)
{
    if (ctx->initialized)
        EVP_MD_CTX_free(ctx->ossl_md_ctx);
    ctx->initialized = 0;

    ctx->ossl_md = md;
    ctx->ossl_md_ctx = EVP_MD_CTX_new();
    if (!EVP_DigestInit(ctx->ossl_md_ctx, md)) {
        EVP_MD_CTX_free(ctx->ossl_md_ctx);
        ctx->ossl_md_ctx = NULL;
        ctx->ossl_md = NULL;
        return 0;
    }
    ctx->initialized = 1;
    return 1;
}

static int
ossl_md_update(hc_EVP_MD_CTX *d, const void *data, size_t count)
{
    struct ossl_md_ctx *ctx = (void *)d;

    return EVP_DigestUpdate(ctx->ossl_md_ctx, data, count);
}

static int
ossl_md_final(void *md_data, hc_EVP_MD_CTX *d)
{
    struct ossl_md_ctx *ctx = (void *)d;

    return EVP_DigestFinal(ctx->ossl_md_ctx, md_data, NULL);
}

static int
ossl_md_cleanup(hc_EVP_MD_CTX *d)
{
    struct ossl_md_ctx *ctx = (void *)d;

    if (!ctx->initialized)
        return 1;
    EVP_MD_CTX_free(ctx->ossl_md_ctx);
    ctx->ossl_md = NULL;
    ctx->initialized = 0;

    return 1;
}

struct once_init_md_ctx {
    const EVP_MD **ossl_memoizep;
    hc_EVP_MD **hc_memoizep;
    hc_EVP_MD *hc_memoize;
    hc_evp_md_init md_init;
    int block_size;
    int hash_size;
    const EVP_MD *(*f)(void);
};

static void
get_EVP_MD_once_cb(void *d)
{
    struct once_init_md_ctx *ctx = d;
    const EVP_MD *ossl_evp;
    hc_EVP_MD *hc_evp;

    hc_evp = ctx->hc_memoize;
    *ctx->ossl_memoizep = ossl_evp = ctx->f();

    if (ossl_evp == NULL) {
        (void) memset(hc_evp, 0, sizeof(*hc_evp));
        *ctx->hc_memoizep = NULL;
        return;
    }

    assert(ctx->block_size == EVP_MD_block_size(ossl_evp));
    assert(ctx->hash_size == EVP_MD_size(ossl_evp));

    /* Build the hc_EVP_MD */
    hc_evp->block_size = ctx->block_size;
    hc_evp->hash_size = ctx->hash_size;
    hc_evp->ctx_size = sizeof(struct ossl_md_ctx);
    hc_evp->init = ctx->md_init;
    hc_evp->update = ossl_md_update;
    hc_evp->final = ossl_md_final;
    hc_evp->cleanup = ossl_md_cleanup;

    *ctx->hc_memoizep = hc_evp;
}

static hc_EVP_MD *
get_EVP_MD(heim_base_once_t *once, hc_EVP_MD *hc_memoize,
           hc_EVP_MD **hc_memoizep, const EVP_MD **ossl_memoizep,
           hc_evp_md_init md_init, int hash_size, int block_size,
           const EVP_MD *(*f)(void))
{
    struct once_init_md_ctx ctx;

    ctx.ossl_memoizep = ossl_memoizep;
    ctx.hc_memoizep = hc_memoizep;
    ctx.hc_memoize = hc_memoize;
    ctx.md_init = md_init;
    ctx.block_size = block_size;
    ctx.hash_size = hash_size;
    ctx.f = f;
    heim_base_once_f(once, &ctx, get_EVP_MD_once_cb);
    return *hc_memoizep; /* May be NULL */
}

#define OSSL_MD_ALGORITHM(name, hs, bs)                                 \
    static const EVP_MD *ossl_EVP_##name;                               \
    static hc_EVP_MD *ossl_##name;                                      \
    static int ossl_init_##name(hc_EVP_MD_CTX *d)                       \
    {                                                                   \
        return ossl_md_init((void *)d, ossl_EVP_##name);                \
    }                                                                   \
    const hc_EVP_MD *hc_EVP_ossl_##name(void)                           \
    {                                                                   \
        static hc_EVP_MD ossl_##name##_st;                              \
        static heim_base_once_t once = HEIM_BASE_ONCE_INIT;             \
        return get_EVP_MD(&once, &ossl_##name##_st, &ossl_##name,       \
                          &ossl_EVP_##name, ossl_init_##name, hs, bs,   \
                          EVP_##name);                                  \
    }

#define OSSL_MD_ALGORITHM_UNAVAILABLE(name)                             \
    const hc_EVP_MD *hc_EVP_ossl_##name(void)                           \
    {                                                                   \
        return NULL;                                                    \
    }

/**
 * The triple DES cipher type (OpenSSL provider)
 *
 * @return the DES-EDE3-CBC EVP_CIPHER pointer.
 *
 * @ingroup hcrypto_evp
 */
#ifdef OPENSSL_NO_DES
OSSL_CIPHER_ALGORITHM_UNAVAILABLE(des_ede3_cbc)
#else
OSSL_CIPHER_ALGORITHM(des_ede3_cbc, hc_EVP_CIPH_CBC_MODE)
#endif

/**
 * The DES cipher type (OpenSSL provider)
 *
 * @return the DES-CBC EVP_CIPHER pointer.
 *
 * @ingroup hcrypto_evp
 */
#ifdef OPENSSL_NO_DES
OSSL_CIPHER_ALGORITHM_UNAVAILABLE(des_cbc)
#else
OSSL_CIPHER_ALGORITHM(des_cbc, hc_EVP_CIPH_CBC_MODE)
#endif

/**
 * The AES-128 cipher type (OpenSSL provider)
 *
 * @return the AES-128-CBC EVP_CIPHER pointer.
 *
 * @ingroup hcrypto_evp
 */
#ifdef OPENSSL_NO_AES
OSSL_CIPHER_ALGORITHM_UNAVAILABLE(aes_128_cbc)
#else
OSSL_CIPHER_ALGORITHM(aes_128_cbc, hc_EVP_CIPH_CBC_MODE)
#endif

/**
 * The AES-192 cipher type (OpenSSL provider)
 *
 * @return the AES-192-CBC EVP_CIPHER pointer.
 *
 * @ingroup hcrypto_evp
 */
#ifdef OPENSSL_NO_AES
OSSL_CIPHER_ALGORITHM_UNAVAILABLE(aes_192_cbc)
#else
OSSL_CIPHER_ALGORITHM(aes_192_cbc, hc_EVP_CIPH_CBC_MODE)
#endif

/**
 * The AES-256 cipher type (OpenSSL provider)
 *
 * @return the AES-256-CBC EVP_CIPHER pointer.
 *
 * @ingroup hcrypto_evp
 */
#ifdef OPENSSL_NO_AES
OSSL_CIPHER_ALGORITHM_UNAVAILABLE(aes_256_cbc)
#else
OSSL_CIPHER_ALGORITHM(aes_256_cbc, hc_EVP_CIPH_CBC_MODE)
#endif

/**
 * The AES-128 CFB8 cipher type (OpenSSL provider)
 *
 * @return the AES-128-CFB8 EVP_CIPHER pointer.
 *
 * @ingroup hcrypto_evp
 */
#ifdef OPENSSL_NO_AES
OSSL_CIPHER_ALGORITHM_UNAVAILABLE(aes_128_cfb8)
#else
OSSL_CIPHER_ALGORITHM(aes_128_cfb8, hc_EVP_CIPH_CFB8_MODE)
#endif

/**
 * The AES-192 CFB8 cipher type (OpenSSL provider)
 *
 * @return the AES-192-CFB8 EVP_CIPHER pointer.
 *
 * @ingroup hcrypto_evp
 */
#ifdef OPENSSL_NO_AES
OSSL_CIPHER_ALGORITHM_UNAVAILABLE(aes_192_cfb8)
#else
OSSL_CIPHER_ALGORITHM(aes_192_cfb8, hc_EVP_CIPH_CFB8_MODE)
#endif

/**
 * The AES-256 CFB8 cipher type (OpenSSL provider)
 *
 * @return the AES-256-CFB8 EVP_CIPHER pointer.
 *
 * @ingroup hcrypto_evp
 */
#ifdef OPENSSL_NO_AES
OSSL_CIPHER_ALGORITHM_UNAVAILABLE(aes_256_cfb8)
#else
OSSL_CIPHER_ALGORITHM(aes_256_cfb8, hc_EVP_CIPH_CFB8_MODE)
#endif

/**
 * The RC2 cipher type - OpenSSL
 *
 * @return the RC2 EVP_CIPHER pointer.
 *
 * @ingroup hcrypto_evp
 */
#ifdef OPENSSL_NO_RC2
OSSL_CIPHER_ALGORITHM_UNAVAILABLE(rc2_cbc)
#else
OSSL_CIPHER_ALGORITHM(rc2_cbc,
                      hc_EVP_CIPH_CBC_MODE |
                      hc_EVP_CIPH_VARIABLE_LENGTH)
#endif

/**
 * The RC2-40 cipher type - OpenSSL
 *
 * @return the RC2-40 EVP_CIPHER pointer.
 *
 * @ingroup hcrypto_evp
 */
#ifdef OPENSSL_NO_RC2
OSSL_CIPHER_ALGORITHM_UNAVAILABLE(rc2_40_cbc)
#else
OSSL_CIPHER_ALGORITHM(rc2_40_cbc,
                      hc_EVP_CIPH_CBC_MODE)
#endif

/**
 * The RC2-64 cipher type - OpenSSL
 *
 * @return the RC2-64 EVP_CIPHER pointer.
 *
 * @ingroup hcrypto_evp
 */
#ifdef OPENSSL_NO_RC2
OSSL_CIPHER_ALGORITHM_UNAVAILABLE(rc2_64_cbc)
#else
OSSL_CIPHER_ALGORITHM(rc2_64_cbc,
                      hc_EVP_CIPH_CBC_MODE |
                      hc_EVP_CIPH_VARIABLE_LENGTH)
#endif

/**
 * The Camellia-128 cipher type - OpenSSL
 *
 * @return the Camellia-128 EVP_CIPHER pointer.
 *
 * @ingroup hcrypto_evp
 */
#ifdef OPENSSL_NO_CAMELLIA
OSSL_CIPHER_ALGORITHM_UNAVAILABLE(camellia_128_cbc)
#else
OSSL_CIPHER_ALGORITHM(camellia_128_cbc, hc_EVP_CIPH_CBC_MODE)
#endif

/**
 * The Camellia-198 cipher type - OpenSSL
 *
 * @return the Camellia-198 EVP_CIPHER pointer.
 *
 * @ingroup hcrypto_evp
 */
#ifdef OPENSSL_NO_CAMELLIA
OSSL_CIPHER_ALGORITHM_UNAVAILABLE(camellia_192_cbc)
#else
OSSL_CIPHER_ALGORITHM(camellia_192_cbc, hc_EVP_CIPH_CBC_MODE)
#endif

/**
 * The Camellia-256 cipher type - OpenSSL
 *
 * @return the Camellia-256 EVP_CIPHER pointer.
 *
 * @ingroup hcrypto_evp
 */
#ifdef OPENSSL_NO_CAMELLIA
OSSL_CIPHER_ALGORITHM_UNAVAILABLE(camellia_256_cbc)
#else
OSSL_CIPHER_ALGORITHM(camellia_256_cbc, hc_EVP_CIPH_CBC_MODE)
#endif

/**
 * The RC4 cipher type (OpenSSL provider)
 *
 * @return the RC4 EVP_CIPHER pointer.
 *
 * @ingroup hcrypto_evp
 */
#ifdef OPENSSL_NO_RC4
OSSL_CIPHER_ALGORITHM_UNAVAILABLE(rc4)
#else
OSSL_CIPHER_ALGORITHM(rc4,
                      hc_EVP_CIPH_STREAM_CIPHER |
                      hc_EVP_CIPH_VARIABLE_LENGTH)
#endif

/**
 * The RC4-40 cipher type (OpenSSL provider)
 *
 * @return the RC4 EVP_CIPHER pointer.
 *
 * @ingroup hcrypto_evp
 */
#ifdef OPENSSL_NO_RC4
OSSL_CIPHER_ALGORITHM_UNAVAILABLE(rc4_40)
#else
OSSL_CIPHER_ALGORITHM(rc4_40,
                      hc_EVP_CIPH_STREAM_CIPHER |
                      hc_EVP_CIPH_VARIABLE_LENGTH)
#endif

/**
 * The MD2 hash algorithm (OpenSSL provider)
 *
 * @return the MD2 EVP_MD pointer.
 *
 * @ingroup hcrypto_evp
 */
#ifdef OPENSSL_NO_MD2
OSSL_MD_ALGORITHM_UNAVAILABLE(md2)
#else
OSSL_MD_ALGORITHM(md2, 16, 16)
#endif

/**
 * The MD4 hash algorithm (OpenSSL provider)
 *
 * @return the MD4 EVP_MD pointer.
 *
 * @ingroup hcrypto_evp
 */
#ifdef OPENSSL_NO_MD4
OSSL_MD_ALGORITHM_UNAVAILABLE(md4)
#else
OSSL_MD_ALGORITHM(md4, 16, 64)
#endif

/**
 * The MD5 hash algorithm (OpenSSL provider)
 *
 * @return the MD5 EVP_MD pointer.
 *
 * @ingroup hcrypto_evp
 */
#ifdef OPENSSL_NO_MD5
OSSL_MD_ALGORITHM_UNAVAILABLE(md5)
#else
OSSL_MD_ALGORITHM(md5, 16, 64)
#endif

/**
 * The SHA-1 hash algorithm (OpenSSL provider)
 *
 * @return the SHA-1 EVP_MD pointer.
 *
 * @ingroup hcrypto_evp
 */
#ifdef OPENSSL_NO_SHA1
OSSL_MD_ALGORITHM_UNAVAILABLE(sha1)
#else
OSSL_MD_ALGORITHM(sha1, 20, 64)
#endif

/**
 * The SHA-256 hash algorithm (OpenSSL provider)
 *
 * @return the SHA-256 EVP_MD pointer.
 *
 * @ingroup hcrypto_evp
 */
#ifdef OPENSSL_NO_SHA
OSSL_MD_ALGORITHM_UNAVAILABLE(sha256)
#else
OSSL_MD_ALGORITHM(sha256, 32, 64)
#endif

/**
 * The SHA-384 hash algorithm (OpenSSL provider)
 *
 * @return the SHA-384 EVP_MD pointer.
 *
 * @ingroup hcrypto_evp
 */
#ifdef OPENSSL_NO_SHA
OSSL_MD_ALGORITHM_UNAVAILABLE(sha384)
#else
OSSL_MD_ALGORITHM(sha384, 48, 128)
#endif

/**
 * The SHA-512 hash algorithm (OpenSSL provider)
 *
 * @return the SHA-512 EVP_MD pointer.
 *
 * @ingroup hcrypto_evp
 */
#ifdef OPENSSL_NO_SHA
OSSL_MD_ALGORITHM_UNAVAILABLE(sha512)
#else
OSSL_MD_ALGORITHM(sha512, 64, 128)
#endif

#else /* HAVE_HCRYPTO_W_OPENSSL */
static char dummy;
#endif /* HAVE_HCRYPTO_W_OPENSSL */
