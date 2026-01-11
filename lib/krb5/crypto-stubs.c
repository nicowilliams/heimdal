/*
 * Copyright (c) 1997 - 2008 Kungliga Tekniska Högskolan
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

#include <krb5_locl.h>

/* These are stub functions for the standalone RFC3961 crypto library */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_init_context(krb5_context *context)
{
    krb5_context p;
    krb5_context_ossl ossl;

    *context = NULL;

    /* should have a run_once */
    bindtextdomain(HEIMDAL_TEXTDOMAIN, HEIMDAL_LOCALEDIR);

    p = calloc(1, sizeof(*p));
    if(!p)
        return ENOMEM;

    /* Initialize minimal OpenSSL context for crypto operations */
    ossl = calloc(1, sizeof(*ossl));
    if (ossl == NULL) {
        free(p);
        return ENOMEM;
    }
    ossl->libctx = OSSL_LIB_CTX_get0_global_default();
    ossl->openssl_leg = OSSL_PROVIDER_load(ossl->libctx, "legacy");
    ossl->openssl_def = OSSL_PROVIDER_load(ossl->libctx, "default");
    ossl->des_cbc = EVP_CIPHER_fetch(ossl->libctx, "DES-CBC", NULL);
    ossl->des_ede3_cbc = EVP_CIPHER_fetch(ossl->libctx, "DES-EDE3-CBC", NULL);
    ossl->rc4 = EVP_CIPHER_fetch(ossl->libctx, "RC4", NULL);
    ossl->aes128_cbc = EVP_CIPHER_fetch(ossl->libctx, "AES-128-CBC", NULL);
    ossl->aes256_cbc = EVP_CIPHER_fetch(ossl->libctx, "AES-256-CBC", NULL);
    ossl->md4 = EVP_MD_fetch(ossl->libctx, "MD4", NULL);
    ossl->md5 = EVP_MD_fetch(ossl->libctx, "MD5", NULL);
    ossl->sha1 = EVP_MD_fetch(ossl->libctx, "SHA1", NULL);
    ossl->sha256 = EVP_MD_fetch(ossl->libctx, "SHA256", NULL);
    ossl->sha384 = EVP_MD_fetch(ossl->libctx, "SHA384", NULL);
    p->ossl = ossl;

    *context = p;
    return 0;
}

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_free_context(krb5_context context)
{
    krb5_clear_error_message(context);

    if (context->flags & KRB5_CTX_F_SOCKETS_INITIALIZED) {
        rk_SOCK_EXIT();
    }

    /* Clean up OpenSSL context */
    if (context->ossl) {
        EVP_CIPHER_free(context->ossl->des_cbc);
        EVP_CIPHER_free(context->ossl->des_ede3_cbc);
        EVP_CIPHER_free(context->ossl->rc4);
        EVP_CIPHER_free(context->ossl->aes128_cbc);
        EVP_CIPHER_free(context->ossl->aes256_cbc);
        EVP_MD_free(context->ossl->md4);
        EVP_MD_free(context->ossl->md5);
        EVP_MD_free(context->ossl->sha1);
        EVP_MD_free(context->ossl->sha256);
        EVP_MD_free(context->ossl->sha384);
        if (context->ossl->openssl_leg)
            OSSL_PROVIDER_unload(context->ossl->openssl_leg);
        if (context->ossl->openssl_def)
            OSSL_PROVIDER_unload(context->ossl->openssl_def);
        free(context->ossl);
    }

    memset(context, 0, sizeof(*context));
    free(context);
}

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
_krb5_homedir_access(krb5_context context) {
    return 0;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_log(krb5_context context,
         krb5_log_facility *fac,
         int level,
         const char *fmt,
         ...)
{
    return 0;
}

void KRB5_LIB_FUNCTION
_krb5_debug(krb5_context context,
	    int level,
	    const char *fmt,
	    ...)
{
}


/* This function is currently just used to get the location of the EGD
 * socket. If we're not using an EGD, then we can just return NULL */

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_config_get_string (krb5_context context,
                        const krb5_config_section *c,
                        ...)
{
    return NULL;
}
