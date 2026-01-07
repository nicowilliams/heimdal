/*
 * Copyright (c) 2007 Kungliga Tekniska Högskolan
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

#include "hx_locl.h"

#ifdef HAVE_FRAMEWORK_SECURITY

#include <Security/Security.h>

/* Suppress deprecation warnings for SecKeychain APIs - still needed for file-based keychains */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

/*
 * Convert a SecKeyRef to an EVP_PKEY by exporting and re-importing.
 * Returns NULL if the key cannot be exported (e.g., hardware-backed keys).
 */
static EVP_PKEY *
seckey_to_evp_pkey(hx509_context context, SecKeyRef seckey)
{
    CFDictionaryRef attrs = NULL;
    CFDataRef keydata = NULL;
    CFErrorRef error = NULL;
    EVP_PKEY *pkey = NULL;
    CFStringRef keytype;
    const unsigned char *p;

    attrs = SecKeyCopyAttributes(seckey);
    if (attrs == NULL)
        return NULL;

    keytype = CFDictionaryGetValue(attrs, kSecAttrKeyType);
    if (keytype == NULL) {
        CFRelease(attrs);
        return NULL;
    }

    /* Try to export the key - this fails for hardware-backed keys */
    keydata = SecKeyCopyExternalRepresentation(seckey, &error);
    if (keydata == NULL) {
        if (error)
            CFRelease(error);
        CFRelease(attrs);
        return NULL;
    }

    p = CFDataGetBytePtr(keydata);

    if (CFEqual(keytype, kSecAttrKeyTypeRSA)) {
        /* RSA keys are exported in PKCS#1 format */
        pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &p, CFDataGetLength(keydata));
    } else if (CFEqual(keytype, kSecAttrKeyTypeECSECPrimeRandom)) {
        /* EC keys are exported in ANSI X9.63 format, need to convert */
        CFNumberRef keysizeRef;
        int keysize = 0;
        size_t coord_len = 0;
        OSSL_PARAM_BLD *bld = NULL;
        OSSL_PARAM *params = NULL;
        EVP_PKEY_CTX *pctx = NULL;
        BIGNUM *priv = NULL;
        const char *group_name = NULL;

        keysizeRef = CFDictionaryGetValue(attrs, kSecAttrKeySizeInBits);
        if (keysizeRef)
            CFNumberGetValue(keysizeRef, kCFNumberIntType, &keysize);

        switch (keysize) {
        case 256:
            group_name = "prime256v1";
            coord_len = 32;
            break;
        case 384:
            group_name = "secp384r1";
            coord_len = 48;
            break;
        case 521:
            group_name = "secp521r1";
            coord_len = 66;
            break;
        default:
            goto ec_out;
        }

        /*
         * X9.63 private key format: 04 || X || Y || D
         * where X, Y are public key coordinates and D is private key
         */
        if ((size_t)CFDataGetLength(keydata) != 1 + 3 * coord_len)
            goto ec_out;
        if (p[0] != 0x04)
            goto ec_out;

        /* Build EC key using OSSL_PARAM */
        bld = OSSL_PARAM_BLD_new();
        if (bld == NULL)
            goto ec_out;

        /* Private key is after the public point (04 || X || Y) */
        priv = BN_bin2bn(p + 1 + 2 * coord_len, coord_len, NULL);
        if (priv == NULL)
            goto ec_out;

        if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                              group_name, 0) ||
            !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                               p, 1 + 2 * coord_len) ||
            !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv))
            goto ec_out;

        params = OSSL_PARAM_BLD_to_param(bld);
        if (params == NULL)
            goto ec_out;

        pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        if (pctx == NULL)
            goto ec_out;

        if (EVP_PKEY_fromdata_init(pctx) <= 0 ||
            EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0)
            pkey = NULL;

    ec_out:
        BN_free(priv);
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_CTX_free(pctx);
    }

    CFRelease(keydata);
    CFRelease(attrs);
    return pkey;
}

static int
set_private_key(hx509_context context,
                SecKeyRef keyRef,
                hx509_cert cert)
{
    hx509_private_key key;
    EVP_PKEY *pkey;
    int pkey_type;
    int ret;

    pkey = seckey_to_evp_pkey(context, keyRef);
    if (pkey == NULL) {
        /* Key couldn't be exported - likely hardware-backed */
        return 0;
    }

    ret = hx509_private_key_init(&key, NULL, NULL);
    if (ret) {
        EVP_PKEY_free(pkey);
        return ret;
    }

    /* Assign EVP_PKEY directly */
    key->private_key.pkey = pkey;

    /* Set default signature algorithm based on key type */
    pkey_type = EVP_PKEY_base_id(pkey);
    switch (pkey_type) {
    case EVP_PKEY_RSA:
        key->signature_alg = ASN1_OID_ID_PKCS1_SHA256WITHRSAENCRYPTION;
        break;
    case EVP_PKEY_EC:
        key->signature_alg = ASN1_OID_ID_ECDSA_WITH_SHA256;
        break;
    default:
        break;
    }

    _hx509_cert_assign_key(cert, key);

    return 0;
}

/*
 *
 */

struct ks_keychain {
    int anchors;
    SecKeychainRef keychain;
};

static int
keychain_init(hx509_context context,
	      hx509_certs certs, void **data, int flags,
	      const char *residue, hx509_lock lock)
{
    struct ks_keychain *ctx;

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
	hx509_clear_error_string(context);
	return ENOMEM;
    }

    if (residue) {
	if (strcasecmp(residue, "system-anchors") == 0) {
	    ctx->anchors = 1;
	} else if (strncasecmp(residue, "FILE:", 5) == 0) {
	    OSStatus ret;

	    ret = SecKeychainOpen(residue + 5, &ctx->keychain);
	    if (ret != noErr) {
		hx509_set_error_string(context, 0, ENOENT,
				       "Failed to open %s", residue);
		free(ctx);
		return ENOENT;
	    }
	} else {
	    hx509_set_error_string(context, 0, ENOENT,
				   "Unknown subtype %s", residue);
	    free(ctx);
	    return ENOENT;
	}
    }

    *data = ctx;
    return 0;
}

/*
 *
 */

static int
keychain_free(hx509_certs certs, void *data)
{
    struct ks_keychain *ctx = data;
    if (ctx->keychain)
	CFRelease(ctx->keychain);
    memset(ctx, 0, sizeof(*ctx));
    free(ctx);
    return 0;
}

/*
 *
 */

struct iter {
    hx509_certs certs;
    void *cursor;
    CFArrayRef search_result;
    CFIndex search_index;
};

static int
keychain_iter_start(hx509_context context,
		    hx509_certs certs, void *data, void **cursor)
{
    struct ks_keychain *ctx = data;
    struct iter *iter;

    iter = calloc(1, sizeof(*iter));
    if (iter == NULL) {
	hx509_set_error_string(context, 0, ENOMEM, "out of memory");
	return ENOMEM;
    }

    if (ctx->anchors) {
        CFArrayRef anchors;
	int ret;
	CFIndex i;

	ret = hx509_certs_init(context, "MEMORY:ks-file-create",
			       0, NULL, &iter->certs);
	if (ret) {
	    free(iter);
	    return ret;
	}

	ret = SecTrustCopyAnchorCertificates(&anchors);
	if (ret != 0) {
	    hx509_certs_free(&iter->certs);
	    free(iter);
	    hx509_set_error_string(context, 0, ENOMEM,
				   "Can't get trust anchors from Keychain");
	    return ENOMEM;
	}
	for (i = 0; i < CFArrayGetCount(anchors); i++) {
	    SecCertificateRef cr;
	    CFDataRef certData;
	    hx509_cert cert;

	    cr = (SecCertificateRef)(uintptr_t)CFArrayGetValueAtIndex(anchors, i);
	    certData = SecCertificateCopyData(cr);
	    if (certData == NULL)
		continue;

	    cert = hx509_cert_init_data(context,
					CFDataGetBytePtr(certData),
					CFDataGetLength(certData),
					NULL);
	    CFRelease(certData);
	    if (cert == NULL)
		continue;

	    ret = hx509_certs_add(context, iter->certs, cert);
	    hx509_cert_free(cert);
	}
	CFRelease(anchors);
    } else if (ctx->keychain) {
	/* Search for certificates in the specified keychain */
	CFMutableDictionaryRef query;
	CFArrayRef searchList;
	OSStatus ret;

	query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
					  &kCFTypeDictionaryKeyCallBacks,
					  &kCFTypeDictionaryValueCallBacks);
	if (query == NULL) {
	    free(iter);
	    hx509_set_error_string(context, 0, ENOMEM, "out of memory");
	    return ENOMEM;
	}

	CFDictionarySetValue(query, kSecClass, kSecClassCertificate);
	CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
	CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);

	{
	    const void *keychains[1] = { ctx->keychain };
	    searchList = CFArrayCreate(kCFAllocatorDefault,
				       keychains, 1,
				       &kCFTypeArrayCallBacks);
	}
	if (searchList) {
	    CFDictionarySetValue(query, kSecMatchSearchList, searchList);
	    CFRelease(searchList);
	}

	ret = SecItemCopyMatching(query, (CFTypeRef *)&iter->search_result);
	CFRelease(query);

	if (ret != errSecSuccess && ret != errSecItemNotFound) {
	    free(iter);
	    hx509_set_error_string(context, 0, EINVAL,
				   "Failed to search keychain");
	    return EINVAL;
	}
	iter->search_index = 0;
    }

    if (iter->certs) {
	int ret;
	ret = hx509_certs_start_seq(context, iter->certs, &iter->cursor);
	if (ret) {
	    hx509_certs_free(&iter->certs);
	    free(iter);
	    return ret;
	}
    }

    *cursor = iter;
    return 0;
}

/*
 *
 */

static int
keychain_iter(hx509_context context,
	      hx509_certs certs, void *data, void *cursor, hx509_cert *cert)
{
    struct iter *iter = cursor;

    if (iter->certs)
	return hx509_certs_next_cert(context, iter->certs, iter->cursor, cert);

    *cert = NULL;

    if (iter->search_result == NULL)
	return 0;

    while (iter->search_index < CFArrayGetCount(iter->search_result)) {
	SecCertificateRef certRef;
	SecIdentityRef identity = NULL;
	CFDataRef certData;
	heim_error_t error = NULL;
	OSStatus ret;

	certRef = (SecCertificateRef)(uintptr_t)CFArrayGetValueAtIndex(
	    iter->search_result, iter->search_index++);

	certData = SecCertificateCopyData(certRef);
	if (certData == NULL)
	    continue;

	*cert = hx509_cert_init_data(context,
				     CFDataGetBytePtr(certData),
				     CFDataGetLength(certData),
				     &error);
	CFRelease(certData);

	if (*cert == NULL) {
	    if (error)
		heim_release(error);
	    continue;
	}

	/*
	 * Try to find a matching private key via SecIdentity
	 */
	ret = SecIdentityCreateWithCertificate(NULL, certRef, &identity);
	if (ret == errSecSuccess && identity) {
	    SecKeyRef keyRef = NULL;

	    ret = SecIdentityCopyPrivateKey(identity, &keyRef);
	    if (ret == errSecSuccess && keyRef) {
		set_private_key(context, keyRef, *cert);
		CFRelease(keyRef);
	    }
	    CFRelease(identity);
	}

	return 0;
    }

    return 0;
}

/*
 *
 */

static int
keychain_iter_end(hx509_context context,
		  hx509_certs certs,
		  void *data,
		  void *cursor)
{
    struct iter *iter = cursor;

    if (iter->certs) {
	hx509_certs_end_seq(context, iter->certs, iter->cursor);
	hx509_certs_free(&iter->certs);
    }
    if (iter->search_result)
	CFRelease(iter->search_result);

    memset(iter, 0, sizeof(*iter));
    free(iter);
    return 0;
}

/*
 *
 */

struct hx509_keyset_ops keyset_keychain = {
    "KEYCHAIN",
    0,
    keychain_init,
    NULL,
    keychain_free,
    NULL,
    NULL,
    keychain_iter_start,
    keychain_iter,
    keychain_iter_end,
    NULL,
    NULL,
    NULL,
    NULL
};

#pragma clang diagnostic pop

#endif /* HAVE_FRAMEWORK_SECURITY */

/*
 *
 */

HX509_LIB_FUNCTION void HX509_LIB_CALL
_hx509_ks_keychain_register(hx509_context context)
{
#ifdef HAVE_FRAMEWORK_SECURITY
    _hx509_ks_register(context, &keyset_keychain);
#endif
}
