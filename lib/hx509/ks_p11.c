/*
 * Copyright (c) 2004 - 2008 Kungliga Tekniska Högskolan
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

#include <openssl/store.h>
#include <openssl/ui.h>

static heim_base_once_t once = HEIM_BASE_ONCE_INIT;
static int providers_loaded;
static OSSL_LIB_CTX *global_libctx;

static void
load_providers_f(void *arg)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *def;
    OSSL_PROVIDER *p11;
    const char *cnf = arg;

    if (!libctx ||
        (cnf && !OSSL_LIB_CTX_load_config(libctx, cnf)))
        return;

    def = OSSL_PROVIDER_load(libctx, "default");
    p11 = OSSL_PROVIDER_load(libctx, "pkcs11");
    if (!def || !p11) {
        OSSL_LIB_CTX_free(libctx);
        return;
    }

    global_libctx = libctx;
    providers_loaded = 1;
}

static void
load_providers(void)
{
    heim_base_once_f(&once, NULL, load_providers_f);
}

/* Open the PKCS#11 “store”, which should support PKCS#11 URIs (RFC 7512) */
static OSSL_STORE_CTX *
open_pkcs11_store(OSSL_LIB_CTX *libctx, const char *uri, const char *propq)
{
    return OSSL_STORE_open_ex(uri, libctx, propq,
                              /* UI method */ NULL, /* UI data */ NULL,
                              /* passphrase cb */ NULL, /* cbarg */ NULL);
}

#include <openssl/x509.h>

typedef int (*key_cb)(EVP_PKEY *pkey, const char *desc, void *arg);
typedef int (*cert_cb)(X509 *cert, const char *desc, void *arg);

int
enumerate_pkcs11(OSSL_STORE_CTX *sc, key_cb kcb, cert_cb ccb, void *arg)
{
    if (!sc) return 0;

    /*
     * Only ask for keys and certificates.
     *
     * Ignore failure; some loaders don’t implement expect() and still work.
     */
    if (kcb)
        OSSL_STORE_expect(sc, OSSL_STORE_INFO_PKEY);
    if (ccb)
        OSSL_STORE_expect(sc, OSSL_STORE_INFO_CERT);

    for (;;) {
        OSSL_STORE_INFO *info = OSSL_STORE_load(sc);
        if (info == NULL) {
            if (OSSL_STORE_eof(sc))
                break;
            return 0; /* error */
        }

        int type = OSSL_STORE_INFO_get_type(info);
        const char *desc = OSSL_STORE_INFO_get0_name(info); /* may be NULL */

        switch (type) {
        case OSSL_STORE_INFO_PKEY: {
            EVP_PKEY *pkey = OSSL_STORE_INFO_get1_PKEY(info); /* we own this ref */
            if (pkey && kcb) {
                if (kcb(pkey, desc, arg))
                    pkey = NULL;
            }
            EVP_PKEY_free(pkey);
            break;
        }
        case OSSL_STORE_INFO_CERT: {
            X509 *c = OSSL_STORE_INFO_get1_CERT(info);
            if (c && ccb) {
                if (ccb(x, desc, arg))
                    c = NULL;
            }
            X509_free(c);
            break;
        }
#if 0
        case OSSL_STORE_INFO_NAME:
            /*
             * A "name" can be a discoverable object. You can follow it with
             * OSSL_STORE_open(name).
             */
            break;
#endif
        default:
            break;
        }

        OSSL_STORE_INFO_free(info);
    }
    return 1;
}

struct p11_slot {
    hx509_certs certs;
};

static int
collect_private_key(hx509_context context,
		    struct p11_module *p, struct p11_slot *slot,
		    CK_SESSION_HANDLE session,
		    CK_OBJECT_HANDLE object,
		    void *ptr, CK_ATTRIBUTE *query, int num_query)
{
    struct hx509_collector *collector = ptr;
    hx509_private_key key;
    heim_octet_string localKeyId;
    int ret;
    RSA *rsa;
    struct p11_rsa *p11rsa;

    localKeyId.data = query[0].pValue;
    localKeyId.length = query[0].ulValueLen;

    ret = hx509_private_key_init(&key, NULL, NULL);
    if (ret)
	return ret;

    rsa = RSA_new();
    if (rsa == NULL)
	_hx509_abort("out of memory");

    /*
     * The exponent and modulus should always be present according to
     * the pkcs11 specification, but some smartcards leaves it out,
     * let ignore any failure to fetch it.
     */
    rsa->n = getattr_bn(p, slot, session, object, CKA_MODULUS);
    rsa->e = getattr_bn(p, slot, session, object, CKA_PUBLIC_EXPONENT);

    p11rsa = calloc(1, sizeof(*p11rsa));
    if (p11rsa == NULL)
	_hx509_abort("out of memory");

    p11rsa->p = p;
    p11rsa->slot = slot;
    p11rsa->private_key = object;

    if (p->ref == 0)
	_hx509_abort("pkcs11 ref == 0 on alloc");
    p->ref++;
    if (p->ref == UINT_MAX)
	_hx509_abort("pkcs11 ref == UINT_MAX on alloc");

    RSA_set_method(rsa, &p11_rsa_pkcs1_method);
    ret = RSA_set_app_data(rsa, p11rsa);
    if (ret != 1)
	_hx509_abort("RSA_set_app_data");

    hx509_private_key_assign_rsa(key, rsa);

    ret = _hx509_collector_private_key_add(context,
					   collector,
					   hx509_signature_rsa(),
					   key,
					   NULL,
					   &localKeyId);

    if (ret) {
	hx509_private_key_free(&key);
	return ret;
    }
    return 0;
}

static void
p11_cert_release(hx509_cert cert, void *ctx)
{
    struct p11_module *p = ctx;
}


static int
collect_cert(hx509_context context,
	     struct p11_module *p, struct p11_slot *slot,
	     CK_SESSION_HANDLE session,
	     CK_OBJECT_HANDLE object,
	     void *ptr, CK_ATTRIBUTE *query, int num_query)
{
    struct hx509_collector *collector = ptr;
    heim_error_t error = NULL;
    hx509_cert cert;
    int ret;

    if ((CK_LONG)query[0].ulValueLen == -1 ||
	(CK_LONG)query[1].ulValueLen == -1)
    {
	return 0;
    }

    cert = hx509_cert_init_data(context, query[1].pValue,
			       query[1].ulValueLen, &error);
    if (cert == NULL) {
	ret = heim_error_get_code(error);
	heim_release(error);
	return ret;
    }

    if (p->ref == 0)
	_hx509_abort("pkcs11 ref == 0 on alloc");
    p->ref++;
    if (p->ref == UINT_MAX)
	_hx509_abort("pkcs11 ref to high");

    _hx509_cert_set_release(cert, p11_cert_release, p);

    {
	heim_octet_string data;

	data.data = query[0].pValue;
	data.length = query[0].ulValueLen;

	_hx509_set_cert_attribute(context,
				  cert,
				  &asn1_oid_id_pkcs_9_at_localKeyId,
				  &data);
    }

    if ((CK_LONG)query[2].ulValueLen != -1) {
	char *str;

	ret = asprintf(&str, "%.*s",
		       (int)query[2].ulValueLen, (char *)query[2].pValue);
	if (ret != -1 && str) {
	    hx509_cert_set_friendly_name(cert, str);
	    free(str);
	}
    }

    ret = _hx509_collector_certs_add(context, collector, cert);
    hx509_cert_free(cert);

    return ret;
}

static int
p11_init(hx509_context context,
	 hx509_certs certs, void **data, int flags,
	 const char *residue, hx509_lock lock)
{
    CK_C_GetFunctionList getFuncs;
    struct p11_module *p;
    char *list, *str;
    int ret;

    *data = NULL;

    if (flags & HX509_CERTS_NO_PRIVATE_KEYS) {
	hx509_set_error_string(context, 0, ENOTSUP,
			       "PKCS#11 store does not support "
                               "HX509_CERTS_NO_PRIVATE_KEYS flag");
        return ENOTSUP;
    }

    if (residue == NULL || residue[0] == '\0') {
	hx509_set_error_string(context, 0, EINVAL,
			       "PKCS#11 store not specified");
        return EINVAL;
    }
    list = strdup(residue);
    if (list == NULL)
	return ENOMEM;

    p = calloc(1, sizeof(*p));
    if (p == NULL) {
	free(list);
	return ENOMEM;
    }

    p->ref = 1;
    p->selected_slot = 0;

    str = strchr(list, ',');
    if (str)
	*str++ = '\0';
    while (str) {
	char *strnext;
	strnext = strchr(str, ',');
	if (strnext)
	    *strnext++ = '\0';
	if (strncasecmp(str, "slot=", 5) == 0)
	    p->selected_slot = atoi(str + 5);
	str = strnext;
    }

    p->dl_handle = dlopen(list, RTLD_NOW | RTLD_LOCAL | RTLD_GROUP);
    if (p->dl_handle == NULL) {
	ret = HX509_PKCS11_LOAD;
	hx509_set_error_string(context, 0, ret,
			       "Failed to open %s: %s", list, dlerror());
	goto out;
    }

    getFuncs = (CK_C_GetFunctionList) dlsym(p->dl_handle, "C_GetFunctionList");
    if (getFuncs == NULL) {
	ret = HX509_PKCS11_LOAD;
	hx509_set_error_string(context, 0, ret,
			       "C_GetFunctionList missing in %s: %s",
			       list, dlerror());
	goto out;
    }

    ret = (*getFuncs)(&p->funcs);
    if (ret) {
	ret = HX509_PKCS11_LOAD;
	hx509_set_error_string(context, 0, ret,
			       "C_GetFunctionList failed in %s", list);
	goto out;
    }

    ret = P11FUNC(p, Initialize, (NULL_PTR));
    if (ret != CKR_OK) {
	ret = HX509_PKCS11_TOKEN_CONFUSED;
	hx509_set_error_string(context, 0, ret,
			       "Failed initialize the PKCS11 module");
	goto out;
    }

    ret = P11FUNC(p, GetSlotList, (FALSE, NULL, &p->num_slots));
    if (ret) {
	ret = HX509_PKCS11_TOKEN_CONFUSED;
	hx509_set_error_string(context, 0, ret,
			       "Failed to get number of PKCS11 slots");
	goto out;
    }

   if (p->num_slots == 0) {
	ret = HX509_PKCS11_NO_SLOT;
	hx509_set_error_string(context, 0, ret,
			       "Selected PKCS11 module have no slots");
	goto out;
   }


    {
	CK_SLOT_ID_PTR slot_ids;
	int num_tokens = 0;
	size_t i;

	slot_ids = malloc(p->num_slots * sizeof(*slot_ids));
	if (slot_ids == NULL) {
	    hx509_clear_error_string(context);
	    ret = ENOMEM;
	    goto out;
	}

	ret = P11FUNC(p, GetSlotList, (FALSE, slot_ids, &p->num_slots));
	if (ret) {
	    free(slot_ids);
	    hx509_set_error_string(context, 0, HX509_PKCS11_TOKEN_CONFUSED,
				   "Failed getting slot-list from "
				   "PKCS11 module");
	    ret = HX509_PKCS11_TOKEN_CONFUSED;
	    goto out;
	}

	p->slot = calloc(p->num_slots, sizeof(p->slot[0]));
	if (p->slot == NULL) {
	    free(slot_ids);
	    hx509_set_error_string(context, 0, ENOMEM,
				   "Failed to get memory for slot-list");
	    ret = ENOMEM;
	    goto out;
	}

	for (i = 0; i < p->num_slots; i++) {
	    if ((p->selected_slot != 0) && (slot_ids[i] != (p->selected_slot - 1)))
		continue;
	    ret = p11_init_slot(context, p, lock, slot_ids[i], i, &p->slot[i]);
	    if (!ret) {
	        if (p->slot[i].flags & P11_TOKEN_PRESENT)
	            num_tokens++;
	    }
	}
	free(slot_ids);
	if (ret)
	    goto out;
	if (num_tokens == 0) {
	    ret = HX509_PKCS11_NO_TOKEN;
	    goto out;
	}
    }

    free(list);

    *data = p;

    return 0;
 out:
    if (list)
	free(list);
    return ret;
}

static int
p11_free(hx509_certs certs, void *data)
{
    struct p11_module *p = data;
    size_t i;

    for (i = 0; i < p->num_slots; i++) {
	if (p->slot[i].certs)
	    hx509_certs_free(&p->slot[i].certs);
    }
    return 0;
}

struct p11_cursor {
    hx509_certs certs;
    void *cursor;
};

static int
p11_iter_start(hx509_context context,
	       hx509_certs certs, void *data, void **cursor)
{
    struct p11_module *p = data;
    struct p11_cursor *c;
    int ret;
    size_t i;

    c = malloc(sizeof(*c));
    if (c == NULL) {
	hx509_clear_error_string(context);
	return ENOMEM;
    }
    ret = hx509_certs_init(context, "MEMORY:pkcs11-iter", 0, NULL, &c->certs);
    if (ret) {
	free(c);
	return ret;
    }

    for (i = 0 ; i < p->num_slots; i++) {
	if (p->slot[i].certs == NULL)
	    continue;
	ret = hx509_certs_merge(context, c->certs, p->slot[i].certs);
	if (ret) {
	    hx509_certs_free(&c->certs);
	    free(c);
	    return ret;
	}
    }

    ret = hx509_certs_start_seq(context, c->certs, &c->cursor);
    if (ret) {
	hx509_certs_free(&c->certs);
	free(c);
	return 0;
    }
    *cursor = c;

    return 0;
}

static int
p11_iter(hx509_context context,
	 hx509_certs certs, void *data, void *cursor, hx509_cert *cert)
{
    struct p11_cursor *c = cursor;
    return hx509_certs_next_cert(context, c->certs, c->cursor, cert);
}

static int
p11_iter_end(hx509_context context,
	     hx509_certs certs, void *data, void *cursor)
{
    struct p11_cursor *c = cursor;
    int ret;
    ret = hx509_certs_end_seq(context, c->certs, c->cursor);
    hx509_certs_free(&c->certs);
    free(c);
    return ret;
}

#define MECHFLAG(x) { "unknown-flag-" #x, x }
static struct units mechflags[] = {
	MECHFLAG(0x80000000),
	MECHFLAG(0x40000000),
	MECHFLAG(0x20000000),
	MECHFLAG(0x10000000),
	MECHFLAG(0x08000000),
	MECHFLAG(0x04000000),
	{"ec-compress",		0x2000000 },
	{"ec-uncompress",	0x1000000 },
	{"ec-namedcurve",	0x0800000 },
	{"ec-ecparameters",	0x0400000 },
	{"ec-f-2m",		0x0200000 },
	{"ec-f-p",		0x0100000 },
	{"derive",		0x0080000 },
	{"unwrap",		0x0040000 },
	{"wrap",		0x0020000 },
	{"genereate-key-pair",	0x0010000 },
	{"generate",		0x0008000 },
	{"verify-recover",	0x0004000 },
	{"verify",		0x0002000 },
	{"sign-recover",	0x0001000 },
	{"sign",		0x0000800 },
	{"digest",		0x0000400 },
	{"decrypt",		0x0000200 },
	{"encrypt",		0x0000100 },
	MECHFLAG(0x00080),
	MECHFLAG(0x00040),
	MECHFLAG(0x00020),
	MECHFLAG(0x00010),
	MECHFLAG(0x00008),
	MECHFLAG(0x00004),
	MECHFLAG(0x00002),
	{"hw",			0x0000001 },
	{ NULL,			0x0000000 }
};
#undef MECHFLAG

static int
p11_printinfo(hx509_context context,
	      hx509_certs certs,
	      void *data,
	      int (*func)(void *, const char *),
	      void *ctx)
{
    struct p11_module *p = data;
    size_t i, j;

    _hx509_pi_printf(func, ctx, "pkcs11 driver with %d slot%s",
		     p->num_slots, p->num_slots > 1 ? "s" : "");

    for (i = 0; i < p->num_slots; i++) {
	struct p11_slot *s = &p->slot[i];

	_hx509_pi_printf(func, ctx, "slot %d: id: %d name: %s flags: %08x",
			 i, (int)s->id, s->name, s->flags);

	_hx509_pi_printf(func, ctx, "number of supported mechanisms: %lu",
			 (unsigned long)s->mechs.num);
	for (j = 0; j < s->mechs.num; j++) {
	    const char *mechname = "unknown";
	    char flags[256], unknownname[40];
#define MECHNAME(s,n) case s: mechname = n; break
	    switch(s->mechs.list[j]) {
		MECHNAME(CKM_RSA_PKCS_KEY_PAIR_GEN, "rsa-pkcs-key-pair-gen");
		MECHNAME(CKM_RSA_PKCS, "rsa-pkcs");
		MECHNAME(CKM_RSA_X_509, "rsa-x-509");
		MECHNAME(CKM_MD5_RSA_PKCS, "md5-rsa-pkcs");
		MECHNAME(CKM_SHA1_RSA_PKCS, "sha1-rsa-pkcs");
		MECHNAME(CKM_SHA256_RSA_PKCS, "sha256-rsa-pkcs");
		MECHNAME(CKM_SHA384_RSA_PKCS, "sha384-rsa-pkcs");
		MECHNAME(CKM_SHA512_RSA_PKCS, "sha512-rsa-pkcs");
		MECHNAME(CKM_RIPEMD160_RSA_PKCS, "ripemd160-rsa-pkcs");
		MECHNAME(CKM_RSA_PKCS_OAEP, "rsa-pkcs-oaep");
		MECHNAME(CKM_SHA512_HMAC, "sha512-hmac");
		MECHNAME(CKM_SHA512, "sha512");
		MECHNAME(CKM_SHA384_HMAC, "sha384-hmac");
		MECHNAME(CKM_SHA384, "sha384");
		MECHNAME(CKM_SHA256_HMAC, "sha256-hmac");
		MECHNAME(CKM_SHA256, "sha256");
		MECHNAME(CKM_SHA_1, "sha1");
		MECHNAME(CKM_MD5, "md5");
		MECHNAME(CKM_RIPEMD160, "ripemd-160");
		MECHNAME(CKM_DES_ECB, "des-ecb");
		MECHNAME(CKM_DES_CBC, "des-cbc");
		MECHNAME(CKM_AES_ECB, "aes-ecb");
		MECHNAME(CKM_AES_CBC, "aes-cbc");
		MECHNAME(CKM_DH_PKCS_PARAMETER_GEN, "dh-pkcs-parameter-gen");
	    default:
		snprintf(unknownname, sizeof(unknownname),
			 "unknown-mech-%lu",
			 (unsigned long)s->mechs.list[j]);
		mechname = unknownname;
		break;
	    }
#undef MECHNAME
	    unparse_flags(s->mechs.infos[j]->flags, mechflags,
			  flags, sizeof(flags));

	    _hx509_pi_printf(func, ctx, "  %s: %s", mechname, flags);
	}
    }

    return 0;
}

static struct hx509_keyset_ops keyset_pkcs11 = {
    "PKCS11",
    0,
    p11_init,
    NULL,
    p11_free,
    NULL,
    NULL,
    p11_iter_start,
    p11_iter,
    p11_iter_end,
    p11_printinfo,
    NULL,
    NULL,
    NULL
};

#endif /* HAVE_DLOPEN */

HX509_LIB_FUNCTION void HX509_LIB_CALL
_hx509_ks_pkcs11_register(hx509_context context)
{
#ifdef HAVE_DLOPEN
    _hx509_ks_register(context, &keyset_pkcs11);
#endif
}
