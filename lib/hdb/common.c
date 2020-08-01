/*
 * Copyright (c) 1997-2002 Kungliga Tekniska Högskolan
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

#include "krb5_locl.h"
#include "hdb_locl.h"

int
hdb_principal2key(krb5_context context, krb5_const_principal p, krb5_data *key)
{
    Principal new;
    size_t len = 0;
    int ret;

    ret = copy_Principal(p, &new);
    if(ret)
	return ret;
    new.name.name_type = 0;

    ASN1_MALLOC_ENCODE(Principal, key->data, key->length, &new, &len, ret);
    if (ret == 0 && key->length != len)
	krb5_abortx(context, "internal asn.1 encoder error");
    free_Principal(&new);
    return ret;
}

int
hdb_key2principal(krb5_context context, krb5_data *key, krb5_principal p)
{
    return decode_Principal(key->data, key->length, p, NULL);
}

int
hdb_entry2value(krb5_context context, const hdb_entry *ent, krb5_data *value)
{
    size_t len = 0;
    int ret;

    ASN1_MALLOC_ENCODE(hdb_entry, value->data, value->length, ent, &len, ret);
    if (ret == 0 && value->length != len)
	krb5_abortx(context, "internal asn.1 encoder error");
    return ret;
}

int
hdb_value2entry(krb5_context context, krb5_data *value, hdb_entry *ent)
{
    return decode_hdb_entry(value->data, value->length, ent, NULL);
}

int
hdb_entry_alias2value(krb5_context context,
		      const hdb_entry_alias *alias,
		      krb5_data *value)
{
    size_t len = 0;
    int ret;

    ASN1_MALLOC_ENCODE(hdb_entry_alias, value->data, value->length,
		       alias, &len, ret);
    if (ret == 0 && value->length != len)
	krb5_abortx(context, "internal asn.1 encoder error");
    return ret;
}

int
hdb_value2entry_alias(krb5_context context, krb5_data *value,
		      hdb_entry_alias *ent)
{
    return decode_hdb_entry_alias(value->data, value->length, ent, NULL);
}

/*
 * Some old databases may not have stored the salt with each key, which will
 * break clients when aliases or canonicalization are used. Generate a
 * default salt based on the real principal name in the entry to handle
 * this case.
 */
static krb5_error_code
add_default_salts(krb5_context context, HDB *db, hdb_entry *entry)
{
    krb5_error_code ret;
    size_t i;
    krb5_salt pwsalt;

    ret = krb5_get_pw_salt(context, entry->principal, &pwsalt);
    if (ret)
	return ret;

    for (i = 0; i < entry->keys.len; i++) {
	Key *key = &entry->keys.val[i];

	if (key->salt != NULL ||
	    _krb5_enctype_requires_random_salt(context, key->key.keytype))
	    continue;

	key->salt = calloc(1, sizeof(*key->salt));
	if (key->salt == NULL) {
	    ret = krb5_enomem(context);
	    break;
	}

	key->salt->type = KRB5_PADATA_PW_SALT;

	ret = krb5_data_copy(&key->salt->salt,
			     pwsalt.saltvalue.data,
			     pwsalt.saltvalue.length);
	if (ret)
	    break;
    }

    krb5_free_salt(context, pwsalt);

    return ret;
}

krb5_error_code
_hdb_fetch_kvno(krb5_context context, HDB *db, krb5_const_principal principal,
		unsigned flags, krb5_kvno kvno, hdb_entry_ex *entry)
{
    krb5_principal enterprise_principal = NULL;
    krb5_data key, value;
    krb5_error_code ret;

    if (principal->name.name_type == KRB5_NT_ENTERPRISE_PRINCIPAL) {
	if (principal->name.name_string.len != 1) {
	    ret = KRB5_PARSE_MALFORMED;
	    krb5_set_error_message(context, ret, "malformed principal: "
				   "enterprise name with %d name components",
				   principal->name.name_string.len);
	    return ret;
	}
	ret = krb5_parse_name(context, principal->name.name_string.val[0],
			      &enterprise_principal);
	if (ret)
	    return ret;
	principal = enterprise_principal;
    }

    hdb_principal2key(context, principal, &key);
    if (enterprise_principal)
	krb5_free_principal(context, enterprise_principal);
    ret = db->hdb__get(context, db, key, &value);
    krb5_data_free(&key);
    if(ret)
	return ret;
    ret = hdb_value2entry(context, &value, &entry->entry);
    /* HDB_F_GET_ANY indicates request originated from KDC (not kadmin) */
    if (ret == ASN1_BAD_ID && (flags & (HDB_F_CANON|HDB_F_GET_ANY)) == 0) {
	krb5_data_free(&value);
	return HDB_ERR_NOENTRY;
    } else if (ret == ASN1_BAD_ID) {
	hdb_entry_alias alias;

	ret = hdb_value2entry_alias(context, &value, &alias);
	if (ret) {
	    krb5_data_free(&value);
	    return ret;
	}
	hdb_principal2key(context, alias.principal, &key);
	krb5_data_free(&value);
	free_hdb_entry_alias(&alias);

	ret = db->hdb__get(context, db, key, &value);
	krb5_data_free(&key);
	if (ret)
	    return ret;
	ret = hdb_value2entry(context, &value, &entry->entry);
	if (ret) {
	    krb5_data_free(&value);
	    return ret;
	}
    }
    krb5_data_free(&value);
    if ((flags & HDB_F_DECRYPT) && (flags & HDB_F_ALL_KVNOS)) {
	/* Decrypt the current keys */
	ret = hdb_unseal_keys(context, db, &entry->entry);
	if (ret) {
	    hdb_free_entry(context, entry);
	    return ret;
	}
	/* Decrypt the key history too */
	ret = hdb_unseal_keys_kvno(context, db, 0, flags, &entry->entry);
	if (ret) {
	    hdb_free_entry(context, entry);
	    return ret;
	}
    } else if ((flags & HDB_F_DECRYPT)) {
	if ((flags & HDB_F_KVNO_SPECIFIED) == 0 || kvno == entry->entry.kvno) {
	    /* Decrypt the current keys */
	    ret = hdb_unseal_keys(context, db, &entry->entry);
	    if (ret) {
		hdb_free_entry(context, entry);
		return ret;
	    }
	} else {
	    if ((flags & HDB_F_ALL_KVNOS))
		kvno = 0;
	    /*
	     * Find and decrypt the keys from the history that we want,
	     * and swap them with the current keys
	     */
	    ret = hdb_unseal_keys_kvno(context, db, kvno, flags, &entry->entry);
	    if (ret) {
		hdb_free_entry(context, entry);
		return ret;
	    }
	}
    }
    if ((flags & HDB_F_FOR_AS_REQ) && (flags & HDB_F_GET_CLIENT)) {
	/*
	 * Generate default salt for any principals missing one; note such
	 * principals could include those for which a random (non-password)
	 * key was generated, but given the salt will be ignored by a keytab
	 * client it doesn't hurt to include the default salt.
	 */
	ret = add_default_salts(context, db, &entry->entry);
	if (ret) {
	    hdb_free_entry(context, entry);
	    return ret;
	}
    }
    if (enterprise_principal) {
	/*
	 * Whilst Windows does not canonicalize enterprise principal names if
	 * the canonicalize flag is unset, the original specification in
	 * draft-ietf-krb-wg-kerberos-referrals-03.txt says we should.
	 */
	entry->entry.flags.force_canonicalize = 1;
    }

    return 0;
}

static krb5_error_code
hdb_remove_aliases(krb5_context context, HDB *db, krb5_data *key)
{
    const HDB_Ext_Aliases *aliases;
    krb5_error_code code;
    hdb_entry oldentry;
    krb5_data value;
    size_t i;

    code = db->hdb__get(context, db, *key, &value);
    if (code == HDB_ERR_NOENTRY)
	return 0;
    else if (code)
	return code;

    code = hdb_value2entry(context, &value, &oldentry);
    krb5_data_free(&value);
    if (code)
	return code;

    code = hdb_entry_get_aliases(&oldentry, &aliases);
    if (code || aliases == NULL) {
	free_hdb_entry(&oldentry);
	return code;
    }
    for (i = 0; i < aliases->aliases.len; i++) {
	krb5_data akey;

	code = hdb_principal2key(context, &aliases->aliases.val[i], &akey);
        if (code == 0) {
            code = db->hdb__del(context, db, akey);
            krb5_data_free(&akey);
        }
	if (code) {
	    free_hdb_entry(&oldentry);
	    return code;
	}
    }
    free_hdb_entry(&oldentry);
    return 0;
}

static krb5_error_code
hdb_add_aliases(krb5_context context, HDB *db,
		unsigned flags, hdb_entry_ex *entry)
{
    const HDB_Ext_Aliases *aliases;
    krb5_error_code code;
    krb5_data key, value;
    size_t i;

    code = hdb_entry_get_aliases(&entry->entry, &aliases);
    if (code || aliases == NULL)
	return code;

    for (i = 0; i < aliases->aliases.len; i++) {
	hdb_entry_alias entryalias;
	entryalias.principal = entry->entry.principal;

	code = hdb_entry_alias2value(context, &entryalias, &value);
	if (code)
	    return code;

	code = hdb_principal2key(context, &aliases->aliases.val[i], &key);
        if (code == 0) {
            code = db->hdb__put(context, db, flags, key, value);
            krb5_data_free(&key);
        }
	krb5_data_free(&value);
	if (code)
	    return code;
    }
    return 0;
}

static krb5_error_code
hdb_check_aliases(krb5_context context, HDB *db, hdb_entry_ex *entry)
{
    const HDB_Ext_Aliases *aliases;
    int code;
    size_t i;

    /* check if new aliases already is used */

    code = hdb_entry_get_aliases(&entry->entry, &aliases);
    if (code)
	return code;

    for (i = 0; aliases && i < aliases->aliases.len; i++) {
	hdb_entry_alias alias;
	krb5_data akey, value;

	code = hdb_principal2key(context, &aliases->aliases.val[i], &akey);
        if (code == 0) {
            code = db->hdb__get(context, db, akey, &value);
            krb5_data_free(&akey);
        }
	if (code == HDB_ERR_NOENTRY)
	    continue;
	else if (code)
	    return code;

	code = hdb_value2entry_alias(context, &value, &alias);
	krb5_data_free(&value);

	if (code == ASN1_BAD_ID)
	    return HDB_ERR_EXISTS;
	else if (code)
	    return code;

	code = krb5_principal_compare(context, alias.principal,
				      entry->entry.principal);
	free_hdb_entry_alias(&alias);
	if (code == 0)
	    return HDB_ERR_EXISTS;
    }
    return 0;
}

krb5_error_code
_hdb_store(krb5_context context, HDB *db, unsigned flags, hdb_entry_ex *entry)
{
    krb5_data key, value;
    int code;

    if (entry->entry.flags.do_not_store ||
	entry->entry.flags.force_canonicalize)
	return HDB_ERR_MISUSE;
    /* check if new aliases already is used */
    code = hdb_check_aliases(context, db, entry);
    if (code)
	return code;

    if ((flags & HDB_F_PRECHECK) && (flags & HDB_F_REPLACE))
        return 0;

    if ((flags & HDB_F_PRECHECK)) {
        code = hdb_principal2key(context, entry->entry.principal, &key);
        if (code)
            return code;
        code = db->hdb__get(context, db, key, &value);
        krb5_data_free(&key);
        if (code == 0)
            krb5_data_free(&value);
        if (code == HDB_ERR_NOENTRY)
            return 0;
        return code ? code : HDB_ERR_EXISTS;
    }

    if(entry->entry.generation == NULL) {
	struct timeval t;
	entry->entry.generation = malloc(sizeof(*entry->entry.generation));
	if(entry->entry.generation == NULL) {
	    krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
	    return ENOMEM;
	}
	gettimeofday(&t, NULL);
	entry->entry.generation->time = t.tv_sec;
	entry->entry.generation->usec = t.tv_usec;
	entry->entry.generation->gen = 0;
    } else
	entry->entry.generation->gen++;

    code = hdb_seal_keys(context, db, &entry->entry);
    if (code)
	return code;

    hdb_principal2key(context, entry->entry.principal, &key);

    /* remove aliases */
    code = hdb_remove_aliases(context, db, &key);
    if (code) {
	krb5_data_free(&key);
	return code;
    }
    hdb_entry2value(context, &entry->entry, &value);
    code = db->hdb__put(context, db, flags & HDB_F_REPLACE, key, value);
    krb5_data_free(&value);
    krb5_data_free(&key);
    if (code)
	return code;

    code = hdb_add_aliases(context, db, flags, entry);

    return code;
}

krb5_error_code
_hdb_remove(krb5_context context, HDB *db,
            unsigned flags, krb5_const_principal principal)
{
    krb5_data key, value;
    int code;

    hdb_principal2key(context, principal, &key);

    if ((flags & HDB_F_PRECHECK)) {
        /*
         * We don't check that we can delete the aliases because we
         * assume that the DB is consistent.  If we did check for alias
         * consistency we'd also have to provide a way to fsck the DB,
         * otherwise admins would have no way to recover -- papering
         * over this here is less work, but we really ought to provide
         * an HDB fsck.
         */
        code = db->hdb__get(context, db, key, &value);
        krb5_data_free(&key);
        if (code == 0) {
            krb5_data_free(&value);
            return 0;
        }
        return code;
    }

    code = hdb_remove_aliases(context, db, &key);
    if (code) {
	krb5_data_free(&key);
	return code;
    }
    code = db->hdb__del(context, db, key);
    krb5_data_free(&key);
    return code;
}

/* PRF+(K_base, pad, keylen(etype)) */
static krb5_error_code
derive_Key1(krb5_context context,
            krb5_data *pad,
            EncryptionKey *base,
            krb5int32 etype,
            EncryptionKey *nk)
{
    krb5_error_code ret;
    krb5_crypto crypto = NULL;
    krb5_data out;
    size_t len;

    out.data = 0;
    out.length = 0;

    ret = krb5_enctype_keysize(context, base->keytype, &len);
    if (ret == 0)
        ret = krb5_crypto_init(context, base, 0, &crypto);
    if (ret == 0)
        ret = krb5_crypto_prfplus(context, crypto, pad, len, &out);
    if (crypto)
        krb5_crypto_destroy(context, crypto);
    if (ret == 0)
        ret = krb5_random_to_key(context, etype, out.data, out.length, nk);
    krb5_data_free(&out);
    return ret;
}

/* PRF+(PRF+(K_base, princ, keylen(etype)), kvno, keylen(etype)) */
/* XXX Make it PRF+(PRF+(K_base, princ, keylen(K_base.etype)), and lift it, kvno, keylen(etype)) */
static krb5_error_code
derive_Key(krb5_context context,
           const char *princ,
           krb5uint32 kvno,
           EncryptionKey *base,
           krb5int32 etype,
           Key *nk)
{
    krb5_error_code ret = 0;
    EncryptionKey intermediate;
    krb5_data pad;

    nk->salt = NULL;
    nk->mkvno = NULL;
    nk->key.keytype = 0;
    nk->key.keyvalue.data = 0;
    nk->key.keyvalue.length = 0;

    intermediate.keytype = 0;
    intermediate.keyvalue.data = 0;
    intermediate.keyvalue.length = 0;
    if (princ) {
        /* Derive intermediate key for the given principal */
        /* XXX Lift to optimize? */
        pad.data = (void *)(uintptr_t)princ;
        pad.length = strlen(princ);
        ret = derive_Key1(context, &pad, base, etype, &intermediate);
        if (ret == 0)
            base = &intermediate;
    } /* else `base' is already an intermediate key for the desired princ */

    /* Derive final key for `kvno' from intermediate key */
    kvno = htonl(kvno);
    pad.data = &kvno;
    pad.length = sizeof(kvno);
    if (ret == 0)
        ret = derive_Key1(context, &pad, base, etype, &nk->key);
    free_EncryptionKey(&intermediate);
    return ret;
}

/*
 * PRF+(PRF+(K_base, princ, keylen(etype)), kvno, keylen(etype)) for one
 * enctype.
 */
static krb5_error_code
derive_Keys(krb5_context context,
            const char *princ,
            krb5uint32 kvno,
            krb5int32 etype,
            const Keys *base,
            Keys *dk)

{
    krb5_error_code ret = 0;
    size_t i;
    Key nk;

    dk->len = 0;
    dk->val = 0;
    
    /*
     * The enctypes of the base keys is the list of enctypes to derive keys
     * for.  Still, we derive all keys from the first base key.
     */
    for (i = 0; ret == 0 && i < base->len; i++) {
        if (etype != KRB5_ENCTYPE_NULL && etype != base->val[i].key.keytype)
            continue;
        ret = derive_Key(context, princ, kvno, &base->val[0].key,
                         base->val[i].key.keytype, &nk);
        if (ret)
            break;
        ret = add_Keys(dk, &nk);
        free_Key(&nk);
        /*
         * FIXME We need to finish kdc/kadm5/kadmin support for the `etypes' so
         * we can reduce the number of keys in keytabs to just those in current
         * use and only of *one* enctype.
         *
         * What we could do is derive *one* key and for the others output a
         * one-byte key of the intended enctype (which will never work).
         *
         * We'll never need any keys but the first one...
         */
    }

    if (ret)
        free_Keys(dk);
    return ret;
}

/* Helper for derive_keys_for_kr() */
static krb5_error_code
derive_keyset(krb5_context context,
              const Keys *base_keys,
              const char *princ,
              krb5int32 etype,
              krb5uint32 kvno,
              KerberosTime set_time, /* "now" */
              hdb_keyset *dks)
{
    dks->kvno = kvno;
    dks->keys.val = 0;
    dks->set_time = malloc(sizeof(dks->set_time));
    if (dks->set_time == NULL)
        return krb5_enomem(context);
    *dks->set_time = set_time;
    return derive_Keys(context, princ, kvno, etype, base_keys, &dks->keys);
}

/* Possibly derive and install in `h' a keyset identified by `t' */
static krb5_error_code
derive_keys_for_kr(krb5_context context,
                   hdb_entry_ex *h,
                   HDB_Ext_KeySet *base_keys,
                   int is_current_keyset,
                   int rotation_period_offset,
                   const char *princ,
                   krb5int32 etype,
                   krb5uint32 kvno_wanted,
                   KerberosTime t,
                   struct KeyRotation *krp)
{
    krb5_error_code ret;
    hdb_keyset dks;
    KerberosTime set_time, n;
    krb5uint32 kvno;
    size_t i;

    if (rotation_period_offset < -1 || rotation_period_offset > 1)
        return EINVAL; /* wat */

    /*
     * Compute `kvno' and `set_time' given `t' and `krp'.
     *
     * There be signed 32-bit time_t dragons here.
     *
     * (t - krp->epoch < 0) is better than (krp->epoch < t), making us more
     * tolerant of signed 32-bit time_t here near 2038.  Of course, we have
     * signed 32-bit time_t dragons elsewhere.
     */
    n = (t - krp->epoch < 0) ? (t - krp->epoch) / krp->period : 0;
    n += rotation_period_offset;
    set_time = krp->epoch + krp->period * n;
    kvno = krp->base_kvno + n;


    /*
     * Do not waste cycles computing keys not wanted or needed.
     * A past kvno is too old if its set_time + rotation period is in the past
     * by more than half a rotation period, since then no service ticket
     * encrypted with keys of that kvno can still be extant.
     *
     * A future kvno is not coming up soon enough if we're more than a quarter
     * of the rotation period away from it.
     *
     * Recall: the assumption for virtually-keyed principals is that services
     * fetch their future keys frequently enough that they'll never miss having
     * the keys they need.
     */
    if ((kvno_wanted && kvno != kvno_wanted) ||
        t - (set_time + krp->period + (krp->period >> 1)) > 0 ||
        (set_time - t > 0 && (set_time - t) > (krp->period >> 2)))
        return 0;

    for (i = 0; i < base_keys->len; i++) {
        if (base_keys->val[i].kvno == krp->base_key_kvno)
            break;
    }
    if (i == base_keys->len) {
        /* Base key not found! */
        if (kvno_wanted || is_current_keyset) {
            krb5_set_error_message(context, ret = HDB_ERR_KVNO_NOT_FOUND,
                                   "Base key version %u not found for %s",
                                   kvno, princ);
            return ret;
        }
        return 0;
    }

    ret = derive_keyset(context, &base_keys->val[i].keys, princ, etype, kvno,
                        set_time, &dks);
    if (ret == 0)
        ret = hdb_install_keyset(context, &h->entry, is_current_keyset, &dks);

    free_hdb_keyset(&dks);
    return ret;
}

/* Derive and install current keys, and possibly preceding or next keys */
static krb5_error_code
derive_keys_for_current_kr(krb5_context context,
                           hdb_entry_ex *h, 
                           HDB_Ext_KeySet *base_keys,
                           const char *princ,
                           krb5int32 etype,
                           krb5uint32 kvno_wanted,
                           KerberosTime t,
                           struct KeyRotation *krp)
{
    krb5_error_code ret;

    /* derive_keys_for_kr() for current kvno and install as the current keyset */
    ret = derive_keys_for_kr(context, h, base_keys, 1, 0, princ, etype,
                             kvno_wanted, t, krp);
    /* derive_keys_for_kr() for prev kvno if still needed, add to history */
    if (ret == 0)
        ret = derive_keys_for_kr(context, h, base_keys, 0, -1, princ, etype,
                                 kvno_wanted, t, krp);
    /* derive_keys_for_kr() for next kvno if near enough, add to history */
    if (ret == 0)
        ret = derive_keys_for_kr(context, h, base_keys, 0, 1, princ, etype,
                                 kvno_wanted, t, krp);
    return ret;
}

/*
 * Derive and install all keysets in `h' that `princ' needs at time `now'.
 *
 * This mutates the entry `h' to a) not have base keys, b) have keys derived
 * from the base keys according to c) the key rotation periods for the base
 * principal, and the requested time, enctype, and kvno (all of which are
 * optional, with zero implying some default).
 *
 *  - `princ' is the name of the principal we'll end up with in `h'
 *  - `h_is_namespace' indicates whether `h' is for a namespace or a concrete
 *     principal (that might nonetheless have virtual/derived keys)
 *  - `t' is the time such that the derived keys are for kvnos needed at `t'
 *  - `etype' indicates what enctype to derive keys for (0 for all enctypes in
 *    `h->entry.etypes'
 *  - `kvno' requests a particular kvno, or all if zero
 */
static krb5_error_code
derive_keys(krb5_context context,
            unsigned flags,
            krb5_const_principal princ,
            int h_is_namespace,
            krb5_timestamp t,
            krb5int32 etype,
            krb5uint32 kvno,
            hdb_entry_ex *h)
{
    const HDB_Ext_KeyRotation *kr;
    HDB_Ext_KeySet base_keys;
    krb5_error_code ret;
    size_t current_kr, last_kr, i;
    char *p = NULL;

    if (!h_is_namespace && !h->entry.flags.virtual_keys)
        return 0;
    if (h_is_namespace) {
        /* Set the entry's principal name */
        free_Principal(h->entry.principal);
        ret = copy_Principal(princ, h->entry.principal);
    }

    if (ret == 0)
        ret = hdb_entry_get_key_rotation(context, &h->entry, &kr);

    /* Get the base keys from the entry, and remove them */
    base_keys.val = 0;
    base_keys.len = 0;
    if (ret == 0)
        ret = hdb_remove_base_keys(context, &h->entry, &base_keys);

    /* Keys not desired?  Don't derive them! */
    if (ret || !(flags & HDB_F_DECRYPT))
        return ret;

    /* Sanity check key rotations, determine current & last kr */
    if (kr->len < 1 || kr->len > 3)
        krb5_set_error_message(context, ret = HDB_ERR_NOENTRY,
                               "wrong number of virtual key rotation periods");
    for (current_kr = 0, last_kr = 0, i = 0;
         ret == 0 && i < kr->len; i++) {
        /* Check order */
        if (i && kr->val[i - 1].epoch <= kr->val[i].epoch) {
            krb5_set_error_message(context, ret = HDB_ERR_NOENTRY,
                                   "misordered key rotation periods");
            break;
        }
        /* At most one future epoch (the first one) */
        if (i && kr->val[i].epoch >= t) {
            krb5_set_error_message(context, ret = HDB_ERR_NOENTRY,
                                   "multiple future key rotation periods");
            break;
        }
        /* Identify current key rotation period */
        if (i == 0 && kr->val[0].epoch > t) {
            if (kr->len == 1) {
                krb5_set_error_message(context, ret = HDB_ERR_NOENTRY,
                                       "no current key rotation period");
                break;
            }
            current_kr = 1;
        }
        /* At most one relevant but kr older than current */
        if (i == current_kr + 1 &&
            (t - kr->val[i].period) <= (kr->val[i - 1].epoch))
            last_kr = i;
    }

    /* Check that the principal has not been marked deleted */
    if (kr->val[current_kr].flags.deleted)
        ret = HDB_ERR_NOENTRY;

    /*
     * Derive and set in `h' its current kvno and current keys
     * This will set h->entry.kvno as well.
     *
     * This may set up to TWO keysets for the current key rotation period:
     *  - current keys (h->entry.keys and h->entry.kvno)
     *  - possibly one future or one past keyset in hist_keys for the current_kr
     *
     * There may be up to ONE keyset for each of the next and precedinr key
     * rotation periods.
     */

    if (ret == 0 && h_is_namespace)
        ret = krb5_unparse_name(context, princ, &p);
    if (ret == 0)
        ret = derive_keys_for_current_kr(context, h, &base_keys, p, etype,
                                         kvno, t, &kr->val[current_kr]);

    /* Derive and set in `h' its future keys (key history only) */
    if (ret == 0 && current_kr != 0 &&
        t + kr->val[current_kr].period +
        (kr->val[current_kr].period >> 1) > kr->val[0].epoch)
        ret = derive_keys_for_kr(context, h, &base_keys, 0, 0, p, etype, kvno,
                                 kr->val[0].epoch, &kr->val[0]);

    /* Derive and set in `h' its past keys (key history only) */
    if (ret == 0 && last_kr && last_kr != current_kr)
        ret = derive_keys_for_kr(context, h, &base_keys, 0, 0, p, etype, kvno,
                                 kr->val[current_kr].epoch, &kr->val[last_kr]);

    /*
     * Impose a bound on h->entry.max_life so that [when the KDC is the caller]
     * the KDC won't issue tickets longer lived than this.
     *
     * It's OK if ret != 0 here.
     */
    if (h->entry.max_life &&
        *h->entry.max_life > kr->val[current_kr].period >> 1)
        *h->entry.max_life = kr->val[current_kr].period >> 1;

    free(p);
    free_HDB_Ext_KeySet(&base_keys);
    return ret;
}

/* Wrapper around db->hdb_fetch_kvno() that implements virtual princs/keys */
static krb5_error_code
fetch_it(krb5_context context,
         HDB *db,
         krb5_const_principal princ,
         unsigned flags,
         krb5_timestamp t,
         krb5int32 etype,
         krb5uint32 kvno,
         hdb_entry_ex *ent)
{
    krb5_const_principal tmpprinc = princ;
    krb5_principal baseprinc = NULL;
    krb5_error_code ret = 0;
    const char *realm = krb5_principal_get_realm(context, princ);
    const char *comp0 = krb5_principal_get_comp_string(context, princ, 0);
    const char *comp1 = krb5_principal_get_comp_string(context, princ, 1);
    const char *comp2 = krb5_principal_get_comp_string(context, princ, 2);
    const char *tmp;
    size_t mindots = db->virtual_hostbased_princ_ndots;
    size_t maxdots = db->virtual_hostbased_princ_maxdots;
    size_t hdots = 0;
    char *host = NULL;

    if (db->enable_virtual_hostbased_princs && comp1 &&
        strcmp("krbtgt", comp0) != 0) {
        char *htmp;

        if ((host = strdup(comp1)) == NULL)
            return krb5_enomem(context);

        /* Strip out any :port */
        htmp = strchr(host, ':');
        if (htmp) {
            if (strchr(htmp + 1, ':')) {
                /* Extra ':'s?  No virtualization for you! */
                free(host);
                host = NULL;
                htmp = NULL;
            } else {
                *htmp = '\0';
            }
        }
        /* Count dots in `host' */
        for (hdots = 0, htmp = host; htmp && *htmp; htmp++)
            if (*htmp == '.')
                hdots++;
    }

    tmp = host ? host : comp1;
    for (;;) {
        krb5_error_code ret2 = 0;
        /*
         * XXX In order to support the deleted KeyRotationFlags flag we'll have
         * refactor some of this searching for a parent namespace into a
         * utility function that can get called here and elsewhere above.
         */
        /*
         * We break out of this loop with ret == 0 only if we found the HDB
         * entry we were looking for or the HDB entry for a matching namespace.
         *
         * Otherwise we break out with ret != 0, typically HDB_ERR_NOENTRY.
         *
         * First time through we lookup the principal as given.
         *
         * Next we lookup a namespace principal, stripping off hostname labels
         * from the left until we find one or get tired of looking or run out
         * of labels.
         */
	ret = db->hdb_fetch_kvno(context, db, tmpprinc, flags, kvno, ent);
	if (ret != HDB_ERR_NOENTRY || hdots == 0 || hdots < mindots)
	    break;

        /* Here ret == 0 || ret == HDB_ERR_NOENTRY; we'll clobber ret */

        /*
         * Breadcrumb:
         *
         *  - if we found a concrete principal, but it's been marked
         *    as now-virtual, then we must keep going
         *
         * But this will be coded in the future.
         */

        /*
         * The namespace's hostname will not have more labels than maxdots + 1.
         * Thus we truncate immediately down to maxdots + 1 if we haven't yet.
         *
         * Example: with maxdots == 3,
         *          foo.bar.baz.app.blah.example -> baz.app.blah.example
         */
        while (maxdots && hdots > maxdots) {
            tmp = strchr(tmp, '.');
            /* tmp != NULL because maxdots > 0 */
            tmp++;
            hdots--;
        }

        if (baseprinc == NULL) {
            /* First go around, need a namespace princ.  Make it! */
            ret2 = krb5_build_principal(context, &baseprinc, strlen(realm),
                                        realm, "WELLKNOWN",
                                        "HOSTBASED-NAMESPACE", NULL);
            if (ret2 == 0 && comp2)
                /* Support domain-based names */
                ret2 = krb5_principal_set_comp_string(context, baseprinc, 3, comp2);
        }

        /* Update the hostname component */
        if (ret2 == 0)
            ret2 = krb5_principal_set_comp_string(context, baseprinc, 2, tmp);
        tmpprinc = baseprinc;

        /* Strip off left-most label for the next go-around */
	tmp = strchr(tmp, '.');
	if (!tmp) {
            ret = HDB_ERR_NOENTRY;
	    break;
        }
	tmp++;
	hdots--;
    }

    /*
     * If unencrypted keys were requested, derive them.  There may not be any
     * key derivation to do, but that's decided in derive_keys().
     */
    if (ret == 0)
        ret = derive_keys(context, flags, princ, !!baseprinc, t, etype, kvno,
                          ent);
    if (ret)
        hdb_free_entry(context, ent);

    krb5_free_principal(context, baseprinc);
    free(host);
    return ret;
}

/**
 * Fetch a principal's HDB entry, possibly generating virtual keys from base
 * keys according to strict key rotation schedules.  If a time is given, other
 * than HDB I/O, this function is pure, thus usable for testing.
 *
 * HDB writers should use `db->hdb_fetch_kvno()' to avoid materializing virtual
 * principals.
 *
 * HDB readers should use this function rather than `db->hdb_fetch_kvno()'
 * unless they only want to see concrete principals and not bother generating
 * any virtual keys.
 *
 * @param context Context
 * @param db HDB
 * @param principal Principal name
 * @param flags Fetch flags
 * @param t For virtual keys, use this as the point in time (use zero to mean "now")
 * @param etype Key enctype (use KRB5_ENCTYPE_NULL to mean "preferred")
 * @param kvno Key version number (use zero to mean "current")
 * @param h Output HDB entry
 *
 * @return Zero on success, an error code otherwise.
 */
krb5_error_code
hdb_fetch_kvno(krb5_context context,
               HDB *db,
               krb5_const_principal principal,
               unsigned flags,
               krb5_timestamp t,
               krb5int32 etype,
               krb5uint32 kvno,
               hdb_entry_ex *h)
{
    krb5_error_code ret = HDB_ERR_NOENTRY;
    krb5_principal enterprise_principal = NULL;

    flags |= kvno ? HDB_F_KVNO_SPECIFIED : HDB_F_ALL_KVNOS;
    if (t == 0)
        krb5_timeofday(context, &t);
    ret = fetch_it(context, db, principal, flags, t, etype, kvno, h);
    if (ret == HDB_ERR_NOENTRY)
	krb5_set_error_message(context, ret, "no such entry found in hdb");
    krb5_free_principal(context, enterprise_principal);
    return ret;
}
