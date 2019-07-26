/*
 * Copyright (c) 2003 Kungliga Tekniska Högskolan
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

#include "gsskrb5_locl.h"

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_store_cred_into(OM_uint32         *minor_status,
			 gss_const_cred_id_t input_cred_handle,
			 gss_cred_usage_t  cred_usage,
			 const gss_OID     desired_mech,
			 OM_uint32         overwrite_cred,
			 OM_uint32         default_cred,
			 gss_const_key_value_set_t cred_store,
			 gss_OID_set       *elements_stored,
			 gss_cred_usage_t  *cred_usage_stored)
{
    krb5_context context;
    krb5_error_code ret;
    gsskrb5_cred input_cred;
    krb5_ccache id = NULL;
    const char *cctype = NULL;
    time_t exp_current;
    time_t exp_new;
    const char *cs_ccache_name = NULL;
    OM_uint32 major_status;

    *minor_status = 0;

    /* Sanity check inputs */
    if (cred_usage != GSS_C_INITIATE) {
	*minor_status = GSS_KRB5_S_G_BAD_USAGE;
	return GSS_S_FAILURE;
    }
    if (desired_mech != GSS_C_NO_OID &&
        gss_oid_equal(desired_mech, GSS_KRB5_MECHANISM) == 0)
	return GSS_S_BAD_MECH;
    if (input_cred_handle == GSS_C_NO_CREDENTIAL)
	return GSS_S_CALL_INACCESSIBLE_READ;
    input_cred = (gsskrb5_cred)input_cred_handle;

    HEIMDAL_MUTEX_lock(&input_cred->cred_id_mutex);

    /* Sanity check the input_cred */
    if (input_cred->usage != cred_usage && input_cred->usage != GSS_C_BOTH) {
	HEIMDAL_MUTEX_unlock(&input_cred->cred_id_mutex);
	*minor_status = GSS_KRB5_S_G_BAD_USAGE;
	return GSS_S_NO_CRED;
    }
    if (input_cred->principal == NULL) {
	HEIMDAL_MUTEX_unlock(&input_cred->cred_id_mutex);
	*minor_status = GSS_KRB5_S_KG_TGT_MISSING;
	return GSS_S_NO_CRED;
    }

    /* More sanity checking of the input_cred (good to fail early) */
    GSSAPI_KRB5_INIT (&context);
    ret = krb5_cc_get_lifetime(context, input_cred->ccache, &exp_new);
    if (ret) {
	HEIMDAL_MUTEX_unlock(&input_cred->cred_id_mutex);
	*minor_status = ret;
	return GSS_S_NO_CRED;
    }

    /* Extact the ccache name from the store if given */
    if (cred_store != GSS_C_NO_CRED_STORE) {
	major_status = __gsskrb5_cred_store_find(minor_status, cred_store,
						 "ccache", &cs_ccache_name);
	if (major_status == GSS_S_COMPLETE && cs_ccache_name == NULL) {
	    *minor_status = GSS_KRB5_S_G_UNKNOWN_CRED_STORE_ELEMENT;
	    major_status = GSS_S_NO_CRED;
	}
	if (GSS_ERROR(major_status)) {
	    HEIMDAL_MUTEX_unlock(&input_cred->cred_id_mutex);
	    return major_status;
	}
    }

    /*
     * Main event.
     *
     * We need to resolve the given ccache, if given, else find the default,
     * then we need to decide whether to overwrite.
     *
     * Wrinkle: DIR and KCM ccache types (and maybe SQLITE, and maybe API, and
     * maybe others) support storing multiple principals' creds in one ccache,
     * and they have a notion of "default principal" that can be switched.
     *
     * We have {ccache?, default_cred, overwrite} as inputs to help us decide
     * exactly what to do.  If the ccache we find is "switchable" then we'll
     * always create a "new unique" sub-ccache and set `overwrite=1'.  If we
     * don't find a ccache already there then we'll set `overwrite=1'.
     *
     * If `overwrite=1' then we'll krb5_cc_initialize(), else we'll bail.
     *
     * If `default_cred' then we'll switch the ccache if it's switchable, else
     * ??
     */

    if (cs_ccache_name) {
	ret = krb5_cc_resolve(context, cs_ccache_name, &id);
        if (ret == 0)
            cctype = krb5_cc_get_type(context, def_ccache);
    } else {
        krb5_ccache def_ccache = NULL;

        ret = krb5_cc_default(context, &def_ccache);
        if (ret == 0)
	    cctype = krb5_cc_get_type(context, def_ccache);
        if (ret == 0) {
            if (!krb5_cc_support_switch(context, cctype)) {
                /*
                 * Not a DIR or KCM ccache, so we can't store more than one
                 * principal's credentials in the default ccache.
                 */
                id = def_ccache;
                def_ccache = NULL;
            } else {
                /*
                 * A DIR or KCM ccache, so we will create / reinitialize a
                 * ccache in there for the delegated credentials.
                 *
                 * Our krb5_cc_new_unique() does not implement the same
                 * semantics as MIT's, but those are the semantics we need.
                 * Since both do not (well, did not) use the hint argument, and
                 * all callers pass NULL for it we'll have a magical value that
                 * says "do the MIT thing".
                 */
                ret = krb5_cc_new_unique(context, cctype, (char *)1, &id);
                if (ret == 0)
                    overwrite_cred = 1; /* We created it, it's unique */
            }
        }
        (void) krb5_cc_close(context, def_ccache);
    }

    if (ret || id == NULL) {
	HEIMDAL_MUTEX_unlock(&input_cred->cred_id_mutex);
	*minor_status = ret;
	return ret == 0 ? GSS_S_NO_CRED : GSS_S_FAILURE;
    }

    if (!overwrite_cred) {
        /* If current creds are expired or near it, overwrite */
        ret = krb5_cc_get_lifetime(context, id, &exp_current);
        if (ret != 0 || exp_new > exp_current)
            overwrite_cred = 1;
    }

    if (!overwrite_cred) {
        /* Nothing to do */
        krb5_cc_close(context, id);
        HEIMDAL_MUTEX_unlock(&input_cred->cred_id_mutex);
        *minor_status = 0;
        return GSS_S_DUPLICATE_ELEMENT;
    }

    ret = krb5_cc_initialize(context, id, input_cred->principal);
    if (ret == 0)
        ret = krb5_cc_copy_match_f(context, input_cred->ccache, id, NULL, NULL,
                                   NULL);

    if (ret == 0 && default_cred &&
        krb5_cc_support_switch(context, cctype))
	krb5_cc_switch(context, id);
    (void) krb5_cc_close(context, id);

    HEIMDAL_MUTEX_unlock(&input_cred->cred_id_mutex);
    *minor_status = ret;
    return ret ? GSS_S_FAILURE : GSS_S_COMPLETE;
}
