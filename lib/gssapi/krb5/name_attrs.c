/*
 * Copyright (c) 2013, Cryptonector LLC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions, and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of Cryptonector LLC nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY CRYPTONECTOR LLC AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL CRYPTONECTOR LLC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "gsskrb5_locl.h"

#define EQ_BUF2BUF(b1, b2) \
    ((b1)->length == (b2)->length && \
     memcmp((b1)->value, (b2)->value, (b1)->length) == 0)

#define EQ_BUF2STR(b, s) \
    ((b)->length == strlen(s) && \
     strncmp((b)->value, s, (b)->length) == 0)

#define KRB5_NAME_ATTR_URN_PREFIX \
    "urn:ietf:id:ietf-kitten-name-attrs-00-krb5-"

#define KRB5_NAME_ATTR_REALM KRB5_NAME_ATTR_URN_PREFIX "realm"
#define KRB5_NAME_ATTR_COMPS KRB5_NAME_ATTR_URN_PREFIX "comps"
#define KRB5_NAME_ATTR_COMPN KRB5_NAME_ATTR_URN_PREFIX "compN"
#define KRB5_NAME_ATTR_NAME_TYPE KRB5_NAME_ATTR_URN_PREFIX "name-type"


static OM_uint32 ret_issuer(krb5_context, OM_uint32 *, krb5_const_principal,
                            int *, gss_buffer_t, gss_buffer_t);
static OM_uint32 ret_comp(krb5_context, OM_uint32 *, krb5_const_principal,
                          unsigned int, gss_buffer_t);
static OM_uint32 ret_comps(krb5_context, OM_uint32 *,
                           krb5_const_principal, int *, gss_buffer_t);

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_get_name_attribute(OM_uint32 *minor_status,
                            gss_name_t input_name,
                            gss_buffer_t attr,
                            int *authenticated,
                            int *complete,
                            gss_buffer_t value,
                            gss_buffer_t display_value,
                            int *more)
{
    krb5_context context;
    krb5_const_principal name = (krb5_const_principal)input_name;
    const char *nametype;
    char comp_attr[] = KRB5_NAME_ATTR_COMPN;
    char *s;
    size_t i, len;
    int32_t nt;

    GSSAPI_KRB5_INIT(&context);

    *minor_status = 0;
    if (value) {
        value->length = 0;
        value->value = 0;
    }
    if (display_value) {
        display_value->length = 0;
        display_value->value = 0;
    }

    /*
     * For now our attributes are all "complete" in the sense that there
     * are no attributes/values that we don't know about.
     */
    if (complete)
        *complete = 1;

    /*
     * Handling of the authenticated meta-attribute is currently
     * less than stellar.
     *
     * We need to check if a) the name's realm (issuer) is trusted, b)
     * if the transit path to it is trusted (but we only get a
     * krb5_const_principal here, so we lack such information), c) for
     * attrs like hostname and domainname may want to check if the
     * issuer is allowed to represent the given hostname/domainname
     * (i.e., check domain_realm, possibly using DNS!), or probably not
     * bother with DNS, just check that the domain matches the realm or
     * a domain_realm entry and be done.
     *
     * In particular we're going to have to revamp the mech so that it's
     * representation of principal names (the value saved in a
     * gss_name_t by the mechglue) has the enc part of the Ticket
     * (decrypted, and with the session key zeroed out), and a place to
     * cache things like the transit path (decompressed).
     *
     * In the meantime we set *authenticated = 0 for everything but
     * realm or name-type, in which case we set it to 1.
     */
    if (authenticated)
        *authenticated = 0;
    
    if (EQ_BUF2BUF(attr, GSS_C_ATTR_GENERIC_ISSUERNAME) ||
        EQ_BUF2STR(attr, KRB5_NAME_ATTR_REALM)) {
        if (more)
            *more = 0;
        return ret_issuer(context, minor_status, name, authenticated,
                          value, display_value);
    }

    /* Need to add a krb5_principal_display_name_type() */
    if (EQ_BUF2STR(attr, KRB5_NAME_ATTR_NAME_TYPE)) {
        if (!display_value)
            return GSS_S_COMPLETE;
        nt = krb5_principal_get_type(context, name);
        nametype = krb5_display_nametype(context, nt);
        if (nametype) {
            if (authenticated)
                *authenticated = 1;
            s = strdup(nametype);
        } else {
            s = strdup("UNKNOWN");
        }
        display_value->value = s;
        display_value->length = strlen(s);
        return GSS_S_COMPLETE;
    }

    if (EQ_BUF2BUF(attr, GSS_C_ATTR_GENERIC_USERNAME) ||
        EQ_BUF2BUF(attr, GSS_C_ATTR_GENERIC_SERVICENAME)) {
        if (more)
            *more = 0;
        return ret_comp(context, minor_status, name, 0, display_value);
    } else if (EQ_BUF2BUF(attr, GSS_C_ATTR_GENERIC_HOSTNAME)) {
        if (more)
            *more = 0;
        return ret_comp(context, minor_status, name, 1, display_value);
    } else if (EQ_BUF2BUF(attr, GSS_C_ATTR_GENERIC_DOMAINNAME)) {
        if (more)
            *more = 0;
        return ret_comp(context, minor_status, name, 2, display_value);
    } else if (EQ_BUF2STR(attr, KRB5_NAME_ATTR_COMPS)) {
        return ret_comps(context, minor_status, name, more, display_value);
    }

    if (more)
        *more = 0;

    len = strlen(comp_attr);
    for (i = 0; i < 10; i++) {
        comp_attr[len - 1] = '0' + i;
        if (EQ_BUF2STR(attr, comp_attr))
            return ret_comp(context, minor_status, name, i, display_value);
    }

    return GSS_S_UNAVAILABLE;
}

static
OM_uint32
ret_issuer(krb5_context context, OM_uint32 *minor_status,
           krb5_const_principal name, int *authenticated,
           gss_buffer_t value, gss_buffer_t display_value)
{
    OM_uint32 major_status;
    krb5_error_code ret;
    krb5_principal root_krbtgt = NULL;
    char *s;

    /* See note above */
    if (authenticated)
        *authenticated = 1;
    s = strdup(krb5_principal_get_realm(context, name));
    if (s == NULL) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    if (display_value) {
        display_value->value = s;
        display_value->length = strlen(s);
    }
    ret = krb5_make_principal(context, &root_krbtgt, s, KRB5_TGS_NAME, s, NULL);
    if (ret) {
        *minor_status = ret;
        major_status = GSS_S_FAILURE;
        goto out;
    }
    major_status = _gsskrb5_export_name(minor_status,
                                        (gss_const_name_t)root_krbtgt, value);

out:
    if (major_status != GSS_S_COMPLETE) {
        free(s);
        display_value->value = NULL;
        display_value->length = 0;
    }
    krb5_free_principal(context, root_krbtgt);
    return major_status;
}

static
OM_uint32
ret_comp(krb5_context context, OM_uint32 *minor_status,
         krb5_const_principal name, unsigned int comp,
         gss_buffer_t display_value)
{
    char *s;
    if (comp >= krb5_principal_get_num_comp(context, name))
        return GSS_S_COMPLETE; /* Attribute exists, but no value */

    s = strdup(krb5_principal_get_comp_string(context, name, comp));
    if (s == NULL) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    display_value->value = s;
    display_value->length = strlen(s);
    return GSS_S_COMPLETE;
}

static
OM_uint32
ret_comps(krb5_context context, OM_uint32 *minor_status,
          krb5_const_principal name, int *more,
          gss_buffer_t display_value)
{
    unsigned int comp;

    if (*more == -1) {
        *more = krb5_principal_get_num_comp(context, name);
    } else if (*more <= 0) {
        *minor_status = EINVAL;
        return GSS_S_FAILURE;
    } else {
        assert(*more > 0);
    }
    comp = *more - 1;
    (*more)--;
    assert(*more >= 0);
    return ret_comp(context, minor_status, name, comp, display_value);
}
