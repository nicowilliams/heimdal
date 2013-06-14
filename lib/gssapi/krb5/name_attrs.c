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

#define KRB5_NAME_ATTR_URN_PREFIX \
    "urn:ietf:id:ietf-kitten-name-attrs-00-krb5-"

#define KRB5_NAME_ATTR_REALM KRB5_NAME_ATTR_URN_PREFIX "realm"
#define KRB5_NAME_ATTR_COMPS KRB5_NAME_ATTR_URN_PREFIX "comps"
#define KRB5_NAME_ATTR_NAME_TYPE KRB5_NAME_ATTR_URN_PREFIX "name-type"

enum krb5_mech_name_attr {
    K5_MNA_UNKNOWN,
    K5_MNA_REALM,
    K5_MNA_NAME_TYPE,
    K5_MNA_USERNAME,
    K5_MNA_LOCAL_USERNAME,
    K5_MNA_HOSTNAME,
    K5_MNA_DOMAINNAME,
    K5_MNA_COMPS, /* iterate components */
    K5_MNA_COMP0, /* component 0 */
    K5_MNA_COMP1, /* component 1 */
    K5_MNA_COMP2, /* .. */
    K5_MNA_COMP3,
    K5_MNA_COMP4,
    K5_MNA_COMP5,
    K5_MNA_COMP6,
    K5_MNA_COMP7,
    K5_MNA_COMP8,
    K5_MNA_COMP9, /* component 9 */
    K5_MNA_MAX,
};

struct krb5_mech_name_attr_map {
    const char *attrname;
    enum krb5_mech_name_attr attrnum;
} attr_map[] = {
    /* Generic name attributes */
    { GSS_C_ATTR_GENERIC_ISSUERNAME, K5_MNA_REALM },
    { GSS_C_ATTR_GENERIC_SERVICENAME, K5_MNA_COMP0 },
    /* These differ from K5_MNA_COMPn below in that they are constrained */
    { GSS_C_ATTR_GENERIC_USERNAME, K5_MNA_USERNAME },
    { GSS_C_ATTR_GENERIC_HOSTNAME, K5_MNA_HOSTNAME },
    { GSS_C_ATTR_GENERIC_DOMAINNAME, K5_MNA_DOMAINNAME },
    /* Name attributes specific to the Kerberos mechanism */
    { KRB5_NAME_ATTR_REALM, K5_MNA_REALM },
    { KRB5_NAME_ATTR_NAME_TYPE, K5_MNA_NAME_TYPE },
    { KRB5_NAME_ATTR_COMPS, K5_MNA_COMPS },
    { KRB5_NAME_ATTR_URN_PREFIX "compo0", K5_MNA_COMP0 },
    { KRB5_NAME_ATTR_URN_PREFIX "compo1", K5_MNA_COMP1 },
    { KRB5_NAME_ATTR_URN_PREFIX "compo2", K5_MNA_COMP2 },
    { KRB5_NAME_ATTR_URN_PREFIX "compo3", K5_MNA_COMP3 },
    { KRB5_NAME_ATTR_URN_PREFIX "compo4", K5_MNA_COMP4 },
    { KRB5_NAME_ATTR_URN_PREFIX "compo5", K5_MNA_COMP5 },
    { KRB5_NAME_ATTR_URN_PREFIX "compo6", K5_MNA_COMP6 },
    { KRB5_NAME_ATTR_URN_PREFIX "compo7", K5_MNA_COMP7 },
    { KRB5_NAME_ATTR_URN_PREFIX "compo8", K5_MNA_COMP8 },
    { KRB5_NAME_ATTR_URN_PREFIX "compo9", K5_MNA_COMP9 },
};

static enum krb5_mech_name_attr attrname2attrnum(const char *, size_t);
static void parse_attr(gss_buffer_t, gss_buffer_t, size_t *, size_t *,
                       size_t *);
static OM_uint32 validate_username(krb5_context, OM_uint32 *,
                                   krb5_const_principal, size_t, const char *,
                                   const char *, gss_buffer_t, int *);
static OM_uint32 validate_domainname(krb5_context, OM_uint32 *, size_t,
                                     size_t, const char *, const char *,
                                     const char *, gss_buffer_t, int *);
static OM_uint32 ret_issuer(krb5_context, OM_uint32 *, krb5_const_principal,
                            gss_buffer_t, gss_buffer_t);
static OM_uint32 ret_lname(krb5_context, OM_uint32 *, krb5_const_principal,
                           gss_buffer_t);
static OM_uint32 ret_comp(krb5_context, OM_uint32 *, krb5_const_principal,
                          unsigned int, gss_buffer_t);
static OM_uint32 ret_comps(krb5_context, OM_uint32 *,
                           krb5_const_principal, int *, gss_buffer_t);

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_get_name_attribute(OM_uint32 *minor_status,
                            gss_const_name_t input_name,
                            gss_buffer_t attr,
                            int *authenticated,
                            int *complete,
                            gss_buffer_t value,
                            gss_buffer_t display_value,
                            int *more)
{
    krb5_context context;
    krb5_const_principal name = (krb5_const_principal)input_name;
    enum krb5_mech_name_attr attr_num;
    const char *nametype;
    gss_buffer_desc attr_tail;
    char *s;
    size_t constrained = 1, unconstrained_ok = 0, fast = 0;
    int32_t nt;
    OM_uint32 major_status;

    GSSAPI_KRB5_INIT(&context);

    parse_attr(attr, &attr_tail, &constrained, &unconstrained_ok, &fast);
    attr_num = attrname2attrnum(attr_tail.value, attr_tail.length);
    
    if (attr_num == K5_MNA_UNKNOWN)
        return GSS_S_UNAVAILABLE;

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
     * are no attributes/values that we don't know about.  This might
     * change, e.g., with CAMMAC, or with PAC (we won't know about
     * domain group memberships for domains not in the transit path).
     */
    if (complete)
        *complete = 1;

    /*
     * All principal name components are authenticated.  It's some
     * authz-data that might not be: those that are not in
     * AD-KDC-ISSUED in Ticket or similar (e.g., PAC, CAMMAC), an dall
     * that are in the Authenticator authz-data.  Since for now we have
     * none of the Ticket nor Authenticator authz-data in the krb5
     * mech's gss_name_t...
     */
    if (authenticated)
        *authenticated = 1;
    
    if (attr_num == K5_MNA_REALM) {
        if (more)
            *more = 0;
        return ret_issuer(context, minor_status, name, value, display_value);
    }

    /* Need to add a krb5_principal_display_name_type() */
    if (attr_num == K5_MNA_NAME_TYPE) {
        if (!display_value)
            return GSS_S_COMPLETE;
        nt = krb5_principal_get_type(context, name);
        nametype = krb5_display_nametype(context, nt);
        s = strdup(nametype ? nametype : "UNKNOWN");
        display_value->value = s;
        display_value->length = strlen(s);
        return GSS_S_COMPLETE;
    }

    if (attr_num == K5_MNA_LOCAL_USERNAME) {
        if (more)
            *more = 0;
        return ret_lname(context, minor_status, name, display_value);
    }

    if (attr_num == K5_MNA_USERNAME || attr_num == K5_MNA_COMP0) {
        if (more)
            *more = 0;
        major_status = ret_comp(context, minor_status, name, 0, display_value);
        if (major_status != GSS_S_COMPLETE)
            return major_status;
        if (attr_num == K5_MNA_USERNAME && constrained) {
            return validate_username(context, minor_status, name,
                                     unconstrained_ok,
                                     krb5_principal_get_realm(context, name),
                                     krb5_principal_get_comp_string(context,
                                                                    name, 0),
                                     display_value, authenticated);
        }
        return GSS_S_COMPLETE;
    }
    if (attr_num == K5_MNA_HOSTNAME || attr_num == K5_MNA_COMP1) {
        if (more)
            *more = 0;
        major_status = ret_comp(context, minor_status, name, 1, display_value);
        if (major_status != GSS_S_COMPLETE)
            return major_status;
        if (attr_num == K5_MNA_HOSTNAME && constrained) {
            return validate_domainname(context, minor_status,
                                       unconstrained_ok, fast,
                                       krb5_principal_get_realm(context, name),
                                       NULL,
                                       krb5_principal_get_comp_string(context,
                                                                      name, 0),
                                       display_value, authenticated);
        }
        return GSS_S_COMPLETE;
    }
    if (attr_num == K5_MNA_DOMAINNAME || attr_num == K5_MNA_COMP2) {
        if (more)
            *more = 0;
        major_status = ret_comp(context, minor_status, name, 2, display_value);
        if (major_status != GSS_S_COMPLETE)
            return major_status;
        if (attr_num == K5_MNA_DOMAINNAME && constrained) {
            return validate_domainname(context, minor_status,
                                       unconstrained_ok, fast,
                                       krb5_principal_get_realm(context, name),
                                       krb5_principal_get_comp_string(context,
                                                                      name, 0),
                                       NULL,
                                       display_value, authenticated);
        }
        return GSS_S_COMPLETE;
    }

    /* No validation for these */
    if (attr_num == K5_MNA_COMPS)
        return ret_comps(context, minor_status, name, more, display_value);

    /*
     * Lastly, get a specific component between 0 and 9 (inclusive),
     * where the number is the last digit char in the attribute name.
     */
    assert(attr_num > K5_MNA_COMP2 && attr_num < K5_MNA_MAX);
    if (more)
        *more = 0;

    return ret_comp(context, minor_status, name, attr_num - K5_MNA_COMP0,
                    display_value);
}

static
void
tolower_str(char *p)
{
    for (; *p; p++)
        *p = (char)tolower(*p);
}

static
OM_uint32
validate_username(krb5_context context, OM_uint32 *minor_status,
                  krb5_const_principal name, size_t unconstrained_ok,
                  const char *realm, const char *username,
                  gss_buffer_t display_value, int *authenticated)
{
    OM_uint32 major_status = GSS_S_UNAVAILABLE;
    krb5_error_code ret;
    const char *s;
    char *def_realm = NULL;
    char *domain = NULL;
    gss_buffer_desc lname = {0, 0};

    /* XXX Check user_realm instead */
    ret = krb5_get_default_realm(context, &def_realm);
    if (ret)
        goto cleanup;

    if (!strcmp(realm, def_realm)) {
        major_status = GSS_S_COMPLETE;
        goto cleanup;
    }

    s = strchr(username, '@');
    if (!s)
        goto cleanup;
    s++;
    domain = strdup(s);
    if (!domain) {
        ret = krb5_enomem(context);
        goto cleanup;
    }
    tolower_str(domain);
    if (!strcmp(domain, realm)) {
        major_status = GSS_S_COMPLETE;
        goto cleanup;
    }

    /* Check aname2lname */
    major_status = ret_lname(context, minor_status, name, &lname);
    if (!unconstrained_ok && major_status == GSS_S_COMPLETE &&
        strcmp(username, lname.value) != 0) {
        major_status = GSS_S_UNAVAILABLE;
    }

    /* TODO: check kuserok?! */

cleanup:
    free(lname.value);
    free(def_realm);
    free(domain);
    if (!unconstrained_ok && display_value &&
        (ret || major_status != GSS_S_COMPLETE)) {
        display_value->value = NULL;
        display_value->length = 0;
    }
    if (ret) {
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    if (major_status == GSS_S_UNAVAILABLE && unconstrained_ok) {
        if (authenticated)
            *authenticated = 0;
        return GSS_S_COMPLETE;
    }
    return major_status;
}

static
OM_uint32
validate_domainname(krb5_context context, OM_uint32 *minor_status,
                    size_t unconstrained_ok, size_t fast, const char *realm,
                    const char *domainname, const char *host,
                    gss_buffer_t display_value, int *authenticated)
{
    OM_uint32 major_status = GSS_S_UNAVAILABLE;
    krb5_error_code ret = 0;
    krb5_realm *realms = NULL;
    char *domain = NULL;
    char *def_realm = NULL;
    size_t i;

    ret = krb5_get_default_realm(context, &def_realm);
    if (ret)
        goto cleanup;

    if (!strcmp(realm, def_realm)) {
        major_status = GSS_S_COMPLETE;
        goto cleanup;
    }

    if (host && !strchr(host, '.')) {
        /* We should check all default realms here */
        if (!strcmp(realm, def_realm))
            major_status = GSS_S_COMPLETE;
        goto cleanup;
    } else if (host) {
        domainname = strchr(host, '.') + 1;
    }

    domain = strdup(domainname);
    if (!domain) {
        ret = krb5_enomem(context);
        goto cleanup;
    }
    tolower_str(domain);
    if (!strcmp(domain, realm)) {
        major_status = GSS_S_COMPLETE;
        goto cleanup;
    }

    ret = _krb5_get_host_realm_int(context, host, !fast, &realms);
    if (ret)
        goto cleanup;
    for (i = 0; realms[i]; i++) {
        tolower_str(realms[i]);
        if (!strcmp(domain, realms[i])) {
            major_status = GSS_S_COMPLETE;
            goto cleanup;
        }
    }

cleanup:
    krb5_free_host_realm(context, realms);
    free(def_realm);
    free(domain);
    if (!unconstrained_ok && display_value &&
        (ret || major_status != GSS_S_COMPLETE)) {
        display_value->value = NULL;
        display_value->length = 0;
    }
    if (ret) {
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    if (major_status == GSS_S_UNAVAILABLE && unconstrained_ok) {
        if (authenticated)
            *authenticated = 0;
        return GSS_S_COMPLETE;
    }
    return major_status;
}

static
OM_uint32
ret_issuer(krb5_context context, OM_uint32 *minor_status,
           krb5_const_principal name, gss_buffer_t value,
           gss_buffer_t display_value)
{
    OM_uint32 major_status = GSS_S_COMPLETE;
    krb5_error_code ret;
    krb5_principal realm = NULL;
    char *s;

    s = strdup(krb5_principal_get_realm(context, name));
    if (s == NULL) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    if (display_value) {
        display_value->value = s;
        display_value->length = strlen(s);
    }

    if (!value)
        return GSS_S_COMPLETE;

    ret = krb5_make_principal(context, &realm, s, NULL);
    if (ret) {
        free(s);
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    major_status = _gsskrb5_export_name(minor_status,
                                        (const gss_name_t)realm, value);

    krb5_free_principal(context, realm);
    if (major_status != GSS_S_COMPLETE) {
        free(s);
        display_value->value = NULL;
        display_value->length = 0;
    }
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
        return GSS_S_UNAVAILABLE;
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
    unsigned int comp, comps;

    if (more == NULL)
        return GSS_S_UNAVAILABLE;

    comps = krb5_principal_get_num_comp(context, name);

    if (*more == -1) {
        *more = comps;
    } else if (*more <= 0) {
        *minor_status = EINVAL;
        return GSS_S_FAILURE;
    } else {
        assert(*more > 0);
    }
    comp = comps - *more;
    (*more)--;
    assert(*more >= 0);
    return ret_comp(context, minor_status, name, comp, display_value);
}

static
OM_uint32
ret_lname(krb5_context context, OM_uint32 *minor_status,
          krb5_const_principal name, gss_buffer_t display_value)
{
    char *lname;

    lname = malloc(256); /* XXX krb5_aname_to_localname() sucks */
    if (!lname) {
        *minor_status = krb5_enomem(context);
        return GSS_S_FAILURE;
    }

    *minor_status = krb5_aname_to_localname(context, name, sizeof(lname), lname);
    if (*minor_status == 0) {
        if (display_value) {
            display_value->value = lname;
            display_value->length = strlen(lname);
            lname = NULL;
        }
        free(lname);
        return GSS_S_COMPLETE;
    }
    free(lname);
    if (*minor_status == KRB5_NO_LOCALNAME)
        return GSS_S_UNAVAILABLE;
    return GSS_S_FAILURE;
}

static
enum krb5_mech_name_attr
attrname2attrnum(const char *attrname, size_t attrname_len)
{
    size_t i;

    for (i = 0; i < sizeof(attr_map)/sizeof(attr_map[0]); i++) {
        if (strncmp(attrname, attr_map[i].attrname, attrname_len) == 0)
            return attr_map[i].attrnum;
    }
    if (!strncmp(attrname, GSS_C_ATTR_LOCAL_LOGIN_USER->value,
                min(attrname_len, GSS_C_ATTR_LOCAL_LOGIN_USER->length)))
        return K5_MNA_LOCAL_USERNAME;
    return K5_MNA_UNKNOWN;
}

static void
parse_attr(gss_buffer_t attr, gss_buffer_t tail, size_t *constrained,
           size_t *unconstrained_ok, size_t *fast)
{
    const char *prefix;
    size_t prefix_len;
    gss_buffer_desc buf;

    tail->value = memchr(attr->value, ' ', attr->length);
    if (tail->value == NULL) {
        *tail = *attr;
        return;
    }
    tail->value = (char *)tail->value + 1;
    tail->length = attr->length - (((char *)tail->value) - (char *)attr->value);
    prefix = attr->value;
    prefix_len = attr->length - tail->length - 1;
    if (strncmp(prefix, GSS_C_ATTR_GENERIC_UNCONSTRAINED, prefix_len) == 0)
        *constrained = 0;
    else if (strncmp(prefix, GSS_C_ATTR_GENERIC_UNCONSTRAINED_OK, prefix_len) == 0)
        *unconstrained_ok = 1;
    else if (strncmp(prefix, GSS_C_ATTR_GENERIC_FAST, prefix_len) == 0)
        *fast = 1;

    /*
     * Tail recurse; it's at most three times, and if the compiler isn't
     * dumb we could go many more times anyways (as long as we return!).
     */
    buf = *tail;
    parse_attr(&buf, tail, constrained, unconstrained_ok, fast);
}
