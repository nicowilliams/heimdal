/*
 * Copyright (c) 2024, Heimdal project
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

#include "tls_locl.h"

#include <errno.h>

/*
 * GSS-API import_name for TLS mechanism
 *
 * Supports:
 * - GSS_C_NT_HOSTBASED_SERVICE: "service@hostname" - used for SNI
 * - GSS_C_NT_ANONYMOUS: anonymous identity
 * - GSS_C_NT_EXPORT_NAME: previously exported name
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_import_name(OM_uint32 *minor,
                     const gss_buffer_t input_name,
                     const gss_OID name_type,
                     gss_name_t *output_name)
{
    gss_tls_name name = NULL;
    const char *s;
    char *at;

    *minor = 0;
    *output_name = GSS_C_NO_NAME;

    if (input_name == GSS_C_NO_BUFFER || input_name->length == 0) {
        *minor = EINVAL;
        return GSS_S_BAD_NAME;
    }

    /* Handle anonymous name type */
    if (name_type != GSS_C_NO_OID &&
        gss_oid_equal(name_type, GSS_C_NT_ANONYMOUS)) {
        *output_name = _gss_tls_anonymous_identity;
        return GSS_S_COMPLETE;
    }

    name = calloc(1, sizeof(*name));
    if (name == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    /* Default or hostbased service name */
    if (name_type == GSS_C_NO_OID ||
        gss_oid_equal(name_type, GSS_C_NT_HOSTBASED_SERVICE) ||
        gss_oid_equal(name_type, GSS_C_NT_USER_NAME)) {

        name->type = GSS_TLS_NAME_HOSTBASED;

        /* Parse "service@hostname" or just "hostname" */
        s = input_name->value;

        /* Ensure null-terminated for string operations */
        name->u.hostbased.hostname = malloc(input_name->length + 1);
        if (name->u.hostbased.hostname == NULL) {
            *minor = ENOMEM;
            free(name);
            return GSS_S_FAILURE;
        }
        memcpy(name->u.hostbased.hostname, s, input_name->length);
        name->u.hostbased.hostname[input_name->length] = '\0';

        /* Look for service@hostname format */
        at = strchr(name->u.hostbased.hostname, '@');
        if (at != NULL) {
            *at = '\0';
            name->u.hostbased.service = name->u.hostbased.hostname;
            name->u.hostbased.hostname = strdup(at + 1);
            if (name->u.hostbased.hostname == NULL) {
                *minor = ENOMEM;
                free(name->u.hostbased.service);
                free(name);
                return GSS_S_FAILURE;
            }
        }

        *output_name = (gss_name_t)name;
        return GSS_S_COMPLETE;
    }

    /* TODO: Handle GSS_C_NT_EXPORT_NAME */
    /* TODO: Handle X.509 DN name type */

    free(name);
    *minor = EINVAL;
    return GSS_S_BAD_NAMETYPE;
}

/*
 * GSS-API export_name for TLS mechanism
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_export_name(OM_uint32 *minor,
                     gss_const_name_t input_name,
                     gss_buffer_t output_name)
{
    gss_tls_name name = (gss_tls_name)input_name;
    size_t len;
    uint8_t *p;

    *minor = 0;
    output_name->length = 0;
    output_name->value = NULL;

    if (input_name == GSS_C_NO_NAME) {
        *minor = EINVAL;
        return GSS_S_BAD_NAME;
    }

    /* Handle anonymous */
    if (input_name == _gss_tls_anonymous_identity) {
        /* Export as empty name with mechanism OID prefix */
        /* Format: 0x04 0x01 | mech_oid_len | mech_oid | 0x00 0x00 0x00 0x00 */
        len = 4 + 2 + GSS_TLS_MECHANISM->length + 4;
        output_name->value = malloc(len);
        if (output_name->value == NULL) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }
        p = output_name->value;
        *p++ = 0x04;
        *p++ = 0x01;
        *p++ = (GSS_TLS_MECHANISM->length >> 8) & 0xff;
        *p++ = GSS_TLS_MECHANISM->length & 0xff;
        memcpy(p, GSS_TLS_MECHANISM->elements, GSS_TLS_MECHANISM->length);
        p += GSS_TLS_MECHANISM->length;
        *p++ = 0x00;
        *p++ = 0x00;
        *p++ = 0x00;
        *p++ = 0x00;
        output_name->length = len;
        return GSS_S_COMPLETE;
    }

    switch (name->type) {
    case GSS_TLS_NAME_HOSTBASED:
        /* Export as hostbased name */
        {
            size_t svc_len = name->u.hostbased.service ?
                             strlen(name->u.hostbased.service) : 0;
            size_t host_len = name->u.hostbased.hostname ?
                              strlen(name->u.hostbased.hostname) : 0;
            size_t name_len = svc_len + 1 + host_len;

            len = 4 + 2 + GSS_TLS_MECHANISM->length + 4 + name_len;
            output_name->value = malloc(len);
            if (output_name->value == NULL) {
                *minor = ENOMEM;
                return GSS_S_FAILURE;
            }
            p = output_name->value;
            *p++ = 0x04;
            *p++ = 0x01;
            *p++ = (GSS_TLS_MECHANISM->length >> 8) & 0xff;
            *p++ = GSS_TLS_MECHANISM->length & 0xff;
            memcpy(p, GSS_TLS_MECHANISM->elements, GSS_TLS_MECHANISM->length);
            p += GSS_TLS_MECHANISM->length;
            *p++ = (name_len >> 24) & 0xff;
            *p++ = (name_len >> 16) & 0xff;
            *p++ = (name_len >> 8) & 0xff;
            *p++ = name_len & 0xff;
            if (svc_len > 0) {
                memcpy(p, name->u.hostbased.service, svc_len);
                p += svc_len;
            }
            *p++ = '@';
            if (host_len > 0) {
                memcpy(p, name->u.hostbased.hostname, host_len);
            }
            output_name->length = len;
        }
        break;

    case GSS_TLS_NAME_X509_DN:
        /* TODO: Export X.509 DN */
        *minor = ENOTSUP;
        return GSS_S_UNAVAILABLE;

    case GSS_TLS_NAME_ANONYMOUS:
        /* Should have been caught above */
        *minor = EINVAL;
        return GSS_S_BAD_NAME;
    }

    return GSS_S_COMPLETE;
}

/*
 * GSS-API display_name for TLS mechanism
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_display_name(OM_uint32 *minor,
                      gss_const_name_t input_name,
                      gss_buffer_t output_name,
                      gss_OID *output_type)
{
    gss_tls_name name = (gss_tls_name)input_name;
    char *str = NULL;

    *minor = 0;
    output_name->length = 0;
    output_name->value = NULL;
    if (output_type)
        *output_type = GSS_C_NO_OID;

    if (input_name == GSS_C_NO_NAME) {
        *minor = EINVAL;
        return GSS_S_BAD_NAME;
    }

    /* Handle anonymous */
    if (input_name == _gss_tls_anonymous_identity) {
        str = strdup("<anonymous>");
        if (str == NULL) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }
        output_name->value = str;
        output_name->length = strlen(str);
        if (output_type)
            *output_type = GSS_C_NT_ANONYMOUS;
        return GSS_S_COMPLETE;
    }

    switch (name->type) {
    case GSS_TLS_NAME_HOSTBASED:
        if (name->u.hostbased.service) {
            if (asprintf(&str, "%s@%s",
                        name->u.hostbased.service,
                        name->u.hostbased.hostname ? name->u.hostbased.hostname : "") < 0) {
                *minor = ENOMEM;
                return GSS_S_FAILURE;
            }
        } else {
            str = strdup(name->u.hostbased.hostname ? name->u.hostbased.hostname : "");
            if (str == NULL) {
                *minor = ENOMEM;
                return GSS_S_FAILURE;
            }
        }
        if (output_type)
            *output_type = GSS_C_NT_HOSTBASED_SERVICE;
        break;

    case GSS_TLS_NAME_X509_DN:
        /* TODO: Use hx509_name_to_string */
        if (name->u.x509_name) {
            char *dn = NULL;
            int ret = hx509_name_to_string(name->u.x509_name, &dn);
            if (ret == 0 && dn) {
                str = dn;
            } else {
                str = strdup("<X.509 DN>");
                if (str == NULL) {
                    *minor = ENOMEM;
                    return GSS_S_FAILURE;
                }
            }
        } else {
            str = strdup("<X.509 DN>");
            if (str == NULL) {
                *minor = ENOMEM;
                return GSS_S_FAILURE;
            }
        }
        break;

    case GSS_TLS_NAME_ANONYMOUS:
        str = strdup("<anonymous>");
        if (str == NULL) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }
        if (output_type)
            *output_type = GSS_C_NT_ANONYMOUS;
        break;
    }

    output_name->value = str;
    output_name->length = strlen(str);
    return GSS_S_COMPLETE;
}

/*
 * GSS-API compare_name for TLS mechanism
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_compare_name(OM_uint32 *minor,
                      gss_const_name_t name1,
                      gss_const_name_t name2,
                      int *name_equal)
{
    gss_tls_name n1 = (gss_tls_name)name1;
    gss_tls_name n2 = (gss_tls_name)name2;

    *minor = 0;
    *name_equal = 0;

    /* Handle anonymous comparisons */
    if (name1 == _gss_tls_anonymous_identity) {
        *name_equal = (name2 == _gss_tls_anonymous_identity);
        return GSS_S_COMPLETE;
    }
    if (name2 == _gss_tls_anonymous_identity) {
        *name_equal = 0;
        return GSS_S_COMPLETE;
    }

    if (name1 == GSS_C_NO_NAME || name2 == GSS_C_NO_NAME) {
        *name_equal = (name1 == name2);
        return GSS_S_COMPLETE;
    }

    /* Types must match */
    if (n1->type != n2->type) {
        *name_equal = 0;
        return GSS_S_COMPLETE;
    }

    switch (n1->type) {
    case GSS_TLS_NAME_HOSTBASED:
        /* Compare hostname (case-insensitive for DNS names) */
        if (n1->u.hostbased.hostname && n2->u.hostbased.hostname) {
            if (strcasecmp(n1->u.hostbased.hostname,
                          n2->u.hostbased.hostname) != 0) {
                *name_equal = 0;
                return GSS_S_COMPLETE;
            }
        } else if (n1->u.hostbased.hostname || n2->u.hostbased.hostname) {
            *name_equal = 0;
            return GSS_S_COMPLETE;
        }
        /* Compare service (case-sensitive) */
        if (n1->u.hostbased.service && n2->u.hostbased.service) {
            *name_equal = (strcmp(n1->u.hostbased.service,
                                 n2->u.hostbased.service) == 0);
        } else {
            *name_equal = (n1->u.hostbased.service == n2->u.hostbased.service);
        }
        break;

    case GSS_TLS_NAME_X509_DN:
        /* Compare X.509 DNs */
        if (n1->u.x509_name && n2->u.x509_name) {
            *name_equal = (hx509_name_cmp(n1->u.x509_name, n2->u.x509_name) == 0);
        } else {
            *name_equal = (n1->u.x509_name == n2->u.x509_name);
        }
        break;

    case GSS_TLS_NAME_ANONYMOUS:
        *name_equal = 1;
        break;
    }

    return GSS_S_COMPLETE;
}

/*
 * GSS-API release_name for TLS mechanism
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_release_name(OM_uint32 *minor,
                      gss_name_t *name)
{
    gss_tls_name n;

    *minor = 0;

    if (name == NULL || *name == GSS_C_NO_NAME)
        return GSS_S_COMPLETE;

    /* Don't free the singleton anonymous identity */
    if (*name == _gss_tls_anonymous_identity) {
        *name = GSS_C_NO_NAME;
        return GSS_S_COMPLETE;
    }

    n = (gss_tls_name)*name;

    switch (n->type) {
    case GSS_TLS_NAME_HOSTBASED:
        free(n->u.hostbased.service);
        free(n->u.hostbased.hostname);
        break;
    case GSS_TLS_NAME_X509_DN:
        if (n->u.x509_name)
            hx509_name_free(&n->u.x509_name);
        break;
    case GSS_TLS_NAME_ANONYMOUS:
        break;
    }

    free(n);
    *name = GSS_C_NO_NAME;
    return GSS_S_COMPLETE;
}

/*
 * GSS-API duplicate_name for TLS mechanism
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_duplicate_name(OM_uint32 *minor,
                        gss_const_name_t src_name,
                        gss_name_t *dest_name)
{
    gss_tls_name src = (gss_tls_name)src_name;
    gss_tls_name dst = NULL;

    *minor = 0;
    *dest_name = GSS_C_NO_NAME;

    if (src_name == GSS_C_NO_NAME) {
        return GSS_S_COMPLETE;
    }

    /* Anonymous is a singleton */
    if (src_name == _gss_tls_anonymous_identity) {
        *dest_name = _gss_tls_anonymous_identity;
        return GSS_S_COMPLETE;
    }

    dst = calloc(1, sizeof(*dst));
    if (dst == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    dst->type = src->type;

    switch (src->type) {
    case GSS_TLS_NAME_HOSTBASED:
        if (src->u.hostbased.service) {
            dst->u.hostbased.service = strdup(src->u.hostbased.service);
            if (dst->u.hostbased.service == NULL) {
                *minor = ENOMEM;
                free(dst);
                return GSS_S_FAILURE;
            }
        }
        if (src->u.hostbased.hostname) {
            dst->u.hostbased.hostname = strdup(src->u.hostbased.hostname);
            if (dst->u.hostbased.hostname == NULL) {
                *minor = ENOMEM;
                free(dst->u.hostbased.service);
                free(dst);
                return GSS_S_FAILURE;
            }
        }
        break;

    case GSS_TLS_NAME_X509_DN:
        if (src->u.x509_name) {
            int ret = hx509_name_copy(NULL, src->u.x509_name, &dst->u.x509_name);
            if (ret) {
                *minor = ret;
                free(dst);
                return GSS_S_FAILURE;
            }
        }
        break;

    case GSS_TLS_NAME_ANONYMOUS:
        break;
    }

    *dest_name = (gss_name_t)dst;
    return GSS_S_COMPLETE;
}

/*
 * GSS-API canonicalize_name for TLS mechanism
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_canonicalize_name(OM_uint32 *minor,
                           gss_const_name_t input_name,
                           const gss_OID mech_type,
                           gss_name_t *output_name)
{
    (void)mech_type;

    /* For TLS, canonicalization is just duplication */
    return _gss_tls_duplicate_name(minor, input_name, output_name);
}

/*
 * GSS-API inquire_names_for_mech for TLS mechanism
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_inquire_names_for_mech(OM_uint32 *minor,
                                const gss_OID mechanism,
                                gss_OID_set *name_types)
{
    OM_uint32 major;

    (void)mechanism;

    *minor = 0;

    major = gss_create_empty_oid_set(minor, name_types);
    if (major != GSS_S_COMPLETE)
        return major;

    /* We support hostbased service names (for SNI) */
    major = gss_add_oid_set_member(minor, GSS_C_NT_HOSTBASED_SERVICE, name_types);
    if (major != GSS_S_COMPLETE) {
        gss_release_oid_set(minor, name_types);
        return major;
    }

    /* We support anonymous names */
    major = gss_add_oid_set_member(minor, GSS_C_NT_ANONYMOUS, name_types);
    if (major != GSS_S_COMPLETE) {
        gss_release_oid_set(minor, name_types);
        return major;
    }

    return GSS_S_COMPLETE;
}

/*
 * GSS-API inquire_mechs_for_name for TLS mechanism
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_inquire_mechs_for_name(OM_uint32 *minor,
                                gss_const_name_t input_name,
                                gss_OID_set *mech_types)
{
    OM_uint32 major;

    (void)input_name;

    *minor = 0;

    major = gss_create_empty_oid_set(minor, mech_types);
    if (major != GSS_S_COMPLETE)
        return major;

    major = gss_add_oid_set_member(minor, GSS_TLS_MECHANISM, mech_types);
    if (major != GSS_S_COMPLETE) {
        gss_release_oid_set(minor, mech_types);
        return major;
    }

    return GSS_S_COMPLETE;
}
