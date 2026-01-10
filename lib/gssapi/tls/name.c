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
 * Helper: Check if OID matches one of the string-valued SAN types
 * Returns 1 if it's a string SAN type, 0 otherwise
 */
static int
is_string_san_type(const gss_OID_desc *oid)
{
    return gss_oid_equal(oid, GSS_C_NT_X509_RFC822NAME) ||
           gss_oid_equal(oid, GSS_C_NT_X509_DNSNAME) ||
           gss_oid_equal(oid, GSS_C_NT_X509_URI) ||
           gss_oid_equal(oid, GSS_C_NT_MS_UPN_SAN) ||
           gss_oid_equal(oid, GSS_C_NT_XMPP_SAN) ||
           gss_oid_equal(oid, GSS_C_NT_DNSSRV_SAN) ||
           gss_oid_equal(oid, GSS_C_NT_SMTP_SAN);
}

/*
 * Helper: Copy an OID
 */
static int
copy_oid(gss_OID_desc *dst, const gss_OID_desc *src)
{
    dst->elements = malloc(src->length);
    if (dst->elements == NULL)
        return ENOMEM;
    memcpy(dst->elements, src->elements, src->length);
    dst->length = src->length;
    return 0;
}

/*
 * Helper: Free OID contents
 */
static void
free_oid_contents(gss_OID_desc *oid)
{
    free(oid->elements);
    oid->elements = NULL;
    oid->length = 0;
}

/*
 * GSS-API import_name for TLS mechanism
 *
 * Supports:
 * - GSS_C_NT_HOSTBASED_SERVICE: "service@hostname" - used for SNI
 * - GSS_C_NT_ANONYMOUS: anonymous identity
 * - GSS_C_NT_EXPORT_NAME: previously exported name
 * - GSS_C_NT_X509_RFC822NAME: email address SAN
 * - GSS_C_NT_X509_DNSNAME: DNS name SAN
 * - GSS_C_NT_X509_URI: URI SAN
 * - GSS_C_NT_X509_IPADDRESS: IP address SAN (4 or 16 bytes)
 * - GSS_C_NT_X509_DIRNAME: X.500 directory name SAN
 * - GSS_C_NT_X509_REGID: registered OID SAN
 * - GSS_C_NT_PKINIT_SAN: PKINIT (Kerberos principal) SAN
 * - GSS_C_NT_MS_UPN_SAN: Microsoft UPN SAN
 * - GSS_C_NT_XMPP_SAN: XMPP address SAN
 * - GSS_C_NT_DNSSRV_SAN: DNS SRV SAN
 * - GSS_C_NT_SMTP_SAN: SMTP UTF8 mailbox SAN
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

    /*
     * X.509 SAN name types - string-valued SANs
     * (rfc822Name, dNSName, URI, UPN, XMPP, DNSSRV, SMTP)
     */
    if (is_string_san_type(name_type)) {
        name->type = GSS_TLS_NAME_X509_SAN;

        if (copy_oid(&name->u.san.san_type, name_type) != 0) {
            *minor = ENOMEM;
            free(name);
            return GSS_S_FAILURE;
        }

        name->u.san.value.string = malloc(input_name->length + 1);
        if (name->u.san.value.string == NULL) {
            *minor = ENOMEM;
            free_oid_contents(&name->u.san.san_type);
            free(name);
            return GSS_S_FAILURE;
        }
        memcpy(name->u.san.value.string, input_name->value, input_name->length);
        name->u.san.value.string[input_name->length] = '\0';

        *output_name = (gss_name_t)name;
        return GSS_S_COMPLETE;
    }

    /* X.509 SAN: iPAddress (4 bytes for IPv4, 16 bytes for IPv6) */
    if (gss_oid_equal(name_type, GSS_C_NT_X509_IPADDRESS)) {
        if (input_name->length != 4 && input_name->length != 16) {
            *minor = EINVAL;
            free(name);
            return GSS_S_BAD_NAME;
        }

        name->type = GSS_TLS_NAME_X509_SAN;

        if (copy_oid(&name->u.san.san_type, name_type) != 0) {
            *minor = ENOMEM;
            free(name);
            return GSS_S_FAILURE;
        }

        name->u.san.value.ipaddr.data = malloc(input_name->length);
        if (name->u.san.value.ipaddr.data == NULL) {
            *minor = ENOMEM;
            free_oid_contents(&name->u.san.san_type);
            free(name);
            return GSS_S_FAILURE;
        }
        memcpy(name->u.san.value.ipaddr.data, input_name->value, input_name->length);
        name->u.san.value.ipaddr.len = input_name->length;

        *output_name = (gss_name_t)name;
        return GSS_S_COMPLETE;
    }

    /* X.509 SAN: directoryName (RFC 4514 string or DER-encoded) */
    if (gss_oid_equal(name_type, GSS_C_NT_X509_DIRNAME)) {
        int ret;

        name->type = GSS_TLS_NAME_X509_SAN;

        if (copy_oid(&name->u.san.san_type, name_type) != 0) {
            *minor = ENOMEM;
            free(name);
            return GSS_S_FAILURE;
        }

        /* Try parsing as RFC 4514 string first */
        ret = hx509_parse_name(NULL, input_name->value, &name->u.san.value.dirname);
        if (ret != 0) {
            /* Parsing failed - input may need to be null-terminated */
            char *dn_str = malloc(input_name->length + 1);
            if (dn_str == NULL) {
                *minor = ENOMEM;
                free_oid_contents(&name->u.san.san_type);
                free(name);
                return GSS_S_FAILURE;
            }
            memcpy(dn_str, input_name->value, input_name->length);
            dn_str[input_name->length] = '\0';

            ret = hx509_parse_name(NULL, dn_str, &name->u.san.value.dirname);
            free(dn_str);

            if (ret != 0) {
                *minor = ret;
                free_oid_contents(&name->u.san.san_type);
                free(name);
                return GSS_S_BAD_NAME;
            }
        }

        *output_name = (gss_name_t)name;
        return GSS_S_COMPLETE;
    }

    /* X.509 SAN: PKINIT (DER-encoded KRB5PrincipalName) or registeredID (DER OID) */
    if (gss_oid_equal(name_type, GSS_C_NT_PKINIT_SAN) ||
        gss_oid_equal(name_type, GSS_C_NT_X509_REGID)) {

        name->type = GSS_TLS_NAME_X509_SAN;

        if (copy_oid(&name->u.san.san_type, name_type) != 0) {
            *minor = ENOMEM;
            free(name);
            return GSS_S_FAILURE;
        }

        name->u.san.value.der.data = malloc(input_name->length);
        if (name->u.san.value.der.data == NULL) {
            *minor = ENOMEM;
            free_oid_contents(&name->u.san.san_type);
            free(name);
            return GSS_S_FAILURE;
        }
        memcpy(name->u.san.value.der.data, input_name->value, input_name->length);
        name->u.san.value.der.len = input_name->length;

        *output_name = (gss_name_t)name;
        return GSS_S_COMPLETE;
    }

    /* TODO: Handle GSS_C_NT_EXPORT_NAME */

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
    const struct gss_tls_name_desc *name =
        (const struct gss_tls_name_desc *)input_name;
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

    case GSS_TLS_NAME_X509_SAN:
        /* TODO: Export X.509 SAN */
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
    const struct gss_tls_name_desc *name =
        (const struct gss_tls_name_desc *)input_name;
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
        if (name->u.x509_dn) {
            char *dn = NULL;
            int ret = hx509_name_to_string(name->u.x509_dn, &dn);
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

    case GSS_TLS_NAME_X509_SAN:
        /* Display based on SAN type */
        if (is_string_san_type(&name->u.san.san_type)) {
            /* String-valued SANs */
            if (gss_oid_equal(&name->u.san.san_type, GSS_C_NT_X509_RFC822NAME))
                (void)asprintf(&str, "email:%s", name->u.san.value.string);
            else if (gss_oid_equal(&name->u.san.san_type, GSS_C_NT_X509_DNSNAME))
                (void)asprintf(&str, "DNS:%s", name->u.san.value.string);
            else if (gss_oid_equal(&name->u.san.san_type, GSS_C_NT_X509_URI))
                (void)asprintf(&str, "URI:%s", name->u.san.value.string);
            else if (gss_oid_equal(&name->u.san.san_type, GSS_C_NT_MS_UPN_SAN))
                (void)asprintf(&str, "UPN:%s", name->u.san.value.string);
            else if (gss_oid_equal(&name->u.san.san_type, GSS_C_NT_XMPP_SAN))
                (void)asprintf(&str, "XMPP:%s", name->u.san.value.string);
            else if (gss_oid_equal(&name->u.san.san_type, GSS_C_NT_DNSSRV_SAN))
                (void)asprintf(&str, "DNSSRV:%s", name->u.san.value.string);
            else if (gss_oid_equal(&name->u.san.san_type, GSS_C_NT_SMTP_SAN))
                (void)asprintf(&str, "SMTP:%s", name->u.san.value.string);
            else
                str = strdup(name->u.san.value.string);
        } else if (gss_oid_equal(&name->u.san.san_type, GSS_C_NT_X509_IPADDRESS)) {
            /* IP address */
            if (name->u.san.value.ipaddr.len == 4) {
                const uint8_t *ip = name->u.san.value.ipaddr.data;
                (void)asprintf(&str, "IP:%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
            } else if (name->u.san.value.ipaddr.len == 16) {
                const uint8_t *ip = name->u.san.value.ipaddr.data;
                (void)asprintf(&str, "IP:%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                              "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                              ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
                              ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]);
            } else {
                str = strdup("IP:<invalid>");
            }
        } else if (gss_oid_equal(&name->u.san.san_type, GSS_C_NT_X509_DIRNAME)) {
            /* Directory name */
            if (name->u.san.value.dirname) {
                char *dn = NULL;
                int ret = hx509_name_to_string(name->u.san.value.dirname, &dn);
                if (ret == 0 && dn) {
                    (void)asprintf(&str, "dirName:%s", dn);
                    free(dn);
                } else {
                    str = strdup("dirName:<error>");
                }
            } else {
                str = strdup("dirName:<empty>");
            }
        } else if (gss_oid_equal(&name->u.san.san_type, GSS_C_NT_PKINIT_SAN)) {
            /* PKINIT SAN - DER encoded, show as hex for now */
            str = strdup("PKINIT:<DER-encoded>");
        } else if (gss_oid_equal(&name->u.san.san_type, GSS_C_NT_X509_REGID)) {
            /* Registered OID - DER encoded */
            str = strdup("registeredID:<DER-encoded>");
        } else {
            str = strdup("<unknown SAN type>");
        }

        if (str == NULL) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }
        /* Output type is the SAN type OID */
        if (output_type) {
            /* Copy the SAN type OID - caller must release */
            *output_type = malloc(sizeof(gss_OID_desc));
            if (*output_type) {
                (*output_type)->length = name->u.san.san_type.length;
                (*output_type)->elements = malloc(name->u.san.san_type.length);
                if ((*output_type)->elements) {
                    memcpy((*output_type)->elements,
                           name->u.san.san_type.elements,
                           name->u.san.san_type.length);
                } else {
                    free(*output_type);
                    *output_type = GSS_C_NO_OID;
                }
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
    const struct gss_tls_name_desc *n1 =
        (const struct gss_tls_name_desc *)name1;
    const struct gss_tls_name_desc *n2 =
        (const struct gss_tls_name_desc *)name2;

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
        if (n1->u.x509_dn && n2->u.x509_dn) {
            *name_equal = (hx509_name_cmp(n1->u.x509_dn, n2->u.x509_dn) == 0);
        } else {
            *name_equal = (n1->u.x509_dn == n2->u.x509_dn);
        }
        break;

    case GSS_TLS_NAME_X509_SAN:
        /* SAN type OIDs must match */
        if (!gss_oid_equal(&n1->u.san.san_type, &n2->u.san.san_type)) {
            *name_equal = 0;
            return GSS_S_COMPLETE;
        }

        /* Compare based on SAN type */
        if (is_string_san_type(&n1->u.san.san_type)) {
            /* String comparison */
            if (n1->u.san.value.string && n2->u.san.value.string) {
                /* Case-insensitive for DNS names, case-sensitive for others */
                if (gss_oid_equal(&n1->u.san.san_type, GSS_C_NT_X509_DNSNAME) ||
                    gss_oid_equal(&n1->u.san.san_type, GSS_C_NT_DNSSRV_SAN)) {
                    *name_equal = (strcasecmp(n1->u.san.value.string,
                                              n2->u.san.value.string) == 0);
                } else {
                    *name_equal = (strcmp(n1->u.san.value.string,
                                         n2->u.san.value.string) == 0);
                }
            } else {
                *name_equal = (n1->u.san.value.string == n2->u.san.value.string);
            }
        } else if (gss_oid_equal(&n1->u.san.san_type, GSS_C_NT_X509_IPADDRESS)) {
            /* Binary comparison of IP addresses */
            if (n1->u.san.value.ipaddr.len == n2->u.san.value.ipaddr.len &&
                n1->u.san.value.ipaddr.data && n2->u.san.value.ipaddr.data) {
                *name_equal = (memcmp(n1->u.san.value.ipaddr.data,
                                     n2->u.san.value.ipaddr.data,
                                     n1->u.san.value.ipaddr.len) == 0);
            } else {
                *name_equal = 0;
            }
        } else if (gss_oid_equal(&n1->u.san.san_type, GSS_C_NT_X509_DIRNAME)) {
            /* Compare directory names */
            if (n1->u.san.value.dirname && n2->u.san.value.dirname) {
                *name_equal = (hx509_name_cmp(n1->u.san.value.dirname,
                                             n2->u.san.value.dirname) == 0);
            } else {
                *name_equal = (n1->u.san.value.dirname == n2->u.san.value.dirname);
            }
        } else if (gss_oid_equal(&n1->u.san.san_type, GSS_C_NT_PKINIT_SAN) ||
                   gss_oid_equal(&n1->u.san.san_type, GSS_C_NT_X509_REGID)) {
            /* Binary comparison of DER-encoded data */
            if (n1->u.san.value.der.len == n2->u.san.value.der.len &&
                n1->u.san.value.der.data && n2->u.san.value.der.data) {
                *name_equal = (memcmp(n1->u.san.value.der.data,
                                     n2->u.san.value.der.data,
                                     n1->u.san.value.der.len) == 0);
            } else {
                *name_equal = 0;
            }
        } else {
            *name_equal = 0;
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
        if (n->u.x509_dn)
            hx509_name_free(&n->u.x509_dn);
        break;
    case GSS_TLS_NAME_X509_SAN:
        /* Free based on SAN type */
        if (is_string_san_type(&n->u.san.san_type)) {
            free(n->u.san.value.string);
        } else if (gss_oid_equal(&n->u.san.san_type, GSS_C_NT_X509_IPADDRESS)) {
            free(n->u.san.value.ipaddr.data);
        } else if (gss_oid_equal(&n->u.san.san_type, GSS_C_NT_X509_DIRNAME)) {
            if (n->u.san.value.dirname)
                hx509_name_free(&n->u.san.value.dirname);
        } else if (gss_oid_equal(&n->u.san.san_type, GSS_C_NT_PKINIT_SAN) ||
                   gss_oid_equal(&n->u.san.san_type, GSS_C_NT_X509_REGID)) {
            free(n->u.san.value.der.data);
        }
        free_oid_contents(&n->u.san.san_type);
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
    const struct gss_tls_name_desc *src =
        (const struct gss_tls_name_desc *)src_name;
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
        if (src->u.x509_dn) {
            int ret = hx509_name_copy(NULL, src->u.x509_dn, &dst->u.x509_dn);
            if (ret) {
                *minor = ret;
                free(dst);
                return GSS_S_FAILURE;
            }
        }
        break;

    case GSS_TLS_NAME_X509_SAN:
        /* Copy the SAN type OID */
        if (copy_oid(&dst->u.san.san_type, &src->u.san.san_type) != 0) {
            *minor = ENOMEM;
            free(dst);
            return GSS_S_FAILURE;
        }

        /* Copy value based on SAN type */
        if (is_string_san_type(&src->u.san.san_type)) {
            if (src->u.san.value.string) {
                dst->u.san.value.string = strdup(src->u.san.value.string);
                if (dst->u.san.value.string == NULL) {
                    *minor = ENOMEM;
                    free_oid_contents(&dst->u.san.san_type);
                    free(dst);
                    return GSS_S_FAILURE;
                }
            }
        } else if (gss_oid_equal(&src->u.san.san_type, GSS_C_NT_X509_IPADDRESS)) {
            if (src->u.san.value.ipaddr.data && src->u.san.value.ipaddr.len > 0) {
                dst->u.san.value.ipaddr.data = malloc(src->u.san.value.ipaddr.len);
                if (dst->u.san.value.ipaddr.data == NULL) {
                    *minor = ENOMEM;
                    free_oid_contents(&dst->u.san.san_type);
                    free(dst);
                    return GSS_S_FAILURE;
                }
                memcpy(dst->u.san.value.ipaddr.data,
                       src->u.san.value.ipaddr.data,
                       src->u.san.value.ipaddr.len);
                dst->u.san.value.ipaddr.len = src->u.san.value.ipaddr.len;
            }
        } else if (gss_oid_equal(&src->u.san.san_type, GSS_C_NT_X509_DIRNAME)) {
            if (src->u.san.value.dirname) {
                int ret = hx509_name_copy(NULL, src->u.san.value.dirname,
                                         &dst->u.san.value.dirname);
                if (ret) {
                    *minor = ret;
                    free_oid_contents(&dst->u.san.san_type);
                    free(dst);
                    return GSS_S_FAILURE;
                }
            }
        } else if (gss_oid_equal(&src->u.san.san_type, GSS_C_NT_PKINIT_SAN) ||
                   gss_oid_equal(&src->u.san.san_type, GSS_C_NT_X509_REGID)) {
            if (src->u.san.value.der.data && src->u.san.value.der.len > 0) {
                dst->u.san.value.der.data = malloc(src->u.san.value.der.len);
                if (dst->u.san.value.der.data == NULL) {
                    *minor = ENOMEM;
                    free_oid_contents(&dst->u.san.san_type);
                    free(dst);
                    return GSS_S_FAILURE;
                }
                memcpy(dst->u.san.value.der.data,
                       src->u.san.value.der.data,
                       src->u.san.value.der.len);
                dst->u.san.value.der.len = src->u.san.value.der.len;
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
 * Helper macro for adding OID to set with error handling
 */
#define ADD_NAME_TYPE(oid) do { \
    major = gss_add_oid_set_member(minor, (oid), name_types); \
    if (major != GSS_S_COMPLETE) { \
        gss_release_oid_set(minor, name_types); \
        return major; \
    } \
} while (0)

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
    ADD_NAME_TYPE(GSS_C_NT_HOSTBASED_SERVICE);

    /* We support anonymous names */
    ADD_NAME_TYPE(GSS_C_NT_ANONYMOUS);

    /*
     * X.509 SAN name types - string-valued SANs
     */
    ADD_NAME_TYPE(GSS_C_NT_X509_RFC822NAME);   /* email */
    ADD_NAME_TYPE(GSS_C_NT_X509_DNSNAME);      /* DNS name */
    ADD_NAME_TYPE(GSS_C_NT_X509_URI);          /* URI */
    ADD_NAME_TYPE(GSS_C_NT_MS_UPN_SAN);        /* Microsoft UPN */
    ADD_NAME_TYPE(GSS_C_NT_XMPP_SAN);          /* XMPP address */
    ADD_NAME_TYPE(GSS_C_NT_DNSSRV_SAN);        /* DNS SRV */
    ADD_NAME_TYPE(GSS_C_NT_SMTP_SAN);          /* SMTP UTF8 mailbox */

    /*
     * X.509 SAN name types - binary-valued SANs
     */
    ADD_NAME_TYPE(GSS_C_NT_X509_IPADDRESS);    /* IP address (4 or 16 bytes) */
    ADD_NAME_TYPE(GSS_C_NT_X509_DIRNAME);      /* X.500 directory name */
    ADD_NAME_TYPE(GSS_C_NT_PKINIT_SAN);        /* PKINIT (KRB5PrincipalName) */
    ADD_NAME_TYPE(GSS_C_NT_X509_REGID);        /* Registered OID */

    return GSS_S_COMPLETE;
}

#undef ADD_NAME_TYPE

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
