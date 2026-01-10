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

/*
 * GSS-TLS Mechanism
 *
 * A GSS-API mechanism where tokens ARE raw TLS records.
 * - Security context tokens = TLS handshake records
 * - Per-message tokens (wrap) = TLS application data records
 * - Context deletion tokens = TLS close_notify/alert records
 *
 * Uses s2n-tls with memory-based I/O callbacks.
 * Integrates with hx509 for certificate/key management.
 */

/*
 * Anonymous identity - used when no client certificate is presented
 */
static uint8_t anonymous_identity;
gss_name_t _gss_tls_anonymous_identity = (gss_name_t)&anonymous_identity;

/*
 * Mechanism OID
 *
 * OID arc: 1.3.6.1.4.1.40402.1 (PEN 40402, arc 1 = heimdal)
 * GSS-TLS mechanism: 1.3.6.1.4.1.40402.1.1
 */
static gss_OID_desc gss_tls_mechanism_oid_desc = {
    10, rk_UNCONST("\x2b\x06\x01\x04\x01\x82\xbb\x52\x01\x01")
};
gss_OID GSS_TLS_MECHANISM = &gss_tls_mechanism_oid_desc;

/*
 * Mechanism attribute: self-framed tokens
 *
 * This attribute indicates that ALL tokens produced by the mechanism
 * (context tokens, wrap tokens, MIC tokens, etc.) are self-delimiting
 * and include embedded length information.
 *
 * TLS qualifies because every TLS record has a 5-byte header that
 * includes a 2-byte length field.
 *
 * OID: 1.3.6.1.4.1.40402.1.2
 */
static gss_OID_desc gss_c_ma_self_framed_desc = {
    10, rk_UNCONST("\x2b\x06\x01\x04\x01\x82\xbb\x52\x01\x02")
};

/*
 * GSS Name Type OIDs for X.509 SANs
 *
 * For OtherName SANs, use the OtherName type-id OID directly.
 * For non-OtherName SANs, we allocate OIDs under 1.3.6.1.4.1.40402.1.3
 * with sub-arc matching the GeneralName CHOICE tag number.
 */

/* OtherName type-id OIDs (not allocated by us) */

/* id-pkinit-san: 1.3.6.1.5.2.2 - PKINIT SAN (KRB5PrincipalName) */
gss_OID_desc GSS_C_NT_PKINIT_SAN_desc = {
    6, rk_UNCONST("\x2b\x06\x01\x05\x02\x02")
};
gss_OID GSS_C_NT_PKINIT_SAN = &GSS_C_NT_PKINIT_SAN_desc;

/* id-ms-san-upn: 1.3.6.1.4.1.311.20.2.3 - Microsoft UPN SAN */
gss_OID_desc GSS_C_NT_MS_UPN_SAN_desc = {
    10, rk_UNCONST("\x2b\x06\x01\x04\x01\x82\x37\x14\x02\x03")
};
gss_OID GSS_C_NT_MS_UPN_SAN = &GSS_C_NT_MS_UPN_SAN_desc;

/* id-on-xmppAddr: 1.3.6.1.5.5.7.8.5 - XMPP address */
gss_OID_desc GSS_C_NT_XMPP_SAN_desc = {
    8, rk_UNCONST("\x2b\x06\x01\x05\x05\x07\x08\x05")
};
gss_OID GSS_C_NT_XMPP_SAN = &GSS_C_NT_XMPP_SAN_desc;

/* id-on-dnsSRV: 1.3.6.1.5.5.7.8.7 - DNS SRV name */
gss_OID_desc GSS_C_NT_DNSSRV_SAN_desc = {
    8, rk_UNCONST("\x2b\x06\x01\x05\x05\x07\x08\x07")
};
gss_OID GSS_C_NT_DNSSRV_SAN = &GSS_C_NT_DNSSRV_SAN_desc;

/* id-on-SmtpUTF8Mailbox: 1.3.6.1.5.5.7.8.9 - SMTP UTF8 mailbox */
gss_OID_desc GSS_C_NT_SMTP_SAN_desc = {
    8, rk_UNCONST("\x2b\x06\x01\x05\x05\x07\x08\x09")
};
gss_OID GSS_C_NT_SMTP_SAN = &GSS_C_NT_SMTP_SAN_desc;

/* Non-OtherName SAN type OIDs (allocated under 1.3.6.1.4.1.40402.1.3) */

/* GSS_C_NT_X509_RFC822NAME: 1.3.6.1.4.1.40402.1.3.1 - rfc822Name (email) */
gss_OID_desc GSS_C_NT_X509_RFC822NAME_desc = {
    11, rk_UNCONST("\x2b\x06\x01\x04\x01\x82\xbb\x52\x01\x03\x01")
};
gss_OID GSS_C_NT_X509_RFC822NAME = &GSS_C_NT_X509_RFC822NAME_desc;

/* GSS_C_NT_X509_DNSNAME: 1.3.6.1.4.1.40402.1.3.2 - dNSName */
gss_OID_desc GSS_C_NT_X509_DNSNAME_desc = {
    11, rk_UNCONST("\x2b\x06\x01\x04\x01\x82\xbb\x52\x01\x03\x02")
};
gss_OID GSS_C_NT_X509_DNSNAME = &GSS_C_NT_X509_DNSNAME_desc;

/* GSS_C_NT_X509_DIRNAME: 1.3.6.1.4.1.40402.1.3.4 - directoryName */
gss_OID_desc GSS_C_NT_X509_DIRNAME_desc = {
    11, rk_UNCONST("\x2b\x06\x01\x04\x01\x82\xbb\x52\x01\x03\x04")
};
gss_OID GSS_C_NT_X509_DIRNAME = &GSS_C_NT_X509_DIRNAME_desc;

/* GSS_C_NT_X509_URI: 1.3.6.1.4.1.40402.1.3.6 - uniformResourceIdentifier */
gss_OID_desc GSS_C_NT_X509_URI_desc = {
    11, rk_UNCONST("\x2b\x06\x01\x04\x01\x82\xbb\x52\x01\x03\x06")
};
gss_OID GSS_C_NT_X509_URI = &GSS_C_NT_X509_URI_desc;

/* GSS_C_NT_X509_IPADDRESS: 1.3.6.1.4.1.40402.1.3.7 - iPAddress */
gss_OID_desc GSS_C_NT_X509_IPADDRESS_desc = {
    11, rk_UNCONST("\x2b\x06\x01\x04\x01\x82\xbb\x52\x01\x03\x07")
};
gss_OID GSS_C_NT_X509_IPADDRESS = &GSS_C_NT_X509_IPADDRESS_desc;

/* GSS_C_NT_X509_REGID: 1.3.6.1.4.1.40402.1.3.8 - registeredID */
gss_OID_desc GSS_C_NT_X509_REGID_desc = {
    11, rk_UNCONST("\x2b\x06\x01\x04\x01\x82\xbb\x52\x01\x03\x08")
};
gss_OID GSS_C_NT_X509_REGID = &GSS_C_NT_X509_REGID_desc;

/*
 * Mechanism attributes (gss_mo_desc)
 */
static gss_mo_desc tls_mo[] = {
    {
        GSS_C_MA_MECH_NAME,
        GSS_MO_MA,
        "Mechanism name",
        rk_UNCONST("TLS"),
        _gss_mo_get_ctx_as_string,
        NULL
    },
    {
        GSS_C_MA_MECH_DESCRIPTION,
        GSS_MO_MA,
        "Mechanism description",
        rk_UNCONST("Heimdal GSS-TLS mechanism using s2n-tls"),
        _gss_mo_get_ctx_as_string,
        NULL
    },
    {
        GSS_C_MA_MECH_CONCRETE,
        GSS_MO_MA,
        NULL,
        NULL,
        NULL,
        NULL
    },
    /* TLS provides confidentiality */
    {
        GSS_C_MA_CONF_PROT,
        GSS_MO_MA,
        NULL,
        NULL,
        NULL,
        NULL
    },
    /* TLS provides integrity */
    {
        GSS_C_MA_INTEG_PROT,
        GSS_MO_MA,
        NULL,
        NULL,
        NULL,
        NULL
    },
    /* TLS wraps messages */
    {
        GSS_C_MA_WRAP,
        GSS_MO_MA,
        NULL,
        NULL,
        NULL,
        NULL
    },
    /* TLS provides replay detection */
    {
        GSS_C_MA_REPLAY_DET,
        GSS_MO_MA,
        NULL,
        NULL,
        NULL,
        NULL
    },
    /* TLS provides out-of-sequence detection */
    {
        GSS_C_MA_OOS_DET,
        GSS_MO_MA,
        NULL,
        NULL,
        NULL,
        NULL
    },
    /* TLS 1.3 provides perfect forward secrecy */
    {
        GSS_C_MA_PFS,
        GSS_MO_MA,
        NULL,
        NULL,
        NULL,
        NULL
    },
    /* Supports anonymous initiators (no client cert) */
    {
        GSS_C_MA_AUTH_INIT_ANON,
        GSS_MO_MA,
        NULL,
        NULL,
        NULL,
        NULL
    },
    /* TLS 1.3 supports channel bindings via exporter */
    {
        GSS_C_MA_CBINDINGS,
        GSS_MO_MA,
        NULL,
        NULL,
        NULL,
        NULL
    },
    /* All TLS tokens are self-framing (5-byte record header with length) */
    {
        &gss_c_ma_self_framed_desc,
        GSS_MO_MA,
        "Self-framed tokens",
        rk_UNCONST("All tokens include embedded length (TLS record framing)"),
        _gss_mo_get_ctx_as_string,
        NULL
    },
};

/*
 * Mechanism interface descriptor
 */
static gssapi_mech_interface_desc tls_mech = {
    GMI_VERSION,
    "tls",
    { 10, rk_UNCONST("\x2b\x06\x01\x04\x01\x82\xbb\x52\x01\x01") },
    0, /* gm_flags */
    NULL,                              /* gm_acquire_cred - use acquire_cred_from */
    _gss_tls_release_cred,
    _gss_tls_init_sec_context,
    _gss_tls_accept_sec_context,
    _gss_tls_process_context_token,
    _gss_tls_delete_sec_context,
    _gss_tls_context_time,
    _gss_tls_get_mic,
    _gss_tls_verify_mic,
    _gss_tls_wrap,
    _gss_tls_unwrap,
    _gss_tls_display_status,
    NULL,                              /* gm_indicate_mechs */
    _gss_tls_compare_name,
    _gss_tls_display_name,
    _gss_tls_import_name,
    _gss_tls_export_name,
    _gss_tls_release_name,
    _gss_tls_inquire_cred,
    _gss_tls_inquire_context,
    _gss_tls_wrap_size_limit,
    NULL,                              /* gm_add_cred */
    _gss_tls_inquire_cred_by_mech,
    NULL,                              /* gm_export_sec_context */
    NULL,                              /* gm_import_sec_context */
    _gss_tls_inquire_names_for_mech,
    _gss_tls_inquire_mechs_for_name,
    _gss_tls_canonicalize_name,
    _gss_tls_duplicate_name,
    /*
     * TODO: Implement gm_inquire_sec_context_by_oid for TLS-specific attributes
     * Needed OIDs to define and implement:
     *   - GSS_C_INQ_TLS_CIPHER        -> cipher suite name (e.g., "TLS_AES_256_GCM_SHA384")
     *   - GSS_C_INQ_TLS_VERSION       -> protocol version ("TLSv1.2", "TLSv1.3")
     *   - GSS_C_INQ_TLS_ALPN          -> negotiated ALPN protocol (if any)
     *   - GSS_C_INQ_TLS_PEER_CERT     -> peer certificate (DER-encoded)
     *   - GSS_C_INQ_TLS_PEER_CERT_CHAIN -> full cert chain (DER, concatenated)
     *   - GSS_C_INQ_TLS_SNI           -> SNI hostname used
     * These are needed for the gss tool's command execution mode to populate
     * environment variables like GSS_TLS_CIPHER, GSS_TLS_VERSION, etc.
     */
    NULL,                              /* gm_inquire_sec_context_by_oid */
    NULL,                              /* gm_inquire_cred_by_oid */
    NULL,                              /* gm_set_sec_context_option */
    NULL,                              /* gm_set_cred_option */
    NULL,                              /* gm_pseudo_random - TODO: use TLS key exporter */
    NULL,                              /* gm_wrap_iov */
    NULL,                              /* gm_unwrap_iov */
    NULL,                              /* gm_wrap_iov_length */
    NULL,                              /* gm_store_cred */
    NULL,                              /* gm_export_cred */
    NULL,                              /* gm_import_cred */
    _gss_tls_acquire_cred_from,
    NULL,                              /* gm_acquire_cred_impersonate_name */
    NULL,                              /* gm_iter_creds */
    NULL,                              /* gm_destroy_cred */
    NULL,                              /* gm_cred_hold */
    NULL,                              /* gm_cred_unhold */
    NULL,                              /* gm_cred_label_get */
    NULL,                              /* gm_cred_label_set */
    tls_mo,
    sizeof(tls_mo) / sizeof(tls_mo[0]),
    NULL,                              /* gm_localname */
    NULL,                              /* gm_authorize_localname */
    NULL,                              /* gm_display_name_ext */
    NULL,                              /* gm_inquire_name */
    NULL,                              /* gm_get_name_attribute */
    NULL,                              /* gm_set_name_attribute */
    NULL,                              /* gm_delete_name_attribute */
    NULL,                              /* gm_export_name_composite */
    NULL,                              /* gm_duplicate_cred */
    NULL,                              /* gm_add_cred_from */
    NULL,                              /* gm_store_cred_into */
    NULL,                              /* gm_query_mechanism_info */
    NULL,                              /* gm_query_meta_data */
    NULL,                              /* gm_exchange_meta_data */
    NULL,                              /* gm_store_cred_into2 */
    NULL,                              /* gm_compat */
};

/*
 * Initialize and return the GSS-TLS mechanism interface
 */
gssapi_mech_interface
__gss_tls_initialize(void)
{
    return &tls_mech;
}
