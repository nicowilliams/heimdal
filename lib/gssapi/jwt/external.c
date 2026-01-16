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

#include "jwt_locl.h"

/*
 * GSS-JWT Mechanism
 *
 * A GSS-API mechanism that uses JWT (JSON Web Tokens) for authentication.
 * The client obtains a JWT from a Security Token Service (STS) and presents
 * it to the server. The server validates the JWT and extracts the subject
 * as the authenticated identity.
 *
 * This is useful as a Kerberos replacement for applications that support
 * GSS-API (e.g., PostgreSQL, OpenSSH) when:
 * - Kerberos infrastructure is not available
 * - OAuth2/OIDC identity providers are preferred
 * - Cloud-native authentication (KSAT, GSAT) is desired
 *
 * Token exchange supports:
 * - Password/OTP authentication
 * - Kerberos ticket exchange (via Negotiate)
 * - JWT-for-JWT exchange (KSAT, GSAT)
 * - X.509 certificate authentication
 */

/*
 * Anonymous identity - used when no identity is established
 */
static uint8_t anonymous_identity;
gss_name_t _gss_jwt_anonymous_identity = (gss_name_t)&anonymous_identity;

/*
 * Mechanism OID
 *
 * OID arc: 1.3.6.1.4.1.40402.1 (PEN 40402, arc 1 = heimdal)
 * GSS-JWT mechanism: 1.3.6.1.4.1.40402.1.4
 *
 * Encoding: 2b 06 01 04 01 82 bb 52 01 04
 *   2b = 1.3 (40*1 + 3)
 *   06 = 6
 *   01 = 1
 *   04 = 4
 *   01 = 1
 *   82 bb 52 = 40402 (base-128: 0x82, 0xbb, 0x52)
 *   01 = 1
 *   04 = 4
 */
static gss_OID_desc gss_jwt_mechanism_oid_desc = {
    10, rk_UNCONST("\x2b\x06\x01\x04\x01\x82\xbb\x52\x01\x04")
};
gss_OID GSS_JWT_MECHANISM = &gss_jwt_mechanism_oid_desc;

/*
 * Mechanism attributes (gss_mo_desc)
 */
static gss_mo_desc jwt_mo[] = {
    {
        GSS_C_MA_MECH_NAME,
        GSS_MO_MA,
        "Mechanism name",
        rk_UNCONST("JWT"),
        _gss_mo_get_ctx_as_string,
        NULL
    },
    {
        GSS_C_MA_MECH_DESCRIPTION,
        GSS_MO_MA,
        "Mechanism description",
        rk_UNCONST("Heimdal GSS-JWT mechanism for OAuth2/OIDC authentication"),
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
    /* JWT provides integrity via signature */
    {
        GSS_C_MA_INTEG_PROT,
        GSS_MO_MA,
        NULL,
        NULL,
        NULL,
        NULL
    },
    /* JWT mechanism supports MIC */
    {
        GSS_C_MA_MIC,
        GSS_MO_MA,
        NULL,
        NULL,
        NULL,
        NULL
    },
    /* JWT mechanism supports wrap (with derived keys) */
    {
        GSS_C_MA_WRAP,
        GSS_MO_MA,
        NULL,
        NULL,
        NULL,
        NULL
    },
    /* Confidentiality with derived keys */
    {
        GSS_C_MA_CONF_PROT,
        GSS_MO_MA,
        NULL,
        NULL,
        NULL,
        NULL
    },
    /* Replay detection via sequence numbers */
    {
        GSS_C_MA_REPLAY_DET,
        GSS_MO_MA,
        NULL,
        NULL,
        NULL,
        NULL
    },
    /* Out-of-sequence detection */
    {
        GSS_C_MA_OOS_DET,
        GSS_MO_MA,
        NULL,
        NULL,
        NULL,
        NULL
    },
    /* Initial tokens are framed (GSS token format) */
    {
        GSS_C_MA_ITOK_FRAMED,
        GSS_MO_MA,
        NULL,
        NULL,
        NULL,
        NULL
    },
};

/*
 * Mechanism interface descriptor
 */
static gssapi_mech_interface_desc jwt_mech = {
    GMI_VERSION,
    "jwt",
    { 10, rk_UNCONST("\x2b\x06\x01\x04\x01\x82\xbb\x52\x01\x04") },
    GM_USE_MG_NAME, /* Use mech glue names (but not credentials - we have our own) */
    NULL,                              /* gm_acquire_cred - use acquire_cred_from */
    _gss_jwt_release_cred,
    _gss_jwt_init_sec_context,
    _gss_jwt_accept_sec_context,
    _gss_jwt_process_context_token,
    _gss_jwt_delete_sec_context,
    _gss_jwt_context_time,
    _gss_jwt_get_mic,
    _gss_jwt_verify_mic,
    _gss_jwt_wrap,
    _gss_jwt_unwrap,
    _gss_jwt_display_status,
    NULL,                              /* gm_indicate_mechs */
    _gss_jwt_compare_name,
    _gss_jwt_display_name,
    _gss_jwt_import_name,
    _gss_jwt_export_name,
    _gss_jwt_release_name,
    _gss_jwt_inquire_cred,
    _gss_jwt_inquire_context,
    _gss_jwt_wrap_size_limit,
    NULL,                              /* gm_add_cred */
    _gss_jwt_inquire_cred_by_mech,
    NULL,                              /* gm_export_sec_context */
    NULL,                              /* gm_import_sec_context */
    _gss_jwt_inquire_names_for_mech,
    _gss_jwt_inquire_mechs_for_name,
    _gss_jwt_canonicalize_name,
    _gss_jwt_duplicate_name,
    NULL,                              /* gm_inquire_sec_context_by_oid */
    NULL,                              /* gm_inquire_cred_by_oid */
    NULL,                              /* gm_set_sec_context_option */
    NULL,                              /* gm_set_cred_option */
    NULL,                              /* gm_pseudo_random */
    NULL,                              /* gm_wrap_iov */
    NULL,                              /* gm_unwrap_iov */
    NULL,                              /* gm_wrap_iov_length */
    NULL,                              /* gm_store_cred */
    NULL,                              /* gm_export_cred */
    NULL,                              /* gm_import_cred */
    _gss_jwt_acquire_cred_from,
    NULL,                              /* gm_acquire_cred_impersonate_name */
    NULL,                              /* gm_iter_creds */
    NULL,                              /* gm_destroy_cred */
    NULL,                              /* gm_cred_hold */
    NULL,                              /* gm_cred_unhold */
    NULL,                              /* gm_cred_label_get */
    NULL,                              /* gm_cred_label_set */
    jwt_mo,
    sizeof(jwt_mo) / sizeof(jwt_mo[0]),
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
 * Initialize and return the GSS-JWT mechanism interface
 */
gssapi_mech_interface
__gss_jwt_initialize(void)
{
    return &jwt_mech;
}
