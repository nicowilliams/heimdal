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

/* Forward declarations for hx509 private APIs we need */
HX509_LIB_FUNCTION hx509_private_key HX509_LIB_CALL
_hx509_cert_private_key(hx509_cert);
HX509_LIB_FUNCTION void HX509_LIB_CALL
_hx509_private_key_ref(hx509_private_key);

/*
 * Key names for gss_acquire_cred_from() cred_store parameter
 *
 * Common keys:
 *   "certificate"    - hx509 certificate store URI (FILE:, PKCS12:, PKCS11:, etc.)
 *   "private-key"    - hx509 private key store URI
 *   "anchors"        - hx509 trust anchor store URI for peer validation
 *   "revoke"         - hx509 revocation info URI (CRL, OCSP)
 *
 * Initiator (client) keys:
 *   "anonymous"      - "true" to allow anonymous client (no client cert)
 *
 * Acceptor (server) keys:
 *   "require-client-cert" - "true" to require client certificates
 *
 * TODO: Add ALPN/NPN support for protocol negotiation
 *   "alpn"           - Comma-separated list of ALPN protocols (initiator offers these)
 *   "npn"            - Comma-separated list of NPN protocols (legacy, initiator)
 *   For acceptor, these would specify which protocols the server supports.
 *
 * NOTE: The acceptor uses the same cred store mechanism to configure:
 *   - Server certificate and private key ("certificate", "private-key")
 *   - Trust anchors for client certificate validation ("anchors")
 *   - Whether to require/request client certificates ("require-client-cert")
 *   - Revocation checking for client certs ("revoke")
 */
#define GSS_TLS_CRED_CERTIFICATE        "certificate"
#define GSS_TLS_CRED_PRIVATE_KEY        "private-key"
#define GSS_TLS_CRED_ANCHORS            "anchors"
#define GSS_TLS_CRED_REVOKE             "revoke"
#define GSS_TLS_CRED_ANONYMOUS          "anonymous"
#define GSS_TLS_CRED_REQUIRE_CLIENT     "require-client-cert"
/* TODO: Implement these for ALPN/NPN support */
#define GSS_TLS_CRED_ALPN               "alpn"
#define GSS_TLS_CRED_NPN                "npn"

/*
 * Find a value in the credential store key-value set
 */
static const char *
find_cred_store_value(gss_const_key_value_set_t cred_store, const char *key)
{
    size_t i;

    if (cred_store == NULL)
        return NULL;

    for (i = 0; i < cred_store->count; i++) {
        if (strcmp(cred_store->elements[i].key, key) == 0)
            return cred_store->elements[i].value;
    }
    return NULL;
}

/*
 * GSS-API acquire_cred_from for TLS mechanism
 *
 * Acquires a TLS credential from the specified stores.
 *
 * Supported cred_store keys:
 *   "certificate"    - Certificate store URI (FILE:cert.pem, PKCS12:file.p12, etc.)
 *   "private-key"    - Private key store URI (FILE:key.pem, PKCS11:, etc.)
 *   "anchors"        - Trust anchor store URI for peer validation
 *   "revoke"         - Revocation info store URI
 *   "anonymous"      - "true" for anonymous client mode
 *   "require-client-cert" - "true" to require client certs (acceptor only)
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_acquire_cred_from(OM_uint32 *minor,
                           gss_const_name_t desired_name,
                           OM_uint32 time_req,
                           gss_OID_set desired_mechs,
                           gss_cred_usage_t cred_usage,
                           gss_const_key_value_set_t cred_store,
                           gss_cred_id_t *output_cred,
                           gss_OID_set *actual_mechs,
                           OM_uint32 *time_rec)
{
    gss_tls_cred cred = NULL;
    const char *cert_store = NULL;
    const char *key_store = NULL;
    const char *anchor_store = NULL;
    const char *revoke_store = NULL;
    const char *anonymous_str = NULL;
    const char *require_client_str = NULL;
    int ret;

    (void)desired_name; /* Name is derived from certificate */
    (void)time_req;     /* TLS credentials don't expire */
    (void)desired_mechs;

    *minor = 0;
    *output_cred = GSS_C_NO_CREDENTIAL;
    if (actual_mechs)
        *actual_mechs = GSS_C_NO_OID_SET;
    if (time_rec)
        *time_rec = GSS_C_INDEFINITE;

    /* Allocate credential structure */
    cred = calloc(1, sizeof(*cred));
    if (cred == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    cred->usage = cred_usage;

    /* Initialize tracing context */
    gss_tls_trace_init(&cred->hctx);
    heim_debug(cred->hctx, 5, "GSS-TLS: acquiring %s credential",
               cred_usage == GSS_C_INITIATE ? "initiator" :
               cred_usage == GSS_C_ACCEPT ? "acceptor" : "both");

    /* Initialize hx509 context */
    ret = hx509_context_init(&cred->hx509ctx);
    if (ret) {
        *minor = ret;
        free(cred);
        return GSS_S_FAILURE;
    }

    /* Parse credential store parameters */
    cert_store = find_cred_store_value(cred_store, GSS_TLS_CRED_CERTIFICATE);
    key_store = find_cred_store_value(cred_store, GSS_TLS_CRED_PRIVATE_KEY);
    anchor_store = find_cred_store_value(cred_store, GSS_TLS_CRED_ANCHORS);
    revoke_store = find_cred_store_value(cred_store, GSS_TLS_CRED_REVOKE);
    anonymous_str = find_cred_store_value(cred_store, GSS_TLS_CRED_ANONYMOUS);
    require_client_str = find_cred_store_value(cred_store, GSS_TLS_CRED_REQUIRE_CLIENT);

    /* Parse boolean flags */
    if (anonymous_str && strcasecmp(anonymous_str, "true") == 0)
        cred->anonymous = 1;
    if (require_client_str && strcasecmp(require_client_str, "true") == 0)
        cred->require_client_cert = 1;

    /* Load certificate chain if specified */
    if (cert_store) {
        heim_debug(cred->hctx, 5, "GSS-TLS: loading certificate from %s", cert_store);
        ret = hx509_certs_init(cred->hx509ctx, cert_store, 0, NULL, &cred->certs);
        if (ret) {
            heim_debug(cred->hctx, 1, "GSS-TLS: failed to load certificate: %d", ret);
            *minor = ret;
            goto fail;
        }
    }

    /* Load private key if specified */
    if (key_store) {
        hx509_certs key_certs;
        hx509_cursor cursor;
        hx509_cert cert_with_key;

        heim_debug(cred->hctx, 5, "GSS-TLS: loading private key from %s", key_store);

        /* hx509 loads keys via a certificate store interface */
        ret = hx509_certs_init(cred->hx509ctx, key_store, 0, NULL, &key_certs);
        if (ret) {
            heim_debug(cred->hctx, 1, "GSS-TLS: failed to load private key: %d", ret);
            *minor = ret;
            goto fail;
        }

        /* Find a certificate with a private key and extract it */
        ret = hx509_certs_start_seq(cred->hx509ctx, key_certs, &cursor);
        if (ret == 0) {
            while (hx509_certs_next_cert(cred->hx509ctx, key_certs,
                                         cursor, &cert_with_key) == 0 &&
                   cert_with_key != NULL) {
                if (hx509_cert_have_private_key(cert_with_key)) {
                    /* Found a cert with private key - extract the key */
                    cred->key = _hx509_cert_private_key(cert_with_key);
                    if (cred->key) {
                        _hx509_private_key_ref(cred->key);
                        heim_debug(cred->hctx, 5, "GSS-TLS: extracted private key");
                    }
                    hx509_cert_free(cert_with_key);
                    break;
                }
                hx509_cert_free(cert_with_key);
            }
            hx509_certs_end_seq(cred->hx509ctx, key_certs, cursor);
        }
        hx509_certs_free(&key_certs);
    }

    /* Load trust anchors if specified */
    if (anchor_store) {
        heim_debug(cred->hctx, 5, "GSS-TLS: loading trust anchors from %s", anchor_store);
        ret = hx509_certs_init(cred->hx509ctx, anchor_store, 0, NULL,
                               &cred->trust_anchors);
        if (ret) {
            heim_debug(cred->hctx, 1, "GSS-TLS: failed to load trust anchors: %d", ret);
            *minor = ret;
            goto fail;
        }
    }

    /* Load revocation info if specified */
    if (revoke_store) {
        ret = hx509_revoke_init(cred->hx509ctx, &cred->revoke);
        if (ret) {
            *minor = ret;
            goto fail;
        }
        ret = hx509_revoke_add_crl(cred->hx509ctx, cred->revoke, revoke_store);
        if (ret) {
            *minor = ret;
            goto fail;
        }
    }

    /* Validate credential configuration */
    if (cred_usage == GSS_C_ACCEPT && !cred->certs && !cred->anonymous) {
        /* Acceptor (server) must have a certificate unless explicitly anonymous */
        *minor = EINVAL;
        goto fail;
    }

    /* Return mechanism OID set if requested */
    if (actual_mechs) {
        ret = gss_create_empty_oid_set(minor, actual_mechs);
        if (ret != GSS_S_COMPLETE)
            goto fail;
        ret = gss_add_oid_set_member(minor, GSS_TLS_MECHANISM, actual_mechs);
        if (ret != GSS_S_COMPLETE) {
            gss_release_oid_set(minor, actual_mechs);
            goto fail;
        }
    }

    heim_debug(cred->hctx, 5, "GSS-TLS: credential acquired successfully");

    *output_cred = (gss_cred_id_t)cred;
    return GSS_S_COMPLETE;

fail:
    heim_debug(cred->hctx, 1, "GSS-TLS: credential acquisition failed");
    if (cred->hctx)
        heim_context_free(&cred->hctx);
    if (cred->revoke)
        hx509_revoke_free(&cred->revoke);
    if (cred->trust_anchors)
        hx509_certs_free(&cred->trust_anchors);
    if (cred->certs)
        hx509_certs_free(&cred->certs);
    if (cred->hx509ctx)
        hx509_context_free(&cred->hx509ctx);
    free(cred);
    return GSS_S_FAILURE;
}

/*
 * GSS-API release_cred for TLS mechanism
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_release_cred(OM_uint32 *minor,
                      gss_cred_id_t *cred_handle)
{
    gss_tls_cred cred;

    *minor = 0;

    if (cred_handle == NULL || *cred_handle == GSS_C_NO_CREDENTIAL)
        return GSS_S_COMPLETE;

    cred = (gss_tls_cred)*cred_handle;

    heim_debug(cred->hctx, 5, "GSS-TLS: releasing credential");

    if (cred->hctx)
        heim_context_free(&cred->hctx);
    if (cred->revoke)
        hx509_revoke_free(&cred->revoke);
    if (cred->trust_anchors)
        hx509_certs_free(&cred->trust_anchors);
    if (cred->key)
        hx509_private_key_free(&cred->key);
    if (cred->certs)
        hx509_certs_free(&cred->certs);
    if (cred->hx509ctx)
        hx509_context_free(&cred->hx509ctx);

    memset(cred, 0, sizeof(*cred));
    free(cred);
    *cred_handle = GSS_C_NO_CREDENTIAL;

    return GSS_S_COMPLETE;
}

/*
 * GSS-API inquire_cred for TLS mechanism
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_inquire_cred(OM_uint32 *minor,
                      gss_const_cred_id_t cred_handle,
                      gss_name_t *name,
                      OM_uint32 *lifetime,
                      gss_cred_usage_t *cred_usage,
                      gss_OID_set *mechanisms)
{
    const struct gss_tls_cred_desc *cred =
        (const struct gss_tls_cred_desc *)cred_handle;
    OM_uint32 major;

    *minor = 0;

    if (name)
        *name = GSS_C_NO_NAME;
    if (lifetime)
        *lifetime = GSS_C_INDEFINITE;
    if (cred_usage)
        *cred_usage = GSS_C_BOTH;
    if (mechanisms)
        *mechanisms = GSS_C_NO_OID_SET;

    if (cred == NULL) {
        /* Default credential - not supported yet */
        *minor = EINVAL;
        return GSS_S_NO_CRED;
    }

    if (cred_usage)
        *cred_usage = cred->usage;

    /* TODO: Extract name from certificate subject */
    if (name && cred->certs) {
        /* Would iterate certs to find leaf and extract subject DN */
    }

    if (mechanisms) {
        major = gss_create_empty_oid_set(minor, mechanisms);
        if (major != GSS_S_COMPLETE)
            return major;
        major = gss_add_oid_set_member(minor, GSS_TLS_MECHANISM, mechanisms);
        if (major != GSS_S_COMPLETE) {
            gss_release_oid_set(minor, mechanisms);
            return major;
        }
    }

    return GSS_S_COMPLETE;
}

/*
 * GSS-API inquire_cred_by_mech for TLS mechanism
 */
OM_uint32 GSSAPI_CALLCONV
_gss_tls_inquire_cred_by_mech(OM_uint32 *minor,
                              gss_const_cred_id_t cred_handle,
                              const gss_OID mech_type,
                              gss_name_t *name,
                              OM_uint32 *initiator_lifetime,
                              OM_uint32 *acceptor_lifetime,
                              gss_cred_usage_t *cred_usage)
{
    OM_uint32 lifetime;
    gss_cred_usage_t usage;

    (void)mech_type;

    *minor = 0;

    if (name)
        *name = GSS_C_NO_NAME;
    if (initiator_lifetime)
        *initiator_lifetime = 0;
    if (acceptor_lifetime)
        *acceptor_lifetime = 0;
    if (cred_usage)
        *cred_usage = GSS_C_BOTH;

    /* Use inquire_cred for the common work */
    _gss_tls_inquire_cred(minor, cred_handle, name, &lifetime, &usage, NULL);

    if (initiator_lifetime && (usage == GSS_C_INITIATE || usage == GSS_C_BOTH))
        *initiator_lifetime = lifetime;
    if (acceptor_lifetime && (usage == GSS_C_ACCEPT || usage == GSS_C_BOTH))
        *acceptor_lifetime = lifetime;
    if (cred_usage)
        *cred_usage = usage;

    return GSS_S_COMPLETE;
}
