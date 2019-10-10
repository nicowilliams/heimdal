/*
 * Copyright (c) 2006 - 2019 Kungliga Tekniska Högskolan
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

#include "kdc_locl.h"
#include <hex.h>
#include <rfc2459_asn1.h>
#include <hx509.h>
#include <kx509_err.h>

#include <stdarg.h>

/*
 * This file implements the kx509 service.
 *
 * The protocol, its shortcomings, and its future are described in
 * lib/krb5/hx509.c.  See also lib/asn1/kx509.asn1.
 *
 * The service handles requests, decides whether to issue a certificate, and
 * does so by populating a "template" to generate a TBSCertificate and signing
 * it with a configured CA issuer certificate and private key.
 *
 * A "template" is a Certificate that has ${variable} references in its
 * subjectName, and may have EKUs.
 *
 * Some SANs may be included in issued certificates.  See below.
 *
 * Besides future protocol improvements described in lib/krb5/hx509.c, here is
 * a list of KDC functionality we'd like to add:
 *
 *  - support templates as strings (rather than filenames) in configuration?
 *  - lookup an hx509 template for the client principal in its HDB entry?
 *  - lookup subjectName, SANs for a principal in its HDB entry
 *  - lookup a host-based client principal's HDB entry and add its canonical
 *    name / aliases as dNSName SANs
 *    (this would have to be if requested by the client, perhaps; see
 *     commentary about the protocol in lib/krb5/kx509.c)
 *  - add code to build a template on the fly
 *
 *    (just SANs, with empty subjectName?
 *     or
 *     CN=component0,CN=component1,..,CN=componentN,DC=<from-REALM>
 *     and set KU and EKUs)
 */

#ifdef KX509

static const unsigned char version_2_0[4] = {0 , 0, 2, 0};

typedef struct kx509_req_context {
    krb5_kdc_configuration *config;
    const krb5_config_binding *cf;
    const struct Kx509Request *req;
    heim_octet_string token_jwt;
    heim_octet_string token_saml;
    heim_octet_string token_oidc;
    krb5_principal on_behalf_of;
    Kx509CSRPlus csr_plus;
    krb5_auth_context ac;
    const char *realm; /* XXX Confusion: is this crealm or srealm? */
    char *sname;
    char *cname;
    struct sockaddr *addr;
    const char *from;
    krb5_keyblock *key;
    hx509_request csr;
    krb5_data *reply;
    krb5_times ticket_times;
    krb5_times token_times;
    unsigned int have_auth_data:1;      /* Relevant authz data in the AP-REQ */
    unsigned int send_chain:1;          /* Client expects a full chain */
    unsigned int have_csr:1;            /* Client sent a CSR */
    unsigned int clnt_claims_authz:1;   /* Client sent AD-CSR-AUTHORIZED */
    unsigned int csr_authorized:1;      /* AD-CSR-AUTHORIZED accepted */
    unsigned int wants_default_cert:1;
    unsigned int want_server_cert:1;
    unsigned int want_client_cert:1;
    unsigned int want_sans:1;
    unsigned int has_sans:1;
    unsigned int have_tokens:1;
    unsigned int is_not_proxied:1;
    unsigned int is_proxied:1;
    unsigned int mixed_certs_ok:1;
    unsigned int empty_subject_name:1;
} *kx509_req_context;

/*
 * Taste the request to see if it's a kx509 request.
 */
krb5_error_code
_kdc_try_kx509_request(void *ptr, size_t len, struct Kx509Request *req)
{
    const unsigned char *p = (const void *)(uintptr_t)ptr;
    size_t sz;

    if (len < sizeof(version_2_0))
	return -1;
    if (memcmp(version_2_0, p, sizeof(version_2_0)) != 0)
	return -1;
    p += sizeof(version_2_0);
    len -= sizeof(version_2_0);
    if (len == 0)
        return -1;
    return decode_Kx509Request(p, len, req, &sz);
}

static krb5_boolean
get_bool_param(krb5_context context,
               krb5_boolean def,
               const char *crealm,
               const char *name)
{
    krb5_boolean global_default;

    global_default = krb5_config_get_bool_default(context, NULL, def, "kdc",
                                                  name, NULL);
    if (!crealm)
        return global_default;
    return krb5_config_get_bool_default(context, NULL, global_default,
                                        "kdc", "realm", crealm, name, NULL);
}

/*
 * Verify the HMAC in the request.
 */
static krb5_error_code
verify_req_hash(krb5_context context,
		const Kx509Request *req,
		krb5_keyblock *key)
{
    unsigned char digest[SHA_DIGEST_LENGTH];
    HMAC_CTX ctx;

    if (req->pk_hash.length != sizeof(digest)) {
	krb5_set_error_message(context, KRB5KDC_ERR_PREAUTH_FAILED,
			       "pk-hash have wrong length: %lu",
			       (unsigned long)req->pk_hash.length);
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx,
		 key->keyvalue.data, key->keyvalue.length,
		 EVP_sha1(), NULL);
    if (sizeof(digest) != HMAC_size(&ctx))
	krb5_abortx(context, "runtime error, hmac buffer wrong size in kx509");
    HMAC_Update(&ctx, version_2_0, sizeof(version_2_0));
    if (req->pk_key.length)
        HMAC_Update(&ctx, req->pk_key.data, req->pk_key.length);
    else
        HMAC_Update(&ctx, req->authenticator.data, req->authenticator.length);
    HMAC_Final(&ctx, digest, 0);
    HMAC_CTX_cleanup(&ctx);

    if (ct_memcmp(req->pk_hash.data, digest, sizeof(digest)) != 0) {
	krb5_set_error_message(context, KRB5KDC_ERR_PREAUTH_FAILED,
			       "kx509 request MAC mismatch");
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    return 0;
}

/* Wrapper around kdc_log() that adds contextual information */
static void
kx509_log(krb5_context context,
          kx509_req_context reqctx,
          int level,
          const char *fmt,
          ...)
{
    va_list ap;
    char *msg;

    va_start(ap, fmt);
    if (vasprintf(&msg, fmt, ap) == -1 || msg == NULL) {
        kdc_log(context, reqctx->config, level,
                "Out of memory while formatting log message");
        va_end(ap);
        va_start(ap, fmt);
        kdc_vlog(context, reqctx->config, level, fmt, ap);
        va_end(ap);
        return;
    }
    va_end(ap);

    kdc_log(context, reqctx->config, level,
            "kx509 %s (from %s for %s, service %s)", msg,
            reqctx->from ? reqctx->from : "<unknown>",
            reqctx->cname ? reqctx->cname : "<unknown-client-principal>",
            reqctx->sname ? reqctx->sname : "<unknown-service-principal>");
    free(msg);
}

/*
 * Set the HMAC in the response.
 */
static krb5_error_code
calculate_reply_hash(krb5_context context,
		     krb5_keyblock *key,
		     Kx509Response *rep)
{
    krb5_error_code ret;
    HMAC_CTX ctx;

    HMAC_CTX_init(&ctx);

    HMAC_Init_ex(&ctx, key->keyvalue.data, key->keyvalue.length,
		 EVP_sha1(), NULL);
    ret = krb5_data_alloc(rep->hash, HMAC_size(&ctx));
    if (ret) {
	HMAC_CTX_cleanup(&ctx);
	krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
	return ENOMEM;
    }

    HMAC_Update(&ctx, version_2_0, sizeof(version_2_0));
    {
	int32_t t = rep->error_code;
        unsigned char encint[sizeof(t) + 1];
        size_t k;

        /*
         * RFC6717 says this about how the error-code is included in the HMAC:
         *
         *  o DER representation of the error-code exclusive of the tag and
         *    length, if it is present.
         *
         * So we use der_put_integer(), which encodes from the right.
         *
         * RFC6717 does not constrain the error-code's range.  We assume it to
         * be a 32-bit, signed integer, for which we'll need no more than 5
         * bytes.
         */
        ret = der_put_integer(&encint[sizeof(encint) - 1],
                              sizeof(encint), &t, &k);
        if (ret == 0)
            HMAC_Update(&ctx, &encint[sizeof(encint)] - k, k);
    }
    if (rep->certificate)
	HMAC_Update(&ctx, rep->certificate->data, rep->certificate->length);
    if (rep->e_text)
	HMAC_Update(&ctx, (unsigned char *)*rep->e_text, strlen(*rep->e_text));

    HMAC_Final(&ctx, rep->hash->data, 0);
    HMAC_CTX_cleanup(&ctx);

    return 0;
}

static void
frees(char **s)
{
    free(*s);
    *s = NULL;
}

/*
 * Handle desired certificate extensions.
 *
 * If invoked with `tbs == NULL', then just characterize the request into
 * `reqctx'.
 *
 * If invoked with `tbs != NULL', then update the to-be-signed certificate with
 * the extensions if they were authorized.
 */
static krb5_error_code
handle_exts_from_csr_plus(krb5_context context,
                          kx509_req_context reqctx,
                          hx509_ca_tbs tbs)
{
    krb5_error_code ret;
    KeyUsage ku;
    char *s = NULL;
    int cursor;
    int want_ekus = 0;

    if (!reqctx->have_csr) {
        reqctx->wants_default_cert = 1;
        return 0;
    }
    if (!reqctx->csr_authorized)
        return 0;

    reqctx->wants_default_cert = 1;
    cursor = 0;
    while ((ret = hx509_request_get_eku(context->hx509ctx, reqctx->csr,
                                        &s, &cursor)) == 0 && s) {
        heim_oid oid;

        want_ekus = 1;
        ret = der_parse_heim_oid(s, ".", &oid);
        if (ret == 0) {
            /*
             * If the client wants only a server certificate, then we'll be
             * willing to issue one that may be longer-lived than the client's
             * ticket/token.
             *
             * There may be other server EKUs, but these are the ones we know
             * of.
             */
            if (der_heim_oid_cmp(&asn1_oid_id_pkix_kp_serverAuth, &oid) &&
                der_heim_oid_cmp(&asn1_oid_id_pkix_kp_OCSPSigning, &oid) &&
                der_heim_oid_cmp(&asn1_oid_id_pkix_kp_secureShellServer, &oid))
                reqctx->want_client_cert = 1;
            if (tbs)
                ret = hx509_ca_tbs_add_eku(context->hx509ctx, tbs, &oid);
            der_free_oid(&oid);
        }
        frees(&s);
        if (ret)
            return ret;
        reqctx->wants_default_cert = 0;
    }
    frees(&s);
    if (ret && ret != -1)
        return ret;

    cursor = 0;
    while ((ret = hx509_request_get_pkinit_san(context->hx509ctx, reqctx->csr,
                                               &s, &cursor)) == 0 && s) {
        if (tbs)
            ret = hx509_ca_tbs_add_san_pkinit(context->hx509ctx, tbs, s);
        reqctx->has_sans = 1;
        frees(&s);
        if (ret)
            return ret;
        /* This SAN implies client cert if no clienty EKUs requested */
        if (!want_ekus)
            reqctx->want_client_cert = 1;
        reqctx->wants_default_cert = 0;
    }
    frees(&s);
    if (ret && ret != -1)
        return ret;

    cursor = 0;
    while ((ret = hx509_request_get_xmpp_san(context->hx509ctx, reqctx->csr,
                                             &s, &cursor)) == 0 && s) {
        if (tbs)
            ret = hx509_ca_tbs_add_san_jid(context->hx509ctx, tbs, s);
        reqctx->has_sans = 1;
        frees(&s);
        if (ret)
            return ret;
        reqctx->want_client_cert = 1;
        reqctx->wants_default_cert = 0;
    }
    frees(&s);
    if (ret && ret != -1)
        return ret;

    cursor = 0;
    while ((ret = hx509_request_get_ms_upn_san(context->hx509ctx, reqctx->csr,
                                               &s, &cursor)) == 0 && s) {
        if (tbs)
            ret = hx509_ca_tbs_add_san_ms_upn(context->hx509ctx, tbs, s);
        reqctx->has_sans = 1;
        frees(&s);
        if (ret)
            return ret;
        reqctx->wants_default_cert = 0;
        reqctx->want_client_cert = 1;
    }
    frees(&s);
    if (ret && ret != -1)
        return ret;

    cursor = 0;
    while ((ret = hx509_request_get_email_san(context->hx509ctx, reqctx->csr,
                                              &s, &cursor)) == 0 && s) {
        if (tbs)
            ret = hx509_ca_tbs_add_san_rfc822name(context->hx509ctx, tbs, s);
        reqctx->has_sans = 1;
        frees(&s);
        if (ret)
            return ret;
        reqctx->wants_default_cert = 0;
        reqctx->want_client_cert = 1;
    }
    frees(&s);
    if (ret && ret != -1)
        return ret;

    cursor = 0;
    while ((ret = hx509_request_get_dns_name_san(context->hx509ctx,
                                                 reqctx->csr, &s,
                                                 &cursor)) == 0 && s) {
        if (tbs)
            ret = hx509_ca_tbs_add_san_hostname(context->hx509ctx, tbs, s);
        reqctx->has_sans = 1;
        reqctx->wants_default_cert = 0;
        reqctx->want_server_cert = 1;
        frees(&s);
        if (ret)
            return ret;
    }
    frees(&s);
    if (ret && ret != -1)
        return ret;

    ret = hx509_request_get_ku(context->hx509ctx, reqctx->csr, &ku);
    if (ret == 0 && tbs)
        /*
         * Here we can't tell if we had a requested KU, so we'll not reset 
         * reqctx->wants_default_cert.  It's not that important
         */
        (void) hx509_ca_tbs_add_ku(context->hx509ctx, tbs, ku);

    return ret;
}

/*
 * Get a configuration sub-tree for kx509 based on what's being requested / by
 * whom / on behalf of whom.
 *
 * We have a number of cases:
 *
 *  - default certificate (no CSR used, or no certificate extensions requested)
 *     - for client principals
 *     - for service principals
 *  - client certificate requested (CSR used and client-y SANs/EKUs requested)
 *  - server certificate requested (CSR used and server-y SANs/EKUs requested)
 *  - mixed client/server certificate requested (...)
 */
static const krb5_config_binding *
get_cf(krb5_context context,
       kx509_req_context reqctx,
       krb5_principal principal)
{
    const krb5_config_binding *cf = NULL;
    unsigned int ncomp = krb5_principal_get_num_comp(context, principal);
    const char *realm = krb5_principal_get_realm(context, principal);
    const char *comp0 = krb5_principal_get_comp_string(context, principal, 0);
    const char *comp1 = krb5_principal_get_comp_string(context, principal, 1);
    const char *label = NULL;
    const char *svc = NULL;
    const char *def;

    if (ncomp == 0)
        return NULL;

    if (!reqctx->wants_default_cert) {
        def = "custom";
        /* Client requested some certificate extension, a SAN or EKU */
        if (reqctx->want_client_cert && reqctx->want_server_cert)
            label = "mixed";
        else if (reqctx->want_client_cert && !reqctx->want_server_cert)
            label = "client";
        else if (!reqctx->want_client_cert && reqctx->want_server_cert)
            label = "server";
        else
            label = "other";
    } else {
        def = "default";
        /* Default certificate desired */
        if (ncomp == 1) {
            label = "user";
        } else if (ncomp == 2 && strcmp(comp0, "root") == 0) {
            label = "root_user";
        } else if (ncomp == 2 && strcmp(comp1, "admin") == 0) {
            label = "admin_user";
        } else if (strchr(comp1, '.')) {
            label = "hostbased_service";
            svc = comp0;
        } else {
            label = "other";
        }
    }

    cf = krb5_config_get_list(context, NULL, "kdc", "realm", realm, "kx509",
                              label, svc, NULL);
    if (cf == NULL)
        kdc_log(context, reqctx->config, 0,
                "No kx509 configuration for %s %s certificates [kdc] realm "
                "-> %s -> kx509 -> %s%s%s", def, label, realm, label,
                svc ? " -> " : "", svc ? svc : "");
    return cf;
}

/*
 * Find and set a certificate template using a configuration sub-tree
 * appropriate to the requesting principal.
 *
 * This allows for the specification of the following in configuration:
 *
 *  - certificates as templates, with ${var} tokens in subjectName attribute
 *    values that will be expanded later
 *  - a plain string with ${var} tokens to use as the subjectName
 *  - EKUs
 *  - whether to include a PKINIT SAN
 */
static krb5_error_code
set_template(krb5_context context,
             kx509_req_context reqctx,
             krb5_principal principal,
             hx509_ca_tbs tbs)
{
    krb5_error_code ret = 0;
    const char *cert_template = NULL;
    const char *subj_name = NULL;
    char **ekus = NULL;

    if (reqctx->cf == NULL)
        return KRB5KDC_ERR_POLICY; /* Can't happen */

    cert_template = krb5_config_get_string(context, reqctx->cf,
                                           "template_cert", NULL);
    subj_name = krb5_config_get_string(context, reqctx->cf, "subject_name",
                                       NULL);
    ekus = krb5_config_get_strings(context, reqctx->cf, "ekus", NULL);

    if (cert_template) {
	hx509_certs certs;
	hx509_cert template;

	ret = hx509_certs_init(context->hx509ctx, cert_template, 0,
			       NULL, &certs);
        if (ret == 0)
            ret = hx509_get_one_cert(context->hx509ctx, certs, &template);
	hx509_certs_free(&certs);
	if (ret) {
	    kdc_log(context, reqctx->config, 0,
                    "Failed to load template from %s", cert_template);
	    return ret;
	}

        /*
         * Only take the subjectName, the keyUsage, and EKUs from the template
         * certificate.
         */
	ret = hx509_ca_tbs_set_template(context->hx509ctx, tbs,
					HX509_CA_TEMPLATE_SUBJECT |
					HX509_CA_TEMPLATE_KU |
					HX509_CA_TEMPLATE_EKU,
					template);
	hx509_cert_free(template);
	if (ret)
	    return ret;
    }

    if (subj_name) {
        hx509_name dn = NULL;

        ret = hx509_parse_name(context->hx509ctx, subj_name, &dn);
        if (ret == 0)
            ret = hx509_ca_tbs_set_subject(context->hx509ctx, tbs, dn);
        hx509_name_free(&dn);
        if (ret)
            return ret;
    }

    if (cert_template == NULL && subj_name == NULL) {
        hx509_name dn = NULL;

        ret = hx509_empty_name(context->hx509ctx, &dn);
        if (ret == 0)
            ret = hx509_ca_tbs_set_subject(context->hx509ctx, tbs, dn);
        hx509_name_free(&dn);
        if (ret)
            return ret;
    }

    if (hx509_name_is_null_p(hx509_ca_tbs_get_name(tbs)))
        reqctx->empty_subject_name = 1;

    if (ekus) {
        size_t i;

        for (i = 0; ret == 0 && ekus[i]; i++) {
            heim_oid oid = { 0, 0 };

            if ((ret = der_find_or_parse_heim_oid(ekus[i], ".", &oid)) == 0)
                ret = hx509_ca_tbs_add_eku(context->hx509ctx, tbs, &oid);
            der_free_oid(&oid);
        }
        krb5_config_free_strings(ekus);
    }

    /*
     * XXX A KeyUsage template would be nice, but it needs some smarts to
     * remove, e.g., encipherOnly, decipherOnly, keyEncipherment, if the SPKI
     * algorithm does not support encryption.  The same logic should be added
     * to hx509_ca_tbs_set_template()'s HX509_CA_TEMPLATE_KU functionality.
     */
    return ret;
}

/*
 * Find and set a certificate template, set "variables" in `env', and add add
 * default SANs/EKUs as appropriate.
 *
 * TODO:
 *  - lookup a template for the client principal in its HDB entry
 *  - lookup subjectName, SANs for a principal in its HDB entry
 *  - lookup a host-based client principal's HDB entry and add its canonical
 *    name / aliases as dNSName SANs
 *    (this would have to be if requested by the client, perhaps)
 */
static krb5_error_code
set_tbs(krb5_context context,
        kx509_req_context reqctx,
        krb5_principal principal,
        const char *princ_no_realm,
        const char *princ,
        hx509_env *env,
        hx509_ca_tbs tbs)
{
    krb5_error_code ret = KRB5KDC_ERR_POLICY;
    unsigned int ncomp = krb5_principal_get_num_comp(context, principal);
    const char *comp0 = krb5_principal_get_comp_string(context, principal, 0);
    const char *comp1 = krb5_principal_get_comp_string(context, principal, 1);
    const char *comp2 = krb5_principal_get_comp_string(context, principal, 2);

    /* Populate requested certificate extensions from CSR/CSRPlus if allowed */
    ret = handle_exts_from_csr_plus(context, reqctx, tbs);
    if (ret == 0)
        ret = set_template(context, reqctx, principal, tbs);

    /*
     * Optionally add PKINIT SAN.
     *
     * Adding an id-pkinit-san means the client can use the certificate to
     * initiate PKINIT.  That might seem odd, but it enables a sort of PKIX
     * credential delegation by allowing forwarded Kerberos tickets to be
     * used to acquire PKIX credentials.  Thus this can work:
     *
     *      PKIX (w/ HW token) -> Kerberos ->
     *        PKIX (w/ softtoken) -> Kerberos ->
     *          PKIX (w/ softtoken) -> Kerberos ->
     *            ...
     *
     * Note that we may not have added the PKINIT EKU -- that depends on the
     * template, and host-based service templates might well not include it.
     */
    if (ret == 0 && reqctx->wants_default_cert &&
        krb5_config_get_bool_default(context, reqctx->cf, FALSE,
                                     "include_pkinit_san", NULL)) {
        ret = hx509_ca_tbs_add_san_pkinit(context->hx509ctx, tbs, princ);
        reqctx->has_sans = 1;
    }

    if (ret)
        return ret;

    if (ncomp == 1) {
        const char *email_domain;

        ret = hx509_env_add(context->hx509ctx, env, "principal-component0",
                            princ_no_realm);

        /*
         * If configured, include an rfc822Name that's just the client's
         * principal name sans realm @ configured email domain.
         */
        if (ret == 0 && reqctx->wants_default_cert &&
            (email_domain = krb5_config_get_string(context, reqctx->cf,
                                                   "email_domain", NULL))) {
            char *email;

            if (asprintf(&email, "%s@%s", princ_no_realm, email_domain) == -1 ||
                email == NULL)
                return krb5_enomem(context);
            ret = hx509_ca_tbs_add_san_rfc822name(context->hx509ctx, tbs, email);
            reqctx->has_sans = 1;
            free(email);
        }
        return ret;
    } else if (ncomp == 2 || ncomp == 3) {
        /*
         * 2- and 3-component principal name.
         *
         * We do not have a reliable name-type indicator.  If the second
         * component has a '.' in it then we'll assume that the name is a
         * host-based (2-component) or domain-based (3-component) service
         * principal name.  Else we'll assume it's a two-component admin-style
         * username.
         */

        ret = hx509_env_add(context->hx509ctx, env, "principal-component0",
                            comp0);
        if (ret == 0)
            ret = hx509_env_add(context->hx509ctx, env, "principal-component1",
                                comp1);
        if (ret == 0 && ncomp == 3)
            ret = hx509_env_add(context->hx509ctx, env, "principal-component2",
                                comp2);

        if (ret)
            goto out;

        if (ret == 0 && strchr(comp1, '.')) {
            /* Looks like host-based or domain-based service */
            ret = hx509_env_add(context->hx509ctx, env,
                                "principal-service-name", comp0);
            if (ret == 0)
                ret = hx509_env_add(context->hx509ctx, env, "principal-host-name", comp1);
            if (ret == 0 && ncomp == 3)
                ret = hx509_env_add(context->hx509ctx, env, "principal-domain-name", comp2);
            if (ret == 0 &&
                reqctx->wants_default_cert &&
                krb5_config_get_bool_default(context, reqctx->cf, FALSE,
                                             "include_dnsname_san", NULL)) {
                ret = hx509_ca_tbs_add_san_hostname(context->hx509ctx, tbs, comp1);
                reqctx->has_sans = 1;
            }
        }
    } else {
        kdc_log(context, reqctx->config, 2, "kx509 client %s has too many components!",
                princ);
        ret = KRB5KDC_ERR_POLICY;
    }

out:
    return ret;
}

static int
chain_add1_func(hx509_context context, void *d, hx509_cert c)
{
    heim_octet_string os;
    Certificates *cs = d;
    Certificate c2;
    int ret;

    ret = hx509_cert_binary(context, c, &os);
    if (ret)
        return ret;
    ret = decode_Certificate(os.data, os.length, &c2, NULL);
    der_free_octet_string(&os);
    if (ret)
        return ret;
    ret = add_Certificates(cs, &c2);
    free_Certificate(&c2);
    return ret;
}

static krb5_error_code
encode_cert_and_chain(hx509_context hx509ctx,
                      hx509_cert cert,
                      const char *chain_store,
                      krb5_data *out)
{
    krb5_error_code ret;
    Certificates cs;
    hx509_certs certs = NULL;
    size_t len;

    cs.len = 0;
    cs.val = 0;

    ret = chain_add1_func(hx509ctx, &cs, cert);
    if (ret == 0)
        ret = hx509_certs_init(hx509ctx, chain_store, 0, NULL, &certs);
    if (ret == 0)
        ret = hx509_certs_iter_f(hx509ctx, certs, chain_add1_func, &cs);
    hx509_certs_free(&certs);
    if (ret == 0)
        ASN1_MALLOC_ENCODE(Certificates, out->data, out->length,
                           &cs, &len, ret);
    free_Certificates(&cs);
    return ret;
}

static krb5_error_code
tbs_set_times(krb5_context context,
              kx509_req_context reqctx,
              hx509_ca_tbs tbs)
{
    time_t now = time(NULL);
    time_t endtime = 0;
    time_t starttime = 0;
    time_t req_life =
        reqctx->csr_plus.req_life ? *reqctx->csr_plus.req_life : 0;
    int server_life =
        krb5_config_get_time_default(context, NULL, 5 * 24 * 3600, "kdc",
                                     "kx509_server_cert_life", NULL);
    int expless_token_life =
        krb5_config_get_time_default(context, NULL, 0, "kdc"
                                     "kx509_expless_token_life", NULL);

    if (reqctx->is_not_proxied) {
        endtime = reqctx->ticket_times.endtime;
        starttime = reqctx->ticket_times.starttime;
    }

    if (reqctx->have_tokens) {
        starttime = reqctx->token_times.starttime ?
            reqctx->token_times.starttime : time(NULL);

        endtime = reqctx->token_times.endtime;
        if (endtime == 0 && reqctx->is_proxied) {
            if (expless_token_life == 0) {
                krb5_set_error_message(context, EINVAL,
                                       "Bearer token has no endtime and "
                                       "[kdc]->kx509_expless_token_life "
                                       "not set");
                return EINVAL;
            }
            endtime = starttime + expless_token_life;
        }
    }

    if (reqctx->want_server_cert && !reqctx->want_client_cert &&
        starttime + server_life < endtime)
        endtime = starttime + server_life;

    if (req_life && req_life < endtime - now)
        endtime -= endtime - now - req_life;

    hx509_ca_tbs_set_notAfter(context->hx509ctx, tbs, endtime);
    if (starttime)
        hx509_ca_tbs_set_notBefore(context->hx509ctx, tbs, starttime);
    return 0;
}

/*
 * Build a certifate for `principal´
 */
static krb5_error_code
build_certificate(krb5_context context,
                  kx509_req_context reqctx,
		  krb5_principal principal,
		  krb5_data *certificate)
{
    const char *crealm = krb5_principal_get_realm(context, principal);
    const char *kx509_ca;
    char *princ = NULL;
    char *name = NULL;
    hx509_ca_tbs tbs = NULL;
    hx509_env env = NULL;
    hx509_cert cert = NULL;
    hx509_cert signer = NULL;
    krb5_error_code ret;

    /* Characterize the request (e.g., set reqctx->wants_default_cert, etc.) */
    ret = handle_exts_from_csr_plus(context, reqctx, NULL);
    if (ret)
        return ret;

    /* Get configuration */
    if ((reqctx->cf = get_cf(context, reqctx, principal)) == NULL)
        return KRB5KDC_ERR_POLICY;
    if ((kx509_ca = krb5_config_get_string(context, reqctx->cf,
                                           "ca", NULL)) == NULL) {
        kdc_log(context, reqctx->config, 0, "No kx509 CA issuer credential "
                "specified");
        return KRB5KDC_ERR_POLICY;
    }

    ret = hx509_ca_tbs_init(context->hx509ctx, &tbs);
    if (ret)
	return ret;

    ret = krb5_unparse_name_flags(context, principal,
				  KRB5_PRINCIPAL_UNPARSE_NO_REALM,
				  &name);
    if (ret == 0)
        ret = krb5_unparse_name(context, principal, &princ);

    /* Lookup a template and set things in `env' and `tbs' as appropriate */
    if (ret == 0)
        ret = set_tbs(context, reqctx, principal, name, princ, &env, tbs);

    /* Populate generic template "env" variables */
    if (ret == 0)
        ret = hx509_env_add(context->hx509ctx, &env,
                            "principal-name-without-realm", name);
    if (ret == 0)
        ret = hx509_env_add(context->hx509ctx, &env, "principal-name", princ);
    if (ret == 0)
        ret = hx509_env_add(context->hx509ctx, &env, "principal-name-realm",
                            crealm);

    /*
     * The `tbs' and `env' are now complete as to naming and EKUs.
     *
     * We check that the `tbs' is not name-less, after which all remaining
     * failures here will not be policy failures.  So we also log the intent to
     * issue a certificate now.
     */
    if (ret == 0 && reqctx->empty_subject_name && !reqctx->has_sans) {
        kdc_log(context, reqctx->config, 3, "Not issuing certificate to %s "
                "because it would have no names", princ);
        ret = KRB5KDC_ERR_POLICY;
    }
    if (ret)
	goto out;

    /* Remaining failures will not be policy failures.  Log now. */
    kdc_log(context, reqctx->config, 3, "Issuing kx509 certificate to %s",
            princ);

    /*
     * Still to be done below:
     *
     *  - set certificate spki
     *  - set certificate validity
     *  - expand variables in certificate subject name template
     *  - sign certificate
     *  - encode certificate and chain
     */

    /* Load the issuer certificate and private key */
    {
	hx509_certs certs;
	hx509_query *q;

	ret = hx509_certs_init(context->hx509ctx, kx509_ca, 0, NULL, &certs);
	if (ret) {
	    kdc_log(context, reqctx->config, 0,
                    "Failed to load CA %s", kx509_ca);
	    goto out;
	}
	ret = hx509_query_alloc(context->hx509ctx, &q);
	if (ret) {
	    hx509_certs_free(&certs);
	    goto out;
	}

	hx509_query_match_option(q, HX509_QUERY_OPTION_PRIVATE_KEY);
	hx509_query_match_option(q, HX509_QUERY_OPTION_KU_KEYCERTSIGN);

	ret = hx509_certs_find(context->hx509ctx, certs, q, &signer);
	hx509_query_free(context->hx509ctx, q);
	hx509_certs_free(&certs);
	if (ret) {
	    kdc_log(context, reqctx->config, 0,
                    "Failed to find a CA in %s", kx509_ca);
	    goto out;
	}
    }

    /* Populate the subject public key in the TBS context */
    {
	SubjectPublicKeyInfo spki;

        ret = hx509_request_get_SubjectPublicKeyInfo(context->hx509ctx,
                                                     reqctx->csr,
                                                     &spki);
        if (ret == 0)
            ret = hx509_ca_tbs_set_spki(context->hx509ctx, tbs, &spki);
        free_SubjectPublicKeyInfo(&spki);
	if (ret)
	    goto out;
    }

    /* Work out cert expiration */
    if (ret == 0)
        ret = tbs_set_times(context, reqctx, tbs);

    /* Expand the subjectName template in the TBS using the env */
    if (ret == 0)
        ret = hx509_ca_tbs_subject_expand(context->hx509ctx, tbs, env);
    hx509_env_free(&env);

    /* All done with the TBS, sign/issue the certificate */
    ret = hx509_ca_sign(context->hx509ctx, tbs, signer, &cert);
    if (ret)
	goto out;

    /* Encode and output the certificate */
    if (reqctx->send_chain)
        ret = encode_cert_and_chain(context->hx509ctx, cert, kx509_ca, certificate);
    else
        ret = hx509_cert_binary(context->hx509ctx, cert, certificate);

out:
    krb5_xfree(name);
    krb5_xfree(princ);
    if (env)
	hx509_env_free(&env);
    if (tbs)
	hx509_ca_tbs_free(&tbs);
    if (cert)
        hx509_cert_free(cert);
    if (signer)
	hx509_cert_free(signer);
    return ret;
}

/* Check that a krbtgt's second component is a local realm */
static krb5_error_code
is_local_realm(krb5_context context,
               kx509_req_context reqctx,
               const char *realm)
{
    krb5_error_code ret;
    krb5_principal tgs;
    hdb_entry_ex *ent = NULL;

    ret = krb5_make_principal(context, &tgs, realm, KRB5_TGS_NAME, realm,
                              NULL);
    if (ret)
        return ret;
    if (ret == 0)
        ret = _kdc_db_fetch(context, reqctx->config, tgs, HDB_F_GET_KRBTGT,
                            NULL, NULL, &ent);
    if (ent)
        _kdc_free_ent(context, ent);
    krb5_free_principal(context, tgs);
    if (ret == HDB_ERR_NOENTRY || ret == HDB_ERR_NOT_FOUND_HERE)
        return KRB5KRB_AP_ERR_NOT_US;
    return ret;
}

/*
 * Since we're using the HDB as a keytab we have to check that the client used
 * an acceptable name for the kx509 service.
 *
 * We accept two names: kca_service/hostname and krbtgt/REALM.
 *
 * We allow cross-realm requests.
 *
 *     Maybe x-realm support should be configurable.  Requiring INITIAL tickets
 *     does NOT preclude x-realm support!  (Cross-realm TGTs can be INITIAL.)
 *
 *     Support for specific client realms is configurable by configuring issuer
 *     credentials and TBS templates on a per-realm basis and configuring no
 *     default.  But maybe we should have an explicit configuration parameter
 *     to enable support for clients from different realms than the service.
 */
static krb5_error_code
kdc_kx509_verify_service_principal(krb5_context context,
				   kx509_req_context reqctx,
				   krb5_principal sprincipal)
{
    krb5_error_code ret = 0;
    krb5_principal principal = NULL;
    char *expected = NULL;
    char localhost[MAXHOSTNAMELEN];

    if (krb5_principal_get_num_comp(context, sprincipal) != 2)
        goto err;

    /* Check if sprincipal is a krbtgt/REALM name */
    if (strcmp(krb5_principal_get_comp_string(context, sprincipal, 0),
               KRB5_TGS_NAME) == 0) {
        const char *r = krb5_principal_get_comp_string(context, sprincipal, 1);
        if ((ret = is_local_realm(context, reqctx, r)))
            kx509_log(context, reqctx, 2, "client used wrong krbtgt for kx509");
        goto out;
    }

    /* Must be hostbased kca_service name then */
    ret = gethostname(localhost, sizeof(localhost) - 1);
    if (ret != 0) {
	ret = errno;
	krb5_set_error_message(context, ret,
			       N_("Failed to get local hostname", ""));
	return ret;
    }
    localhost[sizeof(localhost) - 1] = '\0';

    ret = krb5_make_principal(context, &principal, "", "kca_service",
			      localhost, NULL);
    if (ret)
	goto out;

    if (krb5_principal_compare_any_realm(context, sprincipal, principal))
	goto out;	/* found a match */

err:
    ret = krb5_unparse_name(context, sprincipal, &expected);
    if (ret)
	goto out;

    ret = KRB5KDC_ERR_SERVER_NOMATCH;
    kx509_log(context, reqctx, 2, "client used wrong kx509 service principal "
              "(expected %s)", expected);

out:
    krb5_xfree(expected);
    krb5_free_principal(context, principal);

    return ret;
}

static krb5_error_code
encode_reply(krb5_context context,
             kx509_req_context reqctx,
             Kx509Response *r)
{
    krb5_error_code ret;
    krb5_data data;
    size_t size;

    reqctx->reply->data = NULL;
    reqctx->reply->length = 0;
    ASN1_MALLOC_ENCODE(Kx509Response, data.data, data.length, r, &size, ret);
    if (ret) {
        kdc_log(context, reqctx->config, 1, "Failed to encode kx509 reply");
        return ret;
    }
    if (size != data.length)
        krb5_abortx(context, "ASN1 internal error");

    ret = krb5_data_alloc(reqctx->reply, data.length + sizeof(version_2_0));
    if (ret == 0) {
        memcpy(reqctx->reply->data, version_2_0, sizeof(version_2_0));
        memcpy(((unsigned char *)reqctx->reply->data) + sizeof(version_2_0),
               data.data, data.length);
    }
    free(data.data);
    return ret;
}

/* Make an error response, and log the error message as well */
static krb5_error_code
mk_error_response(krb5_context context,
                  kx509_req_context reqctx,
                  int32_t code,
                  const char *fmt,
                  ...)
{
    krb5_error_code ret = code;
    krb5_error_code ret2;
    Kx509Response rep;
    const char *msg;
    char *freeme0 = NULL;
    char *freeme1 = NULL;
    va_list ap;

    if (!reqctx->config->enable_kx509)
        code = KRB5KDC_ERR_POLICY;

    /* Make sure we only send RFC4120 and friends wire protocol error codes */
    if (code) {
        if (code == KX509_ERR_NONE) {
            code = 0;
        } else if (code > KX509_ERR_NONE && code <= KX509_ERR_SRV_OVERLOADED) {
            code -= KX509_ERR_NONE;
        } else {
            if (code < KRB5KDC_ERR_NONE || code >= KRB5_ERR_RCSID)
                code = KRB5KRB_ERR_GENERIC;
            code -= KRB5KDC_ERR_NONE;
            code += kx509_krb5_error_base;
        }
    }

    va_start(ap, fmt);
    if (vasprintf(&freeme0, fmt, ap) == -1 || freeme0 == NULL)
        msg = "Could not format error message (out of memory)";
    else
        msg = freeme0;
    va_end(ap);

    if (!reqctx->config->enable_kx509 &&
        asprintf(&freeme1, "kx509 service is disabled (%s)", msg) > -1 &&
        freeme1 != NULL) {
        msg = freeme1;
    }

    kdc_log(context, reqctx->config, 1, "%s", msg);

    rep.hash = NULL;
    rep.certificate = NULL;
    rep.error_code = code;
    if (ALLOC(rep.e_text))
        *rep.e_text = (void *)(uintptr_t)msg;

    if (reqctx->key) {
        if (ALLOC(rep.hash) != NULL &&
            calculate_reply_hash(context, reqctx->key, &rep)) {
            free(rep.hash);
            rep.hash = NULL;
        }
    }

    if ((ret2 = encode_reply(context, reqctx, &rep)))
        ret = ret2;
    if (rep.hash)
        krb5_data_free(rep.hash);
    free(rep.e_text);
    free(rep.hash);
    free(freeme0);
    free(freeme1);
    return ret;
}

/* Wrap a bare public (RSA) key with a CSR (not signed it, since we can't) */
static krb5_error_code
make_csr(krb5_context context, kx509_req_context reqctx, krb5_data *key)
{
    krb5_error_code ret;
    SubjectPublicKeyInfo spki;
    heim_any any;

    ret = hx509_request_init(context->hx509ctx, &reqctx->csr);
    if (ret)
        return ret;

    memset(&spki, 0, sizeof(spki));
    spki.subjectPublicKey.data = key->data;
    spki.subjectPublicKey.length = key->length * 8;

    ret = der_copy_oid(&asn1_oid_id_pkcs1_rsaEncryption,
                       &spki.algorithm.algorithm);

    any.data = "\x05\x00";
    any.length = 2;
    spki.algorithm.parameters = &any;

    if (ret == 0)
        ret = hx509_request_set_SubjectPublicKeyInfo(context->hx509ctx,
                                                     reqctx->csr, &spki);
    der_free_oid(&spki.algorithm.algorithm);
    if (ret)
        hx509_request_free(&reqctx->csr);

    /*
     * TODO: Move a lot of the templating stuff here so we can let clients
     *       leave out extensions they don't want.
     */
    return ret;
}

/* Update a CSR with desired Certificate Extensions */
static krb5_error_code
update_csr(krb5_context context, kx509_req_context reqctx, Extensions *exts)
{
    krb5_error_code ret = 0;
    size_t i, k;

    if (exts == NULL)
        return 0;

    for (i = 0; ret == 0 && i < exts->len; i++) {
        Extension *e = &exts->val[i];

        if (der_heim_oid_cmp(&e->extnID, &asn1_oid_id_x509_ce_keyUsage) == 0) {
            KeyUsage ku;

            ret = decode_KeyUsage(e->extnValue.data, e->extnValue.length, &ku,
                                  NULL);
            if (ret)
                return ret;
            ret = hx509_request_set_ku(context->hx509ctx, reqctx->csr, ku);
        } else if (der_heim_oid_cmp(&e->extnID,
                                    &asn1_oid_id_x509_ce_extKeyUsage) == 0) {
            ExtKeyUsage eku;

            ret = decode_ExtKeyUsage(e->extnValue.data, e->extnValue.length,
                                     &eku, NULL);
            for (k = 0; ret == 0 && k < eku.len; k++) {
                ret = hx509_request_add_eku(context->hx509ctx, reqctx->csr,
                                            &eku.val[k]);
            }
            free_ExtKeyUsage(&eku);
        } else if (der_heim_oid_cmp(&e->extnID,
                                    &asn1_oid_id_x509_ce_subjectAltName) == 0) {
            GeneralNames san;

            ret = decode_GeneralNames(e->extnValue.data, e->extnValue.length,
                                      &san, NULL);
            for (k = 0; ret == 0 && k < san.len; k++) {
                ret = hx509_request_add_GeneralName(context->hx509ctx,
                                                    reqctx->csr, &san.val[k]);
                reqctx->want_sans = 1;
            }
            free_GeneralNames(&san);
        }
    }
    if (ret)
        kx509_log(context, reqctx, 2,
                  "request has bad desired certificate extensions");
    return ret;
}


/*
 * Parse the `pk_key' from the request as a CSR or raw public key, and if the
 * latter, wrap it in a non-signed CSR.
 */
static krb5_error_code
get_csr(krb5_context context, kx509_req_context reqctx)
{
    krb5_error_code ret;
    RSAPublicKey rsapkey;
    heim_octet_string pk_key = reqctx->req->pk_key;
    size_t size;

    ret = decode_Kx509CSRPlus(pk_key.data, pk_key.length, &reqctx->csr_plus,
                              &size);
    if (ret == 0) {
        reqctx->have_csr = 1;
        reqctx->send_chain = 1;
        if (reqctx->csr_plus.authz_datas.len)
            reqctx->have_auth_data = 1;

        /* Parse CSR */
        ret = hx509_request_parse_der(context->hx509ctx, &reqctx->csr_plus.csr,
                                      &reqctx->csr);
        if (ret)
            kx509_log(context, reqctx, 2, "invalid CSR");

        /*
         * Handle any additional Certificate Extensions requested out of band
         * of the CSR.
         */
        if (ret == 0)
            return update_csr(context, reqctx, reqctx->csr_plus.exts);
        return ret;
    }
    reqctx->send_chain = 0;
    reqctx->have_csr = 0;

    /* Check if proof of possession is required by configuration */
    if (!get_bool_param(context, FALSE, reqctx->realm, "require_csr"))
        return mk_error_response(context, reqctx, KX509_STATUS_CLIENT_USE_CSR,
                                 "CSRs required but client did not send one");

    /* Attempt to decode pk_key as RSAPublicKey */
    ret = decode_RSAPublicKey(reqctx->req->pk_key.data,
                              reqctx->req->pk_key.length,
                              &rsapkey, &size);
    free_RSAPublicKey(&rsapkey);
    if (ret == 0 && size == reqctx->req->pk_key.length)
        return make_csr(context, reqctx, &pk_key); /* Make pretend CSR */

    /* Not an RSAPublicKey or garbage follows it */
    if (ret == 0)
        kx509_log(context, reqctx, 2, "request has garbage after key");
    return mk_error_response(context, reqctx, KRB5KDC_ERR_NULL_KEY,
                             "Could not decode CSR or RSA subject public key");
}

/* NB: This is intended only for authz-data from the Authenticator. */
static krb5_error_code
extract_authz_data(krb5_context context,
                   struct kx509_req_context *reqctx,
                   AuthorizationData *ad)
{
    krb5_error_code ret = 0;
    size_t i;

    for (i = 0; ret == 0 && i < ad->len; i++) {
        switch (ad->val[i].ad_type) {
        case KRB5_AUTHDATA_IF_RELEVANT: {
            AuthorizationData ir;

            ret = decode_AuthorizationData(ad->val[i].ad_data.data,
                                           ad->val[i].ad_data.length,
                                           &ir, NULL);

            /* Recurse to extract authz data marked non-critical */
            if (ret == 0)
                ret = extract_authz_data(context, reqctx, &ir);
            free_AuthorizationData(&ir);
            continue;
        }
        case KRB5_AUTHDATA_ON_BEHALF_OF:
            if (reqctx->on_behalf_of == NULL) {
                char *s = NULL;

                ret = der_get_utf8string(ad->val[i].ad_data.data,
                                         ad->val[i].ad_data.length,
                                         &s, NULL);
                if (ret == 0)
                    ret = krb5_parse_name(context, s, &reqctx->on_behalf_of);
            }
            continue;
        case KRB5_AUTHDATA_BEARER_TOKEN_JWT:
            if (!reqctx->token_jwt.length)
                ret = der_copy_octet_string(&ad->val[i].ad_data,
                                            &reqctx->token_jwt);
            continue;
        case KRB5_AUTHDATA_BEARER_TOKEN_SAML:
            if (!reqctx->token_saml.length)
                ret = der_copy_octet_string(&ad->val[i].ad_data,
                                            &reqctx->token_saml);
            continue;
        case KRB5_AUTHDATA_BEARER_TOKEN_OIDC:
            if (!reqctx->token_oidc.length)
                ret = der_copy_octet_string(&ad->val[i].ad_data,
                                            &reqctx->token_oidc);
            continue;
        case KRB5_AUTHDATA_CSR_AUTHORIZED:
            reqctx->clnt_claims_authz = 1;
            continue;
        default:
            /* We've no use for any other authz data here; we ignore it all */
            break;
        }
    }
    return ret;
}

static int
check_is_proxy(krb5_context context,
               struct kx509_req_context *reqctx,
               krb5_principal cprincipal)
{
    krb5_principal proxy_name = NULL;
    const char *kx509_proxy_name;

    if (reqctx->is_proxied)
        return 1;
    if (reqctx->is_not_proxied)
        return 0;

    kx509_proxy_name = krb5_config_get_string(context, NULL, "kdc",
                                              "kx509_proxy_client_service",
                                              NULL);
    if (kx509_proxy_name != NULL &&
        krb5_parse_name(context, kx509_proxy_name, &proxy_name) == 0 &&
        krb5_principal_compare(context, proxy_name, cprincipal)) {
        reqctx->is_proxied = 1;
    } else if (proxy_name) {
        reqctx->is_not_proxied = 1;
    }
    krb5_free_principal(context, proxy_name);
    return reqctx->is_proxied;
}

/* Check impersonation request */
static int
check_impersonation(krb5_context context,
                    struct kx509_req_context *reqctx,
                    krb5_principal cprincipal,
                    krb5_principal *actual_principal)
{
    *actual_principal = NULL;
    if (reqctx->on_behalf_of &&
        check_is_proxy(context, reqctx, cprincipal) &&
        krb5_copy_principal(context, reqctx->on_behalf_of, actual_principal) == 0)
        return 1;

    if (reqctx->on_behalf_of) {
        kx509_log(context, reqctx, 0, "Impersonation request rejected");
        krb5_free_principal(context, reqctx->on_behalf_of);
        reqctx->on_behalf_of = NULL;
    }
    return 0;
}

/*
 * Perform on behalf of bearer token validation.
 *
 * Any bearer tokens will have been sent as authorization data.
 */
static krb5_error_code
verify_auth_data(krb5_context context,
                 struct kx509_req_context *reqctx,
                 krb5_principal cprincipal,
                 krb5_principal *actual_cprincipal)
{
    krb5_authenticator a;
    krb5_error_code ret;
    const char *audiences[] = { "", "*" };
    size_t verified = 0;
    size_t ntokens = 0;
    char *s = NULL;

    if (!check_is_proxy(context, reqctx, cprincipal)) {
        /*
         * If it's not proxied, then we'll ignore the tokens.
         *
         * We can't issue a certificate for a principal authenticated by a
         * bearer token if the Kerberos client principal of this protocol is
         * not a trusted proxy, otherwise any web server could get a
         * certificate for any of their clients!
         */
        reqctx->csr_authorized = 0;
        return krb5_copy_principal(context, cprincipal, actual_cprincipal);
    }

    ret = krb5_auth_con_getauthenticator(context, reqctx->ac, &a);
    if (ret)
        return ret;

    if (a->authorization_data)
        ret = extract_authz_data(context, reqctx, a->authorization_data);
    else
        /* We were told there would be authz data, but there is none */
        ret = EINVAL; /* XXX Need better error? */
    krb5_free_authenticator(context, &a);

    if (check_impersonation(context, reqctx, cprincipal, actual_cprincipal)) {
        /* If authorized to impersonate, then authorized to authorize req */
        reqctx->csr_authorized = reqctx->clnt_claims_authz;
    }

    (void) krb5_unparse_name(context, cprincipal, &s);
    kx509_log(context, reqctx, 0, "untrusted client principal "
              "using bearer tokens: %s", s ? s : "<out of memory>");
    free(s);

    /* If multiple tokens were sent, all must validate (XXX ??) */
    /* XXX Watch for *actual_cprincipal leaking if multiple tokens used */
    /* XXX Maybe allow just one token */
    /*
     * XXX Make audiences configurable for proxied case, and for non-proxied
     * case separately.  For the proxied case we really want to make sure that
     * the audience of a token matches the proxy's name(s).  For the
     * non-proxied case we want to make sure that the audience of the token
     * matches the realm / kx509 service.
     */
    if (ret == 0 && reqctx->token_jwt.length) {
        ntokens++;
        ret = kdc_validate_token(context, reqctx->realm, "Bearer",
                                 &reqctx->token_jwt, audiences,
                                 sizeof(audiences)/sizeof(audiences[0]),
                                 reqctx->on_behalf_of, actual_cprincipal,
                                 &reqctx->token_times);
        verified += (ret == 0) ? 1 : 0;
        if (ret)
            kx509_log(context, reqctx, 0, "JWT token not verified: %s",
                      krb5_get_error_message(context, ret));
        else
            kx509_log(context, reqctx, 0, "JWT token verified");
    }

    if (ret == 0 && reqctx->token_saml.length) {
        ntokens++;
        ret = kdc_validate_token(context, reqctx->realm, "saml",
                                 &reqctx->token_saml, audiences,
                                 sizeof(audiences)/sizeof(audiences[0]),
                                 reqctx->on_behalf_of, actual_cprincipal,
                                 &reqctx->token_times);
        verified += (ret == 0) ? 1 : 0;
        if (ret)
            kx509_log(context, reqctx, 0, "SAML token not verified: %s",
                      krb5_get_error_message(context, ret));
        else
            kx509_log(context, reqctx, 0, "SAML token verified");
    }

    if (ret == 0 && reqctx->token_oidc.length) {
        ntokens++;
        ret = kdc_validate_token(context, reqctx->realm, "oidc",
                                 &reqctx->token_oidc, audiences,
                                 sizeof(audiences)/sizeof(audiences[0]),
                                 reqctx->on_behalf_of, actual_cprincipal,
                                 &reqctx->token_times);
        verified += (ret == 0) ? 1 : 0;
        if (ret)
            kx509_log(context, reqctx, 0, "OIDC token not verified: %s",
                      krb5_get_error_message(context, ret));
        else
            kx509_log(context, reqctx, 0, "OIDC token verified");
    }

    kx509_log(context, reqctx, 0,
              "Number of bearer tokens sent/validated: %llu/%llu",
              (unsigned long long)ntokens, (unsigned long long)verified);

    reqctx->have_tokens = 1;
    if (ntokens == 0 && check_is_proxy(context, reqctx, cprincipal)) {
        if (!reqctx->csr_plus.req_life) {
            kx509_log(context, reqctx, 0, "kx509 request rejected because "
                      "proxy impersonation without desired certificate "
                      "lifetime");
            return EACCES;
        }
        return 0;
    }
    if (ntokens == 0 || verified != ntokens)
        return EACCES;
    return ret;
}

static krb5_error_code
check_authz(krb5_context context,
            kx509_req_context reqctx,
            krb5_principal cprincipal)
{
    krb5_error_code ret;
    const char *comp0 = krb5_principal_get_comp_string(context, cprincipal, 0);
    const char *comp1 = krb5_principal_get_comp_string(context, cprincipal, 1);
    unsigned int ncomp = krb5_principal_get_num_comp(context, cprincipal);
    KeyUsage ku, ku_allowed;
    const heim_oid *eku_whitelist[] = {
        &asn1_oid_id_pkix_kp_serverAuth,
        &asn1_oid_id_pkix_kp_clientAuth,
        &asn1_oid_id_pkekuoid,
        &asn1_oid_id_pkinit_ms_eku
    };
    char *cprinc = NULL;
    char *s = NULL;
    int cursor;

    if (!reqctx->have_csr)
        return 0; /* We'll derive cert contents from client name */
    ret = kdc_authorize_csr(context, reqctx->config, reqctx->csr, cprincipal);
    if (ret == 0) {
        kx509_log(context, reqctx, 0, "Requested extensions authorized "
                  "by plugin");
        return 0;
    }
    if (ret != KRB5_PLUGIN_NO_HANDLE) {
        kx509_log(context, reqctx, 0, "Requested extensions rejected "
                  "by plugin");
        return ret;
    }

    /*
     * Default authorizer.
     *
     *  - Check requested SANs against client principal.
     *    TODO: Add HDB lookup support here.
     *
     *  - Check EKUs.
     *
     *  - Check KU (signature only).
     */

    if ((ret = krb5_unparse_name(context, cprincipal, &cprinc)))
        return ret;

    cursor = 0;
    while ((ret = hx509_request_get_pkinit_san(context->hx509ctx, reqctx->csr,
                                               &s, &cursor)) == 0 && s) {
        if (strcmp(cprinc, s) != 0) {
            kx509_log(context, reqctx, 0, "Requested extensions rejected "
                      "by default policy (PKINIT SAN %s does not match "
                      "client %s)", s, cprinc);
            goto eacces;
        }
        free(s);
        s = NULL;
    }
    if (ret && ret != -1)
        return ret;

    cursor = 0;
    while ((ret = hx509_request_get_xmpp_san(context->hx509ctx, reqctx->csr,
                                             &s, &cursor)) == 0 && s) {
        kx509_log(context, reqctx, 0, "Requested extensions rejected "
                  "by default policy (XMPP SAN not supported)");
        goto eacces;
    }
    if (ret && ret != -1)
        return ret;

    cursor = 0;
    while ((ret = hx509_request_get_email_san(context->hx509ctx, reqctx->csr,
                                              &s, &cursor)) == 0 && s) {
        kx509_log(context, reqctx, 0, "Requested extensions rejected "
                  "by default policy (rfc822Name SAN not supported)");
        goto eacces;
        free(s);
        s = NULL;
    }
    if (ret && ret != -1)
        return ret;

    cursor = 0;
    while ((ret = hx509_request_get_ms_upn_san(context->hx509ctx,
                                             reqctx->csr, &s,
                                             &cursor)) == 0 && s) {
        kx509_log(context, reqctx, 0, "Requested extensions rejected "
                  "by default policy (MSFT UPN SAN not supported)");
        goto eacces;
    }
    if (ret && ret != -1)
        return ret;

    cursor = 0;
    while ((ret = hx509_request_get_dns_name_san(context->hx509ctx,
                                                 reqctx->csr, &s,
                                                 &cursor)) == 0 && s) {
        if (ncomp != 2 || strcasecmp(comp1, s) != 0 ||
            strchr(s, '.') == NULL) {
            kx509_log(context, reqctx, 0, "Requested extensions rejected "
                      "by default policy (dNSName SAN %s does not match "
                      "client %s)", s, cprinc);
            goto eacces;
        }
        if (strcmp(comp0, "HTTP") != 0) {
            kx509_log(context, reqctx, 0, "Requested extensions rejected "
                      "by default policy (hostbased client %s not an "
                      "HTTP service", cprinc);
            goto eacces;
        }
        free(s);
        s = NULL;
    }
    if (ret && ret != -1)
        return ret;

    cursor = 0;
    while ((ret = hx509_request_get_eku(context->hx509ctx,
                                        reqctx->csr, &s,
                                        &cursor)) == 0 && s) {
        heim_oid oid;
        size_t k;

        if ((ret = der_parse_heim_oid(s, ".", &oid))) {
            free(cprinc);
            free(s);
            return ret;
        }
        for (k = 0; k < sizeof(eku_whitelist)/sizeof(eku_whitelist[0]); k++) {
            if (der_heim_oid_cmp(eku_whitelist[k], &oid) == 0)
                break;
        }
        der_free_oid(&oid);
        if (k == sizeof(eku_whitelist)/sizeof(eku_whitelist[0]))
            goto eacces;
        free(s);
        s = NULL;
    }
    if (ret && ret != -1)
        return ret;

    memset(&ku_allowed, 0, sizeof(ku_allowed));
    ku_allowed.digitalSignature = 1;
    ku_allowed.nonRepudiation = 1;
    ret = hx509_request_get_ku(context->hx509ctx, reqctx->csr, &ku);
    if (ret)
        return ret;
    if (KeyUsage2int(ku) != (KeyUsage2int(ku) & KeyUsage2int(ku_allowed)))
        goto eacces;
    
    return 0;

eacces:
    free(cprinc);
    free(s);
    return EACCES;
}

/*
 * Process a request, produce a reply.
 */

krb5_error_code
_kdc_do_kx509(krb5_context context,
	      krb5_kdc_configuration *config,
	      const struct Kx509Request *req, krb5_data *reply,
	      const char *from, struct sockaddr *addr)
{
    krb5_error_code ret = 0;
    krb5_ticket *ticket = NULL;
    krb5_flags ap_req_options;
    krb5_principal actual_cprincipal = NULL;
    krb5_principal cprincipal = NULL;
    krb5_principal sprincipal = NULL;
    krb5_keytab id = NULL;
    Kx509Response rep;
    struct kx509_req_context reqctx;
    int is_probe = 0;

    memset(&reqctx, 0, sizeof(reqctx));
    reqctx.csr_plus.authz_datas.val = NULL;
    reqctx.csr_plus.csr.data = NULL;
    reqctx.csr_plus.exts = NULL;
    reqctx.config = config;
    reqctx.sname = NULL;
    reqctx.cname = NULL;
    reqctx.realm = NULL;
    reqctx.reply = reply;
    reqctx.from = from;
    reqctx.addr = addr;
    reqctx.key = NULL;
    reqctx.csr = NULL;
    reqctx.req = req;
    reqctx.ac = NULL;

    /*
     * In order to support authenticated error messages we defer checking
     * whether the kx509 service is enabled until after accepting the AP-REQ.
     */

    krb5_data_zero(reply);
    memset(&rep, 0, sizeof(rep));


    if (req->authenticator.length == 0) {
        /*
         * Unauthenticated kx509 service availability probe.
         *
         * mk_error_response() will check whether the service is enabled and
         * possibly change the error code and message.
         */
        is_probe = 1;
        kx509_log(context, &reqctx, 4, "unauthenticated probe request");
        ret = mk_error_response(context, &reqctx, KRB5KDC_ERR_NULL_KEY,
                                "kx509 service is available");
        goto out;
    }

    /* Consume the AP-REQ */
    ret = krb5_kt_resolve(context, "HDBGET:", &id);
    if (ret) {
        ret = mk_error_response(context, &reqctx,
                                KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN,
                                "Can't open HDB/keytab for kx509");
	goto out;
    }

    ret = krb5_rd_req(context,
		      &reqctx.ac,
		      &req->authenticator,
		      NULL,
		      id,
		      &ap_req_options,
		      &ticket);
    if (ret == 0)
        ret = krb5_auth_con_getkey(context, reqctx.ac, &reqctx.key);
    if (ret == 0 && reqctx.key == NULL)
	ret = KRB5KDC_ERR_NULL_KEY;
    /*
     * Provided we got the session key, errors past this point will be
     * authenticated.
     */
    if (ret == 0)
        ret = krb5_ticket_get_client(context, ticket, &cprincipal);
    if (ret) {
        ret = mk_error_response(context, &reqctx, ret,
                                "authentication failed");
	goto out;
    }

    /* Optional: check if Ticket is INITIAL */
    if (ret == 0 &&
        !ticket->ticket.flags.initial &&
        !get_bool_param(context, TRUE,
                        krb5_principal_get_realm(context, cprincipal),
                        "require_initial_kca_tickets")) {
        ret = mk_error_response(context, &reqctx, KRB5KDC_ERR_POLICY, /* XXX */
                                "client used non-INITIAL tickets, but kx509"
                                "kx509 service is configured to require "
                                "INITIAL tickets");
        goto out;
    }

    ret = krb5_unparse_name(context, cprincipal, &reqctx.cname);

    /* Check that the service name is a valid kx509 service name */
    if (ret == 0)
        ret = krb5_ticket_get_server(context, ticket, &sprincipal);
    if (ret == 0)
        reqctx.realm = krb5_principal_get_realm(context, sprincipal);
    if (ret == 0)
        ret = krb5_unparse_name(context, sprincipal, &reqctx.sname);
    if (ret == 0)
        ret = kdc_kx509_verify_service_principal(context, &reqctx, sprincipal);
    if (ret) {
        mk_error_response(context, &reqctx, ret,
                          "client used incorrect service name");
	goto out;
    }

    /* Authenticate the rest of the request */
    ret = verify_req_hash(context, req, reqctx.key);
    if (ret) {
        mk_error_response(context, &reqctx, ret, "Incorrect request HMAC");
	goto out;
    }

    if (req->pk_key.length == 0) {
        /*
         * The request is a kx509 service availability probe.
         *
         * mk_error_response() will check whether the service is enabled and
         * possibly change the error code and message.
         */
        is_probe = 1;
        ret = mk_error_response(context, &reqctx, 0,
                                "kx509 authenticated probe request");
	goto out;
    }

    /* Extract and parse CSR or a DER-encoded RSA public key */
    ret = get_csr(context, &reqctx);
    if (ret)
        goto out;

    if (reqctx.have_auth_data) {
        ret = verify_auth_data(context, &reqctx, cprincipal,
                               &actual_cprincipal);
        if (ret) {
            ret = mk_error_response(context, &reqctx, ret,
                                    "authorization data validation failure");
            goto out;
        }
    }

    if (!reqctx.csr_authorized &&
        (ret = check_authz(context, &reqctx, cprincipal))) {
        ret = mk_error_response(context, &reqctx, ret, "rejected by policy");
        goto out;
    }
    reqctx.csr_authorized = 1;

    ALLOC(rep.hash);
    ALLOC(rep.certificate);
    if (rep.certificate == NULL || rep.hash == NULL) {
        ret = mk_error_response(context, &reqctx, ENOMEM,
                                "could allocate memory for response");
        goto out;
    }

    /* Issue the certificate */
    krb5_data_zero(rep.hash);
    krb5_data_zero(rep.certificate);
    krb5_ticket_get_times(context, ticket, &reqctx.ticket_times),
    ret = build_certificate(context, &reqctx,
                            actual_cprincipal ? actual_cprincipal : cprincipal,
                            rep.certificate);
    if (ret) {
        mk_error_response(context, &reqctx, ret, "Failed to build certificate");
        goto out;
    }

    /* Authenticate the response */
    ret = calculate_reply_hash(context, reqctx.key, &rep);
    if (ret) {
        mk_error_response(context, &reqctx, ret,
                          "Failed to compute response HMAC");
	goto out;
    }

    /* Encode and output reply */
    ret = encode_reply(context, &reqctx, &rep);
    if (ret)
        /* Can't send an error message either in this case, surely */
        kx509_log(context, &reqctx, 1, "Could not encode response");

out:
    if (ret == 0 && !is_probe)
        kx509_log(context, &reqctx, 3, "Issued certificate");
    else
        kx509_log(context, &reqctx, 2, "Did not issue certificate");
    if (reqctx.ac)
	krb5_auth_con_free(context, reqctx.ac);
    if (ticket)
	krb5_free_ticket(context, ticket);
    if (id)
	krb5_kt_close(context, id);
    if (sprincipal)
	krb5_free_principal(context, sprincipal);
    if (cprincipal)
	krb5_free_principal(context, cprincipal);
    if (actual_cprincipal)
	krb5_free_principal(context, actual_cprincipal);
    if (reqctx.key)
	krb5_free_keyblock (context, reqctx.key);
    if (reqctx.sname)
	free(reqctx.sname);
    if (reqctx.cname)
	free(reqctx.cname);
    hx509_request_free(&reqctx.csr);
    krb5_free_principal(context, reqctx.on_behalf_of);
    free_Kx509CSRPlus(&reqctx.csr_plus);
    free_Kx509Response(&rep);

    return ret;
}

#endif /* KX509 */
