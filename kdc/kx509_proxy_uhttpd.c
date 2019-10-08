/*
 * Copyright (c) 2019 Kungliga Tekniska Högskolan
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

/*
 * This file implements a RESTful HTTPS API to an online CA, as well as an
 * HTTP/Negotiate token issuer.
 *
 * Users are authenticated with bearer tokens.
 *
 * This is essentially a proxy for the kx509 and PKINIT protocols.
 *
 * To get a key certified:
 *
 *  GET /bx509?csr=<base64-encoded-PKCS#10-CSR>
 *
 * To get an HTTP/Negotiate token:
 *
 *  GET /bnegotiate?target=<acceptor-principal>
 *
 * which, if authorized, produces a Negotiate token (base64-encoded, as
 * expected, with the "Negotiate " prefix, ready to be put in an Authorization:
 * header).
 *
 * TBD:
 *  - rewrite to not use libmicrohttpd but an alternative more appropriate to
 *    Heimdal's license (though libmicrohttpd will do)
 *  - /bx509 should include the certificate chain
 *  - /bx509 should support HTTP/Negotiate
 *  - there should be an end-point for fetching an issuer's chain
 *  - maybe add /bkrb5 which returns a KRB-CRED with the user's TGT
 */

#define _XOPEN_SOURCE_EXTENDED  1
#define _DEFAULT_SOURCE  1
#define _BSD_SOURCE  1
#define _GNU_SOURCE  1

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <microhttpd.h>
#include "kdc_locl.h"
#include "token_validator_plugin.h"
#include <roken.h>
#include <krb5.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <hx509.h>
#include "../lib/hx509/hx_locl.h"
#include <hx509-private.h>

static krb5_kdc_configuration *kdc_config;
static pthread_key_t k5ctx;

static krb5_error_code
get_krb5_context(krb5_context *contextp)
{
    int ret;

    if ((*contextp = pthread_getspecific(k5ctx)))
        return 0;
    if ((ret = krb5_init_context(contextp)))
        return ret;
    (void) pthread_setspecific(k5ctx, *contextp);
    return 0;
}

static int port = -1;
static int help_flag;
static int daemonize;
static int daemon_child_fd = -1;
static int verbose_flag;
static int version_flag;
static int reverse_proxied_flag;
static int thread_per_client_flag;
static const char *cert_file;
static const char *priv_key_file;
static const char *cache_dir;
static char *impersonation_key_fn;

static int
validate_token(struct MHD_Connection *connection,
               char **cprinc_from_token)
{
    krb5_principal actual_cprinc = NULL;
    krb5_context context;
    const char *token;
    char token_type[64]; /* Plenty */
    krb5_data tok;
    size_t brk;
    int ret;

    ret = get_krb5_context(&context);
    if (ret)
        return ret;

    token = MHD_lookup_connection_value(connection, MHD_HEADER_KIND,
                                        "Authorization");
    if (token == NULL)
        return EINVAL;
    brk = strcspn(token, " \t");
    if (token[brk] == '\0' || brk > sizeof(token_type) - 1)
        return EINVAL;
    memcpy(token_type, token, brk);
    token_type[brk] = '\0';
    token += brk + 1;
    tok.length = strlen(token);
    tok.data = (void *)(uintptr_t)token;

    ret = kdc_validate_token(context, NULL /* XXX realm */,
                             token_type, &tok, NULL, &actual_cprinc);
    if (ret) {
        /* XXX Log message */
        return ret;
    }
    if (actual_cprinc) {
        ret = krb5_unparse_name(context, actual_cprinc,
                                cprinc_from_token);
        krb5_free_principal(context, actual_cprinc);
    }
    return ret;
}

static void
generate_key(hx509_context context,
             const char *key_name,
             const char *gen_type,
             unsigned long gen_bits,
             char **fn)
{
    struct hx509_generate_private_context *key_gen_ctx = NULL;
    hx509_private_key key = NULL;
    hx509_certs certs = NULL;
    hx509_cert cert = NULL;
    int ret;

    if (strcmp(gen_type, "rsa"))
        errx(1, "Only RSA keys are supported at this time");

    if (asprintf(fn, "PEM-FILE:%s/.%s_priv_key.pem",
                 cache_dir, key_name) == -1 ||
        *fn == NULL)
        err(1, "Could not setup private key for %s", key_name);

    ret = _hx509_generate_private_key_init(context,
                                           ASN1_OID_ID_PKCS1_RSAENCRYPTION,
                                           &key_gen_ctx);
    if (ret == 0)
        ret = _hx509_generate_private_key_bits(context, key_gen_ctx, gen_bits);
    if (ret == 0)
        ret = _hx509_generate_private_key(context, key_gen_ctx, &key);
    if (ret == 0)
        cert = hx509_cert_init_private_key(context,
                                           _hx509_private_key_ref(key), NULL);
    if (ret == 0)
        ret = hx509_certs_init(context, *fn,
                               HX509_CERTS_CREATE | HX509_CERTS_UNPROTECT_ALL,
                               NULL, &certs);
    if (ret == 0)
        ret = hx509_certs_add(context, certs, cert);
    if (ret == 0)
        ret = hx509_certs_store(context, certs, 0, NULL);
    if (ret)
        hx509_err(context, 1, ret, "Could not generate and save private key "
                  "for %s", key_name);

    _hx509_generate_private_key_free(&key_gen_ctx);
    if (certs)
        hx509_certs_free(&certs);
    if (cert)
        hx509_cert_free(cert);
}

static void
k5_free_context(void *ctx)
{
    krb5_free_context(ctx);
}

#ifndef HAVE_UNLINKAT
static int
unlink1file(const char *dname, const char *name)
{
    char p[PATH_MAX];

    if (strlcpy(p, dname, sizeof(p)) < sizeof(p) &&
        strlcat(p, "/", sizeof(p)) < sizeof(p) &&
        strlcat(p, name, sizeof(p)) < sizeof(p))
        return unlink(p);
    return ERANGE;
}
#endif

static void
rm_cache_dir(void)
{
    struct dirent *e;
    DIR *d;

    /*
     * This works, but not on Win32:
     *
     *  (void) simple_execlp("rm", "rm", "-rf", cache_dir, NULL);
     *
     * We make no directories in `cache_dir', so we need not recurse.
     */
    if ((d = opendir(cache_dir)) == NULL)
        return;

    while ((e = readdir(d))) {
#ifdef HAVE_UNLINKAT
        /*
         * Because unlinkat() takes a directory FD, implementing one for
         * libroken is tricky at best.  Instead we might want to implement an
         * rm_dash_rf() function in lib/roken.
         */
        (void) unlinkat(dirfd(d), e->d_name, 0);
#else
        (void) unlink1file(cache_dir, e->d_name);
#endif
    }
    (void) rmdir(cache_dir);
}

static krb5_error_code
mk_pkix_store(const char *princ, char **pkix_store)
{
    char *s = NULL;
    int ret = ENOMEM;
    int fd;

    *pkix_store = NULL;
    if (asprintf(&s, "PEM-FILE:%s/pkix-XXXXXX.pem", cache_dir) == -1 ||
        s == NULL) {
        free(s);
        return ret;
    }
    *strrchr(s, '.') = '\0';
    /*
     * This way of using mkstemp() isn't safer than mktemp(), but we want to
     * quiet the warning that we'd get if we used mktemp().
     */
    if ((fd = mkstemp(s + sizeof("PEM-FILE:") - 1)) == -1) {
        free(s);
        return errno;
    }
    (void) close(fd);
    s[strlen(s)] = '.';
    *pkix_store = s;
    return 0;
}

static int
resp(struct MHD_Connection *connection,
     int http_status_code,
     enum MHD_ResponseMemoryMode rmmode,
     const void *body,
     size_t bodylen)
{
    struct MHD_Response *response;
    int ret;

    response = MHD_create_response_from_buffer(bodylen, rk_UNCONST(body),
                                               rmmode);
    if (response == NULL)
        return MHD_NO;
    ret = MHD_queue_response(connection, http_status_code, response);
    MHD_destroy_response(response);
    return ret;
}

/* Kerberos API or system error */
static int
bar_req(struct MHD_Connection *connection,
        int ret,
        int http_status_code,
        const char *reason)
{
    if (ret == ENOMEM)
        return resp(connection, http_status_code, MHD_RESPMEM_PERSISTENT,
                    reason, strlen(reason));
    /* XXX Format a message for `ret' along with `reason' */
    return resp(connection, http_status_code, MHD_RESPMEM_MUST_COPY,
                reason, strlen(reason));
}

static int
bad_req(struct MHD_Connection *connection,
        int ret,
        int http_status_code,
        const char *reason)
{
    if (ret == ENOMEM)
        return resp(connection, http_status_code, MHD_RESPMEM_PERSISTENT,
                    reason, strlen(reason));
    /* XXX Format a message for `ret' along with `reason' */
    return resp(connection, http_status_code, MHD_RESPMEM_MUST_COPY,
                reason, strlen(reason));
}

static int
good_bx509(struct MHD_Connection *connection,
           const char *pkix_store)
{
    size_t bodylen;
    void *body;
    int ret;

    ret = rk_undumpdata(strchr(pkix_store, ':') + 1, &body, &bodylen);
    if (ret)
        return bar_req(connection, ret, 503,
                             "Could not recover certificate from PKIX store");

    ret = resp(connection, MHD_HTTP_OK, MHD_RESPMEM_MUST_COPY, body, bodylen);
    free(body);
    return ret;
}

struct bx509_param_handler_arg {
    krb5_context context;
    krb5_kx509_req_ctx kx509ctx;
    krb5_error_code ret;
};

static int
bx509_param_cb(void *d,
               enum MHD_ValueKind kind,
               const char *key,
               const char *val)
{
    struct bx509_param_handler_arg *a = d;

    if (strcmp(key, "eku") == 0 && val)
        a->ret = krb5_kx509_ctx_add_eku(a->context, a->kx509ctx, val);
    else if (strcmp(key, "dNSName") == 0 && val)
        a->ret = krb5_kx509_ctx_add_san_dns_name(a->context, a->kx509ctx, val);
    else if (strcmp(key, "rfc822Name") == 0 && val)
        a->ret = krb5_kx509_ctx_add_san_rfc822Name(a->context, a->kx509ctx,
                                                   val);
    else if (strcmp(key, "xMPPName") == 0 && val)
        a->ret = krb5_kx509_ctx_add_san_xmpp(a->context, a->kx509ctx, val);
    else if (strcmp(key, "krb5PrincipalName") == 0 && val)
        a->ret = krb5_kx509_ctx_add_san_pkinit(a->context, a->kx509ctx, val);
    else if (strcmp(key, "ms-upn") == 0 && val)
        a->ret = krb5_kx509_ctx_add_san_ms_upn(a->context, a->kx509ctx, val);
    else if (strcmp(key, "registeredID") == 0 && val)
        a->ret = krb5_kx509_ctx_add_san_registeredID(a->context, a->kx509ctx,
                                                     val);
    else if (strcmp(key, "csr") == 0 && val)
        a->ret = 0; /* Handled upstairs */
    else if (strcmp(key, "for") == 0 && val)
        a->ret = 0; /* Handled upstairs */

    return a->ret ? MHD_NO : MHD_YES;
}

/* Setup a kx509 request context */
static int
setup_kx509_req(krb5_context context,
                struct MHD_Connection *connection,
                krb5_kx509_req_ctx kx509ctx,
                const char *realm,
                const char *token,
                const char *csr,
                const char *princ,
                char **pkix_store)
{
    struct bx509_param_handler_arg bx509_param_cbdata;
    krb5_error_code ret = 0;

    *pkix_store = NULL;

    if (realm &&
        (ret = krb5_kx509_ctx_set_realm(context, kx509ctx, realm)))
        return bad_req(connection, ENOMEM, 503, "Out of memory");

    bx509_param_cbdata.kx509ctx = kx509ctx;
    bx509_param_cbdata.context = context;
    bx509_param_cbdata.ret = 0;

    /* Set CSR */
    if (csr) {
        krb5_data binary_csr;
        if ((binary_csr.data = malloc(strlen(csr))) == NULL)
            return bad_req(connection, ENOMEM, 503, "Out of memory");
        binary_csr.length = rk_base64_decode(csr, binary_csr.data);

        ret = krb5_kx509_ctx_set_csr_der(context, kx509ctx, &binary_csr);
        free(binary_csr.data);
    } else {
        /*
         * Else use a single priv key to avoid having to generate one here.
         *
         * This is for the /bnegotiate end-point only.  This path
         * makes no sense of the /bx509 end-point.
         */
        ret = krb5_kx509_ctx_set_key(context, kx509ctx, impersonation_key_fn);
    }

    /*
     * Set token as authz-data in the AP-REQ's Authenticator (to protect the
     * token's confidentiality).  Note that it's the KDC/kx509 server that must
     * validate the token, though we could as well (thus giving us the ability
     * to extract the principal name from it instead of requiring it as a query
     * parameter).
     */
    if (ret == 0) {
        krb5_data tok;

        tok.data = rk_UNCONST(token);
        tok.length = strlen(token);
        ret = krb5_kx509_ctx_add_auth_data(context, kx509ctx,
                                           KRB5_AUTHDATA_BEARER_TOKEN_JWT,
                                           &tok);
        if (ret)
            return bad_req(connection, ret, 503, "Out of memory");
    }

    /* Set the given principal name as authz-data too */
    if (ret == 0 && princ) {
        krb5_data p;

        /*
         * XXX We should extract a principal name from the token if we don't
         * have a principal name given to us as a query parameter.
         *
         * Until we do, clients must tell us.
         */
        p.data = rk_UNCONST(princ);
        p.length = strlen(princ);
        ret = krb5_kx509_ctx_add_auth_data(context, kx509ctx,
                                           KRB5_AUTHDATA_ON_BEHALF_OF, &p);
        if (ret)
            return bad_req(connection, ret, 503, "Out of memory");
    }

    /* Setup kx509 options (desired EKUs and SANs) from query parameters */
    (void) MHD_get_connection_values(connection, MHD_GET_ARGUMENT_KIND,
                                     bx509_param_cb, &bx509_param_cbdata);
    if (bx509_param_cbdata.ret == ENOMEM)
        return bad_req(connection, ret, 503, "Out of memory");
    if (bx509_param_cbdata.ret)
        return bad_req(connection, ret, 400, "Malformed request");

    /* Setup PKIX store */
    if ((ret = mk_pkix_store(princ, pkix_store)))
        return bad_req(connection, ret, 503, "Could not create cache");

    /* Let the caller do the rest */
    return MHD_YES;
}

/* Implements GETs of /bx509 */
static int
bx509(struct MHD_Connection *connection, const char *realm)
{
    krb5_error_code ret;
    krb5_context context;
    krb5_kx509_req_ctx kx509ctx = NULL;
    const char *token;
    const char *csr;
    char *cprinc_from_token = NULL;
    char *pkix_store = NULL;
    int mret = MHD_YES;

    /* Get required inputs */
    token = MHD_lookup_connection_value(connection, MHD_HEADER_KIND,
                                        "Authorization");
    if (token == NULL)
        return bad_req(connection, 0, MHD_HTTP_UNAUTHORIZED,
                       "Authorization token is missing");
    if (strncasecmp(token, "Bearer ", sizeof("Bearer ") - 1) == 0)
        token += sizeof("Bearer ") - 1;
    csr = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND,
                                      "csr");
    if (csr == NULL)
        return bad_req(connection, 0, MHD_HTTP_BAD_REQUEST, "CSR is missing");

    if (realm == NULL) {
        realm = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND,
                                            "realm");
        if (realm == NULL)
            return bad_req(connection, 0, MHD_HTTP_BAD_REQUEST, "Realm is missing");
    }

    if ((ret = validate_token(connection, &cprinc_from_token)))
        return bad_req(connection, 0, MHD_HTTP_BAD_REQUEST,
                       "Could not validate token or extract "
                       "principal name");

    if ((ret = get_krb5_context(&context))) {
        mret = bad_req(connection, ret, MHD_HTTP_SERVICE_UNAVAILABLE,
                       "Could not initialize Kerberos library");
        goto out;
    }

    /* Prep to proxy kx509 request */
    if ((ret = krb5_kx509_ctx_init(context, &kx509ctx))) {
        mret = bad_req(connection, ret, MHD_HTTP_SERVICE_UNAVAILABLE,
                       "Could not initialize Kerberos library");
        goto out;
    }
    /* Load all relevant query parameters into kx509 request context */
    if ((mret = setup_kx509_req(context, connection, kx509ctx, realm, token,
                                csr, cprinc_from_token,
                                &pkix_store)) == MHD_NO ||
        pkix_store == NULL)
        goto out; /* setup_kx509_req() will have called bad_req() */
    /* Run the kx509 protocol */
    if ((ret = krb5_kx509_ext(context, kx509ctx,
                              NULL /* default ccache */,
                              pkix_store, NULL)))
        mret = bad_req(connection, ret, 403, /* XXX */
                       "Could not acquire PKIX credentials using kx509");
    /* Read and send the contents of the PKIX store */
    if (ret == 0)
        mret = good_bx509(connection, pkix_store);

out:
    krb5_kx509_ctx_free(context, &kx509ctx);
    if (pkix_store)
        (void) unlink(strchr(pkix_store, ':') + 1);
    free(cprinc_from_token);
    free(pkix_store);
    return mret;
}

/*
 * princ_fs_encode_sz() and princ_fs_encode() encode a principal name to be
 * safe for use as a file name.  They function very much like URL encoders, but
 * '~' and '.' also get encoded, and '@' does not.
 *
 * A corresponding decoder is not needed.
 */
static size_t
princ_fs_encode_sz(const char *in)
{
    size_t sz = strlen(in);

    while (*in) {
        char c = *(in++);

        if (isalnum(c))
            continue;
        switch (c) {
        case '@':
        case '-':
        case '_':
            continue;
        default:
            sz += 2;
        }
    }
    return sz;
}

static char *
princ_fs_encode(const char *in)
{
    size_t len = strlen(in);
    size_t sz = princ_fs_encode_sz(in);
    size_t i, k;
    char *s;

    if ((s = malloc(sz + 1)) == NULL)
        return NULL;
    s[sz] = '\0';

    for (i = k = 0; i < len; i++) {
        char c = in[i];

        switch (c) {
        case '@':
        case '-':
        case '_':
            s[k++] = c;
            break;
        default:
            if (isalnum(c)) {
                s[k++] = c;
            } else  {
                s[k++] = '%';
                s[k++] = "0123456789abcdef"[(c&0xff)>>4];
                s[k++] = "0123456789abcdef"[(c&0x0f)];
            }
        }
    }
    return s;
}


/*
 * Find an existing, live ccache for `princ' in `cache_dir' or acquire Kebreros
 * creds for `princ' with PKINIT and put them in a ccache in `cache_dir'.
 */
static krb5_error_code
find_ccache(krb5_context context, const char *princ, char **ccname)
{
    krb5_error_code ret = ENOMEM;
    krb5_ccache cc = NULL;
    time_t life;
    char *s = NULL;

    *ccname = NULL;

    /*
     * Name the ccache after the principal.  The principal may have special
     * characters in it, such as / or \ (path component separarot), or shell
     * special characters, so princ_fs_encode() it to make a ccache name.
     */
    if ((s = princ_fs_encode(princ)) == NULL ||
        asprintf(ccname, "FILE:%s/%s.cc", cache_dir, s) == -1 ||
        *ccname == NULL)
        return ENOMEM;
    free(s);

    if ((ret = krb5_cc_resolve(context, *ccname, &cc))) {
        /* krb5_cc_resolve() suceeds even if the file doesn't exist */
        free(*ccname);
        *ccname = NULL;
        cc = NULL;
    }

    /* Check if we have a good enough credential */
    if (ret == 0 &&
        (ret = krb5_cc_get_lifetime(context, cc, &life)) == 0 && life > 60)
        return 0;
    if (cc)
        krb5_cc_close(context, cc);
    return ret;
}

/*
 * Acquire credentials for `princ' using PKINIT and the PKIX credentials in
 * `pkix_store', then place the result in the ccache named `ccname' (which will
 * be in our own private `cache_dir').
 *
 * This function could be rewritten using gss_acquire_cred_from() and
 * gss_store_cred_into() provided we add new generic cred store key/value pairs
 * for PKINIT.
 */
static krb5_error_code
do_pkinit(krb5_context context,
          krb5_kx509_req_ctx kx509ctx,
          const char *princ,
          const char *pkix_store,
          const char *ccname)
{
    krb5_get_init_creds_opt *opt = NULL;
    krb5_init_creds_context ctx = NULL;
    krb5_error_code ret = ENOMEM;
    krb5_ccache temp_cc = NULL;
    krb5_ccache cc = NULL;
    krb5_principal p = NULL;
    time_t life;
    const char *crealm;
    char *temp_ccname = NULL;
    int fd = -1;

    if ((ret = krb5_cc_resolve(context, ccname, &cc)))
        return ret;

    /*
     * Avoid nasty race conditions and ccache file corruption, take an flock on
     * temp_ccname and do the cleanup dance.
     */
    if (asprintf(&temp_ccname, "%s.ccnew", ccname) == -1 ||
        temp_ccname == NULL)
        ret = ENOMEM;
    if (ret == 0 &&
        (fd = open(temp_ccname + sizeof("FILE:") - 1,
                   O_RDWR | O_CREAT, 0600)) == -1)
        ret = errno;
    if (ret == 0 && flock(fd, LOCK_EX) == -1)
        ret = errno;
    if (ret == 0)
        ret = krb5_cc_resolve(context, temp_ccname, &temp_cc);

    /* Check if we lost any race to acquire Kerberos creds */
    if (ret == 0)
        ret = krb5_cc_get_lifetime(context, cc, &life);
    if (ret == 0 && life > 60)
        goto out; /* We lost the race, we get to do less work */

    /*
     * We won the race.  Setup to acquire Kerberos creds with PKINIT.
     *
     * We should really make sure that gss_acquire_cred_from() can do this for
     * us.  We'd add generic cred store key/value pairs for PKIX cred store,
     * trust anchors, and so on, and acquire that way, then
     * gss_store_cred_into() to save it in a FILE ccache.
     */
    ret = krb5_parse_name(context, princ, &p);
    if (ret == 0)
        crealm = krb5_principal_get_realm(context, p);
    if (ret == 0 &&
        (ret = krb5_parse_name(context, princ, &p)) == 0 &&
        (ret = krb5_cc_initialize(context, temp_cc, p)) == 0 &&
        (ret = krb5_get_init_creds_opt_alloc(context, &opt)) == 0)
        krb5_get_init_creds_opt_set_default_flags(context, "kinit", crealm,
                                                  opt);
    if (ret == 0 &&
        (ret = krb5_get_init_creds_opt_set_addressless(context,
                                                       opt, 1)) == 0)
        ret = krb5_get_init_creds_opt_set_pkinit(context, opt, p, pkix_store,
                                                 NULL,  /* XXX pkinit_anchor */
                                                 NULL,  /* XXX anchor_chain */
                                                 NULL,  /* XXX pkinit_crl */
                                                 0,     /* flags */
                                                 NULL,  /* prompter */
                                                 NULL,  /* prompter data */
                                                 NULL   /* password */);
    if (ret == 0)
        ret = krb5_init_creds_init(context, p,
                                   NULL /* prompter */,
                                   NULL /* prompter data */,
                                   0 /* start_time */,
                                   opt, &ctx);

    /*
     * Finally, do the AS exchange w/ PKINIT, extract the new Kerberos creds
     * into temp_cc, and rename into place.
     */
    if (ret == 0 &&
        (ret = krb5_init_creds_get(context, ctx)) == 0 &&
        (ret = krb5_init_creds_store(context, ctx, temp_cc)) == 0 &&
        (ret = krb5_cc_move(context, temp_cc, cc)) == 0)
        temp_cc = NULL;

out:
    if (ctx)
        krb5_init_creds_free(context, ctx);
    krb5_get_init_creds_opt_free(context, opt);
    krb5_free_principal(context, p);
    if (temp_cc)
        krb5_cc_close(context, temp_cc);
    if (cc)
        krb5_cc_close(context, cc);
    if (fd != -1)
        (void) close(fd); /* Drops the flock */
    return ret;
}

/* Get impersonated Kerberos credentials for `cprinc' */
static int
bnegotiate_get_creds(struct MHD_Connection *connection,
                     const char *realm,
                     const char *token,
                     const char *cprinc,
                     char **ccname)
{
    krb5_error_code ret;
    krb5_context context;
    krb5_kx509_req_ctx kx509ctx = NULL;
    char *pkix_store = NULL;
    int mret = MHD_YES;

    *ccname = NULL;

    if ((ret = get_krb5_context(&context)))
        return bad_req(connection, ret, MHD_HTTP_SERVICE_UNAVAILABLE,
                       "Could not initialize Kerberos library");

    /* If we have a live ccache for `cprinc', we're done */
    if ((ret = find_ccache(context, cprinc, ccname)) == 0)
        return MHD_YES;

    /*
     * Else we have to acquire a credential for them using their bearer token
     * for authentication (and our keytab / initiator credentials perhaps).
     */
    if ((ret = krb5_kx509_ctx_init(context, &kx509ctx)))
        return bad_req(connection, ret, MHD_HTTP_SERVICE_UNAVAILABLE,
                       "Could not initialize Kerberos library");
    if ((mret = setup_kx509_req(context, connection, kx509ctx, realm, token,
                                NULL, cprinc, &pkix_store)) == MHD_NO)
        mret = bad_req(connection, ret, MHD_HTTP_SERVICE_UNAVAILABLE,
                       "Could not setup kx509 context");

    if (ret == 0 &&
        (ret = krb5_kx509_ext(context, kx509ctx, NULL, pkix_store, NULL)))
        mret = bad_req(connection, ret, 403, /* XXX */
                       "Could not acquire PKIX credentials w/ kx509");

    if (ret == 0 &&
        (ret = do_pkinit(context, kx509ctx, cprinc, pkix_store, *ccname)))
        mret = bad_req(connection, ret, 403, /* XXX */
                       "Could not acquire Kerberos credentials w/ PKINIT");

    krb5_kx509_ctx_free(context, &kx509ctx);
    free(pkix_store);
    return mret;
}

/* GSS-API error */
static int
bad_req_gss(struct MHD_Connection *connection,
            OM_uint32 major,
            OM_uint32 minor,
            int http_status_code,
            const char *reason)
{
    /* XXX gss_display_status()... */
    return resp(connection, http_status_code, MHD_RESPMEM_PERSISTENT,
                reason, strlen(reason));
}

static gss_OID
get_name_type(struct MHD_Connection *connection)
{
    const char *nt;

    nt = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND,
                                     "nametype");
    if (nt == NULL || strcmp(nt, "hostbased-service") == 0)
        return GSS_C_NT_HOSTBASED_SERVICE;
    if (strcmp(nt, "exported-name") == 0)
        return GSS_C_NT_EXPORT_NAME;
    if (strcmp(nt, "krb5") == 0)
        return GSS_KRB5_NT_PRINCIPAL_NAME;
    return GSS_C_NO_OID;
}

/* Make an HTTP/Negotiate token */
static int
bnegotiate_core(struct MHD_Connection *connection,
                const char *realm,
                const char *cprinc,
                const char *target,
                const char *ccname)
{
    gss_key_value_element_desc kv[1];
    gss_key_value_set_desc store = { 1, kv };
    gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc name = GSS_C_EMPTY_BUFFER;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_name_t iname = GSS_C_NO_NAME;
    gss_name_t aname = GSS_C_NO_NAME;
    OM_uint32 major, minor, junk;
    gss_OID nt;
    char *negotiate_token = NULL;
    char *token_b64 = NULL;
    int ret;

    if ((nt = get_name_type(connection)) == GSS_C_NO_OID)
        return bad_req(connection, EINVAL, MHD_HTTP_BAD_REQUEST,
                       "unknown GSS name type in request");

    /* Import initiator name */
    name.length = strlen(cprinc);
    name.value = rk_UNCONST(cprinc);
    major = gss_import_name(&minor, &name, GSS_KRB5_NT_PRINCIPAL_NAME, &iname);
    if (major != GSS_S_COMPLETE)
        return bad_req_gss(connection, major, minor,
                           MHD_HTTP_SERVICE_UNAVAILABLE,
                           "Could not import cprinc parameter value as "
                           "Kerberos principal name");

    /* Import target acceptor name */
    name.length = strlen(target);
    name.value = rk_UNCONST(target);
    major = gss_import_name(&minor, &name, nt, &aname);
    if (major != GSS_S_COMPLETE) {
        (void) gss_release_name(&junk, &iname);
        return bad_req_gss(connection, major, minor,
                           MHD_HTTP_SERVICE_UNAVAILABLE,
                           "Could not import target parameter value as "
                           "Kerberos principal name");
    }

    /* Acquire a credential from the given ccache */
    kv[0].key = "ccache";
    kv[0].value = ccname;
    store.count = 1;
    store.elements = kv;
    major = gss_add_cred_from(&minor, cred, iname, GSS_KRB5_MECHANISM,
                              GSS_C_INITIATE, GSS_C_INDEFINITE, 0, &store,
                              &cred, NULL, NULL, NULL);
    (void) gss_release_name(&junk, &iname);
    if (major != GSS_S_COMPLETE) {
        (void) gss_release_name(&junk, &aname);
        return bad_req_gss(connection, major, minor, MHD_HTTP_FORBIDDEN,
                           "Could not acquire credentials for requested "
                           "cprinc");
    }

    if (major == GSS_S_COMPLETE)
        major = gss_init_sec_context(&minor, cred, &ctx, aname,
                                     GSS_KRB5_MECHANISM, 0, GSS_C_INDEFINITE,
                                     NULL, GSS_C_NO_BUFFER, NULL, &token, NULL,
                                     NULL);
    (void) gss_release_name(&junk, &aname);
    (void) gss_release_cred(&junk, &cred);
    if (major != GSS_S_COMPLETE)
        return bad_req_gss(connection, major, minor,
                           MHD_HTTP_SERVICE_UNAVAILABLE,
                           "Could not acquire Negotiate token for requested "
                           "target");

    /* XXX encode token, output */
    ret = rk_base64_encode(token.value, token.length, &token_b64);
    (void) gss_release_buffer(&junk, &token);
    if (ret > 0)
        ret = asprintf(&negotiate_token, "Negotiate %s", token_b64);
    free(token_b64);
    if (ret < 0 || negotiate_token == NULL)
        return bad_req(connection, errno, MHD_HTTP_SERVICE_UNAVAILABLE,
                       "Could not allocate memory for encoding Negotiate "
                       "token");

    /*
     * XXX Move the call to resp() upstairs, outputting the token instead, as
     * this will allow us to:
     *
     * TODO Add support for this as a redirect with the token as an
     * Authorization: header in the 3xx.  For this we needa query param
     * indicating the URI to redirect to, and maybe a param to influence the
     * choice of particular 3xx.
     */
    ret = resp(connection, MHD_HTTP_OK, MHD_RESPMEM_MUST_COPY, negotiate_token,
               ret /* Already set to the number of bytes by asprintf() */);
    free(negotiate_token);
    return ret;
}

/* Implements /bnegotiate end-point */
static int
bnegotiate(struct MHD_Connection *connection, const char *realm)
{
    const char *target;
    const char *token;
    char *cprinc_from_token = NULL;
    char *ccname;
    int mret;
    int ret;

    token = MHD_lookup_connection_value(connection, MHD_HEADER_KIND,
                                        "Authorization");
    if (token == NULL)
        return bad_req(connection, 0, MHD_HTTP_UNAUTHORIZED,
                       "Authorization token is missing");
    if (strncasecmp(token, "Bearer ", sizeof("Bearer ") - 1) == 0)
        token += sizeof("Bearer ") - 1;
    target = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND,
                                         "target");
    if (target == NULL)
        return bad_req(connection, 0, MHD_HTTP_BAD_REQUEST,
                       "Query missing 'target' parameter value");

    if ((ret = validate_token(connection, &cprinc_from_token)))
        return bad_req(connection, 0, MHD_HTTP_BAD_REQUEST,
                       "Could not validate token or extract "
                       "principal name");

    /*
     * Make sure we have Kerberos credentials for cprinc.  If we have them
     * cached from earlier, this will be fast (all local), else it will involve
     * taking a file lock and talking to the KDC using kx509 and PKINIT.
     *
     * Perhaps we could use S4U instead, which would speed up the slow path a
     * bit.
     */
    mret = bnegotiate_get_creds(connection, realm, token, cprinc_from_token,
                                &ccname);

    /* Acquire the Negotiate token and output it */
    if (mret == MHD_YES && ccname != NULL)
        mret = bnegotiate_core(connection, realm, cprinc_from_token, target,
                               ccname);

    free(cprinc_from_token);
    free(ccname);
    return mret;
}

/* Implements the entirety of this REST service */
static int
route(void *cls,
      struct MHD_Connection *connection,
      const char *url,
      const char *method,
      const char *version,
      const char *upload_data,
      size_t *upload_data_size,
      void **ctx)
{
    static int aptr = 0;

    if (0 != strcmp(method, "GET"))
        return MHD_NO;              /* unexpected method */
    if (*ctx == NULL) {
        /*
         * This is the first call, right after headers were read.
         *
         * We must return quickly so that any 100-Continue might be sent with
         * celerity.
         *
         * We'll get called again to really do the processing.  If we handled
         * POSTs then we'd also get called with upload_data != NULL between the
         * first and last calls.  We need to keep no state between the first
         * and last calls, but we do need to distinguish first and last call,
         * so we use the ctx argument for this.
         */
        *ctx = &aptr;
        return MHD_YES;
    }
    if (strcmp(url, "/bx509") == 0)
        return bx509(connection, cls);
    if (strcmp(url, "/bnegotiate") == 0)
        return bnegotiate(connection, cls);
    return bad_req(connection, 0, MHD_HTTP_NOT_FOUND,
                   "No such resource");
}

static struct getargs args[] = {
    { "help", 'h', arg_flag, &help_flag, "help", "show usage message" },
    { "version", 'h', arg_flag, &version_flag, "version", "show version message" },
    { "daemon", 'd', arg_flag, &daemonize, "daemonize", "daemonize" },
    { "daemon-child", 0, arg_flag, &daemon_child_fd, NULL, NULL }, /* priv */
    { "reverse-proxied", 0, arg_flag, &reverse_proxied_flag,
        "reverse proxied", "listen on 127.0.0.1 and do not use TLS" },
    { "port", 'p', arg_integer, &port, "port", "port number (default: 443)" },
    { "cache-dir", 0, arg_string, &cache_dir,
        "cache directory", "cache directory" },
    { "cert", 0, arg_string, &cert_file,
        "certificate", "certificate file path (PEM)" },
    { "private-key", 0, arg_string, &priv_key_file,
        "private key", "private key file path (PEM)" },
    { "thread-per-client", 't', arg_flag, &thread_per_client_flag,
        "thread per-client", "use thread per-client" },
    { "verbose", 'v', arg_flag, &verbose_flag, "verbose", "run verbosely" }
};

static int
usage(int e)
{
    arg_printusage(args, sizeof(args) / sizeof(args[0]), "bx509",
        "\nServes RESTful GETs of /bx509, /bnegotiate, /kx509, and /bkrb5\n"
        "performing corresponding kx509 and, possibly, PKINIT requests\n"
        "to the KDCs of the requested realms (or just the given REALM).\n");
    exit(e);
}

static int sigpipe[2] = { -1, -1 };

static void
sighandler(int sig)
{
    char c = sig;
    while (write(sigpipe[1], &c, sizeof(c)) == -1 && errno == EINTR)
        ;
}

int
main(int argc, char **argv)
{
    unsigned int flags = MHD_USE_THREAD_PER_CONNECTION; /* XXX */
    const char *realm = NULL;
    struct sockaddr_in sin;
    struct MHD_Daemon *previous = NULL;
    struct MHD_Daemon *current = NULL;
    struct sigaction sa;
    hx509_context hx509ctx = NULL;
    krb5_context context = NULL;
    char *priv_key_pem = NULL;
    char *cert_pem = NULL;
    char sig;
    int optidx = 0;
    int ret;

    if (getarg(args, sizeof(args) / sizeof(args[0]), argc, argv, &optidx))
        usage(1);
    if (help_flag)
        usage(0);
    if (version_flag) {
        print_version(NULL);
        exit(0);
    }
    if (argc > optidx) /* Add option to set a URI local part prefix? */
        usage(1);
    if (port < 0)
        errx(1, "Port number must be given");

    if (daemonize && daemon_child_fd == -1)
        daemon_child_fd = roken_detach_prep(argc, argv, "--daemon-child");
    daemonize = 0;

    argc -= optidx;
    argv += optidx;

    if ((errno = get_krb5_context(&context)))
        err(1, "Could not init krb5 context");

    if ((ret = krb5_kdc_get_config(context, &kdc_config)))
        krb5_err(context, 1, ret, "Could not init krb5 context");

    if (cache_dir == NULL) {
        char *s = NULL;

        if (asprintf(&s, "%s/kx509_proxy_cache-XXXXXX",
                     getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp") == -1 ||
            s == NULL ||
            (cache_dir = mkdtemp(s)) == NULL)
            err(1, "could not create temporary cache directory");
        if (verbose_flag)
            fprintf(stderr, "Note: using %s as cache directory\n", cache_dir);
        atexit(rm_cache_dir);
        setenv("TMPDIR", cache_dir, 1);
    }

    if ((ret = hx509_context_init(&hx509ctx)))
        hx509_err(NULL, 1, ret, "Could not initialize hx509 library");
    generate_key(hx509ctx, "impersonation", "rsa", 2048, &impersonation_key_fn);

    if ((errno = pthread_key_create(&k5ctx, k5_free_context)))
        err(1, "Could not create thread-specific storage");

again:
    if (cert_file && !priv_key_file)
        priv_key_file = cert_file;

    if (cert_file) {
        hx509_cursor cursor = NULL;
        hx509_certs certs = NULL;
        hx509_cert cert = NULL;
        time_t min_cert_life = 0;
        size_t len;
        void *s;

        ret = hx509_certs_init(hx509ctx, cert_file, 0, NULL, &certs);
        if (ret == 0)
            ret = hx509_certs_start_seq(hx509ctx, certs, &cursor);
        while (ret == 0 &&
               (ret = hx509_certs_next_cert(hx509ctx, certs,
                                            cursor, &cert)) == 0 && cert) {
            time_t notAfter = 0;

            if (!hx509_cert_have_private_key_only(cert) &&
                (notAfter = hx509_cert_get_notAfter(cert)) <= time(NULL) + 30)
                errx(1, "One or more certificates in %s are expired",
                     cert_file);
            if (notAfter) {
                notAfter -= time(NULL);
                if (notAfter < 600)
                    warnx("One or more certificates in %s expire soon",
                          cert_file);
                /* Reload 5 minutes prior to expiration */
                if (notAfter < min_cert_life || min_cert_life < 1)
                    min_cert_life = notAfter;
            }
            hx509_cert_free(cert);
        }
        (void) hx509_certs_end_seq(hx509ctx, certs, cursor);
        if (min_cert_life > 4)
            alarm(min_cert_life >> 1);
        hx509_certs_free(&certs);
        if (ret)
            hx509_err(hx509ctx, 1, ret,
                      "could not read certificate from %s", cert_file);

        errno = rk_undumpdata(cert_file, &s, &len);
        if ((errno = rk_undumpdata(cert_file, &s, &len)) ||
            (cert_pem = strndup(s, len)) == NULL)
            err(1, "could not read certificate from %s", cert_file);
        if (strlen(cert_pem) != len)
            err(1, "NULs in certificate file contents: %s", cert_file);
        free(s);
    }

    if (priv_key_file) {
        size_t len;
        void *s;

        errno = rk_undumpdata(priv_key_file, &s, &len);
        if ((errno = rk_undumpdata(priv_key_file, &s, &len)) ||
            (priv_key_pem = strndup(s, len)) == NULL)
            err(1, "could not read private key from %s", priv_key_file);
        if (strlen(priv_key_pem) != len)
            err(1, "NULs in private key file contents: %s", priv_key_file);
        free(s);
    }

    if (verbose_flag)
        flags |= MHD_USE_DEBUG;
    if (thread_per_client_flag)
        flags |= MHD_USE_THREAD_PER_CONNECTION;


    if (pipe(sigpipe) == -1)
        err(1, "Could not setup key/cert reloading");
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sighandler;
    (void) sigaction(SIGHUP, &sa, NULL);    /* Reload key & cert */
    (void) sigaction(SIGUSR1, &sa, NULL);   /* Reload key & cert */
    (void) sigaction(SIGINT, &sa, NULL);    /* Graceful shutdown */
    (void) sigaction(SIGTERM, &sa, NULL);   /* Graceful shutdown */
    (void) sigaction(SIGALRM, &sa, NULL);   /* Graceful shutdown */
    (void) signal(SIGPIPE, SIG_IGN);

    if (reverse_proxied_flag) {
        /*
         * XXX IPv6 too.  Create the sockets and tell MHD_start_daemon() about
         * them.
         */
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sin.sin_family = AF_INET;
        sin.sin_port = htons(port);
        current = MHD_start_daemon(flags, port,
                                   NULL, NULL,
                                   route, rk_UNCONST(realm),
                                   MHD_OPTION_SOCK_ADDR, &sin,
                                   MHD_OPTION_CONNECTION_LIMIT, (unsigned int)200,
                                   MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)10,
                                   MHD_OPTION_END);
    } else {
        current = MHD_start_daemon(flags | MHD_USE_SSL, port,
                                   NULL, NULL,
                                   route, rk_UNCONST(realm),
                                   MHD_OPTION_HTTPS_MEM_KEY, priv_key_pem,
                                   MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
                                   MHD_OPTION_CONNECTION_LIMIT, (unsigned int)200,
                                   MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)10,
                                   /*
                                    * On cert change reuse to co-exitst briefly
                                    * with the previous MHD instance in the
                                    * same process.
                                    *
                                    * On startup don't so we can fail if
                                    * another instance is already running.
                                    */
                                   (previous == NULL) ? MHD_OPTION_END :
                                        MHD_OPTION_LISTENING_ADDRESS_REUSE,
                                   (previous == NULL) ? MHD_OPTION_END :
                                        (unsigned int)1,
                                   MHD_OPTION_END);
    }
    if (current == NULL)
        err(1, "Could not start kx509 proxy REST service");

    if (previous) {
        MHD_stop_daemon(previous);
        previous = NULL;
    }

    if (verbose_flag)
        fprintf(stderr, "Ready!\n");
    if (daemon_child_fd != -1)
        roken_detach_finish(NULL, daemon_child_fd);

    /* Wait for signal, possibly SIGALRM, to reload certs and/or exit */
    while ((ret = read(sigpipe[0], &sig, sizeof(sig))) == -1 &&
           errno == EINTR)
        ;

    free(priv_key_pem);
    free(cert_pem);
    priv_key_pem = NULL;
    cert_pem = NULL;

    if (ret == 1 && (sig == SIGHUP || sig == SIGUSR1 || sig == SIGALRM)) {
        /* Reload certs and restart service gracefully */
        previous = current;
        current = NULL;
        goto again;
    }

    MHD_stop_daemon(current);
    pthread_key_delete(k5ctx);
    return 0;
}
