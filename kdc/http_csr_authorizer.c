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
 * This plugin authorizes requested certificate SANs and EKUs by performing an
 * HTTP GET of a URI as described below.  The response body will be ignored --
 * only the HTTP status code matters, which must be 200 Ok if authorization is
 * granted, 403 if denied, or some other HTTP status code.  Up to 5 redirects
 * will be followed.
 *
 * The URI must be of the form:
 *
 *      <base_URI>?requestor=<principal>&<san_type>=<san_value>&...
 *
 * where <base_URI> is the value of:
 *
 *      [kdc] http_csr_authorizer_uri = URI
 *
 * <principal> is the URL-encoded requesting client principal name,
 * <san_type> is one of:
 *
 *  - pkinit        (SAN)
 *  - xmpt          (SAN)
 *  - email         (SAN)
 *  - ms-upn        (SAN)
 *  - dnsname       (SAN)
 *
 * and <value> is a display form of the SAN, with SANs URL-encoded just like
 * principal names (see above).
 *
 * OIDs are of the form "1.2.3.4.5".
 *
 * Only digitalSignature and nonRepudiation key usage values are permitted.
 */
#define _GNU_SOURCE 1

#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

#include <roken.h>
#include <heimbase.h>
#include <krb5.h>
#include <hx509.h>
#include <kdc.h>
#include <common_plugin.h>
#include <csr_authorizer_plugin.h>

static heim_base_once_t once = HEIM_BASE_ONCE_INIT;

static void
my_curl_global_init(void *d)
{
    if (curl_global_init(*(long *)d) != CURLE_OK)
        abort(); /* XXX */
}

/* Throw away resource bodies -- we care only for the HTTP status code */
static size_t
write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    (void) ptr;
    (void) userdata;
    return size * nmemb;
}

static krb5_error_code
call_authorize_api(krb5_context context, CURL *hnd, const char *uri)
{
    krb5_error_code ret = ENOTSUP;
    const char *trace = getenv("HEIM_AUTHZ_VERBOSE");;
    CURLcode cret;
    long flags = CURL_GLOBAL_ALL | CURL_GLOBAL_ACK_EINTR;
    long http_code = 0;
    size_t elen;
    char ebuf[CURL_ERROR_SIZE] = { 0 };
    FILE *f = NULL;
    int is_file_uri = strncmp(uri, "file:///", sizeof("file:///") - 1) == 0;

    heim_base_once_f(&once, &flags, my_curl_global_init);

    cret = curl_easy_setopt(hnd, CURLOPT_URL, uri);
    if (cret == CURLE_OK)
        cret = curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_callback);
    if (cret == CURLE_OK)
        cret = curl_easy_setopt(hnd, CURLOPT_BUFFERSIZE, 102400L);
    if (cret == CURLE_OK)
        cret = curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
    if (cret == CURLE_OK)
        cret = curl_easy_setopt(hnd, CURLOPT_USERAGENT, "curl/7.58.0");
    if (cret == CURLE_OK)
        cret = curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 8L);
    if (cret == CURLE_OK)
        cret = curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION,
                                (long)CURL_HTTP_VERSION_2TLS); /* XXX */
    if (cret == CURLE_OK)
        cret = curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 0L);
    if (cret == CURLE_OK && trace)
        cret = curl_easy_setopt(hnd, CURLOPT_VERBOSE, 1L);
    if (cret == CURLE_OK && trace && trace[0] && strcmp(trace, "stderr")) {
        if ((f = fopen(trace, "a")))
            cret = curl_easy_setopt(hnd, CURLOPT_STDERR, f);
        else
            warn("Could not open verbose destination %s; using stderr", trace);
    }

    if (cret == CURLE_OK)
        cret = curl_easy_perform(hnd);
    if (cret == CURLE_OK)
        cret = curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &http_code);

    elen = strlen(ebuf);
    while (elen && ebuf[elen] == '\n') ebuf[elen--] = '\0';

    if (cret == CURLE_OK && is_file_uri)
        http_code = 200;

    switch (http_code) {
    case 0:
        /* GET didn't happen */
        krb5_set_error_message(context, ret = ENOTSUP, "Failed to authorized "
                               "due to curl error: %s (%d): %s",
                               curl_easy_strerror(cret), (int)cret, ebuf);
        break;
    case 200:
        krb5_set_error_message(context, ret = 0, "Authorization granted "
                               "for %s", uri);
        break;
    case 401:
        krb5_set_error_message(context, ret = EACCES, "Authorization failed "
                               "(%ld authentication failed) for %s: %s",
                               http_code, uri, ebuf);
        break;
    case 403:
    case 404:
        /* 404 -> EACCES since we might test using file: URIs */
        krb5_set_error_message(context, ret = EACCES, "Authorization failed "
                               "(%ld) for %s", http_code, uri);
        break;
    default:
        /* 5xx most likely */
        krb5_set_error_message(context, ret = EACCES, "Authorization failed "
                               "(%ld) for %s: %s", http_code, uri, ebuf);
        break;
    }

    if (f)
        (void) fclose(f);
    return ret;
}

static krb5_error_code
compute_uri_len(krb5_context context,
                const char *base,
                hx509_request csr,
                const char *cprinc,
                size_t *out)
{
    size_t sz, i;
    int ret = 0;

    *out = 0;
    sz = strlen(base) + sizeof("?requestor=") + 3 * strlen(cprinc);
    for (i = 0; ret == 0; i++) {
        hx509_san_type san_type;
        char *san;

        ret = hx509_request_get_san(csr, i, &san_type, &san);
        if (ret) break;
        switch (san_type) {
        case HX509_SAN_TYPE_EMAIL:
            sz += sizeof("&email="); break;
        case HX509_SAN_TYPE_DNSNAME:
            sz += sizeof("&dnsname="); break;
        case HX509_SAN_TYPE_XMPP:
            sz += sizeof("&xmpp="); break;
        case HX509_SAN_TYPE_PKINIT:
            sz += sizeof("&pkinit="); break;
        case HX509_SAN_TYPE_MS_UPN:
            sz += sizeof("&ms-upn="); break;
        default: ret = ENOTSUP; break;
        }
        if (ret) break;
        sz += 3 * strlen(san); /* 3x is worst case URL encoding */
        free(san);
    }
    if (ret == HX509_NO_ITEM)
        ret = 0;

    for (i = 0; ret == 0; i++) {
        char *s;

        ret = hx509_request_get_eku(csr, i, &s);
        if (ret == 0)
            sz += sizeof("&eku=") + strlen(s);
        free(s);
    }
    if (ret == HX509_NO_ITEM)
        ret = 0;

    *out = sz;
    return ret;
}

static krb5_error_code
make_uri(krb5_context context,
         CURL *hnd,
         const char *base,
         hx509_request csr,
         const char *cprinc,
         char *out,
         size_t sz)
{
    char *escaped;
    size_t len, i;
    int is_file_uri = strncmp(base, "file:///", sizeof("file:///") - 1) == 0;
    int ret = 0;

    out[0] = '\0';
    len = strlen(base);
    if (len >= sz)
        return ERANGE;

    (void) memcpy(out, base, len + 1);
    out += len;
    sz -= len;
    (void) memcpy(out, "?requestor=", sizeof("?requestor="));
    out[0] = is_file_uri ? '/' : '?';
    out += sizeof("?requestor=") - 1;
    sz -= sizeof("?requestor=") - 1;

    if ((escaped = curl_easy_escape(hnd, cprinc, 0)) == NULL)
        return krb5_enomem(context);
    len = strlen(escaped);
    if (len >= sz)
        return ERANGE;
    (void) memcpy(out, escaped, len + 1);
    out += len;
    sz -= len;

    for (i = 0; ret == 0; i++) {
        hx509_san_type san_type;
        char *san = NULL;

        escaped = NULL;
        ret = hx509_request_get_san(csr, i, &san_type, &san);
        if (ret == 0 && (escaped = curl_easy_escape(hnd, san, 0)) == NULL)
            ret = krb5_enomem(context);
        free(san);
        if (ret == 0)
            len = strlen(escaped);
        if (ret == 0 && sz < 1)
            ret = ERANGE;
        if (ret) { free(escaped); break; }

#define SAN_QPARAM(t, p)                                        \
        case t:                                                     \
            if (sizeof(p) >= sz) { ret = ERANGE; break; }           \
            (void) memcpy(out, p, sizeof(p));                       \
            out[0] = is_file_uri ? '/' : '&';                       \
            out += sizeof(p) - 1; sz -= sizeof(p) - 1;              \
            if (len >= sz) { ret = ERANGE; break; }                 \
            (void) memcpy(out, escaped, len);                       \
            out += len; sz -= len;                                  \
            break

        switch (san_type) {
        SAN_QPARAM(HX509_SAN_TYPE_EMAIL, "&email=");
        SAN_QPARAM(HX509_SAN_TYPE_DNSNAME, "&dnsname=");
        SAN_QPARAM(HX509_SAN_TYPE_XMPP, "&xmpp=");
        SAN_QPARAM(HX509_SAN_TYPE_PKINIT, "&pkinit=");
        SAN_QPARAM(HX509_SAN_TYPE_MS_UPN, "&ms-upn=");
        default: ret = ENOTSUP; break;
        }
        free(escaped);
    }
    if (ret == HX509_NO_ITEM)
        ret = 0;

    for (i = 0; ret == 0; i++) {
        char *s;

        ret = hx509_request_get_eku(csr, i, &s);
        if (ret)
            break;
        len = strlen(s);
        if (sizeof("&eku=") + len >= sz) { ret = ERANGE; break; }
        out += sizeof("&eku=") - 1;
        sz -= sizeof("&eku=") - 1;
        (void) memcpy(out, s, strlen(s) + 1);
        out[0] = is_file_uri ? '/' : '&';                       \
        out += len;
        sz -= len;
        free(s);
    }
    if (ret == HX509_NO_ITEM)
        ret = 0;

    return ret;
}

static KRB5_LIB_CALL krb5_error_code
authorize(void *ctx,
          krb5_context context,
          const char *app,
          hx509_request csr,
          krb5_const_principal client,
          krb5_boolean *result)
{
    krb5_error_code ret;
    KeyUsage ku;
    const char *base_uri;
    size_t i, uri_len = 0;
    CURL *hnd = NULL;
    char *princ = NULL;
    char *uri = NULL;

    base_uri = krb5_config_get_string(context, NULL, app ? app : "kdc",
                                      "http_csr_authorizer_uri", NULL);
    if (base_uri == NULL)
        return KRB5_PLUGIN_NO_HANDLE;

    if (strncmp(base_uri, "https://", sizeof("https://") - 1) &&
        strncmp(base_uri, "file:///", sizeof("file:///") - 1)) {
        const char *p = base_uri;

        /* Check that this is an http: URI with localhost as the authority */
        if (strncmp(p, "http://", sizeof("http://") - 1))
            return KRB5_PLUGIN_NO_HANDLE;
        p += sizeof("http://") - 1;
        if (strncmp(p, "localhost", sizeof("localhost") - 1) == 0)
            p += sizeof("localhost") - 1;
        else if (strncmp(p, "127.0.0.1", sizeof("127.0.0.1") - 1) == 0)
            p += sizeof("127.0.0.1") - 1;
        else if (strncmp(p, "[::1]", sizeof("[::1]") - 1) == 0)
            p += sizeof("[::1]") - 1;
        else
            return KRB5_PLUGIN_NO_HANDLE;
        if (p[0] != ':' && p[0] != '/')
            return KRB5_PLUGIN_NO_HANDLE;

        if (p[0] == ':')
            for (p++; p[0] >= '0' && p[0] <= '9'; p++)
                ;
        if (p[0] != '/')
            return KRB5_PLUGIN_NO_HANDLE;
    }

    ret = krb5_unparse_name(context, client, &princ);
    if (ret == 0)
        ret = compute_uri_len(context, base_uri, csr, princ, &uri_len);
    if (ret == 0 && (uri = calloc(1, uri_len)) == NULL)
        ret = krb5_enomem(context);
    if (ret == 0 && (hnd = curl_easy_init()) == NULL)
        ret = krb5_enomem(context);
    if (ret == 0)
        ret = make_uri(context, hnd, base_uri, csr, princ, uri, uri_len);
    free(princ);
    if (ret == 0)
        ret = call_authorize_api(context, hnd, uri);
    free(uri);
    if (hnd)
        curl_easy_cleanup(hnd);

    for (i = 0; ret == 0; i++) {
        hx509_san_type san_type;
        char *san = NULL;

        ret = hx509_request_get_san(csr, i, &san_type, &san);
        if (ret == 0 && san)
            ret = hx509_request_authorize_san(csr, i);
        free(san);
    }
    if (ret == HX509_NO_ITEM)
        ret = 0;

    for (i = 0; ret == 0; i++) {
        char *eku = NULL;

        ret = hx509_request_get_eku(csr, i, &eku);
        if (ret == 0)
            ret = hx509_request_authorize_eku(csr, i);
        free(eku);
    }
    if (ret == HX509_NO_ITEM)
        ret = 0;

    ku = int2KeyUsage(0);
    ku.digitalSignature = 1;
    ku.nonRepudiation = 1;
    hx509_request_authorize_ku(csr, ku);
    if (ret == 0)
        *result = TRUE;
    return ret;
}

static KRB5_LIB_CALL krb5_error_code
http_csr_authorizer_init(krb5_context context, void **c)
{
    *c = NULL;
    return 0;
}

static KRB5_LIB_CALL void
http_csr_authorizer_fini(void *c)
{
}

static krb5plugin_csr_authorizer_ftable plug_desc =
    { 1, http_csr_authorizer_init, http_csr_authorizer_fini, authorize };

static krb5plugin_csr_authorizer_ftable *plugs[] = { &plug_desc };

static uintptr_t
http_csr_authorizer_get_instance(const char *libname)
{
    if (strcmp(libname, "krb5") == 0)
        return krb5_get_instance(libname);
    if (strcmp(libname, "kdc") == 0)
        return kdc_get_instance(libname);
    if (strcmp(libname, "hx509") == 0)
        return hx509_get_instance(libname);
    return 0;
}

krb5_plugin_load_ft kdc_csr_authorizer_plugin_load;

krb5_error_code KRB5_CALLCONV
kdc_csr_authorizer_plugin_load(heim_pcontext context,
                               krb5_get_instance_func_t *get_instance,
                               size_t *num_plugins,
                               krb5_plugin_common_ftable_cp **plugins)
{
    *get_instance = http_csr_authorizer_get_instance;
    *num_plugins = sizeof(plugs) / sizeof(plugs[0]);
    *plugins = (krb5_plugin_common_ftable_cp *)plugs;
    return 0;
}
