/*
 * Copyright (c) 2020 Kungliga Tekniska Högskolan
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
#include <getarg.h>
#include <roken.h>
#include <krb5.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <hx509.h>
#include "../lib/hx509/hx_locl.h"
#include <hx509-private.h>
#include <kadm5/admin.h>
#include <kadm5/private.h>
#include <kadm5/kadm5_err.h>

#define heim_pcontext krb5_context
#define heim_pconfig krb5_context
#include <heimbase-svc.h>

typedef struct kadmin_request_desc {
    HEIM_SVC_REQUEST_DESC_COMMON_ELEMENTS;

    struct MHD_Connection *connection;
    krb5_error_code ret;
    krb5_times token_times;
    /*
     * FIXME
     *
     * Currently we re-use the authz framework from bx509d, using an
     * `hx509_request' instance (an abstraction for CSRs) to represent the
     * request because that is what the authz plugin uses that implements the
     * policy we want checked here.
     *
     * This is inappropriate in the long-term in two ways:
     *
     *  - the policy for certificates deals in SANs and EKUs, whereas the
     *    policy for ext_keytab deals in host-based service principal names,
     *    and there is not a one-to-one mapping of service names to EKUs;
     *
     *  - using a type from libhx509 for representing requests for things that
     *    aren't certificates is really not appropriate no matter how similar
     *    the use cases for this all might be.
     *
     * What we need to do is develop a library that can represent requests for
     * credentials via naming attributes like SANs and Kerberos principal
     * names, but more arbitrary still than what `hx509_request' supports, and
     * then invokes a plugin.
     *
     * Also, we might want to develop an in-tree authorization solution that is
     * richer than what kadmin.acl supports now, storing grants in HDB entries
     * and/or similar places.
     *
     * For expediency we use `hx509_request' here for now, impedance mismatches
     * be damned.
     */
    hx509_request req;          /* For authz only */
    heim_array_t service_names;
    heim_array_t hostnames;
    heim_array_t spns;
    krb5_principal cprinc;
    krb5_keytab keytab;
    krb5_storage *sp;
    void *kadm_handle;
    char *realm;
    char *keytab_name;
    char *freeme1;
    char *enctypes;
    const char *method;
    unsigned int materialize:1;
    unsigned int rotate_now:1;
    unsigned int rotate:1;
    unsigned int revoke:1;
    unsigned int create:1;
    unsigned int ro:1;
    char frombuf[128];
} *kadmin_request_desc;

static void
audit_trail(kadmin_request_desc r, krb5_error_code ret)
{
    const char *retname = NULL;

    /* Get a symbolic name for some error codes */
#define CASE(x) case x : retname = #x; break
    switch (ret) {
    CASE(ENOMEM);
    CASE(EACCES);
    CASE(HDB_ERR_NOT_FOUND_HERE);
    CASE(HDB_ERR_WRONG_REALM);
    CASE(HDB_ERR_EXISTS);
    CASE(HDB_ERR_KVNO_NOT_FOUND);
    CASE(HDB_ERR_NOENTRY);
    CASE(HDB_ERR_NO_MKEY);
    CASE(KRB5KDC_ERR_BADOPTION);
    CASE(KRB5KDC_ERR_CANNOT_POSTDATE);
    CASE(KRB5KDC_ERR_CLIENT_NOTYET);
    CASE(KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN);
    CASE(KRB5KDC_ERR_ETYPE_NOSUPP);
    CASE(KRB5KDC_ERR_KEY_EXPIRED);
    CASE(KRB5KDC_ERR_NAME_EXP);
    CASE(KRB5KDC_ERR_NEVER_VALID);
    CASE(KRB5KDC_ERR_NONE);
    CASE(KRB5KDC_ERR_NULL_KEY);
    CASE(KRB5KDC_ERR_PADATA_TYPE_NOSUPP);
    CASE(KRB5KDC_ERR_POLICY);
    CASE(KRB5KDC_ERR_PREAUTH_FAILED);
    CASE(KRB5KDC_ERR_PREAUTH_REQUIRED);
    CASE(KRB5KDC_ERR_SERVER_NOMATCH);
    CASE(KRB5KDC_ERR_SERVICE_EXP);
    CASE(KRB5KDC_ERR_SERVICE_NOTYET);
    CASE(KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN);
    CASE(KRB5KDC_ERR_TRTYPE_NOSUPP);
    CASE(KRB5KRB_ERR_RESPONSE_TOO_BIG);
    /* XXX Add relevant error codes */
    case 0:
        retname = "SUCCESS";
        break;
    default:
        retname = NULL;
        break;
    }

    /* Let's save a few bytes */
    if (retname && !strncmp("KRB5KDC_", retname, sizeof("KRB5KDC_") - 1))
        retname += sizeof("KRB5KDC_") - 1;
#undef PREFIX
    heim_audit_trail((heim_svc_req_desc)r, ret, retname);
}

static krb5_log_facility *logfac;
static pthread_key_t k5ctx;

static krb5_error_code
get_krb5_context(krb5_context *contextp)
{
    krb5_error_code ret;

    if ((*contextp = pthread_getspecific(k5ctx)))
        return 0;

    ret = krb5_init_context(contextp);
    /* XXX krb5_set_log_dest(), warn_dest, debug_dest */
    if (ret == 0)
        (void) pthread_setspecific(k5ctx, *contextp);
    return ret;
}

static int port = -1;
static int help_flag;
static int daemonize;
static int daemon_child_fd = -1;
static int verbose_counter;
static int version_flag;
static int reverse_proxied_flag;
static int thread_per_client_flag;
struct getarg_strings audiences;
static const char *cert_file;
static const char *priv_key_file;
static const char *cache_dir;
static const char *realm;
static const char *hdb;
static const char *primary_server;
static const char *admin_client_name;
static const char *admin_server;
static const char *primary_admin_server;
static const char *stash_file;
static const char *kadmin_client_name = "keytab_service";

static krb5_error_code
get_kadm_handle(krb5_context context, void **kadm_handle, int primary)
{
    kadm5_config_params conf;
    krb5_error_code ret = 0;
    const char *pstr;
    const char *server = NULL;
    char *s = NULL;

    /* Configure kadmin connection */
    memset(&conf, 0, sizeof(conf));
    if (primary || !admin_server)
        server = primary_admin_server;
    else
        server = admin_server;
    if (server && (pstr = strrchr(server, ':'))) {
        int32_t n;
        char *ends;

        if ((s = strdup(server)) == NULL)
            return krb5_enomem(context);

        errno = 0;
        if ((n = strtol(pstr, &ends, 10)) < 0 ||
            n > UINT16_MAX || errno || *ends != '\0') {
            errno = errno ? errno : ERANGE;
            err(1, "Port number invalid in: %s", server);
            return ERANGE;
        }
        conf.kadmind_port = htons(n);
        conf.mask |= KADM5_CONFIG_KADMIND_PORT;
        s[pstr - server] = '\0';
        server = s;
    }
    if (server) {
        conf.admin_server = s ? s : strdup(server);
        conf.mask |= KADM5_CONFIG_ADMIN_SERVER;
        s = NULL;

        if (conf.admin_server == NULL)
            err(1, "Out of memory");
    }
    if (hdb) {
        conf.dbname = strdup(hdb);
        conf.mask |= KADM5_CONFIG_DBNAME;
        if (conf.dbname == NULL)
            err(1, "Out of memory");
    }
    if (realm) {
        krb5_set_default_realm(context, realm); /* XXX ??? */
        conf.realm = strdup(realm);
        conf.mask |= KADM5_CONFIG_REALM;
        if (conf.stash_file == NULL)
            err(1, "Out of memory");
    }
    if (stash_file) {
        conf.stash_file = strdup(stash_file);
        conf.mask |= KADM5_CONFIG_KADMIND_PORT;
        if (conf.stash_file == NULL)
            err(1, "Out of memory");
    }

    if (!server)
        /* Local */
        return kadm5_s_init_with_password_ctx(context,
                                              kadmin_client_name,
                                              NULL,
                                              NULL,
                                              &conf, 0, 0,
                                              kadm_handle);
    /* Remote */
    ret = kadm5_c_init_with_password_ctx(context,
                                         kadmin_client_name,
                                         NULL,
                                         KADM5_ADMIN_SERVICE,
                                         &conf, 0, 0,
                                         kadm_handle);
    free(s);
    return ret;
}

static krb5_error_code resp(kadmin_request_desc, int,
                            enum MHD_ResponseMemoryMode, const char *,
                            const void *, size_t, const char *, const char *);
static krb5_error_code bad_req(kadmin_request_desc, krb5_error_code, int,
                               const char *, ...)
                               HEIMDAL_PRINTF_ATTRIBUTE((__printf__, 4, 5));

static krb5_error_code bad_enomem(kadmin_request_desc, krb5_error_code);
static krb5_error_code bad_400(kadmin_request_desc, krb5_error_code, const char *);
static krb5_error_code bad_401(kadmin_request_desc, const char *);
static krb5_error_code bad_403(kadmin_request_desc, krb5_error_code, const char *);
static krb5_error_code bad_404(kadmin_request_desc, const char *);
static krb5_error_code bad_405(kadmin_request_desc, const char *);
/*static krb5_error_code bad_500(kadmin_request_desc, krb5_error_code, const char *);*/
static krb5_error_code bad_503(kadmin_request_desc, krb5_error_code, const char *);

static int
validate_token(kadmin_request_desc r)
{
    krb5_error_code ret;
    const char *token;
    const char *host;
    char token_type[64]; /* Plenty */
    char *p;
    krb5_data tok;
    size_t host_len, brk, i;

    memset(&r->token_times, 0, sizeof(r->token_times));
    host = MHD_lookup_connection_value(r->connection, MHD_HEADER_KIND,
                                       MHD_HTTP_HEADER_HOST);
    if (host == NULL)
        return bad_400(r, EINVAL, "Host header is missing");

    /* Exclude port number here (IPv6-safe because of the below) */
    host_len = ((p = strchr(host, ':'))) ? p - host : strlen(host);

    token = MHD_lookup_connection_value(r->connection, MHD_HEADER_KIND,
                                        MHD_HTTP_HEADER_AUTHORIZATION);
    if (token == NULL)
        return bad_401(r, "Authorization token is missing");
    brk = strcspn(token, " \t");
    if (token[brk] == '\0' || brk > sizeof(token_type) - 1)
        return bad_401(r, "Authorization token is missing");
    memcpy(token_type, token, brk);
    token_type[brk] = '\0';
    token += brk + 1;
    tok.length = strlen(token);
    tok.data = (void *)(uintptr_t)token;

    for (i = 0; i < audiences.num_strings; i++)
        if (strncasecmp(host, audiences.strings[i], host_len) == 0 &&
            audiences.strings[i][host_len] == '\0')
            break;
    if (i == audiences.num_strings)
        return bad_403(r, EINVAL, "Host: value is not accepted here");

    r->sname = strdup(host); /* No need to check for ENOMEM here */

    ret = kdc_validate_token(r->context, NULL /* realm */, token_type, &tok,
                             (const char **)&audiences.strings[i], 1,
                             &r->cprinc, &r->token_times);
    if (ret)
        return bad_403(r, ret, "Token validation failed");
    if (r->cprinc == NULL)
        return bad_403(r, ret, "Could not extract a principal name "
                       "from token");
    return krb5_unparse_name(r->context, r->cprinc, &r->cname);
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
    (void) closedir(d);
    (void) rmdir(cache_dir);
}

/*
 * XXX Shouldn't be a body, but a status message.  The body should be
 * configurable to be from a file.  MHD doesn't give us a way to set the
 * response status message though, just the body.
 */
static krb5_error_code
resp(kadmin_request_desc r,
     int http_status_code,
     enum MHD_ResponseMemoryMode rmmode,
     const char *content_type,
     const void *body,
     size_t bodylen,
     const char *token,
     const char *csrf)
{
    struct MHD_Response *response;
    int mret = MHD_YES;

    (void) gettimeofday(&r->tv_end, NULL);
    if (http_status_code == MHD_HTTP_OK ||
        http_status_code == MHD_HTTP_TEMPORARY_REDIRECT)
        audit_trail(r, 0);

    response = MHD_create_response_from_buffer(bodylen, rk_UNCONST(body),
                                               rmmode);
    if (response == NULL)
        return -1;
    mret = MHD_add_response_header(response, MHD_HTTP_HEADER_CACHE_CONTROL,
                                   "no-cache");
    if (mret == MHD_YES && http_status_code == MHD_HTTP_UNAUTHORIZED) {
        mret = MHD_add_response_header(response,
                                       MHD_HTTP_HEADER_WWW_AUTHENTICATE,
                                       "Bearer");
        if (mret == MHD_YES)
            mret = MHD_add_response_header(response,
                                           MHD_HTTP_HEADER_WWW_AUTHENTICATE,
                                           "Negotiate");
    } else if (http_status_code == MHD_HTTP_TEMPORARY_REDIRECT) {
        mret = MHD_add_response_header(response, MHD_HTTP_HEADER_LOCATION,
                                       primary_server);
    }

    if (mret == MHD_YES && csrf)
        mret = MHD_add_response_header(response,
                                       "X-CSRF-Token",
                                       csrf);

    if (mret == MHD_YES && content_type) {
        mret = MHD_add_response_header(response,
                                       MHD_HTTP_HEADER_CONTENT_TYPE,
                                       content_type);
    }
    if (mret != MHD_NO)
        mret = MHD_queue_response(r->connection, http_status_code, response);
    MHD_destroy_response(response);
    return mret == MHD_NO ? -1 : 0;
}

static krb5_error_code
bad_reqv(kadmin_request_desc r,
         krb5_error_code code,
         int http_status_code,
         const char *fmt,
         va_list ap)
{
    krb5_error_code ret;
    krb5_context context = NULL;
    const char *k5msg = NULL;
    const char *emsg = NULL;
    char *formatted = NULL;
    char *msg = NULL;

    heim_audit_addkv((heim_svc_req_desc)r, 0, "http-status-code", "%d",
                     http_status_code);
    (void) gettimeofday(&r->tv_end, NULL);
    if (code == ENOMEM) {
        if (r->context)
            krb5_log_msg(r->context, logfac, 1, NULL, "Out of memory");
        audit_trail(r, code);
        return resp(r, http_status_code, MHD_RESPMEM_PERSISTENT,
                    NULL, fmt, strlen(fmt), NULL, NULL);
    }

    if (code) {
        if (r->context)
            emsg = k5msg = krb5_get_error_message(r->context, code);
        else
            emsg = strerror(code);
    }

    ret = vasprintf(&formatted, fmt, ap) == -1;
    if (code) {
        if (ret > -1 && formatted)
            ret = asprintf(&msg, "%s: %s (%d)", formatted, emsg, (int)code);
    } else {
        msg = formatted;
        formatted = NULL;
    }
    heim_audit_addreason((heim_svc_req_desc)r, "%s", formatted);
    audit_trail(r, code);
    krb5_free_error_message(context, k5msg);

    if (ret == -1 || msg == NULL) {
        if (context)
            krb5_log_msg(r->context, logfac, 1, NULL, "Out of memory");
        return resp(r, MHD_HTTP_SERVICE_UNAVAILABLE,
                    MHD_RESPMEM_PERSISTENT, NULL,
                    "Out of memory", sizeof("Out of memory") - 1, NULL, NULL);
    }

    ret = resp(r, http_status_code, MHD_RESPMEM_MUST_COPY,
               NULL, msg, strlen(msg), NULL, NULL);
    free(formatted);
    free(msg);
    return ret == -1 ? -1 : code;
}

static krb5_error_code
bad_req(kadmin_request_desc r,
        krb5_error_code code,
        int http_status_code,
        const char *fmt,
        ...)
{
    krb5_error_code ret;
    va_list ap;

    va_start(ap, fmt);
    ret = bad_reqv(r, code, http_status_code, fmt, ap);
    va_end(ap);
    return ret;
}

static krb5_error_code
bad_enomem(kadmin_request_desc r, krb5_error_code ret)
{
    return bad_req(r, ret, MHD_HTTP_SERVICE_UNAVAILABLE,
                   "Out of memory");
}

static krb5_error_code
bad_400(kadmin_request_desc r, int ret, const char *reason)
{
    return bad_req(r, ret, MHD_HTTP_BAD_REQUEST, "%s", reason);
}

static krb5_error_code
bad_401(kadmin_request_desc r, const char *reason)
{
    return bad_req(r, EACCES, MHD_HTTP_UNAUTHORIZED, "%s", reason);
}

static krb5_error_code
bad_403(kadmin_request_desc r, krb5_error_code ret, const char *reason)
{
    return bad_req(r, ret, MHD_HTTP_FORBIDDEN, "%s", reason);
}

static krb5_error_code
bad_404(kadmin_request_desc r, const char *name)
{
    return bad_req(r, ENOENT, MHD_HTTP_NOT_FOUND,
                   "Resource not found: %s", name);
}

static krb5_error_code
bad_405(kadmin_request_desc r, const char *method)
{
    return bad_req(r, EPERM, MHD_HTTP_METHOD_NOT_ALLOWED,
                   "Method not supported: %s", method);
}

static krb5_error_code
bad_method_want_POST(kadmin_request_desc r)
{
    return bad_req(r, EPERM, MHD_HTTP_METHOD_NOT_ALLOWED,
                   "Use POST for making changes to principals");
}

#if 0
static krb5_error_code
bad_500(kadmin_request_desc r,
        krb5_error_code ret,
        const char *reason)
{
    return bad_req(r, ret, MHD_HTTP_INTERNAL_SERVER_ERROR,
                   "Internal error: %s", reason);
}
#endif

static krb5_error_code
bad_503(kadmin_request_desc r,
        krb5_error_code ret,
        const char *reason)
{
    return bad_req(r, ret, MHD_HTTP_SERVICE_UNAVAILABLE,
                   "Service unavailable: %s", reason);
}

static krb5_error_code
good_ext_keytab(kadmin_request_desc r)
{
    krb5_error_code ret;
    size_t bodylen;
    void *body;

    ret = rk_undumpdata(strchr(r->keytab_name, ':') + 1, &body, &bodylen);
    if (ret)
        return bad_503(r, ret, "Could not recover issued certificate "
                       "from PKIX store");

    (void) gettimeofday(&r->tv_end, NULL);
    ret = resp(r, MHD_HTTP_OK, MHD_RESPMEM_MUST_COPY,
               "application/octet-stream", body, bodylen, NULL, NULL);
    free(body);
    return ret;
}

static int
param_cb(void *d,
         enum MHD_ValueKind kind,
         const char *key,
         const char *val)
{
    kadmin_request_desc r = d;
    krb5_error_code ret = 0;
    heim_string_t s = NULL;

    /*
     * Multi-valued params:
     *
     *  - spn=<service>/<hostname>
     *  - dNSName=<hostname>
     *  - service=<service>
     *
     * Single-valued params:
     *
     *  - realm=<REALM>
     *  - materialize=true  -- create a concrete princ where it's virtual
     *  - enctypes=...      -- key-salt types
     *  - revoke=true       -- delete old keys (concrete princs only)
     *  - rotate=true       -- change keys (no-op for virtual princs)
     *  - create=true       -- create a concrete princ
     *  - ro=true           -- perform no writes
     */

    if (strcmp(key, "realm") == 0 && val) {
        if (!r->realm && !(r->realm = strdup(val)))
            ret = krb5_enomem(r->context);
    } else if (strcmp(key, "materialize") == 0  ||
               strcmp(key, "revoke") == 0       ||
               strcmp(key, "rotate") == 0       ||
               strcmp(key, "create") == 0       ||
               strcmp(key, "ro") == 0) {
        if (!val || strcmp(val, "true") != 0)
            krb5_set_error_message(r->context, ret = EINVAL,
                                   "ext_keytab \"%s\" q-param accepts "
                                   "only \"true\"", key);
        else if (strcmp(key, "materialize") == 0)
            r->materialize = 1;
        else if (strcmp(key, "revoke") == 0)
            r->revoke = 1;
        else if (strcmp(key, "rotate") == 0)
            r->rotate = 1;
        else if (strcmp(key, "create") == 0)
            r->create = 1;
        else if (strcmp(key, "ro") == 0)
            r->ro = 1;
        if (ret == 0)
            heim_audit_addkv((heim_svc_req_desc)r, KDC_AUDIT_VIS,
                             "requested_option", "%s", key);
    } else if (strcmp(key, "dNSName") == 0 && val) {
        s = heim_string_create(val);
        if (!s)
            ret = krb5_enomem(r->context);
        else
            ret = heim_array_append_value(r->hostnames, s);
        heim_audit_addkv((heim_svc_req_desc)r, KDC_AUDIT_VIS,
                         "requested_dNSName", "%s", val);
        ret = hx509_request_add_dns_name(r->context->hx509ctx, r->req, val);
    } else if (strcmp(key, "service") == 0 && val) {
        s = heim_string_create(val);
        if (!s)
            ret = krb5_enomem(r->context);
        else
            ret = heim_array_append_value(r->service_names, s);
        heim_audit_addkv((heim_svc_req_desc)r, KDC_AUDIT_VIS,
                         "requested_service", "%s", val);
    } else if (strcmp(key, "enctypes") == 0 && val) {
        r->enctypes = strdup(val);
        if (!(r->enctypes = strdup(val)))
            ret = krb5_enomem(r->context);
        heim_audit_addkv((heim_svc_req_desc)r, KDC_AUDIT_VIS,
                         "requested_enctypes", "%s", val);
    } else if (strcmp(key, "spn") == 0 && val) {
        krb5_principal p;
        const char *hostname = "";

        heim_audit_addkv((heim_svc_req_desc)r, KDC_AUDIT_VIS,
                         "requested_spn", "%s", val);

        ret = krb5_parse_name(r->context, val, &p);
        if (ret == 0) {
            if (krb5_principal_get_num_comp(r->context, p) < 2 ||
                krb5_principal_get_num_comp(r->context, p) > 3)
                ret = ENOTSUP;
        }
        if (ret == 0)
            hostname = krb5_principal_get_comp_string(r->context, p, 1);
        if (!hostname || !strchr(hostname, '.'))
            krb5_set_error_message(r->context, ret = ENOTSUP,
                                   "Only host-based service names supported");
        if (ret == 0)
            ret = hx509_request_add_dns_name(r->context->hx509ctx, r->req,
                                             hostname);
        if (ret == 0 && !(s = heim_string_create(hostname)))
            ret = krb5_enomem(r->context);

#if 0
        /* The authorizer probably doesn't know what to do with this */
        ret = hx509_request_add_pkinit(r->context->hx509ctx, r->req, val);
#endif
    } else {
        /* Produce error for unknown params */
        heim_audit_addkv((heim_svc_req_desc)r, 0, "requested_unknown", "true");
        krb5_set_error_message(r->context, r->ret = ENOTSUP,
                               "Query parameter %s not supported", key);
    }
    if (ret && !r->ret)
        r->ret = ret;
    heim_release(s);
    return ret ? MHD_NO /* Stop iterating */ : MHD_YES;
}

static krb5_error_code
authorize_req(kadmin_request_desc r)
{
    krb5_error_code ret;

    ret = hx509_request_init(r->context->hx509ctx, &r->req);
    if (ret)
        return bad_enomem(r, ret);
    (void) MHD_get_connection_values(r->connection, MHD_GET_ARGUMENT_KIND,
                                     param_cb, r);
    ret = r->ret;
    if (ret)
        return bad_req(r, ret, MHD_HTTP_SERVICE_UNAVAILABLE,
                       "Could not handle query parameters");
    ret = kdc_authorize_csr(r->context, "ext_keytab", r->req, r->cprinc);
    if (ret == EACCES || ret == EINVAL || ret == ENOTSUP ||
        ret == KRB5KDC_ERR_POLICY)
        return bad_403(r, ret, "Not authorized to requested certificate");
    if (ret)
        return bad_req(r, ret, MHD_HTTP_SERVICE_UNAVAILABLE,
                       "Error checking authorization");
    return ret;
}

static krb5_error_code
make_keytab(kadmin_request_desc r)
{
    krb5_error_code ret = 0;
    int fd = -1;

    r->keytab_name = NULL;
    if (asprintf(&r->keytab_name, "FILE:%s/kt-XXXXXX", cache_dir) == -1 ||
        r->keytab_name == NULL)
        ret = krb5_enomem(r->context);
    if (ret == 0)
        fd = mkstemp(r->keytab_name + sizeof("FILE:") - 1);
    if (ret == 0 && fd == -1)
        ret = errno;
    if (ret == 0)
        ret = krb5_kt_resolve(r->context, r->keytab_name, &r->keytab);
    return ret;
}

static krb5_error_code
write_keytab(kadmin_request_desc r,
             kadm5_principal_ent_rec *princ,
             const char *unparsed)
{
    krb5_error_code ret = 0;
    krb5_keytab_entry key;
    size_t i;

    if (princ->n_key_data <= 0)
        return 0;

    memset(&key, 0, sizeof(key));
    for (i = 0; ret == 0 && i < princ->n_key_data; i++) {
        krb5_key_data *kd = &princ->key_data[i];

        if (kadm5_all_keys_are_bogus(1, kd))
            continue;

        key.principal = princ->principal;
        key.vno = kd->key_data_kvno;
        key.keyblock.keytype = kd->key_data_type[0];
        key.keyblock.keyvalue.length = kd->key_data_length[0];
        key.keyblock.keyvalue.data = kd->key_data_contents[0];

        /*
         * XXX kadm5 doesn't give us set_time here, but we can compute it using
         * the KeyRotation metadata in the TL data.  We should!
         */
        key.timestamp = time(NULL);

        ret = krb5_kt_add_entry(r->context, r->keytab, &key);
    }
    if (ret)
        krb5_warn(r->context, ret,
                  "Failed to write keytab entries for %s", unparsed);

    return ret;
}

static void
random_password(krb5_context context, char *buf, size_t buflen)
{
    static const char chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.,";
    char p[32];
    size_t i;
    char b;

    buflen--;
    for (i = 0; i < buflen; i++) {
        if (i % sizeof(p) == 0)
            krb5_generate_random_block(p, sizeof(p));
        b = p[i % sizeof(p)];
        buf[i] = chars[b % (sizeof(chars) - 1)];
    }
    buf[i] = '\0';
}

static krb5_error_code
make_kstuple(krb5_context context,
             kadm5_principal_ent_rec *p,
             krb5_key_salt_tuple **kstuple,
             size_t *n_kstuple)
{
    size_t i;

    *kstuple = 0;
    *n_kstuple = 0;

    if (p->n_key_data < 1)
        return 0;
    *kstuple = calloc(p->n_key_data, sizeof (*kstuple));
    for (i = 0; *kstuple && i < p->n_key_data; i++) {
        if (p->key_data[i].key_data_kvno == p->kvno) {
            (*kstuple)[i].ks_enctype = p->key_data[i].key_data_type[0];
            (*kstuple)[i].ks_salttype = p->key_data[i].key_data_type[1];
            (*n_kstuple)++;
        }
    }
    return *kstuple ? 0 :krb5_enomem(context);
}

/* Setup a CSR for ext_keytab() */
static krb5_error_code
do_ext_keytab1(kadmin_request_desc r, const char *pname)
{
    kadm5_principal_ent_rec princ;
    krb5_key_salt_tuple *kstuple = NULL;
    krb5_error_code ret = 0;
    krb5_principal p = NULL;
    uint32_t mask =
        KADM5_PRINCIPAL | KADM5_KVNO | KADM5_MAX_LIFE | KADM5_MAX_RLIFE |
        KADM5_ATTRIBUTES | KADM5_KEY_DATA | KADM5_TL_DATA;
    uint32_t create_mask = mask & ~(KADM5_KEY_DATA | KADM5_TL_DATA);
    size_t nkstuple = 0;
    int change = 0;
    int refetch = 0;
    int freeit = 0;

    memset(&princ, 0, sizeof(princ));
    princ.key_data = NULL;
    princ.tl_data = NULL;

    ret = krb5_parse_name(r->context, pname, &p);
    if (ret == 0 && r->enctypes)
        ret = krb5_string_to_keysalts2(r->context, r->enctypes,
                                       &nkstuple, &kstuple);
    if (ret == 0)
        ret = kadm5_get_principal(r->kadm_handle, p, &princ, mask);
    if (ret == 0) {
        freeit = 1;

        /*
         * If princ is virtual and we're not asked to materialize, ignore
         * requests to rotate.
         */
        if (!r->materialize &&
            (princ.attributes & (KRB5_KDB_VIRTUAL_KEYS | KRB5_KDB_VIRTUAL))) {
            r->rotate = 0;
            r->revoke = 0;
        }
    }

    change = !r->ro && (r->rotate || r->revoke);

    /* Handle create / materialize options */
    if (ret == KADM5_UNK_PRINC && r->create) {
        char pw[128];

        ret = strcmp(r->method, "POST") == 0 ? 0 : ENOSYS; /* XXX */

        /*
         * We're writing, but maybe we can't (not a primary) or have to
         * reconnect to a primary kadmind.
         */
        if (ret == 0 && primary_server && !primary_admin_server) {
            /* Local DB, not a primary -> redirect */
            ret = KADM5_READ_ONLY;
        } else if (ret == 0 && primary_admin_server && admin_server) {
            /* Connected to replica -> reconnect to primary */
            kadm5_destroy(r->kadm_handle);
            ret = get_kadm_handle(r->context, &r->kadm_handle, 1);
        }
        memset(&princ, 0, sizeof(princ));
        princ.kvno = 1;
        princ.tl_data = NULL;
        princ.key_data = NULL;
        princ.max_life = 24 * 3600;                /* XXX Make configurable */
        princ.max_renewable_life = princ.max_life; /* XXX Make configurable */

        random_password(r->context, pw, sizeof(pw));
        princ.principal = p;     /* Borrow */
        if (ret == 0)
            ret = kadm5_create_principal(r->kadm_handle, &princ, create_mask,
                                         pw);
        princ.principal = NULL;  /* Return */
        refetch = 1;
    } else if (ret == 0 && r->materialize &&
               (princ.attributes & KRB5_KDB_VIRTUAL)) {

        ret = strcmp(r->method, "POST") == 0 ? 0 : ENOSYS; /* XXX */

        /*
         * We're writing, but maybe we can't (not a primary) or have to
         * reconnect to a primary kadmind.
         */
        if (ret == 0 && primary_server && !primary_admin_server) {
            /* Local DB, not a primary -> redirect */
            ret = KADM5_READ_ONLY;
        } else if (ret == 0 && primary_admin_server && admin_server) {
            /* Connected to replica -> reconnect to primary */
            kadm5_destroy(r->kadm_handle);
            ret = get_kadm_handle(r->context, &r->kadm_handle, 1);
        }
        princ.attributes |= KRB5_KDB_MATERIALIZE;
        princ.attributes &= ~KRB5_KDB_VIRTUAL;
        /*
         * XXX If there are TL data which should be re-encoded and sent as
         * KRB5_TL_EXTENSION, then this call will fail with KADM5_BAD_TL_TYPE.
         *
         * We should either drop those TLs, re-encode them, or make
         * perform_tl_data() handle them.  (New extensions should generally go
         * as KRB5_TL_EXTENSION so that non-critical ones can be set on
         * principals via old kadmind programs that don't support them.)
         */
        if (ret == 0)
            ret = kadm5_create_principal(r->kadm_handle, &princ, mask, "");
        refetch = 1;
    } /* else create/materialize q-params are superfluous */

    /* Handle rotate / revoke options */
    if (ret == 0 && change) {
        krb5_keyblock *k = NULL;
        size_t i;
        int n_k = 0;
        int keepold = r->revoke ? 0 : 1;

        ret = strcmp(r->method, "POST") == 0 ? 0 : ENOSYS; /* XXX */

        /* Use requested enctypes or same ones as princ already had keys for */
        if (ret == 0 && kstuple == NULL)
            ret = make_kstuple(r->context, &princ, &kstuple, &nkstuple);

        /* Set new keys */
        if (ret == 0)
            ret = kadm5_randkey_principal_3(r->kadm_handle, p, keepold,
                                            nkstuple, kstuple, &k, &n_k);
        refetch = 1;
        for (i = 0; n_k > 0 && i < n_k; i++)
            if (k[i].keyvalue.length)
                memset(k[i].keyvalue.data, 0, k[i].keyvalue.length);
        free(kstuple);
        free(k);
    }

    if (ret == 0 && refetch) {
        /* Refetch changed principal */
        if (freeit)
            kadm5_free_principal_ent(r->kadm_handle, &princ);
        freeit = 0;
        ret = kadm5_get_principal(r->kadm_handle, p, &princ, mask);
        if (ret == 0)
            freeit = 1;
    }

    if (ret == 0)
        ret = write_keytab(r, &princ, pname);
    if (freeit)
        kadm5_free_principal_ent(r->kadm_handle, &princ);
    krb5_free_principal(r->context, p);
    return ret;
}

static krb5_error_code
do_ext_keytab(kadmin_request_desc r)
{
    krb5_error_code ret;
    size_t nhosts;
    size_t nsvcs;
    size_t nspns;
    size_t i, k;

    /* Parses and validates the request, then checks authorization */
    ret = authorize_req(r);
    if (ret)
        return ret; /* authorize_req() calls bad_req() */

    nhosts = heim_array_get_length(r->hostnames);
    nsvcs = heim_array_get_length(r->service_names);
    nspns = heim_array_get_length(r->spns);
    if (!nhosts && !nsvcs && !nspns) {
        krb5_set_error_message(r->context, ret = EINVAL,
                               "No service principals requested");
        return ret;
    }

    if (nhosts && !nsvcs) {
        heim_string_t s;

        if ((s = heim_string_create("HTTP")) == NULL)
            ret = krb5_enomem(r->context);
        if (ret == 0)
            ret = heim_array_append_value(r->service_names, s);
        heim_release(s);
        nsvcs = 1;
    }

    ret = make_keytab(r);

    for (i = 0; ret == 0 && i < nsvcs; i++) {
        const char *svc =
            heim_string_get_utf8(
                heim_array_get_value(r->service_names, i));

        for (k = 0; ret == 0 && k < nhosts; k++) {
            const char *hostname =
                heim_string_get_utf8(
                    heim_array_get_value(r->hostnames, i));
            char *spn = NULL;

            if (asprintf(&spn, "%s/%s", svc, hostname) == -1 ||
                spn == NULL)
                ret = krb5_enomem(r->context);
            if (ret == 0)
                ret = do_ext_keytab1(r, spn);
            free(spn);
        }
    }
    for (i = 0; ret == 0 && i < nspns; i++) {
        ret = do_ext_keytab1(r,
                             heim_string_get_utf8(
                                heim_array_get_value(r->spns, i)));
    }
    return ret;
}

/* Copied from kdc/connect.c */
static void
addr_to_string(krb5_context context,
               struct sockaddr *addr,
               char *str,
               size_t len)
{
    krb5_error_code ret;
    krb5_address a;

    ret = krb5_sockaddr2address(context, addr, &a);
    if (ret == 0) {
        ret = krb5_print_address(&a, str, len, &len);
        krb5_free_address(context, &a);
    }
    if (ret)
        snprintf(str, len, "<family=%d>", addr->sa_family);
}

static krb5_error_code
set_req_desc(struct MHD_Connection *connection,
             const char *method,
             const char *url,
             kadmin_request_desc r)
{
    const union MHD_ConnectionInfo *ci;
    const char *token;
    krb5_error_code ret;

    memset(r, 0, sizeof(*r));
    (void) gettimeofday(&r->tv_start, NULL);

    ret = get_krb5_context(&r->context);
    r->kadm_handle = NULL;
    if (ret == 0)
        ret = get_kadm_handle(r->context, &r->kadm_handle, 0);
    /* HEIM_SVC_REQUEST_DESC_COMMON_ELEMENTS fields */
    r->request.data = "<HTTP-REQUEST>";
    r->request.length = sizeof("<HTTP-REQUEST>");
    r->from = r->frombuf;
    r->config = NULL;
    r->logf = logfac;
    r->reqtype = url;
    r->reason = NULL;
    r->reply = NULL;
    r->sname = NULL;
    r->cname = NULL;
    r->addr = NULL;
    r->kv = heim_array_create();
    /* Our fields */
    r->connection = connection;
    r->hcontext = r->context->hcontext;
    r->service_names = heim_array_create();
    r->hostnames = heim_array_create();
    r->spns = heim_array_create();
    r->keytab_name = NULL;
    r->enctypes = NULL;
    r->freeme1 = NULL;
    r->method = method;
    r->cprinc = NULL;
    r->req = NULL;
    r->sp = NULL;
    ci = MHD_get_connection_info(connection,
                                 MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    if (ci) {
        r->addr = ci->client_addr;
        addr_to_string(r->context, r->addr, r->frombuf, sizeof(r->frombuf));
    }

    if (r->kv) {
        heim_audit_addkv((heim_svc_req_desc)r, 0, "method", "GET");
        heim_audit_addkv((heim_svc_req_desc)r, 0, "endpoint", "%s", r->reqtype);
    }
    token = MHD_lookup_connection_value(r->connection, MHD_HEADER_KIND,
                                        MHD_HTTP_HEADER_AUTHORIZATION);
    if (token && r->kv) {
        const char *token_end;

        if ((token_end = strchr(token, ' ')) == NULL ||
            (token_end - token) > INT_MAX || (token_end - token) < 2)
            heim_audit_addkv((heim_svc_req_desc)r, 0, "auth", "<unknown>");
        else
            heim_audit_addkv((heim_svc_req_desc)r, 0, "auth", "%.*s",
                             (int)(token_end - token), token);

    }

    if (ret == 0 && r->kv == NULL) {
        krb5_log_msg(r->context, logfac, 1, NULL, "Out of memory");
        ret = r->ret = ENOMEM;
    }
    return ret;
}

static void
clean_req_desc(kadmin_request_desc r)
{
    if (!r)
        return;

    if (r->keytab)
        krb5_kt_destroy(r->context, r->keytab);
    if (r->kadm_handle)
        kadm5_destroy(r->kadm_handle);
    hx509_request_free(&r->req);
    heim_release(r->service_names);
    heim_release(r->hostnames);
    heim_release(r->reason);
    heim_release(r->spns);
    heim_release(r->kv);
    krb5_free_principal(r->context, r->cprinc);
    free(r->keytab_name);
    free(r->enctypes);
    free(r->freeme1);
    free(r->cname);
    free(r->sname);
}

/* Implements GETs of /ext_keytab */
static krb5_error_code
ext_keytab(kadmin_request_desc r)
{
    krb5_error_code ret;

    if ((ret = validate_token(r)))
        return ret; /* validate_token() calls bad_req() */
    if (r->cname == NULL || r->cprinc == NULL)
        return bad_403(r, EINVAL,
                       "Could not extract principal name from token");
    switch ((ret = do_ext_keytab(r))) {
    case ENOSYS: /* XXX */
        return bad_method_want_POST(r);
    case KADM5_READ_ONLY:
        krb5_log_msg(r->context, logfac, 1, NULL,
                     "Redirect for %s to primary server to "
                     "materialize or rotate principal", r->cname);
        return resp(r, MHD_HTTP_TEMPORARY_REDIRECT, MHD_RESPMEM_PERSISTENT,
                    NULL, "", 0, NULL, NULL);
    case 0:
        /* Read and send the contents of the PKIX store */
        krb5_log_msg(r->context, logfac, 1, NULL,
                     "Issued service principal keys to %s", r->cname);
        return good_ext_keytab(r);
    default:
        return bad_503(r, ret, "Could not get keys");
    }

}

static krb5_error_code
mac_csrf_token(kadmin_request_desc r, krb5_storage *sp)
{
    kadm5_principal_ent_rec princ;
    krb5_error_code ret;
    krb5_principal p = NULL;
    krb5_data data;
    char mac[EVP_MAX_MD_SIZE];
    unsigned int maclen;
    size_t i;
    int freeit = 0;

    memset(&princ, 0, sizeof(princ));
    ret = krb5_storage_to_data(sp, &data);
    if (ret == 0)
        ret = krb5_parse_name(r->context, "WELLKNOWN/CSRFTOKEN", &p);
    if (ret == 0)
        ret = kadm5_get_principal(r->kadm_handle, p, &princ, 
                                  KADM5_PRINCIPAL | KADM5_KVNO |
                                  KADM5_KEY_DATA);
    if (ret == 0)
        freeit = 1;
    if (ret == 0 && princ.n_key_data < 1)
        ret = KADM5_UNK_PRINC;
    if (ret == 0)
        for (i = 0; i < princ.n_key_data; i++)
            if (princ.key_data[i].key_data_kvno == princ.kvno)
                break;
    if (i == princ.n_key_data)
        i = 0; /* Weird, but can't happen */

    if (ret == 0) {
        (void) HMAC(EVP_sha256(),
                    princ.key_data[i].key_data_contents[0],
                    princ.key_data[i].key_data_length[0],
                    data.data, data.length, mac, &maclen);
        krb5_data_free(&data);
        data.length = maclen;
        data.data = mac;
        if (krb5_storage_write(sp, mac, maclen) != maclen)
            ret = krb5_enomem(r->context);
    }
    krb5_free_principal(r->context, p);
    if (freeit)
        kadm5_free_principal_ent(r->kadm_handle, &princ);
    return ret;
}

static krb5_error_code
make_csrf_token(kadmin_request_desc r,
                const char *given,
                char **token,
                int64_t *age)
{
    static HEIMDAL_THREAD_LOCAL char tokenbuf[128]; /* See below, be sad */
    krb5_error_code ret = 0;
    unsigned char given_decoded[128];
    krb5_storage *sp = NULL;
    krb5_data data;
    ssize_t dlen = -1;
    uint64_t nonce;
    int64_t t = 0;


    *age = 0;
    data.data = NULL;
    data.length = 0;
    if (given) {
        size_t len = strlen(given);

        if (len >= sizeof(given_decoded))
            ret = ERANGE;
        if (ret == 0 && (dlen = rk_base64_decode(given, &given_decoded)) <= 0)
            ret = errno;
        if (ret == 0 &&
            (sp = krb5_storage_from_mem(given_decoded, dlen)) == NULL)
            ret = krb5_enomem(r->context);
        if (ret == 0)
            ret = krb5_ret_int64(sp, &t);
        if (ret == 0)
            ret = krb5_ret_uint64(sp, &nonce);
        krb5_storage_free(sp);
        sp = NULL;
        if (ret == 0)
            *age = time(NULL) - t;
    } else {
        t = time(NULL);
        krb5_generate_random_block((void *)&nonce, sizeof(nonce));
    }

    if (ret == 0 && (sp = krb5_storage_emem()) == NULL)
        ret = krb5_enomem(r->context);
    if (ret == 0)
        ret = krb5_store_int64(sp, t);
    if (ret == 0)
        ret = krb5_store_uint64(sp, nonce);
    if (ret == 0)
        ret = mac_csrf_token(r, sp);
    if (ret == 0)
        ret = krb5_storage_to_data(sp, &data);
    if (ret == 0 && data.length > INT_MAX)
        ret = ERANGE;
    if (ret == 0 &&
        (dlen = rk_base64_encode(data.data, data.length, token)) < 0)
        ret = errno;
    if (ret == 0 && dlen >= sizeof(tokenbuf))
        ret = ERANGE;
    if (ret == 0) {
        /*
         * Work around for older versions of libmicrohttpd do not strdup()ing
         * response header values.
         */
        memcpy(tokenbuf, *token, dlen);
        free(*token);
        *token = tokenbuf;
    }
    krb5_data_free(&data);
    return ret;
}

static krb5_error_code
check_csrf(kadmin_request_desc r)
{
    krb5_error_code ret;
    const char *given;
    int64_t age;
    size_t givenlen, expectedlen;
    char *expected = NULL;

    given = MHD_lookup_connection_value(r->connection, MHD_HEADER_KIND,
                                        "X-CSRF-Token");
    ret = make_csrf_token(r, given, &expected, &age);
    if (ret)
        bad_503(r, ret, "Could not create a CSRF token");
    if (given == NULL) {
        (void) resp(r, MHD_HTTP_FORBIDDEN, MHD_RESPMEM_PERSISTENT, NULL,
                    "Request missing a CSRF token",
                    sizeof("Request missing a CSRF token"), NULL,
                    expected);
        /*
         * XXX Some versions of libmicrohttpd don't strdup() header values
         * added to responses, so we can't free expected.
         */
        /*free(expected); */
        return EACCES;
    }

    /* Validate the CSRF token for this request */
    givenlen = strlen(given);
    expectedlen = strlen(expected);
    if (givenlen != expectedlen || ct_memcmp(given, expected, givenlen)) {
        (void) bad_403(r, EACCES, "Invalid CSRF token");
        return EACCES;
    }
    if (age > 300) { /* XXX */
        (void) bad_403(r, EACCES, "CSRF token too old");
        return EACCES;
    }
    return 0;
}

static krb5_error_code
health(const char *method, kadmin_request_desc r)
{
    if (strcmp(method, "HEAD") == 0)
        return resp(r, MHD_HTTP_OK, MHD_RESPMEM_PERSISTENT, NULL, "", 0, NULL,
                    NULL);
    return resp(r, MHD_HTTP_OK, MHD_RESPMEM_PERSISTENT, NULL,
                "To determine the health of the service, use the /ext_keytab "
                "end-point.\n",
                sizeof("To determine the health of the service, use the "
                       "/ext_keytab end-point.\n") - 1, NULL, NULL);

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
    struct kadmin_request_desc r;
    int ret;

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

    if ((ret = set_req_desc(connection, method, url, &r)))
        return bad_503(&r, ret, "Could not initialize request state");
    if ((strcmp(method, "HEAD") == 0 || strcmp(method, "GET") == 0) &&
        (strcmp(url, "/health") == 0 || strcmp(url, "/") == 0))
        ret = health(method, &r);
    else if (strcmp(method, "GET") != 0 && strcmp(method, "POST") != 0)
        ret = bad_405(&r, method);
    else if (strcmp(method, "POST") == 0 && (ret = check_csrf(&r)))
        ;
    else if (strcmp(url, "/get-keys") == 0)
        ret = ext_keytab(&r);
    else
        ret = bad_404(&r, url);

    clean_req_desc(&r);
    return ret == -1 ? MHD_NO : MHD_YES;
}

static struct getargs args[] = {
    { "help", 'h', arg_flag, &help_flag, "Print usage message", NULL },
    { "version", '\0', arg_flag, &version_flag, "Print version", NULL },
    { NULL, 'H', arg_strings, &audiences,
        "expected token audience(s) of ext_keytab service", "HOSTNAME" },
    { "daemon", 'd', arg_flag, &daemonize, "daemonize", "daemonize" },
    { "daemon-child", 0, arg_flag, &daemon_child_fd, NULL, NULL }, /* priv */
    { "reverse-proxied", 0, arg_flag, &reverse_proxied_flag,
        "reverse proxied", "listen on 127.0.0.1 and do not use TLS" },
    { NULL, 'p', arg_integer, &port, "PORT", "port number (default: 443)" },
    { "cache-dir", 0, arg_string, &cache_dir,
        "cache directory", "DIRECTORY" },
    { "cert", 0, arg_string, &cert_file,
        "certificate file path (PEM)", "HX509-STORE" },
    { "private-key", 0, arg_string, &priv_key_file,
        "private key file path (PEM)", "HX509-STORE" },
    { "thread-per-client", 't', arg_flag, &thread_per_client_flag, "thread per-client", NULL },
    { "realm", 0, arg_string, &realm, "realm", "REALM" },
    { "hdb", 0, arg_string, &hdb, "HDB filename", "PATH" },
    { "admin-client-principal", 0, arg_string, &admin_client_name,
        "Name of client principal for kadmin connection", "PRINC" },
    { "admin-server", 0, arg_string, &admin_server,
        "Name of kadmin server", "HOST[:PORT]" },
    { "primary-admin-server", 0, arg_string, &primary_admin_server,
        "Name of primary kadmin server", "HOST[:PORT]" },
    { "primary-server", 0, arg_string, &primary_server,
        "Name of primary ext_keytab server for redirects", "URL" },
    { "verbose", 'v', arg_counter, &verbose_counter, "verbose", "run verbosely" }
};

static int
usage(int e)
{
    arg_printusage(args, sizeof(args) / sizeof(args[0]), "ext_keytab",
        "\nServes RESTful GETs of /ext_keytab and /bnegotiate,\n"
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

static void
my_openlog(krb5_context context,
           const char *svc,
           krb5_log_facility **fac)
{
    char **s = NULL, **p;

    krb5_initlog(context, "httpkadmind", fac);
    s = krb5_config_get_strings(context, NULL, svc, "logging", NULL);
    if (s == NULL)
        s = krb5_config_get_strings(context, NULL, "logging", svc, NULL);
    if (s) {
        for(p = s; *p; p++)
            krb5_addlog_dest(context, *fac, *p);
        krb5_config_free_strings(s);
    } else {
        char *ss;
        if (asprintf(&ss, "0-1/FILE:%s/%s", hdb_db_dir(context),
            KDC_LOG_FILE) < 0)
            err(1, "out of memory");
        krb5_addlog_dest(context, *fac, ss);
        free(ss);
    }
    krb5_set_warn_dest(context, *fac);
}

static const char *sysplugin_dirs[] =  {
#ifdef _WIN32
    "$ORIGIN",
#else
    "$ORIGIN/../lib/plugin/kdc",
#endif
#ifdef __APPLE__
    LIBDIR "/plugin/kdc",
#endif
    NULL
};

static void
load_plugins(krb5_context context)
{
    const char * const *dirs = sysplugin_dirs;
#ifndef _WIN32
    char **cfdirs;

    cfdirs = krb5_config_get_strings(context, NULL, "kdc", "plugin_dir", NULL);
    if (cfdirs)
        dirs = (const char * const *)cfdirs;
#endif

    /* XXX kdc? */
    _krb5_load_plugins(context, "kdc", (const char **)dirs);

#ifndef _WIN32
    krb5_config_free_strings(cfdirs);
#endif
}

int
main(int argc, char **argv)
{
    unsigned int flags = MHD_USE_THREAD_PER_CONNECTION; /* XXX */
    struct sockaddr_in sin;
    struct MHD_Daemon *previous = NULL;
    struct MHD_Daemon *current = NULL;
    struct sigaction sa;
    krb5_context context = NULL;
    MHD_socket sock = MHD_INVALID_SOCKET;
    void *kadm_handle;
    char *priv_key_pem = NULL;
    char *cert_pem = NULL;
    char sig;
    int optidx = 0;
    int ret;

    setprogname("httpkadmind");
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

    if (audiences.num_strings == 0) {
        char localhost[MAXHOSTNAMELEN];

        ret = gethostname(localhost, sizeof(localhost));
        if (ret == -1)
            errx(1, "Could not determine local hostname; use --audience");

        if ((audiences.strings =
                 calloc(1, sizeof(audiences.strings[0]))) == NULL ||
            (audiences.strings[0] = strdup(localhost)) == NULL)
            err(1, "Out of memory");
        audiences.num_strings = 1;
    }

    if (daemonize && daemon_child_fd == -1)
        daemon_child_fd = roken_detach_prep(argc, argv, "--daemon-child");
    daemonize = 0;

    argc -= optidx;
    argv += optidx;

    if ((errno = pthread_key_create(&k5ctx, k5_free_context)))
        err(1, "Could not create thread-specific storage");

    if ((errno = get_krb5_context(&context)))
        err(1, "Could not init krb5 context (config file issue?)");

    if ((errno = get_kadm_handle(context, &kadm_handle, 0)))
        err(1, "Could not connect to HDB");
    kadm5_destroy(kadm_handle);

    my_openlog(context, "httpkadmind", &logfac);
    load_plugins(context);

    if (cache_dir == NULL) {
        char *s = NULL;

        if (asprintf(&s, "%s/httpkadmind-XXXXXX",
                     getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp") == -1 ||
            s == NULL ||
            (cache_dir = mkdtemp(s)) == NULL)
            err(1, "could not create temporary cache directory");
        if (verbose_counter)
            fprintf(stderr, "Note: using %s as cache directory\n", cache_dir);
        atexit(rm_cache_dir);
        setenv("TMPDIR", cache_dir, 1);
    }

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

        ret = hx509_certs_init(context->hx509ctx, cert_file, 0, NULL, &certs);
        if (ret == 0)
            ret = hx509_certs_start_seq(context->hx509ctx, certs, &cursor);
        while (ret == 0 &&
               (ret = hx509_certs_next_cert(context->hx509ctx, certs,
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
        if (certs)
            (void) hx509_certs_end_seq(context->hx509ctx, certs, cursor);
        if (min_cert_life > 4)
            alarm(min_cert_life >> 1);
        hx509_certs_free(&certs);
        if (ret)
            hx509_err(context->hx509ctx, 1, ret,
                      "could not read certificate from %s", cert_file);

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

        if ((errno = rk_undumpdata(priv_key_file, &s, &len)) ||
            (priv_key_pem = strndup(s, len)) == NULL)
            err(1, "could not read private key from %s", priv_key_file);
        if (strlen(priv_key_pem) != len)
            err(1, "NULs in private key file contents: %s", priv_key_file);
        free(s);
    }

    if (verbose_counter > 1)
        flags |= MHD_USE_DEBUG;
    if (thread_per_client_flag)
        flags |= MHD_USE_THREAD_PER_CONNECTION;


    if (pipe(sigpipe) == -1)
        err(1, "Could not set up key/cert reloading");
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sighandler;
    if (reverse_proxied_flag) {
        /*
         * We won't use TLS in the reverse proxy case, so no need to reload
         * certs.  But we'll still read them if given, and alarm() will get
         * called.
         */
        (void) signal(SIGHUP, SIG_IGN);
        (void) signal(SIGUSR1, SIG_IGN);
        (void) signal(SIGALRM, SIG_IGN);
    } else {
        (void) sigaction(SIGHUP, &sa, NULL);    /* Reload key & cert */
        (void) sigaction(SIGUSR1, &sa, NULL);   /* Reload key & cert */
        (void) sigaction(SIGALRM, &sa, NULL);   /* Reload key & cert */
    }
    (void) sigaction(SIGINT, &sa, NULL);    /* Graceful shutdown */
    (void) sigaction(SIGTERM, &sa, NULL);   /* Graceful shutdown */
    (void) signal(SIGPIPE, SIG_IGN);

    if (previous)
        sock = MHD_quiesce_daemon(previous);

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
                                   route, (char *)NULL,
                                   MHD_OPTION_SOCK_ADDR, &sin,
                                   MHD_OPTION_CONNECTION_LIMIT, (unsigned int)200,
                                   MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)10,
                                   MHD_OPTION_END);
    } else if (sock != MHD_INVALID_SOCKET) {
        /*
         * Certificate/key rollover: reuse the listen socket returned by
         * MHD_quiesce_daemon().
         */
        current = MHD_start_daemon(flags | MHD_USE_SSL, port,
                                   NULL, NULL,
                                   route, (char *)NULL,
                                   MHD_OPTION_HTTPS_MEM_KEY, priv_key_pem,
                                   MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
                                   MHD_OPTION_CONNECTION_LIMIT, (unsigned int)200,
                                   MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)10,
                                   MHD_OPTION_LISTEN_SOCKET, sock,
                                   MHD_OPTION_END);
        sock = MHD_INVALID_SOCKET;
    } else {
        current = MHD_start_daemon(flags | MHD_USE_SSL, port,
                                   NULL, NULL,
                                   route, (char *)NULL,
                                   MHD_OPTION_HTTPS_MEM_KEY, priv_key_pem,
                                   MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
                                   MHD_OPTION_CONNECTION_LIMIT, (unsigned int)200,
                                   MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)10,
                                   MHD_OPTION_END);
    }
    if (current == NULL)
        err(1, "Could not start ext_keytab REST service");

    if (previous) {
        MHD_stop_daemon(previous);
        previous = NULL;
    }

    if (verbose_counter)
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
    _krb5_unload_plugins(context, "kdc");
    pthread_key_delete(k5ctx);
    return 0;
}
