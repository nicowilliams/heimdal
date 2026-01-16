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

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

/*
 * Key names for gss_acquire_cred_from() cred_store parameter
 *
 * Initiator (client) keys - for obtaining JWT from STS:
 *   "sts-endpoint"   - STS token endpoint URL (required for initiator)
 *   "cred-type"      - Credential type: "auto", "password", "kerberos", "jwt", "certificate"
 *   "username"       - Username for password authentication
 *   "password"       - Password (inline - NOT RECOMMENDED for production)
 *   "password-file"  - File containing password (more secure)
 *   "ccache"         - Kerberos ccache name for Negotiate auth to STS
 *   "token-file"     - File containing JWT (for KSAT, GSAT, or pre-obtained token)
 *   "token"          - JWT string directly (for testing, alternative to token-file)
 *   "certificate"    - hx509 certificate store URI for client cert auth
 *   "private-key"    - hx509 private key store URI for client cert auth
 *   "trust-anchors"  - CA certificates for validating STS TLS connection
 *
 * Acceptor (server) keys - for validating received JWTs:
 *   "jwks-uri"       - JWKS endpoint URL for fetching public keys
 *   "signing-key"    - JWK JSON string for direct key validation (testing)
 *   "issuer"         - Expected JWT issuer ("iss" claim)
 *   "trust-anchors"  - CA certificates for validating JWKS endpoint TLS
 *
 * TLS protection keys (when CONF_FLAG, INTEG_FLAG, or MUTUAL_FLAG requested):
 *   "tls-certificate" - TLS certificate for acceptor-side TLS
 *   "tls-private-key" - TLS private key for acceptor-side TLS
 */
#define GSS_JWT_CRED_STS_ENDPOINT       "sts-endpoint"
#define GSS_JWT_CRED_STS_METHOD         "sts-method"
#define GSS_JWT_CRED_TYPE               "cred-type"
#define GSS_JWT_CRED_USERNAME           "username"
#define GSS_JWT_CRED_PASSWORD           "password"
#define GSS_JWT_CRED_PASSWORD_FILE      "password-file"
#define GSS_JWT_CRED_CCACHE             "ccache"
#define GSS_JWT_CRED_TOKEN_FILE         "token-file"
#define GSS_JWT_CRED_TOKEN              "token"
#define GSS_JWT_CRED_CERTIFICATE        "certificate"
#define GSS_JWT_CRED_PRIVATE_KEY        "private-key"
#define GSS_JWT_CRED_TRUST_ANCHORS      "trust-anchors"
#define GSS_JWT_CRED_JWKS_URI           "jwks-uri"
#define GSS_JWT_CRED_SIGNING_KEY        "signing-key"
#define GSS_JWT_CRED_ISSUER             "issuer"
#define GSS_JWT_CRED_TLS_CERTIFICATE    "tls-certificate"
#define GSS_JWT_CRED_TLS_PRIVATE_KEY    "tls-private-key"

/* Forward declarations for hx509 private APIs we need */
HX509_LIB_FUNCTION hx509_private_key HX509_LIB_CALL
_hx509_cert_private_key(hx509_cert);
HX509_LIB_FUNCTION void HX509_LIB_CALL
_hx509_private_key_ref(hx509_private_key);

/*
 * Tracing support via GSS_JWT_TRACE environment variable
 *
 * Set GSS_JWT_TRACE to a log specification (e.g., "STDERR", "FILE:/tmp/trace.log")
 * to enable debug tracing of the GSS-JWT mechanism.
 */
static inline void
gss_jwt_trace_init(heim_context *hctx)
{
    const char *trace;

    *hctx = NULL;
    trace = secure_getenv("GSS_JWT_TRACE");
    if (trace && *trace) {
        *hctx = heim_context_init();
        if (*hctx)
            heim_add_debug_dest(*hctx, "gss-jwt", trace);
    }
}

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
 * Parse credential type string to enum
 */
static jwt_cred_type
parse_cred_type(const char *type_str)
{
    if (type_str == NULL || strcasecmp(type_str, "auto") == 0)
        return JWT_CRED_AUTO;
    if (strcasecmp(type_str, "password") == 0)
        return JWT_CRED_PASSWORD;
    if (strcasecmp(type_str, "kerberos") == 0 ||
        strcasecmp(type_str, "negotiate") == 0)
        return JWT_CRED_KERBEROS;
    if (strcasecmp(type_str, "jwt") == 0 ||
        strcasecmp(type_str, "token") == 0)
        return JWT_CRED_JWT;
    if (strcasecmp(type_str, "certificate") == 0 ||
        strcasecmp(type_str, "cert") == 0)
        return JWT_CRED_CERTIFICATE;

    /* Unknown type, default to auto */
    return JWT_CRED_AUTO;
}

/*
 * Parse STS method string to enum
 *
 * Valid values:
 *   "auto" - Try GET first, fall back to POST (default)
 *   "get"  - GET request only (metadata service style)
 *   "post" - POST request only (OAuth 2.0 RFC 8693 style)
 */
static jwt_sts_method
parse_sts_method(const char *method_str)
{
    if (method_str == NULL || strcasecmp(method_str, "auto") == 0)
        return JWT_STS_METHOD_AUTO;
    if (strcasecmp(method_str, "get") == 0)
        return JWT_STS_METHOD_GET;
    if (strcasecmp(method_str, "post") == 0)
        return JWT_STS_METHOD_POST;

    /* Unknown method, default to auto */
    return JWT_STS_METHOD_AUTO;
}

/*
 * Read file contents into a newly allocated string
 * Returns 0 on success, errno on failure
 */
static int
read_file_contents(const char *filename, char **contents, size_t *length)
{
    struct stat st;
    int fd;
    ssize_t n;
    char *buf;

    *contents = NULL;
    if (length)
        *length = 0;

    fd = open(filename, O_RDONLY);
    if (fd < 0)
        return errno;

    if (fstat(fd, &st) < 0) {
        int saved_errno = errno;
        close(fd);
        return saved_errno;
    }

    /* Sanity check - don't read huge files */
    if (st.st_size > 1024 * 1024) {
        close(fd);
        return EFBIG;
    }

    buf = malloc(st.st_size + 1);
    if (buf == NULL) {
        close(fd);
        return ENOMEM;
    }

    n = read(fd, buf, st.st_size);
    close(fd);

    if (n < 0) {
        int saved_errno = errno;
        free(buf);
        return saved_errno;
    }

    buf[n] = '\0';

    /* Strip trailing newlines (common for password files) */
    while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r')) {
        buf[--n] = '\0';
    }

    *contents = buf;
    if (length)
        *length = n;
    return 0;
}

/*
 * GSS-API acquire_cred_from for JWT mechanism
 *
 * Acquires a JWT credential from the specified stores.
 *
 * For initiators (clients):
 *   - Parses credential configuration for obtaining JWTs from STS
 *   - Does NOT obtain the JWT yet - that happens in init_sec_context
 *     when we know the target (audience)
 *
 * For acceptors (servers):
 *   - Parses configuration for validating incoming JWTs
 *   - Sets up JWKS URI and expected issuer
 */
OM_uint32 GSSAPI_CALLCONV
_gss_jwt_acquire_cred_from(OM_uint32 *minor,
                           gss_const_name_t desired_name,
                           OM_uint32 time_req,
                           gss_OID_set desired_mechs,
                           gss_cred_usage_t cred_usage,
                           gss_const_key_value_set_t cred_store,
                           gss_cred_id_t *output_cred,
                           gss_OID_set *actual_mechs,
                           OM_uint32 *time_rec)
{
    gss_jwt_cred cred = NULL;
    const char *sts_endpoint = NULL;
    const char *cred_type_str = NULL;
    const char *username = NULL;
    const char *password = NULL;
    const char *password_file = NULL;
    const char *ccache = NULL;
    const char *token_file = NULL;
    const char *cert_store = NULL;
    const char *key_store = NULL;
    const char *anchor_store = NULL;
    const char *jwks_uri = NULL;
    const char *issuer = NULL;
    int ret;

    (void)desired_name; /* Name is derived from JWT subject */
    (void)time_req;     /* Credentials don't expire (tokens do) */
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
    gss_jwt_trace_init(&cred->hctx);
    heim_debug(cred->hctx, 5, "GSS-JWT: acquiring %s credential",
               cred_usage == GSS_C_INITIATE ? "initiator" :
               cred_usage == GSS_C_ACCEPT ? "acceptor" : "both");

    /* Parse credential store parameters */
    sts_endpoint = find_cred_store_value(cred_store, GSS_JWT_CRED_STS_ENDPOINT);
    cred_type_str = find_cred_store_value(cred_store, GSS_JWT_CRED_TYPE);
    username = find_cred_store_value(cred_store, GSS_JWT_CRED_USERNAME);
    password = find_cred_store_value(cred_store, GSS_JWT_CRED_PASSWORD);
    password_file = find_cred_store_value(cred_store, GSS_JWT_CRED_PASSWORD_FILE);
    ccache = find_cred_store_value(cred_store, GSS_JWT_CRED_CCACHE);
    token_file = find_cred_store_value(cred_store, GSS_JWT_CRED_TOKEN_FILE);
    {
        const char *token_inline = find_cred_store_value(cred_store, GSS_JWT_CRED_TOKEN);
        if (token_inline) {
            /* Direct token takes precedence over token-file */
            cred->token = strdup(token_inline);
            if (cred->token == NULL) {
                *minor = ENOMEM;
                goto fail;
            }
            heim_debug(cred->hctx, 5, "GSS-JWT: using inline token");
        }
    }
    cert_store = find_cred_store_value(cred_store, GSS_JWT_CRED_CERTIFICATE);
    key_store = find_cred_store_value(cred_store, GSS_JWT_CRED_PRIVATE_KEY);
    anchor_store = find_cred_store_value(cred_store, GSS_JWT_CRED_TRUST_ANCHORS);
    jwks_uri = find_cred_store_value(cred_store, GSS_JWT_CRED_JWKS_URI);
    issuer = find_cred_store_value(cred_store, GSS_JWT_CRED_ISSUER);

    /* Parse credential type */
    cred->cred_type = parse_cred_type(cred_type_str);
    heim_debug(cred->hctx, 5, "GSS-JWT: credential type: %s",
               cred->cred_type == JWT_CRED_AUTO ? "auto" :
               cred->cred_type == JWT_CRED_PASSWORD ? "password" :
               cred->cred_type == JWT_CRED_KERBEROS ? "kerberos" :
               cred->cred_type == JWT_CRED_JWT ? "jwt" :
               cred->cred_type == JWT_CRED_CERTIFICATE ? "certificate" : "unknown");

    /* Parse STS request method */
    {
        const char *sts_method_str = find_cred_store_value(cred_store, GSS_JWT_CRED_STS_METHOD);
        cred->sts_method = parse_sts_method(sts_method_str);
        heim_debug(cred->hctx, 5, "GSS-JWT: STS method: %s",
                   cred->sts_method == JWT_STS_METHOD_AUTO ? "auto" :
                   cred->sts_method == JWT_STS_METHOD_GET ? "get" :
                   cred->sts_method == JWT_STS_METHOD_POST ? "post" : "unknown");
    }

    /* Store STS endpoint */
    if (sts_endpoint) {
        cred->sts_endpoint = strdup(sts_endpoint);
        if (cred->sts_endpoint == NULL) {
            *minor = ENOMEM;
            goto fail;
        }
        heim_debug(cred->hctx, 5, "GSS-JWT: STS endpoint: %s", sts_endpoint);
    }

    /* Store username */
    if (username) {
        cred->username = strdup(username);
        if (cred->username == NULL) {
            *minor = ENOMEM;
            goto fail;
        }
        heim_debug(cred->hctx, 5, "GSS-JWT: username: %s", username);
    }

    /* Load password from file or inline */
    if (password_file) {
        cred->password_file = strdup(password_file);
        if (cred->password_file == NULL) {
            *minor = ENOMEM;
            goto fail;
        }
        ret = read_file_contents(password_file, &cred->password, NULL);
        if (ret) {
            heim_debug(cred->hctx, 1, "GSS-JWT: failed to read password file %s: %s",
                       password_file, strerror(ret));
            *minor = ret;
            goto fail;
        }
        heim_debug(cred->hctx, 5, "GSS-JWT: loaded password from file");
    } else if (password) {
        cred->password = strdup(password);
        if (cred->password == NULL) {
            *minor = ENOMEM;
            goto fail;
        }
        heim_debug(cred->hctx, 5, "GSS-JWT: using inline password");
    }

    /* Store ccache name */
    if (ccache) {
        cred->ccache = strdup(ccache);
        if (cred->ccache == NULL) {
            *minor = ENOMEM;
            goto fail;
        }
        heim_debug(cred->hctx, 5, "GSS-JWT: ccache: %s", ccache);
    }

    /* Load token from file (for KSAT, GSAT, or pre-obtained JWT) */
    /* Only if not already set via inline token */
    if (token_file && cred->token == NULL) {
        cred->token_file = strdup(token_file);
        if (cred->token_file == NULL) {
            *minor = ENOMEM;
            goto fail;
        }
        ret = read_file_contents(token_file, &cred->token, NULL);
        if (ret) {
            heim_debug(cred->hctx, 1, "GSS-JWT: failed to read token file %s: %s",
                       token_file, strerror(ret));
            *minor = ret;
            goto fail;
        }
        heim_debug(cred->hctx, 5, "GSS-JWT: loaded token from file");
    }

    /* Load certificates and keys if using certificate authentication */
    if (cert_store || key_store) {
        ret = hx509_context_init(&cred->hx509ctx);
        if (ret) {
            heim_debug(cred->hctx, 1, "GSS-JWT: hx509_context_init failed: %d", ret);
            *minor = ret;
            goto fail;
        }

        if (cert_store) {
            heim_debug(cred->hctx, 5, "GSS-JWT: loading certificate from %s", cert_store);
            ret = hx509_certs_init(cred->hx509ctx, cert_store, 0, NULL,
                                   &cred->client_certs);
            if (ret) {
                heim_debug(cred->hctx, 1, "GSS-JWT: failed to load certificate: %d", ret);
                *minor = ret;
                goto fail;
            }
        }

        if (key_store) {
            hx509_certs key_certs;
            hx509_cursor cursor;
            hx509_cert cert_with_key;

            heim_debug(cred->hctx, 5, "GSS-JWT: loading private key from %s", key_store);

            ret = hx509_certs_init(cred->hx509ctx, key_store, 0, NULL, &key_certs);
            if (ret) {
                heim_debug(cred->hctx, 1, "GSS-JWT: failed to load private key: %d", ret);
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
                        cred->client_key = _hx509_cert_private_key(cert_with_key);
                        if (cred->client_key) {
                            _hx509_private_key_ref(cred->client_key);
                            heim_debug(cred->hctx, 5, "GSS-JWT: extracted private key");
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
    }

    /* Load trust anchors for TLS connections (to STS or JWKS endpoint) */
    if (anchor_store) {
        if (cred->hx509ctx == NULL) {
            ret = hx509_context_init(&cred->hx509ctx);
            if (ret) {
                *minor = ret;
                goto fail;
            }
        }
        heim_debug(cred->hctx, 5, "GSS-JWT: loading trust anchors from %s", anchor_store);
        ret = hx509_certs_init(cred->hx509ctx, anchor_store, 0, NULL,
                               &cred->trust_anchors);
        if (ret) {
            heim_debug(cred->hctx, 1, "GSS-JWT: failed to load trust anchors: %d", ret);
            *minor = ret;
            goto fail;
        }
    }

    /* Load TLS certificate and key for acceptor-side TLS protection */
    {
        const char *tls_cert_store = find_cred_store_value(cred_store, GSS_JWT_CRED_TLS_CERTIFICATE);
        const char *tls_key_store = find_cred_store_value(cred_store, GSS_JWT_CRED_TLS_PRIVATE_KEY);

        if (tls_cert_store || tls_key_store) {
            if (cred->hx509ctx == NULL) {
                ret = hx509_context_init(&cred->hx509ctx);
                if (ret) {
                    *minor = ret;
                    goto fail;
                }
            }

            if (tls_cert_store) {
                heim_debug(cred->hctx, 5, "GSS-JWT: loading TLS certificate from %s", tls_cert_store);
                ret = hx509_certs_init(cred->hx509ctx, tls_cert_store, 0, NULL,
                                       &cred->tls_certs);
                if (ret) {
                    heim_debug(cred->hctx, 1, "GSS-JWT: failed to load TLS certificate: %d", ret);
                    *minor = ret;
                    goto fail;
                }
            }

            if (tls_key_store) {
                hx509_certs key_certs;
                hx509_cursor cursor;
                hx509_cert cert_with_key;

                heim_debug(cred->hctx, 5, "GSS-JWT: loading TLS private key from %s", tls_key_store);

                ret = hx509_certs_init(cred->hx509ctx, tls_key_store, 0, NULL, &key_certs);
                if (ret) {
                    heim_debug(cred->hctx, 1, "GSS-JWT: failed to load TLS private key: %d", ret);
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
                            cred->tls_key = _hx509_cert_private_key(cert_with_key);
                            if (cred->tls_key) {
                                _hx509_private_key_ref(cred->tls_key);
                                heim_debug(cred->hctx, 5, "GSS-JWT: extracted TLS private key");
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
        }
    }

    /* Store JWKS URI for server-side validation */
    if (jwks_uri) {
        cred->jwks_uri = strdup(jwks_uri);
        if (cred->jwks_uri == NULL) {
            *minor = ENOMEM;
            goto fail;
        }
        heim_debug(cred->hctx, 5, "GSS-JWT: JWKS URI: %s", jwks_uri);
    }

    /* Store signing key (JWK) for direct validation (testing) */
    {
        const char *signing_key = find_cred_store_value(cred_store,
                                                        GSS_JWT_CRED_SIGNING_KEY);
        if (signing_key) {
            /* Store JWK in cache dictionary */
            cred->jwks_cache = heim_dict_create(10);
            if (cred->jwks_cache == NULL) {
                *minor = ENOMEM;
                goto fail;
            }
            heim_string_t jwk_str = heim_string_create(signing_key);
            if (jwk_str == NULL) {
                *minor = ENOMEM;
                goto fail;
            }
            heim_dict_set_value(cred->jwks_cache, HSTR("jwk"), jwk_str);
            heim_release(jwk_str);
            heim_debug(cred->hctx, 5, "GSS-JWT: signing key configured");
        }
    }

    /* Store expected issuer for server-side validation */
    if (issuer) {
        cred->expected_issuer = strdup(issuer);
        if (cred->expected_issuer == NULL) {
            *minor = ENOMEM;
            goto fail;
        }
        heim_debug(cred->hctx, 5, "GSS-JWT: expected issuer: %s", issuer);
    }

    /* Validate credential configuration */
    if (cred_usage == GSS_C_INITIATE || cred_usage == GSS_C_BOTH) {
        /*
         * Initiator needs either:
         * - STS endpoint (to obtain JWT from STS), or
         * - Direct token (for testing without STS)
         */
        if (!cred->sts_endpoint && !cred->token) {
            heim_debug(cred->hctx, 1, "GSS-JWT: initiator credential requires sts-endpoint or token");
            *minor = EINVAL;
            goto fail;
        }
        if (cred->token && !cred->sts_endpoint) {
            heim_debug(cred->hctx, 5, "GSS-JWT: using direct token (no STS)");
        }

        /* Check that we have at least one way to authenticate to STS */
        /* Skip this check if using direct token without STS */
        if (cred->sts_endpoint && cred->cred_type == JWT_CRED_AUTO) {
            /* Auto mode - check what credentials are available */
            int have_creds = 0;
            if (cred->username && cred->password)
                have_creds = 1;
            if (cred->ccache)
                have_creds = 1;
            if (cred->token)
                have_creds = 1;
            if (cred->client_certs && cred->client_key)
                have_creds = 1;

            if (!have_creds) {
                heim_debug(cred->hctx, 1, "GSS-JWT: no credentials configured for STS authentication");
                *minor = EINVAL;
                goto fail;
            }
        } else if (cred->sts_endpoint) {
            /* Specific credential type - validate that type is configured */
            switch (cred->cred_type) {
            case JWT_CRED_PASSWORD:
                if (!cred->username || !cred->password) {
                    heim_debug(cred->hctx, 1, "GSS-JWT: password auth requires username and password");
                    *minor = EINVAL;
                    goto fail;
                }
                break;
            case JWT_CRED_KERBEROS:
                /* ccache is optional - will use default if not specified */
                break;
            case JWT_CRED_JWT:
                if (!cred->token) {
                    heim_debug(cred->hctx, 1, "GSS-JWT: jwt/token auth requires token-file");
                    *minor = EINVAL;
                    goto fail;
                }
                break;
            case JWT_CRED_CERTIFICATE:
                if (!cred->client_certs || !cred->client_key) {
                    heim_debug(cred->hctx, 1, "GSS-JWT: certificate auth requires certificate and private-key");
                    *minor = EINVAL;
                    goto fail;
                }
                break;
            default:
                break;
            }
        }
    }

    if (cred_usage == GSS_C_ACCEPT || cred_usage == GSS_C_BOTH) {
        /* Acceptor needs JWKS URI or signing key to validate tokens */
        if (!cred->jwks_uri && !cred->jwks_cache) {
            heim_debug(cred->hctx, 1, "GSS-JWT: acceptor credential requires jwks-uri or signing-key");
            *minor = EINVAL;
            goto fail;
        }
    }

    /* Return mechanism OID set if requested */
    if (actual_mechs) {
        OM_uint32 maj;
        maj = gss_create_empty_oid_set(minor, actual_mechs);
        if (maj != GSS_S_COMPLETE)
            goto fail;
        maj = gss_add_oid_set_member(minor, GSS_JWT_MECHANISM, actual_mechs);
        if (maj != GSS_S_COMPLETE) {
            gss_release_oid_set(minor, actual_mechs);
            goto fail;
        }
    }

    heim_debug(cred->hctx, 5, "GSS-JWT: credential acquired successfully");

    *output_cred = (gss_cred_id_t)cred;
    return GSS_S_COMPLETE;

fail:
    heim_debug(cred->hctx, 1, "GSS-JWT: credential acquisition failed");
    _gss_jwt_release_cred(minor, (gss_cred_id_t *)&cred);
    return GSS_S_FAILURE;
}
