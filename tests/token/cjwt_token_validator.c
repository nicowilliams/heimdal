#define _DEFAULT_SOURCE
#define _GNU_SOURCE
#define _BSD_SOURCE

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <string.h>
#include <krb5.h>
#include <hdb.h>
#include <roken.h>
#include <token_validator_plugin.h>
#include <cjwt/cjwt.h>

int
token_validate(const char *realm,
               const char *plugin_config,
               const char *token_kind,
               const char *requested_principal,
               const char *token,
               size_t token_size,
               char **actual_principal,
               char **errstr)
{
    heim_octet_string issuer_pubkey;
    const char *p;
    cjwt_t *jwt = NULL;
    char *freeme = NULL;
    int ret;

    *actual_principal = NULL;
    *errstr = NULL;

    if (strnlen(token, token_size) == token_size) {
        if ((freeme = strndup(token, token_size)) == NULL)
            return ENOMEM;
        token = freeme;
    }

    ret = rk_undumpdata(plugin_config, &issuer_pubkey.data,
                        &issuer_pubkey.length);
    if (ret) {
        free(freeme);
        (void) asprintf(errstr, "could not read issuer key %s", plugin_config);
        return ret;
    }

    ret = cjwt_decode(token, 0, &jwt, issuer_pubkey.data,
                      issuer_pubkey.length);
    free(freeme);
    token = NULL;
    switch (ret) {
    case -1:
        *errstr = strdup("invalid jwt format");
        return EINVAL;
    case -2:
        *errstr = strdup("signature validation failed (wrong issuer)");
        return EPERM;
    case 0: break;
    default:
        *errstr = strdup(strerror(ret));
        return ret;
    }

    /* Success; extract principal name */
    if (jwt->sub == NULL) {
        cjwt_destroy(&jwt);
        *errstr = strdup("missing claim");
        return EACCES;
    }

    /* XXX Sanity-check more of the decoded JWT */

    if ((p = strchr(jwt->sub, '@'))) {
        /* XXX We probably don't want any of this */
        if (realm && strcasecmp(strchr(jwt->sub, '@') + 1, realm)) {
            *errstr = strdup("wrong realm");
            ret = EACCES;
        } else if (!realm) {
            ret = ((*actual_principal = strdup(jwt->sub))) ? 0 : ENOMEM;
        } else if (asprintf(actual_principal, "%.*s@%s",
                     (int)(p - jwt->sub), jwt->sub, realm) == -1 ||
            *actual_principal == NULL) {
            ret = ENOMEM;
        } else {
            ret = 0;
        }
    } else if (asprintf(actual_principal, "%s@%s", jwt->sub, realm) == -1 ||
            *actual_principal == NULL) {
        ret = ENOMEM;
    } else {
        ret = 0;
    }
    cjwt_destroy(&jwt);
    return ret;
}

void
token_free_name(char **actual_principal)
{
    free(*actual_principal);
    *actual_principal = NULL;
}
