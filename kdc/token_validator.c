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

#include "kdc_locl.h"
#include "token_validator_plugin.h"

struct plctx {
    const char              *realm;
    const char              *token_kind;
    krb5_data               *token;
    krb5_const_principal    on_behalf_of;
    krb5_boolean            result;
    krb5_principal          actual_principal;
    char                    *errstr;
};

static krb5_error_code KRB5_LIB_CALL
plcallback(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    const krb5plugin_token_validator_ftable *locate = plug;
    krb5_error_code ret;
    struct plctx *plctx = userctx;
    void (KRB5_LIB_CALL *freestr)(char **);
    char *e = NULL;

    ret = locate->validate(plugctx, context, plctx->realm,
                            plctx->token_kind, plctx->token,
                            plctx->on_behalf_of,
                            &plctx->result,
                            &plctx->actual_principal,
                            &e, &freestr);

    if (e) {
        free(plctx->errstr);
        plctx->errstr = strdup(e);
    }
    if (freestr)
        freestr(&e);
    if (ret) {
        krb5_free_principal(context, plctx->actual_principal);
        plctx->actual_principal = NULL;
    }
    return ret;
}

static const char *plugin_deps[] = { "krb5", NULL };

static struct krb5_plugin_data token_validator_data = {
    "kdc",
    KDC_PLUGIN_BEARER,
    1,
    plugin_deps,
    krb5_get_instance
};

/*
 * Invoke a plugin to validate a JWT/SAML/OIDC token and partially-evaluate
 * access control.
 */
krb5_error_code
kdc_validate_token(krb5_context context, const char *realm,
                   const char *token_kind, krb5_data *token,
                   krb5_const_principal on_behalf_of,
                   krb5_principal *actual_cprincipal)
{
    krb5_error_code ret;
    struct plctx ctx;

    ctx.realm = realm;
    ctx.on_behalf_of = on_behalf_of;
    ctx.token_kind = token_kind;
    ctx.token = token;
    ctx.result = FALSE;
    ctx.actual_principal = NULL;
    ctx.errstr = NULL;

    ret = _krb5_plugin_run_f(context, &token_validator_data, 0, &ctx,
                             plcallback);
    if (ret) {
        krb5_set_error_message(context, ret, "token validation failed: %s",
                               ctx.errstr ? ctx.errstr : "<unspecified>");
        free(ctx.errstr);
        return ret;
    }
    free(ctx.errstr);
    if (!ctx.result)
        return EACCES;
    return 0;
}
