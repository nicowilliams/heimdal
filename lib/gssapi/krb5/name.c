/*
 * Copyright (c) 2014 Cryptonector LLC
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

#include "gsskrb5_locl.h"

krb5_const_principal GSSAPI_CALLCONV
_gsskrb5_name2pname(gsskrb5_const_name name)
{
    return ((gsskrb5_name)name)->princ;
}

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_make_name2(OM_uint32 *minor_status,
                    krb5_context ctx,
                    krb5_principal orig,
                    gsskrb5_name *name)
{
    return _gsskrb5_make_name(minor_status, ctx, orig, (gss_name_t *)name);
}

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_make_name(OM_uint32 *minor_status,
                   krb5_context ctx,
                   krb5_principal orig,
                   gss_name_t *name)
{
    krb5_error_code ret;
    gsskrb5_name new_name = calloc(1, sizeof(*new_name));

    if (new_name == NULL) {
        *minor_status = krb5_enomem(ctx);
        return GSS_S_FAILURE;
    }

    ret = krb5_copy_principal(ctx, orig, &new_name->princ);
    if (ret != 0) {
        *minor_status = ret;
        return GSS_S_FAILURE;
    }

    new_name->ticket = NULL;
    new_name->ticket_enc_part = NULL;
    new_name->requested_attrs = NULL;
    new_name->cached_attrs = NULL;

    *name = (gss_name_t)new_name;

    *minor_status = 0;
    return GSS_S_COMPLETE;
}
