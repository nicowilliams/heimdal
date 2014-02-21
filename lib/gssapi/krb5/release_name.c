/*
 * Copyright (c) 1997 - 2003 Kungliga Tekniska Högskolan
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

#include "gsskrb5_locl.h"

static void free_name_attrs(OM_uint32 *, struct gsskrb5_name_attr **);

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_free_name(OM_uint32 *minor_status,
                   krb5_context context,
                   gss_name_t *input_name)
{
    return _gsskrb5_free_name2(minor_status, context,
                               (gsskrb5_name *)input_name);
}

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_free_name2(OM_uint32 *minor_status,
                   krb5_context context,
                   gsskrb5_name *input_name)
{
    gsskrb5_name name = *input_name;

    if (name == NULL)
        return GSS_S_COMPLETE;

    krb5_free_principal(context, name->princ);
    if (name->ticket_enc_part != NULL)
        krb5_free_ticket(context, name->ticket_enc_part);
    if (name->authenticator != NULL)
        krb5_free_authenticator(context, &name->authenticator);
    free_name_attrs(minor_status, name->requested_attrs);
    free_name_attrs(minor_status, name->cached_attrs);
    free(name->requested_attrs);
    free(name->cached_attrs);

    *(gss_name_t *)input_name = GSS_C_NO_NAME;
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_release_name(OM_uint32 *minor_status, gss_name_t *input_name)
{
    krb5_context context;

    *minor_status = 0;
    if (input_name == NULL)
        return GSS_S_COMPLETE;

    GSSAPI_KRB5_INIT (&context);

    return _gsskrb5_free_name(minor_status, context, input_name);
}

static void
free_name_attrs(OM_uint32 *minor_status, struct gsskrb5_name_attr **attrs)
{
    struct gsskrb5_name_attr **a;

    for (a = attrs; a != NULL && *a != NULL; a++) {
        free((*a)->attr);
        _gsskrb5_release_buffer(minor_status, &(*a)->value);
        _gsskrb5_release_buffer(minor_status, &(*a)->display_value);
    }
}
