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

OM_uint32 GSSAPI_CALLCONV _gsskrb5_duplicate_name (
            OM_uint32 * minor_status,
            gss_const_name_t src_name,
            gss_name_t * dest_name
           )
{
    gsskrb5_const_name src = (gsskrb5_const_name)src_name;
    krb5_context context;
    gsskrb5_name dest;
    krb5_error_code kret;

    GSSAPI_KRB5_INIT (&context);

    dest = calloc(1, sizeof(*dest));
    if (dest == NULL) {
        *minor_status = krb5_enomem(context);
        return GSS_S_FAILURE;
    }
    dest->authenticator = NULL;
    dest->ticket_enc_part = NULL;
    dest->requested_attrs = NULL;
    dest->cached_attrs = NULL;


    kret = krb5_copy_principal(context, src->princ, &dest->princ);
    if (kret) {
	*minor_status = kret;
	return GSS_S_FAILURE;
    }

    /* XXX copy the rest: ticket, ticket enc part, and requested attributes! */
    *dest_name = (gss_name_t)dest;
    *minor_status = 0;
    return GSS_S_COMPLETE;
}
