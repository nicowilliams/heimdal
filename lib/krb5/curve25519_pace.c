/*
 * Copyright (c) 2003 - 2007 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
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

#include "krb5_locl.h"

#ifdef CURVE25519_PACE

extern int curve25519(u8 *mypublic, const u8 *secret, const u8 *basepoint);
extern int curve25519_pacemap(u8 *mypublic, const u8 *secret,
			      const u8 *basepoint, const u8 *mappoint);


#include <asn1_err.h>
#include <der.h>

static krb5_error_code
curve_mk_padata(krb5_context context,
		krb5_pk_init_ctx ctx,
		const KDC_REQ_BODY *req_body,
		unsigned nonce,
		METHOD_DATA *md,
		krb5_data *in)
{
}


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_curve_mk_padata(krb5_context context,
		      void *c,
		      int ic_flags,
		      int win2k,
		      const KDC_REQ_BODY *req_body,
		      unsigned nonce,
		      METHOD_DATA *md)
{
}


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_pk_rd_pa_reply(krb5_context context,
		     const char *realm,
		     void *c,
		     krb5_enctype etype,
		     const krb5_krbhst_info *hi,
		     unsigned nonce,
		     const krb5_data *req_buffer,
		     PA_DATA *pa,
		     krb5_keyblock **key)
{
}


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_pk_load_id(krb5_context context,
		 struct krb5_pk_identity **ret_id,
		 const char *user_id,
		 const char *anchor_id,
		 char * const *chain_list,
		 char * const *revoke_list,
		 krb5_prompter_fct prompter,
		 void *prompter_data,
		 char *password)
{
}


#endif /* CURVE25519_PACE */
