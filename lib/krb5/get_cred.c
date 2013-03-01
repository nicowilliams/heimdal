/*
 * Copyright (c) 1997 - 2008 Kungliga Tekniska Högskolan
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
#include <assert.h>

static krb5_error_code
get_credentials_with_flags(krb5_context context,
                           size_t *tgs_limit,
                           krb5_flags options,
                           krb5_kdc_flags flags,
                           krb5_ccache ccache,
                           krb5_creds *in_creds,
                           krb5_creds **out_creds);

/*
 * Take the `body' and encode it into `padata' using the credentials
 * in `creds'.
 */

static krb5_error_code
make_pa_tgs_req(krb5_context context,
		krb5_auth_context ac,
		KDC_REQ_BODY *body,
		PA_DATA *padata,
		krb5_creds *creds)
{
    u_char *buf;
    size_t buf_size;
    size_t len = 0;
    krb5_data in_data;
    krb5_error_code ret;

    ASN1_MALLOC_ENCODE(KDC_REQ_BODY, buf, buf_size, body, &len, ret);
    if (ret)
	goto out;
    if(buf_size != len)
	krb5_abortx(context, "internal error in ASN.1 encoder");

    in_data.length = len;
    in_data.data   = buf;
    ret = _krb5_mk_req_internal(context, &ac, 0, &in_data, creds,
				&padata->padata_value,
				KRB5_KU_TGS_REQ_AUTH_CKSUM,
				KRB5_KU_TGS_REQ_AUTH);
 out:
    free (buf);
    if(ret)
	return ret;
    padata->padata_type = KRB5_PADATA_TGS_REQ;
    return 0;
}

/*
 * Set the `enc-authorization-data' in `req_body' based on `authdata'
 */

static krb5_error_code
set_auth_data (krb5_context context,
	       KDC_REQ_BODY *req_body,
	       krb5_authdata *authdata,
	       krb5_keyblock *subkey)
{
    if(authdata->len) {
	size_t len = 0, buf_size;
	unsigned char *buf;
	krb5_crypto crypto;
	krb5_error_code ret;

	ASN1_MALLOC_ENCODE(AuthorizationData, buf, buf_size, authdata,
			   &len, ret);
	if (ret)
	    return ret;
	if (buf_size != len)
	    krb5_abortx(context, "internal error in ASN.1 encoder");

	ALLOC(req_body->enc_authorization_data, 1);
	if (req_body->enc_authorization_data == NULL) {
	    free (buf);
	    return krb5_enomem(context);
	}
	ret = krb5_crypto_init(context, subkey, 0, &crypto);
	if (ret) {
	    free (buf);
	    free (req_body->enc_authorization_data);
	    req_body->enc_authorization_data = NULL;
	    return ret;
	}
	krb5_encrypt_EncryptedData(context,
				   crypto,
				   KRB5_KU_TGS_REQ_AUTH_DAT_SUBKEY,
				   buf,
				   len,
				   0,
				   req_body->enc_authorization_data);
	free (buf);
	krb5_crypto_destroy(context, crypto);
    } else {
	req_body->enc_authorization_data = NULL;
    }
    return 0;
}

/*
 * Create a tgs-req in `t' with `addresses', `flags', `second_ticket'
 * (if not-NULL), `in_creds', `krbtgt', and returning the generated
 * subkey in `subkey'.
 */

static krb5_error_code
init_tgs_req (krb5_context context,
	      krb5_ccache ccache,
	      krb5_addresses *addresses,
	      krb5_kdc_flags flags,
	      Ticket *second_ticket,
	      krb5_creds *in_creds,
	      krb5_creds *krbtgt,
	      unsigned nonce,
	      const METHOD_DATA *padata,
	      krb5_keyblock **subkey,
	      TGS_REQ *t)
{
    krb5_auth_context ac = NULL;
    krb5_error_code ret = 0;

    memset(t, 0, sizeof(*t));
    t->pvno = 5;
    t->msg_type = krb_tgs_req;
    if (in_creds->session.keytype) {
	ALLOC_SEQ(&t->req_body.etype, 1);
	if(t->req_body.etype.val == NULL) {
	    ret = krb5_enomem(context);
	    goto fail;
	}
	t->req_body.etype.val[0] = in_creds->session.keytype;
    } else {
	ret = _krb5_init_etype(context,
			       KRB5_PDU_TGS_REQUEST,
			       &t->req_body.etype.len,
			       &t->req_body.etype.val,
			       NULL);
    }
    if (ret)
	goto fail;
    t->req_body.addresses = addresses;
    t->req_body.kdc_options = flags.b;
    t->req_body.kdc_options.forwardable = krbtgt->flags.b.forwardable;
    t->req_body.kdc_options.renewable = krbtgt->flags.b.renewable;
    t->req_body.kdc_options.proxiable = krbtgt->flags.b.proxiable;
    ret = copy_Realm(&in_creds->server->realm, &t->req_body.realm);
    if (ret)
	goto fail;
    ALLOC(t->req_body.sname, 1);
    if (t->req_body.sname == NULL) {
	ret = krb5_enomem(context);
	goto fail;
    }

    /* some versions of some code might require that the client be
       present in TGS-REQs, but this is clearly against the spec */

    ret = copy_PrincipalName(&in_creds->server->name, t->req_body.sname);
    if (ret)
	goto fail;

    if (krbtgt->times.starttime) {
        ALLOC(t->req_body.from, 1);
        if(t->req_body.from == NULL){
            ret = krb5_enomem(context);
            goto fail;
        }
        *t->req_body.from = in_creds->times.starttime;
    }

    /* req_body.till should be NULL if there is no endtime specified,
       but old MIT code (like DCE secd) doesn't like that */
    ALLOC(t->req_body.till, 1);
    if(t->req_body.till == NULL){
	ret = krb5_enomem(context);
	goto fail;
    }
    *t->req_body.till = in_creds->times.endtime;

    if (t->req_body.kdc_options.renewable && krbtgt->times.renew_till) {
        ALLOC(t->req_body.rtime, 1);
        if(t->req_body.rtime == NULL){
            ret = krb5_enomem(context);
            goto fail;
        }
        *t->req_body.rtime = in_creds->times.renew_till;
    }

    t->req_body.nonce = nonce;
    if(second_ticket){
	ALLOC(t->req_body.additional_tickets, 1);
	if (t->req_body.additional_tickets == NULL) {
	    ret = krb5_enomem(context);
	    goto fail;
	}
	ALLOC_SEQ(t->req_body.additional_tickets, 1);
	if (t->req_body.additional_tickets->val == NULL) {
	    ret = krb5_enomem(context);
	    goto fail;
	}
	ret = copy_Ticket(second_ticket, t->req_body.additional_tickets->val);
	if (ret)
	    goto fail;
    }
    ALLOC(t->padata, 1);
    if (t->padata == NULL) {
	ret = krb5_enomem(context);
	goto fail;
    }
    ALLOC_SEQ(t->padata, 1 + padata->len);
    if (t->padata->val == NULL) {
	ret = krb5_enomem(context);
	goto fail;
    }
    {
	size_t i;
	for (i = 0; i < padata->len; i++) {
	    ret = copy_PA_DATA(&padata->val[i], &t->padata->val[i + 1]);
	    if (ret) {
		krb5_set_error_message(context, ret,
				       N_("malloc: out of memory", ""));
		goto fail;
	    }
	}
    }

    ret = krb5_auth_con_init(context, &ac);
    if(ret)
	goto fail;

    ret = krb5_auth_con_generatelocalsubkey(context, ac, &krbtgt->session);
    if (ret)
	goto fail;

    ret = set_auth_data (context, &t->req_body, &in_creds->authdata,
			 ac->local_subkey);
    if (ret)
	goto fail;

    ret = make_pa_tgs_req(context,
			  ac,
			  &t->req_body,
			  &t->padata->val[0],
			  krbtgt);
    if(ret)
	goto fail;

    ret = krb5_auth_con_getlocalsubkey(context, ac, subkey);
    if (ret)
	goto fail;

fail:
    if (ac)
	krb5_auth_con_free(context, ac);
    if (ret) {
	t->req_body.addresses = NULL;
	free_TGS_REQ (t);
    }
    return ret;
}

krb5_error_code
_krb5_get_krbtgt(krb5_context context,
		 krb5_ccache  id,
		 krb5_realm realm,
		 krb5_creds **cred)
{
    krb5_error_code ret;
    krb5_creds tmp_cred;

    memset(&tmp_cred, 0, sizeof(tmp_cred));

    ret = krb5_cc_get_principal(context, id, &tmp_cred.client);
    if (ret)
	return ret;

    ret = krb5_make_principal(context,
			      &tmp_cred.server,
			      realm,
			      KRB5_TGS_NAME,
			      realm,
			      NULL);
    if(ret) {
	krb5_free_principal(context, tmp_cred.client);
	return ret;
    }
    ret = krb5_get_credentials(context,
			       KRB5_GC_CACHED,
			       id,
			       &tmp_cred,
			       cred);
    krb5_free_principal(context, tmp_cred.client);
    krb5_free_principal(context, tmp_cred.server);
    if(ret)
	return ret;
    return 0;
}

/* DCE compatible decrypt proc */
static krb5_error_code KRB5_CALLCONV
decrypt_tkt_with_subkey (krb5_context context,
			 krb5_keyblock *key,
			 krb5_key_usage usage,
			 krb5_const_pointer skey,
			 krb5_kdc_rep *dec_rep)
{
    const krb5_keyblock *subkey = skey;
    krb5_error_code ret = 0;
    krb5_data data;
    size_t size;
    krb5_crypto crypto;

    assert(usage == 0);

    krb5_data_zero(&data);

    /*
     * start out with trying with subkey if we have one
     */
    if (subkey) {
	ret = krb5_crypto_init(context, subkey, 0, &crypto);
	if (ret)
	    return ret;
	ret = krb5_decrypt_EncryptedData (context,
					  crypto,
					  KRB5_KU_TGS_REP_ENC_PART_SUB_KEY,
					  &dec_rep->kdc_rep.enc_part,
					  &data);
	/*
	 * If the is Windows 2000 DC, we need to retry with key usage
	 * 8 when doing ARCFOUR.
	 */
	if (ret && subkey->keytype == ETYPE_ARCFOUR_HMAC_MD5) {
	    ret = krb5_decrypt_EncryptedData(context,
					     crypto,
					     8,
					     &dec_rep->kdc_rep.enc_part,
					     &data);
	}
	krb5_crypto_destroy(context, crypto);
    }
    if (subkey == NULL || ret) {
	ret = krb5_crypto_init(context, key, 0, &crypto);
	if (ret)
	    return ret;
	ret = krb5_decrypt_EncryptedData (context,
					  crypto,
					  KRB5_KU_TGS_REP_ENC_PART_SESSION,
					  &dec_rep->kdc_rep.enc_part,
					  &data);
	krb5_crypto_destroy(context, crypto);
    }
    if (ret)
	return ret;

    ret = decode_EncASRepPart(data.data,
			      data.length,
			      &dec_rep->enc_part,
			      &size);
    if (ret)
	ret = decode_EncTGSRepPart(data.data,
				   data.length,
				   &dec_rep->enc_part,
				   &size);
    if (ret)
      krb5_set_error_message(context, ret,
			     N_("Failed to decode encpart in ticket", ""));
    krb5_data_free (&data);
    return ret;
}

static krb5_error_code
get_cred_kdc(krb5_context context,
	     krb5_ccache id,
	     krb5_kdc_flags flags,
	     krb5_addresses *addresses,
	     krb5_creds *in_creds,
	     krb5_creds *krbtgt,
	     krb5_principal impersonate_principal,
	     Ticket *second_ticket,
	     krb5_creds *out_creds)
{
    TGS_REQ req;
    krb5_data enc;
    krb5_data resp;
    krb5_kdc_rep rep;
    KRB_ERROR error;
    krb5_error_code ret;
    unsigned nonce;
    krb5_keyblock *subkey = NULL;
    size_t len = 0;
    Ticket second_ticket_data;
    METHOD_DATA padata;

    krb5_data_zero(&resp);
    krb5_data_zero(&enc);
    padata.val = NULL;
    padata.len = 0;

    krb5_generate_random_block(&nonce, sizeof(nonce));
    nonce &= 0xffffffff;

    if(flags.b.enc_tkt_in_skey && second_ticket == NULL){
	ret = decode_Ticket(in_creds->second_ticket.data,
			    in_creds->second_ticket.length,
			    &second_ticket_data, &len);
	if(ret)
	    return ret;
	second_ticket = &second_ticket_data;
    }


    if (impersonate_principal) {
	krb5_crypto crypto;
	PA_S4U2Self self;
	krb5_data data;
	void *buf;
	size_t size = 0;

	self.name = impersonate_principal->name;
	self.realm = impersonate_principal->realm;
	self.auth = estrdup("Kerberos");

	ret = _krb5_s4u2self_to_checksumdata(context, &self, &data);
	if (ret) {
	    free(self.auth);
	    goto out;
	}

	ret = krb5_crypto_init(context, &krbtgt->session, 0, &crypto);
	if (ret) {
	    free(self.auth);
	    krb5_data_free(&data);
	    goto out;
	}

	ret = krb5_create_checksum(context,
				   crypto,
				   KRB5_KU_OTHER_CKSUM,
				   0,
				   data.data,
				   data.length,
				   &self.cksum);
	krb5_crypto_destroy(context, crypto);
	krb5_data_free(&data);
	if (ret) {
	    free(self.auth);
	    goto out;
	}

	ASN1_MALLOC_ENCODE(PA_S4U2Self, buf, len, &self, &size, ret);
	free(self.auth);
	free_Checksum(&self.cksum);
	if (ret)
	    goto out;
	if (len != size)
	    krb5_abortx(context, "internal asn1 error");

	ret = krb5_padata_add(context, &padata, KRB5_PADATA_FOR_USER, buf, len);
	if (ret)
	    goto out;
    }

    ret = init_tgs_req (context,
			id,
			addresses,
			flags,
			second_ticket,
			in_creds,
			krbtgt,
			nonce,
			&padata,
			&subkey,
			&req);
    if (ret)
	goto out;

    ASN1_MALLOC_ENCODE(TGS_REQ, enc.data, enc.length, &req, &len, ret);
    if (ret)
	goto out;
    if(enc.length != len)
	krb5_abortx(context, "internal error in ASN.1 encoder");

    /* don't free addresses */
    req.req_body.addresses = NULL;
    free_TGS_REQ(&req);

    /*
     * Send and receive
     */
    {
	krb5_sendto_ctx stctx;
	ret = krb5_sendto_ctx_alloc(context, &stctx);
	if (ret)
	    return ret;
	krb5_sendto_ctx_set_func(stctx, _krb5_kdc_retry, NULL);

	ret = krb5_sendto_context (context, stctx, &enc,
				   krbtgt->server->name.name_string.val[1],
				   &resp);
	krb5_sendto_ctx_free(context, stctx);
    }
    if(ret)
	goto out;

    memset(&rep, 0, sizeof(rep));
    if(decode_TGS_REP(resp.data, resp.length, &rep.kdc_rep, &len) == 0) {
	unsigned eflags = 0;

	ret = krb5_copy_principal(context,
				  in_creds->client,
				  &out_creds->client);
	if(ret)
	    goto out2;
	ret = krb5_copy_principal(context,
				  in_creds->server,
				  &out_creds->server);
	if(ret)
	    goto out2;
	/* this should go someplace else */
	out_creds->times.endtime = in_creds->times.endtime;

	/* XXX should do better testing */
	if (flags.b.constrained_delegation || impersonate_principal)
	    eflags |= EXTRACT_TICKET_ALLOW_CNAME_MISMATCH;

	ret = _krb5_extract_ticket(context,
				   &rep,
				   out_creds,
				   &krbtgt->session,
				   NULL,
				   0,
				   &krbtgt->addresses,
				   nonce,
				   eflags,
				   NULL,
				   decrypt_tkt_with_subkey,
				   subkey);
    out2:
	krb5_free_kdc_rep(context, &rep);
    } else if(krb5_rd_error(context, &resp, &error) == 0) {
	ret = krb5_error_from_rd_error(context, &error, in_creds);
	krb5_free_error_contents(context, &error);
    } else if(resp.length > 0 && ((char*)resp.data)[0] == 4) {
	ret = KRB5KRB_AP_ERR_V4_REPLY;
	krb5_clear_error_message(context);
    } else {
	ret = KRB5KRB_AP_ERR_MSG_TYPE;
	krb5_clear_error_message(context);
    }

out:
    if (second_ticket == &second_ticket_data)
	free_Ticket(&second_ticket_data);
    free_METHOD_DATA(&padata);
    krb5_data_free(&resp);
    krb5_data_free(&enc);
    if(subkey)
	krb5_free_keyblock(context, subkey);
    return ret;

}

/*
 * same as above, just get local addresses first if the krbtgt have
 * them and the realm is not addressless
 */

static krb5_error_code
get_cred_kdc_address(krb5_context context,
		     krb5_ccache id,
		     krb5_kdc_flags flags,
		     krb5_addresses *addrs,
		     krb5_creds *in_creds,
		     krb5_creds *krbtgt,
		     krb5_principal impersonate_principal,
		     Ticket *second_ticket,
		     krb5_creds *out_creds)
{
    krb5_error_code ret;
    krb5_addresses addresses = { 0, NULL };

    /*
     * Inherit the address-ness of the krbtgt if the address is not
     * specified.
     */

    if (addrs == NULL && krbtgt->addresses.len != 0) {
	krb5_boolean noaddr;

	krb5_appdefault_boolean(context, NULL, krbtgt->server->realm,
				"no-addresses", FALSE, &noaddr);

	if (!noaddr) {
	    krb5_get_all_client_addrs(context, &addresses);
	    /* XXX this sucks. */
	    addrs = &addresses;
	    if(addresses.len == 0)
		addrs = NULL;
	}
    }
    ret = get_cred_kdc(context, id, flags, addrs, in_creds,
		       krbtgt, impersonate_principal,
		       second_ticket, out_creds);
    krb5_free_addresses(context, &addresses);
    return ret;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_kdc_cred(krb5_context context,
		  krb5_ccache id,
		  krb5_kdc_flags flags,
		  krb5_addresses *addresses,
		  Ticket  *second_ticket,
		  krb5_creds *in_creds,
		  krb5_creds **out_creds
		  )
{
    krb5_error_code ret;
    krb5_creds *krbtgt;

    *out_creds = calloc(1, sizeof(**out_creds));
    if(*out_creds == NULL)
	return krb5_enomem(context);
    ret = _krb5_get_krbtgt (context,
			    id,
			    in_creds->server->realm,
			    &krbtgt);
    if(ret) {
	free(*out_creds);
	*out_creds = NULL;
	return ret;
    }
    ret = get_cred_kdc(context, id, flags, addresses,
		       in_creds, krbtgt, NULL, NULL, *out_creds);
    krb5_free_creds (context, krbtgt);
    if(ret) {
	free(*out_creds);
	*out_creds = NULL;
    }
    return ret;
}

static int
not_found(krb5_context context, krb5_const_principal p, krb5_error_code code)
{
    krb5_error_code ret;
    char *str;

    ret = krb5_unparse_name(context, p, &str);
    if(ret) {
	krb5_clear_error_message(context);
	return code;
    }
    krb5_set_error_message(context, code,
			   N_("Matching credential (%s) not found", ""), str);
    free(str);
    return code;
}

static krb5_error_code
find_cred(krb5_context context,
	  krb5_ccache id,
	  krb5_principal server,
	  krb5_creds **tgts,
	  krb5_creds **out_creds)
{
    krb5_error_code ret;
    krb5_creds mcreds, ocreds;

    krb5_cc_clear_mcred(&mcreds);
    mcreds.server = server;
    ret = krb5_cc_retrieve_cred(context, id, KRB5_TC_DONT_MATCH_REALM,
				&mcreds, &ocreds);
    if (ret == 0) {
        ret = krb5_copy_creds(context, &ocreds, out_creds);
        krb5_free_cred_contents(context, &ocreds);
        return ret;
    }
    while (tgts && *tgts){
	if (krb5_compare_creds(context, KRB5_TC_DONT_MATCH_REALM,
			       &mcreds, *tgts)){
	    ret = krb5_copy_creds(context, *tgts, out_creds);
	    return ret;
	}
	tgts++;
    }
    return not_found(context, server, KRB5_CC_NOTFOUND);
}

static krb5_error_code
add_cred(krb5_context context, krb5_creds const *tkt, krb5_creds ***tgts)
{
    size_t i;
    krb5_error_code ret;
    krb5_creds **tmp = *tgts;

    for (i = 0; tmp && tmp[i]; i++)
        ; /* XXX */
    tmp = realloc(tmp, (i+2)*sizeof(*tmp));
    if (tmp == NULL)
	return krb5_enomem(context);
    *tgts = tmp;
    ret = krb5_copy_creds(context, tkt, &tmp[i]);
    tmp[i+1] = NULL;
    return ret;
}


static krb5_error_code
concat_realms(krb5_context context,
              krb5_realm **list1,
              krb5_realm *list2)
{
    size_t i, k;
    krb5_realm *tmp;

    if (!list2)
        return 0;

    for (i = 0; (*list1)[i]; i++)
        ;
    for (k = 0; list2[k]; k++)
        ;

    tmp = realloc(*list1, (i + k + 1) * sizeof (**list1));
    if (!tmp)
        return krb5_enomem(context);

    for (k = 0; list2[k]; k++) {
        tmp[i++] = list2[k];
        list2[k] = NULL;
    }
    tmp[i] = NULL;
    (void) krb5_free_host_realm(context, list2);

    *list1 = tmp;
    return 0;
}

static krb5_error_code
add_realm(krb5_context context, krb5_realm **realms, krb5_realm realm)
{
    krb5_realm *tmp;
    size_t i;

    for (i = 0; (*realms)[i]; i++)
        ;

    /* No overflow here; i will be small */
    tmp = realloc(*realms, (i + 1) * sizeof (**realms));
    if (!tmp)
        goto enomem;

    tmp[i + 1] = NULL;
    tmp[i] = strdup(realm);
    if (tmp[i]) {
        *realms = tmp;
        return 0;
    }

enomem:
    return krb5_enomem(context);
}

/* Helper for get_start_realms(), when the target is a krbtgt */
static krb5_error_code
get_capath_realms(krb5_context context,
                  krb5_realm crealm,
                  krb5_realm tgtrealm,
                  krb5_realm **realms_out)
{
    krb5_error_code ret;
    char **capaths_realms;
    krb5_realm *realms = NULL;
    size_t i;

    errno = 0;
    capaths_realms = krb5_config_get_strings(context, NULL, "capaths",
                                             crealm, tgtrealm, NULL);
    if (errno)
        return errno; /* XXX Do better, like krb5_enomem() for ENOMEM */

    for (i = 0; capaths_realms && capaths_realms[i]; i++) {
        if (strcmp(capaths_realms[i], ".") == 0) {
            ret = add_realm(context, &realms, capaths_realms[i]);
            if (ret)
                goto err;
            break;
        }
    }

    /*
     * If capaths_realms == NULL we should work out the last hop realm
     * of the hierarchical path to the target and add that realm to the
     * list here.  Because the whole algorithm is recursive we'll end up
     * computing the whole path, one hop at a time.  Of course, here we
     * really need to know what the current starting realm is, and... we
     * don't.
     */

    krb5_config_free_strings(capaths_realms);

    return 0;

err:
    krb5_config_free_strings(capaths_realms);
    return ret;
}

/*
 * Helper for get_cred_kdc_referral(), figures out at what realms to
 * start looking for the in_creds->server.
 */
static krb5_error_code
get_start_realms(krb5_context context,
                 krb5_creds *in_creds,
                 krb5_realm **realms_out)
{
    krb5_error_code ret;
    krb5_realm *realms, *ref_realms;
    size_t is_tgt;

    is_tgt = krb5_principal_is_krbtgt(context, in_creds->server);

    ret = krb5_get_referral_realms(context, &ref_realms);
    if (ret)
        goto err;

    /*
     * We'll have at least the client realm, we may also have whatever
     * realm the in_creds->server already has, and a terminating NULL.
     */
    realms = calloc(2, sizeof (*realms));
    if (!realms)
        return krb5_enomem(context);

    /*
     * If the server principal is not a krbtgt and has a non-empty
     * (not a "referral") realm, then we should start there (but maybe
     * this should be configurable?).  That will mean we'll go looking
     * for a krbtgt/<that-realm>, which will mean we'll find ourselves
     * here again, but this time with an empty realm.
     */
    if (!is_tgt && in_creds->server->realm && *in_creds->server->realm) {
        ret = add_realm(context, &realms, in_creds->server->realm);
        if (ret)
            goto err;
    }

    ret = add_realm(context, &realms, in_creds->server->realm);
    if (ret)
        goto err;

    if (is_tgt) {
        /*
         * A krbtgt, so try to find a realm to ask for a ticket for this
         * krbtgt using [capaths].
         */
        ret = get_capath_realms(context, in_creds->client->realm,
                                in_creds->server->name.name_string.val[1],
                                &realms);
        if (ret)
            goto err;
    } else if (in_creds->server->name.name_string.len >= 2 &&
        in_creds->server->name.name_type == KRB5_NT_SRV_HST) {

        krb5_realm *host_realms;

        /*
         * A host-based service principal.  Get realm from
         * [domain_realm], DNS even.
         */
        ret = krb5_get_host_realm(context,
                                  in_creds->server->name.name_string.val[1],
                                  &host_realms);
        if (ret)
            goto err;

        ret = concat_realms(context, &realms, host_realms);
        if (ret)
            goto err;
    }

    /* Now append referral realms (default realms if not) to realms */
    if (ref_realms && *ref_realms) {
        ret = concat_realms(context, &realms, ref_realms);
        if (ret)
            goto err;
    }

    *realms_out = realms;
    return 0;

err:
    return ret;
}

struct referral_state {
    krb5_principal  tgtname;
    krb5_creds      ask_for;
    krb5_creds      ask_for_tgt;
    krb5_creds      ask_for_better;
    krb5_creds      ticket;
    krb5_creds      final_ticket;  /* to be output */
    krb5_creds      *better_tgt;
    krb5_creds      *tgt;
};

static void
cleanup_referral_state(krb5_context context, struct referral_state *s)
{
    krb5_free_principal(context, s->tgtname);
    krb5_free_principal(context, s->ask_for.server);
    krb5_free_principal(context, s->ask_for_tgt.server);
    krb5_free_principal(context, s->ask_for_better.server);
    s->tgtname = NULL;
    s->ask_for.server = NULL;
    s->ask_for_tgt.server = NULL;
    s->ask_for_better.server = NULL;

    krb5_free_cred_contents(context, &s->ticket);
    krb5_free_cred_contents(context, &s->final_ticket);
    memset(&s->final_ticket, 0, sizeof(s->final_ticket));
    memset(&s->ticket, 0, sizeof(s->ticket));

    krb5_free_creds(context, s->tgt);
    krb5_free_creds(context, s->better_tgt);
    s->tgt = NULL;
    s->better_tgt = NULL;
}

static krb5_error_code
get_cred_kdc_referral(krb5_context context,
                      size_t *tgs_limit,
		      krb5_kdc_flags flags,
		      krb5_ccache ccache,
		      krb5_creds *in_creds,
		      krb5_principal impersonate_principal,
		      Ticket *second_ticket,
		      krb5_creds **out_creds,
		      krb5_creds ***ret_tgts)
{
    krb5_realm *realms;
    krb5_error_code ret, ret2;
    struct referral_state s;
    int ok_as_delegate = 1;
    size_t i;

    krb5_creds mcreds;
    char *referral_realm;

    if (*tgs_limit == 0)
        return KRB5_GET_IN_TKT_LOOP;

    *out_creds = NULL;

    /*
     * Given some service principal name, either foo@BAR or foo@ we want
     * to try the following variants:
     *
     *  - foo@CLIENT PRINC's REALM
     *  - foo@CONFIGURED DEFAULT REALM(s) (if not the same as above)
     *  - foo@GIVEN REALM (if foo is not a krbtgt)
     *  - foo@<get realm(s) from domain_realm or DNS if foo is host-based>
     *        (multiple domain_realm entries are allowed for each domain)
     *  - foo@<get last hop realm from capaths or hierarchical if foo is
     *         a krbtgt>
     *
     * get_start_realms() puts together the list of "start realms".
     *
     * As we go we'll need a TGT for each of those realms.  We'll
     * recurse if need be to get one.
     *
     * At any point we may get a referral, both when trying to get a
     * ticket for in_creds->server and when trying to get a TGT so we
     * can ask for a ticket for in_creds->server.  When we get a
     * referral we recurse to try to get a better (and cacheable) TGT,
     * and if we don't get one we use (but don't cache) the referral
     * TGT.  This algorithm is recursive in nature and can take care of
     * capaths and hierarchical paths in the absence of referrals.
     *
     * We finish when we first get a ticket for in_creds->server, or
     * when *tgs_limit reaches zero.  We decrement *tgs_limit once
     * per-principal we do TGS exchanges for (not per-TGS exchange).
     */
    ret = get_start_realms(context, in_creds, &realms);
    if (ret)
        return ret; /* likely ENOMEM */

    memset(&s, 0, sizeof(s)); /* loop state */
    for (i = 0; realms[i]; i++) {
        /* Cleanup from previous loop */
        cleanup_referral_state(context, &s);

        /*
         * We'll need to get a tgt for the realm we're trying now (this
         * is likely cached already, as the very first start realm will
         * be the client principal's, and they're quite likely to have a
         * cached TGT for their realm).  Make the krbtgt name for this.
         */
	ret = krb5_make_principal(context, &s.tgtname,
				  "", /* find_cred() ignores this anyways */
				  KRB5_TGS_NAME,
				  realms[i],
				  NULL);
	if(ret)
	    break;

        /*
         * Setup a krb5_creds based on the in_creds but with the current
         * start realm as the realm of the target server.
         */
        s.ask_for = *in_creds;
        s.ask_for.server = NULL;
        ret = krb5_copy_principal(context, in_creds->server, &s.ask_for.server);
        if (ret)
            goto out;
        ret = krb5_principal_set_realm(context, s.ask_for.server, realms[i]);
        if (ret)
            goto out;

        if (impersonate_principal == NULL || flags.b.constrained_delegation) {
            krb5_cc_clear_mcred(&mcreds);
            mcreds.server = s.ask_for.server;
            ret = krb5_cc_retrieve_cred(context, ccache, 0, &mcreds, &s.ticket);
            if (!ret)
                goto out; /* Found the one we were looking for in the ccache */
        }

        /*
         * We didn't find a ticket in the ccache.  Try asking realms[i]
         * for one.  Count the upcoming TGS exchange, even if it fails
         * because the realm's KDCs are unreachable, and count it once
         * even if there are retransmissions.
         */

        /*
         * Look for the TGT for the current realm from the ccache.  It's
         * OK if we don't find one: we'll end up trying to get a TGT to
         * get to the current start realm, so we can start the referrals
         * chase there.  After all, the point of the start realm list is
         * to ask realms we trust most first.
         */
	ret = find_cred(context, ccache, s.tgtname, *ret_tgts, &s.tgt);
	if (ret && ret != KRB5_CC_NOTFOUND)
            break;

        /*
         * Setup a krb5_creds based on the in_creds but with the current
         * start realm as the realm of the target server.
         *
         * Should we setup any s.ask_for_tgt.flags?
         */
        s.ask_for_tgt.client = in_creds->client;
        s.ask_for_tgt.server = NULL;
        ret = krb5_copy_principal(context, s.tgtname, &s.ask_for_tgt.server);
        if (ret)
            goto out;
        ret = krb5_principal_set_realm(context, s.ask_for.server, realms[i]);
        if (ret)
            goto out;

        /* Re-enter to get the TGT we need */
        ret = get_credentials_with_flags(context, tgs_limit,
                                         KRB5_GC_DONT_MATCH_REALM,
                                         flags, ccache,
                                         &s.ask_for_tgt,
                                         &s.tgt);/* XXX wrong */
        if (ret)
            continue;

        (*tgs_limit)--;
        ret = get_cred_kdc_address(context, ccache, flags, NULL,
                                   &s.ask_for, s.tgt,
                                   impersonate_principal,
                                   second_ticket, &s.ticket);
        if (ret) {
            /*
             * XXX We need to make sure we don't fall to the next
             * realm in the search list unless either the app or
             * config did not need secure realm resolution, or we
             * used FAST and got a secure KRB-ERROR saying
             * S_PRINC_UNKNOWN.  We can probably take care of this
             * by having an option for get_cred_kdc_address() for
             * asking for FAST.
             */
            continue;
        }

        /* We got a ticket, cached or not.  Was it the one we wanted? */
        if (krb5_principal_compare_any_realm(context,
                                             s.ask_for.server,
                                             s.ticket.server))
            break; /* Yes! */

        /* No?  Better be a referral then... */
        if (!krb5_principal_is_krbtgt(context, s.ticket.server)) {
            krb5_set_error_message(context, KRB5KRB_AP_ERR_NOT_US,
                                   N_("Got back an non krbtgt "
                                      "ticket referrals", ""));
            ret = KRB5KRB_AP_ERR_NOT_US; /* ... nope; c ya */
            goto out;
        }

        /* ... referral it is */
	referral_realm = s.ticket.server->name.name_string.val[1];

        /* Check that there are no referrals loops */
        /*
         * XXX Use a dict, which we'd have to pass around; we won't save
         * referral TGTs, and whatever equivalents we get may have
         * gotten from the ccache, which means we'd not add them to
         * ret_tgts...  so checking ret_tgts as we used to would be
         * useless.
         *
         * For now we just heuristically detect loops when tgs_limit
         * falls to zero.
         */
        if (*tgs_limit == 0) {
            ret = KRB5_GET_IN_TKT_LOOP;
            goto out;
        }

        /*
         * If either of the chain or the ok_as_delegate was stripped
         * by the kdc, make sure we strip it too.
         */
        if (ok_as_delegate == 0 || s.ticket.flags.b.ok_as_delegate == 0) {
            ok_as_delegate = 0;
            s.ticket.flags.b.ok_as_delegate = 0;
        }

        /*
         * So we have a referral TGT.  But the transit path in the
         * referral TGT may not be correct.  Therefore we try to get a
         * possibly-better TGT for the same realm.
         *
         * We could keep track of the transit path so far and check it
         * against local policy, but our local policy need not match the
         * target service's.  Still, we could make this configurable and
         * then fetch better TGTs only when we can tell that the transit
         * path is bogus, e.g., because it would cause a loop.  Or we
         * could make this configurable and unwind to try to get a
         * better TGT only when a KDC returns KDC_ERR_PATH_NOT_ACCEPTED
         * or KDC_ERR_POLICY.
         */

        /* Get a better TGT for the referral realm and try that */
        s.ask_for_better = *in_creds;
        ret = krb5_copy_principal(context, s.ticket.server,
                                  &s.ask_for_better.server);
        if (ret)
            goto out;

        /* Re-enter to get the better TGT */
        ret = get_credentials_with_flags(context, tgs_limit,
                                         KRB5_GC_DONT_MATCH_REALM,
                                         flags, ccache,
                                         &s.ask_for_better,
                                         &s.better_tgt);

        /* Update the target principal's realm to be the referred-to one */
        ret2 = krb5_principal_set_realm(context, s.ask_for.server,
                                        referral_realm);
        if (ret2) {
            ret = ret2;
            goto out;
        }

	(*tgs_limit)--;
        if (!ret) {
            /*
             * We got a better TGT than the referral TGT, so save it and
             * use it.
             */
            ret = add_cred(context, s.better_tgt, ret_tgts);
            if (ret)
                goto out;
            /* XXX assert s.better_tgt != NULL; remember to free it */
            ret = get_cred_kdc_address(context, ccache, flags, NULL,
                                       &s.ask_for, s.better_tgt,
                                       impersonate_principal,
                                       second_ticket, &s.final_ticket);
        } else {
            /* Fine, use the referral TGT (but we won't cache it) */
            ret = get_cred_kdc_address(context, ccache, flags, NULL,
                                       &s.ask_for, &s.ticket,
                                       impersonate_principal,
                                       second_ticket, &s.final_ticket);
        }

        if (!ret)
            break;

        /*
         * Continue if the referral failed?  See comment above about
         * authenticating KRB-ERRORs.  For now we continue.
         */
    }

    if (ret)
        goto out;

#if 0
    if (!realms[i]) {
        ret = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
        goto out;
    }
#endif
            
    /* Output the ticket we got */
    if (s.ticket.ticket.data)
        ret = krb5_copy_creds(context, &s.ticket, out_creds);
    else if (s.final_ticket.ticket.data)
        ret = krb5_copy_creds(context, &s.final_ticket, out_creds);
    else
        assert(ret != 0);

out:
    cleanup_referral_state(context, &s);
    (void) krb5_free_host_realm(context, realms);
    return ret;
}

/*
 * Glue function between referrals version and old client chasing
 * codebase.
 */

krb5_error_code
_krb5_get_cred_kdc_any(krb5_context context,
                       size_t *tgs_limit,
		       krb5_kdc_flags flags,
		       krb5_ccache ccache,
		       krb5_creds *in_creds,
		       krb5_principal impersonate_principal,
		       Ticket *second_ticket,
		       krb5_creds **out_creds,
		       krb5_creds ***ret_tgts)
{
    krb5_error_code ret;
    krb5_deltat offset;

    if (*tgs_limit == 0)
        return KRB5_GET_IN_TKT_LOOP;

    ret = krb5_cc_get_kdc_offset(context, ccache, &offset);
    if (ret) {
	context->kdc_sec_offset = offset;
	context->kdc_usec_offset = 0;
    }

    flags.b.canonicalize = 1; /* always */
    ret = get_cred_kdc_referral(context,
                                tgs_limit,
				flags,
				ccache,
				in_creds,
				impersonate_principal,
				second_ticket,
				out_creds,
				ret_tgts);
    return ret;
}

static krb5_error_code
check_cc(krb5_context context, krb5_flags options, krb5_ccache ccache,
	 krb5_creds *in_creds, krb5_creds *out_creds)
{
    krb5_error_code ret;
    krb5_timestamp timeret;

    /*
     * If we got a credential, check if credential is expired before
     * returning it.
     */
    ret = krb5_cc_retrieve_cred(context, ccache,
				options & KRB5_TC_MATCH_KEYTYPE,
                                in_creds, out_creds);
    if (ret != 0)
	return ret; /* Caller will check for KRB5_CC_END */

    /*
     * If we got a credential, check if credential is expired before
     * returning it, but only if KRB5_GC_EXPIRED_OK is not set.
     */

    /* If expired ok, don't bother checking */
    if (options & KRB5_GC_EXPIRED_OK)
	return 0;

    krb5_timeofday(context, &timeret);
    if (out_creds->times.endtime > timeret)
	return 0;

    /* Expired and not ok; remove and pretend we didn't find it */
    if (options & KRB5_GC_CACHED)
	krb5_cc_remove_cred(context, ccache, 0, out_creds);

    krb5_free_cred_contents(context, out_creds);
    memset(out_creds, 0, sizeof (*out_creds));
    return KRB5_CC_END;
}

static void
store_cred(krb5_context context, krb5_ccache ccache,
	   krb5_const_principal server_princ, krb5_creds *creds)
{
    krb5_error_code ret;
    krb5_principal tmp_princ = creds->server;
    krb5_principal p;

    krb5_cc_store_cred(context, ccache, creds);
    if (strcmp(server_princ->realm, "") != 0)
	return;

    ret = krb5_copy_principal(context, server_princ, &p);
    if (ret)
	return;
    creds->server = p;
    krb5_cc_store_cred(context, ccache, creds);
    creds->server = tmp_princ;
    krb5_free_principal(context, p);
}


static krb5_error_code
get_credentials_with_flags(krb5_context context,
                           size_t *tgs_limit,
                           krb5_flags options,
                           krb5_kdc_flags flags,
                           krb5_ccache ccache,
                           krb5_creds *in_creds,
                           krb5_creds **out_creds)
{
    krb5_error_code ret;
    krb5_name_canon_iterator name_canon_iter = NULL;
    krb5_creds **tgts;
    krb5_creds *try_creds;
    krb5_creds *res_creds;
    int i;

    if (*tgs_limit == 0)
        return KRB5_GET_IN_TKT_LOOP;

    if (in_creds->session.keytype) {
	ret = krb5_enctype_valid(context, in_creds->session.keytype);
	if (ret)
	    return ret;
	options |= KRB5_TC_MATCH_KEYTYPE;
    }

    *out_creds = NULL;
    res_creds = calloc(1, sizeof(*res_creds));
    if (res_creds == NULL)
	return krb5_enomem(context);

    if (!*in_creds->server->realm) {
	ret = check_cc(context, options, ccache, in_creds, res_creds);
	if (ret == 0) {
	    *out_creds = res_creds;
	    return 0;
	}
    }

    ret = krb5_name_canon_iterator_start(context, NULL, in_creds,
					 &name_canon_iter);
    if (ret)
	return ret;

next_rule:
    krb5_free_cred_contents(context, res_creds);
    memset(res_creds, 0, sizeof (res_creds));
    ret = krb5_name_canon_iterate_creds(context, &name_canon_iter, &try_creds);
    if (ret)
	goto out;
    if (name_canon_iter == NULL) {
	if (options & KRB5_GC_CACHED)
	    ret = KRB5_CC_NOTFOUND;
	else
	    ret = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
	goto out;
    }

    ret = check_cc(context, options, ccache, try_creds, res_creds);
    if (ret == 0) {
	*out_creds = res_creds;
	goto out;
    } else if (ret != KRB5_CC_END) {
        goto out;
    }
    if (options & KRB5_GC_CACHED)
	goto next_rule;

    if (options & KRB5_GC_USER_USER)
	flags.b.enc_tkt_in_skey = 1;
    if (flags.b.enc_tkt_in_skey)
	options |= KRB5_GC_NO_STORE;

    tgts = NULL;
    ret = _krb5_get_cred_kdc_any(context, tgs_limit, flags, ccache,
				 try_creds, NULL, NULL, out_creds, &tgts);
    for (i = 0; tgts && tgts[i]; i++) {
	krb5_cc_store_cred(context, ccache, tgts[i]);
	krb5_free_creds(context, tgts[i]);
    }
    free(tgts);
#if 0
    /* XXX Fix */
    if (ret == KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN &&
	!(rule_opts & KRB5_NCRO_SECURE))
	goto next_rule;
#endif

    if (ret == 0 && (options & KRB5_GC_NO_STORE) == 0)
	store_cred(context, ccache, in_creds->server, *out_creds);

out:
    krb5_free_name_canon_iterator(context, name_canon_iter);
    if (ret) {
	krb5_free_creds(context, res_creds);
	return not_found(context, in_creds->server, ret);
    }
    return 0;
}


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_credentials_with_flags(krb5_context context,
				krb5_flags options,
				krb5_kdc_flags flags,
				krb5_ccache ccache,
				krb5_creds *in_creds,
				krb5_creds **out_creds)
{
    /* XXX 17 is probably too small in some cases; make configurable? */
    size_t tgs_limit = 17;

    return get_credentials_with_flags(context, &tgs_limit, options,
                                      flags, ccache, in_creds,
                                      out_creds);
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_credentials(krb5_context context,
		     krb5_flags options,
		     krb5_ccache ccache,
		     krb5_creds *in_creds,
		     krb5_creds **out_creds)
{
    krb5_kdc_flags flags;
    flags.i = 0;
    return krb5_get_credentials_with_flags(context, options, flags,
					   ccache, in_creds, out_creds);
}

struct krb5_get_creds_opt_data {
    krb5_principal self;
    krb5_flags options;
    krb5_enctype enctype;
    Ticket *ticket;
};


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_creds_opt_alloc(krb5_context context, krb5_get_creds_opt *opt)
{
    *opt = calloc(1, sizeof(**opt));
    if (*opt == NULL)
	return krb5_enomem(context);
    return 0;
}

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_creds_opt_free(krb5_context context, krb5_get_creds_opt opt)
{
    if (opt->self)
	krb5_free_principal(context, opt->self);
    if (opt->ticket) {
	free_Ticket(opt->ticket);
	free(opt->ticket);
    }
    memset(opt, 0, sizeof(*opt));
    free(opt);
}

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_creds_opt_set_options(krb5_context context,
			       krb5_get_creds_opt opt,
			       krb5_flags options)
{
    opt->options = options;
}

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_creds_opt_add_options(krb5_context context,
			       krb5_get_creds_opt opt,
			       krb5_flags options)
{
    opt->options |= options;
}

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_creds_opt_set_enctype(krb5_context context,
			       krb5_get_creds_opt opt,
			       krb5_enctype enctype)
{
    opt->enctype = enctype;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_creds_opt_set_impersonate(krb5_context context,
				   krb5_get_creds_opt opt,
				   krb5_const_principal self)
{
    if (opt->self)
	krb5_free_principal(context, opt->self);
    return krb5_copy_principal(context, self, &opt->self);
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_creds_opt_set_ticket(krb5_context context,
			      krb5_get_creds_opt opt,
			      const Ticket *ticket)
{
    if (opt->ticket) {
	free_Ticket(opt->ticket);
	free(opt->ticket);
	opt->ticket = NULL;
    }
    if (ticket) {
	krb5_error_code ret;

	opt->ticket = malloc(sizeof(*ticket));
	if (opt->ticket == NULL)
	    return krb5_enomem(context);
	ret = copy_Ticket(ticket, opt->ticket);
	if (ret) {
	    free(opt->ticket);
	    opt->ticket = NULL;
	    krb5_set_error_message(context, ret,
				   N_("malloc: out of memory", ""));
	    return ret;
	}
    }
    return 0;
}


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_creds(krb5_context context,
	       krb5_get_creds_opt opt,
	       krb5_ccache ccache,
	       krb5_const_principal inprinc,
	       krb5_creds **out_creds)
{
    krb5_kdc_flags flags;
    krb5_flags options;
    krb5_creds in_creds;
    krb5_error_code ret;
    krb5_creds **tgts;
    krb5_creds *try_creds;
    krb5_creds *res_creds;
    krb5_name_canon_iterator name_canon_iter = NULL;
    size_t tgs_limit = 17; /* XXX */
    int i;

    if (opt && opt->enctype) {
	ret = krb5_enctype_valid(context, opt->enctype);
	if (ret)
	    return ret;
    }

    memset(&in_creds, 0, sizeof(in_creds));
    in_creds.server = rk_UNCONST(inprinc);

    ret = krb5_cc_get_principal(context, ccache, &in_creds.client);
    if (ret)
	return ret;

    if (opt)
	options = opt->options;
    else
	options = 0;
    flags.i = 0;

    *out_creds = NULL;
    res_creds = calloc(1, sizeof(*res_creds));
    if (res_creds == NULL) {
	krb5_free_principal(context, in_creds.client);
	return krb5_enomem(context);
    }

    if (opt && opt->enctype) {
	in_creds.session.keytype = opt->enctype;
	options |= KRB5_TC_MATCH_KEYTYPE;
    }

    /* Check for entry in ccache */
    if (!*inprinc->realm) {
	ret = check_cc(context, options, ccache, &in_creds, res_creds);
	if (ret == 0) {
	    *out_creds = res_creds;
	    goto out;
	}
    }

    ret = krb5_name_canon_iterator_start(context, NULL, &in_creds,
					 &name_canon_iter);
    if (ret)
	goto out;

next_rule:
    ret = krb5_name_canon_iterate_creds(context, &name_canon_iter, &try_creds);
    if (ret)
	return ret;
    if (name_canon_iter == NULL) {
	if (options & KRB5_GC_CACHED)
	    ret = KRB5_CC_NOTFOUND;
	else
	    ret = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
	goto out;
    }
    ret = check_cc(context, options, ccache, try_creds, res_creds);
    if (ret == 0) {
	*out_creds = res_creds;
	goto out;
    } else if(ret != KRB5_CC_END) {
	goto out;
    }
    if(options & KRB5_GC_CACHED)
	goto next_rule;

    /*
     * We always want the canon flag, even when KRB5_GC_CANONICALIZE is
     * not set.  We may want a flag to NOT request canonicalization, but
     * really, the caller needs to decide that the name having changed
     * is bad rather than the caller decide whether we should try canon.
     * The caller also should get an option for requesting secure-only
     * name canonicalization (meaning: use FAST, so we can protect the
     * KRB-ERROR, and fail immediately when we fail to setup a FAST
     * tunnel).
     */
    flags.b.canonicalize = 1;

    if (options & KRB5_GC_USER_USER) {
	flags.b.enc_tkt_in_skey = 1;
	options |= KRB5_GC_NO_STORE;
    }
    if (options & KRB5_GC_FORWARDABLE)
	flags.b.forwardable = 1;
    if (options & KRB5_GC_NO_TRANSIT_CHECK)
	flags.b.disable_transited_check = 1;
    if (options & KRB5_GC_CONSTRAINED_DELEGATION) {
	flags.b.request_anonymous = 1; /* XXX ARGH confusion */
	flags.b.constrained_delegation = 1;
    }

    tgts = NULL;
    ret = _krb5_get_cred_kdc_any(context, &tgs_limit, flags, ccache,
				 try_creds, opt ? opt->self : 0,
                                 opt ? opt->ticket : 0, out_creds, &tgts);
    for(i = 0; tgts && tgts[i]; i++) {
	krb5_cc_store_cred(context, ccache, tgts[i]);
	krb5_free_creds(context, tgts[i]);
    }
    free(tgts);

#if 0
    /* XXX Fix */
    if (ret == KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN &&
	!(rule_opts & KRB5_NCRO_SECURE))
	goto next_rule;
#endif

    if(ret == 0 && (options & KRB5_GC_NO_STORE) == 0)
	store_cred(context, ccache, inprinc, *out_creds);

out:
    if (ret) {
	krb5_free_creds(context, res_creds);
	ret = not_found(context, inprinc, ret);
    }
    krb5_free_principal(context, in_creds.client);
    krb5_free_name_canon_iterator(context, name_canon_iter);
    _krb5_debug(context, 5, "krb5_get_creds: ret = %d", ret);
    return ret;
}

/*
 *
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_renewed_creds(krb5_context context,
		       krb5_creds *creds,
		       krb5_const_principal client,
		       krb5_ccache ccache,
		       const char *in_tkt_service)
{
    krb5_error_code ret;
    krb5_kdc_flags flags;
    krb5_creds in, *template, *out = NULL;

    memset(&in, 0, sizeof(in));
    memset(creds, 0, sizeof(*creds));

    ret = krb5_copy_principal(context, client, &in.client);
    if (ret)
	return ret;

    if (in_tkt_service) {
	ret = krb5_parse_name(context, in_tkt_service, &in.server);
	if (ret) {
	    krb5_free_principal(context, in.client);
	    return ret;
	}
    } else {
	const char *realm = krb5_principal_get_realm(context, client);

	ret = krb5_make_principal(context, &in.server, realm, KRB5_TGS_NAME,
				  realm, NULL);
	if (ret) {
	    krb5_free_principal(context, in.client);
	    return ret;
	}
    }

    flags.i = 0;
    flags.b.renewable = flags.b.renew = 1;

    /*
     * Get template from old credential cache for the same entry, if
     * this failes, no worries.
     */
    ret = krb5_get_credentials(context, KRB5_GC_CACHED, ccache, &in, &template);
    if (ret == 0) {
	flags.b.forwardable = template->flags.b.forwardable;
	flags.b.proxiable = template->flags.b.proxiable;
	krb5_free_creds (context, template);
    }

    ret = krb5_get_kdc_cred(context, ccache, flags, NULL, NULL, &in, &out);
    krb5_free_principal(context, in.client);
    krb5_free_principal(context, in.server);
    if (ret)
	return ret;

    ret = krb5_copy_creds_contents(context, out, creds);
    krb5_free_creds(context, out);

    return ret;
}
