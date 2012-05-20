/*
 * Copyright (c) 1997 - 2004 Kungliga Tekniska Högskolan
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

#include "krb5_locl.h"

static krb5_error_code
add_addrs(krb5_context context,
	  krb5_addresses *addr,
	  struct addrinfo *ai)
{
    krb5_error_code ret;
    unsigned n, i;
    void *tmp;
    struct addrinfo *a;

    n = 0;
    for (a = ai; a != NULL; a = a->ai_next)
	++n;

    tmp = realloc(addr->val, (addr->len + n) * sizeof(*addr->val));
    if (tmp == NULL && (addr->len + n) != 0) {
	ret = ENOMEM;
	krb5_set_error_message(context, ret, N_("malloc: out of memory", ""));
	goto fail;
    }
    addr->val = tmp;
    for (i = addr->len; i < (addr->len + n); ++i) {
	addr->val[i].addr_type = 0;
	krb5_data_zero(&addr->val[i].address);
    }
    i = addr->len;
    for (a = ai; a != NULL; a = a->ai_next) {
	krb5_address ad;

	ret = krb5_sockaddr2address (context, a->ai_addr, &ad);
	if (ret == 0) {
	    if (krb5_address_search(context, &ad, addr))
		krb5_free_address(context, &ad);
	    else
		addr->val[i++] = ad;
	}
	else if (ret == KRB5_PROG_ATYPE_NOSUPP)
	    krb5_clear_error_message (context);
	else
	    goto fail;
	addr->len = i;
    }
    return 0;
fail:
    krb5_free_addresses (context, addr);
    return ret;
}

/**
 * Forward credentials for client to host hostname , making them
 * forwardable if forwardable, and returning the blob of data to sent
 * in out_data.  If hostname == NULL, pick it from server.
 *
 * @param context A kerberos 5 context.
 * @param auth_context the auth context with the key to encrypt the out_data.
 * @param hostname the host to forward the tickets too.
 * @param client the client to delegate from.
 * @param server the server to delegate the credential too.
 * @param ccache credential cache to use.
 * @param forwardable make the forwarded ticket forwabledable.
 * @param out_data the resulting credential.
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_credential
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_fwd_tgt_creds (krb5_context	context,
		    krb5_auth_context	auth_context,
		    const char		*hostname,
		    krb5_principal	client,
		    krb5_principal	server,
		    krb5_ccache		ccache,
		    int			forwardable,
		    krb5_data		*out_data)
{
    krb5_flags flags = 0;
    krb5_creds creds;
    krb5_error_code ret;
    krb5_const_realm client_realm;

    flags |= KDC_OPT_FORWARDED;

    if (forwardable)
	flags |= KDC_OPT_FORWARDABLE;

    if (hostname == NULL &&
	krb5_principal_get_type(context, server) == KRB5_NT_SRV_HST) {
	const char *inst = krb5_principal_get_comp_string(context, server, 0);
	const char *host = krb5_principal_get_comp_string(context, server, 1);

	if (inst != NULL &&
	    strcmp(inst, "host") == 0 &&
	    host != NULL &&
	    krb5_principal_get_comp_string(context, server, 2) == NULL)
	    hostname = host;
    }

    client_realm = krb5_principal_get_realm(context, client);

    memset (&creds, 0, sizeof(creds));
    creds.client = client;

    ret = krb5_make_principal(context,
			      &creds.server,
			      client_realm,
			      KRB5_TGS_NAME,
			      client_realm,
			      NULL);
    if (ret)
	return ret;

    ret = krb5_get_forwarded_creds (context,
				    auth_context,
				    ccache,
				    flags,
				    hostname,
				    &creds,
				    out_data);
    return ret;
}

/**
 * Gets tickets forwarded to hostname. If the tickets that are
 * forwarded are address-less, the forwarded tickets will also be
 * address-less.
 *
 * If the ticket have any address, hostname will be used for figure
 * out the address to forward the ticket too. This since this might
 * use DNS, its insecure and also doesn't represent configured all
 * addresses of the host. For example, the host might have two
 * adresses, one IPv4 and one IPv6 address where the later is not
 * published in DNS. This IPv6 address might be used communications
 * and thus the resulting ticket useless.
 *
 * @param context A kerberos 5 context.
 * @param auth_context the auth context with the key to encrypt the out_data.
 * @param ccache credential cache to use
 * @param flags the flags to control the resulting ticket flags
 * @param hostname the host to forward the tickets too.
 * @param in_creds the in client and server ticket names.  The client
 * and server components forwarded to the remote host.
 * @param out_data the resulting credential.
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_credential
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_forwarded_creds (krb5_context	    context,
			  krb5_auth_context auth_context,
			  krb5_ccache       ccache,
			  krb5_flags        flags,
			  const char        *hostname,
			  krb5_creds        *in_creds,
			  krb5_data         *out_data)
{
    krb5_error_code ret;
    krb5_data *ppdata;
    krb5_creds *ppcreds[2] = { NULL, NULL };
    krb5_addresses addrs, *paddrs;
    krb5_kdc_flags kdc_flags;
    struct addrinfo *ai;
    krb5_creds *ticket;

    paddrs = NULL;
    addrs.len = 0;
    addrs.val = NULL;

    ret = krb5_get_credentials(context, 0, ccache, in_creds, &ticket);
    if (ret) {
	krb5_boolean noaddr;
	krb5_appdefault_boolean(context, NULL,
				krb5_principal_get_realm(context,
							 in_creds->client),
				"no-addresses", KRB5_ADDRESSLESS_DEFAULT,
				&noaddr);
	if (!noaddr)
	    paddrs = &addrs;
    } else {
	if (ticket->addresses.len)
	    paddrs = &addrs;
	krb5_free_creds(context, ticket);
    }

    /*
     * If tickets have addresses, get the address of the remote host.
     */

    if (paddrs != NULL) {
        int eai;

	eai = getaddrinfo (hostname, NULL, NULL, &ai);
	if (eai) {
	    ret = krb5_eai_to_heim_errno(eai, errno);
	    krb5_set_error_message(context, ret,
				   N_("resolving host %s failed: %s",
				      "hostname, error"),
				  hostname, gai_strerror(eai));
	    return ret;
	}

	ret = add_addrs(context, &addrs, ai);
	freeaddrinfo(ai);
	if (ret)
	    return ret;
    }

    kdc_flags.b = int2KDCOptions(flags);

    ret = krb5_get_kdc_cred(context,
			    ccache,
			    kdc_flags,
			    paddrs,
			    NULL,
			    in_creds,
			    &ppcreds[0]);
    krb5_free_addresses(context, &addrs);
    if (ret)
	return ret;

    ret = krb5_mk_ncred(context, auth_context, ppcreds, &ppdata, NULL);
    if (ret)
        goto out;

    out_data->length = ppdata->length;
    out_data->data   = ppdata->data;
    krb5_data_zero(ppdata);
    krb5_free_data(context, ppdata);

 out:
    krb5_free_creds (context, ppcreds[0]);
    return ret;
}

/**
 * Make a KRB-CRED PDU with N credentials.
 *
 * @param context A kerberos 5 context.
 * @param auth_context the auth context with the key to encrypt the out_data.
 * @param ppcreds A NULL terminated array of credentials to forward.
 * @param ppdata The output KRB-CRED.
 * @param replay_data (unused).
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_credential
 */

/* ARGSUSED */
krb5_error_code KRB5_CALLCONV
krb5_mk_ncred(krb5_context context, krb5_auth_context auth_context,
              krb5_creds **ppcreds, krb5_data **ppdata,
              krb5_replay_data *replay_data)
{
    krb5_error_code ret;
    EncKrbCredPart enc_krb_cred_part;
    KrbCredInfo *krb_cred_info;
    krb5_crypto crypto;
    KRB_CRED cred;
    unsigned char *buf = NULL;
    size_t ncreds, i;
    size_t buf_size;
    size_t len;

    for (ncreds = 0; ppcreds[ncreds]; ncreds++)
        ;

    memset (&cred, 0, sizeof(cred));
    cred.pvno = 5;
    cred.msg_type = krb_cred;
    ALLOC_SEQ(&cred.tickets, ncreds);
    if (cred.tickets.val == NULL) {
        ret = krb5_enomem(context);
	goto out;
    }
    memset (&enc_krb_cred_part, 0, sizeof(enc_krb_cred_part));
    ALLOC_SEQ(&enc_krb_cred_part.ticket_info, ncreds);
    if (enc_krb_cred_part.ticket_info.val == NULL) {
        ret = krb5_enomem(context);
	goto out;
    }

    for (i = 0; i < ncreds; i++) {
        ret = decode_Ticket(ppcreds[i]->ticket.data,
                            ppcreds[i]->ticket.length,
                            &cred.tickets.val[i],
                            &len);/* don't care about len */
        if (ret)
           goto out;
         
        /* fill ticket_info.val[i] */
        krb_cred_info = &enc_krb_cred_part.ticket_info.val[i];

        /* XXX Check copy_*() errors */
        copy_EncryptionKey (&ppcreds[i]->session, &krb_cred_info->key);
        ALLOC(krb_cred_info->prealm, 1);
        copy_Realm (&ppcreds[i]->client->realm, krb_cred_info->prealm);
        ALLOC(krb_cred_info->pname, 1);
        copy_PrincipalName(&ppcreds[i]->client->name, krb_cred_info->pname);
        ALLOC(krb_cred_info->flags, 1);
        *krb_cred_info->flags          = ppcreds[i]->flags.b;
        ALLOC(krb_cred_info->authtime, 1);
        *krb_cred_info->authtime       = ppcreds[i]->times.authtime;
        ALLOC(krb_cred_info->starttime, 1);
        *krb_cred_info->starttime      = ppcreds[i]->times.starttime;
        ALLOC(krb_cred_info->endtime, 1);
        *krb_cred_info->endtime        = ppcreds[i]->times.endtime;
        ALLOC(krb_cred_info->renew_till, 1);
        *krb_cred_info->renew_till = ppcreds[i]->times.renew_till;
        ALLOC(krb_cred_info->srealm, 1);
        copy_Realm (&ppcreds[i]->server->realm, krb_cred_info->srealm);
        ALLOC(krb_cred_info->sname, 1);
        copy_PrincipalName (&ppcreds[i]->server->name, krb_cred_info->sname);
        ALLOC(krb_cred_info->caddr, 1);
        copy_HostAddresses (&ppcreds[i]->addresses, krb_cred_info->caddr);
    }

    if (auth_context->flags & KRB5_AUTH_CONTEXT_DO_TIME) {
	krb5_timestamp sec;
	int32_t usec;

	krb5_us_timeofday (context, &sec, &usec);

	ALLOC(enc_krb_cred_part.timestamp, 1);
	if (enc_krb_cred_part.timestamp == NULL) {
            ret = krb5_enomem(context);
            goto out;
	}
	*enc_krb_cred_part.timestamp = sec;
	ALLOC(enc_krb_cred_part.usec, 1);
	if (enc_krb_cred_part.usec == NULL) {
            ret = krb5_enomem(context);
	    goto out;
	}
	*enc_krb_cred_part.usec      = usec;
    } else {
	enc_krb_cred_part.timestamp = NULL;
	enc_krb_cred_part.usec = NULL;
        /* XXX Er, shouldn't we set the seq nums?? */
    }

    if (auth_context->local_address && auth_context->local_port) {
	ret = krb5_make_addrport(context,
				 &enc_krb_cred_part.s_address,
				 auth_context->local_address,
				 auth_context->local_port);
	if (ret)
	    goto out;
    }

    if (auth_context->remote_address) {
	if (auth_context->remote_port) {
            ret = krb5_make_addrport(context,
                                     &enc_krb_cred_part.r_address,
                                     auth_context->remote_address,
                                     auth_context->remote_port);
            if (ret)
                goto out;
	} else {
            /*
             * XXX Ugly, make krb5_make_addrport() handle missing port
             * number (i.e., port == 0), then remove this else.
             */
	    ALLOC(enc_krb_cred_part.r_address, 1);
	    if (enc_krb_cred_part.r_address == NULL) {
                ret = krb5_enomem(context);
		goto out;
	    }

	    ret = krb5_copy_address(context, auth_context->remote_address,
				    enc_krb_cred_part.r_address);
	    if (ret)
		goto out;
	}
    }

    /* encode EncKrbCredPart */
    ASN1_MALLOC_ENCODE(EncKrbCredPart, buf, buf_size,
		       &enc_krb_cred_part, &len, ret);
    if (ret)
        goto out;
    if (buf_size != len)
	krb5_abortx(context, "internal error in ASN.1 encoder");

    /**
     * Some older of the MIT gssapi library used clear-text tickets
     * (warped inside AP-REQ encryption), use the krb5_auth_context
     * flag KRB5_AUTH_CONTEXT_CLEAR_FORWARDED_CRED to support those
     * tickets. The session key is used otherwise to encrypt the
     * forwarded ticket.
     */

    if (auth_context->flags & KRB5_AUTH_CONTEXT_CLEAR_FORWARDED_CRED) {
	cred.enc_part.etype = KRB5_ENCTYPE_NULL;
	cred.enc_part.kvno = NULL;
	cred.enc_part.cipher.data = buf;
	cred.enc_part.cipher.length = buf_size;
    } else {
	/*
	 * Here older versions then 0.7.2 of Heimdal used the local or
	 * remote subkey. That is wrong, the session key should be
	 * used. Heimdal 0.7.2 and newer have code to try both in the
	 * receiving end.
	 */

	ret = krb5_crypto_init(context, auth_context->keyblock, 0, &crypto);
	if (ret) {
	    free(buf);
	    free_KRB_CRED(&cred);
	    return ret;
	}
	ret = krb5_encrypt_EncryptedData (context,
					  crypto,
					  KRB5_KU_KRB_CRED,
					  buf,
					  len,
					  0,
					  &cred.enc_part);
	krb5_crypto_destroy(context, crypto);
	if (ret)
            goto out;
    }

    ASN1_MALLOC_ENCODE(KRB_CRED, buf, buf_size, &cred, &len, ret);
    if (ret)
	goto out;
    if (buf_size != len)
	krb5_abortx(context, "internal error in ASN.1 encoder");

    /* MIT makes us very sad */
    *ppdata = calloc(1, sizeof (*ppdata));
    if (!*ppdata) {
        ret = krb5_enomem(context);
        goto out;
    }
    (*ppdata)->length = len;
    (*ppdata)->data   = buf;
    ret = 0;

 out:
    free_EncKrbCredPart(&enc_krb_cred_part);
    free_KRB_CRED(&cred);
    free(buf);
    return ret;
}


