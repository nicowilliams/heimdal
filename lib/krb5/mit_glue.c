/*
 * Copyright (c) 2003 Kungliga Tekniska H�gskolan
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
RCSID("$Id$");

/*
 * Glue for MIT API
 */

krb5_error_code
krb5_c_make_checksum(krb5_context context, 
		     krb5_cksumtype cksumtype, 
		     const krb5_keyblock *key, 
		     krb5_keyusage usage,
		     const krb5_data *input, 
		     krb5_checksum *cksum)
{
    krb5_error_code ret;
    krb5_crypto crypto;

    ret = krb5_crypto_init(context, key, ETYPE_NULL, &crypto);
    if (ret)
	return ret;

    ret = krb5_create_checksum(context, crypto,  usage, cksumtype,
			       input->data, input->length, cksum);
    krb5_crypto_destroy(context, crypto);

    return ret ;
}

krb5_error_code
krb5_c_verify_checksum(krb5_context context, const krb5_keyblock *key,
		       krb5_keyusage usage, const krb5_data *data,
		       const krb5_checksum *cksum, krb5_boolean *valid)
{
    krb5_error_code ret;
    krb5_checksum data_cksum;

    *valid = 0;

    ret = krb5_c_make_checksum(context, cksum->cksumtype,
			       key, usage, data, &data_cksum);
    if (ret)
	return ret;

    if (data_cksum.cksumtype == cksum->cksumtype
	&& data_cksum.checksum.length == cksum->checksum.length
	&& memcmp(data_cksum.checksum.data, cksum->checksum.data, cksum->checksum.length) == 0)
	*valid = 1;

    krb5_free_checksum_contents(context, &data_cksum);

    return 0;
}

krb5_error_code
krb5_c_get_checksum(krb5_context context, const krb5_checksum *cksum,
		    krb5_cksumtype *type, krb5_data **data)
{
    krb5_error_code ret;

    *data = malloc(sizeof(**data));
    if (data == NULL)
	return ENOMEM;
    *type = cksum->cksumtype;
    ret = copy_octet_string(&cksum->checksum, *data);
    if (ret) {
	free(*data);
	*data = NULL;
    }
    return ret;
}

krb5_error_code
krb5_c_set_checksum(krb5_context context, krb5_checksum *cksum,
		    krb5_cksumtype type, const krb5_data *data)
{
    cksum->cksumtype = type;
    return copy_octet_string(data, &cksum->checksum);
}

void 
krb5_free_checksum (krb5_context context, krb5_checksum *cksum)
{
    krb5_checksum_free(context, cksum);
    free(cksum);
}

void
krb5_free_checksum_contents(krb5_context context, krb5_checksum *cksum)
{
    krb5_checksum_free(context, cksum);
}

void
krb5_checksum_free(krb5_context context, krb5_checksum *cksum)
{
    free_Checksum(cksum);
}

krb5_error_code
krb5_copy_checksum (krb5_context context,
		    const krb5_checksum *old,
		    krb5_checksum **new)
{
    *new = malloc(sizeof(**new));
    if (*new == NULL)
	return ENOMEM;
    return copy_Checksum(old, *new);
}

krb5_error_code
krb5_c_checksum_length (krb5_context context, krb5_cksumtype cksumtype,
			size_t *length)
{
    return krb5_checksumsize(context, cksumtype, length);
}
