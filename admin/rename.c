/*
 * Copyright (c) 2001-2004 Kungliga Tekniska Högskolan
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

#include "ktutil_locl.h"

RCSID("$Id$");

int
kt_rename(struct rename_options *opt, int argc, char **argv)
{
    krb5_error_code ret = 0;
    krb5_keytab_entry entry;
    krb5_keytab keytab;
    krb5_kt_cursor cursor;
    krb5_principal from_princ, to_princ;
    krb5_keytab_entry *entries = NULL;
    size_t num_entries = 0;
    size_t i;

    ret = krb5_parse_name(context, argv[0], &from_princ);
    if(ret != 0) {
	krb5_warn(context, ret, "%s", argv[0]);
	return 1;
    }

    ret = krb5_parse_name(context, argv[1], &to_princ);
    if(ret != 0) {
	krb5_free_principal(context, from_princ);
	krb5_warn(context, ret, "%s", argv[1]);
	return 1;
    }

    if((keytab = ktutil_open_keytab()) == NULL) {
	krb5_free_principal(context, from_princ);
	krb5_free_principal(context, to_princ);
	return 1;
    }

    /*
     * Collect matching entries first, then close the cursor before
     * adding/removing.  We must not call krb5_kt_add_entry() or
     * krb5_kt_remove_entry() while holding the seq_get cursor because
     * the cursor holds a shared file lock and the add/remove operations
     * need an exclusive lock -- with per-fd locking (BSD flock, OFD locks)
     * this self-deadlocks.
     */
    ret = krb5_kt_start_seq_get(context, keytab, &cursor);
    if(ret) {
	krb5_kt_close(context, keytab);
	krb5_free_principal(context, from_princ);
	krb5_free_principal(context, to_princ);
	return 1;
    }
    while((ret = krb5_kt_next_entry(context, keytab, &entry, &cursor)) == 0) {
	if(krb5_principal_compare(context, entry.principal, from_princ)) {
	    krb5_keytab_entry *tmp;

	    tmp = realloc(entries, (num_entries + 1) * sizeof(*entries));
	    if (tmp == NULL) {
		krb5_kt_free_entry(context, &entry);
		ret = krb5_enomem(context);
		break;
	    }
	    entries = tmp;
	    krb5_free_principal(context, entry.principal);
	    entry.principal = NULL;
	    entries[num_entries++] = entry;
	} else {
	    krb5_kt_free_entry(context, &entry);
	}
    }
    if(ret == KRB5_CC_END || ret == KRB5_KT_END)
	ret = 0;
    else if(ret)
	krb5_warn(context, ret, "getting entry from keytab");
    krb5_kt_end_seq_get(context, keytab, &cursor);

    for (i = 0; ret == 0 && i < num_entries; i++) {
	entries[i].principal = to_princ;
	ret = krb5_kt_add_entry(context, keytab, &entries[i]);
	if(ret) {
	    krb5_warn(context, ret, "adding entry");
	    break;
	}
	if (opt->delete_flag) {
	    entries[i].principal = from_princ;
	    ret = krb5_kt_remove_entry(context, keytab, &entries[i]);
	    if(ret) {
		krb5_warn(context, ret, "removing entry");
		break;
	    }
	}
    }

    for (i = 0; i < num_entries; i++) {
	entries[i].principal = NULL;
	krb5_kt_free_entry(context, &entries[i]);
    }
    free(entries);

    krb5_free_principal(context, from_princ);
    krb5_free_principal(context, to_princ);

    return ret != 0;
}

