/*
 * Copyright (c) 2009 Kungliga Tekniska Högskolan
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

#include "hdb_locl.h"
#include "hdb-sqlite-schema.h"
#include "sqlite3.h"
#include <assert.h>
#include <der.h>
#include <malloc.h>

#define MAX_RETRIES 10

/*
 * Some notes regarding the schema.
 *
 * We want a schema that's as normalized as possible so as to enable
 * better reporting and administration tools, with some degree of
 * denormalization to improve performance by reducing the number of
 * JOINs needed in the common case (which is in the KDC, not admin,
 * load, dump, ...).  This means we'll have one table with columns for
 * all scalar elements of a principal entry, as well as a few non-normal
 * columns:
 *  - a canonical name column (copied by triggers from the name table)
 *  - a current kvno column (copied by triggers from the keys table)
 *  - a current keys column containing comma-separated quoted key blobs
 *    (copied by triggers from the keys table)
 *  - an enctypes column containing a stringified list of enctype
 *    numbers separated by colons (copied ... from the enctypes table)
 *
 * Everything else will be in separate tables.
 *
 * In the fast path (in the KDC AS and TGS cases) we want to do lookups
 * by name, including aliases, so the query will be a UNION ALL .. LIMIT 1
 * SELECT from two sources: the main table and a JOIN of the main table
 * and the name table.  This results in no joins in the case of lookup
 * by canonical name, and 1 join in the lookup by alias case.
 *
 * In the slow path (admin, load, dump, ...) we'd ideally want to
 * execute  SQL statements on the individual tables, but the way the HDB
 * API works fetch and store whole entry are the only operations we
 * have, so for simplicity we'll have a VIEW that gives us stringified
 * relations columns for all the non-scalar relations.  We don't get to
 * INSERT/MODIFY this VIEW's stringified non-scalar relations, sadly,
 * not without adding some VIRTUAL TABLEs to help us parse those values
 * in SQL, so the store case is fun (not)!
 *
 * The slow path gets lots and lots of JOINs.  Aliases, enctypes, keys,
 * passwords PKINIT certs/ACLs, delegate_to lists, etecetera -- all of
 * these are JOINed and then group_concat()enated in quote()d form.
 * That's why we call it the slow path.
 *
 * Tests show that with a DB with 1.8e6 principals, CPU-bound access
 * times are slower for a query with JOINs by, roughly, the number of
 * JOINs, this being, apparently, the result of roughly that many fewer
 * pages of data to access and/or move around.  That's why we
 * denormalize enough to have a fast path.  That said, even the slow
 * path will typically be fast enough for production KDCs, but we want
 * to make sure that SQLite3 is not the bottleneck.
 */

typedef struct hdb_sqlite_db {
    double version;
    sqlite3 *db;
    char *db_file;

    /* Cached prepared statements */
    sqlite3_stmt *get_version;
    sqlite3_stmt *fetch;
    sqlite3_stmt *fetch_kvno;
    sqlite3_stmt *get_ids;
    sqlite3_stmt *add_entry;
    sqlite3_stmt *add_principal;
    sqlite3_stmt *add_alias;
    sqlite3_stmt *delete_aliases;
    sqlite3_stmt *update_entry;
    sqlite3_stmt *remove;
    sqlite3_stmt *get_all_entries;

    /* Indexes to named parameters for each prepared statement */
    int add_entry_pidx_canon_name_id;
    int add_entry_pidx_canon_name;
    int add_entry_pidx_id;
    int add_entry_pidx_data;
    int add_entry_pidx_created_at;
    int add_entry_pidx_created_by;
    int add_entry_pidx_modified_at;
    int add_entry_pidx_modified_by;
    int add_entry_pidx_valid_start;
    int add_entry_pidx_valid_end;
    int add_entry_pidx_pw_end;
    int add_entry_pidx_last_pw_change;
    int add_entry_pidx_max_life;
    int add_entry_pidx_max_renew;
    int add_entry_pidx_flags;

    int upd_entry_pidx_canon_name_id;
    int upd_entry_pidx_canon_name;
    int upd_entry_pidx_id;
    int upd_entry_pidx_data;
    int upd_entry_pidx_created_at;
    int upd_entry_pidx_created_by;
    int upd_entry_pidx_modified_at;
    int upd_entry_pidx_modified_by;
    int upd_entry_pidx_valid_start;
    int upd_entry_pidx_valid_end;
    int upd_entry_pidx_pw_end;
    int upd_entry_pidx_last_pw_change;
    int upd_entry_pidx_max_life;
    int upd_entry_pidx_max_renew;
    int upd_entry_pidx_flags;

} hdb_sqlite_db;

/* This should be used to mark updates which make the code incompatible
 * with databases created with previous versions. Don't update it if
 * compatibility is not broken. */
#define HDBSQLITE_VERSION 1.1

#define	HDBSQLITE_SCHEMA_FILE	LIBDIR "/hdb-sqlite-schema.sql"

#define _HDBSQLITE_STRINGIFY(x) #x
#define HDBSQLITE_STRINGIFY(x) _HDBSQLITE_STRINGIFY(x)

#define HDBSQLITE_GET_VERSION \
                 " SELECT max(number) FROM Version"
#define HDBSQLITE_FETCH \
                 " SELECT ed.data FROM Entry ed" \
                 " JOIN EntryName en ON en.entry = ed.id" \
                 " WHERE en.name = @name"
#define HDBSQLITE_GET_IDS \
                 " SELECT en.id, en.entry FROM EntryName en" \
                 " WHERE en.name = @name AND en.entry IS NOT NULL"
#define HDBSQLITE_ADD_ENTRY_DETAIL \
		 " INSERT INTO EntryDetail (canon_name_id, canon_name," \
		 " id, data, created_at, created_by, modified_at," \
		 " modified_by, valid_start, valid_end, pw_end," \
		 " last_pw_change, max_life, max_renew, flags) " \
		 " VALUES (@canon_name_id, @canon_name, @id, @data," \
		 "  @created_at, @created_by, @modified_at," \
		 "  @modified_by, @valid_start, @valid_end, @pw_end," \
		 "  @last_pw_change, @max_life, @max_renew, @flags)"
#define HDBSQLITE_ADD_PRINCIPAL \
                 " INSERT INTO Principal (principal, entry, canonical)" \
                 " VALUES (?, last_insert_rowid(), 1)" /* XXX remove */
#define HDBSQLITE_ADD_ALIAS \
                 " INSERT INTO EntryName (name, entry)" \
                 " VALUES(@name, @entry)"
#define HDBSQLITE_DELETE_ALIASES \
                 " DELETE FROM Principal" \
                 " WHERE entry = ? AND canonical = 0"
#define HDBSQLITE_UPDATE_ENTRY \
                 " UPDATE Entry SET " \
		 " canon_name_id = @canon_name_id," \
		 " canon_name = @canon_name," \
		 " id = @id," \
		 " data = @data," \
		 " created_at = @created_at," \
		 " created_by = @created_by," \
		 " modified_at = @modified_at," \
		 " modified_by = @modified_by," \
		 " valid_start = @valid_start," \
		 " valid_end = @valid_end," \
		 " pw_end = @pw_end," \
		 " last_pw_change = @last_pw_change," \
		 " max_life = @max_life," \
		 " max_renew = @max_renew," \
		 " flags = @flags" \
                 " WHERE id = ?"
#define HDBSQLITE_REMOVE \
                 " DELETE FROM ENTRY WHERE id = " \
                 "  (SELECT entry FROM Principal" \
                 "   WHERE principal = ?)"
#define HDBSQLITE_GET_ALL_ENTRIES \
                 " SELECT data FROM Entry"


/**
 * Function to map a result row for a query into a Principal name.
 */
static krb5_error_code
hdb_sqlite_col2principal(krb5_context context,
			 sqlite3 *db,
			 sqlite3_stmt *cursor,
			 int iCol,
			 Principal **princ)
{
    const unsigned char *name;

    name = sqlite3_column_text(cursor, iCol);
    if (name == NULL) {
	if (sqlite3_errcode(db) == SQLITE_NOMEM)
	    return ENOMEM;
	/*
	 * The schema should disallow NULL names, but still, let's not
	 * assert().
	 */
	return EINVAL; /* XXX Need a better error code */
    }

    return krb5_parse_name(context, (const char *)name, princ);
}


/**
 * Function to map a result row for a query into an Event.
 */
static krb5_error_code
hdb_sqlite_col2event(krb5_context context,
		     sqlite3 *db,
		     sqlite3_stmt *cursor,
		     int timeCol,
		     int nameCol,
		     Event *ev,
		     Event **evp)
{
    int ret;
    sqlite_int64 tmv;
    KerberosTime tm;

    if (sqlite3_column_type(cursor, timeCol) == SQLITE_NULL ||
	sqlite3_column_type(cursor, nameCol) == SQLITE_NULL)
	return 0;

    tmv = sqlite3_column_int64(cursor, timeCol);
    tm = (KerberosTime)tmv;

    if (tmv > tm || tmv < 0)
	return EOVERFLOW;

    if (ev == NULL) {
	ev = calloc(1, sizeof (*ev));
	if (ev == NULL) return ENOMEM;
    }

    ev->time = (KerberosTime)tm;

    ret = hdb_sqlite_col2principal(context, db, cursor, nameCol, &ev->principal);
    if (ret != 0) {
	free_Event(ev);
	return ret;
    }

    if (evp != NULL)
	*evp = ev;

    return 0;
}


/**
 * Function to map a result row for a query into a KerberosTime.
 */
static krb5_error_code
hdb_sqlite_col2time(krb5_context context,
		    sqlite3 *db,
		    sqlite3_stmt *cursor,
		    int iCol,
		    KerberosTime **tmp)
{
    sqlite_int64 tmv;

    if (sqlite3_column_type(cursor, iCol) == SQLITE_NULL) {
	*tmp = NULL;
	return 0;
    }

    if (sqlite3_errcode(db) != SQLITE_OK)
	return ENOMEM; /* Almost certainly what it is; XXX need a map func */

    tmv = sqlite3_column_int64(cursor, iCol);
    if (tmv < 0)
	return EOVERFLOW;

    if (sqlite3_errcode(db) != SQLITE_OK)
	return ENOMEM; /* Almost certainly what it is; XXX need a map func */

    *tmp = malloc(sizeof (**tmp));
    if (*tmp == NULL)
	return ENOMEM;

    **tmp = (KerberosTime)tmv;
    return 0;
}


/**
 * Function to map a result row for a query into a max_life-type of
 * hdb_entry field.
 */
static krb5_error_code
hdb_sqlite_col2uint31(krb5_context context,
		    sqlite3 *db,
		    sqlite3_stmt *cursor,
		    int iCol,
		    unsigned int **tmp)
{
    sqlite_int64 v;

    if (sqlite3_column_type(cursor, iCol) == SQLITE_NULL) {
	*tmp = NULL;
	return 0;
    }

    if (sqlite3_errcode(db) != SQLITE_OK)
	return ENOMEM; /* Almost certainly what it is; XXX need a map func */

    v = sqlite3_column_int64(cursor, iCol);
    if (v < 0 || v > ((2^31) - 1))
	return EOVERFLOW;

    if (sqlite3_errcode(db) != SQLITE_OK)
	return ENOMEM; /* Almost certainly what it is; XXX need a map func */

    *tmp = malloc(sizeof (**tmp));
    if (*tmp == NULL)
	return ENOMEM;

    **tmp = (unsigned int)v;
    return 0;
}


/**
 * Function to map a result row for a query into an enctype array.
 *
 * The enctypes column value is expected to be a string of numbers.
 */
static krb5_error_code
hdb_sqlite_col2etypes(krb5_context context,
		      sqlite3 *db,
		      sqlite3_stmt *cursor,
		      int iCol,
		      struct hdb_entry_etypes **hdb_etypes)
{
    int ret = 0;
    long etype;
    unsigned int *etypes = NULL;
    unsigned int *tmp;
    int count = 0;
    int allocd = 0;
    const unsigned char *s;
    const char *p;

    *hdb_etypes = NULL;
    s = sqlite3_column_text(cursor, iCol);
    if (s == NULL) {
	if (sqlite3_errcode(db) != SQLITE_OK)
	    return ENOMEM; /* XXX Need an error mapping function */
	return 0;
    }

    /* We expect a colon-separated list of decimals */
    for (p = (const char *)s; *p != '\0'; p = strchr(p, ':') + 1) {
	errno = 0;
	etype = strtol(p, NULL, 10);
	if (errno != 0 || etype < 0)
	    continue; /* fail gracefully */

	if (allocd == count) {
	    tmp = realloc(etypes, allocd + 8);
	    if (tmp == NULL) {
		ret = ENOMEM;
		goto out;
	    }
	    etypes = tmp;
	    etypes[count++] = (unsigned int)etype;
	    allocd += 8;
	}
    }

    *hdb_etypes = calloc(1, sizeof (**hdb_etypes));
    if (*hdb_etypes == NULL) {
	ret = ENOMEM;
	goto out;
    }

    (*hdb_etypes)->len = count;
    (*hdb_etypes)->val = etypes;

out:
    if (ret != 0)
	free(etypes);
    return (ret);
}


/**
 * Function to dequote a SQLite3 quote()d string.
 *
 * @param s	Input string
 * @param out	Output string (not necessarily NUL-terminated!)
 * @param nxt	Pointer to one past the end of the output string, always
 *              a single quote character upon success; this is useful
 *              for iteration purporse (optional, may be NULL)
 * @param szp	Length, in bytes, of output string (not counting NUL
 *              terminator)
 * @param blobp	Whether the quoted string was a blob
 * @param freep	Whether the output string must be free()ed
 *
 * SQLite3's quote() function surrounds a string with single quotes and
 * quotes any embedded single quotes with a single quote each.  For
 * example, the string "a'b" becomes "'a''b'".  Blobs get quoted as
 * X'<hex string>' (all upper-case).  This function does not decode hex
 * blobs.
 *
 * This function has a fast path when there's no quoted quotes,
 * returning a pointer to the start of the string, length, and end of
 * the string, without modifying the string.  If a string has quoted
 * quotes then this outputs an allocated string.
 *
 * NOTE: This function only handles quoted UTF-8 text and blobs; it does
 *       NOT handle numeric values nor NULLs!
 */
static int
dequote(const unsigned char *s,
	unsigned char **out,
	const unsigned char **nxt,
	size_t *szp,
	int *blobp,
	int *freep)
{
    const unsigned char *p;
    unsigned char *n = NULL;
    unsigned char *tmp;
    size_t sz = 0;
    size_t len = 0;

    *out = NULL;
    *nxt = NULL;
    *freep = 0;
    *blobp = 0;

    if (s[0] != '\'' && s[0] != 'X') return EINVAL;
    if (s[0] == 'X') {
	*blobp = 1;
	if (s[1] != '\'') return EINVAL;
	s++; /* skip the leading X */
    }
    s++; /* skip the leading quote */
    *freep = 0;
    *out = (unsigned char *)s;

repeat:
    for (p = s; *p != '\0'; p++) {
	if (p[0] != '\'')
	    continue;
	/* We found a quote... */
	if (p[1] != '\'' && n == NULL)
	    goto fast_path; /* followed by non-quote in fast path -> done */

	if (*blobp) {
	    /* Blobs don't have quoted quotes in them */
	    free(n);
	    return EINVAL;
	}

	/* We have or had a quoted quote, so we must allocate and/or copy */
	goto slow_path;
    }

fast_path:
    /* Not an assert because we might have fallen out of the loop. */
    if (p[0] != '\'') {
	/* String must end in a quote */
	free(n);
	return EINVAL;
    }

    if (nxt != NULL)
	*nxt = p;
    *szp = (p - s);
    return 0;

slow_path:
    /* This is an assert because it's not input dependent */
    assert ( p[0] == '\'' && (p[1] == '\'' || n != NULL) );

    if ((p - s) > sz) {
	if (sz == 0)
	    sz += 8;
	sz += 2 * (p - s) + 1;
	tmp = realloc(n, sz);
	if (tmp == NULL) {
	    free(n);
	    return ENOMEM;
	}
	n = tmp;
    }
    memcpy(&n[len], s, p - s);
    len += (p - s);

    if (p[1] == '\'') {
	/* Insert dequoted quote */
	n[len++] = '\'';
	n[len] = '\0'; /* not needed... */
	s = p + 2;
	goto repeat;
    }

    /* p[1] != '\'' -> done! */
    n[len] = '\0';
    *freep = 1;
    *out = n;
    if (nxt != NULL)
	*nxt = p;
    *szp = len;
    return 0;
}


/**
 * A wrapper around dequote() that always returns a NUL-terminated
 * string that must be freed by calling free().
 *
 * @param in	A SQLite3 quote()ed string
 * @param nxt	Pointer to the ending single quote in the original
 *		(useful for iterating over concatenated quoted strings)
 * @param blobp	Set to true if the string is a blob
 *
 * Blobs are not decoded; they are output as hex strings.
 */
static unsigned char *
dequote_alloc(const unsigned char *in, const unsigned char **nxt, int *blobp)
{
    int ret;
    unsigned char *s;
    size_t sz;
    int freeit;

    errno = 0;
    ret = dequote(in, &s, nxt, &sz, blobp, &freeit);
    if (ret != 0) {
	if (ret > 0)
	    errno = ret;
	return NULL;
    }

    if (freeit)
	return s;

    return (unsigned char *)strndup((const char *)s, sz);
}


/**
 * A wrapper around dequote() that always returns a NUL-terminated
 * string that must be freed by calling free(), except for blobs, which
 * are decoded and NOT NUL-terminated.
 *
 * @param in	A SQLite3 quote()ed string
 * @param nxt	Pointer to the ending single quote in the original
 *		(useful for iterating over concatenated quoted strings)
 * @param szp	Set to the length, in bytes, of the ouput string (not
 *              counting NUL) or blob (not NUL-terminated).
 * @param blobp	Set to true if the string is a blob
 */
static unsigned char *
dequote_decode(const unsigned char *in, const unsigned char **nxt, size_t *szp, int *blobp)
{
    int ret;
    unsigned char *s;
    unsigned char *b = NULL;
    size_t sz;
    int freeit;
    int i, k;

    ret = dequote(in, &s, nxt, &sz, blobp, &freeit);
    errno = ret;
    if (ret != 0)
	return NULL;

    *szp = sz;

    if (freeit && !*blobp)
	return s;
    if (!freeit && !*blobp)
	return (unsigned char *)strndup((const char *)s, sz);

    /* We have a blob; decode it */
    if ((sz & 1) == 1)
	goto einval;

    b = memalign(sizeof (long), sz >> 1);
    if (b == NULL)
	return NULL;

    for (i = 0, k = 0; i < sz; i++, k++) {
	if (s[i] >= '0' && s[i] <= '9')
	    b[k] = (s[i] - '0') << 4;
	else if (s[i] >= 'A' && s[i] <= 'F')
	    b[k] = (10 + (s[i] - '0')) << 4;
	else
	    goto einval;
	i++;
	if (s[i] >= '0' && s[i] <= '9')
	    b[k] |= s[i] - '0';
	else if (s[i] >= 'A' && s[i] <= 'F')
	    b[k] |= 10 + (s[i] - '0');
	else
	    goto einval;
    }

    *szp = sz >> 1;
    return b;

einval:
    free(b);
    errno = EINVAL;
    return NULL;
}


/**
 * Decode stringified, quoted PKINIT ACL list and add it to the
 * HDB_Extensions.
 */
static krb5_error_code
hdb_sqlite_col2pkinit_acls(krb5_context context,
			   sqlite3 *db,
			   sqlite3_stmt *cursor,
			   int iCol,
			   hdb_entry *entry)
{
    krb5_error_code ret;
    int is_blob;
    int i = 0;
    int alloced = 0;
    heim_utf8_string *str_ptr;
    const unsigned char *nxt;
    const unsigned char *inner_nxt;
    const unsigned char *sql_str = NULL;
    unsigned char *s = NULL;
    unsigned char *inner_s = NULL;
    HDB_extension tmp, tmp2;
    HDB_Ext_PKINIT_acl *pkinit_acl = &tmp.data.u.pkinit_acl;

    pkinit_acl->len = 0;
    pkinit_acl->val = NULL;

    tmp2.data.u.pkinit_acl.val = 0;

    /*
     * We expect the ACL to be a comma-separated list of quoted
     * strings, which are themselves a list of three quoted values (none
     * NULL), thus always a string.
     */
    sql_str = sqlite3_column_text(cursor, iCol);
    if (sql_str == NULL) {
	if (sqlite3_errcode(db) != SQLITE_OK)
	    return ENOMEM; /* XXX */
	return 0;
    }

    /*
     * Conventions for this loop (and repeated pattern in other, similar
     * functions below):
     *
     *  - The loop is over dequote_{alloc, decode}(), using the nxt
     *    output argument of it to iterate over the list of quoted
     *    strings.
     *  - The string returned by dequote_alloc() or dequote_decode() is
     *    returned at the top of the loop.
     *  - The dequoted value may be a list of quoted values, always with
     *    structure (rather than just a SEQUENCE OF), so we don't loop
     *    for that one.  We do maintain an inner_s and inner_nxt
     *    variables for parsing the inner list.
     *  - We free inner_s at the top of the loop (well, near the top).
     *  - We also free inner_s before each subsequent dequoting in the
     *    loop.
     *  - We set inner_s = NULL whenever we store the value in a place
     *    where free_HDB_Ext_*() would free it.
     *
     * Would that we could generate or macro-ify this code.  We could
     * probably get the ASN.1 compiler to generate this, actually, but
     * that's a larger undertaking.  Some day...
     *
     * At the 'out' label we free s and inner_s, and we call the
     * appropriate free_HDB_Ext_*() function.
     */
    nxt = sql_str;
    do {
	free(s);
	s = dequote_alloc(nxt, &nxt, &is_blob);
	if (is_blob) {
	    ret = EINVAL;
	    goto out;
	}
	if (s == NULL && errno != 0) {
	    ret = errno;
	    goto out;
	}
	if (s == NULL)
	    break;
	if (i >= alloced) {
	    alloced *= 2;
	    tmp2.data.u.pkinit_acl.val =
		realloc(pkinit_acl->val, sizeof (*pkinit_acl->val) * alloced);
	    if (tmp2.data.u.pkinit_acl.val == NULL) {
		ret = ENOMEM;
		goto out;
	    }
	    pkinit_acl->val = tmp2.data.u.pkinit_acl.val;
	}
	pkinit_acl->val[i].subject = NULL;
	pkinit_acl->val[i].issuer = NULL;
	pkinit_acl->val[i].anchor = NULL;

	free(inner_s);

	/* Get the subject name */
	inner_nxt = s;
	inner_s = dequote_alloc(inner_nxt, &inner_nxt, &is_blob);
	if (inner_s == NULL) {
	    if (errno != 0) {
		ret = errno;
		goto out;
	    }
	    goto bottom;
	}
	if (is_blob) {
	    ret = EINVAL;
	    goto out;
	}
	pkinit_acl->val[i].subject = (heim_utf8_string)inner_s;
	inner_s = NULL;
	if (inner_nxt[1] != ':')
	    goto bottom;

	/* Get the issuer */
	inner_s = dequote_alloc(inner_nxt + 2, &inner_nxt, &is_blob);
	if (inner_s == NULL) {
	    if (errno != 0) {
		ret = errno;
		goto out;
	    }
	    goto bottom;
	}
	if (is_blob) {
	    ret = EINVAL;
	    goto out;
	}
	str_ptr = malloc(sizeof (*str_ptr));
	if (str_ptr == NULL) {
	    ret = errno;
	    goto out;
	}
	*str_ptr = (heim_utf8_string)inner_s;
	pkinit_acl->val[i].issuer = str_ptr;
	inner_s = NULL;
	if (inner_nxt[1] != ':')
	    goto bottom;

	/* Get the anchor */
	inner_s = dequote_alloc(inner_nxt + 2, &inner_nxt, &is_blob);
	if (inner_s == NULL) {
	    if (errno != 0) {
		ret = errno;
		goto out;
	    }
	    goto bottom;
	}
	if (is_blob) {
	    ret = EINVAL;
	    goto out;
	}
	str_ptr = malloc(sizeof (*str_ptr));
	if (str_ptr == NULL) {
	    ret = errno;
	    goto out;
	}
	*str_ptr = (heim_utf8_string)inner_s;
	pkinit_acl->val[i].anchor = str_ptr;
	inner_s = NULL;
	/* We ignore any trailing values */

bottom:
	assert( nxt[0] != '\0' );
	if (nxt[1] != ',')
	    break;
    } while (1);

    pkinit_acl->len = i;
    tmp.data.element = choice_HDB_extension_data_pkinit_acl;

    ret = hdb_replace_extension(context, entry, &tmp);

out:
    if (ret != 0) {
	free_HDB_Ext_PKINIT_acl(pkinit_acl);
	free(inner_s);
	free(s);
    }

    return ret;
}


/**
 * Decode stringified, quoted PKINIT certificate hashes list and add it
 * to the HDB_Extensions.
 */
static krb5_error_code
hdb_sqlite_col2pkinit_cert_hashes(krb5_context context,
				  sqlite3 *db,
				  sqlite3_stmt *cursor,
				  int iCol,
				  hdb_entry *entry)
{
    krb5_error_code ret;
    int is_blob;
    int i = 0;
    int alloced = 0;
    const unsigned char *sql_str;
    const unsigned char *nxt;
    const unsigned char *inner_nxt;
    unsigned char *s = NULL;
    unsigned char *inner_s = NULL;
    heim_oid oid;
    size_t bytes;
    HDB_extension tmp, tmp2;
    HDB_Ext_PKINIT_hash *pkinit_cert_hash = &tmp.data.u.pkinit_cert_hash;

    pkinit_cert_hash->len = 0;
    pkinit_cert_hash->val = NULL;

    tmp2.data.u.pkinit_cert_hash.val = 0;

    /*
     * We expect the cert hashes to be a comma-separated list of quoted
     * strings, which are themselves a list of three quoted values (none
     * NULL), thus always a string.
     */
    sql_str = sqlite3_column_text(cursor, iCol);
    if (sql_str == NULL) {
	if (sqlite3_errcode(db) != SQLITE_OK)
	    return ENOMEM; /* XXX */
	return 0;
    }

    nxt = sql_str;
    do {
	free(s);
	s = dequote_alloc(nxt, &nxt, &is_blob);
	if (is_blob) {
	    ret = EINVAL;
	    goto out;
	}
	if (s == NULL && errno != 0) {
	    ret = errno;
	    goto out;
	}
	if (s == NULL)
	    break;
	if (i >= alloced) {
	    alloced *= 2;
	    tmp2.data.u.pkinit_cert_hash.val =
		realloc(pkinit_cert_hash->val,
			sizeof (*pkinit_cert_hash->val) * alloced);
	    if (tmp2.data.u.pkinit_cert_hash.val == NULL) {
		ret = ENOMEM;
		goto out;
	    }
	    pkinit_cert_hash->val = tmp2.data.u.pkinit_cert_hash.val;
	}

	free(inner_s);

	/* Get the digest OID */
	inner_s = dequote_decode(s, &inner_nxt, &bytes, &is_blob);
	if (is_blob) {
	    oid.length = bytes;
	    oid.components = (unsigned *)inner_s;
	    inner_s = NULL;
	} else {
	    ret = der_parse_heim_oid((const char *)inner_s, ".", &oid);
	    if (ret != 0)
		goto out;
	}
	pkinit_cert_hash->val[i].digest_type = oid;
	if (inner_nxt[1] != ':')
	    goto bottom;
	free(inner_s);
	/* Get the digest */
	inner_s = dequote_decode(inner_nxt + 2, &inner_nxt, &bytes, &is_blob);
	if (!is_blob) {
	    ret = EINVAL;
	    goto out;
	}
	pkinit_cert_hash->val[i].digest.length = bytes;
	pkinit_cert_hash->val[i].digest.data = inner_s;
	inner_s = NULL;
	/* We ignore any trailing values */

bottom:
	assert( nxt[0] != '\0' );

	if (nxt[1] != ',')
	    break;
    } while (1);

    pkinit_cert_hash->len = i;
    tmp.data.element = choice_HDB_extension_data_pkinit_cert_hash;

    ret = hdb_replace_extension(context, entry, &tmp);

out:
    if (ret != 0) {
	free_HDB_Ext_PKINIT_hash(pkinit_cert_hash);
	free(inner_s);
	free(s);
    }

    return ret;
}


/**
 * Decode stringified, quoted PKINIT certificate list and add it to the
 * HDB_Extensions.
 */
static krb5_error_code
hdb_sqlite_col2pkinit_certs(krb5_context context,
			    sqlite3 *db,
			    sqlite3_stmt *cursor,
			    int iCol,
			    hdb_entry *entry)
{
    krb5_error_code ret;
    int is_blob;
    int i = 0;
    int alloced = 0;
    const unsigned char *nxt;
    const unsigned char *inner_nxt;
    const unsigned char *sql_str;
    unsigned char *s = NULL;
    unsigned char *inner_s = NULL;
    size_t bytes;
    HDB_extension tmp, tmp2;
    HDB_Ext_PKINIT_cert *pkinit_cert = &tmp.data.u.pkinit_cert;

    pkinit_cert->len = 0;
    pkinit_cert->val = NULL;

    tmp2.data.u.pkinit_cert.val = 0;

    sql_str = sqlite3_column_text(cursor, iCol);
    if (sql_str == NULL) {
	if (sqlite3_errcode(db) != SQLITE_OK)
	    return ENOMEM; /* XXX */
	return 0;
    }

    nxt = sql_str;
    do {
	free(s);
	s = dequote_alloc(nxt, &nxt, &is_blob);
	if (is_blob) {
	    ret = EINVAL;
	    goto out;
	}
	if (s == NULL && errno != 0) {
	    ret = errno;
	    goto out;
	}
	if (s == NULL)
	    break;
	if (i >= alloced) {
	    alloced *= 2;
	    tmp2.data.u.pkinit_cert.val =
		realloc(pkinit_cert->val,
			sizeof (*pkinit_cert->val) * alloced);
	    if (tmp2.data.u.pkinit_cert.val == NULL) {
		ret = ENOMEM;
		goto out;
	    }
	    pkinit_cert->val = tmp2.data.u.pkinit_cert.val;
	}

	if (inner_nxt[1] != ':') {
	    ret = EINVAL;
	    goto out; /* digest is not optional */
	}
	free(inner_s);

	/* Get the digest */
	inner_s = dequote_decode(s, &inner_nxt, &bytes, &is_blob);
	if (!is_blob) {
	    ret = EINVAL;
	    goto out;
	}
	pkinit_cert->val[i].cert.length = bytes;
	pkinit_cert->val[i].cert.data = inner_s;
	inner_s = NULL;
	/* We ignore any trailing values */

	assert( nxt[0] != '\0' );

	if (nxt[1] != ',')
	    break;
    } while (1);

    pkinit_cert->len = i;
    tmp.data.element = choice_HDB_extension_data_pkinit_cert;

    ret = hdb_replace_extension(context, entry, &tmp);

out:
    if (ret != 0) {
	free_HDB_Ext_PKINIT_cert(pkinit_cert);
	free(inner_s);
	free(s);
    }

    return ret;
}


/**
 * Decode stringified, quoted OK to delegate to principal name list and
 * add it to the HDB_Extensions.
 */
static krb5_error_code
hdb_sqlite_col2deleg_to(krb5_context context,
			sqlite3 *db,
			sqlite3_stmt *cursor,
			int iCol,
			hdb_entry *entry)
{
    krb5_error_code ret;
    int is_blob;
    int i = 0;
    int alloced = 0;
    const unsigned char *sql_str;
    const unsigned char *nxt;
    unsigned char *s = NULL;
    Principal *princ;
    Principal *princs = NULL;
    Principal *tmp_princs;
    HDB_extension tmp;
    HDB_Ext_Constrained_delegation_acl *deleg = &tmp.data.u.allowed_to_delegate_to;

    deleg->len = 0;
    deleg->val = NULL;

    sql_str = sqlite3_column_text(cursor, iCol);
    if (sql_str == NULL) {
	if (sqlite3_errcode(db) != SQLITE_OK)
	    return ENOMEM; /* XXX */
	return 0;
    }

    nxt = sql_str;
    do {
	s = dequote_alloc(nxt, &nxt, &is_blob);
	if (s == NULL && errno != 0) {
	    ret = errno;
	    goto out;
	}
	if (s == NULL)
	    break;
	if (i >= alloced) {
	    alloced *= 2;
	    tmp_princs = realloc(princs, sizeof (*princs) * alloced);
	    if (tmp_princs == NULL) {
		ret = ENOMEM;
		goto out;
	    }
	    princs = tmp_princs;
	    deleg->val = princs;
	}
	ret = krb5_parse_name(context, (char *)s, &princ);
	if (ret != 0)
	    continue; /* fail gracefully? */
	princs[i++] = *princ;
	free(s);
    } while (1);

    deleg->len = i;
    tmp.data.element = choice_HDB_extension_data_allowed_to_delegate_to;

    ret = hdb_replace_extension(context, entry, &tmp);

out:
    if (ret != 0) {
	free_HDB_Ext_Constrained_delegation_acl(deleg);
	free(s);
    }

    return ret;
}


/**
 * Decode stringified, quoted LanMan OWF list and add it to the
 * HDB_Extensions.
 */
static krb5_error_code
hdb_sqlite_col2LM_OWF(krb5_context context,
		      sqlite3 *db,
		      sqlite3_stmt *cursor,
		      int iCol,
		      hdb_entry *entry)
{
    return 0;
}


/**
 * Decode stringified, quoted password and add it to the HDB_Extensions.
 */
static krb5_error_code
hdb_sqlite_col2password(krb5_context context,
			sqlite3 *db,
			sqlite3_stmt *cursor,
			int mkvnoCol,
			int pwCol,
			hdb_entry *entry)
{
    int ret;
    int is_blob;
    int mkvno = 0;
    const unsigned char *sql_str;
    unsigned char *s;
    size_t bytes;
    HDB_extension tmp;
    HDB_Ext_Password *pw = &tmp.data.u.password;

    if (sqlite3_column_type(cursor, mkvnoCol) != SQLITE_NULL) {
	mkvno = sqlite3_column_int(cursor, mkvnoCol);

	if (sqlite3_errcode(db) != SQLITE_OK)
	    return ENOMEM; /* XXX */
    }

    /*
     * We expect the password to be a quoted blob, or a quoted string,
     * thus always a string, even when encrypted.
     */
    sql_str = sqlite3_column_text(cursor, pwCol);
    if (sql_str == NULL) {
	if (sqlite3_errcode(db) != SQLITE_OK)
	    return ENOMEM; /* XXX */
	return 0;
    }

    /*
     * Note that this isn't a list because HDB-Ext-Password is not a
     * SEQUENCE OF.  It'd be useful to have such a thing for password
     * history!
     */
    s = dequote_decode(sql_str, NULL, &bytes, &is_blob);
    if (s == NULL)
	return errno; /* might be 0, but then there's nothing to do here */

    pw->mkvno = malloc(sizeof (*pw->mkvno));
    if (pw->mkvno == NULL) {
	free(s);
	return errno;
    }
    *pw->mkvno = mkvno;
    pw->password.length = bytes;
    pw->password.data = s;
    tmp.data.element = choice_HDB_extension_data_password;

    ret = hdb_replace_extension(context, entry, &tmp);
    if (ret != 0)
	free(s);

    return ret;
}


/**
 * Decode stringified, quoted Principal name alias list and add it to
 * the HDB_Extensions.
 */
static krb5_error_code
hdb_sqlite_col2aliases(krb5_context context,
		       sqlite3 *db,
		       sqlite3_stmt *cursor,
		       int iCol,
		       hdb_entry *entry)
{
    krb5_error_code ret;
    int is_blob;
    int i = 0;
    int alloced = 0;
    const unsigned char *sql_str;
    const unsigned char *nxt;
    unsigned char *s = NULL;
    Principal *princ;
    Principal *princs = NULL;
    Principal *tmp_princs;
    HDB_extension tmp;
    HDB_Ext_Aliases *aliases = &tmp.data.u.aliases;

    aliases->case_insensitive = 0;
    aliases->aliases.len = 0;
    aliases->aliases.val = NULL;

    /*
     * We expect the aliases to be a comma-separated list of quoted
     * strings, thus always a string.
     */
    sql_str = sqlite3_column_text(cursor, iCol);
    if (sql_str == NULL) {
	if (sqlite3_errcode(db) != SQLITE_OK)
	    return ENOMEM; /* XXX */
	return 0;
    }

    nxt = sql_str;
    do {
	s = dequote_alloc(nxt, &nxt, &is_blob);
	if (s == NULL && errno != 0) {
	    ret = errno;
	    goto out;
	}
	if (s == NULL)
	    break;
	if (i >= alloced) {
	    alloced *= 2;
	    tmp_princs = realloc(princs, sizeof (*princs) * alloced);
	    if (tmp_princs == NULL) {
		ret = ENOMEM;
		goto out;
	    }
	    princs = tmp_princs;
	    aliases->aliases.val = princs;
	}
	ret = krb5_parse_name(context, (char *)s, &princ);
	princs[i++] = *princ; /* XXX */
	free(s);
    } while (1);

    aliases->aliases.len = i;
    tmp.data.element = choice_HDB_extension_data_aliases;

    ret = hdb_replace_extension(context, entry, &tmp);

out:
    if (ret != 0) {
	free_HDB_Ext_Aliases(aliases);
	free(s);
    }

    return ret;
}


/**
 * Decode time of last password change and add it to the HDB_Extensions.
 */
static krb5_error_code
hdb_sqlite_col2last_pw_chg(krb5_context context,
			   sqlite3 *db,
			   sqlite3_stmt *cursor,
			   int iCol,
			   hdb_entry *entry)
{
    HDB_extension tmp;
    sqlite_int64 tmv;

    if (sqlite3_column_type(cursor, iCol) == SQLITE_NULL)
	return 0;

    if (sqlite3_errcode(db) != SQLITE_OK)
	return ENOMEM; /* Almost certainly what it is; XXX need a map func */

    tmv = sqlite3_column_int64(cursor, iCol);
    if (tmv < 0)
	return EOVERFLOW;

    if (sqlite3_errcode(db) != SQLITE_OK)
	return ENOMEM; /* Almost certainly what it is; XXX need a map func */

    tmp.data.u.last_pw_change = (KerberosTime)tmv;
    tmp.data.element = choice_HDB_extension_data_last_pw_change;
    return hdb_replace_extension(context, entry, &tmp);
}


/**
 * Function to map a result row for a query into an HDB entry.
 *
 * @param context   The current krb5 context
 * @param flags     HDB_F_*
 * @param cursor    The SQLite3 statement the current row of which to
 *		    to decode
 * @param entry	    The HDB entry (output)
 *
 * @return	    0 if OK, an error code if not
 */
static krb5_error_code
hdb_sqlite_row2entry(krb5_context context,
		     int flags,
		     sqlite3 *db,
		     sqlite3_stmt *cursor,
		     hdb_entry *entry)
{
    krb5_error_code ret;

    ret = hdb_sqlite_col2principal(context, db, cursor, 0, &entry->principal);
    if (ret) goto out;

    entry->kvno = (unsigned int)sqlite3_column_int(cursor, 1);

    if (flags & HDB_F_ADMIN_DATA) {
	ret = hdb_sqlite_col2event(context, db, cursor, 2, 3,
				   &entry->created_by,
				   NULL);
	if (ret) goto out;

	ret = hdb_sqlite_col2event(context, db, cursor, 4, 5, NULL,
				   &entry->modified_by);
	if (ret) goto out;
    }

    ret = hdb_sqlite_col2time(context, db, cursor, 5, &entry->valid_start);
    if (ret) goto out;
    ret = hdb_sqlite_col2time(context, db, cursor, 6, &entry->valid_end);
    if (ret) goto out;
    ret = hdb_sqlite_col2time(context, db, cursor, 7, &entry->pw_end);
    if (ret) goto out;
    ret = hdb_sqlite_col2uint31(context, db, cursor, 8, &entry->max_life);
    if (ret) goto out;
    ret = hdb_sqlite_col2uint31(context, db, cursor, 9, &entry->max_renew);
    if (ret) goto out;

    entry->flags = int2HDBFlags((unsigned int)sqlite3_column_int(cursor, 1));

    ret = hdb_sqlite_col2etypes(context, db, cursor, 10, &entry->etypes);
    if (ret) goto out;

    /* We don't keep generation info in the SQLite3 backend yet */

    ret = hdb_sqlite_col2password(context, db, cursor, 11, 12, entry);
    if (ret) goto out;
    ret = hdb_sqlite_col2last_pw_chg(context, db, cursor, 13, entry);
    if (ret) goto out;

    if (flags & HDB_F_ADMIN_DATA) {
	ret = hdb_sqlite_col2aliases(context, db, cursor, 14, entry);
	if (ret) goto out;

	/*
	 * XXX These are not admin data, but they are things that are
	 * not needed in the KDC fastpath.  We should define a new
	 * HDB_F_ flag to refer to thse items.
	 */
	ret = hdb_sqlite_col2pkinit_acls(context, db, cursor, 15, entry);
	if (ret) goto out;
	ret = hdb_sqlite_col2pkinit_cert_hashes(context, db, cursor, 16, entry);
	if (ret) goto out;
	ret = hdb_sqlite_col2pkinit_certs(context, db, cursor, 17, entry);
	if (ret) goto out;
	ret = hdb_sqlite_col2deleg_to(context, db, cursor, 18, entry);
	if (ret) goto out;
	ret = hdb_sqlite_col2LM_OWF(context, db, cursor, 19, entry);
	if (ret) goto out;
    }

out:
    if (ret)
	free_hdb_entry(entry);
    return (ret);
}

/**
 * Wrapper around sqlite3_prepare_v2.
 *
 * @param context   The current krb5 context
 * @param statement Where to store the pointer to the statement
 *                  after preparing it
 * @param str       SQL code for the statement
 *
 * @return          0 if OK, an error code if not
 */
static krb5_error_code
hdb_sqlite_prepare_stmt(krb5_context context,
                        sqlite3 *db,
                        sqlite3_stmt **statement,
                        const char *str,
			const char **str_tail)
{
    int ret, tries = 0;

    ret = sqlite3_prepare_v2(db, str, -1, statement, str_tail);
    while((tries++ < MAX_RETRIES) &&
	  ((ret == SQLITE_BUSY) ||
           (ret == SQLITE_IOERR_BLOCKED) ||
           (ret == SQLITE_LOCKED))) {
	krb5_warnx(context, "hdb-sqlite: prepare busy");
        sleep(1);
        ret = sqlite3_prepare_v2(db, str, -1, statement, NULL);
    }

    if (ret != SQLITE_OK) {
        krb5_set_error_message(context, EINVAL,
			       "Failed to prepare stmt %s: %s",
			       str, sqlite3_errmsg(db));
        return EINVAL;
    }

    return 0;
}

/**
 * Wrapper around hdb_sqlite_prepare_stmt() that executes a string of
 * many statements.  This is used to run many statements, such as when
 * loading a schema.
 */
static krb5_error_code
hdb_sqlite_exec_many(krb5_context context,
		     sqlite3 *db,
		     const char *str)
{
    int ret;
    const char *str_tail = str;
    sqlite3_stmt *stmt = NULL;

    do {
	ret = hdb_sqlite_prepare_stmt(context, db,  &stmt, str, &str_tail);
	if (ret) goto out;

	/*
	 * We loop over sqlite3_step() just in case we have an INSERT ..
	 * SELECT .. that needs stepping.
	 */
	do {
	    ret = sqlite3_step(stmt);
	} while (ret == SQLITE_ROW);
	if (ret != SQLITE_DONE) goto out;
	(void) sqlite3_finalize(stmt);
	str = str_tail;
    } while (str_tail != NULL);

    return (ret);

out:
    if (stmt != NULL)
	(void) sqlite3_finalize(stmt);

    krb5_set_error_message(context, EINVAL,
			   "Failed to execute many statements: %s",
			   sqlite3_errmsg(db));
    ret = EINVAL;
    return (ret);
}

/**
 * A wrapper around sqlite3_exec.
 *
 * @param context    The current krb5 context
 * @param database   An open sqlite3 database handle
 * @param statement  SQL code to execute
 * @param error_code What to return if the statement fails
 *
 * @return           0 if OK, else error_code
 */
static krb5_error_code
hdb_sqlite_exec_stmt(krb5_context context,
                     sqlite3 *database,
                     const char *statement,
                     krb5_error_code error_code)
{
    int ret;

    ret = sqlite3_exec(database, statement, NULL, NULL, NULL);

    while(((ret == SQLITE_BUSY) ||
           (ret == SQLITE_IOERR_BLOCKED) ||
           (ret == SQLITE_LOCKED))) {
	krb5_warnx(context, "hdb-sqlite: exec busy: %d", (int)getpid());
        sleep(1);
        ret = sqlite3_exec(database, statement, NULL, NULL, NULL);
    }

    if (ret != SQLITE_OK && error_code) {
        krb5_set_error_message(context, error_code,
			       "Execute %s: %s", statement,
                              sqlite3_errmsg(database));
        return error_code;
    }

    return 0;
}

/**
 * Opens an sqlite3 database handle to a file, may create the
 * database file depending on flags.
 *
 * @param context The current krb5 context
 * @param db      Heimdal database handle
 * @param flags   Controls whether or not the file may be created,
 *                may be 0 or SQLITE_OPEN_CREATE
 */
static krb5_error_code
hdb_sqlite_open_database(krb5_context context, HDB *db, int flags)
{
    int ret;
    hdb_sqlite_db *hsdb = (hdb_sqlite_db*) db->hdb_db;

    ret = sqlite3_open_v2(hsdb->db_file, &hsdb->db,
                          SQLITE_OPEN_READWRITE | flags, NULL);

    if (ret) {
        if (hsdb->db) {
	    ret = ENOENT;
            krb5_set_error_message(context, ret,
                                  "Error opening sqlite database %s: %s",
                                  hsdb->db_file, sqlite3_errmsg(hsdb->db));
            sqlite3_close(hsdb->db);
            hsdb->db = NULL;
        } else
	    ret = krb5_enomem(context);
        return ret;
    }

    return 0;
}

static int
hdb_sqlite_step(krb5_context context, sqlite3 *db, sqlite3_stmt *stmt)
{
    int ret;

    ret = sqlite3_step(stmt);
    while(((ret == SQLITE_BUSY) ||
           (ret == SQLITE_IOERR_BLOCKED) ||
           (ret == SQLITE_LOCKED))) {
	krb5_warnx(context, "hdb-sqlite: step busy: %d", (int)getpid());
        sleep(1);
        ret = sqlite3_step(stmt);
    }
    return ret;
}

/**
 * Closes the database and frees memory allocated for statements.
 *
 * @param context The current krb5 context
 * @param db      Heimdal database handle
 */
static krb5_error_code
hdb_sqlite_close_database(krb5_context context, HDB *db)
{
    hdb_sqlite_db *hsdb = (hdb_sqlite_db *) db->hdb_db;

    sqlite3_finalize(hsdb->get_version);
    sqlite3_finalize(hsdb->fetch);
    sqlite3_finalize(hsdb->get_ids);
    sqlite3_finalize(hsdb->add_entry);
    sqlite3_finalize(hsdb->add_principal);
    sqlite3_finalize(hsdb->add_alias);
    sqlite3_finalize(hsdb->delete_aliases);
    sqlite3_finalize(hsdb->update_entry);
    sqlite3_finalize(hsdb->remove);
    sqlite3_finalize(hsdb->get_all_entries);

    sqlite3_close(hsdb->db);

    return 0;
}

/**
 * Opens an sqlite database file and prepares it for use.
 * If the file does not exist it will be created.
 *
 * @param context  The current krb5_context
 * @param db       The heimdal database handle
 * @param filename Where to store the database file
 *
 * @return         0 if everything worked, an error code if not
 */
static krb5_error_code
hdb_sqlite_make_database(krb5_context context, HDB *db, const char *filename)
{
    int ret;
    int created_file = 0;
    hdb_sqlite_db *hsdb = (hdb_sqlite_db *) db->hdb_db;

    hsdb->db_file = strdup(filename);
    if(hsdb->db_file == NULL)
        return ENOMEM;

    ret = hdb_sqlite_open_database(context, db, 0);
    if (ret) {
        ret = hdb_sqlite_open_database(context, db, SQLITE_OPEN_CREATE);
        if (ret) goto out;

        created_file = 1;

	/*
	 * The way the schema is specified we could do this step even
	 * when we open an existing DB.  This would mostly only
	 * re-create TRIGGERs.  It might be worth doing.
	 */
	ret = hdb_sqlite_exec_many(context, hsdb->db, HDB_SQLITE_SCHEMA);
	if (ret) goto out;
    }

    ret = hdb_sqlite_prepare_stmt(context, hsdb->db,
                                  &hsdb->get_version,
                                  HDBSQLITE_GET_VERSION,
				  NULL);
    if (ret) goto out;
    ret = hdb_sqlite_prepare_stmt(context, hsdb->db,
                                  &hsdb->fetch,
                                  HDBSQLITE_FETCH,
				  NULL);
    if (ret) goto out;
    ret = hdb_sqlite_prepare_stmt(context, hsdb->db,
                                  &hsdb->get_ids,
                                  HDBSQLITE_GET_IDS,
				  NULL);
    if (ret) goto out;
    ret = hdb_sqlite_prepare_stmt(context, hsdb->db,
                                  &hsdb->add_entry,
                                  HDBSQLITE_ADD_ENTRY_DETAIL,
				  NULL);
    if (ret) goto out;
    ret = hdb_sqlite_prepare_stmt(context, hsdb->db,
                                  &hsdb->add_principal,
                                  HDBSQLITE_ADD_PRINCIPAL,
				  NULL);
    if (ret) goto out;
    ret = hdb_sqlite_prepare_stmt(context, hsdb->db,
                                  &hsdb->add_alias,
                                  HDBSQLITE_ADD_ALIAS,
				  NULL);
    if (ret) goto out;
    ret = hdb_sqlite_prepare_stmt(context, hsdb->db,
                                  &hsdb->delete_aliases,
                                  HDBSQLITE_DELETE_ALIASES,
				  NULL);
    if (ret) goto out;
    ret = hdb_sqlite_prepare_stmt(context, hsdb->db,
                                  &hsdb->update_entry,
                                  HDBSQLITE_UPDATE_ENTRY,
				  NULL);
    if (ret) goto out;
    ret = hdb_sqlite_prepare_stmt(context, hsdb->db,
                                  &hsdb->remove,
                                  HDBSQLITE_REMOVE,
				  NULL);
    if (ret) goto out;
    ret = hdb_sqlite_prepare_stmt(context, hsdb->db,
                                  &hsdb->get_all_entries,
                                  HDBSQLITE_GET_ALL_ENTRIES,
				  NULL);
    if (ret) goto out;

    ret = hdb_sqlite_step(context, hsdb->db, hsdb->get_version);
    if(ret == SQLITE_ROW) {
        hsdb->version = sqlite3_column_double(hsdb->get_version, 0);
    }
    sqlite3_reset(hsdb->get_version);
    ret = 0;

    if(hsdb->version != HDBSQLITE_VERSION) {
        ret = EINVAL;
        krb5_set_error_message(context, ret, "HDBSQLITE_VERSION mismatch");
    }

    if(ret) goto out;

    return 0;
    
 out:
    if (ret == 0)
	ret = errno;
    if (hsdb->db)
        sqlite3_close(hsdb->db);
    if (created_file)
        unlink(hsdb->db_file);
    
    return ret;
}

/**
 * Retrieves an entry by searching for the given
 * principal in the Principal database table, both
 * for canonical principals and aliases.
 *
 * @param context   The current krb5_context
 * @param db        Heimdal database handle
 * @param principal The principal whose entry to search for
 * @param flags     Currently only for HDB_F_DECRYPT
 * @param kvno	    kvno to fetch is HDB_F_KVNO_SPECIFIED use used
 *
 * @return          0 if everything worked, an error code if not
 */
static krb5_error_code
hdb_sqlite_fetch_kvno(krb5_context context, HDB *db, krb5_const_principal principal,
		      unsigned flags, krb5_kvno kvno, hdb_entry_ex *entry)
{
    int sqlite_error;
    krb5_error_code ret;
    char *principal_string;
    hdb_sqlite_db *hsdb = (hdb_sqlite_db*)(db->hdb_db);
    sqlite3_stmt *fetch = hsdb->fetch;

    ret = krb5_unparse_name(context, principal, &principal_string);
    if (ret) {
        free(principal_string);
        return ret;
    }

    if (flags & HDB_F_KVNO_SPECIFIED && kvno != 0) {
	fetch = hsdb->fetch_kvno;
	sqlite3_bind_int(fetch, 2, kvno);
    }

    sqlite3_bind_text(fetch, 1, principal_string, -1, SQLITE_STATIC);

    sqlite_error = hdb_sqlite_step(context, hsdb->db, fetch);
    if (sqlite_error != SQLITE_ROW) {
        if(sqlite_error == SQLITE_DONE) {
            ret = HDB_ERR_NOENTRY;
            goto out;
        } else {
            ret = EINVAL;
            krb5_set_error_message(context, ret,
                                  "sqlite fetch failed: %d",
                                  sqlite_error);
            goto out;
        }
    }

    ret = hdb_sqlite_row2entry(context, flags, hsdb->db, fetch, &entry->entry);
    if(ret)
        goto out;

    if (db->hdb_master_key_set && (flags & HDB_F_DECRYPT)) {
        ret = hdb_unseal_keys(context, db, &entry->entry);
        if(ret) {
           hdb_free_entry(context, entry);
           goto out;
        }
    }

    ret = 0;

out:
    sqlite3_clear_bindings(fetch);
    sqlite3_reset(fetch);

    free(principal_string);

    return ret;
}

/**
 * Convenience function to step a prepared statement with no
 * value once.
 *
 * @param context   The current krb5_context
 * @param statement A prepared sqlite3 statement
 *
 * @return        0 if everything worked, an error code if not
 */
static krb5_error_code
hdb_sqlite_step_once(krb5_context context, HDB *db, sqlite3_stmt *statement)
{
    int ret;
    hdb_sqlite_db *hsdb = (hdb_sqlite_db *) db->hdb_db;

    ret = hdb_sqlite_step(context, hsdb->db, statement);
    sqlite3_clear_bindings(statement);
    sqlite3_reset(statement);

    return ret;
}


/**
 * Stores an hdb_entry in the database. If flags contains HDB_F_REPLACE
 * a previous entry may be replaced.
 *
 * @param context The current krb5_context
 * @param db      Heimdal database handle
 * @param flags   May currently only contain HDB_F_REPLACE
 * @param entry   The data to store
 *
 * @return        0 if everything worked, an error code if not
 */
static krb5_error_code
hdb_sqlite_store(krb5_context context, HDB *db, unsigned flags,
                 hdb_entry_ex *entry)
{
    int ret;
    int i;
    sqlite_int64 entry_id;
    char *principal_string = NULL;
    char *alias_string;
    const HDB_Ext_Aliases *aliases;

    hdb_entry_ex orig;

    hdb_sqlite_db *hsdb = (hdb_sqlite_db *)(db->hdb_db);
    krb5_data value;
    sqlite3_stmt *get_ids = hsdb->get_ids;

    ret = hdb_sqlite_exec_stmt(context, hsdb->db,
                               "BEGIN IMMEDIATE TRANSACTION", EINVAL);
    if(ret != SQLITE_OK) {
	ret = EINVAL;
        krb5_set_error_message(context, ret, 
			       "SQLite BEGIN TRANSACTION failed: %s",
			       sqlite3_errmsg(hsdb->db));
        goto rollback;
    }

    /* XXX For now we'll not handle renames */
    
    ret = krb5_unparse_name(context,
                            entry->entry.principal, &principal_string);
    if (ret) {
        goto rollback;
    }

    ret = hdb_sqlite_fetch_kvno(context, db, entry->entry.principal,
				HDB_F_GET_CLIENT | HDB_F_REPLACE |
				HDB_F_GET_CLIENT | HDB_F_GET_SERVER |
				HDB_F_GET_ANY | HDB_F_ADMIN_DATA,
				0, &orig);

    ret = hdb_seal_keys(context, db, &entry->entry);
    if(ret) {
        goto rollback;
    }

    ret = hdb_entry2value(context, &entry->entry, &value);
    if(ret) {
        goto rollback;
    }

    sqlite3_bind_text(get_ids, 1, principal_string, -1, SQLITE_STATIC);
    ret = hdb_sqlite_step(context, hsdb->db, get_ids);

    if(ret == SQLITE_DONE) { /* No such principal */

	/* XXX add all the other columns too */
	sqlite3_bind_text(hsdb->add_entry, hsdb->add_entry_pidx_canon_name,
                          principal_string, -1, SQLITE_STATIC);
	sqlite3_bind_blob(hsdb->add_entry, hsdb->add_entry_pidx_data,
                          value.data, value.length, SQLITE_STATIC);
        ret = hdb_sqlite_step(context, hsdb->db, hsdb->add_entry);
        sqlite3_clear_bindings(hsdb->add_entry);
        sqlite3_reset(hsdb->add_entry);
        if(ret != SQLITE_DONE)
            goto rollback;

        sqlite3_bind_text(hsdb->add_principal, 1,
                          principal_string, -1, SQLITE_STATIC);
        ret = hdb_sqlite_step(context, hsdb->db, hsdb->add_principal);
        sqlite3_clear_bindings(hsdb->add_principal);
        sqlite3_reset(hsdb->add_principal);
        if(ret != SQLITE_DONE)
            goto rollback;

        entry_id = sqlite3_column_int64(get_ids, 1);
        
    } else if(ret == SQLITE_ROW) { /* Found a principal */

        if(! (flags & HDB_F_REPLACE)) /* Not allowed to replace it */
            goto rollback;

        entry_id = sqlite3_column_int64(get_ids, 1);

        sqlite3_bind_int64(hsdb->delete_aliases, 1, entry_id);
        ret = hdb_sqlite_step_once(context, db, hsdb->delete_aliases);
        if(ret != SQLITE_DONE)
            goto rollback;

        sqlite3_bind_blob(hsdb->update_entry, 1,
                          value.data, value.length, SQLITE_STATIC);
        sqlite3_bind_int64(hsdb->update_entry, 2, entry_id);
        ret = hdb_sqlite_step_once(context, db, hsdb->update_entry);
        if(ret != SQLITE_DONE)
            goto rollback;

    } else {
	/* Error! */
        goto rollback;
    }

    ret = hdb_entry_get_aliases(&entry->entry, &aliases);
    if(ret || aliases == NULL)
        goto commit;

    for(i = 0; i < aliases->aliases.len; i++) {

        ret = krb5_unparse_name(context, &aliases->aliases.val[i],
				&alias_string);
        if (ret) {
            free(alias_string);
            goto rollback;
        }

        sqlite3_bind_text(hsdb->add_alias, 1, alias_string,
                          -1, SQLITE_STATIC);
        sqlite3_bind_int64(hsdb->add_alias, 2, entry_id);
        ret = hdb_sqlite_step_once(context, db, hsdb->add_alias);

        free(alias_string);
        
        if(ret != SQLITE_DONE)
            goto rollback;
    }

    ret = 0;

commit:

    free(principal_string);
    
    krb5_data_free(&value);

    sqlite3_clear_bindings(get_ids);
    sqlite3_reset(get_ids);
    
    ret = hdb_sqlite_exec_stmt(context, hsdb->db, "COMMIT", EINVAL);
    if(ret != SQLITE_OK)
	krb5_warnx(context, "hdb-sqlite: COMMIT problem: %d: %s",
		   ret, sqlite3_errmsg(hsdb->db));

    return ret;

rollback:

    krb5_warnx(context, "hdb-sqlite: store rollback problem: %d: %s",
	       ret, sqlite3_errmsg(hsdb->db));

    free(principal_string);

    ret = hdb_sqlite_exec_stmt(context, hsdb->db,
                               "ROLLBACK", EINVAL);
    return ret;
}

/**
 * This may be called often by other code, since the BDB backends
 * can not have several open connections. SQLite can handle
 * many processes with open handles to the database file
 * and closing/opening the handle is an expensive operation.
 * Hence, this function does nothing.
 *
 * @param context The current krb5 context
 * @param db      Heimdal database handle
 *
 * @return        Always returns 0
 */
static krb5_error_code
hdb_sqlite_close(krb5_context context, HDB *db)
{
    return 0;
}

/**
 * The opposite of hdb_sqlite_close. Since SQLite accepts
 * many open handles to the database file the handle does not
 * need to be closed, or reopened.
 *
 * @param context The current krb5 context
 * @param db      Heimdal database handle
 * @param flags   
 * @param mode_t  
 *
 * @return        Always returns 0
 */
static krb5_error_code
hdb_sqlite_open(krb5_context context, HDB *db, int flags, mode_t mode)
{
    return 0;
}

/**
 * Closes the databse and frees all resources.
 *
 * @param context The current krb5 context
 * @param db      Heimdal database handle
 *
 * @return        0 on success, an error code if not
 */
static krb5_error_code
hdb_sqlite_destroy(krb5_context context, HDB *db)
{
    int ret;
    hdb_sqlite_db *hsdb;

    ret = hdb_clear_master_key(context, db);

    hdb_sqlite_close_database(context, db);

    hsdb = (hdb_sqlite_db*)(db->hdb_db);

    free(hsdb->db_file);
    free(db->hdb_db);
    free(db);
    
    return ret;
}

/*
 * Not sure if this is needed.
 */
static krb5_error_code
hdb_sqlite_lock(krb5_context context, HDB *db, int operation)
{
    krb5_set_error_message(context, HDB_ERR_CANT_LOCK_DB,
			   "lock not implemented");
    return HDB_ERR_CANT_LOCK_DB;
}

/*
 * Not sure if this is needed.
 */
static krb5_error_code
hdb_sqlite_unlock(krb5_context context, HDB *db)
{
    krb5_set_error_message(context, HDB_ERR_CANT_LOCK_DB,
			  "unlock not implemented");
    return HDB_ERR_CANT_LOCK_DB;
}

/*
 * Should get the next entry, to allow iteration over all entries.
 */
static krb5_error_code
hdb_sqlite_nextkey(krb5_context context, HDB *db, unsigned flags,
                   hdb_entry_ex *entry)
{
    krb5_error_code ret = 0;
    int sqlite_error;
    krb5_data value;

    hdb_sqlite_db *hsdb = (hdb_sqlite_db *) db->hdb_db;

    sqlite_error = hdb_sqlite_step(context, hsdb->db, hsdb->get_all_entries);
    if(sqlite_error == SQLITE_ROW) {
	/* Found an entry */
        value.length = sqlite3_column_bytes(hsdb->get_all_entries, 0);
        value.data = (void *) sqlite3_column_blob(hsdb->get_all_entries, 0);
        memset(entry, 0, sizeof(*entry));
        ret = hdb_value2entry(context, &value, &entry->entry);
    }
    else if(sqlite_error == SQLITE_DONE) {
	/* No more entries */
        ret = HDB_ERR_NOENTRY;
        sqlite3_reset(hsdb->get_all_entries);
    }
    else {
	/* XXX SQLite error. Should be handled in some way. */
        ret = EINVAL;
    }

    return ret;
}

/*
 * Should get the first entry in the database.
 * What is flags used for?
 */
static krb5_error_code
hdb_sqlite_firstkey(krb5_context context, HDB *db, unsigned flags,
                    hdb_entry_ex *entry)
{
    hdb_sqlite_db *hsdb = (hdb_sqlite_db *) db->hdb_db;
    krb5_error_code ret;

    sqlite3_reset(hsdb->get_all_entries);

    ret = hdb_sqlite_nextkey(context, db, flags, entry);
    if(ret)
        return ret;

    return 0;
}

/*
 * Renames the database file.
 */
static krb5_error_code
hdb_sqlite_rename(krb5_context context, HDB *db, const char *new_name)
{
    hdb_sqlite_db *hsdb = (hdb_sqlite_db *) db->hdb_db;
    int ret;

    krb5_warnx(context, "hdb_sqlite_rename");

    if (strncasecmp(new_name, "sqlite:", 7) == 0)
	new_name += 7;

    hdb_sqlite_close_database(context, db);

    ret = rename(hsdb->db_file, new_name);
    free(hsdb->db_file);

    hdb_sqlite_make_database(context, db, new_name);

    return ret;
}

/*
 * Removes a principal, including aliases and associated entry.
 */
static krb5_error_code
hdb_sqlite_remove(krb5_context context, HDB *db,
                  krb5_const_principal principal)
{
    krb5_error_code ret;
    char *principal_string;
    hdb_sqlite_db *hsdb = (hdb_sqlite_db*)(db->hdb_db);
    sqlite3_stmt *remove = hsdb->remove;
    
    ret = krb5_unparse_name(context, principal, &principal_string);
    if (ret) {
        free(principal_string);
        return ret;
    }

    sqlite3_bind_text(remove, 1, principal_string, -1, SQLITE_STATIC);

    ret = hdb_sqlite_step(context, hsdb->db, remove);
    if (ret != SQLITE_DONE) {
	ret = EINVAL;
        krb5_set_error_message(context, ret,
                              "sqlite remove failed: %d",
                              ret);
    } else
        ret = 0;
    
    sqlite3_clear_bindings(remove);
    sqlite3_reset(remove);

    return ret;
}

/**
 * Create SQLITE object, and creates the on disk database if its doesn't exists.
 *
 * @param context A Kerberos 5 context.
 * @param db a returned database handle.
 * @param argument filename
 *
 * @return        0 on success, an error code if not
 */

krb5_error_code
hdb_sqlite_create(krb5_context context, HDB **db, const char *argument)
{
    krb5_error_code ret;
    hdb_sqlite_db *hsdb;

    *db = calloc(1, sizeof (**db));
    if (*db == NULL)
	return krb5_enomem(context);

    hsdb = (hdb_sqlite_db*) calloc(1, sizeof (*hsdb));
    if (hsdb == NULL) {
        free(*db);
        *db = NULL;
	return krb5_enomem(context);
    }

    (*db)->hdb_db = hsdb;

    /* XXX make_database should make sure everything else is freed on error */
    ret = hdb_sqlite_make_database(context, *db, argument);
    if (ret) {
        free((*db)->hdb_db);
        free(*db);

        return ret;
    }

    (*db)->hdb_master_key_set = 0;
    (*db)->hdb_openp = 0;
    (*db)->hdb_capability_flags = 0;

    (*db)->hdb_open = hdb_sqlite_open;
    (*db)->hdb_close = hdb_sqlite_close;

    (*db)->hdb_lock = hdb_sqlite_lock;
    (*db)->hdb_unlock = hdb_sqlite_unlock;
    (*db)->hdb_firstkey = hdb_sqlite_firstkey;
    (*db)->hdb_nextkey = hdb_sqlite_nextkey;
    (*db)->hdb_fetch_kvno = hdb_sqlite_fetch_kvno;
    (*db)->hdb_store = hdb_sqlite_store;
    (*db)->hdb_remove = hdb_sqlite_remove;
    (*db)->hdb_destroy = hdb_sqlite_destroy;
    (*db)->hdb_rename = hdb_sqlite_rename;
    (*db)->hdb__get = NULL;
    (*db)->hdb__put = NULL;
    (*db)->hdb__del = NULL;

    return 0;
}
