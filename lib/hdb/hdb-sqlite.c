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
#include "hdb-sqlite-statements.h"
#include "sqlite3.h"
#include <assert.h>
#include <ctype.h>
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
    sqlite3_stmt *fetch_fast;
    sqlite3_stmt *fetch_slow;
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
    int fetch_pidCol;
    int fetch_pcnameidCol;
    int fetch_pnameCol;
    int fetch_kvnoCol;
    int fetch_keysCol;
    int fetch_gentimeCol;
    int fetch_genusecCol;
    int fetch_gengenCol;
    int fetch_crbytimeCol;
    int fetch_crbypnameCol;
    int fetch_modbytimeCol;
    int fetch_modbypnameCol;
    int fetch_validstartCol;
    int fetch_validendCol;
    int fetch_pwendCol;
    int fetch_maxlifeCol;
    int fetch_maxrenewCol;
    int fetch_hdbflagsCol;
    int fetch_etypesCol;
    int fetch_pwmkvnoCol;
    int fetch_pwpwCol;
    int fetch_lastpwchgCol;
    int fetch_aliasesCol;
    int fetch_pkaclsCol;
    int fetch_pkcerthashesCol;
    int fetch_pkcertsCol;
    int fetch_delegtoCol;
    int fetch_lmowfCol;

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

/* XXX Update this */
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
hdb_sqlite_col2generation(krb5_context context,
			  sqlite3 *db,
			  sqlite3_stmt *cursor,
			  int timeCol,
			  int usecCol,
			  int genCol,
			  GENERATION **generation)
{
    sqlite_int64 v;

    *generation = calloc(1, sizeof (**generation));
    if (*generation == NULL)
	return errno;

    if (sqlite3_column_type(cursor, timeCol) != SQLITE_NULL) {
	v = sqlite3_column_int64(cursor, timeCol);
	(*generation)->time = (KerberosTime)v;
	if (v != (*generation)->time || v < 0)
	    (*generation)->time = 0;
    }

    if (sqlite3_column_type(cursor, usecCol) != SQLITE_NULL) {
	v = sqlite3_column_int64(cursor, usecCol);
	(*generation)->usec = (unsigned int)v;
	if (v != (*generation)->usec || v < 0)
	    (*generation)->usec = 0;
    }

    if (sqlite3_column_type(cursor, genCol) != SQLITE_NULL) {
	v = sqlite3_column_int64(cursor, genCol);
	(*generation)->gen = (unsigned int)v;
	if (v != (*generation)->gen || v < 0)
	    (*generation)->gen = 0;
    }

    return 0;
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
    krb5_error_code ret;
    sqlite_int64 tmv;
    KerberosTime tm;

    assert( ev != NULL || evp != NULL );

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
hdb_sqlite_col2uint(krb5_context context,
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
    krb5_error_code ret = 0;
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

#define DQSQLV_TYPE_NULL        0
#define DQSQLV_TYPE_INT64       1
#define DQSQLV_TYPE_STR         2
#define DQSQLV_TYPE_BLOB        3
#define DQSQLV_TYPE_OTHER       4


/**
 * A wrapper around dequote() that always returns a allocated strings
 * and blobs when the value dequoted is a string or a blob.  Also
 * supports integers and SQL NULL values.
 *
 * @param in	A SQLite3 quote()ed string
 * @param nxt	Pointer to the ending single quote in the original
 *		(useful for iterating over concatenated quoted strings)
 * @param typ	Indicates the type of the value dequoted (output)
 * @param str	Dequoted string, if type is text (output)
 * @param blob	Dequoted blob, if type is blob (output)
 * @param sz	Set to the length, in bytes, of the ouput string (not
 *              counting NUL) or blob (not NUL-terminated).
 * @param nump	64-bit signed integer value, if type is integer (output)
 */
static int
dequote_decode(const unsigned char *in,
	       const unsigned char **nxt,
	       int *typ,
	       unsigned char **str,
	       void **blob,
	       size_t *szp,
	       int64_t *nump)
{
    int ret;
    unsigned char *s = NULL;
    unsigned char *b = NULL;
    size_t sz;
    char *e;
    int freeit, is_blob;
    int i, k;
    int64_t num;

    if (str != NULL)
	*str = NULL;
    if (blob != NULL)
	*blob = NULL;
    if (szp != NULL)
	*szp = 0;
    if (typ != NULL)
	*typ = DQSQLV_TYPE_OTHER;

    if (in[0] == '\'' || (in[0] == 'X' && in[1] == '\'')) {
	ret = dequote(in, &s, nxt, &sz, &is_blob, &freeit);
	if (ret != 0)
	    return ret;
	if (szp != NULL)
	    *szp = sz;

	(*nxt)++;
	if (freeit && !is_blob) {
	    if (str != NULL)
		*str = s;
	    else
		free(s);
	    if (typ != NULL)
		*typ = DQSQLV_TYPE_STR;
	    return 0;
	}
	if (!freeit && !is_blob) {
	    if (str != NULL)
		*str = (unsigned char *)strndup((const char *)s, sz);
	    if (typ != NULL)
	    *typ = DQSQLV_TYPE_STR;
	    return 0;
	}

	/* We have a blob; decode it */
	if ((sz & 1) == 1)
	    goto einval;

	if (blob != NULL) {
	    b = memalign(sizeof (long), sz >> 1);
	    if (b == NULL)
		return errno;
	}

	for (i = 0, k = 0; i < sz; i++, k++) {
	    if (s[i] >= '0' && s[i] <= '9') {
		if (blob != NULL)
		    b[k] = (s[i] - '0') << 4;
	    } else if (s[i] >= 'A' && s[i] <= 'F') {
		if (blob != NULL)
		    b[k] = (10 + (s[i] - '0')) << 4;
	    } else
		goto einval;
	    i++;
	    if (s[i] >= '0' && s[i] <= '9') {
		if (blob != NULL)
		    b[k] |= s[i] - '0';
	    } else if (s[i] >= 'A' && s[i] <= 'F') {
		if (blob != NULL)
		    b[k] |= 10 + (s[i] - '0');
	    } else
		goto einval;
	}

	sz >>= 1;

	if (blob != NULL) {
	    *blob = b;
	    *szp = sz;
	}
	if (typ != NULL)
	    *typ = DQSQLV_TYPE_BLOB;
	return 0;
    } else if (strncmp((char *)in, "NULL", 4) == 0 &&
	       isascii(in[4]) &&
	       (ispunct(in[4]) || isspace(in[4]))) {
	if (typ != NULL)
	    *typ = DQSQLV_TYPE_NULL;
	*nxt = in + 4;
	return 0;
    }

    /* Must be something else, say, a number, but we don't handle reals */
    num = strtoll((char *)in, &e, 10);
    if (errno != 0 || e == (char *)in || e[0] == '.')
	return EINVAL;

    *nxt = (const unsigned char *)e;
    if (typ != NULL)
	*typ = DQSQLV_TYPE_INT64;
    if (nump != NULL)
	*nump = num;
    return 0;

einval:
    free(b);
    return EINVAL;
}


/**
 * Decode stringified, quoted symmetric key sets.
 *
 * See hdb_sqlite_col2pkinit_acls() below for more details.
 */
static krb5_error_code
hdb_sqlite_col2keys(krb5_context context,
		    sqlite3 *db,
		    sqlite3_stmt *cursor,
		    int kvno,
		    int iCol,
		    hdb_entry *entry)
{
    krb5_error_code ret;
    int i = -1;
    int count = 0;
    int alloced = 0;
    const unsigned char *sql_str;
    const unsigned char *nxt;
    const unsigned char *inner_nxt;
    unsigned char *s = NULL;
    unsigned char *inner_s = NULL;
    void *inner_b = NULL;
    size_t bytes;
    krb5int32 etype = -1;
    krb5int32 salttype = -1;
    unsigned int mkvno;
    Key *keys = NULL;
    Key *key = NULL;
    Key *tmp;

    /*
     * We expect keys to be a comma-separated list of quoted strings,
     * which are themselves a list of three values, two of them quoted,
     * thus always a string.
     */
    sql_str = sqlite3_column_text(cursor, iCol);
    if (sql_str == NULL) {
	if (sqlite3_errcode(db) != SQLITE_OK)
	    return ENOMEM; /* XXX */
	return 0;
    }

    nxt = sql_str;
    do {
	int typ;
	int64_t num;

	free(s);
	ret = dequote_decode(nxt, &nxt, NULL, &s, NULL, NULL, NULL);
	if (s == NULL && ret == 0) ret = EINVAL;
	if (ret != 0) goto out;

	i++;
	count++;
	if (count >= alloced) {
	    alloced *= 2;
	    if (alloced == 0)
		alloced = 2;
	    tmp = realloc(keys, sizeof (*keys) * alloced);
	    if (tmp == NULL) {
		ret = errno;
		goto out;
	    }
	}
	key = &keys[i];

	/* Get the kvno from the entry */
	free(inner_s);
	ret = dequote_decode(s, &inner_nxt, &typ, NULL, NULL, NULL, &num);
	if (typ != DQSQLV_TYPE_INT64) {
	    ret = EINVAL;
	    goto out;
	}

	if (num != kvno)
	    goto bottom;

	/* Get the mkvno (which is optional) */
	num = 0;
	ret = dequote_decode(inner_nxt + 2, &inner_nxt, &typ, NULL, NULL, NULL, &num);
	if (ret != 0) goto out;
	if ((typ != DQSQLV_TYPE_INT64 && typ != DQSQLV_TYPE_NULL) || num < 0) {
	    ret = EINVAL;
	    goto out;
	}
	mkvno = (krb5int32)num;
	if (mkvno != num) {
	    ret = EOVERFLOW;
	    goto out;
	}
	if (typ == DQSQLV_TYPE_INT64 && num > 0) {
	    key->mkvno = malloc(sizeof (*key->mkvno));
	    if (key->mkvno == NULL) {
		ret = errno;
		goto out;
	    }
	} else {
	    key->mkvno = NULL;
	}

	/* Get the enctype */
	ret = dequote_decode(inner_nxt + 2, &inner_nxt, &typ, NULL, NULL, NULL, &num);
	if (ret != 0) goto out;
	if (typ != DQSQLV_TYPE_INT64) {
	    ret = EINVAL;
	    goto out;
	}
	etype = (krb5int32)num;
	if (etype != num) {
	    ret = EOVERFLOW;
	    goto out;
	}
	key->key.keytype = etype;

	/* Get the key */
	ret = dequote_decode(inner_nxt + 2, &inner_nxt, NULL, NULL, &inner_b, &bytes, NULL);
	if (ret != 0) goto out;
	if (inner_b == NULL) {
	    ret = EINVAL;
	    goto out;
	}
	key->key.keyvalue.data = inner_b;;
	key->key.keyvalue.length = bytes;
	inner_b = NULL;

	/* Get the salttype */
	ret = dequote_decode(inner_nxt + 2, &inner_nxt, &typ, NULL, NULL, NULL, &num);
	if (ret != 0) goto out;
	if (typ != DQSQLV_TYPE_INT64 && typ != DQSQLV_TYPE_NULL) {
	    ret = EINVAL;
	    goto out;
	}
	salttype = (krb5int32)num;
	if (salttype != num) {
	    ret = EOVERFLOW;
	    goto out;
	}

	/* Get the salt */
	ret = dequote_decode(inner_nxt + 2, &inner_nxt, NULL, &inner_s, NULL, NULL, NULL);
	if (ret != 0) goto out;
	if (inner_s != NULL) {
	    key->salt = calloc(1, sizeof (*key->salt));
	    if (key->salt == NULL) {
		ret = errno;
		goto out;
	    }
	    key->salt->type = salttype;
	    key->salt->salt.data = inner_s;
	    key->salt->salt.length = strlen((char *)inner_s);
	    inner_s = NULL;
	}

	/* We ignore any trailing values */

bottom:
	assert( nxt[0] != '\0' );

	if (!isascii(nxt[1]))
	    break;
	nxt += 2;
    } while (1);

out:
    if (ret != 0) {
	free(inner_s);
	free(inner_b);
	free(s);
	for (i = 0; i < count; i++)
	    free_Key(&keys[i]);
    }

    return ret;
}


/**
 * Helper to decode stringified, quoted PKINIT ACL list and add it to
 * the HDB_Extensions.
 *
 * @param context   krb5 context
 * @param db	    SQLite3 DB handle (used to check for errors)
 * @param cursor    SQLite3 statement the current row of which to
 *		    extract the PKINIT ACLs of
 * @param iCol	    Column of the row that has the PKINIT ACLs
 * @param entry	    Entry to store the decoded PKINIT ACL into
 *
 * This function expects a column whose value is a comma-separated list
 * of quoted() (SQLite3 function) lists of colon-separated quoted()
 * subject name, issuer name, and anchor.
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
	ret = dequote_decode(nxt, &nxt, NULL, &s, NULL, NULL, NULL);
	if (ret != 0) goto out;
	if (s == NULL) {
	    ret = EINVAL;
	    goto out;
	}
	i++;
	if (i >= alloced) {
	    alloced *= 2;
	    if (alloced == 0)
		alloced = 2;
	    tmp2.data.u.pkinit_acl.val =
		realloc(pkinit_acl->val, sizeof (*pkinit_acl->val) * alloced);
	    if (tmp2.data.u.pkinit_acl.val == NULL) {
		ret = ENOMEM;
		goto out;
	    }
	    pkinit_acl->val = tmp2.data.u.pkinit_acl.val;
	}
	pkinit_acl->val[i - 1].subject = NULL;
	pkinit_acl->val[i - 1].issuer = NULL;
	pkinit_acl->val[i - 1].anchor = NULL;

	free(inner_s);

	/* Get the subject name */
	inner_nxt = s;
	ret = dequote_decode(inner_nxt, &inner_nxt, NULL, &inner_s, NULL, NULL, NULL);
	if (ret != 0) goto out;
	if (inner_s == NULL) {
	    ret = EINVAL;
	    goto out;
	}
	pkinit_acl->val[i - 1].subject = (heim_utf8_string)inner_s;
	inner_s = NULL;

	/* Skip separator character; we don't really care what it is */
	if (!isascii(inner_nxt[1]))
	    goto bottom;

	/* Get the issuer */
	ret = dequote_decode(inner_nxt + 2, &inner_nxt, NULL, &inner_s, NULL, NULL, NULL);
	if (ret != 0) goto out;
	if (inner_s == NULL) {
	    ret = EINVAL;
	    goto out;
	}
	str_ptr = malloc(sizeof (*str_ptr));
	if (str_ptr == NULL) {
	    ret = errno;
	    goto out;
	}
	*str_ptr = (heim_utf8_string)inner_s;
	pkinit_acl->val[i - 1].issuer = str_ptr;
	inner_s = NULL;
	if (!isascii(inner_nxt[1]))
	    goto bottom;

	/* Get the anchor */
	ret = dequote_decode(inner_nxt + 2, &inner_nxt, NULL, &inner_s, NULL, NULL, NULL);
	if (ret != 0) goto out;
	if (inner_s == NULL) {
	    ret = EINVAL;
	    goto out;
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
	pkinit_acl->val[i - 1].anchor = str_ptr;
	inner_s = NULL;
	/* We ignore any trailing values */

bottom:
	assert( nxt[0] != '\0' );
	if (!isascii(nxt[1]))
	    break;
	nxt += 2;
    } while (1);

    pkinit_acl->len = i;
    tmp.data.element = choice_HDB_extension_data_pkinit_acl;
    tmp.mandatory = 0;

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
 *
 * See hdb_sqlite_col2pkinit_acls() for more details.
 */
static krb5_error_code
hdb_sqlite_col2pkinit_cert_hashes(krb5_context context,
				  sqlite3 *db,
				  sqlite3_stmt *cursor,
				  int iCol,
				  hdb_entry *entry)
{
    krb5_error_code ret;
    int typ;
    int i = 0;
    int alloced = 0;
    const unsigned char *sql_str;
    const unsigned char *nxt;
    const unsigned char *inner_nxt;
    unsigned char *s = NULL;
    unsigned char *inner_s = NULL;
    void *inner_b = NULL;
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
	ret = dequote_decode(nxt, &nxt, NULL, &s, NULL, NULL, NULL);
	if (ret != 0)
	    goto out;
	if (s == NULL) {
	    ret = EINVAL;
	    goto out;
	}
	if (s == NULL && errno != 0) {
	    ret = errno;
	    goto out;
	}
	if (s == NULL)
	    break;
	i++;
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
	ret = dequote_decode(s, &inner_nxt, &typ, &inner_s, &inner_b,
				 &bytes, NULL);
	if (ret != 0)
	    goto out;
	if (typ == DQSQLV_TYPE_BLOB) {
	    oid.length = bytes;
	    oid.components = (unsigned *)inner_b;
	    inner_s = NULL;
	} else if (typ == DQSQLV_TYPE_STR) {
	    ret = der_parse_heim_oid((const char *)inner_s, ".", &oid);
	    if (ret != 0)
		goto out;
	} else {
	    ret = EINVAL;
	    goto out;
	}
	pkinit_cert_hash->val[i - 1].digest_type = oid;
	if (!isascii(inner_nxt[1]))
	    goto bottom;
	free(inner_s);
	free(inner_b);

	/* Get the digest */
	ret = dequote_decode(inner_nxt + 2, &inner_nxt, NULL, NULL, &inner_b, &bytes, NULL);
	if (ret != 0)
	    goto out;
	if (inner_b == NULL) {
	    ret = EINVAL;
	    goto out;
	}
	pkinit_cert_hash->val[i - 1].digest.length = bytes;
	pkinit_cert_hash->val[i - 1].digest.data = inner_s;
	inner_s = NULL;
	inner_b = NULL;
	/* We ignore any trailing values */

bottom:
	assert( nxt[0] != '\0' );

	if (!isascii(nxt[1]))
	    break;
	nxt += 2;
    } while (1);

    pkinit_cert_hash->len = i;
    tmp.data.element = choice_HDB_extension_data_pkinit_cert_hash;
    tmp.mandatory = 0;

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
 *
 * See hdb_sqlite_col2pkinit_acls() for more details.
 */
static krb5_error_code
hdb_sqlite_col2pkinit_certs(krb5_context context,
			    sqlite3 *db,
			    sqlite3_stmt *cursor,
			    int iCol,
			    hdb_entry *entry)
{
    krb5_error_code ret;
    int i = 0;
    int alloced = 0;
    const unsigned char *nxt;
    const unsigned char *inner_nxt;
    const unsigned char *sql_str;
    unsigned char *s = NULL;
    unsigned char *inner_s = NULL;
    void *inner_b = NULL;
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
	ret = dequote_decode(nxt, &nxt, NULL, &s, NULL, NULL, NULL);
	if (ret != 0)
	    goto out;
	if (inner_s == NULL) {
	    ret = EINVAL;
	    goto out;
	}
	i++;
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

	if (!isascii(inner_nxt[1])) {
	    ret = EINVAL;
	    goto out; /* digest is not optional */
	}
	free(inner_s);
	inner_s = NULL;

	/* Get the digest */
	ret = dequote_decode(s, &inner_nxt, NULL, NULL, &inner_b, &bytes, NULL);
	if (ret != 0)
	    goto out;
	if (inner_b == NULL) {
	    ret = EINVAL;
	    goto out;
	}
	pkinit_cert->val[i - 1].cert.length = bytes;
	pkinit_cert->val[i - 1].cert.data = inner_s;
	inner_s = NULL;
	/* We ignore any trailing values */

	assert( nxt[0] != '\0' );

	if (!isascii(nxt[1]))
	    break;
	nxt += 2;
    } while (1);

    pkinit_cert->len = i;
    tmp.data.element = choice_HDB_extension_data_pkinit_cert;
    tmp.mandatory = 0;

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
 *
 * See hdb_sqlite_col2pkinit_acls() for more details.
 */
static krb5_error_code
hdb_sqlite_col2deleg_to(krb5_context context,
			sqlite3 *db,
			sqlite3_stmt *cursor,
			int iCol,
			hdb_entry *entry)
{
    krb5_error_code ret;
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
	ret = dequote_decode(nxt, &nxt, NULL, &s, NULL, NULL, NULL);
	if (ret == 0) goto out;
	if (s == NULL) {
	    ret = EINVAL;
	    goto out;
	}
	if (s == NULL)
	    break;
	i++;
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
	princs[i - 1] = *princ;
	free(s);
    } while (1);

    deleg->len = i;
    tmp.data.element = choice_HDB_extension_data_allowed_to_delegate_to;
    tmp.mandatory = 0;

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
    /* XXX Implement! */
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
    krb5_error_code ret;
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
    ret = dequote_decode(sql_str, NULL, NULL, &s, NULL, &bytes, NULL);
    if (ret != 0)
	return ret;
    if (s == NULL)
	return 0; /* well, there's nothing to do here */

    pw->mkvno = malloc(sizeof (*pw->mkvno));
    if (pw->mkvno == NULL) {
	free(s);
	return errno;
    }
    *pw->mkvno = mkvno;
    pw->password.length = bytes;
    pw->password.data = s;
    tmp.data.element = choice_HDB_extension_data_password;
    tmp.mandatory = 0;

    ret = hdb_replace_extension(context, entry, &tmp);
    if (ret != 0)
	free(s);

    return ret;
}


/**
 * Decode stringified, quoted Principal name alias list and add it to
 * the HDB_Extensions.
 *
 * See hdb_sqlite_col2pkinit_acls() for more details.
 */
static krb5_error_code
hdb_sqlite_col2aliases(krb5_context context,
		       sqlite3 *db,
		       sqlite3_stmt *cursor,
		       int iCol,
		       hdb_entry *entry)
{
    krb5_error_code ret;
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
	ret = dequote_decode(nxt, &nxt, NULL, &s, NULL, NULL, NULL);
	if (ret != 0) goto out;
	if (s == NULL) {
	    ret = EINVAL;
	    goto out;
	}
	i++;
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
	princs[i - 1] = *princ; /* XXX */
	free(s);
    } while (1);

    aliases->aliases.len = i;
    tmp.data.element = choice_HDB_extension_data_aliases;
    tmp.mandatory = 0;

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
    tmp.mandatory = 0;
    return hdb_replace_extension(context, entry, &tmp);
}


/**
 * Function to map a result row for a query into an HDB entry.
 *
 * @param context   The current krb5 context
 * @param flags     HDB_F_*
 * @param db	    The HDB-SQLite backend handle
 * @param cursor    The SQLite3 statement the current row of which to
 *		    to decode
 * @param entry	    The HDB entry (output)
 *
 * @return	    0 if OK, an error code if not
 *
 * This fetches *all* data items, whether HDB_F_ADMIN_DATA is set or not.
 * It is the caller's job to ensure that the SELECT statement produces NULLs for
 * those columns which we're not interested in.
 */
static krb5_error_code
hdb_sqlite_row2entry(krb5_context context,
		     int flags,
		     hdb_sqlite_db *db,
		     sqlite3_stmt *cursor,
		     hdb_entry *entry)
{
    krb5_error_code ret;
    Principal *princ;
    HDB_extension tmp;

    /* Get the principal ID; we need this when we store princs */
    tmp.data.element = choice_HDB_extension_data_principal_id;
    tmp.data.u.principal_id = sqlite3_column_int(cursor, db->fetch_pidCol);
    if (sqlite3_errcode(db->db) != SQLITE_OK) {
	ret = ENOMEM; /* XXX */
	goto out;
    }
    ret = hdb_replace_extension(context, entry, &tmp);
    if (ret) goto out;

    /*
     * Get the principal's name, and save a copy as an extension, which
     * we'll need later when we store the entry.
     */
    ret = hdb_sqlite_col2principal(context, db->db, cursor, db->fetch_pnameCol,
				   &entry->principal);
    if (ret) goto out;
    ret = krb5_copy_principal(context, entry->principal, &princ);
    if (ret) goto out;
    tmp.data.element = choice_HDB_extension_data_old_principal_name;
    tmp.data.u.old_principal_name = *princ;
    free(princ);
    ret = hdb_replace_extension(context, entry, &tmp);
    if (ret) goto out;

    entry->kvno = (unsigned int)sqlite3_column_int(cursor, db->fetch_kvnoCol);
    if (sqlite3_errcode(db->db) != SQLITE_OK) {
	ret = ENOMEM; /* XXX */
	goto out;
    }
    hdb_sqlite_col2keys(context, db->db, cursor, entry->kvno, db->fetch_keysCol,
			entry);

    ret = hdb_sqlite_col2generation(context, db->db, cursor,
				    db->fetch_gentimeCol, db->fetch_genusecCol,
				    db->fetch_gengenCol, &entry->generation);
    if (ret) goto out;

    ret = hdb_sqlite_col2event(context, db->db, cursor, db->fetch_crbytimeCol,
			       db->fetch_crbypnameCol, &entry->created_by,
			       NULL);
    if (ret) goto out;

    ret = hdb_sqlite_col2event(context, db->db, cursor, db->fetch_modbytimeCol,
			       db->fetch_modbypnameCol, NULL,
			       &entry->modified_by);
    if (ret) goto out;

    ret = hdb_sqlite_col2time(context, db->db, cursor, db->fetch_validstartCol,
			      &entry->valid_start);
    if (ret) goto out;
    ret = hdb_sqlite_col2time(context, db->db, cursor, db->fetch_validendCol,
			      &entry->valid_end);
    if (ret) goto out;
    ret = hdb_sqlite_col2time(context, db->db, cursor, db->fetch_pwendCol,
			      &entry->pw_end);
    if (ret) goto out;
    ret = hdb_sqlite_col2uint(context, db->db, cursor, db->fetch_maxlifeCol,
			      &entry->max_life);
    if (ret) goto out;
    ret = hdb_sqlite_col2uint(context, db->db, cursor, db->fetch_maxrenewCol,
			      &entry->max_renew);
    if (ret) goto out;

    entry->flags = int2HDBFlags((unsigned int)sqlite3_column_int(cursor,
	db->fetch_hdbflagsCol));

    ret = hdb_sqlite_col2etypes(context, db->db, cursor, db->fetch_etypesCol,
				&entry->etypes);
    if (ret) goto out;

    /* We don't keep generation info in the SQLite3 backend yet */

    ret = hdb_sqlite_col2password(context, db->db, cursor, db->fetch_pwmkvnoCol,
				  db->fetch_pwpwCol, entry);
    if (ret) goto out;
    ret = hdb_sqlite_col2last_pw_chg(context, db->db, cursor,
				     db->fetch_lastpwchgCol, entry);
    if (ret) goto out;

    ret = hdb_sqlite_col2aliases(context, db->db, cursor, db->fetch_aliasesCol,
				 entry);
    if (ret) goto out;

    ret = hdb_sqlite_col2pkinit_acls(context, db->db, cursor,
				     db->fetch_pkaclsCol, entry);
    if (ret) goto out;
    ret = hdb_sqlite_col2pkinit_cert_hashes(context, db->db, cursor,
					    db->fetch_pkcerthashesCol,
					    entry);
    if (ret) goto out;
    ret = hdb_sqlite_col2pkinit_certs(context, db->db, cursor,
				      db->fetch_pkcertsCol, entry);
    if (ret) goto out;
    ret = hdb_sqlite_col2deleg_to(context, db->db, cursor, db->fetch_delegtoCol,
				  entry);
    if (ret) goto out;
    ret = hdb_sqlite_col2LM_OWF(context, db->db, cursor, db->fetch_lmowfCol,
				entry);
    if (ret) goto out;

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
    sqlite3_finalize(hsdb->fetch_fast);
    sqlite3_finalize(hsdb->fetch_slow);
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
 * Utility function that returns the column number of given column name.
 *
 * Use the corresponding utility macro GET_COL_IDX().
 */
static int
get_col_idx(sqlite3_stmt *stmt, const char *colname)
{
    const char *s;
    int count;
    int i;

    count = sqlite3_column_count(stmt);

    for (i = 0; i < count; i++) {
	s = sqlite3_column_name(stmt, i);
	if (s == NULL)
	    return -1;
	if (strcmp(colname, s) == 0)
	    return i;
    }

    assert( s == NULL );
    return -1;
}

#define GET_COL_IDX(stmt, c, var, lab) \
    if (((var) = get_col_idx((stmt), (c))) == -1) \
	goto lab;


static krb5_error_code
prep_fetch(krb5_context context, hdb_sqlite_db *hsdb)
{
    int ret;

    ret = hdb_sqlite_prepare_stmt(context, hsdb->db,
                                  &hsdb->fetch_fast,
                                  HDBSQLITE_FETCH_FAST,
				  NULL);
    return ret;

    ret = hdb_sqlite_prepare_stmt(context, hsdb->db,
                                  &hsdb->fetch_slow,
                                  HDBSQLITE_FETCH_SLOW,
				  NULL);
    if (ret) return ret;

    GET_COL_IDX(hsdb->fetch_fast, "pid", hsdb->fetch_pidCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "canon_name_id", hsdb->fetch_pcnameidCol,
		err);
    GET_COL_IDX(hsdb->fetch_fast, "pname", hsdb->fetch_pnameCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "kvno", hsdb->fetch_kvnoCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "keys", hsdb->fetch_keysCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "gentime", hsdb->fetch_gentimeCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "genusec", hsdb->fetch_genusecCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "gengen", hsdb->fetch_gengenCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "crbytime", hsdb->fetch_crbytimeCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "crbypname", hsdb->fetch_crbypnameCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "modbytime", hsdb->fetch_modbytimeCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "modbypname", hsdb->fetch_modbypnameCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "validstart", hsdb->fetch_validstartCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "validend", hsdb->fetch_validendCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "pwend", hsdb->fetch_pwendCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "maxlife", hsdb->fetch_maxlifeCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "maxrenew", hsdb->fetch_maxrenewCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "hdbflags", hsdb->fetch_hdbflagsCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "etypes", hsdb->fetch_etypesCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "pwmkvno", hsdb->fetch_pwmkvnoCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "pwpw", hsdb->fetch_pwpwCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "lastpwchg", hsdb->fetch_lastpwchgCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "aliases", hsdb->fetch_aliasesCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "pkacls", hsdb->fetch_pkaclsCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "pkcerthashes", hsdb->fetch_pkcerthashesCol,
		err);
    GET_COL_IDX(hsdb->fetch_fast, "pkcerts", hsdb->fetch_pkcertsCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "delegto", hsdb->fetch_delegtoCol, err);
    GET_COL_IDX(hsdb->fetch_fast, "lmowf", hsdb->fetch_lmowfCol, err);

    return 0;

err:
    return ENOMEM; /* Most likely the issue */
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
    ret = prep_fetch(context, hsdb);
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
    sqlite3_stmt *fetch = hsdb->fetch_fast;

    /* Rest doesn't clear bindings, watch out! */
    (void) sqlite3_clear_bindings(fetch);
    (void) sqlite3_reset(fetch);

    if (flags & HDB_F_KVNO_SPECIFIED && kvno != 0) {
	fetch = hsdb->fetch_kvno;
	sqlite_error = sqlite3_bind_int(fetch, 2, kvno);
	if (sqlite_error != SQLITE_OK)
	    return HDB_ERR_NOENTRY; /* XXX Need a better error */
    }

    ret = krb5_unparse_name(context, principal, &principal_string);
    if (ret) return ret;

    sqlite_error = sqlite3_bind_text(fetch, 1, principal_string, -1, SQLITE_TRANSIENT);
    free(principal_string);
    if (sqlite_error != SQLITE_OK) {
	ret = HDB_ERR_NOENTRY; /* XXX Need a better error */
	goto out;
    }


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

    ret = hdb_sqlite_row2entry(context, flags, hsdb, fetch, &entry->entry);
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
    /* Rest doesn't clear bindings, watch out! */
    sqlite3_clear_bindings(fetch);
    sqlite3_reset(fetch);

    return ret;
}

/**
 * Convenience function to step a prepared statement once.  Useful for
 * statements with no expected result rows.
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
 * This function checks if an entry being stored is an update or a new
 * entry, whether it's a rename, and whether there is some sort of race
 * or conflict.  Some of this could be done with triggers, but it'd be
 * nice to have a per-operation flag requesting atomicity -- that's what
 * this function is ultimate aimed at.
 *
 * @param context	krb5_context
 * @param db		HDB DB handle
 * @param entry		Entry being stored
 * @param previous	Entry from DB with entry's old name (output,
 *			optional)
 * @param target	Entry from DB with entry's new name (output)
 * @param princid	Pointer to principal ID to use for updates (output)
 * @param is_update	True if an entry exists with this name (output)
 * @param is_rename	True if this is a rename (output)
 * @param is_conflict	True if this update conflicts with an existing
 *			entry (output)
 *
 * This function must be called in an immediate transaction, so that the
 * DB is locked, so that we can check for updates where two threads
 * fetch the same principal concurrently (so they get the same
 * hdb_entry) and then race to update it.
 *
 * The princid, is_rename, and is_conflict output parameters will be set
 * to -1 if the principal ID or type of update cannot be determined,
 * respectively.  Otherwise *is_update, *is_rename, and *is_conflict are
 * set to 0 (false) or 1 (true).
 *
 * Returns 0 on success, even if the update conditions are such that the
 * caller should return an error; the caller must check the boolean
 * output parameters.
 *
 * The princid cannot be determined when the entry being set came from a
 * non-HDB-SQLite backend.
 *
 * The is_rename condition cannot be determined if the entry came from a
 * non-HDB-SQLite backend (though this could be fixed in the other
 * backends) or from a dump.
 *
 * The is_confict condition cannot be determined if either the given
 * entry or the existing one on in the HDB do not have a generation.  If
 * *is_conflict == 1 then either this thread raced with another in
 * reading the original entry or updating the new one.  In this case a
 * caller that wants atomic updates should return an error to its
 * caller.
 */
static krb5_error_code
check_update(krb5_context context,
	     HDB *db,
	     hdb_entry_ex *entry,
	     hdb_entry_ex *previous,
	     hdb_entry_ex *target,
	     sqlite_int64 *princid,
	     sqlite_int64 *targ_princid,
	     int *is_update,
	     int *is_rename,
	     int *is_conflict)
{
    krb5_error_code ret;
    HDB_extension ext;
    HDB_extension *extp;
    HDB_extension *exts;
    sqlite_int64 prev_princid = -1LL;
    Principal *princ;
    Principal *oldprinc = NULL;
    GENERATION entry_gen1, entry_gen2;

    *princid = -1LL;
    *targ_princid = -1LL;
    *is_update = 0;
    *is_rename = -1; /* unknown */
    *is_conflict = 0;
    if (previous != NULL)
	memset(&previous->entry, 0, sizeof (previous->entry));
    memset(&target->entry, 0, sizeof (target->entry));

    if (entry->entry.principal == NULL)
	return HDB_ERR_NOENTRY; /* XXX Need an EINVAL type code here */

    princ = entry->entry.principal;
    exts = entry->entry.extensions->val;

    /* Get the principal ID */
    ext.data.element = choice_HDB_extension_data_principal_id;
    extp = hdb_find_extension(&entry->entry, ext.data.element);
    if (extp != NULL)
	*princid = extp->data.u.principal_id;

    /* Get the old principal name, so we can check for renames */
    ext.data.element = choice_HDB_extension_data_old_principal_name;
    extp = hdb_find_extension(&entry->entry, ext.data.element);
    if (extp == NULL)
	/* Probably an entry from a dump of an old HDB */
	goto past_rename;
    oldprinc = &extp->data.u.old_principal_name;

    /* Check if this is a rename */
    *is_rename = 0;
    if (krb5_principal_compare(context, princ, oldprinc) != TRUE) {
	*is_rename = 1;
	if (previous != NULL) {
	    ret = hdb_sqlite_fetch_kvno(context, db, oldprinc, 0, 0, previous);
	    if (ret != 0 && ret != HDB_ERR_NOENTRY)
		return ret;
	    ext.data.element = choice_HDB_extension_data_principal_id;
	    extp = hdb_find_extension(&entry->entry, ext.data.element);
	    assert( extp != NULL );
	    prev_princid = extp->data.u.principal_id;
	    /* Check if we raced with an update/replace of the previous entry */
	    if (*princid != -1LL && prev_princid == *princid)
		*is_conflict = 1;

	    if (entry->entry.generation == NULL ||
		previous->entry.generation == NULL)
		goto past_rename;
	    entry_gen1 = *entry->entry.generation;
	    entry_gen2 = *previous->entry.generation;
	    if (entry_gen1.time != entry_gen2.time ||
		entry_gen1.usec != entry_gen2.usec ||
		entry_gen1.gen != entry_gen2.gen)
		*is_conflict = 1;
	}
    }

past_rename:
    /*
     * Check if we'll be overwriting anything.  It's the caller's job to
     * check for HDB_F_REPLACE.
     */
    ret = hdb_sqlite_fetch_kvno(context, db, princ, 0, 0, target);
    if (ret != 0 && ret != HDB_ERR_NOENTRY)
	return ret;

    if (ret == HDB_ERR_NOENTRY)
	return 0;

    *is_update = 1;
    if (*is_rename == 1) {
	*is_conflict = 1;
	return 0;
    }

    /* Get the principal ID of the entry that will be overwritten */
    ext.data.element = choice_HDB_extension_data_principal_id;
    extp = hdb_find_extension(&target->entry, ext.data.element);
    assert( extp != NULL );
    *targ_princid = extp->data.u.principal_id;

    if (*targ_princid != *princid && *princid != -1LL)
	*is_conflict = 1;

    /* Check for non-atomicity */
    if (entry->entry.generation == NULL || target->entry.generation == NULL) {
	/* Can't tell for sure if this is a conflict or not */
	*is_conflict = -1;
	return 0;
    }

    entry_gen1 = *entry->entry.generation;
    entry_gen2 = *target->entry.generation;

    if (entry_gen1.time != entry_gen2.time ||
	entry_gen1.usec != entry_gen2.usec ||
	entry_gen1.gen >= entry_gen2.gen ||
	(entry_gen1.gen + 1) != entry_gen2.gen)
	*is_conflict = 1;

    return 0;
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
    int is_update, is_rename, is_conflict;
    int i;
    sqlite_int64 entry_id = -1LL;
    sqlite_int64 del_entry_id = -1LL;
    char *principal_string = NULL;
    char *alias_string;
    const HDB_Ext_Aliases *aliases;
    hdb_sqlite_db *hsdb = (hdb_sqlite_db *)(db->hdb_db);
    krb5_data value;
    sqlite3_stmt *get_ids = hsdb->get_ids;
    hdb_entry_ex previous;
    hdb_entry_ex target;

    ret = hdb_sqlite_exec_stmt(context, hsdb->db,
                               "BEGIN IMMEDIATE TRANSACTION", EINVAL);
    if(ret != SQLITE_OK) {
	ret = EINVAL;
        krb5_set_error_message(context, ret, 
			       "SQLite BEGIN TRANSACTION failed: %s",
			       sqlite3_errmsg(hsdb->db));
        goto rollback;
    }

    ret = krb5_unparse_name(context,
                            entry->entry.principal, &principal_string);
    if (ret) goto rollback;

    /* Check to see if we should go ahead with this update */
    ret = check_update(context, db, entry, &previous, &target,
		       &entry_id, &del_entry_id,
		       &is_update, &is_rename, &is_conflict);
    if (ret != 0) goto rollback;

    if (is_conflict != 0 && (flags & HDB_F_DONT_RACE)) {
	ret = HDB_ERR_RACED;
	goto rollback;
    }

    if (is_update && !(flags & HDB_F_REPLACE)) {
	ret = HDB_ERR_EXISTS;
	goto rollback;
    }

    if (!(flags & HDB_F_FORCE) && is_rename == 1 && is_conflict == 1) {
	ret = HDB_ERR_EXISTS;
	goto rollback;
    }

    ret = hdb_seal_keys(context, db, &entry->entry);
    if(ret) goto rollback;

    /*
     * XXX So here we want to do INSERT OR REPLACE on everything, but
     * we'll want to preserve existing rowids so we don't trigger
     * deferred foreign key constraints when we're just updating
     * something.  Every little thing will need a statement...  *sigh*
     */

#if OLD
    ret = hdb_entry2value(context, &entry->entry, &value);
    if(ret) {
        goto rollback;
    }
#endif

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
