/*
 * Copyright (c) 2010 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2010 Apple Inc. All rights reserved.
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef WIN32
#include <sys/file.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>

#include "baselocl.h"

static void
memory_free(heim_object_t obj)
{
}

static int
test_memory(void)
{
    void *ptr;

    ptr = heim_alloc(10, "memory", memory_free);

    heim_retain(ptr);
    heim_release(ptr);

    heim_retain(ptr);
    heim_release(ptr);

    heim_release(ptr);

    ptr = heim_alloc(10, "memory", NULL);
    heim_release(ptr);

    return 0;
}

static int
test_dict(void)
{
    heim_dict_t dict;
    heim_number_t a1 = heim_number_create(1);
    heim_string_t a2 = heim_string_create("hejsan");
    heim_number_t a3 = heim_number_create(3);
    heim_string_t a4 = heim_string_create("foosan");

    dict = heim_dict_create(10);

    heim_dict_set_value(dict, a1, a2);
    heim_dict_set_value(dict, a3, a4);

    heim_dict_delete_key(dict, a3);
    heim_dict_delete_key(dict, a1);

    heim_release(a1);
    heim_release(a2);
    heim_release(a3);
    heim_release(a4);

    heim_release(dict);

    return 0;
}

static int
test_auto_release(void)
{
    heim_auto_release_t ar1, ar2;
    heim_number_t n1;
    heim_string_t s1;

    ar1 = heim_auto_release_create();

    s1 = heim_string_create("hejsan");
    heim_auto_release(s1);

    n1 = heim_number_create(1);
    heim_auto_release(n1);

    ar2 = heim_auto_release_create();

    n1 = heim_number_create(1);
    heim_auto_release(n1);

    heim_release(ar2);
    heim_release(ar1);

    return 0;
}

static int
test_string(void)
{
    heim_string_t s1, s2;
    const char *string = "hejsan";

    s1 = heim_string_create(string);
    s2 = heim_string_create(string);

    if (heim_cmp(s1, s2) != 0) {
	printf("the same string is not the same\n");
	exit(1);
    }

    heim_release(s1);
    heim_release(s2);

    return 0;
}

static int
test_error(void)
{
    heim_error_t e;
    heim_string_t s;

    e = heim_error_create(10, "foo: %s", "bar");
    heim_assert(heim_error_get_code(e) == 10, "error_code != 10");

    s = heim_error_copy_string(e);
    heim_assert(strcmp(heim_string_get_utf8(s), "foo: bar") == 0, "msg wrong");

    heim_release(s);
    heim_release(e);

    return 0;
}

static int
test_json(void)
{
    heim_object_t o, o2;
    heim_string_t k1 = heim_string_create("k1");

    o = heim_json_create("\"string\"", NULL);
    heim_assert(o != NULL, "string");
    heim_assert(heim_get_tid(o) == heim_string_get_type_id(), "string-tid");
    heim_assert(strcmp("string", heim_string_get_utf8(o)) == 0, "wrong string");
    heim_release(o);

    o = heim_json_create(" \"foo\\\"bar\" ]", NULL);
    heim_assert(o != NULL, "string");
    heim_assert(heim_get_tid(o) == heim_string_get_type_id(), "string-tid");
    heim_assert(strcmp("foo\"bar", heim_string_get_utf8(o)) == 0, "wrong string");
    heim_release(o);

    o = heim_json_create(" { \"key\" : \"value\" }", NULL);
    heim_assert(o != NULL, "dict");
    heim_assert(heim_get_tid(o) == heim_dict_get_type_id(), "dict-tid");
    heim_release(o);

    o = heim_json_create(" { \"k1\" : \"s1\", \"k2\" : \"s2\" }", NULL);
    heim_assert(o != NULL, "dict");
    heim_assert(heim_get_tid(o) == heim_dict_get_type_id(), "dict-tid");
    o2 = heim_dict_get_value(o, k1);
    heim_assert(heim_get_tid(o2) == heim_string_get_type_id(), "string-tid");
    heim_release(o2);
    heim_release(o);

    o = heim_json_create(" { \"k1\" : { \"k2\" : \"s2\" } }", NULL);
    heim_assert(o != NULL, "dict");
    heim_assert(heim_get_tid(o) == heim_dict_get_type_id(), "dict-tid");
    o2 = heim_dict_get_value(o, k1);
    heim_assert(heim_get_tid(o2) == heim_dict_get_type_id(), "dict-tid");
    heim_release(o2);
    heim_release(o);

    o = heim_json_create("{ \"k1\" : 1 }", NULL);
    heim_assert(o != NULL, "array");
    heim_assert(heim_get_tid(o) == heim_dict_get_type_id(), "dict-tid");
    o2 = heim_dict_get_value(o, k1);
    heim_assert(heim_get_tid(o2) == heim_number_get_type_id(), "number-tid");
    heim_release(o2);
    heim_release(o);

    o = heim_json_create("-10", NULL);
    heim_assert(o != NULL, "number");
    heim_assert(heim_get_tid(o) == heim_number_get_type_id(), "number-tid");
    heim_release(o);

    o = heim_json_create("99", NULL);
    heim_assert(o != NULL, "number");
    heim_assert(heim_get_tid(o) == heim_number_get_type_id(), "number-tid");
    heim_release(o);

    o = heim_json_create(" [ 1 ]", NULL);
    heim_assert(o != NULL, "array");
    heim_assert(heim_get_tid(o) == heim_array_get_type_id(), "array-tid");
    heim_release(o);

    o = heim_json_create(" [ -1 ]", NULL);
    heim_assert(o != NULL, "array");
    heim_assert(heim_get_tid(o) == heim_array_get_type_id(), "array-tid");
    heim_release(o);

    heim_release(k1);

    return 0;
}

static int
test_path(void)
{
    heim_dict_t dict = heim_dict_create(11);
    heim_string_t p1 = heim_string_create("abc");
    heim_string_t p2a = heim_string_create("def");
    heim_string_t p2b = heim_string_create("DEF");
    heim_number_t p3 = heim_number_create(0);
    heim_string_t p4a = heim_string_create("ghi");
    heim_string_t p4b = heim_string_create("GHI");
    heim_array_t a = heim_array_create();
    heim_number_t l1 = heim_number_create(42);
    heim_number_t l2 = heim_number_create(813);
    heim_number_t l3 = heim_number_create(1234);
    heim_object_t o;
    int ret;

    if (!dict || !p1 || !p2a || !p2b || !p4a || !p4b)
	return ENOMEM;

    ret = heim_path_create(dict, 11, a, NULL, p1, p2a, NULL);
    heim_release(a);
    if (ret)
	return ret;
    ret = heim_path_create(dict, 11, l3, NULL, p1, p2b, NULL);
    if (ret)
	return ret;
    o = heim_path_get(dict, NULL, p1, p2b, NULL);
    if (o != l3)
	return 1;
    ret = heim_path_create(dict, 11, NULL, NULL, p1, p2a, p3, NULL);
    if (ret)
	return ret;
    ret = heim_path_create(dict, 11, l1, NULL, p1, p2a, p3, p4a, NULL);
    if (ret)
	return ret;
    ret = heim_path_create(dict, 11, l2, NULL, p1, p2a, p3, p4b, NULL);
    if (ret)
	return ret;

    o = heim_path_get(dict, NULL, p1, p2a, p3, p4a, NULL);
    if (o != l1)
	return 1;
    o = heim_path_get(dict, NULL, p1, p2a, p3, p4b, NULL);
    if (o != l2)
	return 1;

    heim_release(dict);
    heim_release(p1);
    heim_release(p2a);
    heim_release(p2b);
    heim_release(p4a);
    heim_release(p4b);

    return 0;
}

typedef struct dict_db {
    heim_dict_t dict;
    heim_object_t to_release;
    int locked;
} *dict_db_t;

static int
dict_db_open(void *plug, const char *dbtype, const char *dbname,
	     heim_dict_t options, void **db, heim_error_t *error)
{
    dict_db_t dictdb;
    heim_dict_t contents = NULL;

    if (error)
	*error = NULL;
    if (dbtype && *dbtype && strcmp(dbtype, "dictdb"))
	return EINVAL;
    if (dbname && *dbname && strcmp(dbname, "MEMORY") != 0)
	return EINVAL;
    dictdb = heim_alloc(sizeof (*dictdb), "dict_db", NULL);
    if (dictdb == NULL)
	return ENOMEM;

    if (contents != NULL)
	dictdb->dict = contents;
    else {
	dictdb->dict = heim_dict_create(29);
	if (dictdb->dict == NULL) {
	    heim_release(dictdb);
	    return ENOMEM;
	}
    }

    *db = dictdb;
    return 0;
}

static int
dict_db_close(void *db, heim_error_t *error)
{
    dict_db_t dictdb = db;

    if (error)
	*error = NULL;
    heim_release(dictdb->to_release);
    heim_release(dictdb->dict);
    heim_release(dictdb);
    return 0;
}

static int
dict_db_lock(void *db, int read_only, heim_error_t *error)
{
    dict_db_t dictdb = db;

    if (error)
	*error = NULL;
    if (dictdb->locked)
	return EWOULDBLOCK;
    dictdb->locked = 1;
    return 0;
}

static int
dict_db_unlock(void *db, heim_error_t *error)
{
    dict_db_t dictdb = db;

    if (error)
	*error = NULL;
    dictdb->locked = 0;
    return 0;
}

static heim_data_t
dict_db_get_value(void *db, heim_string_t table, heim_data_t key,
		  heim_error_t *error)
{
    dict_db_t dictdb = db;

    if (error)
	*error = NULL;

    heim_release(dictdb->to_release);
    dictdb->to_release = NULL;

    return (heim_path_get(dictdb->dict, error, table, key, NULL));
}

static int
dict_db_set_value(void *db, heim_string_t table,
		  heim_data_t key, heim_data_t value, heim_error_t *error)
{
    dict_db_t dictdb = db;

    if (error)
	*error = NULL;

    if (table == NULL)
	table = HSTR("");

    return heim_path_create(dictdb->dict, 29, value, error, table, key, NULL);
}

static int
dict_db_del_key(void *db, heim_string_t table, heim_data_t key,
		heim_error_t *error)
{
    dict_db_t dictdb = db;

    if (error)
	*error = NULL;

    if (table == NULL)
	table = HSTR("");

    heim_path_delete(dictdb->dict, error, table, key, NULL);
    return 0;
}

struct dict_db_iter_ctx {
    heim_db_iterator_f_t        iter_f;
    void                        *iter_ctx;
};

static void dict_db_iter_f(heim_object_t key, heim_object_t value, void *arg)
{
    struct dict_db_iter_ctx *ctx = arg;

    ctx->iter_f((heim_object_t)key, (heim_object_t)value, ctx->iter_ctx);
}

static void
dict_db_iter(void *db, heim_string_t table, void *iter_data,
	     heim_db_iterator_f_t iter_f, heim_error_t *error)
{
    dict_db_t dictdb = db;
    struct dict_db_iter_ctx ctx;
    heim_dict_t table_dict;

    if (error)
	*error = NULL;

    if (table == NULL)
	table = HSTR("");

    table_dict = heim_dict_get_value(dictdb->dict, table);
    if (table_dict == NULL)
	return;

    ctx.iter_ctx = iter_data;
    ctx.iter_f = iter_f;

    heim_dict_iterate_f(table_dict, &ctx, dict_db_iter_f);
    heim_release(table_dict);
}

static void
test_db_iter(heim_data_t k, heim_data_t v, void *arg)
{
    int *ret = arg;

    heim_assert(heim_get_tid(k) == heim_data_get_type_id(), "...");

    if (heim_data_get_length(k) == strlen("msg") && strncmp(heim_data_get_ptr(k), "msg", strlen("msg")) == 0 &&
	heim_data_get_length(v) == strlen("abc") && strncmp(heim_data_get_ptr(v), "abc", strlen("abc")) == 0)
	*ret &= ~(1);
    else if (heim_data_get_length(k) == strlen("msg2") && strncmp(heim_data_get_ptr(k), "msg2", strlen("msg2")) == 0 &&
	heim_data_get_length(v) == strlen("FooBar") && strncmp(heim_data_get_ptr(v), "FooBar", strlen("FooBar")) == 0)
	*ret &= ~(2);
    else
	*ret |= 4;
}

static struct heim_db_type dbt = {
    1, dict_db_open, NULL, dict_db_close,
    dict_db_lock, dict_db_unlock, NULL, NULL, NULL, NULL,
    dict_db_get_value, dict_db_set_value,
    dict_db_del_key, dict_db_iter
};

static int
test_db(const char *dbtype, const char *dbname)
{
    heim_data_t k1, k2, v, v1, v2, v3;
    heim_db_t db;
    heim_dict_t options = NULL;
    int ret;

    if (dbtype == NULL) {
	ret = heim_db_register("dictdb", NULL, &dbt);
	if (ret)
	    return 1;

	db = heim_db_create("dictdb", "foo", NULL, NULL);
	if (db)
	    return 1;

	db = heim_db_create("foobar", "MEMORY", NULL, NULL);
	if (db)
	    return 1;

	db = heim_db_create("dictdb", "MEMORY", NULL, NULL);
	if (!db)
	    return 1;
    } else {
	options = heim_dict_create(11);
	if (options == NULL)
	    return ENOMEM;
	if (heim_dict_set_value(options, HSTR("journal-filename"),
				HSTR("json-journal")))
	    return ENOMEM;
	if (heim_dict_set_value(options, HSTR("create"), heim_null_create()))
	    return ENOMEM;
	if (heim_dict_set_value(options, HSTR("truncate"), heim_null_create()))
	    return ENOMEM;
	db = heim_db_create(dbtype, dbname, options, NULL);
	if (!db)
	    return 1;
    }

    k1 = heim_data_create("msg", strlen("msg"));
    k2 = heim_data_create("msg2", strlen("msg2"));
    v1 = heim_data_create("Hello world!", strlen("Hello world!"));
    v2 = heim_data_create("FooBar", strlen("FooBar"));
    v3 = heim_data_create("abc", strlen("abc"));

    ret = heim_db_set_value(db, NULL, k1, v1, NULL);
    if (ret)
	return ret;

    v = heim_db_get_value(db, NULL, k1, NULL);
    if (v == NULL)
	return 1;
    if (heim_cmp(v, v1))
	return 1;

    ret = heim_db_set_value(db, NULL, k2, v2, NULL);
    if (ret)
	return ret;

    v = heim_db_get_value(db, NULL, k2, NULL);
    if (v == NULL)
	return 1;
    if (heim_cmp(v, v2))
	return 1;

    ret = heim_db_set_value(db, NULL, k1, v3, NULL);
    if (ret)
	return ret;

    v = heim_db_get_value(db, NULL, k1, NULL);
    if (v == NULL)
	return 1;
    if (heim_cmp(v, v3))
	return 1;

    ret = 3;
    heim_db_iterate_f(db, NULL, &ret, test_db_iter, NULL);
    if (ret)
	return ret;

    ret = heim_db_begin(db, 0, NULL);
    if (ret)
	return ret;

    ret = heim_db_commit(db, NULL);
    if (ret)
	return ret;

    ret = heim_db_begin(db, 0, NULL);
    if (ret)
	return ret;

    ret = heim_db_rollback(db, NULL);
    if (ret)
	return ret;

    ret = heim_db_begin(db, 0, NULL);
    if (ret)
	return ret;

    ret = heim_db_set_value(db, NULL, k1, v1, NULL);
    if (ret)
	return ret;

    v = heim_db_get_value(db, NULL, k1, NULL);
    if (v == NULL)
	return 1;
    if (heim_cmp(v, v1))
	return 1;

    ret = heim_db_rollback(db, NULL);
    if (ret)
	return ret;

    v = heim_db_get_value(db, NULL, k1, NULL);
    if (v == NULL)
	return 1;
    if (heim_cmp(v, v3))
	return 1;

    ret = heim_db_begin(db, 0, NULL);
    if (ret)
	return ret;

    ret = heim_db_set_value(db, NULL, k1, v1, NULL);
    if (ret)
	return ret;

    v = heim_db_get_value(db, NULL, k1, NULL);
    if (v == NULL)
	return 1;
    if (heim_cmp(v, v1))
	return 1;

    ret = heim_db_commit(db, NULL);
    if (ret)
	return ret;

    v = heim_db_get_value(db, NULL, k1, NULL);
    if (v == NULL)
	return 1;
    if (heim_cmp(v, v1))
	return 1;

    ret = heim_db_begin(db, 0, NULL);
    if (ret)
	return ret;

    ret = heim_db_delete_key(db, NULL, k1, NULL);
    if (ret)
	return ret;

    v = heim_db_get_value(db, NULL, k1, NULL);
    if (v != NULL)
	return 1;

    ret = heim_db_rollback(db, NULL);
    if (ret)
	return ret;

    v = heim_db_get_value(db, NULL, k1, NULL);
    if (v == NULL)
	return 1;
    if (heim_cmp(v, v1))
	return 1;

    if (dbtype != NULL) {
	heim_data_t k3 = heim_data_create("value-is-a-dict", strlen("value-is-a-dict"));
	heim_dict_t vdict = heim_dict_create(11);
	heim_db_t db2;

	if (k3 == NULL || vdict == NULL) return ENOMEM;
	ret = heim_dict_set_value(vdict, HSTR("vdict-k1"), heim_number_create(11));
	if (ret) return ret;
	ret = heim_dict_set_value(vdict, HSTR("vdict-k2"), heim_null_create());
	if (ret) return ret;
	ret = heim_dict_set_value(vdict, HSTR("vdict-k3"), HSTR("a value"));
	if (ret) return ret;
	ret = heim_db_set_value(db, NULL, k3, (heim_data_t)vdict, NULL);
	if (ret) return ret;

	heim_release(vdict);

	db2 = heim_db_create(dbtype, dbname, NULL, NULL);
	if (!db2) return 1;

	vdict = (heim_dict_t)heim_db_get_value(db2, NULL, k3, NULL);
	if (vdict == NULL) return 1;
	if (heim_get_tid(vdict) != heim_dict_get_type_id()) return EINVAL;
	v = heim_dict_get_value(vdict, HSTR("vdict-k1"));
	if (v == NULL || heim_cmp(v, heim_number_create(11))) return EINVAL;
	v = heim_dict_get_value(vdict, HSTR("vdict-k2"));
	if (v == NULL || heim_cmp(v, heim_null_create())) return EINVAL;
	v = heim_dict_get_value(vdict, HSTR("vdict-k3"));
	if (v == NULL || heim_cmp(v, HSTR("a value"))) return EINVAL;

	heim_release(db2);
    }

    heim_release(db);

    heim_release(k1);
    heim_release(k2);
    heim_release(v1);
    heim_release(v2);
    heim_release(v3);

    return 0;
}

struct test_array_iter_ctx {
    char buf[256];
};

static void test_array_iter(heim_object_t elt, void *arg)
{
    struct test_array_iter_ctx *iter_ctx = arg;

    strcat(iter_ctx->buf, heim_string_get_utf8((heim_string_t)elt));
}

static int
test_array()
{
    struct test_array_iter_ctx iter_ctx;
    heim_string_t s1 = heim_string_create("abc");
    heim_string_t s2 = heim_string_create("def");
    heim_string_t s3 = heim_string_create("ghi");
    heim_string_t s4 = heim_string_create("jkl");
    heim_string_t s5 = heim_string_create("mno");
    heim_string_t s6 = heim_string_create("pqr");
    heim_array_t a = heim_array_create();

    if (!s1 || !s2 || !s3 || !s4 || !s5 || !s6 || !a)
	return ENOMEM;

    heim_array_append_value(a, s4);
    heim_array_append_value(a, s5);
    heim_array_insert_value(a, 0, s3);
    heim_array_insert_value(a, 0, s2);
    heim_array_append_value(a, s6);
    heim_array_insert_value(a, 0, s1);

    iter_ctx.buf[0] = '\0';
    heim_array_iterate_f(a, &iter_ctx, test_array_iter);
    if (strcmp(iter_ctx.buf, "abcdefghijklmnopqr") != 0)
	return 1;

    iter_ctx.buf[0] = '\0';
    heim_array_delete_value(a, 2);
    heim_array_iterate_f(a, &iter_ctx, test_array_iter);
    if (strcmp(iter_ctx.buf, "abcdefjklmnopqr") != 0)
	return 1;

    iter_ctx.buf[0] = '\0';
    heim_array_delete_value(a, 2);
    heim_array_iterate_f(a, &iter_ctx, test_array_iter);
    if (strcmp(iter_ctx.buf, "abcdefmnopqr") != 0)
	return 1;

    iter_ctx.buf[0] = '\0';
    heim_array_delete_value(a, 0);
    heim_array_iterate_f(a, &iter_ctx, test_array_iter);
    if (strcmp(iter_ctx.buf, "defmnopqr") != 0)
	return 1;

    iter_ctx.buf[0] = '\0';
    heim_array_delete_value(a, 2);
    heim_array_iterate_f(a, &iter_ctx, test_array_iter);
    if (strcmp(iter_ctx.buf, "defmno") != 0)
	return 1;

    heim_array_insert_value(a, 0, s1);
    iter_ctx.buf[0] = '\0';
    heim_array_iterate_f(a, &iter_ctx, test_array_iter);
    if (strcmp(iter_ctx.buf, "abcdefmno") != 0)
	return 1;

    heim_array_insert_value(a, 0, s2);
    iter_ctx.buf[0] = '\0';
    heim_array_iterate_f(a, &iter_ctx, test_array_iter);
    if (strcmp(iter_ctx.buf, "defabcdefmno") != 0)
	return 1;

    heim_array_append_value(a, s3);
    iter_ctx.buf[0] = '\0';
    heim_array_iterate_f(a, &iter_ctx, test_array_iter);
    if (strcmp(iter_ctx.buf, "defabcdefmnoghi") != 0)
	return 1;

    heim_array_append_value(a, s6);
    iter_ctx.buf[0] = '\0';
    heim_array_iterate_f(a, &iter_ctx, test_array_iter);
    if (strcmp(iter_ctx.buf, "defabcdefmnoghipqr") != 0)
	return 1;

    heim_release(s1);
    heim_release(s2);
    heim_release(s3);
    heim_release(s4);
    heim_release(s5);
    heim_release(s6);
    heim_release(a);

    return 0;
}

int
main(int argc, char **argv)
{
    int res = 0;

    res |= test_memory();
    res |= test_dict();
    res |= test_auto_release();
    res |= test_string();
    res |= test_error();
    res |= test_json();
    res |= test_path();
    res |= test_db(NULL, NULL);
    res |= test_db("json", "test_db.json");
    res |= test_array();

    return res ? 1 : 0;
}
