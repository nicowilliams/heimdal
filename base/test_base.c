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

#include "heimbase.h"
#include "heimbasepriv.h"

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
    heim_release(o);

    o = heim_json_create(" { \"k1\" : { \"k2\" : \"s2\" } }", NULL);
    heim_assert(o != NULL, "dict");
    heim_assert(heim_get_tid(o) == heim_dict_get_type_id(), "dict-tid");
    o2 = heim_dict_get_value(o, k1);
    heim_assert(heim_get_tid(o2) == heim_dict_get_type_id(), "dict-tid");
    heim_release(o);

    o = heim_json_create("{ \"k1\" : 1 }", NULL);
    heim_assert(o != NULL, "array");
    heim_assert(heim_get_tid(o) == heim_dict_get_type_id(), "dict-tid");
    o2 = heim_dict_get_value(o, k1);
    heim_assert(heim_get_tid(o2) == heim_number_get_type_id(), "number-tid");
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

typedef struct dict_db {
    heim_dict_t dict;
    heim_object_t to_release;
    int locked;
} *dict_db_t;

static int
dict_db_open(void *plug, const char *dbtype, const char *dbname,
	     const char *tblname, heim_db_flags_t flags, void **db,
	     heim_error_t *error)
{
    dict_db_t dictdb;

    if (dbtype && *dbtype && strcmp(dbtype, "dictdb"))
	return EINVAL;
    if (dbname && *dbname && strcmp(dbname, "MEMORY"))
	return EINVAL;
    if (tblname && *tblname && strcmp(tblname, "main"))
	return EINVAL;

    dictdb = heim_alloc(sizeof (*dictdb), "dict_db", NULL);
    if (dictdb == NULL)
	return ENOMEM;

    dictdb->dict = heim_dict_create(29);
    if (dictdb->dict == NULL) {
	heim_release(dictdb);
	return ENOMEM;
    }

    *db = dictdb;
    return 0;
}

static int
dict_db_close(void *db, heim_error_t *error)
{
    dict_db_t dictdb = db;

    heim_release(dictdb->to_release);
    heim_release(dictdb->dict);
    heim_release(dictdb);
    return 0;
}

static int
dict_db_lock(void *db, heim_error_t *error)
{
    dict_db_t dictdb = db;

    if (dictdb->locked)
	return EWOULDBLOCK;
    dictdb->locked = 1;
    return 0;
}

static int
dict_db_unlock(void *db, heim_error_t *error)
{
    dict_db_t dictdb = db;

    dictdb->locked = 0;
    return 0;
}

static int
dict_db_get_value(void *db, heim_db_data_t key,
		  heim_db_data_t value, heim_error_t *error)
{
    dict_db_t dictdb = db;
    heim_data_t k, v;
    heim_object_t o;

    heim_assert(key && key->len > 0, "Key must be provided");

    heim_release(dictdb->to_release);
    dictdb->to_release = NULL;

    k = heim_data_create(key->data, key->len);
    if (k == NULL)
	return ENOMEM;

    o = heim_dict_get_value(dictdb->dict, k);
    heim_release(k);
    if (o) {
	heim_assert(heim_get_tid(o) == HEIM_TID_DATA, "foo");
	v = (heim_data_t)o;
	dictdb->to_release = v;
	value->len = heim_data_get_length(v);
	value->data = heim_data_get_ptr(v);
	return 0;
    }
    return -1;
}

static int
dict_db_set_value(void *db, heim_db_data_t key,
		  heim_db_data_t value, heim_error_t *error)
{
    dict_db_t dictdb = db;
    heim_data_t k, v;
    int ret;

    heim_assert(key && key->len > 0, "Key must be provided");

    k = heim_data_create(key->data, key->len);
    if (k == NULL)
	return ENOMEM;
    if (value != NULL && value->len > 0)
	v = heim_data_create(value->data, value->len);
    else
	v = heim_data_create(NULL, 0);
    if (v == NULL) {
	heim_release(k);
	return ENOMEM;
    }

    ret = heim_dict_set_value(dictdb->dict, k, v);
    heim_release(k);
    heim_release(v);
    return ret;
}

static int
dict_db_del_key(void *db, heim_db_data_t key, heim_error_t *error)
{
    dict_db_t dictdb = db;
    heim_data_t k;

    heim_assert(key && key->len > 0, "Key must be provided");

    k = heim_data_create(key->data, key->len);
    if (k == NULL)
	return ENOMEM;

    heim_dict_delete_key(dictdb->dict, k);
    heim_release(k);
    return 0;
}

struct dict_db_iter_ctx {
    heim_db_iterator_f_t        iter_f;
    void                        *iter_ctx;
};

static void dict_db_iter_f(heim_object_t key, heim_object_t value, void *arg)
{
    struct dict_db_iter_ctx *ctx = arg;
    heim_db_data k, v;

    heim_assert(heim_get_tid(key) == HEIM_TID_DATA, "foo");
    heim_assert(heim_get_tid(value) == HEIM_TID_DATA, "foo");

    k.len = heim_data_get_length((heim_data_t)key);
    k.data = heim_data_get_ptr((heim_data_t)key);
    v.len = heim_data_get_length((heim_data_t)value);
    v.data = heim_data_get_ptr((heim_data_t)value);
    ctx->iter_f(&k, &v, ctx->iter_ctx);
}

static void
dict_db_iter(void *db, void *iter_data,
	     heim_db_iterator_f_t iter_f, heim_error_t *error)
{
    dict_db_t dictdb = db;
    struct dict_db_iter_ctx ctx;

    ctx.iter_ctx = iter_data;
    ctx.iter_f = iter_f;

    heim_dict_iterate_f(dictdb->dict, &ctx, dict_db_iter_f);
}

static void
test_db_iter(heim_db_data_t k, heim_db_data_t v, void *arg)
{
    int *ret = arg;

    if (k->len == strlen("msg") && strncmp(k->data, "msg", strlen("msg")) == 0 &&
	v->len == strlen("abc") && strncmp(v->data, "abc", strlen("abc")) == 0)
	*ret &= ~(1);
    else if (k->len == strlen("msg2") && strncmp(k->data, "msg2", strlen("msg2")) == 0 &&
	v->len == strlen("FooBar") && strncmp(v->data, "FooBar", strlen("FooBar")) == 0)
	*ret &= ~(2);
    else
	*ret |= 4;
}

static struct heim_db_type dbt = {
    1, dict_db_open, NULL, dict_db_close,
    dict_db_lock, dict_db_unlock, NULL, NULL, NULL,
    dict_db_get_value, dict_db_set_value,
    dict_db_del_key, dict_db_iter
};

static int
test_db()
{
    heim_db_data k, k2, v;
    heim_db_t db;
    int ret;

    ret = heim_db_register("dictdb", NULL, &dbt);
    if (ret)
	return 1;

    db = heim_db_create("dictdb", "foo", "main", 0, NULL);
    if (db)
	return 1;

    db = heim_db_create("dictdb", "MEMORY", "bar", 0, NULL);
    if (db)
	return 1;

    db = heim_db_create("foobar", "MEMORY", "main", 0, NULL);
    if (db)
	return 1;

    db = heim_db_create("dictdb", "MEMORY", "main", 0, NULL);
    if (!db)
	return ret;

    k.len = strlen("msg");
    k.data = "msg";
    v.len = strlen("Hello world!");
    v.data = "Hello world!";
    ret = heim_db_set_value(db, &k, &v, NULL);
    if (ret)
	return ret;

    v.len = 0;
    v.data = NULL;
    ret = heim_db_get_value(db, &k, &v, NULL);
    if (ret)
	return ret;
    if (v.len != strlen("Hello world!") || strncmp(v.data, "Hello world!", strlen("Hello world!")))
	return 1;

    k2.len = strlen("msg2");
    k2.data = "msg2";
    v.len = strlen("FooBar");
    v.data = "FooBar";
    ret = heim_db_set_value(db, &k2, &v, NULL);
    if (ret)
	return ret;

    v.len = 0;
    v.data = NULL;
    ret = heim_db_get_value(db, &k2, &v, NULL);
    if (ret)
	return ret;
    if (v.len != strlen("FooBar") || strncmp(v.data, "FooBar", strlen("FooBar")))
	return 1;

    k.len = strlen("msg");
    k.data = "msg";
    v.len = strlen("abc");
    v.data = "abc";
    ret = heim_db_set_value(db, &k, &v, NULL);
    if (ret)
	return ret;

    v.len = 0;
    v.data = NULL;
    ret = heim_db_get_value(db, &k, &v, NULL);
    if (ret)
	return ret;
    if (v.len != strlen("abc") || strncmp(v.data, "abc", strlen("abc")))
	return 1;

    ret = 3;
    heim_db_iterate_f(db, &ret, test_db_iter, NULL);

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

    v.len = strlen("Hello world!");
    v.data = "Hello world!";
    ret = heim_db_set_value(db, &k, &v, NULL);
    if (ret)
	return ret;

    v.len = 0;
    v.data = NULL;
    ret = heim_db_get_value(db, &k, &v, NULL);
    if (ret)
	return ret;
    if (v.len != strlen("Hello world!") || strncmp(v.data, "Hello world!", strlen("Hello world!")))
	return 1;

    ret = heim_db_rollback(db, NULL);
    if (ret)
	return ret;

    v.len = 0;
    v.data = NULL;
    ret = heim_db_get_value(db, &k, &v, NULL);
    if (ret)
	return ret;
    if (v.len != strlen("abc") || strncmp(v.data, "abc", strlen("abc")))
	return 1;

    ret = heim_db_begin(db, 0, NULL);
    if (ret)
	return ret;

    v.len = strlen("Hello world!");
    v.data = "Hello world!";
    ret = heim_db_set_value(db, &k, &v, NULL);
    if (ret)
	return ret;

    v.len = 0;
    v.data = NULL;
    ret = heim_db_get_value(db, &k, &v, NULL);
    if (ret)
	return ret;
    if (v.len != strlen("Hello world!") || strncmp(v.data, "Hello world!", strlen("Hello world!")))
	return 1;

    ret = heim_db_commit(db, NULL);
    if (ret)
	return ret;

    v.len = 0;
    v.data = NULL;
    ret = heim_db_get_value(db, &k, &v, NULL);
    if (ret)
	return ret;
    if (v.len != strlen("Hello world!") || strncmp(v.data, "Hello world!", strlen("Hello world!")))
	return 1;

    ret = heim_db_begin(db, 0, NULL);
    if (ret)
	return ret;

    ret = heim_db_delete_key(db, &k, NULL);
    if (ret)
	return ret;

    v.len = 0;
    v.data = NULL;
    ret = heim_db_get_value(db, &k, &v, NULL);
    if (ret != -1)
	return ret;

    ret = heim_db_rollback(db, NULL);
    if (ret)
	return ret;

    v.len = 0;
    v.data = NULL;
    ret = heim_db_get_value(db, &k, &v, NULL);
    if (ret)
	return ret;
    if (v.len != strlen("Hello world!") || strncmp(v.data, "Hello world!", strlen("Hello world!")))
	return 1;

    heim_release(db);

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
    res |= test_db();

    return res ? 1 : 0;
}
