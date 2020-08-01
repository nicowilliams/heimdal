/*
 * Copyright (c) 2020 Kungliga Tekniska Högskolan
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

typedef struct {
    HDB hdb;            /* generic members */
    hdb_entry *entries;
    size_t nentries;
} TEST_HDB;

struct hdb_called {
    int create;
    int init;
    int fini;
};

static krb5_error_code
TDB_close(krb5_context context, HDB *db)
{
    return 0;
}

static krb5_error_code
TDB_destroy(krb5_context context, HDB *db)
{
    return 0;
}

static krb5_error_code
TDB_set_sync(krb5_context context, HDB *db, int on)
{
    return 0;
}

static krb5_error_code
TDB_lock(krb5_context context, HDB *db, int operation)
{

    return 0;
}

static krb5_error_code
TDB_unlock(krb5_context context, HDB *db)
{

    return 0;
}

static krb5_error_code
TDB_firstkey(krb5_context context, HDB *db, unsigned flags, hdb_entry_ex *entry)
{
    return 0;
}


static krb5_error_code
TDB_nextkey(krb5_context context, HDB *db, unsigned flags, hdb_entry_ex *entry)
{
    return 0;
}

static krb5_error_code
TDB_rename(krb5_context context, HDB *db, const char *new_name)
{
    return 0;
}

static krb5_error_code
TDB__get(krb5_context context, HDB *db, krb5_data key, krb5_data *reply)
{
    return 0;
}

static krb5_error_code
TDB__put(krb5_context context, HDB *db, int replace,
	krb5_data key, krb5_data value)
{
    return 0;
}

static krb5_error_code
TDB__del(krb5_context context, HDB *db, krb5_data key)
{
    return 0;
}

static krb5_error_code
TDB_open(krb5_context context, HDB *db, int flags, mode_t mode)
{
    return 0;
}

static krb5_error_code
hdb_test_create(krb5_context context, struct HDB **db, const char *arg)
{
    TEST_HDB *tdb;

    if ((tdb = calloc(1, sizeof(**db))) == NULL ||
        (tdb->hdb.hdb_name = strdup(arg)) == NULL) {
        free(tdb);
        return krb5_enomem(context);
    }

    tdb->hdb.hdb_db = NULL;
    tdb->hdb.hdb_master_key_set = 0;
    tdb->hdb.hdb_openp = 0;
    tdb->hdb.hdb_capability_flags = HDB_CAP_F_HANDLE_ENTERPRISE_PRINCIPAL;
    tdb->hdb.hdb_open  = TDB_open;
    tdb->hdb.hdb_close = TDB_close;
    tdb->hdb.hdb_fetch_kvno = _hdb_fetch_kvno;
    tdb->hdb.hdb_store = _hdb_store;
    tdb->hdb.hdb_remove = _hdb_remove;
    tdb->hdb.hdb_firstkey = TDB_firstkey;
    tdb->hdb.hdb_nextkey= TDB_nextkey;
    tdb->hdb.hdb_lock = TDB_lock;
    tdb->hdb.hdb_unlock = TDB_unlock;
    tdb->hdb.hdb_rename = TDB_rename;
    tdb->hdb.hdb__get = TDB__get;
    tdb->hdb.hdb__put = TDB__put;
    tdb->hdb.hdb__del = TDB__del;
    tdb->hdb.hdb_destroy = TDB_destroy;
    tdb->hdb.hdb_set_sync = TDB_set_sync;
    *db = &tdb->hdb;

    return 0;
}

static krb5_error_code
hdb_test_init(krb5_context context, void **ctx)
{
    *ctx = NULL;
    return 0;
}

static void hdb_test_fini(void *ctx)
{
}

struct hdb_method hdb_test =
{
#ifdef WIN32
    /* Not c99 */
    HDB_INTERFACE_VERSION,
    hdb_test_init,
    hdb_test_fini,
    "test",
    hdb_test_create
#else
    .version = HDB_INTERFACE_VERSION,
    .init = hdb_test_init,
    .fini = hdb_test_fini,
    .prefix = "test",
    .create = hdb_test_create
#endif
};

int
main(int argc, char **argv)
{
    krb5_error_code ret;
    krb5_context context;
    HDB *db;

    setprogname(argv[0]);

    ret = krb5_init_context(&context);
    if (ret)
        errx(1, "krb5_init_context");

    ret = krb5_plugin_register(context, PLUGIN_TYPE_DATA, "hdb_test_interface",
                               &hdb_test);
    if (ret)
        krb5_err(context, 1, ret, "krb5_plugin_register");

    ret = hdb_create(context, &db, "test:mem");
    if (ret)
        krb5_err(context, 1, ret, "hdb_create");

    krb5_free_context(context);
    return 0;
}
