/*
 * Copyright (c) 2011, Secure Endpoints Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This is a pluggable simple DB abstraction, with a simple get/set/
 * delete key/value pair interface.
 *
 * Plugins may provide any of the following optional features:
 *
 *  - tables -- multiple attribute/value tables in one DB
 *  - locking
 *  - transactions (i.e., allow any heim_object_t as key or value)
 *  - transcoding of values
 *
 * Stackable plugins that provide missing optional features are
 * possible.
 *
 * Any plugin that provides locking will also provide transactions, but
 * those transactions will not be atomic in the face of failures (a
 * memory-based rollback log is used).
 */

#include "baselocl.h"

static void db_dealloc(void *ptr);

struct heim_type_data db_object = {
    HEIM_TID_DB,
    "db-object",
    NULL,
    db_dealloc,
    NULL,
    NULL,
    NULL
};


static heim_base_once_t db_plugin_init_once = HEIM_BASE_ONCE_INIT;

static heim_dict_t db_plugins;

typedef struct db_plugin {
    heim_string_t               name;
    heim_db_plug_open_f_t       openf;
    heim_db_plug_clone_f_t      clonef;
    heim_db_plug_close_f_t      closef;
    heim_db_plug_lock_f_t       lockf;
    heim_db_plug_unlock_f_t     unlockf;
    heim_db_plug_sync_f_t       syncf;
    heim_db_plug_rdjournal_f_t  rdjournalf;
    heim_db_plug_wrjournal_f_t  wrjournalf;
    heim_db_plug_begin_f_t      beginf;
    heim_db_plug_commit_f_t     commitf;
    heim_db_plug_rollback_f_t   rollbackf;
    heim_db_plug_get_value_f_t  getf;
    heim_db_plug_set_value_f_t  setf;
    heim_db_plug_del_key_f_t    delf;
    heim_db_plug_iter_f_t       iterf;
    void                        *data;
} db_plugin_desc, *db_plugin;

struct heim_db_data {
    db_plugin           plug;
    heim_string_t       dbtype;
    heim_string_t       dbname;
    heim_dict_t         options;
    void                *db_data;
    heim_error_t        error;
    int                 ret;
    unsigned int        in_transaction:1;
    unsigned int        do_sync:1;
    unsigned int	ro:1;
    unsigned int	ro_tx:1;
    heim_dict_t         set_keys;
    heim_dict_t         del_keys;
    heim_string_t       current_table;
};

static int
db_do_log_actions(heim_db_t db, heim_error_t *error);
static int
db_replay_log(heim_db_t db, heim_error_t *error);

static void
db_init_plugins_once(void *arg)
{
    db_plugins = arg;
}

static void
plugin_dealloc(void *arg)
{
    db_plugin plug = arg;

    heim_release(plug->name);
}

/** heim_db_register
 * @brief Registers a DB type for use with heim_db_create().
 *
 * @param dbtype Name of DB type
 * @param data   Private data argument to the dbtype's openf method
 * @param plugin Structure with DB type methods (function pointers)
 *
 * Backends that provide begin/commit/rollback methods must provide ACID
 * semantics.
 *
 * The registered DB type will have ACID semantics for backends that do
 * not provide begin/commit/rollback methods but do provide lock/unlock
 * and rdjournal/wrjournal methods (using a replay log journalling
 * scheme).
 *
 * If the registered DB type does not natively provide read vs. write
 * transaction isolation but does provide a lock method then the DB will
 * provide read/write transaction isolation.
 *
 * @return ENOMEM on failure, else 0.
 *
 * @addtogroup heimbase
 */
int
heim_db_register(const char *dbtype,
		 void *data,
		 struct heim_db_type *plugin)
{
    heim_dict_t plugins;
    heim_string_t s;
    db_plugin plug;
    int ret = 0;

    if ((plugin->beginf != NULL && plugin->commitf == NULL) ||
	(plugin->beginf != NULL && plugin->rollbackf == NULL) ||
	(plugin->lockf != NULL && plugin->unlockf == NULL) ||
	(plugin->rdjournalf != NULL && plugin->wrjournalf == NULL) ||
	plugin->getf == NULL)
	heim_abort("Invalid DB plugin; make sure methods are paired");

    /* Initialize */
    plugins = heim_dict_create(11);
    if (plugins == NULL)
	return ENOMEM;
    heim_base_once_f(&db_plugin_init_once, plugins, db_init_plugins_once);
    if (plugins != db_plugins)
	heim_release(plugins);
    heim_assert(db_plugins != NULL, "heim_db plugin table initialized");

    s = heim_string_create(dbtype);
    if (s == NULL)
	return ENOMEM;

    plug = heim_dict_get_value(db_plugins, s);
    if (plug) {
	heim_release(s);
	heim_release(plug);
	return EEXIST;
    }

    plug = heim_alloc(sizeof (*plug), "db_plug", plugin_dealloc);
    if (plug == NULL) {
	heim_release(s);
	return ENOMEM;
    }

    plug->name = heim_retain(s);
    plug->openf = plugin->openf;
    plug->clonef = plugin->clonef;
    plug->closef = plugin->closef;
    plug->lockf = plugin->lockf;
    plug->unlockf = plugin->unlockf;
    plug->syncf = plugin->syncf;
    plug->rdjournalf = plugin->rdjournalf;
    plug->wrjournalf = plugin->wrjournalf;
    plug->beginf = plugin->beginf;
    plug->commitf = plugin->commitf;
    plug->rollbackf = plugin->rollbackf;
    plug->getf = plugin->getf;
    plug->setf = plugin->setf;
    plug->delf = plugin->delf;
    plug->iterf = plugin->iterf;
    plug->data = data;

    ret = heim_dict_set_value(db_plugins, s, plug);
    heim_release(plug);
    heim_release(s);

    return ret;
}

static void
db_dealloc(void *arg)
{
    heim_db_t db = arg;
    heim_assert(!db->in_transaction,
		"rollback or commit heim_db_t before releasing it");
    if (db->db_data)
	(void) db->plug->closef(db->db_data, NULL);
    heim_release(db->dbtype);
    heim_release(db->dbname);
    heim_release(db->options);
    heim_release(db->set_keys);
    heim_release(db->del_keys);
    heim_release(db->error);
    heim_release(db->plug);
}

struct dbtype_iter {
    heim_db_t           db;
    const char          *dbname;
    heim_dict_t         options;
    heim_error_t        *error;
};

/*
 * Helper to create a DB handle with the first registered DB type that
 * can open the given DB.  This is useful when the app doesn't know the
 * DB type a priori.  This assumes that DB types can "taste" DBs, either
 * from the filename extension or from the actual file contents.
 */
static void
dbtype_iter2create_f(heim_object_t dbtype, heim_object_t junk, void *arg)
{
    struct dbtype_iter *iter_ctx = arg;

    if (iter_ctx->db != NULL)
	return;
    iter_ctx->db = heim_db_create(heim_string_get_utf8(dbtype),
				  iter_ctx->dbname, iter_ctx->options,
				  iter_ctx->error);
}

/**
 * Open a database of the given dbtype.
 *
 * Database type names can be composed of one or more pseudo-DB types
 * and one concrete DB type joined with a '+' between each.  For
 * example: "transaction+bdb" might be a Berkeley DB with a layer above
 * that provides transactions.
 *
 * Options may be provided via a dict (an associative array).  Existing
 * options include:
 *
 *  - "create", with any value (create if DB doesn't exist)
 *  - "exclusive", with any value (exclusive create)
 *  - "truncate", with any value (truncate the DB)
 *  - "read-only", with any value (disallow writes)
 *  - "sync", with any value (make transactions durable)
 *  - "journal-name", with a string value naming a journal file name
 *
 * @param dbtype  Name of DB type
 * @param dbname  Name of DB (likely a file path)
 * @param options Options dict
 * @param db      Output open DB handle
 * @param error   Output error  object
 *
 * @return a DB handle
 *
 * @addtogroup heimbase
 */
heim_db_t
heim_db_create(const char *dbtype, const char *dbname,
	       heim_dict_t options, heim_error_t *error)
{
    heim_object_t v;
    heim_string_t s;
    char *p;
    db_plugin plug;
    heim_db_t db;
    int ret = 0;

    if (db_plugins == NULL)
	return NULL;

    if (dbtype == NULL || *dbtype == '\0') {
	/* Try all dbtypes */
	struct dbtype_iter iter_ctx = { NULL, dbname, options, error};
	heim_dict_iterate_f(db_plugins, &iter_ctx, dbtype_iter2create_f);

	return iter_ctx.db;
    }

    /*
     * Allow for dbtypes that are composed from pseudo-dbtypes chained
     * to a real DB type with '+'.  For example a pseudo-dbtype might
     * add locking, transactions, transcoding of values, ...
     */
    p = strchr(dbtype, '+');
    if (p != NULL)
	s = heim_string_create_with_bytes(dbtype, p - dbtype);
    else
	s = heim_string_create(dbtype);
    if (s == NULL)
	return NULL;

    plug = heim_dict_get_value(db_plugins, s);
    heim_release(s);
    if (plug == NULL) {
	if (error)
	    *error = heim_error_create(ESRCH, N_("Heimdal DB plugin not found: %s", ""),
				       dbtype);
	return NULL;
    }

    db = _heim_alloc_object(&db_object, sizeof(*db));
    if (db == NULL)
	return NULL;

    db->in_transaction = 0;
    db->ro_tx = 0;
    db->set_keys = NULL;
    db->del_keys = NULL;
    db->plug = plug;

    ret = plug->openf(plug->data, dbtype, dbname, options, &db->db_data, error);
    if (ret) {
	heim_release(db);
	if (error && *error == NULL)
	    *error = heim_error_create(ENOENT,
				       N_("Heimdal DB could not be opened: %s", ""),
				       dbname);
	return NULL;
    }

    ret = db_replay_log(db, error);
    if (ret) {
	heim_release(db);
	return NULL;
    }

    if (plug->clonef == NULL) {
	db->dbtype = heim_string_create(dbtype);
	db->dbname = heim_string_create(dbname);
	db->options = heim_retain(options);

	if (!db->dbtype || ! db->dbname) {
	    heim_release(db);
	    if (error)
		*error = heim_error_enomem();
	    return NULL;
	}
    }

    if (options != NULL) {
	v = heim_dict_get_value(options, "sync");
	if (v != NULL) {
	    heim_release(v);
	    db->do_sync = 1;
	}
    }

    return db;
}

/**
 * Clone (duplicate) an open DB handle.
 *
 * This is useful for multi-threaded applications.  Applications must
 * synchronize access to any given DB handle.
 *
 * Returns EBUSY if there is an open transaction for the input db.
 *
 * @param db      Open DB handle
 * @param error   Output error object
 *
 * @return a DB handle
 *
 * @addtogroup heimbase
 */
heim_db_t
heim_db_clone(heim_db_t db, heim_error_t *error)
{
    heim_db_t clone;
    int ret;

    if (heim_get_tid(db) != HEIM_TID_DB)
	heim_abort("Expected a database");
    if (db->in_transaction)
	heim_abort("DB handle is busy");

    if (db->plug->clonef == NULL) {
	return heim_db_create(heim_string_get_utf8(db->dbtype),
			      heim_string_get_utf8(db->dbname),
			      db->options, error);
    }

    clone = _heim_alloc_object(&db_object, sizeof(*clone));
    if (clone == NULL) {
	if (error)
	    *error = heim_error_enomem();
	return NULL;
    }

    clone->set_keys = NULL;
    clone->del_keys = NULL;
    ret = db->plug->clonef(db->db_data, &clone->db_data, error);
    if (ret) {
	heim_release(clone);
	if (error && !*error)
	    *error = heim_error_create(ENOENT,
				       N_("Could not re-open DB while cloning", ""));
	return NULL;
    }
    db->db_data = NULL;
    return clone;
}

/**
 * Open a transaction on the given db.
 *
 * @param db    Open DB handle
 * @param error Output error object
 *
 * @return 0 on success, system error otherwise
 *
 * @addtogroup heimbase
 */
int
heim_db_begin(heim_db_t db, int read_only, heim_error_t *error)
{
    int ret;

    if (heim_get_tid(db) != HEIM_TID_DB)
	return EINVAL;

    if (db->in_transaction && (read_only || !db->ro_tx || (!read_only && !db->ro_tx)))
	heim_abort("DB already in transaction");

    if (db->plug->setf == NULL || db->plug->delf == NULL)
	return EINVAL;

    if (db->plug->beginf) {
	ret = db->plug->beginf(db->db_data, read_only, error);
    } else if (!db->in_transaction) {
	/* Try to emulate transactions */

	if (db->plug->lockf == NULL)
	    return EINVAL; /* can't lock? -> no transactions */

	/* Assume unlock provides sync/durability */
	ret = db->plug->lockf(db->db_data, read_only, error);

	ret = db_replay_log(db, error);
	if (ret) {
	    ret = db->plug->unlockf(db->db_data, error);
	    return ret;
	}

	db->set_keys = heim_dict_create(11);
	if (db->set_keys == NULL)
	    return ENOMEM;
	db->del_keys = heim_dict_create(11);
	if (db->del_keys == NULL) {
	    heim_release(db->set_keys);
	    db->set_keys = NULL;
	    return ENOMEM;
	}
    } else {
	heim_assert(read_only == 0, "Internal error");
	ret = db->plug->lockf(db->db_data, 0, error);
	if (ret)
	    return ret;
    }
    db->in_transaction = 1;
    db->ro_tx = !!read_only;
    return 0;
}

/**
 * Commit an open transaction on the given db.
 *
 * @param db    Open DB handle
 * @param error Output error object
 *
 * @return 0 on success, system error otherwise
 *
 * @addtogroup heimbase
 */
int
heim_db_commit(heim_db_t db, heim_error_t *error)
{
    int ret, ret2;

    if (heim_get_tid(db) != HEIM_TID_DB)
	return EINVAL;
    if (!db->in_transaction)
	return 0;
    if (db->plug->commitf == NULL && db->plug->lockf == NULL)
	return EINVAL;

    if (db->plug->commitf != NULL) {
	ret = db->plug->commitf(db->db_data, error);
	if (ret)
	    (void) db->plug->rollbackf(db->db_data, error);

	db->in_transaction = 0;
	db->ro_tx = 0;
	return ret;
    }

    if (db->ro_tx) {
	ret = 0;
	goto done;
    }

    if (db->plug->wrjournalf != NULL) {
	heim_array_t a;
	heim_string_t journal_contents;

	/* Create contents for replay log */
	ret = ENOMEM;
	a = heim_array_create();
	if (a == NULL)
	    goto err;
	ret = heim_array_append_value(a, db->set_keys);
	if (ret) {
	    heim_release(a);
	    goto err;
	}
	ret = heim_array_append_value(a, db->del_keys);
	if (ret) {
	    heim_release(a);
	    goto err;
	}
	journal_contents = heim_serialize(a, error);
	heim_release(a);

	/* Write replay log */
	ret = db->plug->wrjournalf(db->db_data, journal_contents,
				   db->do_sync, error);
	heim_release(journal_contents);
	if (ret)
	    goto err;
    }

    /* Apply logged actions */
    ret = db_do_log_actions(db, error);
    if (ret)
	return ret;

    if (db->do_sync && db->plug->syncf != NULL) {
	/* fsync() or whatever */
	ret = db->plug->syncf(db->db_data, error);
	if (ret)
	    return ret;
    }

    /* Remove replay log and we're done */
    if (db->plug->wrjournalf != NULL)
	ret = db->plug->wrjournalf(db->db_data, NULL, 0, error);

    /*
     * Clean up; if we failed to remore the replay log that's OK, we'll
     * handle that again in heim_db_commit()
     */
done:
    heim_release(db->set_keys);
    heim_release(db->del_keys);
    db->set_keys = NULL;
    db->del_keys = NULL;
    db->in_transaction = 0;
    db->ro_tx = 0;

    ret2 = db->plug->unlockf(db->db_data, error);
    if (ret == 0)
	ret = ret2;

    return ret;

err:
    if (error != NULL && *error == NULL) {
	if (ret == ENOMEM)
	    *error = heim_error_enomem();
	else
	    *error = heim_error_create(ret, "Error while committing transaction");
    }
    return ret;
}

/**
 * Rollback an open transaction on the given db.
 *
 * @param db    Open DB handle
 * @param error Output error object
 *
 * @return 0 on success, system error otherwise
 *
 * @addtogroup heimbase
 */
int
heim_db_rollback(heim_db_t db, heim_error_t *error)
{
    int ret = 0;

    if (heim_get_tid(db) != HEIM_TID_DB)
	return EINVAL;
    if (!db->in_transaction)
	return 0;

    if (db->plug->rollbackf != NULL)
	ret = db->plug->rollbackf(db->db_data, error);
    else if (db->plug->unlockf != NULL)
	ret = db->plug->unlockf(db->db_data, error);

    heim_release(db->set_keys);
    heim_release(db->del_keys);
    db->set_keys = NULL;
    db->del_keys = NULL;
    db->in_transaction = 0;
    db->ro_tx = 0;

    return ret;
}

/**
 * Get type ID of heim_db_t objects.
 *
 * @addtogroup heimbase
 */
heim_tid_t
heim_db_get_type_id(void)
{
    return HEIM_TID_DB;
}

/**
 * Lookup a key's value in the DB.
 *
 * Returns 0 on success, -1 if the key does not exist in the DB, or a
 * system error number on failure.
 *
 * @param db    Open DB handle
 * @param key   Key
 * @param error Output error object
 *
 * @return the value, if there is one for the given key
 *
 * @addtogroup heimbase
 */
heim_data_t
heim_db_get_value(heim_db_t db, heim_string_t table, heim_data_t key,
		  heim_error_t *error)
{
    heim_object_t v;
    heim_data_t result;

    if (heim_get_tid(db) != HEIM_TID_DB)
	return NULL;

    if (error != NULL)
	*error = NULL;

    if (table == NULL)
	table = heim_null_create();

    if (db->in_transaction) {
	v = heim_path_get(db->set_keys, error, table, key, NULL);
	if (v != NULL)
	    return v;
	v = heim_path_get(db->del_keys, error, table, key, NULL); /* can't be NULL */
	if (v != NULL)
	    return NULL;
    }

    result = db->plug->getf(db->db_data, table, key, error);

    return result;
}


/**
 * Set a key's value in the DB.
 *
 * @param db    Open DB handle
 * @param key   Key
 * @param value Value (if NULL the key will be deleted, but empty is OK)
 * @param error Output error object
 *
 * @return 0 on success, system error otherwise
 *
 * @addtogroup heimbase
 */
int
heim_db_set_value(heim_db_t db, heim_string_t table,
		  heim_data_t key, heim_data_t value, heim_error_t *error)
{
    int ret;

    if (error != NULL)
	*error = NULL;

    if (table == NULL)
	table = heim_null_create();

    if (value == NULL)
	/* Use heim_null_t instead of NULL */
	return heim_db_delete_key(db, table, key, error);

    if (heim_get_tid(db) != HEIM_TID_DB)
	return EINVAL;

    if (db->plug->setf == NULL)
	return EBADF;

    if (db->set_keys != NULL) {
	/* Transaction emulation */
	if (db->ro_tx) {
	    ret = heim_db_begin(db, 0, error);
	    if (ret)
		goto err;
	}
	ret = heim_path_create(db->set_keys, 29, value, error, table, key, NULL);
	if (ret)
	    goto err;
	heim_path_delete(db->del_keys, error, table, key, NULL);

	return 0;
    }

    return db->plug->setf(db->db_data, table, key, value, error);

err:
    if (error != NULL && *error == NULL) {
	if (ret == ENOMEM)
	    *error = heim_error_enomem();
	else
	    *error = heim_error_create(ret, "Could not set a dict value while "
				       "setting a DB value");
    }
    return ret;
}

/**
 * Delete a key and its value from the DB
 *
 *
 * @param db    Open DB handle
 * @param key   Key
 * @param error Output error object
 *
 * @return 0 on success, system error otherwise
 *
 * @addtogroup heimbase
 */
int
heim_db_delete_key(heim_db_t db, heim_string_t table, heim_data_t key,
		   heim_error_t *error)
{
    int ret;

    if (error != NULL)
	*error = NULL;

    if (table == NULL)
	table = heim_null_create();

    if (heim_get_tid(db) != HEIM_TID_DB)
	return EINVAL;

    if (db->plug->delf == NULL)
	return EBADF;

    if (db->del_keys != NULL) {
	/* Transaction emulation */
	if (db->ro_tx) {
	    ret = heim_db_begin(db, 0, error);
	    if (ret)
		goto err;
	}
	ret = heim_path_create(db->del_keys, 29, heim_number_create(1), error, table, key, NULL);
	if (ret)
	    goto err;
	heim_path_delete(db->set_keys, error, table, key, NULL);

	return 0;
    }

    return db->plug->delf(db->db_data, table, key, error);

err:
    if (error != NULL && *error == NULL) {
	if (ret == ENOMEM)
	    *error = heim_error_enomem();
	else
	    *error = heim_error_create(ret, "Could not set a dict value while "
				       "deleting a DB value");
    }
    return ret;
}

/**
 * Iterate a callback function over keys and values from a DB.
 *
 * @param db        Open DB handle
 * @param iter_data Callback function's private data
 * @param iter_f    Callback function, called once per-key/value pair
 * @param error     Output error object
 *
 * @addtogroup heimbase
 */
void
heim_db_iterate_f(heim_db_t db, heim_string_t table, void *iter_data,
		  heim_db_iterator_f_t iter_f, heim_error_t *error)
{
    if (error != NULL)
	*error = NULL;

    if (heim_get_tid(db) != HEIM_TID_DB)
	return;

    if (!db->in_transaction)
	db->plug->iterf(db->db_data, table, iter_data, iter_f, error);
}

static void
db_replay_log_table_set_keys_iter(heim_object_t key, heim_object_t value,
				  void *arg)
{
    heim_db_t db = arg;
    heim_data_t k, v;

    if (db->ret)
	return;

    k = (heim_data_t)key;
    v = (heim_data_t)value;

    db->ret = db->plug->setf(db->db_data, db->current_table, k, v, &db->error);
}

static void
db_replay_log_table_del_keys_iter(heim_object_t key, heim_object_t value,
				  void *arg)
{
    heim_db_t db = arg;
    heim_data_t k;

    if (db->ret)
	return;

    k = (heim_data_t)key;

    db->ret = db->plug->delf(db->db_data, db->current_table, k, &db->error);
}

static void
db_replay_log_set_keys_iter(heim_object_t table, heim_object_t table_dict,
			    void *arg)
{
    heim_db_t db = arg;

    if (db->ret)
	return;

    db->current_table = table;
    heim_dict_iterate_f(table_dict, db, db_replay_log_table_set_keys_iter);
}

static void
db_replay_log_del_keys_iter(heim_object_t table, heim_object_t table_dict,
			    void *arg)
{
    heim_db_t db = arg;

    if (db->ret)
	return;

    db->current_table = table;
    heim_dict_iterate_f(table_dict, db, db_replay_log_table_del_keys_iter);
}

static int
db_do_log_actions(heim_db_t db, heim_error_t *error)
{
    int ret;

    if (error)
	*error = NULL;

    db->ret = 0;
    db->error = NULL;
    if (db->set_keys != NULL)
	heim_dict_iterate_f(db->set_keys, db, db_replay_log_set_keys_iter);
    if (db->del_keys != NULL)
	heim_dict_iterate_f(db->del_keys, db, db_replay_log_del_keys_iter);

    ret = db->ret;
    db->ret = 0;
    if (error && db->error) {
	*error = db->error;
	db->error = NULL;
    } else {
	heim_release(db->error);
	db->error = NULL;
    }
    return ret;
}

static int
db_replay_log(heim_db_t db, heim_error_t *error)
{
    int ret;
    heim_string_t journal_contents;
    heim_object_t journal;
    heim_error_t my_error;
    size_t len;

    heim_assert(!db->in_transaction, "DB transaction not open");
    heim_assert(db->set_keys == NULL && db->set_keys == NULL, "DB transaction not open");

    if (error)
	*error = NULL;

    if (db->plug->rdjournalf == NULL)
	return 0;

    journal_contents = db->plug->rdjournalf(db->db_data, error);
    if (journal_contents == NULL)
	return 0;

    journal = heim_json_create(heim_string_get_utf8(journal_contents), &my_error);
    if (journal == NULL) {
	ret = heim_error_get_code(my_error);
	if (error)
	    *error = my_error;
	else
	    heim_release(my_error);
	return ret;
    }
    if (heim_get_tid(journal) != HEIM_TID_ARRAY) {
	if (error)
	    *error = heim_error_create(EINVAL, "Invalid journal contents; "
				       "delete journal");
	return EINVAL;
    }

    len = heim_array_get_length(journal);

    if (len > 0)
	db->set_keys = heim_array_get_value(journal, 0);
    if (len > 1)
	db->del_keys = heim_array_get_value(journal, 1);
    ret = db_do_log_actions(db, error);
    if (ret)
	return ret;

    /* Remove replay log and we're done */
    ret = db->plug->wrjournalf(db->db_data, NULL, 0, error);
    if (ret)
	return ret;
    heim_release(db->set_keys);
    heim_release(db->del_keys);
    db->set_keys = NULL;
    db->del_keys = NULL;

    return 0;
}
