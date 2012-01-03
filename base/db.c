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
    heim_string_t       tblname;
    heim_db_flags_t     flags;
    void                *db_data;
    heim_error_t	error;
    int                 ret;
    int                 in_transaction;
    heim_array_t        journal;
};

typedef struct db_journal_entry {
    heim_data_t         key;
    heim_data_t         value; /* If null -> delete key, else set */
} *db_journal_entry_t;

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
	(plugin->beginf == NULL && plugin->rollbackf != NULL) ||
	(plugin->lockf != NULL && plugin->unlockf == NULL) ||
	plugin->getf == NULL)
	return EINVAL;

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
db_journal_undo(heim_object_t item, void *arg)
{
    db_journal_entry_t entry = (db_journal_entry_t)item;
    heim_db_t db = arg;
    heim_data_t key, value;

    if (db->error != NULL)
	return;

    key = entry->key;

    if (entry->value == NULL) {
	(void) db->plug->delf(db->db_data, key, &db->error);
	return;
    }

    value = entry->value;
    (void) db->plug->setf(db->db_data, key, value,
			  &db->error);
}

static int
db_rollback(heim_db_t db, heim_error_t *error)
{
    int ret;

    if (!db->in_transaction) {
	heim_assert(db->journal == NULL, "no transaction yet have journal");
	return 0;
    }

    if (db->plug->rollbackf)
	return db->plug->rollbackf(db->db_data, error);

    db->ret = 0;
    if (db->error) {
	heim_release(db->error);
	db->error = NULL;
    }
    heim_array_iterate_reverse_f(db->journal, db, db_journal_undo);
    heim_release(db->journal);
    db->journal = NULL;
    db->in_transaction = 0;
    if (error)
	*error = db->error;
    ret = db->ret;
    db->error = NULL;
    db->ret = 0;
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
    heim_release(db->dbname);
    heim_release(db->tblname);
    heim_release(db->journal);
    heim_release(db->error);
    heim_release(db->plug);
}

/**
 * Open a database of the given dbtype.
 *
 * Database type names can be composed of one or more pseudo-DB types
 * and one concrete DB type joined with a '+' between each.  For
 * example: "transaction+bdb" might be a Berkeley DB with a layer above
 * that provides transactions.
 *
 * The flags may be the logical-or of zero, one, or more of the following:
 *  - HEIM_DB_CREATE
 *  - HEIM_DB_EXCL
 *  - HEIM_DB_TRUNC
 *  - HEIM_DB_RDONLY
 *
 * @param dbtype  Name of DB type
 * @param dbname  Name of DB (likely a file path)
 * @param tblname Name of key/value table (NULL or "main" for single-table DBs)
 * @param flags   Flags
 * @param db      Output open DB handle
 * @param error   Output error  object
 *
 * @return a DB handle
 *
 * @addtogroup heimbase
 */
heim_db_t
heim_db_create(const char *dbtype, const char *dbname,
	       const char *tblname, heim_db_flags_t flags,
	       heim_error_t *error)
{
    heim_string_t s;
    char *p;
    db_plugin plug;
    heim_db_t db;
    int ret = 0;

    if (db_plugins == NULL)
	return NULL;

    if (dbtype == NULL)
	dbtype = "";

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
    db->journal = NULL;
    db->plug = plug;

    ret = plug->openf(plug->data, dbtype, dbname, tblname, flags,
		      &db->db_data, error);
    if (ret) {
	heim_release(db);
	if (error && *error == NULL)
	    *error = heim_error_create(ENOENT,
				       N_("Heimdal DB could not be opened: %s", ""),
				       dbname);
	return NULL;
    }

    if (plug->clonef == NULL) {
	db->dbtype = heim_string_create(dbtype);
	db->dbname = heim_string_create(dbname);
	db->tblname = heim_string_create(tblname);

	if (!db->dbtype || ! db->dbname || !db->tblname) {
	    heim_release(db);
	    if (error)
		*error = heim_error_enomem();
	    return NULL;
	}
	db->flags = flags;
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
			      heim_string_get_utf8(db->tblname),
			      db->flags, error);
    }

    clone = _heim_alloc_object(&db_object, sizeof(*clone));
    if (clone == NULL) {
	if (error)
	    *error = heim_error_enomem();
	return NULL;
    }

    clone->journal = NULL;
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
 * @param flags Transaction semantics desired
 * @param error Output error object
 *
 * @return 0 on success, system error otherwise
 *
 * @addtogroup heimbase
 */
int
heim_db_begin(heim_db_t db, heim_db_tx_flags_t flags, heim_error_t *error)
{
    int ret;

    if (heim_get_tid(db) != HEIM_TID_DB)
	return EINVAL;

    if (db->plug->setf == NULL || db->plug->delf == NULL)
	return EINVAL;

    /* We always want and provide isolation */
    flags |= HEIM_DB_TX_ISOLATION;
    if (db->plug->beginf == NULL && db->plug->lockf == NULL)
	return EINVAL;

    if (db->plug->beginf) {
	ret = db->plug->beginf(db->db_data, flags, error);
    } else {
	if (flags & HEIM_DB_TX_ATOMICITY)
	    return ENOTSUP;
	/* Assume unlock provides sync/durability */
	ret = db->plug->lockf(db->db_data, error);
    }

    db->in_transaction = 1;
    if (db->plug->rollbackf == NULL) {
	db->journal = heim_array_create();
	if (db->journal == NULL)
	    return ENOMEM;
    }
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
    int ret;

    if (heim_get_tid(db) != HEIM_TID_DB)
	return EINVAL;
    if (!db->in_transaction)
	return 0;
    if (db->plug->commitf == NULL && db->plug->lockf == NULL)
	return EINVAL;

    if (db->plug->commitf != NULL)
	ret = db->plug->commitf(db->db_data, error);
    else
	ret = db->plug->unlockf(db->db_data, error);

    if (ret)
	(void) db_rollback(db, error);

    heim_release(db->journal);
    db->journal = NULL;
    db->in_transaction = 0;

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
    int ret;

    if (heim_get_tid(db) != HEIM_TID_DB)
	return EINVAL;
    if (!db->in_transaction)
	return 0;

    if (db->plug->rollbackf == NULL)
	return db_rollback(db, error);

    ret = db->plug->rollbackf(db->db_data, error);

    heim_release(db->journal);
    db->journal = NULL;

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
heim_db_get_value(heim_db_t db, heim_data_t key, heim_error_t *error)
{
    if (heim_get_tid(db) != HEIM_TID_DB)
	return NULL;

    if (error != NULL)
	*error = NULL;
    return db->plug->getf(db->db_data, key, error);
}

static void
journal_entry_dealloc(void *arg)
{
    db_journal_entry_t e = arg;

    heim_release(e->key);
    heim_release(e->value);
}

static int
db_journal(heim_db_t db, heim_data_t key, heim_error_t *error)
{
    db_journal_entry_t journal_entry;
    heim_error_t err;
    heim_data_t v;
    int ret;

    if (!db->in_transaction || db->journal == NULL)
	return 0;

    v = heim_db_get_value(db, key, &err);
    if (v == NULL && err != NULL) {
	if (error)
	    *error = err;
	else
	    heim_release(err);
	return 1; /* XXX Better error code? */
    }

    journal_entry = heim_alloc(sizeof (*journal_entry), "db-journal-entry",
			       journal_entry_dealloc);
    if (journal_entry == NULL) {
	if (error)
	    *error = heim_error_enomem();
	return ENOMEM;
    }
    journal_entry->key = heim_retain(key);
    if (journal_entry->key == NULL)
	goto enomem;

    if (v != NULL) {
	journal_entry->value = heim_retain(v);
	if (journal_entry->value == NULL)
	     goto enomem;
    }

    ret = heim_array_append_value(db->journal, journal_entry);
    heim_release(journal_entry);

    return ret;

enomem:
    if (error)
	*error = heim_error_enomem();
    heim_release(journal_entry);
    return ENOMEM;
}

/**
 * Set a key's value in the DB.
 *
 * @param db    Open DB handle
 * @param key   Key
 * @param value Value
 * @param error Output error object
 *
 * @return 0 on success, system error otherwise
 *
 * @addtogroup heimbase
 */
int
heim_db_set_value(heim_db_t db, heim_data_t key, heim_data_t value,
		  heim_error_t *error)
{
    int ret;

    if (error != NULL)
	*error = NULL;

    if (heim_get_tid(db) != HEIM_TID_DB)
	return EINVAL;

    if (db->plug->setf == NULL)
	return EBADF;

    ret = db_journal(db, key, error);
    if (ret)
	return ret;

    ret = db->plug->setf(db->db_data, key, value, error);
    if (ret) {
	size_t len = heim_array_get_length(db->journal);

	/* Set failed, remove entry from journal */
	heim_array_delete_value(db->journal, len - 1);
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
heim_db_delete_key(heim_db_t db, heim_data_t key, heim_error_t *error)
{
    int ret;

    if (error != NULL)
	*error = NULL;

    if (heim_get_tid(db) != HEIM_TID_DB)
	return EINVAL;

    if (db->plug->delf == NULL)
	return EBADF;

    ret = db_journal(db, key, error);
    if (ret)
	return ret;

    ret = db->plug->delf(db->db_data, key, error);
    if (ret) {
	size_t len = heim_array_get_length(db->journal);

	/* Delete failed, remove entry from journal */
	heim_array_delete_value(db->journal, len - 1);
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
heim_db_iterate_f(heim_db_t db, void *iter_data,
		  heim_db_iterator_f_t iter_f,
		  heim_error_t *error)
{
    if (error != NULL)
	*error = NULL;

    if (heim_get_tid(db) != HEIM_TID_DB)
	return;

    db->plug->iterf(db->db_data, iter_data, iter_f, error);
}

