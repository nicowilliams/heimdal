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

#ifndef HEIM_BASE_H
#define HEIM_BASE_H 1

#include <sys/types.h>
#include <krb5-types.h>
#include <stdarg.h>
#include <stdbool.h>

typedef void * heim_object_t;
typedef unsigned int heim_tid_t;
typedef heim_object_t heim_bool_t;
typedef heim_object_t heim_null_t;
#define HEIM_BASE_ONCE_INIT 0
typedef long heim_base_once_t; /* XXX arch dependant */

#if !defined(__has_extension)
#define __has_extension(x) 0
#endif

#define HEIM_REQUIRE_GNUC(m,n,p) \
    (((__GNUC__ * 10000) + (__GNUC_MINOR__ * 100) + __GNUC_PATCHLEVEL__) >= \
     (((m) * 10000) + ((n) * 100) + (p)))


#if __has_extension(__builtin_expect) || HEIM_REQUIRE_GNUC(3,0,0)
#define heim_builtin_expect(_op,_res) __builtin_expect(_op,_res)
#else
#define heim_builtin_expect(_op,_res) (_op)
#endif


void *	heim_retain(heim_object_t);
void	heim_release(heim_object_t);

void	heim_show(heim_object_t);

typedef void (*heim_type_dealloc)(void *);

void *
heim_alloc(size_t size, const char *name, heim_type_dealloc dealloc);

heim_tid_t
heim_get_tid(heim_object_t object);

int
heim_cmp(heim_object_t a, heim_object_t b);

unsigned long
heim_get_hash(heim_object_t ptr);

void
heim_base_once_f(heim_base_once_t *, void *, void (*)(void *));

void
heim_abort(const char *fmt, ...)
    HEIMDAL_NORETURN_ATTRIBUTE
    HEIMDAL_PRINTF_ATTRIBUTE((printf, 1, 2));

void
heim_abortv(const char *fmt, va_list ap)
    HEIMDAL_NORETURN_ATTRIBUTE
    HEIMDAL_PRINTF_ATTRIBUTE((printf, 1, 0));

#define heim_assert(e,t) \
    (heim_builtin_expect(!(e), 0) ? heim_abort(t ":" #e) : (void)0)

/*
 *
 */

heim_null_t
heim_null_create(void);

heim_bool_t
heim_bool_create(int);

int
heim_bool_val(heim_bool_t);

/*
 * Array
 */

typedef struct heim_array_data *heim_array_t;

heim_array_t heim_array_create(void);
heim_tid_t heim_array_get_type_id(void);

typedef void (*heim_array_iterator_f_t)(heim_object_t, void *);

int	heim_array_append_value(heim_array_t, heim_object_t);
void	heim_array_iterate_f(heim_array_t, void *, heim_array_iterator_f_t);
void	heim_array_iterate_reverse_f(heim_array_t, void *, heim_array_iterator_f_t);
#ifdef __BLOCKS__
void	heim_array_iterate(heim_array_t, void (^)(heim_object_t));
void	heim_array_iterate_reverse(heim_array_t, void (^)(heim_object_t));
#endif
size_t	heim_array_get_length(heim_array_t);
heim_object_t
	heim_array_get_value(heim_array_t, size_t);
void	heim_array_delete_value(heim_array_t, size_t);
#ifdef __BLOCKS__
void	heim_array_filter(heim_array_t, int (^)(heim_object_t));
#endif

/*
 * Dict
 */

typedef struct heim_dict_data *heim_dict_t;

heim_dict_t heim_dict_create(size_t size);
heim_tid_t heim_dict_get_type_id(void);

typedef void (*heim_dict_iterator_f_t)(heim_object_t, heim_object_t, void *);

int	heim_dict_set_value(heim_dict_t, heim_object_t, heim_object_t);
void	heim_dict_iterate_f(heim_dict_t, void *, heim_dict_iterator_f_t);
#ifdef __BLOCKS__
void	heim_dict_iterate(heim_dict_t, void (^)(heim_object_t, heim_object_t));
#endif

heim_object_t
	heim_dict_get_value(heim_dict_t, heim_object_t);
void	heim_dict_delete_key(heim_dict_t, heim_object_t);

/*
 * String
 */

typedef struct heim_string_data *heim_string_t;

heim_string_t heim_string_create(const char *);
heim_string_t heim_string_create_with_bytes(const void *, size_t);
heim_tid_t heim_string_get_type_id(void);
const char * heim_string_get_utf8(heim_string_t);

#define HSTR(_str) (__heim_string_constant("" _str ""))
heim_string_t __heim_string_constant(const char *);

/*
 * Errors
 */

typedef struct heim_error * heim_error_t;

heim_error_t	heim_error_create(int, const char *, ...)
    HEIMDAL_PRINTF_ATTRIBUTE((printf, 2, 3));

heim_error_t	heim_error_createv(int, const char *, va_list)
    HEIMDAL_PRINTF_ATTRIBUTE((printf, 2, 0));

heim_string_t heim_error_copy_string(heim_error_t);
int heim_error_get_code(heim_error_t);

heim_error_t heim_error_append(heim_error_t, heim_error_t);

/*
 * DB
 */

typedef struct heim_db_inst_data *heim_db_t;

typedef enum heim_db_flags {
	HEIM_DB_CREATE = 1,
	HEIM_DB_EXCL   = 2,
	HEIM_DB_TRUNC  = 4,
	HEIM_DB_RDONLY = 8
} heim_db_flags_t;

typedef enum heim_db_tx_flags {
	HEIM_DB_TX_ATOMICITY    = 1,
	HEIM_DB_TX_CONSISTENCY  = 2,
	HEIM_DB_TX_ISOLATION    = 4,
	HEIM_DB_TX_DURABILITY   = 8
} heim_db_tx_flags_t;

typedef struct heim_db_data {
    const void *data;
    size_t len;
} heim_db_data, *heim_db_data_t;

typedef void (*heim_db_iterator_f_t)(heim_db_data_t, heim_db_data_t, void *);

typedef int (*heim_db_plug_open_f_t)(void *, const char *, const char *,
				     const char *, heim_db_flags_t,
				     void **, heim_error_t *);
typedef int (*heim_db_plug_clone_f_t)(void *, void **, heim_error_t *);
typedef int (*heim_db_plug_close_f_t)(void *, heim_error_t *);
typedef int (*heim_db_plug_lock_f_t)(void *, heim_error_t *);
typedef int (*heim_db_plug_unlock_f_t)(void *, heim_error_t *);
typedef int (*heim_db_plug_begin_f_t)(void *, heim_db_tx_flags_t,
				      heim_error_t *);
typedef int (*heim_db_plug_commit_f_t)(void *, heim_error_t *);
typedef int (*heim_db_plug_rollback_f_t)(void *, heim_error_t *);
typedef int (*heim_db_plug_get_value_f_t)(void *, heim_db_data_t,
					  heim_db_data_t, heim_error_t *);
typedef int (*heim_db_plug_set_value_f_t)(void *, heim_db_data_t,
					  heim_db_data_t, heim_error_t *);
typedef int (*heim_db_plug_del_key_f_t)(void *, heim_db_data_t, heim_error_t *);
typedef void (*heim_db_plug_iter_f_t)(void *, void *, heim_db_iterator_f_t,
				      heim_error_t *);

struct heim_db_type {
    int                         version;
    heim_db_plug_open_f_t       openf;
    heim_db_plug_clone_f_t      clonef;
    heim_db_plug_close_f_t      closef;
    heim_db_plug_lock_f_t       lockf;
    heim_db_plug_lock_f_t       unlockf;
    heim_db_plug_begin_f_t      beginf;
    heim_db_plug_commit_f_t     commitf;
    heim_db_plug_rollback_f_t   rollbackf;
    heim_db_plug_get_value_f_t  getf;
    heim_db_plug_set_value_f_t  setf;
    heim_db_plug_del_key_f_t    delf;
    heim_db_plug_iter_f_t       iterf;
};

#define HEIM_DB_TYPE_VERSION_01 1

int heim_db_register(const char *dbtype,
		     void *data,
		     struct heim_db_type *plugin);

heim_db_t heim_db_create(const char *dbtype, const char *dbname,
		         const char *tblname, heim_db_flags_t flags,
			 heim_error_t *error);
heim_db_t heim_db_clone(heim_db_t, heim_error_t *);
int heim_db_begin(heim_db_t, heim_db_tx_flags_t, heim_error_t *);
int heim_db_commit(heim_db_t, heim_error_t *);
int heim_db_rollback(heim_db_t, heim_error_t *);
heim_tid_t heim_db_get_type_id(void);

int	heim_db_set_value(heim_db_t, heim_db_data_t, heim_db_data_t,
			  heim_error_t *);
int	heim_db_get_value(heim_db_t, heim_db_data_t, heim_db_data_t,
			  heim_error_t *);
int	heim_db_delete_key(heim_db_t, heim_db_data_t, heim_error_t *);
void	heim_db_iterate_f(heim_db_t, void *, heim_db_iterator_f_t,
			  heim_error_t *);
#ifdef __BLOCKS__
void	heim_db_iterate(heim_db_t, void (^)(heim_db_data_t, heim_db_data_t),
			heim_error_t *);
#endif


/*
 * Number
 */

typedef struct heim_number_data *heim_number_t;

heim_number_t heim_number_create(int);
heim_tid_t heim_number_get_type_id(void);
int heim_number_get_int(heim_number_t);

/*
 *
 */

typedef struct heim_auto_release * heim_auto_release_t;

heim_auto_release_t heim_auto_release_create(void);
void heim_auto_release_drain(heim_auto_release_t);
void heim_auto_release(heim_object_t);

/*
 * JSON
 */
heim_object_t heim_json_create(const char *, heim_error_t *);
heim_object_t heim_json_create_with_bytes(const void *, size_t, heim_error_t *);

/*
 *
 */

#ifndef __HEIM_OCTET_STRING__
#define __HEIM_OCTET_STRING__
typedef struct heim_octet_string {
    size_t length;
    void *data;
} heim_octet_string;
#endif

typedef struct heim_data * heim_data_t;

heim_data_t	heim_data_create(const void *, size_t);
heim_tid_t	heim_data_get_type_id(void);
const heim_octet_string *
		heim_data_get_data(heim_data_t);
const void *	heim_data_get_ptr(heim_data_t);
size_t		heim_data_get_length(heim_data_t);


/*
 * Binary search.
 *
 * Note: these are private until integrated into the heimbase object system.
 */
typedef struct bsearch_file_handle *bsearch_file_handle;
int __bsearch_text(const char *buf, size_t buf_sz, const char *key,
		   char **value, size_t *location, size_t *loops);
int __bsearch_file_open(const char *fname, size_t max_sz, size_t page_sz,
			bsearch_file_handle *bfh, size_t *reads);
int __bsearch_file(bsearch_file_handle bfh, const char *key, char **value,
		   size_t *location, size_t *loops, size_t *reads);
void __bsearch_file_info(bsearch_file_handle bfh, size_t *page_sz,
			 size_t *max_sz, int *blockwise);
void __bsearch_file_close(bsearch_file_handle *bfh);

#endif /* HEIM_BASE_H */
