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
typedef const void * heim_const_object_t;
typedef unsigned int heim_tid_t;
typedef heim_object_t heim_bool_t;
typedef heim_const_object_t heim_const_bool_t;
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
heim_get_tid(heim_const_object_t object);

int
heim_cmp(heim_const_object_t a, heim_const_object_t b);

unsigned long
heim_get_hash(heim_const_object_t ptr);

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
heim_bool_val(heim_const_bool_t);

/*
 * Array
 */

typedef struct heim_array_data *heim_array_t;
typedef const struct heim_array_data *heim_const_array_t;

heim_array_t heim_array_create(void);
heim_tid_t heim_array_get_type_id(void);

typedef void (*heim_array_iterator_f_t)(heim_object_t, void *);

int	heim_array_append_value(heim_array_t, heim_object_t);
int	heim_array_insert_value(heim_array_t, size_t idx, heim_object_t);
void	heim_array_iterate_f(heim_const_array_t, void *, heim_array_iterator_f_t);
void	heim_array_iterate_reverse_f(heim_const_array_t, void *, heim_array_iterator_f_t);
#ifdef __BLOCKS__
void	heim_array_iterate(heim_const_array_t, void (^)(heim_object_t));
void	heim_array_iterate_reverse(heim_const_array_t, void (^)(heim_object_t));
#endif
size_t	heim_array_get_length(heim_const_array_t);
heim_object_t
	heim_array_get_value(heim_const_array_t, size_t);
heim_object_t
	heim_array_copy_value(heim_const_array_t, size_t);
void	heim_array_set_value(heim_array_t, size_t, heim_object_t);
void	heim_array_delete_value(heim_array_t, size_t);
#ifdef __BLOCKS__
void	heim_array_filter(heim_array_t, int (^)(heim_object_t));
#endif

/*
 * Dict
 */

typedef struct heim_dict_data *heim_dict_t;
typedef const struct heim_dict_data *heim_const_dict_t;

heim_dict_t heim_dict_create(size_t size);
heim_tid_t heim_dict_get_type_id(void);

typedef void (*heim_dict_iterator_f_t)(heim_object_t, heim_object_t, void *);

int	heim_dict_set_value(heim_dict_t, heim_object_t, heim_object_t);
void	heim_dict_iterate_f(heim_const_dict_t, void *, heim_dict_iterator_f_t);
int     heim_dict_iterate_nf(heim_const_dict_t dict, void **statep,
			     heim_object_t *key, heim_object_t *value);

#ifdef __BLOCKS__
void	heim_dict_iterate(heim_const_dict_t, void (^)(heim_object_t, heim_object_t));
#endif

heim_object_t
	heim_dict_get_value(heim_const_dict_t, heim_object_t);
heim_object_t
	heim_dict_copy_value(heim_const_dict_t, heim_object_t);
void	heim_dict_delete_key(heim_dict_t, heim_object_t);

/*
 * String
 */

typedef struct heim_string_data *heim_string_t;
typedef const struct heim_string_data *heim_const_string_t;
typedef void (*heim_string_free_f_t)(void *);

heim_string_t heim_string_create(const char *);
heim_string_t heim_string_ref_create(const char *, heim_string_free_f_t);
heim_string_t heim_string_create_with_bytes(const void *, size_t);
heim_string_t heim_string_ref_create_with_bytes(const void *, size_t,
						heim_string_free_f_t);
heim_tid_t heim_string_get_type_id(void);
const char * heim_string_get_utf8(heim_const_string_t);

#define HSTR(_str) (__heim_string_constant("" _str ""))
heim_string_t __heim_string_constant(const char *);

/*
 * Errors
 */

typedef struct heim_error * heim_error_t;
typedef const struct heim_error * heim_const_error_t;
heim_error_t heim_error_enomem(void);

heim_error_t	heim_error_create(int, const char *, ...)
    HEIMDAL_PRINTF_ATTRIBUTE((printf, 2, 3));

heim_error_t	heim_error_createv(int, const char *, va_list)
    HEIMDAL_PRINTF_ATTRIBUTE((printf, 2, 0));

heim_string_t heim_error_copy_string(heim_const_error_t);
int heim_error_get_code(heim_const_error_t);

heim_error_t heim_error_append(heim_error_t, heim_error_t);

/*
 * Path
 */

typedef enum heim_path_iter_order {
    HEIM_PATH_PREORDER = 0,
    HEIM_PATH_INORDER = 1,
    HEIM_PATH_POSTORDER = 2
} heim_path_iter_order_t;

typedef enum heim_path_iter_flags {
    HEIM_PATH_LEAF_ONLY = 1
} heim_path_iter_flags_t;

typedef void (*heim_path_iter_f_t)(void *, heim_const_object_t, size_t,
                                   heim_object_t, heim_array_t,
                                   heim_object_t);

heim_object_t heim_path_get(heim_const_object_t ptr, heim_error_t *error, ...);
heim_object_t heim_path_get_by_cstrings(heim_const_object_t ptr,
                                        heim_error_t *error, 
                                        const char * const *strs);
heim_object_t heim_path_get_by_cstring(heim_const_object_t ptr,
                                       heim_error_t *error, ...);
heim_object_t heim_path_copy(heim_const_object_t ptr, heim_error_t *error, ...);
heim_object_t heim_path_copy_by_cstrings(heim_const_object_t ptr,
                                         heim_error_t *error,
                                         const char * const *strs);
heim_object_t heim_path_copy_by_cstring(heim_const_object_t ptr,
                                        heim_error_t *error, ...);
heim_object_t heim_path_vget(heim_const_object_t ptr, heim_error_t *error,
                             va_list ap);
heim_object_t heim_path_vget_by_cstring(heim_const_object_t ptr,
                                       heim_error_t *error, va_list ap);
heim_object_t heim_path_vcopy(heim_const_object_t ptr, heim_error_t *error,
                              va_list ap);
heim_object_t heim_path_vcopy_by_cstring(heim_const_object_t ptr,
                                        heim_error_t *error, va_list ap);

int heim_path_vcreate(heim_object_t ptr, size_t size, heim_object_t leaf,
                      heim_error_t *error, va_list ap);
int heim_path_create(heim_object_t ptr, size_t size, heim_object_t leaf,
                     heim_error_t *error, ...);

void heim_path_vdelete(heim_object_t ptr, heim_error_t *error, va_list ap);
void heim_path_delete(heim_object_t ptr, heim_error_t *error, ...);

int heim_path_iter(heim_const_object_t ptr, heim_path_iter_order_t order,
                   heim_path_iter_flags_t flags,
                   size_t max_depth, void **state,
                   heim_error_t *error, size_t *depth, heim_object_t *key,
                   heim_array_t *path, heim_object_t *node);
void heim_path_iter_f(heim_object_t ptr, heim_path_iter_order_t order,
                      heim_path_iter_flags_t flags, size_t max_depth,
                      heim_error_t *error, heim_path_iter_f_t f, void *arg);

/*
 * [JSON] Schema
 */

typedef int (*heim_schema_validator_f_t)(void *arg, heim_const_dict_t schema,
                                         heim_const_dict_t schema_node,
                                         heim_const_object_t object,
                                         heim_array_t node_path,
                                         heim_const_object_t object_node,
                                         heim_error_t *error);

int heim_schema_validate(heim_const_dict_t schema, heim_const_object_t object,
                         heim_error_t *error,
                         heim_schema_validator_f_t extra_validator,
                         void *validator_arg);

/*
 * Data (octet strings)
 */

#ifndef __HEIM_OCTET_STRING__
#define __HEIM_OCTET_STRING__
typedef struct heim_octet_string {
    size_t length;
    void *data;
} heim_octet_string;
typedef const struct heim_octet_string heim_const_octet_string;
#endif

typedef struct heim_data * heim_data_t;
typedef const struct heim_data * heim_const_data_t;
typedef void (*heim_data_free_f_t)(void *);

heim_data_t	heim_data_create(const void *, size_t);
heim_data_t	heim_data_ref_create(const void *, size_t, heim_data_free_f_t);
heim_tid_t	heim_data_get_type_id(void);
const heim_octet_string *
		heim_data_get_data(heim_const_data_t);
const void *	heim_data_get_ptr(heim_const_data_t);
size_t		heim_data_get_length(heim_const_data_t);

/*
 * DB
 */

typedef struct heim_db_data *heim_db_t;
typedef const struct heim_db_data *heim_const_db_t;

typedef void (*heim_db_iterator_f_t)(heim_data_t, heim_data_t, void *);

typedef int (*heim_db_plug_open_f_t)(void *, const char *, const char *,
				     heim_dict_t, void **, heim_error_t *);
typedef int (*heim_db_plug_clone_f_t)(void *, void **, heim_error_t *);
typedef int (*heim_db_plug_close_f_t)(void *, heim_error_t *);
typedef int (*heim_db_plug_lock_f_t)(void *, int, heim_error_t *);
typedef int (*heim_db_plug_unlock_f_t)(void *, heim_error_t *);
typedef int (*heim_db_plug_sync_f_t)(void *, heim_error_t *);
typedef int (*heim_db_plug_begin_f_t)(void *, int, heim_error_t *);
typedef int (*heim_db_plug_commit_f_t)(void *, heim_error_t *);
typedef int (*heim_db_plug_rollback_f_t)(void *, heim_error_t *);
typedef heim_data_t (*heim_db_plug_copy_value_f_t)(void *, heim_string_t,
                                                   heim_data_t,
                                                   heim_error_t *);
typedef int (*heim_db_plug_set_value_f_t)(void *, heim_string_t, heim_data_t,
                                          heim_data_t, heim_error_t *);
typedef int (*heim_db_plug_del_key_f_t)(void *, heim_string_t, heim_data_t,
                                        heim_error_t *);
typedef void (*heim_db_plug_iter_f_t)(void *, heim_string_t, void *,
                                      heim_db_iterator_f_t, heim_error_t *);

struct heim_db_type {
    int                         version;
    heim_db_plug_open_f_t       openf;
    heim_db_plug_clone_f_t      clonef;
    heim_db_plug_close_f_t      closef;
    heim_db_plug_lock_f_t       lockf;
    heim_db_plug_unlock_f_t     unlockf;
    heim_db_plug_sync_f_t       syncf;
    heim_db_plug_begin_f_t      beginf;
    heim_db_plug_commit_f_t     commitf;
    heim_db_plug_rollback_f_t   rollbackf;
    heim_db_plug_copy_value_f_t copyf;
    heim_db_plug_set_value_f_t  setf;
    heim_db_plug_del_key_f_t    delf;
    heim_db_plug_iter_f_t       iterf;
};

extern struct heim_db_type heim_sorted_text_file_dbtype;

#define HEIM_DB_TYPE_VERSION_01 1

int heim_db_register(const char *dbtype,
		     void *data,
		     struct heim_db_type *plugin);

heim_db_t heim_db_create(const char *dbtype, const char *dbname,
		         heim_dict_t options, heim_error_t *error);
heim_db_t heim_db_clone(heim_const_db_t, heim_error_t *);
int heim_db_begin(heim_db_t, int, heim_error_t *);
int heim_db_commit(heim_db_t, heim_error_t *);
int heim_db_rollback(heim_db_t, heim_error_t *);
heim_tid_t heim_db_get_type_id(void);

int     heim_db_set_value(heim_db_t, heim_string_t, heim_data_t, heim_data_t,
                          heim_error_t *);
heim_data_t heim_db_copy_value(heim_const_db_t, heim_string_t, heim_data_t,
                               heim_error_t *);
int     heim_db_delete_key(heim_db_t, heim_string_t, heim_data_t,
                           heim_error_t *);
void    heim_db_iterate_f(heim_const_db_t, heim_string_t, void *,
                          heim_db_iterator_f_t, heim_error_t *);
#ifdef __BLOCKS__
void    heim_db_iterate(heim_const_db_t, heim_string_t,
                        void (^)(heim_data_t, heim_data_t), heim_error_t *);
#endif


/*
 * Number
 */

typedef struct heim_number_data *heim_number_t;
typedef const struct heim_number_data *heim_const_number_t;

heim_number_t heim_number_create(int);
heim_tid_t heim_number_get_type_id(void);
int heim_number_get_int(heim_const_number_t);

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
typedef enum heim_json_flags {
	HEIM_JSON_F_NO_C_NULL = 1,
	HEIM_JSON_F_STRICT_STRINGS = 2,
	HEIM_JSON_F_NO_DATA = 4,
	HEIM_JSON_F_NO_DATA_DICT = 8,
	HEIM_JSON_F_STRICT_DICT = 16,
	HEIM_JSON_F_STRICT = 31,
	HEIM_JSON_F_CNULL2JSNULL = 32,
	HEIM_JSON_F_TRY_DECODE_DATA = 64,
	HEIM_JSON_F_ONE_LINE = 128
} heim_json_flags_t;

heim_object_t heim_json_create(const char *, size_t, heim_json_flags_t,
			       heim_error_t *);
heim_object_t heim_json_create_with_bytes(const void *, size_t, size_t,
					  heim_json_flags_t,
					  heim_error_t *);
heim_string_t heim_serialize(heim_object_t, heim_json_flags_t flags,
			     heim_error_t *);


/* Shortest path first utility */

typedef int (*heim_spf_filterf_t)(void *, heim_dict_t, heim_dict_t,
				  heim_object_t, heim_object_t, heim_object_t,
				  heim_object_t, int *);

int
heim_shortest_path_first(heim_dict_t g, heim_object_t source,
			 heim_object_t target, heim_dict_t *paths,
			 heim_spf_filterf_t filter, void *filter_arg);



/*
 * Binary search.
 *
 * Note: these are private until integrated into the heimbase object system.
 */
typedef struct bsearch_file_handle *bsearch_file_handle;
int _bsearch_text(const char *buf, size_t buf_sz, const char *key,
		   char **value, size_t *location, size_t *loops);
int _bsearch_file_open(const char *fname, size_t max_sz, size_t page_sz,
			bsearch_file_handle *bfh, size_t *reads);
int _bsearch_file(bsearch_file_handle bfh, const char *key, char **value,
		   size_t *location, size_t *loops, size_t *reads);
void _bsearch_file_info(bsearch_file_handle bfh, size_t *page_sz,
			 size_t *max_sz, int *blockwise);
void _bsearch_file_close(bsearch_file_handle *bfh);

#endif /* HEIM_BASE_H */
