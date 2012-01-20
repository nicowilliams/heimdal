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

#include "baselocl.h"
#include <syslog.h>

static heim_base_atomic_type tidglobal = HEIM_TID_USER;

struct heim_base {
    heim_type_t isa;
    heim_base_atomic_type ref_cnt;
    HEIM_TAILQ_ENTRY(heim_base) autorel;
    heim_auto_release_t autorelpool;
    uintptr_t isaextra[3];
};

/* specialized version of base */
struct heim_base_mem {
    heim_type_t isa;
    heim_base_atomic_type ref_cnt;
    HEIM_TAILQ_ENTRY(heim_base) autorel;
    heim_auto_release_t autorelpool;
    const char *name;
    void (*dealloc)(void *);
    uintptr_t isaextra[1];
};

#define PTR2BASE(ptr) (((struct heim_base *)ptr) - 1)
#define BASE2PTR(ptr) ((void *)(((struct heim_base *)ptr) + 1))

#ifdef HEIM_BASE_NEED_ATOMIC_MUTEX
HEIMDAL_MUTEX _heim_base_mutex = HEIMDAL_MUTEX_INITIALIZER;
#endif

/*
 * Auto release structure
 */

struct heim_auto_release {
    HEIM_TAILQ_HEAD(, heim_base) pool;
    HEIMDAL_MUTEX pool_mutex;
    struct heim_auto_release *parent;
};


/**
 * Retain object
 *
 * @param object to be released, NULL is ok
 *
 * @return the same object as passed in
 */

void *
heim_retain(void *ptr)
{
    struct heim_base *p = PTR2BASE(ptr);

    if (ptr == NULL || heim_base_is_tagged(ptr))
	return ptr;

    if (p->ref_cnt == heim_base_atomic_max)
	return ptr;

    if ((heim_base_atomic_inc(&p->ref_cnt) - 1) == 0)
	heim_abort("resurection");
    return ptr;
}

/**
 * Release object, free is reference count reaches zero
 *
 * @param object to be released
 */

void
heim_release(void *ptr)
{
    heim_base_atomic_type old;
    struct heim_base *p = PTR2BASE(ptr);

    if (ptr == NULL || heim_base_is_tagged(ptr))
	return;

    if (p->ref_cnt == heim_base_atomic_max)
	return;

    old = heim_base_atomic_dec(&p->ref_cnt) + 1;

    if (old > 1)
	return;

    if (old == 1) {
	heim_auto_release_t ar = p->autorelpool;
	/* remove from autorel pool list */
	if (ar) {
	    p->autorelpool = NULL;
	    HEIMDAL_MUTEX_lock(&ar->pool_mutex);
	    HEIM_TAILQ_REMOVE(&ar->pool, p, autorel);
	    HEIMDAL_MUTEX_unlock(&ar->pool_mutex);
	}
	if (p->isa->dealloc)
	    p->isa->dealloc(ptr);
	free(p);
    } else
	heim_abort("over release");
}

void
_heim_make_permanent(heim_object_t ptr)
{
    struct heim_base *p = PTR2BASE(ptr);
    p->ref_cnt = heim_base_atomic_max;
}


static heim_type_t tagged_isa[9] = {
    &_heim_number_object,
    &_heim_null_object,
    &_heim_bool_object,

    NULL,
    NULL,
    NULL,

    NULL,
    NULL,
    NULL
};

heim_type_t
_heim_get_isa(heim_object_t ptr)
{
    struct heim_base *p;
    if (heim_base_is_tagged(ptr)) {
	if (heim_base_is_tagged_object(ptr))
	    return tagged_isa[heim_base_tagged_object_tid(ptr)];
	heim_abort("not a supported tagged type");
    }
    p = PTR2BASE(ptr);
    return p->isa;
}

/**
 * Get type ID of object
 *
 * @param object object to get type id of
 *
 * @return type id of object
 */

heim_tid_t
heim_get_tid(heim_object_t ptr)
{
    heim_type_t isa = _heim_get_isa(ptr);
    return isa->tid;
}

/**
 * Get hash value of object
 *
 * @param object object to get hash value for
 *
 * @return a hash value
 */

unsigned long
heim_get_hash(heim_object_t ptr)
{
    heim_type_t isa = _heim_get_isa(ptr);
    if (isa->hash)
	return isa->hash(ptr);
    return (unsigned long)ptr;
}

/**
 * Compare two objects, returns 0 if equal, can use used for qsort()
 * and friends.
 *
 * @param a first object to compare
 * @param b first object to compare
 *
 * @return 0 if objects are equal
 */

int
heim_cmp(heim_object_t a, heim_object_t b)
{
    heim_tid_t ta, tb;
    heim_type_t isa;

    ta = heim_get_tid(a);
    tb = heim_get_tid(b);

    if (ta != tb)
	return ta - tb;

    isa = _heim_get_isa(a);

    if (isa->cmp)
	return isa->cmp(a, b);

    return (uintptr_t)a - (uintptr_t)b;
}

/*
 * Private - allocates an memory object
 */

static void
memory_dealloc(void *ptr)
{
    struct heim_base_mem *p = (struct heim_base_mem *)PTR2BASE(ptr);
    if (p->dealloc)
	p->dealloc(ptr);
}

struct heim_type_data memory_object = {
    HEIM_TID_MEMORY,
    "memory-object",
    NULL,
    memory_dealloc,
    NULL,
    NULL,
    NULL
};

void *
heim_alloc(size_t size, const char *name, heim_type_dealloc dealloc)
{
    /* XXX use posix_memalign */

    struct heim_base_mem *p = calloc(1, size + sizeof(*p));
    if (p == NULL)
	return NULL;
    p->isa = &memory_object;
    p->ref_cnt = 1;
    p->name = name;
    p->dealloc = dealloc;
    return BASE2PTR(p);
}

heim_type_t
_heim_create_type(const char *name,
		  heim_type_init init,
		  heim_type_dealloc dealloc,
		  heim_type_copy copy,
		  heim_type_cmp cmp,
		  heim_type_hash hash)
{
    heim_type_t type;

    type = calloc(1, sizeof(*type));
    if (type == NULL)
	return NULL;

    type->tid = heim_base_atomic_inc(&tidglobal);
    type->name = name;
    type->init = init;
    type->dealloc = dealloc;
    type->copy = copy;
    type->cmp = cmp;
    type->hash = hash;

    return type;
}

heim_object_t
_heim_alloc_object(heim_type_t type, size_t size)
{
    /* XXX should use posix_memalign */
    struct heim_base *p = calloc(1, size + sizeof(*p));
    if (p == NULL)
	return NULL;
    p->isa = type;
    p->ref_cnt = 1;

    return BASE2PTR(p);
}

void *
_heim_get_isaextra(heim_object_t ptr, size_t idx)
{
    struct heim_base *p = (struct heim_base *)PTR2BASE(ptr);

    heim_assert(ptr != NULL, "internal error");
    if (p->isa == &memory_object)
	return NULL;
    heim_assert(idx < 3, "invalid private heim_base extra data index");
    return &p->isaextra[idx];
}

heim_tid_t
_heim_type_get_tid(heim_type_t type)
{
    return type->tid;
}

/**
 * Call func once and only once
 *
 * @param once pointer to a heim_base_once_t
 * @param ctx context passed to func
 * @param func function to be called
 */

void
heim_base_once_f(heim_base_once_t *once, void *ctx, void (*func)(void *))
{
#ifdef HAVE_DISPATCH_DISPATCH_H
    dispatch_once_f(once, ctx, func);
#else
    static HEIMDAL_MUTEX mutex = HEIMDAL_MUTEX_INITIALIZER;
    HEIMDAL_MUTEX_lock(&mutex);
    if (*once == 0) {
	*once = 1;
	HEIMDAL_MUTEX_unlock(&mutex);
	func(ctx);
	HEIMDAL_MUTEX_lock(&mutex);
	*once = 2;
	HEIMDAL_MUTEX_unlock(&mutex);
    } else if (*once == 2) {
	HEIMDAL_MUTEX_unlock(&mutex);
    } else {
	HEIMDAL_MUTEX_unlock(&mutex);
	while (1) {
	    struct timeval tv = { 0, 1000 };
	    select(0, NULL, NULL, NULL, &tv);
	    HEIMDAL_MUTEX_lock(&mutex);
	    if (*once == 2)
		break;
	    HEIMDAL_MUTEX_unlock(&mutex);
	}
	HEIMDAL_MUTEX_unlock(&mutex);
    }
#endif
}

/**
 * Abort and log the failure (using syslog)
 */

void
heim_abort(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    heim_abortv(fmt, ap);
    va_end(ap);
}

/**
 * Abort and log the failure (using syslog)
 */

void
heim_abortv(const char *fmt, va_list ap)
{
    static char str[1024];

    vsnprintf(str, sizeof(str), fmt, ap);
    syslog(LOG_ERR, "heim_abort: %s", str);
    abort();
}

/*
 *
 */

static int ar_created = 0;
static HEIMDAL_thread_key ar_key;

struct ar_tls {
    struct heim_auto_release *head;
    struct heim_auto_release *current;
    HEIMDAL_MUTEX tls_mutex;
};

static void
ar_tls_delete(void *ptr)
{
    struct ar_tls *tls = ptr;
    if (tls->head)
	heim_release(tls->head);
    free(tls);
}

static void
init_ar_tls(void *ptr)
{
    int ret;
    HEIMDAL_key_create(&ar_key, ar_tls_delete, ret);
    if (ret == 0)
	ar_created = 1;
}

static struct ar_tls *
autorel_tls(void)
{
    static heim_base_once_t once = HEIM_BASE_ONCE_INIT;
    struct ar_tls *arp;
    int ret;

    heim_base_once_f(&once, NULL, init_ar_tls);
    if (!ar_created)
	return NULL;

    arp = HEIMDAL_getspecific(ar_key);
    if (arp == NULL) {

	arp = calloc(1, sizeof(*arp));
	if (arp == NULL)
	    return NULL;
	HEIMDAL_setspecific(ar_key, arp, ret);
	if (ret) {
	    free(arp);
	    return NULL;
	}
    }
    return arp;

}

static void
autorel_dealloc(void *ptr)
{
    heim_auto_release_t ar = ptr;
    struct ar_tls *tls;

    tls = autorel_tls();
    if (tls == NULL)
	heim_abort("autorelease pool released on thread w/o autorelease inited");

    heim_auto_release_drain(ar);

    if (!HEIM_TAILQ_EMPTY(&ar->pool))
	heim_abort("pool not empty after draining");

    HEIMDAL_MUTEX_lock(&tls->tls_mutex);
    if (tls->current != ptr)
	heim_abort("autorelease not releaseing top pool");

    if (tls->current != tls->head)
	tls->current = ar->parent;
    HEIMDAL_MUTEX_unlock(&tls->tls_mutex);
}

static int
autorel_cmp(void *a, void *b)
{
    return (a == b);
}

static unsigned long
autorel_hash(void *ptr)
{
    return (unsigned long)ptr;
}


static struct heim_type_data _heim_autorel_object = {
    HEIM_TID_AUTORELEASE,
    "autorelease-pool",
    NULL,
    autorel_dealloc,
    NULL,
    autorel_cmp,
    autorel_hash
};

/**
 *
 */

heim_auto_release_t
heim_auto_release_create(void)
{
    struct ar_tls *tls = autorel_tls();
    heim_auto_release_t ar;

    if (tls == NULL)
	heim_abort("Failed to create/get autorelease head");

    ar = _heim_alloc_object(&_heim_autorel_object, sizeof(struct heim_auto_release));
    if (ar) {
	HEIMDAL_MUTEX_lock(&tls->tls_mutex);
	if (tls->head == NULL)
	    tls->head = ar;
	ar->parent = tls->current;
	tls->current = ar;
	HEIMDAL_MUTEX_unlock(&tls->tls_mutex);
    }

    return ar;
}

/**
 * Mark the current object as a
 */

void
heim_auto_release(heim_object_t ptr)
{
    struct heim_base *p = PTR2BASE(ptr);
    struct ar_tls *tls = autorel_tls();
    heim_auto_release_t ar;

    if (ptr == NULL || heim_base_is_tagged(ptr))
	return;

    /* drop from old pool */
    if ((ar = p->autorelpool) != NULL) {
	HEIMDAL_MUTEX_lock(&ar->pool_mutex);
	HEIM_TAILQ_REMOVE(&ar->pool, p, autorel);
	p->autorelpool = NULL;
	HEIMDAL_MUTEX_unlock(&ar->pool_mutex);
    }

    if (tls == NULL || (ar = tls->current) == NULL)
	heim_abort("no auto relase pool in place, would leak");

    HEIMDAL_MUTEX_lock(&ar->pool_mutex);
    HEIM_TAILQ_INSERT_HEAD(&ar->pool, p, autorel);
    p->autorelpool = ar;
    HEIMDAL_MUTEX_unlock(&ar->pool_mutex);
}

/**
 *
 */

void
heim_auto_release_drain(heim_auto_release_t autorel)
{
    heim_object_t obj;

    /* release all elements on the tail queue */

    HEIMDAL_MUTEX_lock(&autorel->pool_mutex);
    while(!HEIM_TAILQ_EMPTY(&autorel->pool)) {
	obj = HEIM_TAILQ_FIRST(&autorel->pool);
	HEIMDAL_MUTEX_unlock(&autorel->pool_mutex);
	heim_release(BASE2PTR(obj));
	HEIMDAL_MUTEX_lock(&autorel->pool_mutex);
    }
    HEIMDAL_MUTEX_unlock(&autorel->pool_mutex);
}

static heim_object_t
heim_path_vget2(heim_object_t ptr, heim_object_t *parent, heim_object_t *key,
		heim_error_t *error, va_list ap)
{
    heim_object_t path_element;
    heim_object_t node;
    heim_tid_t node_type;

    if (ptr == NULL)
	return NULL;

    *parent = NULL;
    *key = NULL;
    for (node = ptr; node != NULL;) {
	path_element = va_arg(ap, heim_object_t);
	if (path_element == NULL)
	    return node;

	*parent = node;
	*key = path_element;

	node_type = heim_get_tid(node);
	switch (node_type) {
	case HEIM_TID_ARRAY:
	case HEIM_TID_DICT:
	case HEIM_TID_DB:
	    break;
	default:
	    if (node == ptr)
		heim_abort("heim_path_get() only operates on container types");
	    return NULL;
	}

	if (node_type == HEIM_TID_DICT) {
	    node = heim_dict_get_value(node, path_element);
	} else if (node_type == HEIM_TID_DB) {
	    switch (heim_get_tid(path_element)) {
	    case HEIM_TID_STRING:
	    case HEIM_TID_DATA:
		break;
	    default:
		if (error)
		    *error = heim_error_create(EINVAL,
					       "heim_path_get() path elements "
					       "for DB nodes must be strings "
					       "or data");
		return NULL;
	    }
	    node = heim_dict_get_value(node, path_element);
	} else if (node_type == HEIM_TID_ARRAY) {
	    int idx = -1;

	    if (heim_get_tid(path_element) == HEIM_TID_NUMBER)
		idx = heim_number_get_int(path_element);
	    if (idx < 0) {
		if (error)
		    *error = heim_error_create(EINVAL,
					       "heim_path_get() path elements "
					       "for array nodes must be "
					       "numeric and positive");
		return NULL;
	    }
	    node = heim_array_get_value(node, idx);
	}
    }
    return NULL;
}

heim_object_t
heim_path_vget(heim_object_t ptr, heim_error_t *error, va_list ap)
{
    heim_object_t p, k;

    return heim_path_vget2(ptr, &p, &k, error, ap);
}

heim_object_t
heim_path_vget_copy(heim_object_t ptr, heim_error_t *error, va_list ap)
{
    return heim_retain(heim_path_vget(ptr, error, ap));
}


heim_object_t
heim_path_get(heim_object_t ptr, heim_error_t *error, ...)
{
    heim_object_t o;
    va_list ap;

    if (ptr == NULL)
	return NULL;

    va_start(ap, error);
    o = heim_path_vget(ptr, error, ap);
    va_end(ap);
    return o;
}

heim_object_t
heim_path_get_copy(heim_object_t ptr, heim_error_t *error, ...)
{
    heim_object_t o;
    va_list ap;

    if (ptr == NULL)
	return NULL;

    va_start(ap, error);
    o = heim_path_vget_copy(ptr, error, ap);
    va_end(ap);
    return o;
}

int
heim_path_vcreate(heim_object_t ptr, size_t size, heim_object_t leaf,
		  heim_error_t *error, va_list ap)
{
    heim_object_t path_element = NULL;
    heim_object_t next_path_element = NULL;
    heim_object_t node, next_node;
    heim_tid_t node_type;
    int first = 1;
    int ret;

    if (ptr == NULL)
	heim_abort("heim_path_vcreate() does not create root nodes");

    for (node = ptr, next_node = NULL; ; first = 0) {
	next_path_element = va_arg(ap, heim_object_t);

	/* Handle interior node creation / addition of leaf */
	if (!first && next_node == NULL) {
	    /* If not first go around and we don't have a next node, add one */
	    if (next_path_element == NULL) {
		/* Last path element -> will add leaf node */
		if (leaf == NULL)
		    break;
		next_node = leaf;
	    } else {
		/* Else will add an interior node (dict) */
		next_node = heim_dict_create(size);
		if (next_node == NULL) {
		    ret = ENOMEM;
		    goto err;
		}
	    }

	    /* Do the addition */
	    if (node_type == HEIM_TID_DICT)
		ret = heim_dict_set_value(node, path_element, next_node);
	    else
		ret = heim_array_insert_value(node,
					      heim_number_get_int(path_element),
					      next_node);
	    if (ret)
		goto err;
	}

	path_element = next_path_element;
	if (next_node)
	    node = next_node;
	if (path_element == NULL)
	    break;

	node_type = heim_get_tid(node);
	switch (node_type) {
	case HEIM_TID_ARRAY:
	case HEIM_TID_DICT:
	case HEIM_TID_DB:
	    break;
	default:
	    if (node == ptr)
		heim_abort("heim_path_create() only operates on container "
			   "types");
	    if (error)
		*error = heim_error_create(EINVAL, "Non-container node in path");
	    return EINVAL;
	}

	if (node_type == HEIM_TID_DICT) {
	    next_node = heim_dict_get_value(node, path_element);
	} else if (node_type == HEIM_TID_ARRAY) {
	    int idx = -1;

	    if (heim_get_tid(path_element) == HEIM_TID_NUMBER)
		idx = heim_number_get_int(path_element);
	    if (idx < 0) {
		if (error)
		    *error = heim_error_create(EINVAL,
					       "heim_path() path elements for "
					       "array nodes must be numeric "
					       "and positive");
		return EINVAL;
	    }
	    if (idx < heim_array_get_length(node))
		next_node = heim_array_get_value(node, idx);
	    else
		next_node = NULL;
	} else if (node_type == HEIM_TID_DB) {
	    if (error)
		*error = heim_error_create(EINVAL, "Interior node is a DB");
	    return EINVAL;
	}
    }
    return 0;

err:
    if (error) {
	if (ret == ENOMEM)
	    *error = heim_error_enomem();
	else
	    *error = heim_error_create(ret, "Could not set "
				       "dict value");
    }
    return ret;
}

int
heim_path_create(heim_object_t ptr, size_t size, heim_object_t leaf,
		 heim_error_t *error, ...)
{
    va_list ap;
    int ret;

    va_start(ap, error);
    ret = heim_path_vcreate(ptr, size, leaf, error, ap);
    va_end(ap);
    return ret;
}

void
heim_path_vdelete(heim_object_t ptr, heim_error_t *error, va_list ap)
{
    heim_object_t parent, key, child;

    child = heim_path_vget2(ptr, &parent, &key, error, ap);
    if (child != NULL) {
	if (heim_get_tid(parent) == HEIM_TID_DICT)
	    heim_dict_delete_key(parent, key);
	else if (heim_get_tid(parent) == HEIM_TID_DB)
	    heim_db_delete_key(parent, NULL, key, error);
	else if (heim_get_tid(parent) == HEIM_TID_ARRAY)
	    heim_array_delete_value(parent, heim_number_get_int(key));
    }
}

void
heim_path_delete(heim_object_t ptr, heim_error_t *error, ...)
{
    va_list ap;

    va_start(ap, error);
    heim_path_vdelete(ptr, error, ap);
    va_end(ap);
    return;
}

