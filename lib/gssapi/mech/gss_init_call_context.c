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
 *
 */

#include "mech_locl.h"
#include <heimbase.h>
#include <heim_threads.h>

/*
 * This file has utility functions for the mechglue only and
 * public APIs that make "PGSS" possible.  Namely: the new GSS functions
 * for allocating, duplicating, and releasing call context handles, and
 * internal-only functions for mapping minor_status->call context
 * handles, allocating them, and so on.
 *
 * The mechglue will always invoke PGSS-capable mechanism providers with
 * minor_status arguments associated with call contexts, thus for
 * mechanism providers a trivial cast (and/or possibly pointer
 * arithmetic) will suffice for mapping minor_status<->call context.
 * But not all GSS applications will be PGSS-aware, so the mapping for
 * the mechglue is more complex, effectively necessitating a table
 * lookup.  See below.
 */

static HEIMDAL_MUTEX call_context_mutex = HEIMDAL_MUTEX_INITIALIZER;

#ifndef AO_HAVE_load
#define AO_load(addr) (*(addr))
#endif
#ifndef AO_HAVE_store
#define AO_store(addr, new_val) ((*addr) = (new_val))
#endif
#ifndef AO_HAVE_fetch_and_add1_full
AO_t AO_fetch_and_add1_full(volatile AO_t *addr)
{
    AO_t value;
    HEIMDAL_MUTEX_lock(&call_context_mutex);
    value = (*addr)++;
    HEIMDAL_MUTEX_unlock(&call_context_mutex);
    return value;
}
#endif /* AO_HAVE_fetch_and_add1_full */
#ifndef AO_HAVE_fetch_and_sub1_full
AO_t AO_fetch_and_sub1_full(volatile AO_t *addr)
{
    AO_t value;
    HEIMDAL_MUTEX_lock(&call_context_mutex);
    value = (*addr)--;
    HEIMDAL_MUTEX_unlock(&call_context_mutex);
    return value;
}
#endif /* AO_HAVE_fetch_and_sub1_full */

/*
 * This is the number of call contexts for which we'll do a very fast
 * mapping of OM_uint32 * to call context lookup.  The lookup consists
 * of checking the call_contexts_fast[] array bounds and if the
 * OM_uint32 * fits then compute the index into that array.
 */
#define CALL_CTX_FAST 8
static struct _gss_call_context call_contexts_fast[CALL_CTX_FAST];

/*
 * Call contexts beyond 8 are placed on a linked list.
 *
 * XXX Switch to a heim_dict_t instead; that will scale much better!
 */
static _gss_call_context_list call_contexts_slow;

/* Allocate a call context */
static OM_uint32
_gss_alloc_call_context(_gss_call_context *cc)
{
    _gss_call_context p;
    size_t i;

    /*
     * Fast path: alloc from static array.  What's fast about this is
     * searching, since it's just pointer arithmetic; allocation is
     * infrequent.  See _gss_get_call_context().
     */
    for (i = 0; i < CALL_CTX_FAST; i++) {
	p = &call_contexts_fast[i];
	if (AO_load(&p->cc_refs))
	    continue; /* It's OK if we race and miss an available slot */
	if (AO_fetch_and_add1_full(&p->cc_refs) > 1) {
            /*
             * XXX Make sure we're not racing with a destroy and
             * forgetting to destroy this, thus leaking
             */
	    (void) AO_fetch_and_sub1_full(&p->cc_refs);
	    continue;
	}
	memset(p, 0, sizeof (p));
	p->cc_gss_mechsp = &p->cc_gss_mechs;
	*cc = p;
	return GSS_S_COMPLETE;
    }

    /*
     * Slow path: calloc() and add to the slow path list.
     *
     * Mind you, we cache the last used call context in thread-specific
     * data, so this slow path for lookup (a singly linked list,
     * protected by a global lock) should rarely be hit.
     */
    p = calloc(1, sizeof (*p));
    if (!p)
	return GSS_S_UNAVAILABLE;
    p->cc_gss_mechsp = &p->cc_gss_mechs;

    HEIMDAL_MUTEX_lock(&call_context_mutex);
    HEIM_SLIST_INSERT_HEAD(call_contexts_slow, p, cc_link);
    *cc = p;
    HEIMDAL_MUTEX_unlock(&call_context_mutex);
    /*
     * Optimize lookup of this call context from the same thread so
     * we don't fall into the slow path below.
     */
    _gss_remember_call_context(&(*cc)->cc_minor_status, *cc);
    return GSS_S_COMPLETE;
}

/*
 * Map an "OM_uint32 *minor_status" to a call context handle.
 *
 * If looking_for == NULL then allocate a new call context.  This is
 * always for a PGSS-aware application.
 *
 * If looking_for != NULL we are dealing with a PGSS-aware app if it
 * turns out we allocated that value, else it must be a non-PGSS
 * application.
 *
 * We have a fast path, and a slow path, with thread-specific data used
 * to cache the slow path so that repeated use -in the same thread- of a
 * call context that would require a trip through the slow path can
 * actually avoid that slow path.
 */
OM_uint32
_gss_get_call_context(OM_uint32 *looking_for, _gss_call_context *cc)
{
    _gss_call_context p;
    ptrdiff_t i;

    *cc = NULL;

    if (!looking_for)
	return _gss_alloc_call_context(cc);

    /* Fast path: no locks, pointer arithmetic, O(1) */
    if (looking_for >= &call_contexts_fast[0].cc_minor_status &&
	looking_for <= &call_contexts_fast[CALL_CTX_FAST - 1].cc_minor_status) {
        uintptr_t k = (uintptr_t)looking_for;

        if (k % sizeof (_gss_call_context))
            /* XXX We should allocate a better major status code */
            return GSS_S_FAILURE;

	/*
	 * NOTE WELL: We assume that the first field of
	 *            _gss_call_context is OM_uint32 cc_minor_status.
	 */
	i = ((_gss_call_context)looking_for) - &call_contexts_fast[0];
        /*
         * XXX Do we need this check?  We could just trust the app, be
         * faster...
         */
	if (!AO_load(&call_contexts_fast[i].cc_refs))
	    return GSS_S_BAD_CALL_CONTEXT;
	*cc = &call_contexts_fast[i];
	_gss_remember_call_context(looking_for, *cc);
	return GSS_S_COMPLETE;
    }

    /*
     * Medium path: use thread-specific data
     */
    *cc = _gss_get_thr_call_context(looking_for);
    if (*cc)
	return GSS_S_COMPLETE;

    /* Slow path: search a singly linked list with global lock held */
    HEIMDAL_MUTEX_lock(&call_context_mutex);
    if (call_contexts_slow) {
        HEIM_SLIST_FOREACH(p, call_contexts_slow, cc_link) {
            if (looking_for != &p->cc_minor_status)
                continue;
            HEIMDAL_MUTEX_unlock(&call_context_mutex);
            *cc = p;
            /* Hit the medium path next time around in this thread */
            _gss_remember_call_context(looking_for, *cc);
            return GSS_S_COMPLETE;
        }
    }
    HEIMDAL_MUTEX_unlock(&call_context_mutex);

    /*
     * We did not find looking_for in our allocation list, therefore
     * this must be a non-PGSS application.
     *
     * We use a thread-specific duplicate of a global call context.
     *
     * Note that this is past the slow path.  If we have a mixture of
     * PGSS-aware apps using lots of call contexts and some non-PGSS-
     * aware apps in the same process, then we'll fall into the slow
     * path for the non-PGSS-aware application.  For the common case of
     * non-PGSS-aware apps we have a fair number of branches above, but
     * no loops.
     */
    p = _gss_get_thr_call_context(NULL);
    if (!p) {
	OM_uint32 major_status;

	p = calloc(1, sizeof (*p));
	if (!p)
	    return GSS_S_UNAVAILABLE;
	p->cc_gss_mechsp = &_gss_mechs; /* global mech list */
	p->cc_refs = 1;
	major_status = _gss_set_thr_call_context(p);
	if (major_status != GSS_S_COMPLETE) {
	    free(p);
	    return major_status;
	}
    }

    *cc = p;
    return GSS_S_COMPLETE;
}

/*
 * Utility function that takes an application-provided minor_status
 * argument (OM_uint32 *) and a mechanism OID and returns a mech-glue
 * call context, the mechanism provider struct, and a mechanism-specific
 * minor_status pointer (OM_uint32 *) if there is one.
 *
 * This is intended to be used thus:
 *
 * OM_uint32
 * gss_something_or_other(OM_uint32 *minor_status, ...)
 * {
 *     ...
 *     OM_uint32 major_status;
 *     _gss_call_context cc = NULL;
 *     gssapi_mech_interface m = NULL;
 *     OM_uint32 *mech_min_stat;
 *
 *     <initialize output arguments>
 *     ...
 *     major_status = _gss_get_cc_glue_and_mech(mech_oid,
 *						&minor_status,
 *						&cc, &m,
 *						&mech_min_stat);
 *
 *     if (major_status != GSS_S_COMPLETE)
 *         return major_status;
 *     ...
 *     major_status = m->gm_something_or_other(mech_min_stat, ...);
 *     *minor_status = *mech_min_stat;
 *     if (<error>) {
 *         _gss_mg_error(m, major_status, *minor_status);
 *         <cleanup>
 *         return major_status;
 *     }
 *     ...
 * }
 *
 * For GSS functions that have a desired_mechs (gss_OID_set) input or a
 * union object with elements for multiple mechanisms, the pattern is
 * slightly different, with the function first calling
 * _gss_get_call_context() to get the call context, then for each
 * mechanism calling _gss_get_cc_glue_and_mech() with that call context
 * to get the gssapi_mech_interface and mech_min_stat for it.  This
 * causes the minor_status -> call context mapping to be done just once.
 *
 * Non-standard GSS extensions that lack a minor_status argument, but
 * which need a call context to operate correctly, should have a
 * OM_uint32 *minor_status automatic variable initialized to NULL and
 * pass in the pointer to it (&minor_status).  This allows us to fetch
 * the last used call context.
 *
 * Inputs:
 *
 *  - mech (may be NULL when *m != NULL)
 *
 * Outputs:
 *
 *  - mech_cc (if not then *mech_cc is never NULL on success)
 *
 * Inputs if deref'ed != NULL / outputs if deref'ed == NULL:
 *
 *  - minor_statusp
 *  - cc
 *  - m (may/must be NULL if mech is GSS_C_NO_OID)
 *
 * All outputs (including input/outputs) are non-NULL on success.
 *
 * XXX Make sure we follow cc_parent to duplicate the parent's mech
 * element if it has one and the child doesn't.
 */
OM_uint32
_gss_get_cc_glue_and_mech(gss_const_OID mech,
			  OM_uint32 **minor_statusp,
			  _gss_call_context *cc,
			  gssapi_mech_interface *m,
			  OM_uint32 **mech_cc)
{
    struct _gss_mech_switch_list *mech_list;
    gssapi_mech_interface mi;
    _gss_mech_call_context p;
    OM_uint32 major_status;
    OM_uint32 *min;

    if (mech_cc != NULL)
	*mech_cc = NULL;
    if (minor_statusp != NULL && *minor_statusp != NULL)
	**minor_statusp = 0;

    /* XXX assert mech != GSS_C_NO_OID || (m && *m) */

    /*
     * We have some non-standard GSS extension functions that don't have
     * a OM_uint32 *minor_status argument.  For those we try to get the
     * last call context used and its associated minor_status.
     */
    if (*cc == NULL && (minor_statusp == NULL || *minor_statusp == NULL)) {
	*cc = _gss_get_thr_best_call_context();
	if (*cc == NULL)
	    return GSS_S_UNAVAILABLE;
    }

    if (*cc == NULL) {
	/* assert minor_status != NULL && *minor_statusp != NULL */
	major_status = _gss_get_call_context(*minor_statusp, cc);
	if (major_status != GSS_S_COMPLETE)
	    return major_status;
    }

    if (*cc != NULL && minor_statusp != NULL && *minor_statusp == NULL)
	*minor_statusp = &(*cc)->cc_minor_status;

    if (m != NULL && *m != NULL) {
	mi = *m;
    } else {
	/* This must be a GSS function operating on a single mechanism */
	mech_list = _gss_get_mech_list(*cc);
	mi = __gss_get_mechanism(mech_list, mech);
	if (mi == NULL)
	    return GSS_S_BAD_MECH;
	if (m != NULL)
	    *m = mi;
    }

    if (mech_cc == NULL)
	return GSS_S_COMPLETE;

    /* Find an element of the call context for the given mechanism */
    if ((*cc)->cc_mech) {
        HEIM_SLIST_FOREACH(p, (*cc)->cc_mech, gmcc_link) {
            if (p->gmcc_mech != *m)
                continue;
            /* Already have one */
            *mech_cc = p->gmcc_minor_status;
            return GSS_S_COMPLETE;
        }
    }

    if (!(*m)->gm_init_call_context || !(*m)->gm_release_call_context) {
	/*
	 * Mech provider doesn't support call contexts.  Use the
	 * application's minor_status argument for the mechanism method
	 * invocations.
	 */
	if (minor_statusp != NULL)
	    *mech_cc = *minor_statusp;
        else
            *mech_cc = &(*cc)->cc_minor_status;
	return GSS_S_COMPLETE;
    }

    /* Alloc mech element for call context */
    p = calloc(1, sizeof (*p));
    if (!p)
	return GSS_S_UNAVAILABLE;

    p->gmcc_mech = *m;


    if (minor_statusp != NULL)
	min = *minor_statusp;
    else
	min = &(*cc)->cc_minor_status;
    major_status = (*m)->gm_init_call_context(min, &p->gmcc_minor_status,
					      &(*cc)->cc_configuration);
    if (major_status != GSS_S_COMPLETE) {
	free(p);
	return major_status;
    }

    *mech_cc = p->gmcc_minor_status;
    HEIM_SLIST_INSERT_HEAD((*cc)->cc_mech, p, gmcc_link);

    return GSS_S_COMPLETE;
}

struct _gss_mech_switch_list *
_gss_get_mech_list(_gss_call_context cc)
{
    _gss_load_mech(cc->cc_gss_mechsp);
    return cc->cc_gss_mechsp;
}


GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_init_call_context(OM_uint32 *minor_status,
		      OM_uint32 **new_minor_status,
		      gss_buffer_t configuration)
{
    OM_uint32 major_status;
    void *config = NULL;
    _gss_call_context old_cc = NULL;
    _gss_call_context new_cc = NULL;

    if (configuration) {
	config = malloc(configuration->length);
	if (!config)
	    return GSS_S_UNAVAILABLE;
	(void) memcpy(config, configuration->value, configuration->length);
    }

    (void) _gss_get_call_context(minor_status, &old_cc);
    major_status = _gss_get_call_context(NULL, &new_cc);
    if (major_status != GSS_S_COMPLETE)
	return major_status;

    if (configuration != NULL) {
	new_cc->cc_configuration.length = configuration->length;
	new_cc->cc_configuration.value = config;
    } else if (old_cc != NULL) {
	old_cc->cc_refs++;
	new_cc->cc_parent = old_cc;
	new_cc->cc_gss_mechsp = old_cc->cc_gss_mechsp;
	new_cc->cc_configuration = old_cc->cc_configuration;
    }

    *new_minor_status = &new_cc->cc_minor_status;
    return GSS_S_COMPLETE;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_duplicate_call_context(OM_uint32 *minor_status,
			   OM_uint32 **new_minor_status)
{
    OM_uint32 major_status;
    _gss_call_context old_cc;
    _gss_call_context new_cc;

    major_status = _gss_get_call_context(minor_status, &old_cc);
    if (major_status != GSS_S_COMPLETE)
	return major_status;

    new_cc = calloc(1, sizeof (*new_cc));
    if (new_cc == NULL)
	return GSS_S_UNAVAILABLE;
    old_cc->cc_refs++;
    new_cc->cc_refs = 1;
    new_cc->cc_parent = old_cc;
    new_cc->cc_gss_mechsp = old_cc->cc_gss_mechsp;
    new_cc->cc_configuration = old_cc->cc_configuration;

    /* We don't duplicate mech elements here */

    *new_minor_status = &new_cc->cc_minor_status;
    return GSS_S_COMPLETE;
}

/* XXX Make this a void function */
GSSAPI_LIB_FUNCTION _gss_call_context GSSAPI_LIB_CALL
_gss_ref_call_context(_gss_call_context cc)
{
    cc->cc_refs++;
    return cc;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
_gss_release_call_context(_gss_call_context *ccp)
{
    _gss_mech_call_context p;
    _gss_call_context cc;
    OM_uint32 junk;

    cc = *ccp;
    if (cc == NULL)
	return GSS_S_COMPLETE;

    /* This check is silly; give us a bad handle and results are undefined */
    if (AO_load(&cc->cc_refs) == 0)
	return GSS_S_BAD_CALL_CONTEXT;

    if (AO_fetch_and_sub1_full(&cc->cc_refs) == 0) {
	while (cc->cc_mech) {
	    p = HEIM_SLIST_FIRST(cc->cc_mech);
	    if (p->gmcc_mech->gm_release_call_context)
		(void) p->gmcc_mech->gm_release_call_context(&junk,
							     &p->gmcc_minor_status);
	    HEIM_SLIST_REMOVE_HEAD(cc->cc_mech, gmcc_link);
	}
	if (cc->cc_parent == NULL) {
	    /* XXX Free loaded mechs, if any */
	    free(cc->cc_configuration.value);
	}
	if (cc >= &call_contexts_fast[0] &&
	    cc <= &call_contexts_fast[CALL_CTX_FAST - 1])
	    return GSS_S_COMPLETE;
	HEIMDAL_MUTEX_lock(&call_context_mutex);
	HEIM_SLIST_REMOVE(call_contexts_slow, cc, _gss_call_context, cc_link);
	HEIMDAL_MUTEX_unlock(&call_context_mutex);
	free(cc);
    }

    return GSS_S_COMPLETE;
}

void
_gss_release_thr_call_context(_gss_call_context *cc)
{
    (void) _gss_release_call_context(cc);
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_release_call_context(OM_uint32 *minor_status,
			 OM_uint32 **old_minor_status)
{
    OM_uint32 major_status;
    _gss_call_context cc;

    if (minor_status)
	*minor_status = 0;
    if (!*old_minor_status)
	return GSS_S_COMPLETE;

    major_status = _gss_get_call_context(*old_minor_status, &cc);
    if (major_status != GSS_S_COMPLETE)
	return GSS_S_BAD_CALL_CONTEXT;

    *old_minor_status = NULL;
    return _gss_release_call_context(&cc);
}
