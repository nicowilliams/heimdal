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

#define CALL_CTX_FAST 4
#define CALL_CTX_SLOW 64
static struct _gss_call_context call_contexts_fast[CALL_CTX_FAST];
static OM_uint32 *cc_minor_status_fast[CALL_CTX_FAST];
static _gss_call_context call_contexts_slow;
static HEIM_SLIST_HEAD(call_contexts_slow_rest, _gss_call_context) *call_contexts_slow_rest;
static HEIMDAL_MUTEX call_context_mutex = HEIMDAL_MUTEX_INITIALIZER;

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
 * We have three fast paths, and one slow path to do this mapping.
 */
OM_uint32
_gss_get_call_context(OM_uint32 *looking_for, _gss_call_context *cc)
{
    OM_uint32 major_status;
    _gss_call_context p;
    size_t i;

    *cc = NULL;

    /* Fast path 1 -- no locks, look in tiny array */

    if (looking_for) {
	/* Search for existing */
	for (i = 0; i < CALL_CTX_FAST; i++) {
	    if (looking_for != cc_minor_status_fast[i])
		continue;
	    if (!call_contexts_fast[i].cc_refs)
		return GSS_S_BAD_CALL_CONTEXT;
	    *cc = &call_contexts_fast[i];
	    return GSS_S_COMPLETE;
	}
    } else {
	/* Alloc new */
	for (i = 0; i < CALL_CTX_FAST; i++) {
	    if (call_contexts_fast[i].cc_refs)
		continue;
#if 0
	    if (heim_base_atomic_inc(&call_contexts_fast[i].cc_refs) > 1) {
		(void) heim_base_atomic_dec(&call_contexts_fast[i].cc_refs);
		continue;
	    }
#else
	    HEIMDAL_MUTEX_lock(&call_context_mutex);
	    if (call_contexts_fast[i].cc_refs++ > 0) {
		call_contexts_fast[i].cc_refs--;
		HEIMDAL_MUTEX_unlock(&call_context_mutex);
		continue;
	    }
	    HEIMDAL_MUTEX_unlock(&call_context_mutex);
#endif
	    memset(&call_contexts_fast[i], 0, sizeof (call_contexts_fast[i]));
	    call_contexts_fast[i].cc_gss_mechsp = &call_contexts_fast[i].cc_gss_mechs;
	    *cc = &call_contexts_fast[i];
	    return GSS_S_COMPLETE;
	}
    }

    /* Fast path 2 -- look in larger array */
    /*
     * XXX The intention is to make this path faster by comparing
     * looking_for to the call_contexts_slow[] array bounds.  Also, the
     * intention is to hold locks only while allocating this array,
     * using atomic integer ops for allocation (see below).
     */

    HEIMDAL_MUTEX_lock(&call_context_mutex);
    if (!looking_for && !call_contexts_slow) {
	call_contexts_slow = calloc(CALL_CTX_SLOW,
				    sizeof (*call_contexts_slow));
	if (!call_contexts_slow)
	    return GSS_S_UNAVAILABLE;
    }
    if (call_contexts_slow) {
	/* XXX Turn this into an array bounds index check instead of a loop */
	for (i = 0; i < CALL_CTX_SLOW; i++) {
	    if (looking_for &&
		looking_for != &call_contexts_slow[i].cc_minor_status)
		continue;
	    else if (!looking_for && call_contexts_fast[i].cc_refs)
		continue;
	    else if (!looking_for)
		call_contexts_fast[i].cc_refs++; /* XXX use atomics, not mutex */
	    HEIMDAL_MUTEX_unlock(&call_context_mutex);
	    if (looking_for && call_contexts_fast[i].cc_refs)
		return GSS_S_BAD_CALL_CONTEXT;
	    memset(&call_contexts_slow[i], 0, sizeof (call_contexts_slow[i]));
	    call_contexts_slow[i].cc_gss_mechsp = &call_contexts_slow[i].cc_gss_mechs;
	    *cc = &call_contexts_slow[i];
	    return GSS_S_COMPLETE;
	}
    }
    HEIMDAL_MUTEX_unlock(&call_context_mutex);

    /* Medium path -- check thread-specific */
    if (looking_for) {
	*cc = _gss_get_thr_call_context(looking_for);
	if (*cc)
	    return GSS_S_COMPLETE;
    } else {
	/* Allocate a new call context, add it to the slow path list */
	p = calloc(1, sizeof (*p));
	if (!p)
	    return GSS_S_UNAVAILABLE;
	p->cc_gss_mechsp = &p->cc_gss_mechs;

	HEIMDAL_MUTEX_lock(&call_context_mutex);
	HEIM_SLIST_INSERT_HEAD(call_contexts_slow_rest, p, cc_link);
	*cc = p;
	HEIMDAL_MUTEX_unlock(&call_context_mutex);
	/*
	 * Optimize lookup of this call context from the same thread so
	 * we don't fall into the slow path below.
	 */
	_gss_remember_call_context(&(*cc)->cc_minor_status, *cc);
	return GSS_S_COMPLETE;
    }

    /* Slow path -- check a singly linked list, with lock held */

    if (looking_for) {
	HEIMDAL_MUTEX_lock(&call_context_mutex);
	HEIM_SLIST_FOREACH(p, call_contexts_slow_rest, cc_link) {
	    if (looking_for != &p->cc_minor_status)
		continue;
	    HEIMDAL_MUTEX_unlock(&call_context_mutex);
	    *cc = p;
	    return GSS_S_COMPLETE;
	}
	HEIMDAL_MUTEX_unlock(&call_context_mutex);
    }

    /*
     * Non-PGSS application.  The OM_uint32 * we were looking for is not
     * one we've allocated.  We use a thread-specific call context
     * with global configuration.
     *
     * Note that this is past the slow path.  If we have a mixture of
     * PGSS-aware apps using lots of call contexts and some non-PGSS-
     * aware apps in the same process, then we'll fall into the slow
     * path for the non-PGSS-aware application.  For the common case of
     * non-PGSS-aware apps we have a fair number of branches above, but
     * no loops.  XXX We can optimize this by not checking for PGSS call
     * contexts when we know that none have been allocated.
     */

    p = _gss_get_thr_call_context(NULL);
    if (!p) {
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
 * minor_status (OM_uint32 *) if there is one.
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
 * causes the minor_status->call context mapping to be done just once.
 *
 * Non-standard GSS extensions that lack a minor_status argument should
 * have a OM_uint32 *minor_status automatic variable initialized to NULL
 * and pass in the pointer to it (&minor_status).  This allows us to
 * fetch the last used call context.
 *
 * Inputs:
 *
 *  - mech (may be NULL when *m != NULL)
 *
 * Outputs:
 *
 *  - mech_cc (may be NULL, if not *mech_cc is never NULL on success)
 *
 * Inputs if deref'ed != NULL / outputs if deref'ed == NULL:
 *
 *  - minor_statusp
 *  - cc
 *  - m (may/must be NULL if mech is GSS_C_NO_OID)
 *
 * All outputs (and input/outputs) are non-NULL on success.
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
    HEIM_SLIST_FOREACH(p, (*cc)->cc_mech, gmcc_link) {
	if (p->gmcc_mech != *m)
	    continue;
	/* Already have one */
	*mech_cc = p->gmcc_minor_status;
	return GSS_S_COMPLETE;
    }

    if (!(*m)->gm_init_call_context || !(*m)->gm_release_call_context) {
	/*
	 * Mech provider doesn't support call contexts.  Use the
	 * application's minor_status argument for the mechanism method
	 * invocations.
	 */
	if (minor_statusp != NULL)
	    *mech_cc = *minor_statusp;
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

    *new_minor_status = &new_cc->cc_minor_status;
    return GSS_S_COMPLETE;
}

void
_gss_release_thr_call_context(_gss_call_context cc)
{
    OM_uint32 minor_status;
    _gss_mech_call_context p;

    if (cc->cc_refs-- == 1) {
	while (cc->cc_mech) {
	    p = HEIM_SLIST_FIRST(cc->cc_mech);
	    (void)p->gmcc_mech->gm_release_call_context(&minor_status,
							&p->gmcc_minor_status);
	    HEIM_SLIST_REMOVE_HEAD(cc->cc_mech, gmcc_link);
	}
	free(cc->cc_configuration.value);
	/* XXX Free loaded mechs, if any */
	free(cc);
    }
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_release_call_context(OM_uint32 *minor_status,
			 OM_uint32 **old_minor_status)
{
    _gss_mech_call_context p;
    _gss_call_context cc;
    OM_uint32 major_status;

    *minor_status = 0;
    if (!*old_minor_status)
	return GSS_S_COMPLETE;

    major_status = _gss_get_call_context(*old_minor_status, &cc);
    if (major_status != GSS_S_COMPLETE)
	return GSS_S_BAD_CALL_CONTEXT;

    *old_minor_status = NULL;

    while (cc->cc_mech) {
	p = HEIM_SLIST_FIRST(cc->cc_mech);
	/*
	 * Note that there's no need to pass in a mechanism-specific
	 * minor-status as the first argument to gm_release_call_context()
	 * since gm_release_call_context() will be getting it as the
	 * second argument and there's nothing special to do with the
	 * actual minor status code on return.
	 */
	major_status = p->gmcc_mech->gm_release_call_context(minor_status,
							     &p->gmcc_minor_status);
	if (major_status != GSS_S_COMPLETE)
	    return major_status;
	HEIM_SLIST_REMOVE_HEAD(cc->cc_mech, gmcc_link);
    }

    free(cc->cc_configuration.value);
    free(cc);
    return GSS_S_COMPLETE;
}
