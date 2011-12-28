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

#include <gssapi_mech.h>
#include <heimbase.h>
#include "mechqueue.h"
#ifdef HAVE_ATOMIC_OPS
#include <atomic_ops.h>
#else
#ifdef AO_t
#error "Something is defining AO_t that probably shouldn't be"
#endif
#define AO_t size_t
#endif

/*
 * Call contexts are referenced via minor_status argument to GSS
 * functions, that is, call contexts are addressed by OM_uint32
 * pointers.
 */

typedef struct _gss_mech_call_context *_gss_mech_call_context;

struct _gss_mech_call_context {
	OM_uint32		*gmcc_minor_status;
	OM_uint32		gmcc_minor_status_actual;
	gssapi_mech_interface	gmcc_mech;
	HEIM_SLIST_ENTRY(_gss_mech_call_context) gmcc_link;
};

typedef struct _gss_call_context *_gss_call_context;
struct _gss_call_context {
	/* NOTE WELL: The first field must be OM_uint32 cc_minor_status! */
	OM_uint32		cc_minor_status;
	gss_buffer_desc		cc_configuration;
	_gss_call_context	cc_parent;
	AO_t			cc_refs;
	HEIM_SLIST_HEAD(cc_mech, _gss_mech_call_context) *cc_mech;
	HEIM_SLIST_ENTRY(_gss_call_context) cc_link;
	/*
	 * All state that would otherwise be global needs to go here.
	 * This really means the loaded mechanisms, _gss_mechs.
	 *
	 * Use:
	 *
	 * % nm *.o|grep -v ' [NpRrTtU] '|grep ' [a-zA-Z] '|grep -v * oid_desc
	 *
	 * (using the GNU nm) to find global variables in the mechglue
	 * that might need to move here.
	 */
	struct _gss_mech_switch_list cc_gss_mechs;
	struct _gss_mech_switch_list *cc_gss_mechsp;
};

typedef HEIM_SLIST_HEAD(call_contexts_slow_rest, _gss_call_context) *_gss_call_context_list;

OM_uint32 _gss_get_call_context(OM_uint32 *looking_for, _gss_call_context *cc);
struct _gss_mech_switch_list * _gss_get_mech_list(_gss_call_context cc);

OM_uint32 _gss_get_cc_glue_and_mech(gss_const_OID mech,
				    OM_uint32 **minor_statusp,
				    _gss_call_context *cc,
				    gssapi_mech_interface *m,
				    OM_uint32 **mech_cc);

OM_uint32 _gss_set_thr_call_context(_gss_call_context cc);
void _gss_remember_call_context(OM_uint32 *cc_ref, _gss_call_context cc);
_gss_call_context _gss_get_thr_call_context(OM_uint32 *cc);
_gss_call_context _gss_get_thr_best_call_context(void);
void _gss_release_thr_call_context(_gss_call_context *cc);
OM_uint32 _gss_release_call_context(_gss_call_context *ccp);

