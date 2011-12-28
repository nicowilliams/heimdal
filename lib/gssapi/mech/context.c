#include "mech_locl.h"
#include "heim_threads.h"

struct mg_thread_ctx {
    gss_OID		mech;
    OM_uint32		maj_stat;
    OM_uint32		min_stat;
    gss_buffer_desc	maj_error;
    gss_buffer_desc	min_error;
    _gss_call_context	cc;
    /* Speed up lookup of call context by matching the last minor_status used */
    _gss_call_context	last_cc;
    OM_uint32		*last_cc_min_stat;
};

static HEIMDAL_MUTEX context_mutex = HEIMDAL_MUTEX_INITIALIZER;
static int created_key;
static HEIMDAL_thread_key context_key;


static void
destroy_context(void *ptr)
{
    struct mg_thread_ctx *mg = ptr;
    OM_uint32 junk;

    if (mg == NULL)
	return;

    _gss_release_thr_call_context(&mg->cc); /* but not last_cc */
    gss_release_buffer(&junk, &mg->maj_error);
    gss_release_buffer(&junk, &mg->min_error);
    free(mg);
}


static struct mg_thread_ctx *
_gss_mechglue_thread(void)
{
    struct mg_thread_ctx *ctx;
    int ret = 0;

    HEIMDAL_MUTEX_lock(&context_mutex);

    if (!created_key) {
	HEIMDAL_key_create(&context_key, destroy_context, ret);
	if (ret) {
	    HEIMDAL_MUTEX_unlock(&context_mutex);
	    return NULL;
	}
	created_key = 1;
    }
    HEIMDAL_MUTEX_unlock(&context_mutex);

    ctx = HEIMDAL_getspecific(context_key);
    if (ctx == NULL) {

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL)
	    return NULL;
	HEIMDAL_setspecific(context_key, ctx, ret);
	if (ret) {
	    free(ctx);
	    return NULL;
	}
    }
    return ctx;
}

OM_uint32
_gss_mg_get_error(const gss_OID mech, OM_uint32 type,
		  OM_uint32 value, gss_buffer_t string)
{
    struct mg_thread_ctx *mg;

    mg = _gss_mechglue_thread();
    if (mg == NULL)
	return GSS_S_BAD_STATUS;

#if 0
    /*
     * We cant check the mech here since a pseudo-mech might have
     * called an lower layer and then the mech info is all broken
     */
    if (mech != NULL && gss_oid_equal(mg->mech, mech) == 0)
	return GSS_S_BAD_STATUS;
#endif

    switch (type) {
    case GSS_C_GSS_CODE: {
	if (value != mg->maj_stat || mg->maj_error.length == 0)
	    break;
	string->value = malloc(mg->maj_error.length + 1);
	string->length = mg->maj_error.length;
	memcpy(string->value, mg->maj_error.value, mg->maj_error.length);
        ((char *) string->value)[string->length] = '\0';
	return GSS_S_COMPLETE;
    }
    case GSS_C_MECH_CODE: {
	if (value != mg->min_stat || mg->min_error.length == 0)
	    break;
	string->value = malloc(mg->min_error.length + 1);
	string->length = mg->min_error.length;
	memcpy(string->value, mg->min_error.value, mg->min_error.length);
        ((char *) string->value)[string->length] = '\0';
	return GSS_S_COMPLETE;
    }
    }
    string->value = NULL;
    string->length = 0;
    return GSS_S_BAD_STATUS;
}

void
_gss_mg_error(gssapi_mech_interface m, OM_uint32 maj, OM_uint32 min)
{
    OM_uint32 major_status, minor_status;
    OM_uint32 message_content;
    struct mg_thread_ctx *mg;

    /*
     * Mechs without gss_display_status() does
     * gss_mg_collect_error() by themself.
     */
    if (m->gm_display_status == NULL)
	return ;

    mg = _gss_mechglue_thread();
    if (mg == NULL)
	return;

    gss_release_buffer(&minor_status, &mg->maj_error);
    gss_release_buffer(&minor_status, &mg->min_error);

    mg->mech = &m->gm_mech_oid;
    mg->maj_stat = maj;
    mg->min_stat = min;

    major_status = m->gm_display_status(&minor_status,
					maj,
					GSS_C_GSS_CODE,
					&m->gm_mech_oid,
					&message_content,
					&mg->maj_error);
    if (GSS_ERROR(major_status)) {
	mg->maj_error.value = NULL;
	mg->maj_error.length = 0;
    }
    major_status = m->gm_display_status(&minor_status,
					min,
					GSS_C_MECH_CODE,
					&m->gm_mech_oid,
					&message_content,
					&mg->min_error);
    if (GSS_ERROR(major_status)) {
	mg->min_error.value = NULL;
	mg->min_error.length = 0;
    }
}

void
gss_mg_collect_error(gss_OID mech, OM_uint32 maj, OM_uint32 min)
{
    _gss_call_context cc;
    struct _gss_mech_switch_list *mech_list;
    gssapi_mech_interface m;

    cc = _gss_get_thr_best_call_context();
    if (!cc)
	return;
    mech_list = _gss_get_mech_list(cc);
    m = __gss_get_mechanism(mech_list, mech);
    if (m == NULL)
	return;
    _gss_mg_error(m, maj, min);
}

/*
 * Get one of two possible call contexts saved in thread-specific data:
 * a duplicate of the default call context, or the last call context
 * used by the application.  The latter is both: an optimization and a
 * method of dealing with GSS extensions that lack a minor_status
 * argument.
 */
_gss_call_context
_gss_get_thr_call_context(OM_uint32 *cc_ref)
{
    struct mg_thread_ctx *mg;

    mg = _gss_mechglue_thread();
    if (mg == NULL)
	return NULL;

    if (cc_ref == NULL)
	return mg->cc;

    /*
     * We are either in a non-PGSS-aware application, or in a GSS
     * extension that has no minor_status argument.
     */
    if (cc_ref != NULL && mg->last_cc_min_stat == cc_ref)
	return mg->last_cc;
    return NULL;
}

/*
 * This function is used from GSS functions that lack a OM_uint32 *minor_status
 * argument.  It returns the last call context used by a PGSS-aware
 * application in this same thread, else it returns the thread's global
 * call context.
 */
_gss_call_context
_gss_get_thr_best_call_context(void)
{
    struct mg_thread_ctx *mg;

    mg = _gss_mechglue_thread();
    if (mg == NULL)
	return NULL;

    if (mg->last_cc)
	return mg->last_cc;
    return mg->cc;
}

/*
 * Save in thread-specific data a duplicate of the default configuration
 * call context for a non-PGSS-aware application.
 */
OM_uint32
_gss_set_thr_call_context(_gss_call_context cc)
{
    struct mg_thread_ctx *mg;

    mg = _gss_mechglue_thread();
    if (mg == NULL)
	return GSS_S_UNAVAILABLE;

    mg->cc = cc;
    return GSS_S_COMPLETE;
}

/*
 * Memoize a given OM_uint32*->call context mapping in thread-specific
 * data.  This is for non-PGSS-aware applications and for GSS extensions
 * that lack a call context.
 */
void
_gss_remember_call_context(OM_uint32 *cc_ref, _gss_call_context cc)
{
    struct mg_thread_ctx *mg;

    mg = _gss_mechglue_thread();
    if (mg == NULL)
	return;

    mg->last_cc = cc;
    mg->last_cc_min_stat = cc_ref;
}


