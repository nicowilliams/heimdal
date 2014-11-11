/*
 * Copyright (c) 2001, 2003, 2005 - 2006 Kungliga Tekniska Högskolan
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

#include "krb5_locl.h"

#undef __attribute__
#define __attribute__(x)

static const char *get_error_message(krb5_context, krb5_error_code, int);

/**
 * Clears the error message from the Kerberos 5 context.
 *
 * @param context The Kerberos 5 context to clear
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_clear_error_message(krb5_context context)
{
    HEIMDAL_MUTEX_lock(context->mutex);
    if (context->error_string)
	free(context->error_string);
    context->error_code = 0;
    context->error_string = NULL;
    HEIMDAL_MUTEX_unlock(context->mutex);
}

/**
 * Set the context full error string for a specific error code.
 * The error that is stored should be internationalized.
 *
 * The if context is NULL, no error string is stored.
 *
 * @param context Kerberos 5 context
 * @param ret The error code
 * @param fmt Error string for the error code
 * @param ... printf(3) style parameters.
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_set_error_message(krb5_context context, krb5_error_code ret,
		       const char *fmt, ...)
    __attribute__ ((format (printf, 3, 4)))
{
    va_list ap;

    va_start(ap, fmt);
    krb5_vset_error_message (context, ret, fmt, ap);
    va_end(ap);
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_setmsg(krb5_context context, krb5_error_code ret, const char *fmt, ...)
    __attribute__ ((format (printf, 3, 4)))
{
    va_list ap;

    krb5_clear_error_message(context);
    if (ret != 0) {
        va_start(ap, fmt);
        krb5_vset_error_message(context, ret, fmt, ap);
        va_end(ap);
    }
    return ret;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_prependmsg(krb5_context context, krb5_error_code ret, const char *fmt, ...)
    __attribute__ ((format (printf, 3, 4)))
{
    va_list ap;

    va_start(ap, fmt);
    krb5_vprepend_error_message(context, ret, fmt, ap);
    va_end(ap);
    return ret;
}

/**
 * Set the context full error string for a specific error code.
 *
 * The if context is NULL, no error string is stored.
 *
 * @param context Kerberos 5 context
 * @param ret The error code
 * @param fmt Error string for the error code
 * @param args printf(3) style parameters.
 *
 * @ingroup krb5_error
 */


KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_vset_error_message (krb5_context context, krb5_error_code ret,
			 const char *fmt, va_list args)
    __attribute__ ((format (printf, 3, 0)))
{
    if (context == NULL)
	return;

    HEIMDAL_MUTEX_lock(context->mutex);
    if (context->error_string) {
	free(context->error_string);
	context->error_string = NULL;
    }
    context->error_code = ret;
    if (ret != ENOMEM) {
        if (vasprintf(&context->error_string, fmt, args) < 0)
            context->error_string = NULL;
    }
    HEIMDAL_MUTEX_unlock(context->mutex);
    if (context->error_string)
	_krb5_debug(context, 100, "error message: %s: %d", context->error_string, ret);
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_vsetmsg(krb5_context context, krb5_error_code ret,
			 const char *fmt, va_list args)
    __attribute__ ((format (printf, 3, 0)))
{
    krb5_vset_error_message(context, ret, fmt, args);
    return ret;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_set_error(krb5_context context, krb5_error_code ret)
{
    HEIMDAL_MUTEX_lock(context->mutex);
    if (context->error_code != ret && context->error_string != NULL) {
	free(context->error_string);
	context->error_string = NULL;
    }
    context->error_code = ret;
    _krb5_debug(context, 100, "error number: %d", ret);
    HEIMDAL_MUTEX_unlock(context->mutex);
    return ret;
}

/**
 * Prepend an error message to the error message for the given error
 * code.
 *
 * The if context is NULL, no error string is stored.
 *
 * @param context Kerberos 5 context
 * @param ret The error code
 * @param fmt Error string for the error code
 * @param ... printf(3) style parameters.
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_prepend_error_message(krb5_context context, krb5_error_code ret,
			   const char *fmt, ...)
    __attribute__ ((format (printf, 3, 4)))
{
    va_list ap;

    va_start(ap, fmt);
    krb5_vprepend_error_message(context, ret, fmt, ap);
    va_end(ap);
}

/**
 * Prepend an error message to the error message for the given error
 * code.
 *
 * The if context is NULL, no error string is stored.
 *
 * @param context Kerberos 5 context
 * @param ret The error code
 * @param fmt Error string for the error code
 * @param args printf(3) style parameters.
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_vprepend_error_message(krb5_context context, krb5_error_code ret,
			    const char *fmt, va_list args)
    __attribute__ ((format (printf, 3, 0)))
{
    const char *prev_msg;
    char *str = NULL;
    int e;

    if (context == NULL || vasprintf(&str, fmt, args) < 0 || str == NULL)
	return;

    e = asprintf(&str, fmt, args);
    if (e < 0 || str == NULL) {
        _krb5_set_error(context, ENOMEM);
        return;
    }

    prev_msg = get_error_message(context, ret, 0);
    krb5_set_error_message(context, ret, "%s: %s", str, prev_msg);
    krb5_free_error_message(context, prev_msg);
}

/**
 * Prepend an error message to the error message for a given error
 * code, and set the error code to the second given error code.
 *
 * The if context is NULL, no error string is stored.
 *
 * @param context Kerberos 5 context
 * @param old_ret The previous error code
 * @param new_ret The new error code
 * @param fmt Error string for the error code
 * @param ... printf(3) style parameters.
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_prepend_error_message2(krb5_context context,
                            krb5_error_code old_ret,
                            krb5_error_code new_ret,
			    const char *fmt, ...)
    __attribute__ ((format (printf, 4, 5)))
{
    va_list ap;

    va_start(ap, fmt);
    krb5_vprepend_error_message2(context, old_ret, new_ret, fmt, ap);
    va_end(ap);
}

/**
 * Prepend an error message to the error message for a given error
 * code, and set the error code to the second given error code.
 *
 * The if context is NULL, no error string is stored.
 *
 * @param context Kerberos 5 context
 * @param old_ret The previous error code
 * @param new_ret The new error code
 * @param fmt Error string for the error code
 * @param args printf(3) style parameters.
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_vprepend_error_message2(krb5_context context,
                             krb5_error_code old_ret,
                             krb5_error_code new_ret,
			     const char *fmt, va_list args)
    __attribute__ ((format (printf, 4, 0)))
{
    const char *prev_msg;
    char *str = NULL;
    int e;

    if (context == NULL || vasprintf(&str, fmt, args) < 0 || str == NULL)
	return;

    e = asprintf(&str, fmt, args);
    if (e < 0 || str == NULL) {
        _krb5_set_error(context, ENOMEM);
        return;
    }

    prev_msg = get_error_message(context, old_ret, 0);
    krb5_set_error_message(context, new_ret, "%s: %s", str, prev_msg);
    krb5_free_error_message(context, prev_msg);
}

static char *oom_msg = N_("Out of memory", "");

static char *
err_fmt_fmt(const char *err_fmt, long code, const char *msg)
{
    krb5_error_code ret;
    krb5_storage *sp;
    const char *p, *s;
    char *res;

    sp = krb5_storage_emem();

    for (s = p = err_fmt; p != NULL && *p != '\0'; p++) {
        if (*p != '%')
            continue;
        if (p[1] == '\0')
            break;
        krb5_storage_write(sp, s, p - s);
        s = p + 2;
        switch (p[1]) {
        case 'M':
            krb5_storage_write(sp, msg, strlen(msg));
            break;
        case 'C':
            krb5_storage_printf(sp, "%ld", code);
            break;
        case '%':
            krb5_storage_write(sp, "%", sizeof("%") - 1);
            break;
        default:
            krb5_storage_printf(sp, "%%%c", p[1]);
            break;
        }
        p++;
        continue;
    }
    krb5_storage_write(sp, s, p - s);       /* Remainder after last token. */
    krb5_storage_write(sp, "", sizeof("")); /* NUL */
    ret = krb5_ret_stringz(sp, &res);
    krb5_storage_free(sp);
    if (ret)
        return oom_msg;
    return res;
}


static const char *
get_error_message(krb5_context context, krb5_error_code code, int final)
{
    char *str = NULL;
    char *str_formatted = NULL;
    const char *err_fmt = NULL;
    const char *cstr = NULL;
    char buf[128];
    int free_context = 0;

    if (code == 0) {
	str = strdup("Success");
        if (str == NULL)
            return oom_msg;
        return str;
    }

    /*
     * The MIT version of this function ignores the krb5_context
     * and several widely deployed applications call krb5_get_error_message()
     * with a NULL context in order to translate an error code as a
     * replacement for error_message().  Another reason a NULL context
     * might be provided is if the krb5_init_context() call itself
     * failed.
     */
    if (context) {
        if (final) {
            err_fmt = krb5_config_get_string(context, NULL, "libdefaults",
                                             "err_fmt", NULL);
        }
        HEIMDAL_MUTEX_lock(context->mutex);
        if (context->error_string &&
            (code == context->error_code || context->error_code == 0)) {
            str = strdup(context->error_string);
            if (str == NULL)
                str = oom_msg;
        }
        HEIMDAL_MUTEX_unlock(context->mutex);

        if (str) {
            if (final)
                return str;

            str_formatted = err_fmt_fmt(err_fmt, code, str);
            free(str);
            return str_formatted;
        }
    } else if (code == ENOMEM) {
        return oom_msg;
    } else {
        if (krb5_init_context(&context) == 0)
            free_context = 1;
    }

    /* Why com_right_r() and not com_right()? */
    if (context) {
        cstr = com_right_r(context->et_list, code, buf, sizeof(buf));
    }

    if (free_context)
        krb5_free_context(context);

    if (cstr == NULL)
        cstr = error_message(code);

    if (cstr) {
        if (final && err_fmt != NULL)
            return err_fmt_fmt(err_fmt, code, cstr);
        return strdup(cstr);
    }

    if (asprintf(&str, "<unknown error: %d>", (int)code) == -1 || str == NULL)
	return oom_msg;

    return cstr;
}


/**
 * Return the error message for `code' in context. On memory
 * allocation error the function returns NULL.
 *
 * @param context Kerberos 5 context
 * @param code Error code related to the error
 *
 * @return an error string, needs to be freed with
 * krb5_free_error_message(). The functions return NULL on error.
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION const char * KRB5_LIB_CALL
krb5_get_error_message(krb5_context context, krb5_error_code code)
{
    return get_error_message(context, code, 1);
}


/**
 * Free the error message returned by krb5_get_error_message().
 *
 * @param context Kerberos context
 * @param msg error message to free, returned byg
 *        krb5_get_error_message().
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_free_error_message(krb5_context context, const char *msg)
{
    if (msg != oom_msg)
        free(rk_UNCONST(msg));
}


/**
 * Return the error string for the error code. The caller must not
 * free the string.
 *
 * This function is deprecated since its not threadsafe.
 *
 * @param context Kerberos 5 context.
 * @param code Kerberos error code.
 *
 * @return the error message matching code
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_get_err_text(krb5_context context, krb5_error_code code)
    KRB5_DEPRECATED_FUNCTION("Use krb5_get_error_message instead")
{
    const char *p = NULL;
    if(context != NULL)
	p = com_right(context->et_list, code);
    if(p == NULL)
	p = strerror(code);
    if (p == NULL)
	p = "Unknown error";
    return p;
}

