/*
 * Copyright (c) 2020 Kungliga Tekniska Högskolan
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

#include "baselocl.h"

#undef __attribute__
#define __attribute__(X)

struct heim_context_s {
    heim_log_facility       *warn_dest; /* XXX Move warn.c into lib/base as well */
    heim_log_facility       *debug_dest;
    char                    *time_fmt;
    unsigned int            log_utc:1;
    unsigned int            homedir_access:1;
    heim_err_cb_context     error_context;
    heim_err_cb_clear_msg    clear_error_message;
    heim_err_cb_free_msg    free_error_message;
    heim_err_cb_get_msg     get_error_message;
    heim_err_cb_set_msg     set_error_message;
    const char              *unknown_error;
    const char              *success;
};

heim_context
heim_context_init(void)
{
    heim_context context;

    if ((context = calloc(1, sizeof(*context))) == NULL)
        return NULL;

    context->log_utc = 1;
    context->clear_error_message = NULL;
    context->free_error_message = NULL;
    context->get_error_message = NULL;
    context->set_error_message = NULL;
    context->error_context = NULL;
    context->unknown_error = "Unknown error";
    context->success = "Success";
    context->debug_dest = NULL;
    context->warn_dest = NULL;
    context->time_fmt = NULL;
    return context;
}

void
heim_context_free(heim_context *contextp)
{
    heim_context context = *contextp;

    *contextp = NULL;
    if (!context)
        return;
    heim_closelog(context, context->debug_dest);
    heim_closelog(context, context->warn_dest);
    free(context->time_fmt);
    free(context);
}

void
heim_context_set_msg_cb(heim_context context,
                        heim_err_cb_context cb_context,
                        heim_err_cb_clear_msg cb_clear_msg,
                        heim_err_cb_free_msg cb_free_msg,
                        heim_err_cb_get_msg cb_get_msg,
                        heim_err_cb_set_msg cb_set_msg)
{
    context->error_context = cb_context;
    context->clear_error_message = cb_clear_msg;
    context->free_error_message = cb_free_msg;
    context->set_error_message = cb_set_msg;
    context->get_error_message = cb_get_msg;
}

heim_error_code
heim_context_set_time_fmt(heim_context context, const char *fmt)
{
    char *s;

    if (fmt == NULL) {
        free(context->time_fmt);
        return 0;
    }
    if ((s = strdup(fmt)) == NULL)
        return heim_enomem(context);
    free(context->time_fmt);
    context->time_fmt = s;
    return 0;
}

const char *
heim_context_get_time_fmt(heim_context context)
{
    return context->time_fmt ? context->time_fmt : "%Y-%m-%dT%H:%M:%S";
}

unsigned int
heim_context_set_log_utc(heim_context context, unsigned int log_utc)
{
    unsigned int old = context->log_utc;

    context->log_utc = log_utc ? 1 : 0;
    return old;
}

int
heim_context_get_log_utc(heim_context context)
{
    return context->log_utc;
}

unsigned int
heim_context_set_homedir_access(heim_context context, unsigned int homedir_access)
{
    unsigned int old = context->homedir_access;

    context->homedir_access = homedir_access ? 1 : 0;
    return old;
}

unsigned int
heim_context_get_homedir_access(heim_context context)
{
    return context->homedir_access;
}

void
heim_clear_error_message(heim_context context)
{
    if (context != NULL && context->clear_error_message != NULL)
        context->clear_error_message(context->error_context);
}

void
heim_free_error_message(heim_context context, const char *msg)
{
    if (context != NULL && context->free_error_message != NULL &&
        msg != context->unknown_error && msg != context->success)
        context->free_error_message(context->error_context, msg);
}

const char *
heim_get_error_message(heim_context context, heim_error_code ret)
{
    if (context != NULL && context->get_error_message != NULL)
        return context->get_error_message(context->error_context, ret);
    if (ret)
        return context->unknown_error;
    return context->success;
}

void
heim_set_error_message(heim_context context, heim_error_code ret,
		       const char *fmt, ...)
    __attribute__ ((__format__ (__printf__, 3, 4)))
{
    va_list ap;

    va_start(ap, fmt);
    heim_vset_error_message(context, ret, fmt, ap);
    va_end(ap);
}

void
heim_vset_error_message(heim_context context, heim_error_code ret,
                        const char *fmt, va_list args)
    __attribute__ ((__format__ (__printf__, 3, 0)))
{
    if (context != NULL && context->set_error_message != NULL)
        context->set_error_message(context->error_context, ret, fmt, args);
}

heim_error_code
heim_enomem(heim_context context)
{
    heim_set_error_message(context, ENOMEM, "malloc: out of memory");
    return ENOMEM;
}

heim_log_facility *
heim_get_warn_dest(heim_context context)
{
    return context->warn_dest;
}

heim_log_facility *
heim_get_debug_dest(heim_context context)
{
    return context->debug_dest;
}

heim_error_code
heim_set_warn_dest(heim_context context, heim_log_facility *fac)
{
    context->warn_dest = fac;
    return 0;
}

heim_error_code
heim_set_debug_dest(heim_context context, heim_log_facility *fac)
{
    context->debug_dest = fac;
    return 0;
}

#define PATH_SEP ":"

static heim_error_code
add_file(char ***pfilenames, int *len, char *file)
{
    char **pp = *pfilenames;
    int i;

    for(i = 0; i < *len; i++) {
        if(strcmp(pp[i], file) == 0) {
            free(file);
            return 0;
        }
    }

    pp = realloc(*pfilenames, (*len + 2) * sizeof(*pp));
    if (pp == NULL) {
        free(file);
        return ENOMEM;
    }

    pp[*len] = file;
    pp[*len + 1] = NULL;
    *pfilenames = pp;
    *len += 1;
    return 0;
}

#ifdef WIN32
static char *
get_default_config_config_files_from_registry(void)
{
    static const char *KeyName = "Software\\Heimdal"; /* XXX #define this */
    char *config_file = NULL;
    LONG rcode;
    HKEY key;

    rcode = RegOpenKeyEx(HKEY_CURRENT_USER, KeyName, 0, KEY_READ, &key);
    if (rcode == ERROR_SUCCESS) {
        config_file = heim_parse_reg_value_as_multi_string(NULL, key, "config",
                                                           REG_NONE, 0, PATH_SEP);
        RegCloseKey(key);
    }

    if (config_file)
        return config_file;

    rcode = RegOpenKeyEx(HKEY_LOCAL_MACHINE, KeyName, 0, KEY_READ, &key);
    if (rcode == ERROR_SUCCESS) {
        config_file = heim_parse_reg_value_as_multi_string(NULL, key, "config",
                                                           REG_NONE, 0, PATH_SEP);
        RegCloseKey(key);
    }

    return config_file;
}
#endif

heim_error_code
heim_prepend_config_files(const char *filelist,
                          char **pq,
                          char ***ret_pp)
{
    heim_error_code ret;
    const char *p, *q;
    char **pp;
    int len;
    char *fn;

    pp = NULL;

    len = 0;
    p = filelist;
    while(1) {
        ssize_t l;
        q = p;
        l = strsep_copy(&q, PATH_SEP, NULL, 0);
        if(l == -1)
            break;
        fn = malloc(l + 1);
        if(fn == NULL) {
            heim_free_config_files(pp);
            return ENOMEM;
        }
        (void) strsep_copy(&p, PATH_SEP, fn, l + 1);
        ret = add_file(&pp, &len, fn);
        if (ret) {
            heim_free_config_files(pp);
            return ret;
        }
    }

    if (pq != NULL) {
        int i;

        for (i = 0; pq[i] != NULL; i++) {
            fn = strdup(pq[i]);
            if (fn == NULL) {
                heim_free_config_files(pp);
                return ENOMEM;
            }
            ret = add_file(&pp, &len, fn);
            if (ret) {
                heim_free_config_files(pp);
                return ret;
            }
        }
    }

    *ret_pp = pp;
    return 0;
}

heim_error_code
heim_prepend_config_files_default(const char *prepend,
                                  const char *def,
                                  const char *envvar,
                                  char ***pfilenames)
{
    heim_error_code ret;
    char **defpp, **pp = NULL;

    ret = heim_get_default_config_files(def, envvar, &defpp);
    if (ret)
        return ret;

    ret = heim_prepend_config_files(prepend, defpp, &pp);
    heim_free_config_files(defpp);
    if (ret) {
        return ret;
    }
    *pfilenames = pp;
    return 0;
}

heim_error_code
heim_get_default_config_files(const char *def,
                              const char *envvar,
                              char ***pfilenames)
{
    const char *files = NULL;

    files = secure_getenv(envvar);

#ifdef _WIN32
    if (files == NULL) {
        char * reg_files;
        reg_files = get_default_config_config_files_from_registry();
        if (reg_files != NULL) {
            heim_error_code code;

            code = heim_prepend_config_files(reg_files, NULL, pfilenames);
            free(reg_files);

            return code;
        }
    }
#endif

    if (files == NULL)
        files = def;
    return heim_prepend_config_files(files, NULL, pfilenames);
}

heim_error_code
heim_set_config_files(heim_context context, char **filenames,
                      heim_config_binding **res)
{
    heim_error_code ret;
    size_t ngood = 0;

    *res = NULL;
    while (filenames != NULL && *filenames != NULL && **filenames != '\0') {
        ret = heim_config_parse_file_multi(context, *filenames, res);
        if (ret != 0 && ret != ENOENT && ret != EACCES && ret != EPERM
            && ret != HEIM_ERR_CONFIG_BADFORMAT) {
            heim_config_file_free(context, *res);
            *res = NULL;
            return ret;
        }
        ngood += ret ? 0 : 1;
        filenames++;
    }

#ifdef _WIN32
    {
        heim_error_code ret2;

        ret2 = heim_load_config_from_registry(context, REGPATH_KERBEROS,
                                              REGPATH_HEIMDAL, res);

        if (ngood == 0)
            ret = ret2;
        ngood += ret2 ? 0 : 1;
    }
#endif
    return ngood ? 0 : ret;
}

void
heim_free_config_files(char **filenames)
{
    char **p;

    for (p = filenames; p && *p != NULL; p++)
        free(*p);
    free(filenames);
}
