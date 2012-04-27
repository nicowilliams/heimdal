/*
 * Copyright (c) 1997 - 2004 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
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

#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#endif

/* Gaah! I want a portable funopen */
struct fileptr {
    const char *s;
    FILE *f;
};

static char *
config_fgets(char *str, size_t len, struct fileptr *ptr)
{
    /* XXX this is not correct, in that they don't do the same if the
       line is longer than len */
    if(ptr->f != NULL)
	return fgets(str, len, ptr->f);
    else {
	/* this is almost strsep_copy */
	const char *p;
	ssize_t l;
	if(*ptr->s == '\0')
	    return NULL;
	p = ptr->s + strcspn(ptr->s, "\n");
	if(*p == '\n')
	    p++;
	l = min(len, (size_t)(p - ptr->s));
	if(len > 0) {
	    memcpy(str, ptr->s, l);
	    str[l] = '\0';
	}
	ptr->s = p;
	return str;
    }
}

static krb5_error_code parse_section(char *p, heim_object_t *s,
				     heim_object_t *res,
				     const char **err_message);
static krb5_error_code parse_binding(struct fileptr *f, unsigned *lineno, char *p,
				     heim_object_t *b,
				     heim_object_t *parent,
				     const char **err_message);
static krb5_error_code parse_list(struct fileptr *f, unsigned *lineno,
				  heim_object_t *parent,
				  const char **err_message);

static char **heim_array_to_cstring_array(heim_array_t a);

/*
 * Gets a node from the tree, adding the node if it's missing.
 */
heim_object_t
_krb5_config_get_entry(heim_object_t *parent, const char *name, int type)
{
    heim_object_t o;
    heim_object_t c;
    heim_string_t s;
    int ret;

    s = heim_string_create(name);
    if (!s)
	return NULL;

    if (*parent == NULL)
        *parent = heim_dict_create(11);
    if (*parent == NULL) {
        heim_release(s);
        return NULL; /* XXX ENOMEM */
    }

    o = heim_dict_get_value(*parent, s);
    if (o) {
        heim_release(s);
	return (o);
    }
    if (type == krb5_config_string)
	c = heim_array_create();
    else
	c = heim_dict_create(11);
    if (!c) {
        heim_release(s);
	return NULL;
    }

    /*
     * References to s and c are retained by *parent.  We release c in
     * particular so that the caller need not release it.
     */
    ret = heim_dict_set_value(*parent, s, c);
    heim_release(s);
    heim_release(c);
    if (ret)
	return NULL;
    return c;
}

int
_krb5_config_add_string(heim_object_t parent, const char *str)
{
    heim_string_t s;
    int ret;

    heim_assert(heim_get_tid(parent) == heim_array_get_type_id(),
		"Internal error in configuration parsing");

    s = heim_string_create(str);
    if (!s)
	return ENOMEM;

    ret = heim_array_append_value(parent, s);
    heim_release(s);
    return ret;
}


/*
 * Parse a section:
 *
 * [section]
 *	foo = bar
 *	b = {
 *		a
 *	    }
 * ...
 *
 * starting at the line in `p', storing the resulting structure in
 * `s' and hooking it into `parent'.
 * Store the error message in `err_message'.
 */

static krb5_error_code
parse_section(char *p, heim_object_t *s, heim_object_t *parent,
	      const char **err_message)
{
    char *p1;
    heim_object_t tmp;

    p1 = strchr (p + 1, ']');
    if (p1 == NULL) {
	*err_message = "missing ]";
	return KRB5_CONFIG_BADFORMAT;
    }
    *p1 = '\0';
    tmp = _krb5_config_get_entry(parent, p + 1, krb5_config_list);
    if(tmp == NULL) {
	*err_message = "out of memory";
	return KRB5_CONFIG_BADFORMAT; /* XXX Should be ENOMEM, no? */
    }
    *s = tmp;
    return 0;
}

/*
 * Parse a brace-enclosed list from `f', hooking in the structure at
 * `parent'.
 * Store the error message in `err_message'.
 */

static krb5_error_code
parse_list(struct fileptr *f, unsigned *lineno, heim_object_t *parent,
	   const char **err_message)
{
    char buf[KRB5_BUFSIZ];
    krb5_error_code ret;
    heim_object_t b = NULL;
    unsigned beg_lineno = *lineno;

    while(config_fgets(buf, sizeof(buf), f) != NULL) {
	char *p;

	++*lineno;
	buf[strcspn(buf, "\r\n")] = '\0';
	p = buf;
	while(isspace((unsigned char)*p))
	    ++p;
	if (*p == '#' || *p == ';' || *p == '\0')
	    continue;
	while(isspace((unsigned char)*p))
	    ++p;
	if (*p == '}')
	    return 0;
	if (*p == '\0')
	    continue;
	ret = parse_binding (f, lineno, p, &b, parent, err_message);
	if (ret)
	    return ret;
    }
    *lineno = beg_lineno;
    *err_message = "unclosed {";
    return KRB5_CONFIG_BADFORMAT;
}

/*
 *
 */

static krb5_error_code
parse_binding(struct fileptr *f, unsigned *lineno, char *p,
	      heim_object_t *b, heim_object_t *parent,
	      const char **err_message)
{
    heim_object_t tmp;
    char *p1, *p2;
    krb5_error_code ret = 0;

    p1 = p;
    while (*p && *p != '=' && !isspace((unsigned char)*p))
	++p;
    if (*p == '\0') {
	*err_message = "missing =";
	return KRB5_CONFIG_BADFORMAT;
    }
    p2 = p;
    while (isspace((unsigned char)*p))
	++p;
    if (*p != '=') {
	*err_message = "missing =";
	return KRB5_CONFIG_BADFORMAT;
    }
    ++p;
    while(isspace((unsigned char)*p))
	++p;
    *p2 = '\0';
    if (*p == '{') {
	tmp = _krb5_config_get_entry(parent, p1, krb5_config_list);
	if (tmp == NULL) {
	    *err_message = "out of memory";
	    return KRB5_CONFIG_BADFORMAT; /* XXX Should be ENOMEM, no? */
	}
	ret = parse_list (f, lineno, &tmp, err_message);
    } else {
	tmp = _krb5_config_get_entry(parent, p1, krb5_config_string);
	if (tmp == NULL) {
	    *err_message = "out of memory";
	    return KRB5_CONFIG_BADFORMAT; /* XXX Should be ENOMEM, no? */
	}
	p1 = p;
	p = p1 + strlen(p1);
	while(p > p1 && isspace((unsigned char)*(p-1)))
	    --p;
	*p = '\0';
	_krb5_config_add_string(tmp, p1);
    }
    *b = tmp;
    return ret;
}

#if defined(__APPLE__)

#if MAC_OS_X_VERSION_MIN_REQUIRED >= 1060
#define HAVE_CFPROPERTYLISTCREATEWITHSTREAM 1
#endif

static char *
cfstring2cstring(CFStringRef string)
{
    CFIndex len;
    char *str;

    str = (char *) CFStringGetCStringPtr(string, kCFStringEncodingUTF8);
    if (str)
	return strdup(str);

    len = CFStringGetLength(string);
    len = 1 + CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8);
    str = malloc(len);
    if (str == NULL)
	return NULL;

    if (!CFStringGetCString(string, str, len, kCFStringEncodingUTF8)) {
	free(str);
	return NULL;
    }
    return str;
}

static void
convert_content(const void *key, const void *value, void *context)
{
    krb5_config_section *tmp, **parent = context;
    char *k = NULL;
    char *v = NULL;

    if (CFGetTypeID(key) != CFStringGetTypeID())
	return;

    k = cfstring2cstring(key);
    if (k == NULL)
	return; /* XXX silent ENOMEM! */

    if (CFGetTypeID(value) == CFStringGetTypeID()) {
	tmp = _krb5_config_get_entry(parent, k, krb5_config_string);
        if (tmp == NULL)
            goto out;
        v = cfstring2cstring(value);
        if (v == NULL)
            goto out;
        _krb5_config_add_string(tmp, v);
    } else if (CFGetTypeID(value) == CFDictionaryGetTypeID()) {
	tmp = _krb5_config_get_entry(parent, k, krb5_config_list);
        if (tmp == NULL)
            goto out;
	CFDictionaryApplyFunction(value, convert_content, &tmp);
    } else {
	/* log */
    }

out:
    free(k);
    free(v);
    return; /* XXX silent errors! */
}

static krb5_error_code
parse_plist_config(krb5_context context, const char *path, krb5_config_section **parent)
{
    CFReadStreamRef s;
    CFDictionaryRef d;
    CFURLRef url;

    url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (UInt8 *)path, strlen(path), FALSE);
    if (url == NULL) {
	krb5_clear_error_message(context);
	return ENOMEM;
    }

    s = CFReadStreamCreateWithFile(kCFAllocatorDefault, url);
    CFRelease(url);
    if (s == NULL) {
	krb5_clear_error_message(context);
	return ENOMEM;
    }

    if (!CFReadStreamOpen(s)) {
	CFRelease(s);
	krb5_clear_error_message(context);
	return ENOENT;
    }

#ifdef HAVE_CFPROPERTYLISTCREATEWITHSTREAM
    d = (CFDictionaryRef)CFPropertyListCreateWithStream(NULL, s, 0, kCFPropertyListImmutable, NULL, NULL);
#else
    d = (CFDictionaryRef)CFPropertyListCreateFromStream(NULL, s, 0, kCFPropertyListImmutable, NULL, NULL);
#endif
    CFRelease(s);
    if (d == NULL) {
	krb5_clear_error_message(context);
	return ENOENT;
    }

    CFDictionaryApplyFunction(d, convert_content, parent);
    CFRelease(d);

    return 0;
}

#endif


/*
 * Parse the config file `fname', generating the structures into `res'
 * returning error messages in `err_message'
 */

static krb5_error_code
krb5_config_parse_debug(struct fileptr *f,
			heim_object_t *res,
			unsigned *lineno,
			const char **err_message)
{
    heim_object_t s = NULL;
    heim_object_t b = NULL;
    char buf[KRB5_BUFSIZ];
    krb5_error_code ret;

    while (config_fgets(buf, sizeof(buf), f) != NULL) {
	char *p;

	++*lineno;
	buf[strcspn(buf, "\r\n")] = '\0';
	p = buf;
	while(isspace((unsigned char)*p))
	    ++p;
	if (*p == '#' || *p == ';')
	    continue;
	if (*p == '[') {
	    ret = parse_section(p, &s, res, err_message);
	    if (ret)
		return ret;
	    b = NULL;
	} else if (*p == '}') {
	    *err_message = "unmatched }";
	    return EINVAL;
	} else if(*p != '\0') {
	    if (s == NULL) {
		*err_message = "binding before section";
		return EINVAL;
	    }
	    ret = parse_binding(f, lineno, p, &b, &s, err_message);
	    if (ret)
		return ret;
	}
    }
    return 0;
}

static int
is_plist_file(const char *fname)
{
    size_t len = strlen(fname);
    char suffix[] = ".plist";
    if (len < sizeof(suffix))
	return 0;
    if (strcasecmp(&fname[len - (sizeof(suffix) - 1)], suffix) != 0)
	return 0;
    return 1;
}

static int
is_json_file(const char *fname)
{
    size_t len = strlen(fname);
    char suffix[] = ".json";
    if (len < sizeof(suffix))
	return 0;
    if (strcasecmp(&fname[len - (sizeof(suffix) - 1)], suffix) != 0)
	return 0;
    return 1;
}

/**
 * Parse a configuration file and add the result into res. This
 * interface can be used to parse several configuration files into one
 * resulting krb5_config_section by calling it repeatably.
 *
 * @param context a Kerberos 5 context.
 * @param fname a file name to a Kerberos configuration file
 * @param res the returned result, must be free with krb5_free_config_files().
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_config_parse_file_multi (krb5_context context,
			      const char *fname,
			      krb5_config_section **res)
{
    const char *str = "Unknown syntax error";
    char *newfname = NULL;
    unsigned lineno = 0;
    krb5_error_code ret;
    heim_error_t e = NULL;
    heim_string_t err_str = NULL;
    heim_object_t *resobj = (heim_object_t *)res;
    struct fileptr f;

    /**
     * If the fname starts with "~/" parse configuration file in the
     * current users home directory. The behavior can be disabled and
     * enabled by calling krb5_set_home_dir_access().
     */
    if (fname[0] == '~' && fname[1] == '/') {
#ifndef KRB5_USE_PATH_TOKENS
	const char *home = NULL;

	if (!_krb5_homedir_access(context)) {
	    krb5_set_error_message(context, EPERM,
				   "Access to home directory not allowed");
	    return EPERM;
	}

	if(!issuid())
	    home = getenv("HOME");

	if (home == NULL) {
	    struct passwd *pw = getpwuid(getuid());
	    if(pw != NULL)
		home = pw->pw_dir;
	}
	if (home) {
	    int aret;

	    aret = asprintf(&newfname, "%s%s", home, &fname[1]);
	    if (aret == -1 || newfname == NULL) {
		krb5_set_error_message(context, ENOMEM,
				       N_("malloc: out of memory", ""));
		return ENOMEM;
	    }
	    fname = newfname;
	}
#else  /* KRB5_USE_PATH_TOKENS */
	if (asprintf(&newfname, "%%{USERCONFIG}%s", &fname[1]) < 0 ||
	    newfname == NULL)
	{
	    krb5_set_error_message(context, ENOMEM,
				   N_("malloc: out of memory", ""));
	    return ENOMEM;
	}
	fname = newfname;
#endif
    }

    if (is_plist_file(fname)) {
#ifdef __APPLE__
	ret = parse_plist_config(context, fname, resobj);
	if (ret) {
	    krb5_set_error_message(context, ret,
				   "Failed to parse plist %s", fname);
	    if (newfname)
		free(newfname);
	    return ret;
	}
#else
	krb5_set_error_message(context, ENOENT,
			       "no support for plist configuration files");
	return ENOENT;
#endif
    } else {
#ifdef KRB5_USE_PATH_TOKENS
	char * exp_fname = NULL;

	ret = _krb5_expand_path_tokens(context, fname, &exp_fname);
	if (ret) {
	    if (newfname)
		free(newfname);
	    return ret;
	}

	if (newfname)
	    free(newfname);
	fname = newfname = exp_fname;
#endif

	f.f = fopen(fname, "r");
	f.s = NULL;
	if(f.f == NULL) {
	    ret = errno;
	    krb5_set_error_message(context, ret, "open %s: %s",
				   fname, strerror(ret));
	    if (newfname)
		free(newfname);
	    return ret;
	}

        if (is_json_file(fname)) {
            char *fdata;
            size_t len;

            fseek(f.f, 0, SEEK_END);
            len = ftell(f.f);
            fseek(f.f, 0, SEEK_SET);

            if (len < 1){
                ret = ENOENT;
                str = "JSON file was empty";
                goto err;
            }

            fdata = malloc(len + 1);
            if (!fdata) {
                ret = ENOMEM;
                str = "Out of memory";
                goto err;
            }
            fdata[len] = '\0';

            if (fread(fdata, 1, len, f.f) != len) {
                ret = EIO;
                str = "Could not read JSON file";
                goto err;
            }

            ret = EINVAL;
            *resobj = heim_json_create(fdata, 8, 0, &e);
            if (*resobj)
                ret = 0;
        } else {
            ret = krb5_config_parse_debug(&f, resobj, &lineno, &str);
        }
err:
        if (e) {
            ret = heim_error_get_code(e);
            err_str = heim_error_copy_string(e);
            if (err_str)
                str = heim_string_get_utf8(err_str);
            krb5_set_error_message(context, ret, "%s: %s",
                                   fname, str);
            heim_release(err_str);
            heim_release(e);
        } else if (ret) {
            krb5_set_error_message(context, ret, "%s:%u: %s",
                                   fname, lineno, str);
        }
	fclose(f.f);
	if (ret) {
	    if (newfname)
		free(newfname);
	    return ret;
	}
    }
    return 0;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_config_parse_file (krb5_context context,
			const char *fname,
			krb5_config_section **res)
{
    *res = NULL;
    return krb5_config_parse_file_multi(context, fname, res);
}

/**
 * Free configuration file section, the result of
 * krb5_config_parse_file() and krb5_config_parse_file_multi().
 *
 * @param context A Kerberos 5 context
 * @param s the configuration section to free
 *
 * @return returns 0 on successes, otherwise an error code, see
 *          krb5_get_error_message()
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_config_file_free (krb5_context context, krb5_config_section *s)
{
    heim_release((heim_object_t)s);
    return 0;
}

#ifndef HEIMDAL_SMALLER

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_config_copy(krb5_context context,
		  krb5_config_section *c,
		  krb5_config_section **head)
{
    /* XXX Deep copy?? */
    *head = heim_retain(c);
    return 0;
}

#endif /* HEIMDAL_SMALLER */

/**
 * Get a list of configuration binding list for more processing
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param ... a list of names, terminated with NULL.
 *
 * @return NULL if configuration list is not found, a list otherwise
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION const krb5_config_binding * KRB5_LIB_CALL
krb5_config_get_list (krb5_context context,
		      const krb5_config_section *c,
		      ...)
{
    heim_const_object_t o;
    va_list args;

    va_start(args, c);
    o = krb5_config_vget_list(context, c, args);
    va_end(args);

    return o;
}

/**
 * Get a list of configuration binding list for more processing
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param args a va_list of arguments
 *
 * @return NULL if configuration list is not found, a list otherwise
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION const krb5_config_binding * KRB5_LIB_CALL
krb5_config_vget_list(krb5_context context,
		      const krb5_config_section *c,
		      va_list args)
{
    krb5_config_binding *o;
    heim_error_t herr;

    if (!c)
        c = context->cf;
    o = heim_path_vget_by_cstring(c, &herr, args);
    if (!o && herr) {
	heim_string_t s = heim_error_copy_string(herr);
	const char *p = NULL;

	if (s)
	    p = heim_string_get_utf8(s);
	if (p)
	    krb5_set_error_message(context, heim_error_get_code(herr), "%s", p);
	heim_release(s);
    }

    return o;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_config_iter_bindings(krb5_context context,
                          const krb5_config_binding *c,
                          void **statep,
                          const char **keyp,
                          const krb5_config_binding **valuep)
{
    heim_tid_t dicttid = heim_dict_get_type_id();
    heim_object_t k, v;
    int ret;

    do {
        ret = heim_dict_iterate_nf(c, statep, &k, &v);
        if (ret > 0)
            return ret;
    } while (ret == 0 && heim_get_tid(v) != dicttid);
    if (ret)
        return ret;

    heim_assert(heim_get_tid(k) == heim_string_get_type_id(),
                "Non-string keys in krb5 configuration not allowed");
    *keyp = heim_string_get_utf8(k);
    *valuep = (heim_const_object_t)v;

    return ret;
}

/**
 * Returns a "const char *" to a string in the configuration database.
 * The string may not be valid after a reload of the configuration
 * database so a caller should make a local copy if it needs to keep
 * the string.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param ... a list of names, terminated with NULL.
 *
 * @return NULL if configuration string not found, a string otherwise
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_config_get_string (krb5_context context,
			const krb5_config_section *c,
			...)
{
    const char *ret;
    va_list args;

    va_start(args, c);
    if (!c)
        c = context->cf;
    ret = krb5_config_vget_string (context, c, args);
    va_end(args);
    return ret;
}

/**
 * Like krb5_config_get_string(), but uses a va_list instead of ...
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param args a va_list of arguments
 *
 * @return NULL if configuration string not found, a string otherwise
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_config_vget_string (krb5_context context,
			 const krb5_config_section *c,
			 va_list args)
{
    heim_object_t o;
    heim_error_t herr;

    if (!c)
        c = context->cf;
    o = heim_path_vget_by_cstring(c, &herr, args);
    if (!o)
        return NULL;
    if (heim_get_tid(o) == heim_array_get_type_id())
        o = heim_array_get_value(o, 0);
    if (!o)
        return NULL;
    if (heim_get_tid(o) != heim_string_get_type_id())
	return NULL; /* We could serialize o as JSON... */

    if (!o && herr) {
	heim_string_t s = heim_error_copy_string(herr);
	const char *p = NULL;

	if (s)
	    p = heim_string_get_utf8(s);
	if (p)
	    krb5_set_error_message(context, heim_error_get_code(herr), "%s", p);
	heim_release(s);
    }

    return heim_string_get_utf8(o);
}

/**
 * Like krb5_config_vget_string(), but instead of returning NULL,
 * instead return a default value.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param def_value the default value to return if no configuration
 *        found in the database.
 * @param args a va_list of arguments
 *
 * @return a configuration string
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_config_vget_string_default (krb5_context context,
				 const krb5_config_section *c,
				 const char *def_value,
				 va_list args)
{
    const char *ret;

    ret = krb5_config_vget_string (context, c, args);
    if (ret == NULL)
	ret = def_value;
    return ret;
}

/**
 * Like krb5_config_get_string(), but instead of returning NULL,
 * instead return a default value.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param def_value the default value to return if no configuration
 *        found in the database.
 * @param ... a list of names, terminated with NULL.
 *
 * @return a configuration string
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_config_get_string_default (krb5_context context,
				const krb5_config_section *c,
				const char *def_value,
				...)
{
    const char *ret;
    va_list args;

    va_start(args, def_value);
    ret = krb5_config_vget_string_default (context, c, def_value, args);
    va_end(args);
    return ret;
}

static char *
next_component_string(char * begin, const char * delims, char **state)
{
    char * end;

    if (*state)
        begin = *state;

    if (*begin == '\0')
        return NULL;

    end = begin;
    while (*end == '"') {
        char * t = strchr(end + 1, '"');

        if (t)
            end = ++t;
        else
            end += strlen(end);
    }

    if (*end != '\0') {
        size_t pos;

        pos = strcspn(end, delims);
        end = end + pos;
    }

    if (*end != '\0') {
        *end = '\0';
        *state = end + 1;
        if (*begin == '"' && *(end - 1) == '"' && begin + 1 < end) {
            begin++; *(end - 1) = '\0';
        }
        return begin;
    }

    *state = end;
    if (*begin == '"' && *(end - 1) == '"' && begin + 1 < end) {
        begin++; *(end - 1) = '\0';
    }
    return begin;
}

/**
 * Get a list of configuration strings, free the result with
 * krb5_config_free_strings().
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param args a va_list of arguments
 *
 * @return TRUE or FALSE
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION char ** KRB5_LIB_CALL
krb5_config_vget_strings(krb5_context context,
			 const krb5_config_section *c,
			 va_list args)
{
    heim_array_t a = NULL;
    heim_error_t herr;
    char **strs = NULL;
    char **res = NULL;
    char **tmp_res = NULL;
    const char *p;
    char *pos;
    size_t i, alen, reslen;

    if (!c)
        c = context->cf;
    a = heim_path_vget_by_cstring(c, &herr, args);
    if (!a) {
        if (herr) {
            heim_string_t s = heim_error_copy_string(herr);

            if (s)
                p = heim_string_get_utf8(s);
            if (p)
                krb5_set_error_message(context, heim_error_get_code(herr), "%s", p);
            heim_release(s);
        }
        return NULL;
    }

    alen = heim_array_get_length(a);
    if (alen == 0)
        return NULL;
    strs = heim_array_to_cstring_array(a);
    if (!strs)
        goto enomem;
    reslen = 0;
    res = calloc(reslen + 1, sizeof (*res));
    if (!res)
        goto enomem;

    /*
     * For backwards compatibility we have to do this here, not when
     * parsing the config file.  So gross.  So, so, so, so gross.
     */
    for (i = 0; i < alen; i++) {
        pos = NULL;
        while ((p = next_component_string(strs[i], " \t", &pos))) {
            tmp_res = realloc(res, (reslen + 2) * sizeof (*res));
            tmp_res[reslen] = strdup(p);
            if (!tmp_res[reslen])
                goto enomem;
            reslen++;
            tmp_res[reslen] = NULL;
            res = tmp_res;
        }
    }
    krb5_config_free_strings(strs);

    return res;

enomem:
    krb5_config_free_strings(strs);
    krb5_config_free_strings(res);
    krb5_enomem(context);

    return NULL;
}

/**
 * Get a list of configuration strings, free the result with
 * krb5_config_free_strings().
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param ... a list of names, terminated with NULL.
 *
 * @return TRUE or FALSE
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION char** KRB5_LIB_CALL
krb5_config_get_strings(krb5_context context,
			const krb5_config_section *c,
			...)
{
    va_list ap;
    char **ret;

    va_start(ap, c);
    if (!c)
        c = context->cf;
    ret = krb5_config_vget_strings(context, c, ap);
    va_end(ap);
    return ret;
}

/**
 * Free the resulting strings from krb5_config-get_strings() and
 * krb5_config_vget_strings().
 *
 * @param strings strings to free
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_config_free_strings(char **strings)
{
    char **s = strings;
    while(s && *s){
	free(*s);
	s++;
    }
    free(strings);
}

/**
 * Like krb5_config_get_bool_default() but with a va_list list of
 * configuration selection.
 *
 * Configuration value to a boolean value, where yes/true and any
 * non-zero number means TRUE and other value is FALSE.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param def_value the default value to return if no configuration
 *        found in the database.
 * @param args a va_list of arguments
 *
 * @return TRUE or FALSE
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_config_vget_bool_default (krb5_context context,
			       const krb5_config_section *c,
			       krb5_boolean def_value,
			       va_list args)
{
    const char *str;
    str = krb5_config_vget_string (context, c, args);
    if(str == NULL)
	return def_value;
    if(strcasecmp(str, "yes") == 0 ||
       strcasecmp(str, "true") == 0 ||
       atoi(str)) return TRUE;
    return FALSE;
}

/**
 * krb5_config_get_bool() will convert the configuration
 * option value to a boolean value, where yes/true and any non-zero
 * number means TRUE and other value is FALSE.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param args a va_list of arguments
 *
 * @return TRUE or FALSE
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_config_vget_bool  (krb5_context context,
			const krb5_config_section *c,
			va_list args)
{
    return krb5_config_vget_bool_default (context, c, FALSE, args);
}

/**
 * krb5_config_get_bool_default() will convert the configuration
 * option value to a boolean value, where yes/true and any non-zero
 * number means TRUE and other value is FALSE.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param def_value the default value to return if no configuration
 *        found in the database.
 * @param ... a list of names, terminated with NULL.
 *
 * @return TRUE or FALSE
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_config_get_bool_default (krb5_context context,
			      const krb5_config_section *c,
			      krb5_boolean def_value,
			      ...)
{
    va_list ap;
    krb5_boolean ret;
    va_start(ap, def_value);
    ret = krb5_config_vget_bool_default(context, c, def_value, ap);
    va_end(ap);
    return ret;
}

/**
 * Like krb5_config_get_bool() but with a va_list list of
 * configuration selection.
 *
 * Configuration value to a boolean value, where yes/true and any
 * non-zero number means TRUE and other value is FALSE.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param ... a list of names, terminated with NULL.
 *
 * @return TRUE or FALSE
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_config_get_bool (krb5_context context,
		      const krb5_config_section *c,
		      ...)
{
    va_list ap;
    krb5_boolean ret;
    va_start(ap, c);
    ret = krb5_config_vget_bool (context, c, ap);
    va_end(ap);
    return ret;
}

/**
 * Get the time from the configuration file using a relative time.
 *
 * Like krb5_config_get_time_default() but with a va_list list of
 * configuration selection.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param def_value the default value to return if no configuration
 *        found in the database.
 * @param args a va_list of arguments
 *
 * @return parsed the time (or def_value on parse error)
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_config_vget_time_default (krb5_context context,
			       const krb5_config_section *c,
			       int def_value,
			       va_list args)
{
    const char *str;
    krb5_deltat t;

    if (!c)
        c = context->cf;
    str = krb5_config_vget_string (context, c, args);
    if(str == NULL)
	return def_value;
    if (krb5_string_to_deltat(str, &t))
	return def_value;
    return t;
}

/**
 * Get the time from the configuration file using a relative time, for example: 1h30s
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param args a va_list of arguments
 *
 * @return parsed the time or -1 on error
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_config_vget_time  (krb5_context context,
			const krb5_config_section *c,
			va_list args)
{
    return krb5_config_vget_time_default (context, c, -1, args);
}

/**
 * Get the time from the configuration file using a relative time, for example: 1h30s
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param def_value the default value to return if no configuration
 *        found in the database.
 * @param ... a list of names, terminated with NULL.
 *
 * @return parsed the time (or def_value on parse error)
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_config_get_time_default (krb5_context context,
			      const krb5_config_section *c,
			      int def_value,
			      ...)
{
    va_list ap;
    int ret;
    va_start(ap, def_value);
    ret = krb5_config_vget_time_default(context, c, def_value, ap);
    va_end(ap);
    return ret;
}

/**
 * Get the time from the configuration file using a relative time, for example: 1h30s
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param ... a list of names, terminated with NULL.
 *
 * @return parsed the time or -1 on error
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_config_get_time (krb5_context context,
		      const krb5_config_section *c,
		      ...)
{
    va_list ap;
    int ret;
    va_start(ap, c);
    ret = krb5_config_vget_time (context, c, ap);
    va_end(ap);
    return ret;
}


KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_config_vget_int_default (krb5_context context,
			      const krb5_config_section *c,
			      int def_value,
			      va_list args)
{
    const char *str;

    if (!c)
        c = context->cf;
    str = krb5_config_vget_string (context, c, args);
    if(str == NULL)
	return def_value;
    else {
	char *endptr;
	long l;
	l = strtol(str, &endptr, 0);
	if (endptr == str)
	    return def_value;
	else
	    return l;
    }
}

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_config_vget_int  (krb5_context context,
		       const krb5_config_section *c,
		       va_list args)
{
    return krb5_config_vget_int_default (context, c, -1, args);
}

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_config_get_int_default (krb5_context context,
			     const krb5_config_section *c,
			     int def_value,
			     ...)
{
    va_list ap;
    int ret;
    va_start(ap, def_value);
    ret = krb5_config_vget_int_default(context, c, def_value, ap);
    va_end(ap);
    return ret;
}

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_config_get_int (krb5_context context,
		     const krb5_config_section *c,
		     ...)
{
    va_list ap;
    int ret;
    va_start(ap, c);
    ret = krb5_config_vget_int (context, c, ap);
    va_end(ap);
    return ret;
}

static char **
heim_array_to_cstring_array(heim_array_t a)
{
    heim_string_t str;
    size_t i, alen;
    char **p;
    const char *s;

    alen = heim_array_get_length(a);
    p = calloc(alen + 1, sizeof (*p));
    if (!p)
        return NULL;

    for (i = 0; i < alen; i++) {
        str = heim_array_get_value(a, i);
        /* str can't be NULL; assert? */
        s = heim_string_get_utf8(str);
        /* s can't be NULL; assert? */
        p[i] = strdup(s);
        if (!p[i])
            goto err;
    }
    p[alen] = NULL;
    return p;

err:
    for (i = 0; i < alen; i++) {
        if (p[i])
            free(p[i]);
    }
    free(p);
    return NULL;
}


#ifndef HEIMDAL_SMALLER

/**
 * Deprecated: configuration files are not strings
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_config_parse_string_multi(krb5_context context,
			       const char *string,
			       krb5_config_section **res)
    KRB5_DEPRECATED_FUNCTION("Use X instead")
{
    heim_object_t *resobj = (heim_object_t *)res;
    const char *str;
    unsigned lineno = 0;
    krb5_error_code ret;
    struct fileptr f;
    f.f = NULL;
    f.s = string;

    ret = krb5_config_parse_debug(&f, resobj, &lineno, &str);
    if (ret) {
	krb5_set_error_message(context, ret, "%s:%u: %s",
			       "<constant>", lineno, str);
	return ret;
    }
    return 0;
}

#endif
