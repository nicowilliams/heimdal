/*
 * Copyright (c) 1997 - 2005 Kungliga Tekniska Högskolan
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
#include "kuserok_plugin.h"
#include <dirent.h>

#ifndef SYSTEM_K5LOGIN_DIR
#define SYSTEM_K5LOGIN_DIR SYSCONFDIR "/k5login.d"
#endif

struct plctx {
    const char           *rule;
    const char           *luser;
    krb5_const_principal principal;
    krb5_boolean         result;
};

static krb5_error_code
plcallback(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    const krb5plugin_kuserok_ftable *locate = plug;
    struct plctx *plctx = userctx;

    return locate->kuserok(plugctx, context, plctx->rule, plctx->luser,
			   plctx->principal, &plctx->result);
}

static krb5_error_code kuserok_user_k5login_plug_f(void *, krb5_context,
						   const char *, const char *,
						   krb5_const_principal,
						   krb5_boolean *);

static krb5_error_code plugin_reg_ret;
static krb5plugin_kuserok_ftable kuserok_simple_plug;
static krb5plugin_kuserok_ftable kuserok_sys_k5login_plug;
static krb5plugin_kuserok_ftable kuserok_user_k5login_plug;

static void
reg_def_plugins_once(void *ctx)
{
    krb5_error_code ret;
    krb5_context context = ctx;

    plugin_reg_ret = krb5_plugin_register(context, PLUGIN_TYPE_DATA,
					  KRB5_PLUGIN_KUSEROK,
					  &kuserok_simple_plug);
    ret = krb5_plugin_register(context, PLUGIN_TYPE_DATA,
                               KRB5_PLUGIN_KUSEROK, &kuserok_sys_k5login_plug);
    if (!plugin_reg_ret)
	plugin_reg_ret = ret;
    ret = krb5_plugin_register(context, PLUGIN_TYPE_DATA,
                               KRB5_PLUGIN_KUSEROK, &kuserok_user_k5login_plug);
    if (!plugin_reg_ret)
	plugin_reg_ret = ret;
}

#ifndef _WIN32

/* see if principal is mentioned in the filename access file, return
   TRUE (in result) if so, FALSE otherwise */

static krb5_error_code
check_one_file(krb5_context context,
	       const char *filename,
	       struct passwd *pwd,
	       krb5_const_principal principal,
	       krb5_boolean *result)
{
    FILE *f;
    char buf[BUFSIZ];
    krb5_error_code ret;
    struct stat st;

    *result = FALSE;

    f = fopen (filename, "r");
    if (f == NULL)
	return errno;
    rk_cloexec_file(f);

    /* check type and mode of file */
    if (fstat(fileno(f), &st) != 0) {
	fclose (f);
	return errno;
    }
    if (S_ISDIR(st.st_mode)) {
	fclose (f);
	return EISDIR;
    }
    if (st.st_uid != pwd->pw_uid && st.st_uid != 0) {
	fclose (f);
	return EACCES;
    }
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
	fclose (f);
	return EACCES;
    }

    while (fgets (buf, sizeof(buf), f) != NULL) {
	krb5_principal tmp;
	char *newline = buf + strcspn(buf, "\n");

	if(*newline != '\n') {
	    int c;
	    c = fgetc(f);
	    if(c != EOF) {
		while(c != EOF && c != '\n')
		    c = fgetc(f);
		/* line was too long, so ignore it */
		continue;
	    }
	}
	*newline = '\0';
	ret = krb5_parse_name (context, buf, &tmp);
	if (ret)
	    continue;
	*result = krb5_principal_compare (context, principal, tmp);
	krb5_free_principal (context, tmp);
	if (*result) {
	    fclose (f);
	    return 0;
	}
    }
    fclose (f);
    return 0;
}

static krb5_error_code
check_directory(krb5_context context,
		const char *dirname,
		struct passwd *pwd,
		krb5_const_principal principal,
		krb5_boolean *result)
{
    DIR *d;
    struct dirent *dent;
    char filename[MAXPATHLEN];
    krb5_error_code ret = 0;
    struct stat st;

    *result = FALSE;

    if(lstat(dirname, &st) < 0)
	return errno;

    if (!S_ISDIR(st.st_mode))
	return ENOTDIR;

    if (st.st_uid != pwd->pw_uid && st.st_uid != 0)
	return EACCES;
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
	return EACCES;

    if((d = opendir(dirname)) == NULL)
	return errno;

    {
	int fd;
	struct stat st2;

	fd = dirfd(d);
	if(fstat(fd, &st2) < 0) {
	    closedir(d);
	    return errno;
	}
	if(st.st_dev != st2.st_dev || st.st_ino != st2.st_ino) {
	    closedir(d);
	    return EACCES;
	}
    }

    while((dent = readdir(d)) != NULL) {
	if(strcmp(dent->d_name, ".") == 0 ||
	   strcmp(dent->d_name, "..") == 0 ||
	   dent->d_name[0] == '#' ||			  /* emacs autosave */
	   dent->d_name[strlen(dent->d_name) - 1] == '~') /* emacs backup */
	    continue;
	snprintf(filename, sizeof(filename), "%s/%s", dirname, dent->d_name);
	ret = check_one_file(context, filename, pwd, principal, result);
	if(ret == 0 && *result == TRUE)
	    break;
	ret = 0; /* don't propagate errors upstream */
    }
    closedir(d);
    return ret;
}

#endif  /* !_WIN32 */

static krb5_boolean
match_local_principals(krb5_context context,
		       krb5_const_principal principal,
		       const char *luser)
{
    krb5_error_code ret;
    krb5_realm *realms, *r;
    krb5_boolean result = FALSE;

    /* multi-component principals can never match */
    if (krb5_principal_get_comp_string(context, principal, 1) != NULL)
	return FALSE;

    ret = krb5_get_default_realms (context, &realms);
    if (ret)
	return FALSE;

    for (r = realms; *r != NULL; ++r) {
	if (strcmp(krb5_principal_get_realm(context, principal),
		  *r) != 0)
	    continue;
	if (strcmp(krb5_principal_get_comp_string(context, principal, 0),
		  luser) == 0) {
	    result = TRUE;
	    break;
	}
    }
    krb5_free_host_realm(context, realms);
    return result;
}

/**
 * This function takes the name of a local user and checks if
 * principal is allowed to log in as that user.
 *
 * The user may have a ~/.k5login file listing principals that are
 * allowed to login as that user. If that file does not exist, all
 * principals with a only one component that is identical to the
 * username, and a realm considered local, are allowed access.
 *
 * The .k5login file must contain one principal per line, be owned by
 * user and not be writable by group or other (but must be readable by
 * anyone).
 *
 * Note that if the file exists, no implicit access rights are given
 * to user@@LOCALREALM.
 *
 * Optionally, a set of files may be put in ~/.k5login.d (a
 * directory), in which case they will all be checked in the same
 * manner as .k5login.  The files may be called anything, but files
 * starting with a hash (#) , or ending with a tilde (~) are
 * ignored. Subdirectories are not traversed. Note that this directory
 * may not be checked by other Kerberos implementations.
 *
 * If no configuration file exists, match user against local domains,
 * ie luser@@LOCAL-REALMS-IN-CONFIGURATION-FILES.
 *
 * @param context Kerberos 5 context.
 * @param principal principal to check if allowed to login
 * @param luser local user id
 *
 * @return returns TRUE if access should be granted, FALSE otherwise.
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_kuserok (krb5_context context,
	      krb5_principal principal,
	      const char *luser)
{
    static heim_base_once_t reg_def_plugins = HEIM_BASE_ONCE_INIT;
    krb5_error_code ret;
    krb5_boolean result = FALSE;
    size_t i;
    char **rules;
    struct plctx ctx;

    heim_base_once_f(&reg_def_plugins, context, reg_def_plugins_once);

    ctx.luser = luser;
    ctx.principal = principal;
    ctx.result = FALSE;

    rules = krb5_config_get_strings(context, NULL, "libdefault",
				    "kuserok", NULL);
    if (rules == NULL) {
	/* Default: check ~/.k5login */
	ret = kuserok_user_k5login_plug_f(NULL, context, "USER_K5LOGIN", luser,
					  principal, &result);
	return result;
    }

    for (i = 0; rules[i]; i++) {
	ctx.rule = rules[i];
	ret = _krb5_plugin_run_f(context, "krb5", KRB5_PLUGIN_KUSEROK,
				 KRB5_PLUGIN_KUSEROK_VERSION_0, 0,
				 &ctx, plcallback);
	if (ret != KRB5_PLUGIN_NO_HANDLE)
	    return ctx.result;
    }
    return FALSE;
}

static krb5_error_code
kuserok_simple_plug_f(void *plug_ctx, krb5_context context, const char *rule,
		      const char *luser, krb5_const_principal principal,
		      krb5_boolean *result)
{
    if (strcmp(rule, "SIMPLE") != 0)
	return KRB5_PLUGIN_NO_HANDLE;
    *result = match_local_principals(context, principal, luser);
    return 0;
}

static krb5_error_code
kuserok_sys_k5login_plug_f(void *plug_ctx, krb5_context context,
			   const char *rule, const char *luser,
			   krb5_const_principal principal, krb5_boolean *result)
{
    char *path = NULL;
    char *profile_dir = NULL;
    krb5_error_code ret;
#if 0
    krb5_boolean found_file = FALSE;
#endif

    *result = FALSE;
    if (strcmp(rule, "SYSTEM-K5LOGIN") != 0 &&
	strncmp(rule, "SYSTEM-K5LOGIN:", strlen("SYSTEM-K5LOGIN:")) != 0)
	return KRB5_PLUGIN_NO_HANDLE;

    profile_dir = strchr(rule, ':');
    if (profile_dir == NULL)
	profile_dir = SYSTEM_K5LOGIN_DIR;

    /* XXX expand tokens */
    ret = _krb5_expand_path_tokens(context, profile_dir, luser, &path);
    if (ret)
	return ret;

    ret = check_one_file(context, path, NULL, principal, result);

    if (ret == 0 && *result == TRUE) {
	free(path);
	return 0;
    }

    return KRB5_PLUGIN_NO_HANDLE;
}
static krb5_error_code
kuserok_user_k5login_plug_f(void *plug_ctx, krb5_context context,
			    const char *rule, const char *luser,
			    krb5_const_principal principal, krb5_boolean *result)
{
#ifdef _WIN32
    return KRB5_PLUGIN_NO_HANDLE;
#else
    char *buf;
    size_t buflen;
    struct passwd *pwd = NULL;
    char *profile_dir = NULL;
    krb5_error_code ret;
    krb5_boolean found_file = FALSE;

    if (strcmp(rule, "USER_K5LOGIN") != 0)
	return KRB5_PLUGIN_NO_HANDLE;

#ifdef POSIX_GETPWNAM_R
    char pwbuf[2048];
    struct passwd pw;

    if(getpwnam_r(luser, &pw, pwbuf, sizeof(pwbuf), &pwd) != 0)
	return FALSE;
#else
    pwd = getpwnam (luser);
#endif
    if (pwd == NULL)
	return FALSE;
    profile_dir = pwd->pw_dir;

#define KLOGIN "/.k5login"
    buflen = strlen(profile_dir) + sizeof(KLOGIN) + 2; /* 2 for .d */
    buf = malloc(buflen);
    if(buf == NULL)
	return FALSE;
    /* check user's ~/.k5login */
    strlcpy(buf, profile_dir, buflen);
    strlcat(buf, KLOGIN, buflen);
    ret = check_one_file(context, buf, pwd, principal, result);

    if(ret == 0 && *result == TRUE) {
	free(buf);
	return TRUE;
    }

    if(ret != ENOENT)
	found_file = TRUE;

    strlcat(buf, ".d", buflen);
    ret = check_directory(context, buf, pwd, principal, result);
    free(buf);
    if(ret == 0 && *result == TRUE)
	return TRUE;

    if(ret != ENOENT && ret != ENOTDIR)
	found_file = TRUE;

    /* finally if no files exist, allow all principals matching
       <localuser>@<LOCALREALM> */
    if(found_file == FALSE)
	return match_local_principals(context, principal, luser);

    return FALSE;
#endif
}

static krb5_error_code
kuser_ok_null_plugin_init(krb5_context context, void **ctx)
{
    *ctx = NULL;
    return 0;
}

static void
kuser_ok_null_plugin_fini(void *ctx)
{
    return;
}

static krb5plugin_kuserok_ftable kuserok_simple_plug = {
    0,
    kuser_ok_null_plugin_init,
    kuser_ok_null_plugin_fini,
    kuserok_simple_plug_f,
};

static krb5plugin_kuserok_ftable kuserok_sys_k5login_plug = {
    0,
    kuser_ok_null_plugin_init,
    kuser_ok_null_plugin_fini,
    kuserok_sys_k5login_plug_f,
};

static krb5plugin_kuserok_ftable kuserok_user_k5login_plug = {
    0,
    kuser_ok_null_plugin_init,
    kuser_ok_null_plugin_fini,
    kuserok_user_k5login_plug_f,
};

