/*
 * Copyright (c) 2006 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Copyright (c) 2013 Cryptonector LLC
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
 * 3. Neither the name of KTH nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY KTH AND ITS CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL KTH OR ITS CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <roken.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <gssapi.h>
#include <gssapi_krb5.h>
#include <gssapi_spnego.h>
#include <err.h>
#include <getarg.h>

static void
gss_print_errors(OM_uint32 status, gss_OID mech)
{
    OM_uint32 maj_stat, min_stat;
    OM_uint32 msg_ctx = 0;
    gss_buffer_desc status_string;
    int status_type = mech != GSS_C_NO_OID ? GSS_C_MECH_CODE : GSS_C_GSS_CODE;

    if (status_type == GSS_C_MECH_CODE && status == 0) {
        fprintf(stderr, "\tMinor status: <unknown>\n");
        return;
    }

    fprintf(stderr, "\t%s status: ",
            status_type == GSS_C_GSS_CODE ? "Major" : "Minor");
    do {
        maj_stat = gss_display_status(&min_stat, status, status_type,
                                      GSS_C_NO_OID, &msg_ctx, &status_string);
	if (!GSS_ERROR(maj_stat)) {
            fprintf(stderr, "%.*s%s\n", (int)status_string.length,
                    (char *)status_string.value, msg_ctx ? "; " : "");
	    gss_release_buffer(&min_stat, &status_string);
	}
    } while (!GSS_ERROR(maj_stat) && msg_ctx != 0);
}

static void
gss_err(OM_uint32 major, OM_uint32 minor, gss_OID mech, const char *fmt, ...)
{
    va_list args;

    if (major == GSS_S_COMPLETE)
        return;

    va_start(args, fmt);
    vwarnx(fmt, args);
    gss_print_errors(major, GSS_C_NO_OID);
    gss_print_errors(minor, mech);
    va_end(args);
    exit(1);
}

static int version_flag = 0;
static int help_flag	= 0;

static struct getargs args[] = {
    {"version",	0,	arg_flag,	&version_flag, "print version", NULL },
    {"help",	0,	arg_flag,	&help_flag,  NULL, NULL }
};

static void
usage(int status)
{
    arg_printusage(args, sizeof(args)/sizeof(*args), NULL,
                   "name-type name-string mech attribute-name\n\n"
                   "\tValid name-types:\n"
                   "\t\thostbased, domainbased (not yet), user, krb5, any\n"
                   "\tValid mechs: krb5\n");
    exit(status);
}


int
main(int argc, char **argv)
{
    gss_buffer_desc name_buf, attr, display_value;
    gss_OID name_type, mech;
    OM_uint32 maj_stat, min_stat;
    gss_name_t name, MN;
    int optidx = 0;
    int more = -1;
    int authenticated, complete;
    size_t value_count = 0;

    setprogname(argv[0]);
    if (getarg(args, sizeof(args) / sizeof(args[0]), argc, argv, &optidx))
	usage(1);

    argc -= optidx;
    argv += optidx;

    if (help_flag || argc == 0)
	usage(0);
    if (argc != 4)
	usage(1);

    if (version_flag){
	print_version(NULL);
	exit(0);
    }


    if (!strcmp(argv[0], "userbased"))
        name_type = GSS_C_NT_USER_NAME;
    else if (!strcmp(argv[0], "hostbased"))
        name_type = GSS_C_NT_HOSTBASED_SERVICE;
    else if (!strcmp(argv[0], "domainbased"))
	errx(1, "Domain-based service names not yet supported");
    else if (!strcmp(argv[0], "krb5"))
        name_type = GSS_KRB5_NT_PRINCIPAL_NAME;
    else if (!strcmp(argv[0], "any"))
        name_type = GSS_C_NO_OID;
    else
        usage(1);

    if (strcmp(argv[2], "krb5"))
        usage(1);
    mech = GSS_KRB5_MECHANISM;

    name_buf.value = argv[1];
    name_buf.length = strlen(argv[1]);

    maj_stat = gss_import_name(&min_stat, &name_buf, name_type, &name);
    gss_err(maj_stat, min_stat, GSS_C_NO_OID, "Failed to import name");

    maj_stat = gss_canonicalize_name(&min_stat, name, mech, &MN);
    gss_err(maj_stat, min_stat, mech, "Failed to canonicalize name");

    attr.value = argv[3];
    attr.length = strlen(argv[3]);

    do {
        maj_stat = gss_get_name_attribute(&min_stat, MN, &attr,
                                          &authenticated, &complete,
                                          NULL, &display_value, &more);
        gss_err(maj_stat, min_stat, mech, "Failed to get name attribute");
        printf("Display value #%d (%sauthenticated, %scomplete): %.*s\n",
               value_count, authenticated ? "" : "not ", complete ? "" : "not ",
               (int)display_value.length, (char *)display_value.value);
        gss_release_buffer(&min_stat, &display_value);
        value_count++;
    } while (more != 0);

    gss_release_name(&min_stat, &name);

    return 0;
}
