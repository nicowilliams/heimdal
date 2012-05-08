/*
 * Copyright (c) 1997-2005 Kungliga Tekniska Högskolan
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

#include "kdc_locl.h"
#ifdef HAVE_UTIL_H
#include <util.h>
#endif

#ifdef HAVE_CAPNG
#include <cap-ng.h>
#endif

sig_atomic_t exit_flag = 0;

#ifdef SUPPORT_DETACH
int detach_from_console = -1;
int print_child_pid = -1;
#endif

static RETSIGTYPE
sigterm(int sig)
{
    exit_flag = sig;
}

/*
 * Allow dropping root bit, since heimdal reopens the database all the
 * time the database needs to be owned by the user you are switched
 * too. A better solution is to split the kdc in to more processes and
 * run the network facing part with very low privilege.
 */

static void
switch_environment(void)
{
#ifdef HAVE_GETEUID
    if ((runas_string || chroot_string) && geteuid() != 0)
	errx(1, "no running as root, can't switch user/chroot");

    if (chroot_string) {
	if (chroot(chroot_string))
	    err(1, "chroot(%s) failed", chroot_string);
	if (chdir("/"))
	    err(1, "chdir(/) after chroot failed");
    }

    if (runas_string) {
	struct passwd *pw;

	pw = getpwnam(runas_string);
	if (pw == NULL)
	    errx(1, "unknown user %s", runas_string);

	if (initgroups(pw->pw_name, pw->pw_gid) < 0)
	    err(1, "initgroups failed");

#ifndef HAVE_CAPNG
	if (setgid(pw->pw_gid) < 0)
	    err(1, "setgid(%s) failed", runas_string);

	if (setuid(pw->pw_uid) < 0)
	    err(1, "setuid(%s)", runas_string);
#else
	capng_clear (CAPNG_EFFECTIVE | CAPNG_PERMITTED);
	if (capng_updatev (CAPNG_ADD, CAPNG_EFFECTIVE | CAPNG_PERMITTED,
	                   CAP_NET_BIND_SERVICE, CAP_SETPCAP, -1) < 0)
	    err(1, "capng_updateev");

	if (capng_change_id(pw->pw_uid, pw->pw_gid,
	                    CAPNG_CLEAR_BOUNDING) < 0)
	    err(1, "capng_change_id(%s)", runas_string);
#endif
    }
#endif
}

#ifdef SUPPORT_DETACH
static int
my_daemon(pid_t *child, int *pipe_fd)
{
    int fd, pipes[2];
    int ret;

    *pipe_fd = -1;
    *child = -1;
    if (pipe(pipes))
        return errno;
    *pipe_fd = pipes[0];

    *child = fork();
    if (*child == -1) {
        ret = errno;
        close(*pipe_fd);
        *pipe_fd = -1;
        return ret;
    }

    if (*child) {
        char byte;
        ssize_t sz;

        /* Parent; wait for child to be ready */
        close(pipes[1]);
        sz = net_read(pipes[0], &byte, sizeof (byte));
        if (sz == sizeof (byte))
            return byte;
        return -1;
    }

    /* Child */
    if (setsid() == -1)
        errx(1, "setsid() failed: %d", errno);
    chdir("/");
    fd = open(_PATH_DEVNULL, O_RDWR, 0);
    if (fd == -1)
        errx(1, "open(/dev/null) failed: %d", errno);
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    close(pipes[0]);
    *pipe_fd = pipes[1];
    return 0;
}
#endif


int
main(int argc, char **argv)
{
    krb5_error_code ret;
    krb5_context context;
    krb5_kdc_configuration *config;
    int optidx = 0;
    struct descr *d;
    unsigned int ndescr;
#ifdef SUPPORT_DETACH
    int pipe_fd = -1;
    char byte = 0;
#endif

    setprogname(argv[0]);

    ret = krb5_init_context(&context);
    if (ret == KRB5_CONFIG_BADFORMAT)
	errx (1, "krb5_init_context failed to parse configuration file");
    else if (ret)
	errx (1, "krb5_init_context failed: %d", ret);

    ret = krb5_kt_register(context, &hdb_kt_ops);
    if (ret)
	errx (1, "krb5_kt_register(HDB) failed: %d", ret);

    config = configure(context, argc, argv, &optidx);

#ifdef HAVE_SIGACTION
    {
	struct sigaction sa;

	sa.sa_flags = 0;
	sa.sa_handler = sigterm;
	sigemptyset(&sa.sa_mask);

	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
#ifdef SIGXCPU
	sigaction(SIGXCPU, &sa, NULL);
#endif

	sa.sa_handler = SIG_IGN;
#ifdef SIGPIPE
	sigaction(SIGPIPE, &sa, NULL);
#endif
    }
#else
    signal(SIGINT, sigterm);
    signal(SIGTERM, sigterm);
#ifdef SIGXCPU
    signal(SIGXCPU, sigterm);
#endif
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif
#endif
    
#ifdef SUPPORT_DETACH
    if (detach_from_console) {
        pid_t child;

        ret = my_daemon(&child, &pipe_fd);
        if (ret && child != 0)
            errx(1, "child setup failed: %d", ret);
        if (!ret && child > 0 && print_child_pid)
            printf("%d\n", child);
        if (child != 0)
            return ret;
    }
#endif

#ifdef __APPLE__
    bonjour_announce(context, config);
#endif
    pidfile(NULL);

    switch_environment();

    ndescr = init_sockets(context, config, &d);
    if(ndescr <= 0)
	krb5_errx(context, 1, "No sockets!");

#ifdef SUPPORT_DETACH
    /* Indicate readiness */
    net_write(pipe_fd, &byte, sizeof (byte));
#endif /* SUPPORT_DETACH */

    loop(context, config, d, ndescr);
    krb5_free_context(context);
    return 0;
}
