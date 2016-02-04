/*
 * Copyright (c) 1997 - 2007 Kungliga Tekniska Högskolan
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

#include "iprop.h"

#if defined(HAVE_FORK) && defined(HAVE_WAITPID)
#include <sys/types.h>
#include <sys/wait.h>
#endif

sig_atomic_t exit_flag;

static RETSIGTYPE
sigterm(int sig)
{
    exit_flag = sig;
}

void
setup_signal(void)
{
#ifdef HAVE_SIGACTION
    {
	struct sigaction sa;

	sa.sa_flags = 0;
	sa.sa_handler = sigterm;
	sigemptyset(&sa.sa_mask);

#ifdef SA_RESTART
        sa.sa_flags |= SA_RESTART;
#endif

	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGXCPU, &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);
    }
#else
    signal(SIGINT, sigterm);
    signal(SIGTERM, sigterm);
#ifndef NO_SIGXCPU
    signal(SIGXCPU, sigterm);
#endif
#ifndef NO_SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif
#endif
}

/*
 * Fork a child to run the service, and restart it if it dies.
 *
 * Returns -1 if not supported, else a file descriptor that the service
 * should select() for.  Any events on that file descriptor should cause
 * the service to exit immediately, as that means that the restarter
 * exited.
 *
 * The service's normal exit status values should be should be taken
 * from enum ipropd_exit_code.  IPROPD_FATAL causes the restarter to
 * stop restarting the service and to exit.
 *
 * This requires fork() and waitpid() (otherwise returns -1).  Ignoring
 * SIGCHLD, of course, would be bad.
 *
 * We could support this on Windows by spawning a child with mostly the
 * same arguments as the restarter process.
 */
int
restarter(krb5_context context)
{
#if defined(HAVE_FORK) && defined(HAVE_WAITPID)
    pid_t pid;
    pid_t wpid = -1;
    int status;
    int sig = SIGTERM;
    int fds[2];

    if (pipe(fds) == -1)
        return -1;

    while (!exit_flag) {
        fflush(stdout);
        fflush(stderr);

        pid = fork();
        if (pid == -1)
            krb5_err(context, 1, errno, "Could not fork in service restarter");
        if (pid == 0) {
            (void) close(fds[1]);
            return fds[0];
        }

        do {
            wpid = waitpid(pid, &status, 0);
        } while (wpid == -1 && errno == EINTR);
        if (wpid == -1)
            krb5_err(context, 1, errno, "restarter failed waiting for child");

        if (WIFEXITED(status)) {
            switch ((enum ipropd_exit_code) WEXITSTATUS(status)) {
            case IPROPD_DONE:
                exit(0);
            case IPROPD_RESTART_SLOW:
                krb5_warn(context, WEXITSTATUS(status),
                          "Waiting 2 minutes to restart");
                sleep(120);
                continue;
            case IPROPD_FATAL:
                krb5_err(context, WEXITSTATUS(status), WEXITSTATUS(status),
                         "Sockets and pipes not supported for "
                         "iprop log files");
            case IPROPD_RESTART:
            default:
                /* Add exponential backoff (with max backoff)? */
                krb5_warn(context, WEXITSTATUS(status),
                          "Waiting 30 seconds to restart");
                sleep(30);
                continue;
            }
        }
    }

    if (pid == -1) {
        /*
         * Shouldn't happen, but still, there's no point trying to
         * kill(-1, ...)!  That would be very bad indeed!
         */
        exit(0);
    }

    sig = exit_flag;
    krb5_warnx(context, "killing child (pid %ld) with %d", (long)pid, sig);
    kill(pid, sig);
    if (wpid != pid) {
        wpid = waitpid(pid, &status, WNOHANG);
        if (wpid == -1 && errno == ECHILD)
            krb5_err(context, 1, errno, "restarter failed waiting for child");
    }
    while (wpid != pid) {
        krb5_warnx(context, "killing child (pid %ld) with %d", (long)pid, sig);
        kill(pid, sig);
        sleep(1);
        sig = SIGKILL;
        wpid = waitpid(pid, &status, 0);
        if (wpid == -1 && errno == ECHILD)
            krb5_err(context, 1, errno, "restarter failed waiting for child");
        if (wpid == -1 && errno != EINTR)
            krb5_err(context, 1, errno, "restarter failed waiting for child");
    }
    if (WIFEXITED(status))
        exit(WEXITSTATUS(status));
    if (WIFSIGNALED(status)) {
        switch (WTERMSIG(status)) {
        case SIGTERM:
        case SIGXCPU:
        case SIGINT:
            exit(0);
        default:
            kill(getpid(), WTERMSIG(status));
        }
    }
    exit(1);
#else
    return -1;
#endif
}

