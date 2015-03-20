/*-
 * Copyright (c) 2015
 *	Cryptonector LLC.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Cryptonector LLC may not be used to endorse or promote products
 *    derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <config.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include "roken.h"


static int pipefds[2] = {-1, -1};

ROKEN_LIB_FUNCTION void ROKEN_LIB_CALL
roken_detach_prep(void)
{
    pid_t child;
    char buf[1];
    ssize_t bytes;

    pipefds[0] = -1;
    pipefds[1] = -1;
    if (pipe(pipefds) == -1)
        err(1, "failed to setup to detach daemon");

    child = fork();
    if (child == -1)
        err(1, "failed to setup to fork daemon");

    if (child == 0) {
        int fd;

        (void) close(pipefds[0]);
        pipefds[0] = -1;
        /*
         * Keep stdout/stderr for now so output and errors prior to
         * detach_finish() can be seen by the user.
         */
        fd = open(_PATH_DEVNULL, O_RDWR, 0);
        if (fd == -1)
            err(1, "failed to open /dev/null");
        (void) dup2(fd, STDIN_FILENO);
        if (fd > STDERR_FILENO)
            (void) close(fd);
        return;
    }

    (void) close(pipefds[1]);
    pipefds[1] = -1;
    do {
        bytes = read(pipefds[0], buf, sizeof(buf));
    } while (bytes == -1 && errno == EINTR);
    if (bytes == -1) {
        (void) kill(child, SIGQUIT);
        err(1, "failed to setup daemon child");
    }
    if (bytes == 0)
        errx(1, "daemon child preparation failed");
    _exit(0);
}

ROKEN_LIB_FUNCTION void ROKEN_LIB_CALL
roken_detach_finish(void)
{
    char buf[1];
    ssize_t bytes;
    int fd;

    if (pipefds[1] == -1)
        return;

    if (setsid() == -1)
        err(1, "failed to detach from tty");

    /*
     * Hopefully we've written any pidfiles by now, if they had to be in
     * the current directory...
     */
    if (chdir("/"))
        err(1, "failed to chdir to /");

    buf[1] = 0;
    do {
        bytes = write(pipefds[1], buf, sizeof(buf));
    } while (bytes == -1 && errno == EINTR);
    (void) close(pipefds[1]);
    if (bytes == -1)
        err(1, "failed to signal parent while detaching");
    if (bytes != sizeof(buf))
        errx(1, "failed to signal parent while detaching");

    fd = open(_PATH_DEVNULL, O_RDWR, 0);
    if (fd == -1)
        err(1, "failed to open /dev/null");
    /*
     * Maybe we should check that our output got written, if redirected
     * to a file.  File utils normally do this.
     */
    (void) dup2(fd, STDOUT_FILENO);
    (void) dup2(fd, STDERR_FILENO);
    if (fd > 2)
        (void) close(fd);
}
