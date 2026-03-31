/*
 * Copyright (c) 2026 Kungliga Tekniska Högskolan
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

/*
 * TPM transport abstraction.
 *
 * URI format: "type:arg"
 *   "device:/dev/tpmrm0"
 *   "socket:/path/to/unix/socket"
 *   "tcp:host:port"
 *   "pipe:command arg1 arg2 ..."
 */

#include "htpm2_locl.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

/*
 * Internal transport structure.
 */
struct htpm2_transport_data {
    const htpm2_transport_ops *ops;
    int fd;
    int fd_write;       /* write fd for pipe (-1 if same as fd) */
    pid_t child_pid;    /* child process for pipe (0 if none) */
};

/* Forward declarations for shared helpers */
static int  common_get_read_fd(htpm2_transport tp);
static int  common_get_write_fd(htpm2_transport tp);
static void common_close(htpm2_transport *tp);

static htpm2_result read_exact(int fd, void *buf, size_t len);
static htpm2_result write_exact(int fd, const void *buf, size_t len);

/*
 * Send a TPM command and read the response.
 *
 * The TPM command/response framing is self-describing: bytes [2..5] of
 * the command header contain the total command size as a big-endian
 * uint32, and likewise for the response.  So we:
 *  1. Write the full command
 *  2. Read the 10-byte response header
 *  3. Extract response size from bytes [2..5]
 *  4. Read the remaining bytes
 *
 * This works for /dev/tpmrm0, Unix sockets (swtpm), and TCP.
 */
static htpm2_result
tpm_send_recv(htpm2_transport tp,
              const void *cmd, size_t cmd_len,
              void *rsp, size_t *rsp_len)
{
    htpm2_result r;
    uint32_t rsp_size;
    int wfd, rfd;

    wfd = (tp->fd_write >= 0) ? tp->fd_write : tp->fd;
    rfd = tp->fd;

    r = write_exact(wfd, cmd, cmd_len);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "transport send");

    if (*rsp_len < 10)
        return htpm2_result_local(ENOBUFS, HTPM2_F_TRANSPORT | HTPM2_F_LOCAL,
                                  ENOBUFS, "transport: response buffer < 10");

    r = read_exact(rfd, rsp, 10);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "transport recv header");

    /* Extract response size from bytes [2..5] */
    rsp_size = ((uint32_t)((unsigned char *)rsp)[2] << 24) |
               ((uint32_t)((unsigned char *)rsp)[3] << 16) |
               ((uint32_t)((unsigned char *)rsp)[4] << 8) |
               ((uint32_t)((unsigned char *)rsp)[5]);

    if (rsp_size < 10 || rsp_size > *rsp_len)
        return htpm2_result_local(EIO, HTPM2_F_TRANSPORT | HTPM2_F_LOCAL,
                                  EIO, "transport: bad response size %u",
                                  rsp_size);

    if (rsp_size > 10) {
        r = read_exact(rfd, (unsigned char *)rsp + 10, rsp_size - 10);
        if (htpm2_is_err(r))
            return htpm2_result_prepend(r, "transport recv body");
    }

    *rsp_len = rsp_size;
    return HTPM2_OK;
}

/* --- Device transport (/dev/tpm0, /dev/tpmrm0) --- */

static htpm2_result device_open(const htpm2_context, const char *,
                                htpm2_transport *);
static htpm2_result device_send_recv(htpm2_transport , const void *, size_t,
                                     void *, size_t *);

static const htpm2_transport_ops device_ops = {
    "device",
    device_open,
    device_send_recv,
    common_get_read_fd,
    common_get_write_fd,
    common_close
};


static htpm2_result
device_open(const htpm2_context ctx, const char *arg, htpm2_transport *tp)
{
    struct htpm2_transport_data *t;
    int fd;

    (void)ctx;

    fd = open(arg, O_RDWR);
    if (fd < 0)
        return htpm2_result_local(errno, HTPM2_F_TRANSPORT | HTPM2_F_LOCAL,
                                  errno, "device: open(%s): %s",
                                  arg, strerror(errno));

    t = calloc(1, sizeof(*t));
    if (t == NULL) {
        close(fd);
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "device: out of memory");
    }
    t->fd = fd;
    t->fd_write = -1;
    t->ops = &device_ops;
    *tp = t;
    return HTPM2_OK;
}

/*
 * For /dev/tpm0 the kernel driver handles framing: you write the full
 * command in one write() and read the full response in one read().
 */
static htpm2_result
device_send_recv(htpm2_transport tp,
                 const void *cmd, size_t cmd_len,
                 void *rsp, size_t *rsp_len)
{
    ssize_t n;

    n = write(tp->fd, cmd, cmd_len);
    if (n < 0 || (size_t)n != cmd_len)
        return htpm2_result_local(errno, HTPM2_F_TRANSPORT | HTPM2_F_LOCAL,
                                  errno, "device: write: %s",
                                  strerror(errno));

    n = read(tp->fd, rsp, *rsp_len);
    if (n < 0)
        return htpm2_result_local(errno, HTPM2_F_TRANSPORT | HTPM2_F_LOCAL,
                                  errno, "device: read: %s",
                                  strerror(errno));
    if (n < 10)
        return htpm2_result_local(EIO, HTPM2_F_TRANSPORT | HTPM2_F_LOCAL,
                                  EIO, "device: short response (%zd)", n);
    *rsp_len = n;
    return HTPM2_OK;
}

/* --- Socket transport (AF_LOCAL / TCP) --- */

static htpm2_result socket_open(const htpm2_context, const char *,
                                htpm2_transport *);

static const htpm2_transport_ops socket_ops = {
    "socket",
    socket_open,
    tpm_send_recv,
    common_get_read_fd,
    common_get_write_fd,
    common_close
};

static const htpm2_transport_ops tcp_ops = {
    "tcp",
    socket_open,
    tpm_send_recv,
    common_get_read_fd,
    common_get_write_fd,
    common_close
};

static htpm2_result
socket_open(const htpm2_context ctx, const char *arg, htpm2_transport *tp)
{
    struct htpm2_transport_data *t;
    int fd = -1;

    (void)ctx;

    if (arg[0] == '/') {
        /* Unix domain socket */
        struct sockaddr_un sun;

        if (strlen(arg) >= sizeof(sun.sun_path))
            return htpm2_result_local(ENAMETOOLONG,
                                      HTPM2_F_TRANSPORT | HTPM2_F_LOCAL,
                                      ENAMETOOLONG,
                                      "socket: path too long: %s", arg);

        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
            return htpm2_result_local(errno,
                                      HTPM2_F_TRANSPORT | HTPM2_F_LOCAL,
                                      errno, "socket(): %s",
                                      strerror(errno));

        memset(&sun, 0, sizeof(sun));
        sun.sun_family = AF_UNIX;
        snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", arg);

        if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
            int e = errno;
            close(fd);
            return htpm2_result_local(e, HTPM2_F_TRANSPORT | HTPM2_F_LOCAL, e,
                                      "socket: connect(%s): %s",
                                      arg, strerror(e));
        }
    } else {
        /* TCP: "host:port" */
        char *host, *colon;
        const char *port;
        struct addrinfo hints, *res, *rp;
        int ret;

        host = strdup(arg);
        if (host == NULL)
            return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                      "tcp: out of memory");

        colon = strrchr(host, ':');
        if (colon == NULL) {
            free(host);
            return htpm2_result_local(EINVAL,
                                      HTPM2_F_TRANSPORT | HTPM2_F_LOCAL,
                                      EINVAL,
                                      "tcp: no port in '%s'", arg);
        }
        *colon = '\0';
        port = colon + 1;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        ret = getaddrinfo(host, port, &hints, &res);
        if (ret != 0) {
            free(host);
            return htpm2_result_local(ENOENT,
                                      HTPM2_F_TRANSPORT | HTPM2_F_LOCAL,
                                      ENOENT, "tcp: resolve(%s): %s",
                                      arg, gai_strerror(ret));
        }

        for (rp = res; rp; rp = rp->ai_next) {
            fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd < 0)
                continue;
            if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
                break;
            close(fd);
            fd = -1;
        }
        freeaddrinfo(res);
        free(host);

        if (fd < 0)
            return htpm2_result_local(errno,
                                      HTPM2_F_TRANSPORT | HTPM2_F_LOCAL,
                                      errno, "tcp: connect(%s) failed", arg);
    }

    t = calloc(1, sizeof(*t));
    if (t == NULL) {
        close(fd);
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "socket: out of memory");
    }
    t->fd = fd;
    t->fd_write = -1;
    t->ops = &socket_ops;
    *tp = t;
    return HTPM2_OK;
}

/* --- Pipe transport --- */

static htpm2_result pipe_open(const htpm2_context, const char *, htpm2_transport *);
static void pipe_close(htpm2_transport *);

static const htpm2_transport_ops pipe_ops = {
    "pipe",
    pipe_open,
    tpm_send_recv,
    common_get_read_fd,
    common_get_write_fd,
    pipe_close
};

static htpm2_result
pipe_open(const htpm2_context ctx, const char *arg, htpm2_transport *tp)
{
    struct htpm2_transport_data *t;
    int to_child[2] = {-1, -1};
    int from_child[2] = {-1, -1};
    pid_t pid;

    (void)ctx;

    if (pipe(to_child) < 0 || pipe(from_child) < 0) {
        int e = errno;
        if (to_child[0] >= 0) { close(to_child[0]); close(to_child[1]); }
        if (from_child[0] >= 0) { close(from_child[0]); close(from_child[1]); }
        return htpm2_result_local(e, HTPM2_F_TRANSPORT | HTPM2_F_LOCAL, e,
                                  "pipe: pipe(): %s", strerror(e));
    }

    pid = fork();
    if (pid < 0) {
        int e = errno;
        close(to_child[0]); close(to_child[1]);
        close(from_child[0]); close(from_child[1]);
        return htpm2_result_local(e, HTPM2_F_TRANSPORT | HTPM2_F_LOCAL, e,
                                  "pipe: fork(): %s", strerror(e));
    }

    if (pid == 0) {
        /* Child */
        close(to_child[1]);
        close(from_child[0]);
        dup2(to_child[0], STDIN_FILENO);
        dup2(from_child[1], STDOUT_FILENO);
        close(to_child[0]);
        close(from_child[1]);
        execl("/bin/sh", "sh", "-c", arg, (char *)NULL);
        _exit(127);
    }

    /* Parent */
    close(to_child[0]);
    close(from_child[1]);

    t = calloc(1, sizeof(*t));
    if (t == NULL) {
        close(to_child[1]);
        close(from_child[0]);
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "pipe: out of memory");
    }
    t->fd = from_child[0];       /* read from child's stdout */
    t->fd_write = to_child[1];   /* write to child's stdin */
    t->child_pid = pid;
    t->ops = &pipe_ops;
    *tp = t;
    return HTPM2_OK;
}

static void
pipe_close(htpm2_transport *tp)
{
    if (tp == NULL || *tp == NULL)
        return;
    if ((*tp)->fd_write >= 0)
        close((*tp)->fd_write);
    if ((*tp)->fd >= 0)
        close((*tp)->fd);
    if ((*tp)->child_pid > 0) {
        int status;
        waitpid((*tp)->child_pid, &status, 0);
    }
    free(*tp);
    *tp = NULL;
}

/* --- Common helpers --- */

static int
common_get_read_fd(htpm2_transport tp)
{
    return tp ? tp->fd : -1;
}

static int
common_get_write_fd(htpm2_transport tp)
{
    if (tp == NULL)
        return -1;
    return (tp->fd_write >= 0) ? tp->fd_write : tp->fd;
}

static void
common_close(htpm2_transport *tp)
{
    if (tp == NULL || *tp == NULL)
        return;
    if ((*tp)->fd >= 0)
        close((*tp)->fd);
    free(*tp);
    *tp = NULL;
}

static htpm2_result
read_exact(int fd, void *buf, size_t len)
{
    size_t done = 0;

    while (done < len) {
        ssize_t n = read(fd, (unsigned char *)buf + done, len - done);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return htpm2_result_local(errno,
                                      HTPM2_F_TRANSPORT | HTPM2_F_LOCAL,
                                      errno, "read: %s", strerror(errno));
        }
        if (n == 0)
            return htpm2_result_local(EIO, HTPM2_F_TRANSPORT | HTPM2_F_LOCAL,
                                      EIO, "read: unexpected EOF");
        done += n;
    }
    return HTPM2_OK;
}

static htpm2_result
write_exact(int fd, const void *buf, size_t len)
{
    size_t done = 0;

    while (done < len) {
        ssize_t n = write(fd, (const unsigned char *)buf + done, len - done);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return htpm2_result_local(errno,
                                      HTPM2_F_TRANSPORT | HTPM2_F_LOCAL,
                                      errno, "write: %s", strerror(errno));
        }
        done += n;
    }
    return HTPM2_OK;
}

/* --- Transport dispatch --- */

static const htpm2_transport_ops *builtin_ops[] = {
    &device_ops,
    &socket_ops,
    &tcp_ops,
    &pipe_ops,
    NULL
};

htpm2_result
htpm2_transport_open(const htpm2_context ctx,
                     htpm2_result prior,
                     const char *uri,
                     htpm2_transport *tp)
{
    const char *colon;
    size_t type_len;
    const htpm2_transport_ops **opsp;

    if (prior.code)
        return prior;

    *tp = NULL;

    if (uri == NULL)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "transport_open: NULL URI");

    colon = strchr(uri, ':');
    if (colon == NULL)
        return htpm2_result_local(EINVAL, HTPM2_F_TRANSPORT | HTPM2_F_LOCAL,
                                  EINVAL,
                                  "transport_open: no ':' in URI '%s'", uri);

    type_len = colon - uri;

    for (opsp = builtin_ops; *opsp != NULL; opsp++) {
        if (strlen((*opsp)->name) == type_len &&
            strncmp((*opsp)->name, uri, type_len) == 0)
            return (*opsp)->open(ctx, colon + 1, tp);
    }

    return htpm2_result_local(ENOENT, HTPM2_F_TRANSPORT | HTPM2_F_LOCAL,
                              ENOENT,
                              "transport_open: unknown type '%.*s'",
                              (int)type_len, uri);
}

void
htpm2_transport_close(htpm2_transport *tp)
{
    if (tp == NULL || *tp == NULL)
        return;
    /* Use pipe_close for pipe transports (handles child_pid), common_close otherwise */
    if ((*tp)->child_pid > 0)
        pipe_close(tp);
    else
        common_close(tp);
}

int
htpm2_transport_get_read_fd(htpm2_transport tp)
{
    return common_get_read_fd(tp);
}

int
htpm2_transport_get_write_fd(htpm2_transport tp)
{
    return common_get_write_fd(tp);
}

/*
 * Internal function for command layer to call transport send/recv.
 * Dispatches to the appropriate transport's send_recv based on how it
 * was opened.
 */
htpm2_result
htpm2_transport_send_recv(htpm2_transport tp,
                          const void *cmd, size_t cmd_len,
                          void *rsp, size_t *rsp_len)
{
    return tp->ops->send_recv(tp, cmd, cmd_len, rsp, rsp_len);
}

htpm2_result
htpm2_transport_register(htpm2_context ctx, const htpm2_transport_ops *ops)
{
    (void)ctx;
    (void)ops;
    return htpm2_result_local(ENOSYS, HTPM2_F_LOCAL, ENOSYS,
                              "transport_register: not yet implemented");
}
