/*
 * Copyright (c) 1995, 1996, 1997 Kungliga Tekniska Högskolan
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

#include <config.h>

#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

#include "roken.h"

/* Undo the flock -> rk_flock redirection for this file */
#undef flock

/*
 * Implement flock() semantics with the best available locking mechanism.
 *
 * We prefer OFD (Open File Description) locks when available because they:
 * - Are associated with the file description, not the process
 * - Work correctly with threads (each open() gets its own lock)
 * - Are inherited across fork() with the file descriptor
 * - Don't have the POSIX lock problem where close() on ANY fd to the
 *   same file releases all locks
 *
 * Fallback order:
 * 1. OFD locks (F_OFD_SETLK/F_OFD_SETLKW) - Linux 3.15+, FreeBSD 13+
 * 2. BSD flock() - works on most local filesystems
 * 3. POSIX fcntl() locks - most portable, but has issues
 *
 * We also handle EINVAL/ENOLCK from flock() by falling back to fcntl(),
 * which helps on filesystems that don't support flock() (e.g., some NFS).
 */

#ifndef LOCK_SH
#define LOCK_SH   1		/* Shared lock */
#endif
#ifndef	LOCK_EX
#define LOCK_EX   2		/* Exclusive lock */
#endif
#ifndef LOCK_NB
#define LOCK_NB   4		/* Don't block when locking */
#endif
#ifndef LOCK_UN
#define LOCK_UN   8		/* Unlock */
#endif

#define OP_MASK (LOCK_SH | LOCK_EX | LOCK_UN)

#if defined(HAVE_FCNTL) && defined(F_SETLK)
static int
flock_fcntl(int fd, int operation, int ofd)
{
    struct flock l;
    int cmd;

    l.l_whence = SEEK_SET;
    l.l_start = 0;
    l.l_len = 0;		/* 0 means to EOF */

    switch (operation & OP_MASK) {
    case LOCK_UN:
	l.l_type = F_UNLCK;
#ifdef F_OFD_SETLK
	cmd = ofd ? F_OFD_SETLK : F_SETLK;
#else
	cmd = F_SETLK;
#endif
	break;
    case LOCK_SH:
	l.l_type = F_RDLCK;
#ifdef F_OFD_SETLK
	if (ofd)
	    cmd = (operation & LOCK_NB) ? F_OFD_SETLK : F_OFD_SETLKW;
	else
#endif
	    cmd = (operation & LOCK_NB) ? F_SETLK : F_SETLKW;
	break;
    case LOCK_EX:
	l.l_type = F_WRLCK;
#ifdef F_OFD_SETLK
	if (ofd)
	    cmd = (operation & LOCK_NB) ? F_OFD_SETLK : F_OFD_SETLKW;
	else
#endif
	    cmd = (operation & LOCK_NB) ? F_SETLK : F_SETLKW;
	break;
    default:
	errno = EINVAL;
	return -1;
    }
    return fcntl(fd, cmd, &l);
}
#endif /* HAVE_FCNTL && F_SETLK */

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_flock(int fd, int operation)
{
    int ret;

#if defined(HAVE_FCNTL) && defined(F_OFD_SETLK)
    /*
     * Try OFD locks first -- the sane variant of POSIX byte range file
     * locking, and it should work on NFS (it's the client that implements sane
     * or insane POSIX semantics, not the server, and the protocol is the same
     * either way).
     *
     * Note that even if F_OFD_SETLK is defined in headers, the kernel might
     * not support it (e.g., old kernel with new userspace), so we have a
     * run-time fallback for OFD locks.
     */
    ret = flock_fcntl(fd, operation, 1);
    if (ret == 0)
	return 0;
    if (errno != EINVAL)
	return ret;
#endif

#ifdef HAVE_FLOCK
    {
	int op;

	switch (operation & OP_MASK) {
	case LOCK_UN:
	    op = LOCK_UN;
	    break;
	case LOCK_SH:
	    op = LOCK_SH;
	    break;
	case LOCK_EX:
	    op = LOCK_EX;
	    break;
	default:
	    errno = EINVAL;
	    return -1;
	}
	if (operation & LOCK_NB)
	    op |= LOCK_NB;

	/*
	 * Note: we call the real flock() here, not rk_flock() recursively.
	 * The roken.h header renames flock to rk_flock, but that only
	 * affects code that includes roken.h.  Since we're implementing
	 * rk_flock, we get the real system flock().
	 */
	ret = flock(fd, op);
	if (ret == 0)
	    return 0;
	/*
	 * Some filesystems (e.g., NFS) don't support flock().
	 * Fall back to POSIX locks.
	 */
	if (errno != EINVAL && errno != ENOLCK && errno != ENOTSUP)
	    return ret;
    }
#endif /* HAVE_FLOCK */

#if defined(HAVE_FCNTL) && defined(F_SETLK)
    /* Fall back to POSIX locks */
    (void)ret;  /* may be unused depending on #ifdefs above */
    return flock_fcntl(fd, operation, 0);

#elif defined(_WIN32)
    /* Windows */

#define FLOCK_OFFSET_LOW  0
#define FLOCK_OFFSET_HIGH 0
#define FLOCK_LENGTH_LOW  0x00000000
#define FLOCK_LENGTH_HIGH 0x80000000

    HANDLE hFile;
    OVERLAPPED ov;
    BOOL rv = FALSE;
    DWORD f = 0;

    hFile = (HANDLE) _get_osfhandle(fd);
    if (hFile == NULL || hFile == INVALID_HANDLE_VALUE) {
	_set_errno(EBADF);
	return -1;
    }

    ZeroMemory(&ov, sizeof(ov));
    ov.hEvent = NULL;
    ov.Offset = FLOCK_OFFSET_LOW;
    ov.OffsetHigh = FLOCK_OFFSET_HIGH;

    if (operation & LOCK_NB)
	f = LOCKFILE_FAIL_IMMEDIATELY;

    switch (operation & OP_MASK) {
    case LOCK_UN:			/* Unlock */
	rv = UnlockFileEx(hFile, 0,
			  FLOCK_LENGTH_LOW, FLOCK_LENGTH_HIGH, &ov);
	break;

    case LOCK_SH:			/* Shared lock */
	rv = LockFileEx(hFile, f, 0,
			FLOCK_LENGTH_LOW, FLOCK_LENGTH_HIGH, &ov);
	break;

    case LOCK_EX:			/* Exclusive lock */
	rv = LockFileEx(hFile, f|LOCKFILE_EXCLUSIVE_LOCK, 0,
			FLOCK_LENGTH_LOW, FLOCK_LENGTH_HIGH,
			&ov);
	break;

    default:
	_set_errno(EINVAL);
	return -1;
    }

    if (!rv) {
	switch (GetLastError()) {
	case ERROR_SHARING_VIOLATION:
	case ERROR_LOCK_VIOLATION:
	case ERROR_IO_PENDING:
	    _set_errno(EWOULDBLOCK);
	    break;

	case ERROR_ACCESS_DENIED:
	    _set_errno(EACCES);
	    break;

	default:
	    _set_errno(ENOLCK);
	}
	return -1;
    }

    return 0;

#else
    errno = ENOSYS;
    return -1;
#endif
}
