/*
 * Copyright (c) 1998 - 2001 Kungliga Tekniska Högskolan
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

#ifdef HAVE_SYS_AUXV_H
#include <sys/auxv.h>
#endif

#include <errno.h>

#include "roken.h"

/* NetBSD calls AT_UID AT_RUID.  Everyone else calls it AT_UID. */
#if defined(AT_EUID) && defined(AT_RUID) && !defined(AT_UID)
#define AT_UID AT_RUID
#endif
#if defined(AT_EGID) && defined(AT_RGID) && !defined(AT_GID)
#define AT_GID AT_RGID
#endif

#ifdef HAVE_GETAUXVAL
static unsigned long
rk_getauxval(unsigned long type)
{
    return getauxval(type);
}
#define USE_RK_GETAUXVAL
#elif defined(HAVE____GETAUXVAL)
static unsigned long
getauxval(unsigned long type)
{
    return ___getauxval((int)type);
}
#define USE_RK_GETAUXVAL
#endif

/**
 * Returns non-zero if the caller's process started as set-uid or
 * set-gid (and therefore the environment cannot be trusted).
 *
 * @return Non-zero if the environment is not trusted.
 */
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
issuid(void)
{
    /*
     * We want to use issetugid(), but issetugid() is not the same on
     * all OSes.
     *
     * On Illumos derivatives, OpenBSD, and Solaris issetugid() returns
     * true IFF the program exec()ed was set-uid or set-gid.
     *
     * On NetBSD and FreeBSD issetugid() returns true if the program
     * exec()ed was set-uid or set-gid, or if the process has switched
     * UIDs/GIDs or otherwise changed privileges or is a descendant of
     * such a process and has not exec()ed since.
     *
     * What we want here is to know only if the program exec()ed was
     * set-uid or set-gid, so we can decide whether to trust the
     * enviroment variables.  We don't care if this was a process that
     * started as root and later changed UIDs/privs whatever: since it
     * started out as privileged, it inherited an environment from a
     * privileged pre-exec self, and so on, so the environment is
     * trusted.
     *
     * Therefore the FreeBSD/NetBSD issetugid() does us no good.
     *
     * Linux, meanwhile, has no issetugid() (at least glibc doesn't
     * anyways).
     *
     * Systems that support ELF put an "auxilliary vector" on the stack
     * prior to starting the RTLD, and this vector includes (optionally)
     * information about the process' EUID, RUID, EGID, RGID, and so on
     * at the time of exec(), which we can use to construct proper
     * issetugid() functionality.
     *
     * Where available, we use the ELF auxilliary vector as a fallback
     * if issetugid() is not available.
     *
     * All of this is true as of late March 2015, and might become stale
     * in the future.
     */

#ifdef USE_RK_GETAUXVAL
#if (defined(AT_EUID) && defined(AT_UID) || (defined(AT_EGID) && defined(AT_GID)))
    int seen = 0;
#endif
    /*
     * If we have getauxval(), use that, but it's not easy to use: at
     * least glibc (and FreeBSD's ___getauxval()) fails to indicate "aux
     * val type not found" in any way.
     */
#if defined(AT_EUID) && defined(AT_UID)
    {
        unsigned long euid;
        unsigned long uid;

        errno = 0;
        euid = rk_getauxval(AT_EUID);
        if (euid != 0)
            seen |= 1;
        if (errno == 0) {
            uid = rk_getauxval(AT_UID);
            if (uid != 0)
                seen |= 2;
            if (errno == 0 && euid != uid)
                return 1;
        }
    }
#endif
#if defined(AT_EGID) && defined(AT_GID)
    {
        unsigned long egid;
        unsigned long gid;

        errno = 0;
        egid = rk_getauxval(AT_EGID);
        if (egid != 0)
            seen |= 4;
        if (errno == 0) {
            gid = rk_getauxval(AT_GID);
            if (gid != 0)
                seen |= 8;
            if (errno == 0 && egid != gid)
                return 2;
        }
    }
#endif
#ifdef AT_SECURE
    /* AT_SECURE is set if the program was set-id. */
    errno = 0;
    if (rk_getauxval(AT_SECURE) != 0)
        return 1;
#endif
#if (defined(AT_EUID) && defined(AT_UID) || (defined(AT_EGID) && defined(AT_GID)))
    if (seen == 15)
        return 0;
#endif
    /*
     * Fall through if we have getauxval() but we didn't have (or don't
     * know if we don't have) the aux entries that we needed.
     */
#endif /* USE_RK_GETAUXVAL */

#if defined(HAVE_ISSETUGID)
    /* If we have issetugid(), use it.  We may lose on some BSDs. */
    return issetugid();
#endif /* USE_RK_GETAUXVAL */

    /*
     * Paranoia: for extra safety we ought to default to returning 1.
     * But who knows what that might break where users link statically
     * and use a.out, say.  Also, on Windows we should always return 0.
     *
     * For now we stick to returning zero by default.
     */

#if defined(HAVE_GETUID) && defined(HAVE_GETEUID)
    if (getuid() != geteuid())
	return 1;
#endif
#if defined(HAVE_GETGID) && defined(HAVE_GETEGID)
    if (getgid() != getegid())
	return 2;
#endif

    return 0;
}
