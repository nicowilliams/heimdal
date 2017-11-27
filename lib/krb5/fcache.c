/*
 * Copyright (c) 1997 - 2017 Kungliga Tekniska Högskolan
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

/*
 * We now have a lock-less, O(1) extension to the ccache.
 *
 * We store (as usual, holding a file lock) one very large cconfig entry that
 * consists of a small header and a large hash table consisting of a
 * fixed-sized array of fixed-sized slots.  The hash table is indexed by
 * HMAC-SHA-1-96() of the principal name, keyed with a nonce in the header.
 *
 * We use cuckoo hashing with a number of alternate locations, and we us an LRU
 * strategy.
 *
 * Large entries span multiple slots.  Not contiguous slots, but slots given by
 * taking unique sliding windows of the hash of the principal name.  Thus a
 * two-slot entry might be written at slots 33 and 587.  Up to N * <nslots>
 * slots will be checked when writing, and up to N * <max_nslots> will be
 * checked when reading.
 *
 * The hash table is sized as a power of 2 that is larger than N^2, where N is
 * the working set size of ccache entries a user/app will need.  This sizing
 * consideration, the M alternate locations, and LRU, reduces the likelihood
 * of thrashing.  E.g., 2^10 (1024) == 32^2, so for working set sizes up to 32,
 * 1024 will do fine, 2048 ~ 45^2, 4096 = 64^2, and so on -- that's without
 * counting the effect of the M alternate locations.
 *
 * Therefore 1024 slots should suffice for a working set of 128 small tickets.
 *
 * Extra-large ccache entries are not written in the hash table, but they are
 * written to the FILE ccache beyond the hash table as usual: holding a file
 * lock.  In order to avoid having to always look past the hash table on cache
 * miss, we do isert a one-slot placeholder in the hash table for such large
 * entries.
 *
 * Each slot stores the HMAC-SHA-256-128() (keyed with a nonce in the hash
 * table header) of the real ccache entry, the HMAC-SHA-1-96() of the principal
 * name, the size of the real ccache entry, and the real ccache entry.
 *
 * The hash table header stores:
 *
 *  - nonce for HMACs
 *  - number of hash table slots
 *  - slot size
 *  - max ccache entry size
 *  - ...
 *
 * We use a ccache v4 extension to make finding the hash table fast by
 * recording up front its offset.  This way we always read this offset early on
 * when reading the ccache and need not iterate any entries at all to find
 * service tickets.  (We could also do this for the start TGT and the
 * start-realm ccconfig...)
 *
 * Retrieving is as follows:
 *
 *  - hash the name of the principal we're looking for and compute all the slot
 *    locations we'd look in if the ccache entry turns out to be the largest
 *    allowed
 *  - iterate over the slot list, reading each and checking the name MACs found
 *    in each
 *     - if none matches -> CC_NOTFOUND
 *     - if any matches -> reconstitute all matches
 *        - read the slot header to get the size of the entry
 *        - read the the entry
 *        - MAC the entry and compare the MAC
 *           - if not match -> CC_NOTFOUND
 *           - if match -> check the other match params and return accordingly
 *              - if all constraints match -> pick the newest (by create time)
 *                                            entry, and write the last use
 *                                            timestamp in the slot headers for
 *                                            all of that entry's slots
 *
 * Iteration is as follows:
 * 
 *  - starting at the zero-th slot, read its size, read the entry (using the
 *    stored principal MAC to compute the slot list for that entry), check the
 *    MAC, and if it matches, output that and skipt to the slot after it, else
 *    move one slot down and repeat until the last slot is read
 *
 * Writing is as follows:
 *  - hash the name of the principal we're looking for and compute the four (or
 *    fewer) sets of slots in which we might store
 *  - check the last use times of the two entries, replace the Least Recently
 *    Used one (LRU); where the LRU time is zero, use the creation time
 *     - construct array of slots in memmory
 *     - write each slot to its intended location in the file (writes are not
 *       atomic anyways)
 *
 * The use of HMAC for hashing principal names is to avoid linearization and
 * other DoS attacks on the hash table.  We keep 128 bits of the MAC of the
 * principal name, which, if log2(nslots) == 10, then we get up 119 unique
 * locations, but perhaps, too, as few as 1 unique location (very unlikely!).
 *
 * The use of HMAC for integrity protection of actual ccache entries is to
 * protect against smuggling ccache entries in Tickets, and to provide
 * protection against corruption due to concurrency.
 *
 * Lock-less for reading, lock-less for writing.
 */

#include "krb5_locl.h"
#include <assert.h>

typedef struct krb5_fcache{
    char *filename;
    int version;
    int fd;             /* XXX Set! */
    krb5_principal def_princ;
#ifdef HAVE_MMAP
    off_t tbl_off_off;  /* offset to offset for table */
    off_t tbl_off;      /* offset to hash table */
    size_t tbl_sz;      /* size of hash table */
    struct fcc_hash_table_header *tbl; /* mmap'ed table */
    size_t tbl_mmap_sz; /* mmap'ed size; should be == to tbl_sz */
    krb5_crypto crypto; /* for MAC operations */
    unsigned char *bitmap;
    size_t bitmap_sz;
#endif
}krb5_fcache;

struct fcc_cursor {
    int fd;
    off_t cred_start;
    off_t cred_end;
    krb5_storage *sp;
};

struct fcc_hash_table_header {
    char nonce[16];             /* key for MACs */
    uint32_t nslots;            /* no. of slots in table */
    uint32_t slotsz;            /* slot size */
    uint32_t princ_cksumtype;   /* MAC for princ name */
    uint32_t entry_cksumtype;   /* MAC for ccache entry */
    uint32_t entry_max_sz;      /* max size for entries in hash table */
};

/* 64-byte header; 512 slot size - 64 -> large enough for most tix w/o PACs */
struct fcc_hash_slot_header {
    char princ_mac[16];         /* MAC(client, server) */
    char entry_mac[16];         /* entry MAC; 128 bits is plenty */
    int64_t large_entry_off;    /* loc past hash table of extra large entry */
    uint64_t store_time;        /* time at which this entry was written */
    uint64_t exp_time;          /* entry expiration time */
    uint32_t entrysz;           /* entrysz > entry_max_sz -> look past table */
    /*
     * We put seqnum and last_use_time last so we can memcmp() just a prefix of
     * this struct minus those two fields when reconstituting entries.
     */
    uint32_t seqnum;            /* 0 -> first slot of entry, 1 -> 2nd, ... */
    uint64_t last_use_time;     /* last time at which this entry was read */
};

#define KRB5_FCC_FVNO_1 1
#define KRB5_FCC_FVNO_2 2
#define KRB5_FCC_FVNO_3 3
#define KRB5_FCC_FVNO_4 4

#define FCC_TAG_DELTATIME 1
#define FCC_TAG_HASH_TABLE_OFFSET 2 /* offset to table */

#define FCACHE(X) ((krb5_fcache*)(X)->data.data)

#define FILENAME(X) (FCACHE(X)->filename)

#define FCC_CURSOR(C) ((struct fcc_cursor*)(C))

#if defined(HAVE_MMAP) && defined(HAVE_SYSCONF) && defined(_SC_PAGE_SIZE)
static ssize_t sc_page_size = 0;
#endif

static const char* KRB5_CALLCONV
fcc_get_name(krb5_context context,
	     krb5_ccache id)
{
    if (FCACHE(id) == NULL)
        return NULL;

    return FILENAME(id);
}

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
_krb5_xlock(krb5_context context, int fd, krb5_boolean exclusive,
	    const char *filename)
{
    int ret;
#ifdef HAVE_FCNTL
    struct flock l;

    l.l_start = 0;
    l.l_len = 0;
    l.l_type = exclusive ? F_WRLCK : F_RDLCK;
    l.l_whence = SEEK_SET;
    ret = fcntl(fd, F_SETLKW, &l);
#else
    ret = flock(fd, exclusive ? LOCK_EX : LOCK_SH);
#endif
    if(ret < 0)
	ret = errno;
    if(ret == EACCES) /* fcntl can return EACCES instead of EAGAIN */
	ret = EAGAIN;

    switch (ret) {
    case 0:
	break;
    case EINVAL: /* filesystem doesn't support locking, let the user have it */
	ret = 0;
	break;
    case EAGAIN:
	krb5_set_error_message(context, ret,
			       N_("timed out locking cache file %s", "file"),
			       filename);
	break;
    default: {
	char buf[128];
	rk_strerror_r(ret, buf, sizeof(buf));
	krb5_set_error_message(context, ret,
			       N_("error locking cache file %s: %s",
				  "file, error"), filename, buf);
	break;
    }
    }
    return ret;
}

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
_krb5_xunlock(krb5_context context, int fd)
{
    int ret;
#ifdef HAVE_FCNTL
    struct flock l;
    l.l_start = 0;
    l.l_len = 0;
    l.l_type = F_UNLCK;
    l.l_whence = SEEK_SET;
    ret = fcntl(fd, F_SETLKW, &l);
#else
    ret = flock(fd, LOCK_UN);
#endif
    if (ret < 0)
	ret = errno;
    switch (ret) {
    case 0:
	break;
    case EINVAL: /* filesystem doesn't support locking, let the user have it */
	ret = 0;
	break;
    default: {
	char buf[128];
	rk_strerror_r(ret, buf, sizeof(buf));
	krb5_set_error_message(context, ret,
			       N_("Failed to unlock file: %s", ""), buf);
	break;
    }
    }
    return ret;
}

static krb5_error_code
write_storage(krb5_context context, krb5_storage *sp, int fd)
{
    krb5_error_code ret;
    krb5_data data;
    ssize_t sret;

    ret = krb5_storage_to_data(sp, &data);
    if (ret) {
	krb5_set_error_message(context, ret, N_("malloc: out of memory", ""));
	return ret;
    }
    sret = write(fd, data.data, data.length);
    ret = (sret != (ssize_t)data.length);
    krb5_data_free(&data);
    if (ret) {
	ret = errno;
	krb5_set_error_message(context, ret,
			       N_("Failed to write FILE credential data", ""));
	return ret;
    }
    return 0;
}


static krb5_error_code KRB5_CALLCONV
fcc_lock(krb5_context context, krb5_ccache id,
	 int fd, krb5_boolean exclusive)
{
    if (exclusive == FALSE)
        return 0;
    return _krb5_xlock(context, fd, exclusive, fcc_get_name(context, id));
}

static krb5_error_code KRB5_CALLCONV
fcc_resolve(krb5_context context, krb5_ccache *id, const char *res)
{
    krb5_fcache *f;
    f = calloc(1, sizeof(*f));
    if(f == NULL) {
	krb5_set_error_message(context, KRB5_CC_NOMEM,
			       N_("malloc: out of memory", ""));
	return KRB5_CC_NOMEM;
    }
    f->filename = strdup(res);
    if(f->filename == NULL){
	free(f);
	krb5_set_error_message(context, KRB5_CC_NOMEM,
			       N_("malloc: out of memory", ""));
	return KRB5_CC_NOMEM;
    }
    f->version = 0;
    f->def_princ = NULL;
#ifdef HAVE_MMAP
    f->tbl_off_off = -1;
    f->tbl_off = -1;
    f->crypto = NULL;
    f->bitmap = NULL;
    f->tbl = NULL;
#endif
    (*id)->data.data = f;
    (*id)->data.length = sizeof(*f);
    return 0;
}

/*
 * Try to scrub the contents of `filename' safely.
 */

static int
scrub_file (int fd)
{
    off_t pos;
    char buf[128];

    pos = lseek(fd, 0, SEEK_END);
    if (pos < 0)
        return errno;
    if (lseek(fd, 0, SEEK_SET) < 0)
        return errno;
    memset(buf, 0, sizeof(buf));
    while(pos > 0) {
	ssize_t tmp;
	size_t wr = sizeof(buf);
	if (wr > pos)
	    wr = (size_t)pos;
        tmp = write(fd, buf, wr);

	if (tmp < 0)
	    return errno;
	pos -= tmp;
    }
#ifdef _MSC_VER
    _commit (fd);
#else
    fsync (fd);
#endif
    return 0;
}

/*
 * Erase `filename' if it exists, trying to remove the contents if
 * it's `safe'.  We always try to remove the file, it it exists.  It's
 * only overwritten if it's a regular file (not a symlink and not a
 * hardlink)
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_erase_file(krb5_context context, const char *filename)
{
    int fd;
    struct stat sb1, sb2;
    int ret;

    ret = lstat (filename, &sb1);
    if (ret < 0)
	return errno;

    fd = open(filename, O_RDWR | O_BINARY | O_CLOEXEC | O_NOFOLLOW);
    if(fd < 0) {
	if(errno == ENOENT)
	    return 0;
	else
	    return errno;
    }
    rk_cloexec(fd);
    ret = _krb5_xlock(context, fd, 1, filename);
    if (ret) {
	close(fd);
	return ret;
    }
    if (unlink(filename) < 0) {
	ret = errno;
        close (fd);
	krb5_set_error_message(context, errno,
	    N_("krb5_cc_destroy: unlinking \"%s\": %s", ""),
	    filename, strerror(ret));
        return ret;
    }
    ret = fstat(fd, &sb2);
    if (ret < 0) {
	ret = errno;
	close (fd);
	return ret;
    }

    /* check if someone was playing with symlinks */

    if (sb1.st_dev != sb2.st_dev || sb1.st_ino != sb2.st_ino) {
	close(fd);
	return EPERM;
    }

    /* there are still hard links to this file */

    if (sb2.st_nlink != 0) {
        close(fd);
        return 0;
    }

    ret = scrub_file(fd);
    close(fd);
    return ret;
}

static krb5_error_code KRB5_CALLCONV
fcc_gen_new(krb5_context context, krb5_ccache *id)
{
    char *file = NULL, *exp_file = NULL;
    krb5_error_code ret;
    krb5_fcache *f;
    int fd;

    f = calloc(1, sizeof(*f));
    if(f == NULL) {
	krb5_set_error_message(context, KRB5_CC_NOMEM,
			       N_("malloc: out of memory", ""));
	return KRB5_CC_NOMEM;
    }
    ret = asprintf(&file, "%sXXXXXX", KRB5_DEFAULT_CCFILE_ROOT);
    if(ret < 0 || file == NULL) {
	free(f);
	krb5_set_error_message(context, KRB5_CC_NOMEM,
			       N_("malloc: out of memory", ""));
	return KRB5_CC_NOMEM;
    }
    ret = _krb5_expand_path_tokens(context, file, 1, &exp_file);
    free(file);
    if (ret) {
	free(f);
	return ret;
    }

    file = exp_file;

    fd = mkstemp(exp_file);
    if(fd < 0) {
	ret = (krb5_error_code)errno;
	krb5_set_error_message(context, ret, N_("mkstemp %s failed", ""), exp_file);
	free(f);
	free(exp_file);
	return ret;
    }
    close(fd);
    f->filename = exp_file;
    f->version = 0;
    f->def_princ = NULL;
#ifdef HAVE_MMAP
    f->tbl_off_off = -1;
    f->tbl_off = -1;
    f->crypto = NULL;
    f->bitmap = NULL;
    f->tbl = NULL;
#endif
    (*id)->data.data = f;
    (*id)->data.length = sizeof(*f);
    return 0;
}

static void
storage_set_flags(krb5_context context, krb5_storage *sp, int vno)
{
    int flags = 0;
    switch(vno) {
    case KRB5_FCC_FVNO_1:
	flags |= KRB5_STORAGE_PRINCIPAL_WRONG_NUM_COMPONENTS;
	flags |= KRB5_STORAGE_PRINCIPAL_NO_NAME_TYPE;
	flags |= KRB5_STORAGE_HOST_BYTEORDER;
	break;
    case KRB5_FCC_FVNO_2:
	flags |= KRB5_STORAGE_HOST_BYTEORDER;
	break;
    case KRB5_FCC_FVNO_3:
	flags |= KRB5_STORAGE_KEYBLOCK_KEYTYPE_TWICE;
	break;
    case KRB5_FCC_FVNO_4:
	break;
    default:
	krb5_abortx(context,
		    "storage_set_flags called with bad vno (%x)", vno);
    }
    krb5_storage_set_flags(sp, flags);
}

static krb5_error_code KRB5_CALLCONV
fcc_open(krb5_context context,
	 krb5_ccache id,
	 const char *operation,
	 int *fd_ret,
	 int flags,
	 mode_t mode)
{
    krb5_boolean exclusive = ((flags | O_WRONLY) == flags ||
			      (flags | O_RDWR) == flags);
    krb5_error_code ret;
    const char *filename;
    struct stat sb1, sb2;
#ifndef _WIN32
    struct stat sb3;
    size_t tries = 3;
#endif
    int strict_checking;
    int fd;

    flags |= O_BINARY | O_CLOEXEC | O_NOFOLLOW;

    *fd_ret = -1;

    if (FCACHE(id) == NULL)
        return krb5_einval(context, 2);

    filename = FILENAME(id);

    strict_checking = (flags & O_CREAT) == 0 &&
	(context->flags & KRB5_CTX_F_FCACHE_STRICT_CHECKING) != 0;

again:
    memset(&sb1, 0, sizeof(sb1));
    ret = lstat(filename, &sb1);
    if (ret == 0) {
	if (!S_ISREG(sb1.st_mode)) {
	    krb5_set_error_message(context, EPERM,
				   N_("Refuses to open symlinks for caches FILE:%s", ""), filename);
	    return EPERM;
	}
    } else if (errno != ENOENT || !(flags & O_CREAT)) {
	krb5_set_error_message(context, errno, N_("%s lstat(%s)", "file, error"),
			       operation, filename);
	return errno;
    }

    fd = open(filename, flags, mode);
    if(fd < 0) {
	char buf[128];
	ret = errno;
	rk_strerror_r(ret, buf, sizeof(buf));
	krb5_set_error_message(context, ret, N_("%s open(%s): %s", "file, error"),
			       operation, filename, buf);
	return ret;
    }
    rk_cloexec(fd);

    ret = fstat(fd, &sb2);
    if (ret < 0) {
	krb5_clear_error_message(context);
	close(fd);
	return errno;
    }

    if (!S_ISREG(sb2.st_mode)) {
	krb5_set_error_message(context, EPERM, N_("Refuses to open non files caches: FILE:%s", ""), filename);
	close(fd);
	return EPERM;
    }

#ifndef _WIN32
    if (sb1.st_dev && sb1.st_ino &&
	(sb1.st_dev != sb2.st_dev || sb1.st_ino != sb2.st_ino)) {
	/*
	 * Perhaps we raced with a rename().  To complain about
	 * symlinks in that case would cause unnecessary concern, so
	 * we check for that possibility and loop.  This has no
	 * TOCTOU problems because we redo the open().  We could also
	 * not do any of this checking if O_NOFOLLOW != 0...
	 */
	close(fd);
	ret = lstat(filename, &sb3);
	if (ret || sb1.st_dev != sb2.st_dev ||
	    sb3.st_dev != sb2.st_dev || sb3.st_ino != sb2.st_ino) {
	    krb5_set_error_message(context, EPERM, N_("Refuses to open possible symlink for caches: FILE:%s", ""), filename);
	    return EPERM;
	}
	if (--tries == 0) {
	    krb5_set_error_message(context, EPERM, N_("Raced too many times with renames of FILE:%s", ""), filename);
	    return EPERM;
	}
	goto again;
    }
#endif

    /*
     * /tmp (or wherever default ccaches go) might not be on its own
     * filesystem, or on a filesystem different /etc, say, and even if
     * it were, suppose a user hard-links another's ccache to her
     * default ccache, then runs a set-uid program that will user her
     * default ccache (even if it ignores KRB5CCNAME)...
     *
     * Default ccache locations should really be on per-user non-tmp
     * locations on tmpfs "run" directories.  But we don't know here
     * that this is the case.  Thus: no hard-links, no symlinks.
     */
    if (sb2.st_nlink != 1) {
	krb5_set_error_message(context, EPERM, N_("Refuses to open hardlinks for caches FILE:%s", ""), filename);
	close(fd);
	return EPERM;
    }

    if (strict_checking) {
#ifndef _WIN32
	/*
	 * XXX WIN32: Needs to have ACL checking code!
	 * st_mode comes out as 100666, and st_uid is no use.
	 */
	/*
	 * XXX Should probably add options to improve control over this
	 * check.  We might want strict checking of everything except
	 * this.
	 */
	if (sb2.st_uid != geteuid()) {
	    krb5_set_error_message(context, EPERM, N_("Refuses to open cache files not own by myself FILE:%s (owned by %d)", ""), filename, (int)sb2.st_uid);
	    close(fd);
	    return EPERM;
	}
	if ((sb2.st_mode & 077) != 0) {
	    krb5_set_error_message(context, EPERM,
				   N_("Refuses to open group/other readable files FILE:%s", ""), filename);
	    close(fd);
	    return EPERM;
	}
#endif
    }

    if((ret = fcc_lock(context, id, fd, exclusive)) != 0) {
	close(fd);
	return ret;
    }
    *fd_ret = fd;
    return 0;
}

static krb5_error_code KRB5_CALLCONV
fcc_initialize(krb5_context context,
	       krb5_ccache id,
	       krb5_principal primary_principal)
{
    krb5_fcache *f = FCACHE(id);
    int ret = 0;
    int fd;

    if (f == NULL)
        return krb5_einval(context, 2);

    unlink (f->filename);
#ifdef HAVE_MMAP
    f->tbl_off_off = -1;
    f->tbl_off = -1;
    if (f->tbl != NULL)
        munmap(f->tbl, f->tbl_mmap_sz);
    f->tbl_mmap_sz = 0;
    f->tbl_sz = 0;
    f->tbl = NULL;
#endif

    ret = fcc_open(context, id, "initialize", &fd, O_RDWR | O_CREAT | O_EXCL, 0600);
    if(ret)
	return ret;
    {
	krb5_storage *sp;
	sp = krb5_storage_emem();
	krb5_storage_set_eof_code(sp, KRB5_CC_END);
	if(context->fcache_vno != 0)
	    f->version = context->fcache_vno;
	else
	    f->version = KRB5_FCC_FVNO_4;
        if (ret == 0)
            ret = krb5_store_int8(sp, 5);
        if (ret == 0)
            ret = krb5_store_int8(sp, f->version);
	storage_set_flags(context, sp, f->version);
	if (f->version == KRB5_FCC_FVNO_4 && ret == 0) {
	    /* V4 ccache extensions */
            if (ret == 0)
                ret = krb5_store_int16(sp, 28); /* length of all extensions */
            if (ret == 0)
                ret = krb5_store_int16(sp, FCC_TAG_DELTATIME); /* Tag */
            if (ret == 0)
                ret = krb5_store_int16(sp, 8); /* length of time offset */
            if (ret == 0)
                ret = krb5_store_int32(sp, context->kdc_sec_offset);
            if (ret == 0)
                ret = krb5_store_int32(sp, context->kdc_usec_offset);
            if (ret == 0)
                ret = krb5_store_int16(sp, FCC_TAG_HASH_TABLE_OFFSET); /* Tag */
            if (ret == 0)
                ret = krb5_store_int16(sp, 12); /* length of extension payload */
            if (ret == 0) {
                f->tbl_off_off = krb5_storage_seek(sp, 0, SEEK_CUR);
                ret = krb5_store_int64(sp, -1); /* offset to hash table */
            }
            if (ret == 0)
                ret = krb5_store_uint32(sp, 0); /* size of hash table */
	}
        if (ret == 0)
            ret = krb5_store_principal(sp, primary_principal);

        if (ret == 0)
            ret = write_storage(context, sp, fd);

	krb5_storage_free(sp);
    }
    if (close(fd) < 0)
	if (ret == 0) {
	    char buf[128];
	    ret = errno;
	    rk_strerror_r(ret, buf, sizeof(buf));
	    krb5_set_error_message(context, ret, N_("close %s: %s", ""),
				   FILENAME(id), buf);
	}
    return ret;
}

static krb5_error_code KRB5_CALLCONV
fcc_close(krb5_context context,
	  krb5_ccache id)
{
    if (FCACHE(id) == NULL)
        return krb5_einval(context, 2);

    free (FILENAME(id));
#ifdef HAVE_MMAP
    if (FCACHE(id)->tbl != NULL)
        (void) munmap(FCACHE(id)->tbl, FCACHE(id)->tbl_mmap_sz);
    if (FCACHE(id)->crypto != NULL)
        krb5_crypto_destroy(context, FCACHE(id)->crypto);
    if (FCACHE(id)->bitmap != NULL)
        free(FCACHE(id)->bitmap);
    FCACHE(id)->tbl_mmap_sz = 0;
    FCACHE(id)->tbl_off_off = -1;
    FCACHE(id)->tbl_off = -1;
    FCACHE(id)->tbl_sz = 0;
    FCACHE(id)->crypto = NULL;
    FCACHE(id)->bitmap = NULL;
    FCACHE(id)->tbl = NULL;
#endif

    krb5_data_free(&id->data);
    return 0;
}

static krb5_error_code KRB5_CALLCONV
fcc_destroy(krb5_context context,
	    krb5_ccache id)
{
    if (FCACHE(id) == NULL)
        return krb5_einval(context, 2);

    return _krb5_erase_file(context, FILENAME(id));
}

#ifdef HAVE_MMAP
static krb5_error_code KRB5_CALLCONV
make_hash_table(krb5_context context, krb5_ccache id, int fd)
{
    struct fcc_hash_table_header tbl;
    krb5_error_code ret;
    krb5_storage *sp = NULL;
    krb5_creds tbl_cred;
    ssize_t page_size = 8192;
    ssize_t sz;
    off_t off, save_off;

    if (FCACHE(id)->def_princ == NULL || FCACHE(id)->tbl_off_off == -1)
        return -1;

#if defined(HAVE_SYSCONF) && defined(_SC_PAGE_SIZE)
    if (sc_page_size == 0)
        sc_page_size = sysconf(_SC_PAGE_SIZE);
    page_size = sc_page_size > 0 ? sc_page_size : 8192;
#endif

    memset(&tbl, 0, sizeof(tbl));
    tbl.nslots = 1024;
    tbl.slotsz = 512;
    tbl.princ_cksumtype = CKSUMTYPE_HMAC_SHA256_128_AES128;
    tbl.entry_cksumtype = CKSUMTYPE_HMAC_SHA256_128_AES128;
    tbl.entry_max_sz = 1UL<<14;

    assert(sizeof(tbl) < tbl.slotsz);
    sz = (ssize_t)((tbl.nslots + 1) * tbl.slotsz);

    ret = krb5_generate_random(&tbl.nonce, sizeof(tbl.nonce));
    if (ret)
        return ret;

    memset(&tbl_cred, 0, sizeof(tbl_cred));

    /* Prep a krb5_creds to store, then store it */
    tbl_cred.times.authtime = time(NULL);
    if (sizeof(tbl_cred.times.endtime) > sizeof(uint32_t))
        tbl_cred.times.endtime = tbl_cred.times.authtime + 3600 * 24 * 365 * 10;
    else
        tbl_cred.times.endtime = tbl_cred.times.authtime + 3600 * 24 * 365;

    tbl_cred.client = FCACHE(id)->def_princ;
    ret = krb5_make_principal(context, &tbl_cred.server,
                              "X-CACHECONF:", "krb5_ccache_conf_data",
                              "ccache_hash_table", NULL);

    /*
     * XXX If we didn't use krb5_store_creds() then we wouldn't have to
     * allocate sz bytes here for nothing.
     *
     * XXX Teach krb5_store_creds() to seek tbl_cred.ticket.length and continue
     * when tbl_cred.ticket.data == NULL and tbl_cred.ticket.length != 0 and
     * the creds is a ccache_hash_table ccconfig.  Then we won't need this
     * allocation.
     */
    if (ret == 0)
        /*
         * We add a page to the size so that we can align the actual table at a
         * page boundary so we can mmap() the table.
         */
        ret = krb5_data_alloc(&tbl_cred.ticket, sz + page_size);
    if (ret == 0) {
        memset(tbl_cred.ticket.data, 0, tbl_cred.ticket.length);
        sp = krb5_storage_from_fd(fd);
        if (sp == NULL)
            ret = ENOMEM;
    }

    if (ret == 0) {
        off = krb5_storage_seek(sp, 0, SEEK_CUR);
        if (off == -1)
            ret = errno;
    }

    if (ret == 0)
	ret = krb5_store_creds(sp, &tbl_cred);

    /*
     * Work out the offset of the page-aligned table, and make sure to preserve
     * the current offset (end of the cred we just wrote) of the sp.
     */

    if (ret == 0)
        save_off = krb5_storage_seek(sp, 0, SEEK_CUR);
    else
        save_off = -1;

    /* krb5_storage_from_fd() dup()s fd; update fd's offset to match */
    if (save_off > -1 && lseek(fd, off, SEEK_SET) == -1 && ret == 0)
        ret = errno;

    krb5_free_principal(context, tbl_cred.server);
    tbl_cred.client = tbl_cred.server = NULL;
    krb5_data_free(&tbl_cred.ticket);
    
    /* Find the offset to the table in the ccache entry we just wrote */
    if (ret == 0 && save_off != -1 &&
        krb5_storage_seek(sp, off, SEEK_SET) == off) {
        int8_t u8;
        int32_t i32;
        uint32_t u32;

        ret = krb5_ret_principal(sp, &tbl_cred.client);
        if (ret == 0)
            ret = krb5_ret_principal(sp, &tbl_cred.server);
        if (ret == 0)
            ret = krb5_ret_keyblock(sp, &tbl_cred.session);
        if (ret == 0)
            krb5_ret_times(sp, &tbl_cred.times);
        if (ret == 0)
            krb5_ret_int8(sp, &u8);
        if (ret == 0)
            ret = krb5_ret_int32(sp, &i32);
        if (ret == 0) {
            tbl_cred.flags.b = int2TicketFlags(0);
            ret = krb5_ret_addrs(sp, &tbl_cred.addresses);
        }
        if (ret == 0)
            ret = krb5_ret_authdata(sp, &tbl_cred.authdata);

        /* sp's offset now points at the length of the "ticket" */
        if (ret == 0)
            ret = krb5_ret_uint32(sp, &u32);

        if (u32 != sz + page_size)
            ret = KRB5_CC_FORMAT;

        /* sp's offset now points at the "ticket" */

        if (ret == 0)
            off = krb5_storage_seek(sp, 0, SEEK_CUR);

        off += page_size - (off % page_size); /* offset to actual table */

        /* Update the offset to the table in the ccache header */
        if (save_off > off && save_off >= off + sz) {
            if (krb5_storage_seek(sp, FCACHE(id)->tbl_off_off, SEEK_SET) != -1)
                ret = krb5_store_int64(sp, off);
            else
                ret = KRB5_CC_FORMAT;
        } else
            ret = KRB5_CC_FORMAT;
    }

    tbl_cred.client = NULL;
    krb5_free_cred_contents(context, &tbl_cred);
    krb5_storage_free(sp);

    /* Leave fd's offset as expected */
    if (save_off > 0 && lseek(fd, save_off, SEEK_SET) == -1 && ret == 0)
        ret = errno;
    return ret;
}

static inline uint32_t
ones32(register uint32_t x)
{
    x -= ((x >> 1) & 0x55555555);
    x = (((x >> 2) & 0x33333333) + (x & 0x33333333));
    x = (((x >> 4) + x) & 0x0f0f0f0f);
    x += (x >> 8);
    x += (x >> 16);
    return(x & 0x0000003f);
}

static inline uint32_t
my_log2(register uint32_t x)
{
    register int y = (x & (x - 1));

    y |= -y;
    y >>= (sizeof(x) * CHAR_BIT - 1);
    x |= (x >> 1);
    x |= (x >> 2);
    x |= (x >> 4);
    x |= (x >> 8);
    x |= (x >> 16);
    return(ones32(x >> 1) - y);
}

static uint64_t
get_mac_bits(unsigned char *src, size_t len, size_t numbits, size_t idx)
{
    size_t lobits = idx + numbits;          /* index of lowest bit */
    size_t lobyte = len - ((lobits >> 3) % CHAR_BIT);    /* index of lowest bytes */
    size_t bytes = numbits >> 3;    /* floor(no. of bytes needed for numbits) */
    uint64_t bits = 0;
    size_t i;

    assert(CHAR_BIT == 8);
    assert(numbits >= CHAR_BIT);
    assert(((numbits + CHAR_BIT - 1) >> 3) < sizeof(bits));

    /*
     * This loop copies the bits from the bit string into `bits`, such that 0
     * to 7 bits of the LSB of `bits` may need to be shifted out.
     */
    for (i = 0; i < sizeof(bits) && i < bytes + 1 && &src[lobyte - i] >= src; i++)
        bits |= (src[lobyte - i] << (i * 8));
    /*
     * Shift out 0 to 7 bits, then mask out all but the low `numbits` bits of
     * `bits`.
     */
    return (bits >> (lobits % CHAR_BIT)) & ((1<<numbits) - 1);
}

#define BITMAP_BIT_IS_SET(id, idx) \
    ((FCACHE(id)->bitmap)[(idx >> 3)] & (1<<(idx % CHAR_BIT)))

#define BITMAP_BIT_SET(id, idx) \
    ((FCACHE(id)->bitmap)[(idx >> 3)] |= (1<<(idx % CHAR_BIT)))


static krb5_error_code
tbl_mac2offsets(krb5_context context,
                krb5_ccache id,
                heim_octet_string *macp,
                struct fcc_hash_slot_header ***slotsp,
                size_t *nslotsp)
{
    struct fcc_hash_table_header *h = FCACHE(id)->tbl;
    unsigned char *slots;
    size_t i, k, nslots, maxi, numbits, slotsz;
    uint32_t *indexes;

    if (h == NULL || h->nslots < 256 || h->slotsz < 512)
        return -1;

    slots = (((unsigned char *)h) + h->slotsz);
    numbits = my_log2(h->nslots);

    /* Effective slot size -- space for ccache entry content */
    slotsz = h->slotsz - sizeof(struct fcc_hash_slot_header);

    /*
     * We want up to 1.5 x the number of slots need for storing the largest
     * ccache entry we're willing to store in the hash table.  That's plenty
     * for small tickets, and not very much for large ones.
     *
     * Extra large tickets are written as usual, but we'll still store a
     * one-slot entry for them with the offset of the real entry.
     */
    nslots = h->entry_max_sz / slotsz;
    nslots += nslots >> 1;

    indexes = calloc(nslots, sizeof(indexes[0]));
    if (indexes == NULL)
        return ENOMEM;

    /*
     * How many indices can we generate from a MAC?  For example, for a 128-bit
     * MAC we can get up to 119 10-bit indices.
     */
    maxi = macp->length * CHAR_BIT + 1 - numbits;

    /*
     * We want up to nslots unique indices.  We'll use a bitmap to check for
     * uniqueness.
     */

    if (FCACHE(id)->bitmap == NULL ||
        FCACHE(id)->bitmap_sz < ((1<<numbits) >> 3)) {

        free(FCACHE(id)->bitmap);
        FCACHE(id)->bitmap = malloc((1<<numbits) >> 3);
        if (FCACHE(id)->bitmap == NULL) {
            *nslotsp = 0;
            free(indexes);
            return ENOMEM;
        }
        FCACHE(id)->bitmap_sz = (1<<numbits) >> 3;
    }

    memset(FCACHE(id)->bitmap, 0, FCACHE(id)->bitmap_sz);

    for (i = k = 0; k < nslots && i < maxi; i++) {
        indexes[k] = get_mac_bits(macp->data, macp->length, numbits, i);
        if (BITMAP_BIT_IS_SET(id, indexes[k]))
            continue;
        BITMAP_BIT_SET(id, indexes[k]);
        k++;
    }
    nslots = k; /* may be less than desired, but not likely */

    if (*slotsp == NULL || *nslotsp < nslots) {
        free(*slotsp);
        *slotsp = calloc(nslots, sizeof(*slotsp));
        if (*slotsp == NULL) {
            *nslotsp = 0;
            free(indexes);
            return ENOMEM;
        }
    }

    for (i = 0; i < nslots; i++)
        slotsp[i] = (void *)&slots[FCACHE(id)->tbl->slotsz * i];

    *nslotsp = nslots;
    return 0;
}

static krb5_error_code
tbl_hash(krb5_context context,
         krb5_ccache id,
         const krb5_creds *creds,
         krb5_checksum *macp,
         struct fcc_hash_slot_header ***slotsp,
         size_t *nslotsp)
{
    krb5_error_code ret;
    krb5_checksum mac;
    krb5_storage *sp;
    krb5_data d;
    ssize_t page_size = 8192;

#if defined(HAVE_SYSCONF) && defined(_SC_PAGE_SIZE)
    if ((page_size = sysconf(_SC_PAGE_SIZE)) < 0)
        page_size = 8192;
#endif

    if (FCACHE(id)->tbl_off == -1 || FCACHE(id)->tbl_sz < 2 * page_size ||
        FCACHE(id)->fd < 0)
        return -1;

    /* XXX Actually, do this in init_fcc() */
    if (FCACHE(id)->tbl == NULL) {
        void *p;

        p = mmap(NULL, FCACHE(id)->tbl_sz, PROT_READ | PROT_WRITE, MAP_SHARED,
                 FCACHE(id)->fd, FCACHE(id)->tbl_off);
        if (p == MAP_FAILED)
            return -1;
        FCACHE(id)->tbl = p;
        FCACHE(id)->tbl_mmap_sz = FCACHE(id)->tbl_sz;
    }

    /* MAC the cred's client and server princ name */
    sp = krb5_storage_emem();
    if (sp == NULL)
        return ENOMEM;
    ret = krb5_store_principal(sp, creds->client);
    if (ret == 0)
        ret = krb5_store_principal(sp, creds->client);
    if (ret == 0)
        ret = krb5_storage_to_data(sp, &d);
    krb5_storage_free(sp);
    if (ret == 0 && FCACHE(id)->crypto == NULL) {
        krb5_keyblock key;
        
        key.keytype = FCACHE(id)->tbl->princ_cksumtype;
        key.keyvalue.data = FCACHE(id)->tbl->nonce;
        key.keyvalue.length = sizeof(FCACHE(id)->tbl->nonce);
        ret = krb5_crypto_init(context, &key, 0, &FCACHE(id)->crypto);
    }
    if (ret == 0)
        ret = krb5_create_checksum(context, FCACHE(id)->crypto,
                                   KRB5_KU_OTHER_CKSUM,
                                   FCACHE(id)->tbl->princ_cksumtype,
                                   d.data, d.length, &mac);
    krb5_data_free(&d);

    if (ret == 0)
        ret = tbl_mac2offsets(context, id, &mac.checksum, slotsp, nslotsp);
    if (ret == 0 && macp != NULL)
        *macp = mac;
    else
        krb5_checksum_free(context, &mac);
    return ret;
}

/*
 * If model != NULL then reconstitute the entry found there, else look for it
 * from scratch.
 */
static krb5_error_code
tbl_get_entry(krb5_context context,
              krb5_ccache id,
              const krb5_creds *mcreds,
              struct fcc_hash_slot_header *model,
              krb5_creds *out)
{
    struct fcc_hash_slot_header **slots2check = NULL;
    krb5_checksum princ_mac;
    krb5_error_code ret;
    krb5_storage *sp = NULL;
    krb5_data d;
    uint64_t **last_use_times = NULL;
    size_t chunk_sz;
    size_t nslots2check = 0;
    size_t slots_needed = 0;
    size_t i, first_match, seqmap;

    if (FCACHE(id)->tbl == NULL || FCACHE(id)->fd < 0)
        return -1;

    chunk_sz = FCACHE(id)->tbl->slotsz - sizeof(struct fcc_hash_slot_header);

    d.length = 0;
    d.data = NULL;

    if (model != NULL) {
        heim_octet_string mac;

        mac.data = model->princ_mac;
        mac.length = sizeof(model->princ_mac);
        ret = tbl_mac2offsets(context, id, &mac, &slots2check, &nslots2check);
    } else if (mcreds != NULL) {
        ret = tbl_hash(context, id, mcreds, &princ_mac, &slots2check, &nslots2check);
        if (ret)
            return ret;
        if (princ_mac.checksum.length != sizeof(model->princ_mac))
            return -1; /* XXX */
    } else
        return EINVAL; /* Internal API usage error; can't happen, should assert */

    ret = -1;
    for (i = 0, seqmap = 0, first_match = (size_t)-1; i < nslots2check; i++) {
        if (model != NULL) {
            if (memcmp(model, &slots2check[i],
                       offsetof(struct fcc_hash_slot_header, seqnum)) != 0)
                continue;
        } else if (first_match != -1) {
            if (memcmp(slots2check[i]->princ_mac, princ_mac.checksum.data,
                       sizeof(slots2check[i]->princ_mac)) != 0)
                continue;
            if (memcmp(model, slots2check[first_match],
                       offsetof(struct fcc_hash_slot_header, seqnum)) != 0)
                continue;
        } else {
            if (memcmp(slots2check[i]->princ_mac, princ_mac.checksum.data,
                       sizeof(slots2check[i]->princ_mac)) != 0)
                continue;
            /* From here on only check partial matches of this one */
            first_match = i;
        }

        /* Got a matching slot */

        if (slots_needed == 0) {
            slots_needed = slots2check[i]->entrysz / chunk_sz;
            if (slots2check[i]->entrysz % chunk_sz != 0)
                slots_needed++;
            last_use_times = calloc(slots_needed, sizeof(last_use_times[0]));
        }

        if (slots2check[i]->seqnum > slots_needed || /* can't be a match or */
            seqmap & (1 << slots2check[i]->seqnum))  /* got this already */
            continue;

        if (slots2check[i]->entrysz > d.length) {
            void *tmp;

            if ((tmp = realloc(d.data,
                               (slots_needed + 1) * chunk_sz)) == NULL) {
                free(d.data);
                return ENOMEM;
            }
            d.length = (slots_needed + 1) * chunk_sz;
            d.data = tmp;
        }
        memcpy((char *)d.data + (slots2check[i])->seqnum * chunk_sz,
               slots2check[i] + 1, chunk_sz);
        if (last_use_times != NULL)
            last_use_times[i] = &(slots2check[i])->last_use_time;
        if (seqmap == (1 << slots_needed) - 1) {
            ret = 0;
            break; /* Got all the chunks we needed */
        }
    }

    if (ret == 0 && last_use_times != NULL) {
        time_t now = time(NULL);

        for (i = 0; i < slots_needed; i++)
            *(last_use_times[i]) = now;
    }

    if (ret == 0 && (sp = krb5_storage_from_data(&d)) == NULL)
        ret = ENOMEM;

    if (ret == 0)
        ret = krb5_ret_creds(sp, out);

    free(last_use_times);
    krb5_storage_free(sp);
    krb5_data_free(&d);
    return ret;
}

struct fcc_hash_slot_reference {
    struct fcc_hash_slot_header *slot;
    uint64_t last_use_time;
};

/*
 * `ap` is less than `bp` if `a` is expired or use less recently than `b`, or
 * stored earlier than `b`.
 */
static int
writer_slotcmp(const void *ap, const void *bp, void *ctx)
{
    const struct fcc_hash_slot_reference *a = *(const struct fcc_hash_slot_reference **)ap;
    const struct fcc_hash_slot_reference *b = *(const struct fcc_hash_slot_reference **)bp;
    const time_t *now = ctx;

    /* The more expired of `a` or `b` is lesser */
    if (a->slot->exp_time > *now || b->slot->exp_time > *now)
        return a->slot->exp_time - b->slot->exp_time;

    /* Neither is expired */

    if (a->last_use_time == 0) {
        if (b->last_use_time == 0)
            return a->slot->store_time - b->slot->store_time;
        return -1; /* or a->slot->store_time - b->last_use_time */
    }
    if (b->last_use_time == 0)
        return  1; /* or a->slot->last_use_time - b->store_time */

    /* Both used at least once */
    if (a->last_use_time != b->last_use_time)
        return a->last_use_time - b->last_use_time;

    /* Same last use time, neither expired, pick oldest */
    return a->slot->store_time - b->slot->store_time;
}

static krb5_error_code store_creds(krb5_context, krb5_ccache,
                                   krb5_creds *, int, off_t *);

static krb5_error_code
tbl_put_entry(krb5_context context,
              krb5_ccache id,
              krb5_creds *creds)
{
    struct fcc_hash_slot_header **slots = NULL;
    struct fcc_hash_slot_header model;
    struct fcc_hash_slot_reference *slotrefs = NULL;
    krb5_error_code ret;
    krb5_checksum princ_mac, entry_mac;
    krb5_storage *sp = NULL;
    krb5_data d;
    size_t chunk_sz;
    size_t nslots = 0;
    size_t slots_needed = 0;
    size_t i;
    time_t now;

    if (FCACHE(id)->tbl == NULL || FCACHE(id)->fd < 1)
        return -1;

    if ((sp = krb5_storage_emem()) == NULL)
        return ENOMEM;

    chunk_sz = FCACHE(id)->tbl->slotsz - sizeof(struct fcc_hash_slot_header);

    d.length = 0;
    d.data = NULL;

    ret = tbl_hash(context, id, creds, &princ_mac, &slots, &nslots);
    if (ret == 0)
        ret = krb5_store_creds(sp, creds);
    if (ret == 0)
        ret = krb5_storage_to_data(sp, &d);

    krb5_storage_free(sp);

    if (ret == 0 && FCACHE(id)->crypto == NULL) {
        krb5_keyblock key;
        
        key.keytype = FCACHE(id)->tbl->princ_cksumtype;
        key.keyvalue.data = FCACHE(id)->tbl->nonce;
        key.keyvalue.length = sizeof(FCACHE(id)->tbl->nonce);
        ret = krb5_crypto_init(context, &key, 0, &FCACHE(id)->crypto);
    }

    if (ret == 0)
        ret = krb5_create_checksum(context, FCACHE(id)->crypto,
                                   KRB5_KU_OTHER_CKSUM,
                                   FCACHE(id)->tbl->princ_cksumtype,
                                   d.data, d.length, &entry_mac);

    if (ret)
        goto out;

    now = time(NULL);

    memset(&model, 0, sizeof(model));

    memcpy(model.princ_mac, princ_mac.checksum.data,
           min(sizeof(model.princ_mac), princ_mac.checksum.length));
    memcpy(model.entry_mac, entry_mac.checksum.data,
           min(sizeof(model.entry_mac), entry_mac.checksum.length));

    model.last_use_time = 0;
    model.store_time = now;
    model.exp_time = creds->times.endtime;
    model.entrysz = d.length;

    if (d.length > FCACHE(id)->tbl->entry_max_sz) {
        /*
         * Write the cred as usual, get its offset, and store that in the hash
         * table.
         */
        ret = store_creds(context, id, creds, 0, &model.large_entry_off);
        if (ret)
            goto out;
    } else
        model.large_entry_off = -1;

    /*
     * We want to sort the slots so that the best uses to clobber are first.
     *
     * We can't qsort_r(slots, nslots, ...) because we need to use the
     * last_use_time from each slot, which is unstable, which means using it
     * would yield undefined behavior from qsort().
     *
     * Instead we make and qsort_r() an array of slot references, each with a
     * pointer to its slot, and a copy of that slot's last_use_time.
     */
    slotrefs = calloc(nslots, sizeof(slotrefs[0]));
    if (slotrefs == NULL) {
        ret = ENOMEM;
        goto out;
    }

    /*
     * XXX Further halve the size of slotrefs[i] by storing a 32-bit index and
     * a 32-bit time.  This means passing not just `now` to the comparator, but
     * also the address of the zeroth slot.
     */
    for (i = 0; i < nslots; i++) {
        slotrefs[i].slot = slots[i];
        slotrefs[i].last_use_time = slots[i]->last_use_time;
    }

    qsort_r(slotrefs, nslots, sizeof(slotrefs[0]), writer_slotcmp, &now);

    if (slots_needed == 0)
        slots_needed = d.length / chunk_sz;

    for (i = 0; i < slots_needed; i++) {
        model.seqnum = i;
        memcpy(slotrefs[i].slot, &model, sizeof(model));
        if (i + 1 == slots_needed)
            memcpy(slotrefs[i].slot + 1, (char *)d.data + chunk_sz * i, d.length - chunk_sz * i);
        else
            memcpy(slotrefs[i].slot + 1, (char *)d.data + chunk_sz * i, chunk_sz);
    }

out:
    krb5_checksum_free(context, &princ_mac);
    krb5_checksum_free(context, &entry_mac);
    krb5_data_free(&d);
    return ret;
}
#endif /* HAVE_MMAP */

static krb5_error_code
store_creds(krb5_context context,
            krb5_ccache id,
            krb5_creds *creds,
            int use_hash_tbl,
            off_t *creds_off)
{
    krb5_error_code ret;
    krb5_storage *sp = NULL;
#ifdef HAVE_MMAP
    const char *realm = krb5_principal_get_realm(context, creds->server);
    int hash_it = 0;
#endif
    off_t creds_sz;
    int fd;

    ret = fcc_open(context, id, "store", &fd, O_WRONLY | O_APPEND, 0);
    if (ret == 0)
	sp = krb5_storage_emem();
    if (sp == NULL)
	return ret ? ret : ENOMEM;
    krb5_storage_set_eof_code(sp, KRB5_CC_END);

    storage_set_flags(context, sp, FCACHE(id)->version);
    ret = krb5_store_creds(sp, creds);
    if (ret)
        goto cleanup;

    creds_sz = krb5_storage_seek(sp, 0, SEEK_CUR);

#ifdef HAVE_MMAP
    if (use_hash_tbl) {
        /*
         * If we're storing a non-krbtgt, non-ccconfig entry, and we don't yet
         * have an offset to the hash table, then we don't have a hash table
         * yet, so create it.
         */
        if (FCACHE(id)->tbl_off == -1 &&
            strcmp(realm, "X-CACHECONF:") != 0 &&
            krb5_principal_get_num_comp(context, creds->server) > 0) {
            const char *name0 = krb5_principal_get_comp_string(context,
                                                               creds->server,
                                                               0);

            if (strcmp(name0, "krbtgt") != 0) {
                if (make_hash_table(context, id, fd) == 0)
                    hash_it = 1;
            }
        } else if (FCACHE(id)->tbl_off != -1 &&
                   strcmp(realm, "X-CACHECONF:") != 0)
            hash_it = 1;

        if (hash_it) {
            FCACHE(id)->fd = dup(fd);
            ret = tbl_put_entry(context, id, creds);
            if (FCACHE(id)->fd != -1 && close(FCACHE(id)->fd) == -1)
                ret = errno;
            FCACHE(id)->fd = -1;
            if (ret != 0 && ret != -1) {
                if (creds_off != NULL)
                    *creds_off = -1;
                goto cleanup;
            }
        }
        /* Fall through, write as usual */
    }
#endif /* HAVE_MMAP */

    if (ret == 0)
        ret = write_storage(context, sp, fd);
    if (creds_off != NULL)
        *creds_off = lseek(fd, 0, SEEK_CUR) - creds_sz;

cleanup:
    krb5_storage_free(sp);
    if (close(fd) < 0) {
	if (ret == 0) {
	    char buf[128];
	    ret = errno;
	    rk_strerror_r(ret, buf, sizeof(buf));
	    krb5_set_error_message(context, ret, N_("close %s: %s", ""),
				   FILENAME(id), buf);
	}
    }
    return ret;
}

static krb5_error_code KRB5_CALLCONV
fcc_store_cred(krb5_context context,
               krb5_ccache id,
               krb5_creds *creds)
{
    return store_creds(context, id, creds, 1, NULL);
}

static krb5_error_code
init_fcc(krb5_context context,
	 krb5_ccache id,
	 const char *operation,
	 krb5_storage **ret_sp,
	 int *ret_fd,
	 krb5_deltat *kdc_offset)
{
    int fd = -1;
    int8_t pvno, tag;
    krb5_storage *sp = NULL;
    krb5_error_code ret;

#if 0
    heim_assert(ret_fd == NULL || ret_sp == NULL,
                "init_fcc() called incorrectly");
    heim_assert(ret_fd != NULL || ret_sp != NULL,
                "init_fcc() called incorrectly");
#endif

    if (ret_fd)
        *ret_fd = -1;
    if (ret_sp)
        *ret_sp = NULL;
    if (kdc_offset)
	*kdc_offset = 0;

    ret = fcc_open(context, id, operation, &fd, O_RDONLY, 0);
    if(ret)
	return ret;

    sp = krb5_storage_stdio_from_fd(fd, "r");
    if(sp == NULL) {
	krb5_clear_error_message(context);
	ret = ENOMEM;
	goto out;
    }
    krb5_storage_set_eof_code(sp, KRB5_CC_END);
    ret = krb5_ret_int8(sp, &pvno);
    if (ret != 0) {
	if(ret == KRB5_CC_END) {
	    ret = ENOENT;
	    krb5_set_error_message(context, ret,
				   N_("Empty credential cache file: %s", ""),
				   FILENAME(id));
	} else
	    krb5_set_error_message(context, ret, N_("Error reading pvno "
						    "in cache file: %s", ""),
				   FILENAME(id));
	goto out;
    }
    if (pvno != 5) {
	ret = KRB5_CCACHE_BADVNO;
	krb5_set_error_message(context, ret, N_("Bad version number in credential "
						"cache file: %s", ""),
			       FILENAME(id));
	goto out;
    }
    ret = krb5_ret_int8(sp, &tag); /* should not be host byte order */
    if (ret != 0) {
	ret = KRB5_CC_FORMAT;
	krb5_set_error_message(context, ret, "Error reading tag in "
			      "cache file: %s", FILENAME(id));
	goto out;
    }
    FCACHE(id)->version = tag;
    storage_set_flags(context, sp, FCACHE(id)->version);
    switch (tag) {
    case KRB5_FCC_FVNO_4: {
	int16_t length;

	ret = krb5_ret_int16 (sp, &length);
	if(ret) {
	    ret = KRB5_CC_FORMAT;
	    krb5_set_error_message(context, ret,
				   N_("Error reading tag length in "
				      "cache file: %s", ""), FILENAME(id));
	    goto out;
	}

        while(length > 0) {
            int16_t dtag, data_len;

            ret = krb5_ret_int16(sp, &dtag);
            if(ret) {
                ret = KRB5_CC_FORMAT;
                krb5_set_error_message(context, ret, N_("Error reading dtag in "
                                                        "cache file: %s", ""),
                                       FILENAME(id));
                goto out;
            }
            ret = krb5_ret_int16(sp, &data_len);
            if(ret) {
                ret = KRB5_CC_FORMAT;
                krb5_set_error_message(context, ret,
                                       N_("Error reading dlength "
                                          "in cache file: %s",""),
                                       FILENAME(id));
                goto out;
            }
            switch (dtag) {
            case FCC_TAG_DELTATIME : {
                int32_t offset;

                if (data_len >= 8) {
                    ret = krb5_ret_int32(sp, &offset);
                    ret |= krb5_ret_int32(sp, &context->kdc_usec_offset);
                    if(ret) {
                        ret = KRB5_CC_FORMAT;
                        krb5_set_error_message(context, ret,
                                               N_("Error reading kdc_sec in "
                                                  "cache file: %s", ""),
                                               FILENAME(id));
                        goto out;
                    }
                    context->kdc_sec_offset = offset;
                    if (kdc_offset)
                        *kdc_offset = offset;
                    krb5_storage_seek(sp, data_len - 8, SEEK_CUR);
                } else {
                    krb5_storage_seek(sp, data_len, SEEK_CUR);
                }
                break;
            }
#ifdef HAVE_MMAP
            case FCC_TAG_HASH_TABLE_OFFSET : {
                int64_t off;
                uint32_t sz;

                if (data_len >= 16) {
                    off = krb5_storage_seek(sp, 0, SEEK_CUR);
                    if (off == -1)
                        ret = errno;
                    else
                        FCACHE(id)->tbl_off_off = off;
                    if (ret == 0)
                        ret = krb5_ret_int64(sp, &FCACHE(id)->tbl_off);
                    if (ret == 0) {
                        if (FCACHE(id)->tbl_off != -1 &&
                            FCACHE(id)->tbl_off != off &&
                            FCACHE(id)->tbl != NULL)
                            (void) munmap(FCACHE(id)->tbl,
                                          FCACHE(id)->tbl_mmap_sz);
                        FCACHE(id)->tbl_mmap_sz = 0;
                        FCACHE(id)->tbl_off = off;
                        FCACHE(id)->tbl = NULL;
                        ret = krb5_ret_uint32(sp, &sz);
                    }
                    if (ret == 0)
                        FCACHE(id)->tbl_sz = sz;
                    if (ret) {
                        ret = KRB5_CC_FORMAT;
                        krb5_set_error_message(context, ret,
                                               N_("Error hash table offset in "
                                                  "cache file: %s", ""),
                                               FILENAME(id));
                        goto out;
                    }
                    /* Ignore future extensions to this tag's payload */
                    krb5_storage_seek(sp, data_len - 16, SEEK_CUR);
                } else {
                    krb5_storage_seek(sp, data_len, SEEK_CUR);
                }
                break;
            }
#endif
            default :
                if (krb5_storage_seek(sp, data_len, SEEK_CUR) < 0) {
                    ret = KRB5_CC_FORMAT;
                    krb5_set_error_message(context, ret,
                                           N_("Error reading unknown "
                                              "tag in cache file: %s", ""),
                                           FILENAME(id));
                    goto out;
                }
                break;
            }
            length -= 4 + data_len;
        }
	break;
    }
    case KRB5_FCC_FVNO_3:
    case KRB5_FCC_FVNO_2:
    case KRB5_FCC_FVNO_1:
	break;
    default :
	ret = KRB5_CCACHE_BADVNO;
	krb5_set_error_message(context, ret,
			       N_("Unknown version number (%d) in "
				  "credential cache file: %s", ""),
			       (int)tag, FILENAME(id));
	goto out;
    }

    if (ret == 0) {
        if (ret_sp != NULL) {
            *ret_sp = sp;
            sp = NULL;
        }
        if (ret_fd != NULL) {
            *ret_fd = fd;
            fd = -1;
        }
#if 0
        {
            off_t off = krb5_storage_seek(sp, 0, SEEK_CUR);
            
            /* Ensure that fd has the correct offset */
            if (off == -1 || lseek(fd, off, SEEK_SET) == -1) {
                ret = errno;
                goto out;
            }
            krb5_storage_free(sp);
            sp = NULL;
            *ret_fd = fd;
        }
#endif
    }

out:
    if (sp != NULL)
	krb5_storage_free(sp);
    if (fd != -1)
        (void) close(fd);
    return ret;
}

static krb5_error_code KRB5_CALLCONV
fcc_get_principal(krb5_context context,
		  krb5_ccache id,
		  krb5_principal *principal)
{
    krb5_error_code ret;
    krb5_storage *sp;

    /*
     * XXX We could just return a copy of FCACHE(id)->def_princ if we have one,
     * but perhaps we want to detect changes to the file as soon as possible?
     */
    ret = init_fcc(context, id, "get-principal", &sp, NULL, NULL);
    if (ret)
	return ret;
    ret = krb5_ret_principal(sp, principal);
    if (ret)
	krb5_clear_error_message(context);
    if (ret == 0 && FCACHE(id)->def_princ != NULL) {
        krb5_free_principal(context, FCACHE(id)->def_princ);
        ret = krb5_copy_principal(context, *principal, &FCACHE(id)->def_princ);
        if (ret)
            FCACHE(id)->def_princ = NULL;
    }
    krb5_storage_free(sp);
    return ret;
}

static krb5_error_code KRB5_CALLCONV
fcc_end_get (krb5_context context,
	     krb5_ccache id,
	     krb5_cc_cursor *cursor);

static krb5_error_code KRB5_CALLCONV
fcc_get_first (krb5_context context,
	       krb5_ccache id,
	       krb5_cc_cursor *cursor)
{
    krb5_error_code ret;
    krb5_principal principal;

    if (FCACHE(id) == NULL)
        return krb5_einval(context, 2);

    *cursor = malloc(sizeof(struct fcc_cursor));
    if (*cursor == NULL) {
        krb5_set_error_message(context, ENOMEM, N_("malloc: out of memory", ""));
	return ENOMEM;
    }
    memset(*cursor, 0, sizeof(struct fcc_cursor));

    /* XXX FIX */
    ret = init_fcc(context, id, "get-first", &FCC_CURSOR(*cursor)->sp,
		   &FCC_CURSOR(*cursor)->fd, NULL);
    if (ret) {
	free(*cursor);
	*cursor = NULL;
	return ret;
    }
    ret = krb5_ret_principal (FCC_CURSOR(*cursor)->sp, &principal);
    if(ret) {
	krb5_clear_error_message(context);
	fcc_end_get(context, id, cursor);
	return ret;
    }
    if (FCACHE(id)->def_princ == NULL)
        FCACHE(id)->def_princ = principal;
    else
        krb5_free_principal (context, principal);
    return 0;
}

static krb5_error_code KRB5_CALLCONV
fcc_get_next (krb5_context context,
	      krb5_ccache id,
	      krb5_cc_cursor *cursor,
	      krb5_creds *creds)
{
    krb5_error_code ret;
#ifdef HAVE_MMAP
    const char *realm;
    const char *name0;
    const char *name1;
#endif

    if (FCACHE(id) == NULL)
        return krb5_einval(context, 2);

    if (FCC_CURSOR(*cursor) == NULL)
        return krb5_einval(context, 3);

    FCC_CURSOR(*cursor)->cred_start =
        krb5_storage_seek(FCC_CURSOR(*cursor)->sp, 0, SEEK_CUR);

    ret = krb5_ret_creds(FCC_CURSOR(*cursor)->sp, creds);
    if (ret)
	krb5_clear_error_message(context);

    FCC_CURSOR(*cursor)->cred_end =
        krb5_storage_seek(FCC_CURSOR(*cursor)->sp, 0, SEEK_CUR);
    
#ifdef HAVE_MMAP

#if defined(HAVE_SYSCONF) && defined(_SC_PAGE_SIZE)
    if (sc_page_size == 0)
        sc_page_size = sysconf(_SC_PAGE_SIZE);
#endif
    /*
     * If this is the hash table ccconfig entry then we should set the ccache's
     * tbl_off if it's not set already.
     */
    if (FCACHE(id)->tbl_off == -1 &&
        krb5_principal_get_num_comp(context, creds->server) == 2) {
        off_t off = FCC_CURSOR(*cursor)->cred_end;

        realm = krb5_principal_get_realm(context, creds->client);
        name0 = krb5_principal_get_comp_string(context, creds->client, 0);
        name1 = krb5_principal_get_comp_string(context, creds->client, 1);

        if (strcmp(realm, "X-CACHECONF:") != 0 ||
            strcmp(name0, "krb5_ccache_conf_data") != 0 ||
            strcmp(name1, "ccache_hash_table") != 0)
            goto out;

        /* Compute the offset to the hash table "ticket" payload */
        off -= creds->second_ticket.length;
        off -= sizeof(uint32_t);
        off -= creds->ticket.length;

        /* Compute the offset to mmap() in */
        off += off % (sc_page_size > 0 ? sc_page_size : 8192);
        if (off > 0) /* must be true */
            FCACHE(id)->tbl_off = off;
    }

out:
#endif /* HAVE_MMAP */

    return ret;
}

static krb5_error_code KRB5_CALLCONV
fcc_end_get (krb5_context context,
	     krb5_ccache id,
	     krb5_cc_cursor *cursor)
{

    if (FCACHE(id) == NULL)
        return krb5_einval(context, 2);

    if (FCC_CURSOR(*cursor) == NULL)
        return krb5_einval(context, 3);

    krb5_storage_free(FCC_CURSOR(*cursor)->sp);
    close (FCC_CURSOR(*cursor)->fd);
    free(*cursor);
    *cursor = NULL;
    return 0;
}

#ifdef HAVE_MMAP
static krb5_error_code KRB5_CALLCONV
fcc_retrieve(krb5_context context, krb5_ccache id,
             krb5_flags whichfields, const krb5_creds *mcreds,
             krb5_creds *out)
{
    struct fcc_hash_slot_header *slots;
    const char *realm, *name0, *name1;
    krb5_error_code ret;
    krb5_cc_cursor cursor;
    size_t i;

    ret = fcc_get_first(context, id, &cursor);
    if (ret)
        return ret;

    FCACHE(id)->fd = dup(FCC_CURSOR(cursor)->fd);

    while ((ret = fcc_get_next(context, id, &cursor, out)) == 0) {
        if (krb5_compare_creds(context, whichfields, mcreds, out)) {
            ret = 0;
            goto out;
        }

        if (krb5_principal_get_num_comp(context, out->server) < 2)
            continue;
            
        realm = krb5_principal_get_realm(context, out->client);
        name0 = krb5_principal_get_comp_string(context, out->client, 0);
        name1 = krb5_principal_get_comp_string(context, out->client, 1);
        if (realm == NULL || name0 == NULL || name1 == NULL ||
            strcmp(realm, "X-CACHECONF:") != 0 ||
            strcmp(name0, "krb5_ccache_conf_data") != 0 ||
            strcmp(name1, "ccache_hash_table") != 0)
            continue;

        slots = (void *)((char *)FCACHE(id)->tbl + FCACHE(id)->tbl->slotsz);
        for (i = 0; i < FCACHE(id)->tbl->nslots; i++) {
            if (slots[i].entrysz == 0 ||
                slots[i].entrysz > FCACHE(id)->tbl->entry_max_sz)
                continue;

            ret = tbl_get_entry(context, id, mcreds, &slots[i], out);
            if (ret == -1)
                continue;
            if (ret)
                goto out;
            /* Got one! */
            if (krb5_compare_creds(context, whichfields, mcreds, out)) {
                ret = 0;
                goto out;
            }
            krb5_free_cred_contents(context, out);
        }
    }
    ret = KRB5_CC_NOTFOUND;

out:
    (void) fcc_end_get(context, id, &cursor);
    (void) close(FCACHE(id)->fd);
    FCACHE(id)->fd = -1;
    return ret;
}
#endif

static void KRB5_CALLCONV
cred_delete(krb5_context context,
	    krb5_ccache id,
	    krb5_cc_cursor *cursor,
	    krb5_creds *cred)
{
    krb5_error_code ret;
    krb5_storage *sp;
    krb5_data orig_cred_data;
    unsigned char *cred_data_in_file = NULL;
    off_t new_cred_sz;
    struct stat sb1, sb2;
    int fd = -1;
    ssize_t bytes;
    krb5_const_realm srealm = krb5_principal_get_realm(context, cred->server);

    /* This is best-effort code; if we lose track of errors here it's OK */

    heim_assert(FCC_CURSOR(*cursor)->cred_start < FCC_CURSOR(*cursor)->cred_end,
		"fcache internal error");

    krb5_data_zero(&orig_cred_data);

    sp = krb5_storage_emem();
    if (sp == NULL)
	return;
    krb5_storage_set_eof_code(sp, KRB5_CC_END);
    storage_set_flags(context, sp, FCACHE(id)->version);

    /* Get a copy of what the cred should look like in the file; see below */
    ret = krb5_store_creds(sp, cred);
    if (ret)
	goto out;

    ret = krb5_storage_to_data(sp, &orig_cred_data);
    if (ret)
	goto out;
    krb5_storage_free(sp);

    cred_data_in_file = malloc(orig_cred_data.length);
    if (cred_data_in_file == NULL)
	goto out;

    /*
     * Mark the cred expired; krb5_cc_retrieve_cred() callers should use
     * KRB5_TC_MATCH_TIMES, so this should be good enough...
     */
    cred->times.endtime = 0;

    /* ...except for config creds because we don't check their endtimes */
    if (srealm && strcmp(srealm, "X-CACHECONF:") == 0) {
	ret = krb5_principal_set_realm(context, cred->server, "X-RMED-CONF:");
	if (ret)
	    goto out;
    }

    sp = krb5_storage_emem();
    if (sp == NULL)
	goto out;
    krb5_storage_set_eof_code(sp, KRB5_CC_END);
    storage_set_flags(context, sp, FCACHE(id)->version);

    ret = krb5_store_creds(sp, cred);

    /* The new cred must be the same size as the old cred */
    new_cred_sz = krb5_storage_seek(sp, 0, SEEK_END);
    if (new_cred_sz != orig_cred_data.length || new_cred_sz !=
	(FCC_CURSOR(*cursor)->cred_end - FCC_CURSOR(*cursor)->cred_start)) {
	/* XXX This really can't happen.  Assert like above? */
	krb5_set_error_message(context, EINVAL,
			       N_("Credential deletion failed on ccache "
				  "FILE:%s: new credential size did not "
				  "match old credential size", ""),
			       FILENAME(id));
	goto out;
    }

    ret = fcc_open(context, id, "remove_cred", &fd, O_RDWR, 0);
    if (ret)
	goto out;

    /*
     * Check that we're updating the same file where we got the
     * cred's offset, else we'd be corrupting a new ccache.
     */
    if (fstat(FCC_CURSOR(*cursor)->fd, &sb1) == -1 ||
	fstat(fd, &sb2) == -1)
	goto out;
    if (sb1.st_dev != sb2.st_dev || sb1.st_ino != sb2.st_ino)
	goto out;

    /*
     * Make sure what we overwrite is what we expected.
     *
     * FIXME: We *really* need the ccache v4 tag for ccache ID.  This
     * check that we're only overwriting something that looks exactly
     * like what we want to is probably good enough in practice, but
     * it's not guaranteed to work.
     */
    if (lseek(fd, FCC_CURSOR(*cursor)->cred_start, SEEK_SET) == (off_t)-1)
	goto out;
    bytes = read(fd, cred_data_in_file, orig_cred_data.length);
    if (bytes != orig_cred_data.length)
	goto out;
    if (memcmp(orig_cred_data.data, cred_data_in_file, bytes) != 0)
	goto out;
    if (lseek(fd, FCC_CURSOR(*cursor)->cred_start, SEEK_SET) == (off_t)-1)
	goto out;
    ret = write_storage(context, sp, fd);
out:
    if (fd > -1) {
	if (close(fd) < 0 && ret == 0) {
	    krb5_set_error_message(context, errno, N_("close %s", ""),
				   FILENAME(id));
	}
    }
    krb5_data_free(&orig_cred_data);
    free(cred_data_in_file);
    krb5_storage_free(sp);
    return;
}

static krb5_error_code KRB5_CALLCONV
fcc_remove_cred(krb5_context context,
		krb5_ccache id,
		krb5_flags which,
		krb5_creds *mcred)
{
    krb5_error_code ret, ret2;
    krb5_cc_cursor cursor;
    krb5_creds found_cred;

    if (FCACHE(id) == NULL)
	return krb5_einval(context, 2);

    ret = krb5_cc_start_seq_get(context, id, &cursor);
    if (ret)
	return ret;
    while ((ret = krb5_cc_next_cred(context, id, &cursor, &found_cred)) == 0) {
	if (!krb5_compare_creds(context, which, mcred, &found_cred)) {
            krb5_free_cred_contents(context, &found_cred);
	    continue;
        }
	cred_delete(context, id, &cursor, &found_cred);
	krb5_free_cred_contents(context, &found_cred);
    }
    ret2 = krb5_cc_end_seq_get(context, id, &cursor);
    if (ret == 0)
	return ret2;
    if (ret == KRB5_CC_END)
	return 0;
    return ret;
}

static krb5_error_code KRB5_CALLCONV
fcc_set_flags(krb5_context context,
	      krb5_ccache id,
	      krb5_flags flags)
{
    if (FCACHE(id) == NULL)
        return krb5_einval(context, 2);

    return 0; /* XXX */
}

static int KRB5_CALLCONV
fcc_get_version(krb5_context context,
		krb5_ccache id)
{
    if (FCACHE(id) == NULL)
        return -1;

    return FCACHE(id)->version;
}

struct fcache_iter {
    int first;
};

static krb5_error_code KRB5_CALLCONV
fcc_get_cache_first(krb5_context context, krb5_cc_cursor *cursor)
{
    struct fcache_iter *iter;

    iter = calloc(1, sizeof(*iter));
    if (iter == NULL) {
	krb5_set_error_message(context, ENOMEM, N_("malloc: out of memory", ""));
	return ENOMEM;
    }
    iter->first = 1;
    *cursor = iter;
    return 0;
}

static krb5_error_code KRB5_CALLCONV
fcc_get_cache_next(krb5_context context, krb5_cc_cursor cursor, krb5_ccache *id)
{
    struct fcache_iter *iter = cursor;
    krb5_error_code ret;
    const char *fn, *cc_type;
    krb5_ccache cc;

    if (iter == NULL)
        return krb5_einval(context, 2);

    if (!iter->first) {
	krb5_clear_error_message(context);
	return KRB5_CC_END;
    }
    iter->first = 0;

    /*
     * Note: do not allow krb5_cc_default_name() to recurse via
     * krb5_cc_cache_match().
     * Note that context->default_cc_name will be NULL even though
     * KRB5CCNAME is set in the environment if
     * krb5_cc_set_default_name() hasn't
     */
    fn = krb5_cc_default_name(context);
    ret = krb5_cc_resolve(context, fn, &cc);
    if (ret != 0)
        return ret;
    cc_type = krb5_cc_get_type(context, cc);
    if (strcmp(cc_type, "FILE") != 0) {
        krb5_cc_close(context, cc);
        return KRB5_CC_END;
    }

    *id = cc;

    return 0;
}

static krb5_error_code KRB5_CALLCONV
fcc_end_cache_get(krb5_context context, krb5_cc_cursor cursor)
{
    struct fcache_iter *iter = cursor;

    if (iter == NULL)
        return krb5_einval(context, 2);

    free(iter);
    return 0;
}

static krb5_error_code KRB5_CALLCONV
fcc_move(krb5_context context, krb5_ccache from, krb5_ccache to)
{
    krb5_error_code ret = 0;

    ret = rk_rename(FILENAME(from), FILENAME(to));

    if (ret && errno != EXDEV) {
	char buf[128];
	ret = errno;
	rk_strerror_r(ret, buf, sizeof(buf));
	krb5_set_error_message(context, ret,
			       N_("Rename of file from %s "
				  "to %s failed: %s", ""),
			       FILENAME(from), FILENAME(to), buf);
	return ret;
    } else if (ret && errno == EXDEV) {
	/* make a copy and delete the orignal */
	krb5_ssize_t sz1, sz2;
	int fd1, fd2;
	char buf[BUFSIZ];

	ret = fcc_open(context, from, "move/from", &fd1, O_RDONLY, 0);
	if(ret)
	    return ret;

	unlink(FILENAME(to));

	ret = fcc_open(context, to, "move/to", &fd2,
		       O_WRONLY | O_CREAT | O_EXCL, 0600);
	if(ret)
	    goto out1;

	while((sz1 = read(fd1, buf, sizeof(buf))) > 0) {
	    sz2 = write(fd2, buf, sz1);
	    if (sz1 != sz2) {
		ret = EIO;
		krb5_set_error_message(context, ret,
				       N_("Failed to write data from one file "
					  "credential cache to the other", ""));
		goto out2;
	    }
	}
	if (sz1 < 0) {
	    ret = EIO;
	    krb5_set_error_message(context, ret,
				   N_("Failed to read data from one file "
				      "credential cache to the other", ""));
	    goto out2;
	}
    out2:
	close(fd2);

    out1:
	close(fd1);

	_krb5_erase_file(context, FILENAME(from));

	if (ret) {
	    _krb5_erase_file(context, FILENAME(to));
	    return ret;
	}
    }

    /* make sure ->version is uptodate */
    {
	krb5_storage *sp;
	if ((ret = init_fcc(context, to, "move", &sp, NULL, NULL)) == 0) {
	    if (sp)
		krb5_storage_free(sp);
	}
    }

    fcc_close(context, from);

    return ret;
}

static krb5_error_code KRB5_CALLCONV
fcc_get_default_name(krb5_context context, char **str)
{
    return _krb5_expand_default_cc_name(context,
					KRB5_DEFAULT_CCNAME_FILE,
					str);
}

static krb5_error_code KRB5_CALLCONV
fcc_lastchange(krb5_context context, krb5_ccache id, krb5_timestamp *mtime)
{
    krb5_error_code ret;
    struct stat sb;
    int fd;

    ret = fcc_open(context, id, "lastchange", &fd, O_RDONLY, 0);
    if(ret)
	return ret;
    ret = fstat(fd, &sb);
    close(fd);
    if (ret) {
	ret = errno;
	krb5_set_error_message(context, ret, N_("Failed to stat cache file", ""));
	return ret;
    }
    *mtime = sb.st_mtime;
    return 0;
}

static krb5_error_code KRB5_CALLCONV
fcc_set_kdc_offset(krb5_context context, krb5_ccache id, krb5_deltat kdc_offset)
{
    return 0;
}

static krb5_error_code KRB5_CALLCONV
fcc_get_kdc_offset(krb5_context context, krb5_ccache id, krb5_deltat *kdc_offset)
{
    krb5_error_code ret;
    krb5_storage *sp = NULL;

    ret = init_fcc(context, id, "get-kdc-offset", &sp, NULL, kdc_offset);
    if (sp)
	krb5_storage_free(sp);
    return ret;
}


/**
 * Variable containing the FILE based credential cache implemention.
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_VARIABLE const krb5_cc_ops krb5_fcc_ops = {
    KRB5_CC_OPS_VERSION,
    "FILE",
    fcc_get_name,
    fcc_resolve,
    fcc_gen_new,
    fcc_initialize,
    fcc_destroy,
    fcc_close,
    fcc_store_cred,
#ifdef HAVE_MMAP
    fcc_retrieve,
#else
    NULL,
#endif
    fcc_get_principal,
    fcc_get_first,
    fcc_get_next,
    fcc_end_get,
    fcc_remove_cred,
    fcc_set_flags,
    fcc_get_version,
    fcc_get_cache_first,
    fcc_get_cache_next,
    fcc_end_cache_get,
    fcc_move,
    fcc_get_default_name,
    NULL,
    fcc_lastchange,
    fcc_set_kdc_offset,
    fcc_get_kdc_offset
};
