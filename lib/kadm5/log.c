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

#include "kadm5_locl.h"
#include "heim_threads.h"

RCSID("$Id$");

/*
 * A log consists of a sequence of records of this form:
 *
 * version number		4 bytes -\
 * time in seconds		4 bytes   +> preamble --+> header
 * operation (enum kadm_ops)	4 bytes -/             /
 * n, length of payload		4 bytes --------------+
 *      PAYLOAD DATA...		n bytes
 * n, length of payload		4 bytes ----------------+> trailer
 * version number		4 bytes ->postamble ---/
 *
 * I.e., records have a header and a trailer so that knowing the offset
 * of an record's start or end one can traverse the log forwards and
 * backwards.
 *
 * The log always starts with a nop record that contains the offset (8
 * bytes) where the next record should start after the last one, and the
 * version number and timestamp of the last record:
 *
 * offset of next new record    8 bytes
 * last record time             4 bytes
 * last record version number   4 bytes
 *
 * kadm5 write operations are done in this order:
 *
 *  - replay unconfirmed log records (there should be at most one)
 *  - write (append) and fsync() the log record for the kadm5 update
 *  - update the HDB (which includes fsync() or moral equivalent)
 *  - update the log uber record to mark the log record written as
 *    confirmed (not fsync()ed)
 *
 * This makes it possible and safe to seek to the logical end of the log
 * (that is, the end of the last confirmed record) without traversing
 * the whole log forward from offset zero.  Unconfirmed records (which
 * -currently- should never be more than one) can then be found (and
 * rolled forward) by traversing forward from the logical end of the
 * log.  The trailers make it possible to traverse the log backwards
 * from the logical end.
 *
 * This also makes the log + the HDB a two-phase commit with
 * roll-forward system.
 *
 * HDB entry exists and HDB entry does not exist errors occurring during
 * replay of unconfirmed records are ignored.  This is because the
 * corresponding HDB update might have completed.  But also because a
 * change to add aliases to a principal can fail because we don't check
 * for alias conflicts before going ahead with the write operation.
 *
 * Non-sensical and incomplete log records found during roll-forward are
 * truncated.  A log record is non-sensical if its header and trailer
 * don't match.
 *
 * Recovery (by rolling forward) occurs at the next write, not at the
 * next read.  This means that, e.g., a principal rename could fail in
 * between the store and the delete, and recovery might not take place
 * until the next write operation.
 *
 * The log record payload format for create is:
 *
 * DER-encoded HDB_entry        n bytes
 *
 * The log record payload format for update is:
 *
 * mask                         4 bytes
 * DER-encoded HDB_entry        n-4 bytes
 *
 * The log record payload format for delete is:
 *
 * krb5_store_principal         n bytes
 *
 * The log record payload format for rename is:
 *
 * krb5_store_principal         m bytes (old principal name)
 * DER-encoded HDB_entry        n-m bytes (new record)
 *
 * The log record payload format for nop varies:
 *
 *  - The zeroth record in new logs is a nop with a 16 byte payload:
 *
 *    offset of end of last confirmed record        8 bytes
 *    version number of last confirmed record       4 bytes
 *    timestamp of last confirmed record            4 bytes
 *
 *  - New non-zeroth nop records:
 *
 *    nop type                                      4 bytes
 *
 *  - Old nop records:
 *
 *    version number                                4 bytes
 *    timestamp                                     4 bytes
 */

#define LOG_HEADER_SZ   (sizeof(uint32_t) * 4)
#define LOG_TRAILER_SZ  (sizeof(uint32_t) * 2)
#define LOG_WRAPPER_SZ  (LOG_HEADER_SZ + LOG_TRAILER_SZ)
#define LOG_UBER_SZ    (sizeof(uint64_t) + sizeof(uint32_t) * 2)

/*
 * Read the header of the record starting at the current offset into sp.
 *
 * Preserves sp's offset on success if `peek', else skips the header.
 *
 * Preserves sp's offset on failure where possible.
 */
static kadm5_ret_t
get_header(krb5_storage *sp, int peek, uint32_t *verp, int32_t *tstampp,
           enum kadm_ops *opp, uint32_t *lenp)
{
    krb5_error_code ret;
    uint32_t op, len;
    int32_t tstamp;
    off_t off, new_off;

    if (tstampp == NULL)
        tstampp = &tstamp;
    if (lenp == NULL)
        lenp = &len;

    *verp = 0;
    *tstampp = 0;

    off = krb5_storage_seek(sp, 0, SEEK_CUR);
    if (off < 0)
        return errno;
    ret = krb5_ret_uint32(sp, verp);
    if (ret == HEIM_ERR_EOF) {
        (void) krb5_storage_seek(sp, off, SEEK_SET);
        return HEIM_ERR_EOF;
    }
    if (ret)
        goto log_corrupt;
    ret = krb5_ret_int32(sp, tstampp);
    if (ret)
        goto log_corrupt;

    /* Note: sizeof(*opp) might not == sizeof(op) */
    ret = krb5_ret_uint32(sp, &op);
    if (ret)
        goto log_corrupt;
    if (opp != NULL)
        *opp = op;

    ret = krb5_ret_uint32(sp, lenp);
    if (ret)
        goto log_corrupt;

    /* Restore offset if requested */
    if (peek) {
        new_off = krb5_storage_seek(sp, off, SEEK_SET);
        if (new_off == -1)
            return errno;
        if (new_off != off)
            return EIO;
    }

    return 0;

log_corrupt:
    (void) krb5_storage_seek(sp, off, SEEK_SET);
    return KADM5_LOG_CORRUPT;
}

/*
 * Seek to the start of the preceding record's header and returns its
 * offset.  If sp is at offset zero this sets *verp = 0 and returns 0.
 *
 * Does not verify the header of the previous entry.
 *
 * On error returns -1, setting errno (possibly to a kadm5_ret_t or
 * krb5_error_code value) and preserves sp's offset where possible.
 */
static off_t
seek_prev(krb5_storage *sp, uint32_t *verp, uint32_t *lenp)
{
    krb5_error_code ret;
    uint32_t len, ver;
    off_t off_len;
    off_t off, new_off;

    if (lenp == NULL)
        lenp = &len;
    if (verp == NULL)
        verp = &ver;

    *verp = 0;
    *lenp = 0;

    off = krb5_storage_seek(sp, 0, SEEK_CUR);
    if (off < 0)
        return off;
    if (off == 0)
        return 0;

    /* Check that `off' allows for the record's header and trailer */
    if (off < LOG_WRAPPER_SZ)
        goto log_corrupt;

    /* Get the previous entry's length and version from its trailer */
    new_off = krb5_storage_seek(sp, -8, SEEK_CUR);
    if (new_off == -1)
        return -1;
    if (new_off != off - 8) {
        errno = EIO;
        return -1;
    }
    ret = krb5_ret_uint32(sp, lenp);
    if (ret)
        goto log_corrupt;

    /* Check for overflow/sign extension */
    off_len = (off_t)*lenp;
    if (*lenp > INT_MAX || off_len < 0)
        goto log_corrupt;

    ret = krb5_ret_uint32(sp, verp);
    if (ret)
        goto log_corrupt;

    /* Check that `off' allows for the record */
    if (off < LOG_WRAPPER_SZ + off_len)
        goto log_corrupt;

    /* Seek backwards to the entry's start */
    new_off = krb5_storage_seek(sp, -(LOG_WRAPPER_SZ + off_len), SEEK_CUR);
    if (new_off == -1)
        return -1;
    if (new_off != off - (LOG_WRAPPER_SZ + off_len)) {
        errno = EIO;
        return -1;
    }
    return new_off;

log_corrupt:
    (void) krb5_storage_seek(sp, off, SEEK_SET);
    errno = KADM5_LOG_CORRUPT;
    return -1;
}

/*
 * Seek to the start of the next entry's header.
 *
 * On error returns -1 and preserves sp's offset.
 */
static off_t
seek_next(krb5_storage *sp)
{
    krb5_error_code ret;
    uint32_t ver, ver2, len, len2;
    enum kadm_ops op;
    int32_t tstamp;
    off_t off, off_len, new_off;

    off = krb5_storage_seek(sp, 0, SEEK_CUR);
    if (off < 0)
        return off;

    errno = get_header(sp, 0, &ver, &tstamp, &op, &len);
    if (errno)
        return -1;

    /* Check for overflow */
    off_len = len;
    if (off_len < 0)
        goto log_corrupt;

    new_off = krb5_storage_seek(sp, off_len, SEEK_CUR);
    if (new_off == -1) {
        (void) krb5_storage_seek(sp, off, SEEK_SET);
        return -1;
    }
    if (new_off != off + LOG_HEADER_SZ + off_len)
        goto log_corrupt;
    ret = krb5_ret_uint32(sp, &len2);
    if (ret || len2 != len)
        goto log_corrupt;
    ret = krb5_ret_uint32(sp, &ver2);
    if (ret || ver2 != ver)
        goto log_corrupt;
    new_off = krb5_storage_seek(sp, 0, SEEK_CUR);
    if (new_off == -1) {
        (void) krb5_storage_seek(sp, off, SEEK_SET);
        return -1;
    }
    if (new_off != off + off_len + LOG_WRAPPER_SZ)
        goto log_corrupt;

    return off + off_len + LOG_WRAPPER_SZ;

log_corrupt:
    (void) krb5_storage_seek(sp, off, SEEK_SET);
    errno = KADM5_LOG_CORRUPT;
    return -1;
}

/*
 * Get the version of the entry ending at the current offset into sp.
 *
 * Preserves sp's offset.
 */
static kadm5_ret_t
get_version_prev(krb5_storage *sp, off_t *prev_offp,
                 uint32_t *verp, int32_t *tstampp)
{
    krb5_error_code ret;
    uint32_t ver2, len, len2;
    off_t off, prev_off, new_off;

    if (prev_offp == NULL)
        prev_offp = &prev_off;

    *prev_offp = -1;
    *verp = 0;
    if (tstampp != NULL)
        *tstampp = 0;

    off = krb5_storage_seek(sp, 0, SEEK_CUR);
    if (off < 0)
        return errno;
    if (off == 0)
        return HEIM_ERR_EOF;

    /* Read the trailer and seek back */
    *prev_offp = seek_prev(sp, verp, &len);
    if (*prev_offp == -1)
        return errno;

    /* Verify that the trailer matches header */
    ret = get_header(sp, 0, &ver2, tstampp, NULL, &len2);
    if (ret || *verp != ver2 || len != len2)
        goto log_corrupt;

    /* Preserve offset */
    new_off = krb5_storage_seek(sp, off, SEEK_SET);
    if (new_off == -1)
        return errno;
    if (new_off != off) {
        errno = EIO;
        return errno;
    }
    return 0;

log_corrupt:
    (void) krb5_storage_seek(sp, off, SEEK_SET);
    return KADM5_LOG_CORRUPT;
}


/*
 * Get the version and timestamp metadata of either the uberblock,
 * first, or last confirmed entry in the log.
 *
 * If `which' is 0, then gets the uberblock's metadata.  If `which' is
 * 1, then gets the metadata afor the first entry past the uberblock.
 * If `which' is -1, then gets metadata for the last confirmed entry's
 * version and timestpamp.
 *
 * The `fd''s offset will be set to the start of the header of the entry
 * identified by `which'.
 */
kadm5_ret_t
kadm5_log_get_version_fd(kadm5_server_context *server_context, int fd,
                         int which, uint32_t *ver, int32_t *tstamp)
{
    kadm5_ret_t ret;
    krb5_storage *sp;
    int32_t tmp;

    if (fd == -1)
        return 0; /* /dev/null */

    if (tstamp == NULL)
        tstamp = &tmp;

    *ver = 0;
    *tstamp = 0;

    if (which == -1)
        sp = kadm5_log_goto_end(server_context, fd);
    else if (which == 0 || which == 1)
        sp = kadm5_log_goto_first(server_context, fd);
    else
        return ENOTSUP;

    if (sp == NULL)
	return 0;

    if (which == -1 || which == 0)
        ret = get_version_prev(sp, NULL, ver, tstamp);
    else
        ret = get_header(sp, 1, ver, tstamp, NULL, NULL);
    krb5_storage_free(sp);
    return ret;
}

/* Get the version of the last entry in the log */
kadm5_ret_t
kadm5_log_get_version(kadm5_server_context *server_context, uint32_t *ver)
{
    return kadm5_log_get_version_fd(server_context,
                                    server_context->log_context.log_fd,
                                    -1, ver, NULL);
}

/* Sets the version in the context, but NOT in the log */
kadm5_ret_t
kadm5_log_set_version(kadm5_server_context *context, uint32_t vno)
{
    kadm5_log_context *log_context = &context->log_context;

    log_context->version = vno;
    return 0;
}

static kadm5_ret_t log_recover(kadm5_server_context *);

/* Open the log and setup server_context->log_context */
static kadm5_ret_t
log_init(kadm5_server_context *server_context, uint32_t vno, int lock_mode)
{
    int fd = -1;
    int lock_it = 0;
    struct stat st;
    kadm5_ret_t ret;
    kadm5_log_context *log_context = &server_context->log_context;

    if (lock_mode == log_context->lock_mode && log_context->log_fd != -1)
        return 0;

    if (strcmp(log_context->log_file, "/dev/null") == 0) {
        /* log_context->log_fd should be -1 here */
        return 0;
    }

    if (log_context->log_fd != -1) {
        /* Lock or change lock */
        fd = log_context->log_fd;
        if (lseek(fd, 0, SEEK_SET) == -1)
            return errno;
        lock_it = (lock_mode != log_context->lock_mode);
    } else {
        /* Open and lock */
        fd = open(log_context->log_file, O_RDWR | O_CREAT, 0600);
        if (fd < 0) {
            ret = errno;
            krb5_set_error_message(server_context->context, ret,
                                   "kadm5_log_init: open %s",
                                   log_context->log_file);
            return ret;
        }
        lock_it = (lock_mode != log_context->lock_mode);
    }
    if (lock_it && flock(fd, lock_mode) < 0) {
	ret = errno;
	krb5_set_error_message(server_context->context, ret,
                               "kadm5_log_init: flock %s",
			       log_context->log_file);
        if (fd != log_context->log_fd)
            close(fd);
	return errno;
    }

    log_context->log_fd = fd;
    log_context->lock_mode = lock_mode;
    log_context->read_only = (lock_mode != LOCK_EX);

    if (!log_context->read_only)
        ret = log_recover(server_context);

    ret = kadm5_log_get_version_fd(server_context, fd, -1,
                                   &log_context->version, NULL);
    if (ret && ret != HEIM_ERR_EOF)
	return ret;

    if (vno != 0)
        log_context->version = vno;

    if (ret == HEIM_ERR_EOF) {
        if (fstat(fd, &st) == -1)
            return errno;
        if (st.st_size == 0) {
            /* Write first entry */
            ret = kadm5_log_nop(server_context, kadm_nop_plain);
            if (ret)
                return ret;
        }
        return 0;
    }

    return 0;
}

/* Open the log with an exclusive lock */
kadm5_ret_t
kadm5_log_init(kadm5_server_context *server_context)
{
    return log_init(server_context, 0, LOCK_EX);
}

/* Open the log with no locks */
kadm5_ret_t
kadm5_log_init_nolock(kadm5_server_context *server_context)
{
    return log_init(server_context, 0, LOCK_UN);
}

/* Open the log with a shared lock */
kadm5_ret_t
kadm5_log_init_sharedlock(kadm5_server_context *server_context)
{
    return log_init(server_context, 0, LOCK_SH);
}

/* Reinitialize the log and open it */
kadm5_ret_t
kadm5_log_reinit(kadm5_server_context *server_context)
{
    int ret;
    kadm5_log_context *log_context = &server_context->log_context;

    ret = log_init(server_context, log_context->version, LOCK_EX);
    if (ret)
	return ret;
    if (log_context->log_fd != -1) {
        if (ftruncate(log_context->log_fd, 0) < 0) {
            ret = errno;
            close(log_context->log_fd);
            log_context->log_fd = -1;
            return ret;
        }
        if (lseek(log_context->log_fd, 0, SEEK_SET) < 0) {
            ret = errno;
            close(log_context->log_fd);
            log_context->log_fd = -1;
            return ret;
        }
    }

    /* Write uber entry */
    ret = kadm5_log_nop(server_context, kadm_nop_trunc);
    log_context->version = 0;
    return 0;
}


/* Close the server_context->log_context. */
kadm5_ret_t
kadm5_log_end(kadm5_server_context *server_context)
{
    kadm5_log_context *log_context = &server_context->log_context;
    kadm5_ret_t ret = 0;
    int fd = log_context->log_fd;

    if (fd != -1) {
        if (log_context->lock_mode != LOCK_UN) {
            if (flock(fd, LOCK_UN) == -1 && errno == EBADF)
                ret = errno;
        }
        if (ret != EBADF && close(fd) == -1)
            ret = errno;
    }
    log_context->log_fd = -1;
    log_context->lock_mode = LOCK_UN;
    return ret;
}

/*
 * Write the version, timestamp, and op for a new entry.
 *
 * Note that the sp should be a krb5_storage_emem(), not a file.
 *
 * On success the sp's offset will be where the length of the payload
 * should be written.
 */
static kadm5_ret_t
kadm5_log_preamble(kadm5_server_context *context,
		   krb5_storage *sp,
		   enum kadm_ops op)
{
    kadm5_log_context *log_context = &context->log_context;
    kadm5_ret_t ret;

    log_context->last_time = time(NULL);
    ret = krb5_store_uint32(sp, ++log_context->version);
    if (ret)
        return ret;
    ret = krb5_store_int32(sp, log_context->last_time);
    if (ret)
        return ret;
    return krb5_store_int32(sp, op);
}

/* Writes the version part of the trailer */
static kadm5_ret_t
kadm5_log_postamble(kadm5_log_context *context,
		    krb5_storage *sp)
{
    krb5_store_int32(sp, context->version);
    return 0;
}

/*
 * Signal the ipropd-master about changes to the log.
 */
/*
 * XXX Get rid of the ifdef by having a sockaddr in log_context in both
 * cases.
 */
void
kadm5_log_signal_master(kadm5_server_context *context)
{
    kadm5_log_context *log_context = &context->log_context;
#ifndef NO_UNIX_SOCKETS
    sendto(log_context->socket_fd,
	   (void *)&log_context->version,
	   sizeof(log_context->version),
	   0,
	   (struct sockaddr *)&log_context->socket_name,
	   sizeof(log_context->socket_name));
#else
    sendto(log_context->socket_fd,
	   (void *)&log_context->version,
	   sizeof(log_context->version),
	   0,
	   log_context->socket_info->ai_addr,
	   log_context->socket_info->ai_addrlen);
#endif
}

/*
 * Write sp's contents (which must be a fully formed record, complete
 * with header, payload, and trailer) to the log and fsync the log.
 *
 * Does not free sp.
 */

static kadm5_ret_t
kadm5_log_flush(kadm5_server_context *context, krb5_storage *sp)
{
    kadm5_log_context *log_context = &context->log_context;
    kadm5_ret_t ret;
    krb5_data data;
    size_t len;
    krb5_ssize_t bytes;
    off_t off, end;

    if (strcmp(log_context->log_file, "/dev/null") == 0)
        return 0;

    ret = krb5_storage_to_data(sp, &data);
    if (ret)
        return ret;

    /* Abandon the emem storage reference */
    sp = krb5_storage_from_fd(log_context->log_fd);
    if (sp == NULL) {
        krb5_data_free(&data);
        return ENOMEM;
    }

    /* Check that we are at the end of the log and fail if not */
    off = krb5_storage_seek(sp, 0, SEEK_CUR);
    if (off == -1) {
        krb5_data_free(&data);
        krb5_storage_free(sp);
        return errno;
    }
    end = krb5_storage_seek(sp, 0, SEEK_END);
    if (end == -1) {
        krb5_data_free(&data);
        krb5_storage_free(sp);
        return errno;
    }
    if (end != off) {
        krb5_data_free(&data);
        krb5_storage_free(sp);
        return KADM5_LOG_CORRUPT;
    }

    len = data.length;
    bytes = krb5_storage_write(sp, data.data, len);
    krb5_data_free(&data);
    if (bytes < 0) {
        krb5_storage_free(sp);
	return errno;
    }
    if (bytes != (krb5_ssize_t)len) {
        krb5_storage_free(sp);
        return EIO;
    }

    ret = krb5_storage_fsync(sp);
    krb5_storage_free(sp);
    if (ret)
        return ret;

    return 0;
}

static kadm5_ret_t kadm5_log_replay_create(kadm5_server_context *,
                                           uint32_t, uint32_t,
                                           krb5_storage *);

/*
 * Add a `create' operation to the log and perform the create against
 * the HDB.
 */

kadm5_ret_t
kadm5_log_create(kadm5_server_context *context,
		 hdb_entry *ent)
{
    krb5_storage *sp;
    kadm5_ret_t ret;
    krb5_data value;
    kadm5_log_context *log_context = &context->log_context;

    sp = krb5_storage_emem();
    if (sp == NULL)
        return ENOMEM;
    ret = hdb_entry2value(context->context, ent, &value);
    if (ret) {
	krb5_storage_free(sp);
	return ret;
    }
    ret = kadm5_log_preamble(context, sp, kadm_create);
    if (ret) {
	krb5_data_free(&value);
	krb5_storage_free(sp);
	return ret;
    }
    krb5_store_int32(sp, value.length);
    krb5_storage_write(sp, value.data, value.length);
    krb5_store_int32(sp, value.length);
    ret = kadm5_log_postamble(log_context, sp);
    if (ret) {
        krb5_data_free(&value);
	krb5_storage_free(sp);
	return ret;
    }
    ret = kadm5_log_flush(context, sp);
    krb5_storage_free(sp);
    if (ret) {
        krb5_data_free(&value);
	return ret;
    }

    sp = krb5_storage_from_data(&value);
    if (sp == NULL) {
        krb5_data_free(&value);
	return ENOMEM;
    }
    ret = kadm5_log_replay_create(context, context->log_context.version,
                                  value.length, sp);
    krb5_data_free(&value);
    krb5_storage_free(sp);
    if (ret) {
        return ret;
    }
    
    /*
     * We ignore errors updating the uber entry because, after all, the HDB
     * entry got written successfully above.
     */
    (void) kadm5_log_update_uber(context);
    return ret;
}

/*
 * Read the data of a create log record from `sp' and change the
 * database.
 */
static kadm5_ret_t
kadm5_log_replay_create(kadm5_server_context *context,
		        uint32_t ver,
		        uint32_t len,
		        krb5_storage *sp)
{
    krb5_error_code ret;
    krb5_data data;
    hdb_entry_ex ent;

    memset(&ent, 0, sizeof(ent));

    ret = krb5_data_alloc (&data, len);
    if (ret) {
	krb5_set_error_message(context->context, ret, "out of memory");
	return ret;
    }
    krb5_storage_read(sp, data.data, len);
    ret = hdb_value2entry (context->context, &data, &ent.entry);
    krb5_data_free(&data);
    if (ret) {
	krb5_set_error_message(context->context, ret,
			       "Unmarshaling hdb entry in log failed, "
                               "version: %ld", (long)ver);
	return ret;
    }
    ret = context->db->hdb_store(context->context, context->db, 0, &ent);
    hdb_free_entry(context->context, &ent);
    return ret;
}

static kadm5_ret_t kadm5_log_replay_delete(kadm5_server_context *,
                                           uint32_t, uint32_t,
                                           krb5_storage *);

/*
 * Add a `delete' operation to the log.
 */

kadm5_ret_t
kadm5_log_delete(kadm5_server_context *context,
		 krb5_principal princ)
{
    krb5_storage *sp;
    kadm5_ret_t ret;
    off_t off, end_off;
    kadm5_log_context *log_context = &context->log_context;

    sp = krb5_storage_emem();
    if (sp == NULL)
	return ENOMEM;
    ret = kadm5_log_preamble(context, sp, kadm_delete);
    if (ret)
	goto out;
    ret = krb5_store_int32(sp, 0);
    if (ret)
	goto out;
    off = krb5_storage_seek(sp, 0, SEEK_CUR);
    if (off == -1) {
        ret = errno;
        goto out;
    }
    ret = krb5_store_principal(sp, princ);
    if (ret)
	goto out;
    end_off = krb5_storage_seek(sp, 0, SEEK_CUR);
    if (end_off == -1) {
        ret = errno;
        goto out;
    }
    if (end_off < off || end_off - off > INT_MAX) {
        /*
         * Can't happen.  Just making sure the compiler understands that
         * end_off - off >= 0 below.
         */
        ret = KADM5_LOG_CORRUPT;
        goto out;
    }

    /* Go back and write the payload length */
    if (krb5_storage_seek(sp, off - sizeof(uint32_t), SEEK_SET) == -1) {
        ret = errno;
        goto out;
    }
    ret = krb5_store_int32(sp, end_off - off);
    if (ret)
	goto out;
    if (krb5_storage_seek(sp, end_off, SEEK_SET) == -1) {
        ret = errno;
        goto out;
    }
    ret = krb5_store_int32(sp, end_off - off);
    if (ret)
	goto out;
    ret = kadm5_log_postamble(log_context, sp);
    if (ret)
	goto out;
    ret = kadm5_log_flush(context, sp);
    if (ret)
	goto out;

    /*
     * Lastly, kadm5_log_replay_delete() needs sp's offset to be at the
     * record's payload.
     */
    if (krb5_storage_seek(sp, off, SEEK_SET) == -1) {
        ret = errno;
        goto out;
    }
    ret = kadm5_log_replay_delete(context, context->log_context.version,
                                  end_off - off, sp);
    if (ret)
        goto out;

    (void) kadm5_log_update_uber(context);

out:
    krb5_storage_free(sp);
    return ret;
}

/*
 * Read a `delete' log operation from `sp' and apply it.
 */

static kadm5_ret_t
kadm5_log_replay_delete(kadm5_server_context *context,
		        uint32_t ver, uint32_t len, krb5_storage *sp)
{
    krb5_error_code ret;
    krb5_principal principal;

    ret = krb5_ret_principal(sp, &principal);
    if (ret) {
	krb5_set_error_message(context->context,  ret, "Failed to read deleted "
			       "principal from log version: %ld",  (long)ver);
	return ret;
    }

    ret = context->db->hdb_remove(context->context, context->db, principal);
    krb5_free_principal(context->context, principal);
    return ret;
}

static kadm5_ret_t kadm5_log_replay_rename(kadm5_server_context *,
                                           uint32_t, uint32_t,
                                           krb5_storage *);

/*
 * Add a `rename' operation to the log.
 */

kadm5_ret_t
kadm5_log_rename(kadm5_server_context *context,
		 krb5_principal source,
		 hdb_entry *ent)
{
    krb5_storage *sp;
    kadm5_ret_t ret;
    off_t off;
    off_t len;
    krb5_data value;
    kadm5_log_context *log_context = &context->log_context;

    krb5_data_zero(&value);

    sp = krb5_storage_emem();
    ret = hdb_entry2value(context->context, ent, &value);
    if (ret)
	goto failed;

    ret = kadm5_log_preamble(context, sp, kadm_rename);
    if (ret)
	goto failed;

    ret = krb5_store_int32(sp, 0);
    if (ret)
	goto failed;
    off = krb5_storage_seek(sp, 0, SEEK_CUR);
    if (off == -1) {
        ret = errno;
        goto failed;
    }
    ret = krb5_store_principal(sp, source);
    if (ret)
	goto failed;

    errno = 0;
    if (krb5_storage_write(sp, value.data, value.length) !=
        (krb5_ssize_t)value.length) {
        ret = errno ? errno : EIO;
        goto failed;
    }
    len = krb5_storage_seek(sp, 0, SEEK_CUR) - off;
    if (len < 0) {
        ret = errno;
        goto failed;
    }

    if (krb5_storage_seek(sp, -(len + 4), SEEK_CUR) == -1) {
        ret = errno;
        goto failed;
    }
    ret = krb5_store_int32(sp, len);
    if (ret)
	goto failed;

    if (krb5_storage_seek(sp, len, SEEK_CUR) == -1) {
        ret = errno;
        goto failed;
    }
    ret = krb5_store_int32(sp, len);
    if (ret)
	goto failed;

    ret = kadm5_log_postamble(log_context, sp);
    if (ret)
	goto failed;

    ret = kadm5_log_flush(context, sp);
    if (ret)
	goto failed;

    if (krb5_storage_seek(sp, off, SEEK_SET) == -1) {
        ret = errno;
        goto failed;
    }
    ret = kadm5_log_replay_rename(context, context->log_context.version,
                                  len, sp);
    if (ret)
        goto failed;
    (void) kadm5_log_update_uber(context);

failed:
    krb5_data_free(&value);
    krb5_storage_free(sp);
    return ret;
}

/*
 * Read a `rename' log operation from `sp' and apply it.
 */

static kadm5_ret_t
kadm5_log_replay_rename(kadm5_server_context *context,
		        uint32_t ver,
		        uint32_t len,
		        krb5_storage *sp)
{
    krb5_error_code ret;
    krb5_principal source;
    hdb_entry_ex target_ent;
    krb5_data value;
    off_t off;
    size_t princ_len, data_len;

    memset(&target_ent, 0, sizeof(target_ent));

    off = krb5_storage_seek(sp, 0, SEEK_CUR);
    ret = krb5_ret_principal(sp, &source);
    if (ret) {
	krb5_set_error_message(context->context, ret, "Failed to read renamed "
			       "principal in log, version: %ld", (long)ver);
	return ret;
    }
    princ_len = krb5_storage_seek(sp, 0, SEEK_CUR) - off;
    data_len = len - princ_len;
    ret = krb5_data_alloc(&value, data_len);
    if (ret) {
	krb5_free_principal (context->context, source);
	return ret;
    }
    krb5_storage_read(sp, value.data, data_len);
    ret = hdb_value2entry(context->context, &value, &target_ent.entry);
    krb5_data_free(&value);
    if (ret) {
	krb5_free_principal(context->context, source);
	return ret;
    }
    ret = context->db->hdb_store(context->context, context->db,
				 0, &target_ent);
    hdb_free_entry(context->context, &target_ent);
    if (ret) {
	krb5_free_principal(context->context, source);
	return ret;
    }
    ret = context->db->hdb_remove (context->context, context->db, source);
    krb5_free_principal(context->context, source);

    /*
     * We could try to remove the stored entry if the remove fails, but
     * such a failure seem quite unlikely.
     */
    return ret;
}

static kadm5_ret_t kadm5_log_replay_modify(kadm5_server_context *,
                                           uint32_t, uint32_t,
                                           krb5_storage *);

/*
 * Add a `modify' operation to the log.
 */

kadm5_ret_t
kadm5_log_modify(kadm5_server_context *context,
		 hdb_entry *ent,
		 uint32_t mask)
{
    krb5_storage *sp;
    kadm5_ret_t ret;
    krb5_data value;
    uint32_t len;
    off_t off;
    kadm5_log_context *log_context = &context->log_context;

    krb5_data_zero(&value);

    sp = krb5_storage_emem();
    if (sp == NULL)
        return ENOMEM;

    ret = hdb_entry2value(context->context, ent, &value);
    if (ret)
	goto failed;

    ret = kadm5_log_preamble(context, sp, kadm_modify);
    if (ret)
	goto failed;

    len = value.length + 4;
    ret = krb5_store_int32(sp, len);
    if (ret)
	goto failed;
    off = krb5_storage_seek(sp, 0, SEEK_CUR);
    if (off == -1) {
        ret = errno;
        goto failed;
    }
    ret = krb5_store_int32(sp, mask);
    if (ret)
	goto failed;
    krb5_storage_write(sp, value.data, value.length);

    ret = krb5_store_int32(sp, len);
    if (ret)
	goto failed;
    ret = kadm5_log_postamble(log_context, sp);
    if (ret)
	goto failed;
    ret = kadm5_log_flush(context, sp);
    if (ret)
	goto failed;

    if (krb5_storage_seek(sp, off, SEEK_SET) == -1) {
        ret = errno;
        goto failed;
    }
    ret = kadm5_log_replay_modify(context, context->log_context.version,
                                  len, sp);
    if (ret)
        goto failed;

    (void) kadm5_log_update_uber(context);

failed:
    krb5_data_free(&value);
    krb5_storage_free(sp);
    return ret;
}

/*
 * Read a `modify' log operation from `sp' and apply it.
 */

static kadm5_ret_t
kadm5_log_replay_modify(kadm5_server_context *context,
		        uint32_t ver,
		        uint32_t len,
		        krb5_storage *sp)
{
    krb5_error_code ret;
    int32_t mask;
    krb5_data value;
    hdb_entry_ex ent, log_ent;

    memset(&log_ent, 0, sizeof(log_ent));

    krb5_ret_int32 (sp, &mask);
    len -= 4;
    ret = krb5_data_alloc (&value, len);
    if (ret) {
	krb5_set_error_message(context->context, ret, "out of memory");
	return ret;
    }
    errno = 0;
    if (krb5_storage_read (sp, value.data, len) != (krb5_ssize_t)len) {
        ret = errno ? errno : EIO;
        return ret;
    }
    ret = hdb_value2entry (context->context, &value, &log_ent.entry);
    krb5_data_free(&value);
    if (ret)
	return ret;

    memset(&ent, 0, sizeof(ent));
    ret = context->db->hdb_fetch_kvno(context->context, context->db,
				      log_ent.entry.principal,
				      HDB_F_DECRYPT|HDB_F_ALL_KVNOS|
				      HDB_F_GET_ANY|HDB_F_ADMIN_DATA, 0, &ent);
    if (ret)
	goto out;
    if (mask & KADM5_PRINC_EXPIRE_TIME) {
	if (log_ent.entry.valid_end == NULL) {
	    ent.entry.valid_end = NULL;
	} else {
	    if (ent.entry.valid_end == NULL) {
		ent.entry.valid_end = malloc(sizeof(*ent.entry.valid_end));
		if (ent.entry.valid_end == NULL) {
		    ret = ENOMEM;
		    krb5_set_error_message(context->context, ret, "out of memory");
		    goto out;
		}
	    }
	    *ent.entry.valid_end = *log_ent.entry.valid_end;
	}
    }
    if (mask & KADM5_PW_EXPIRATION) {
	if (log_ent.entry.pw_end == NULL) {
	    ent.entry.pw_end = NULL;
	} else {
	    if (ent.entry.pw_end == NULL) {
		ent.entry.pw_end = malloc(sizeof(*ent.entry.pw_end));
		if (ent.entry.pw_end == NULL) {
		    ret = ENOMEM;
		    krb5_set_error_message(context->context, ret, "out of memory");
		    goto out;
		}
	    }
	    *ent.entry.pw_end = *log_ent.entry.pw_end;
	}
    }
    if (mask & KADM5_LAST_PWD_CHANGE) {
        krb5_warnx (context->context, "Unimplemented mask KADM5_LAST_PWD_CHANGE");
    }
    if (mask & KADM5_ATTRIBUTES) {
	ent.entry.flags = log_ent.entry.flags;
    }
    if (mask & KADM5_MAX_LIFE) {
	if (log_ent.entry.max_life == NULL) {
	    ent.entry.max_life = NULL;
	} else {
	    if (ent.entry.max_life == NULL) {
		ent.entry.max_life = malloc (sizeof(*ent.entry.max_life));
		if (ent.entry.max_life == NULL) {
		    ret = ENOMEM;
		    krb5_set_error_message(context->context, ret, "out of memory");
		    goto out;
		}
	    }
	    *ent.entry.max_life = *log_ent.entry.max_life;
	}
    }
    if ((mask & KADM5_MOD_TIME) && (mask & KADM5_MOD_NAME)) {
	if (ent.entry.modified_by == NULL) {
	    ent.entry.modified_by = malloc(sizeof(*ent.entry.modified_by));
	    if (ent.entry.modified_by == NULL) {
		ret = ENOMEM;
		krb5_set_error_message(context->context, ret, "out of memory");
		goto out;
	    }
	} else
	    free_Event(ent.entry.modified_by);
	ret = copy_Event(log_ent.entry.modified_by, ent.entry.modified_by);
	if (ret) {
	    krb5_set_error_message(context->context, ret, "out of memory");
	    goto out;
	}
    }
    if (mask & KADM5_KVNO) {
	ent.entry.kvno = log_ent.entry.kvno;
    }
    if (mask & KADM5_MKVNO) {
        krb5_warnx(context->context, "Unimplemented mask KADM5_KVNO");
    }
    if (mask & KADM5_AUX_ATTRIBUTES) {
        krb5_warnx(context->context, "Unimplemented mask KADM5_AUX_ATTRIBUTES");
    }
    if (mask & KADM5_POLICY_CLR) {
        krb5_warnx(context->context, "Unimplemented mask KADM5_POLICY_CLR");
    }
    if (mask & KADM5_MAX_RLIFE) {
	if (log_ent.entry.max_renew == NULL) {
	    ent.entry.max_renew = NULL;
	} else {
	    if (ent.entry.max_renew == NULL) {
		ent.entry.max_renew = malloc (sizeof(*ent.entry.max_renew));
		if (ent.entry.max_renew == NULL) {
		    ret = ENOMEM;
		    krb5_set_error_message(context->context, ret, "out of memory");
		    goto out;
		}
	    }
	    *ent.entry.max_renew = *log_ent.entry.max_renew;
	}
    }
    if (mask & KADM5_LAST_SUCCESS) {
        krb5_warnx(context->context, "Unimplemented mask KADM5_LAST_SUCCESS");
    }
    if (mask & KADM5_LAST_FAILED) {
        krb5_warnx(context->context, "Unimplemented mask KADM5_LAST_FAILED");
    }
    if (mask & KADM5_FAIL_AUTH_COUNT) {
        krb5_warnx(context->context, "Unimplemented mask KADM5_FAIL_AUTH_COUNT");
    }
    if (mask & KADM5_KEY_DATA) {
	size_t num;
	size_t i;

	/*
	 * We don't need to do anything about key history here because
	 * the log entry contains a complete entry, including hdb
	 * extensions.  We do need to make sure that KADM5_TL_DATA is in
	 * the mask though, since that's what it takes to update the
	 * extensions (see below).
	 */
	mask |= KADM5_TL_DATA;

	for (i = 0; i < ent.entry.keys.len; ++i)
	    free_Key(&ent.entry.keys.val[i]);
	free (ent.entry.keys.val);

	num = log_ent.entry.keys.len;

	ent.entry.keys.len = num;
	ent.entry.keys.val = malloc(len * sizeof(*ent.entry.keys.val));
	if (ent.entry.keys.val == NULL) {
	    krb5_set_error_message(context->context, ENOMEM, "out of memory");
	    return ENOMEM;
	}
	for (i = 0; i < ent.entry.keys.len; ++i) {
	    ret = copy_Key(&log_ent.entry.keys.val[i],
			   &ent.entry.keys.val[i]);
	    if (ret) {
		krb5_set_error_message(context->context, ret, "out of memory");
		goto out;
	    }
	}
    }
    if ((mask & KADM5_TL_DATA) && log_ent.entry.extensions) {
	HDB_extensions *es = ent.entry.extensions;

	ent.entry.extensions = calloc(1, sizeof(*ent.entry.extensions));
	if (ent.entry.extensions == NULL)
	    goto out;

	ret = copy_HDB_extensions(log_ent.entry.extensions,
				  ent.entry.extensions);
	if (ret) {
	    krb5_set_error_message(context->context, ret, "out of memory");
	    free(ent.entry.extensions);
	    ent.entry.extensions = es;
	    goto out;
	}
	if (es) {
	    free_HDB_extensions(es);
	    free(es);
	}
    }
    ret = context->db->hdb_store(context->context, context->db,
				 HDB_F_REPLACE, &ent);
 out:
    hdb_free_entry(context->context, &ent);
    hdb_free_entry(context->context, &log_ent);
    return ret;
}

/*
 * Update the first entry (which should be a `nop'), the "uber-entry".
 */

kadm5_ret_t
kadm5_log_update_uber(kadm5_server_context *context)
{
    kadm5_log_context *log_context = &context->log_context;
    kadm5_ret_t ret = 0;
    krb5_storage *sp, *mem_sp;
    krb5_data data;
    uint32_t op, len;
    ssize_t bytes;
    off_t off;

    if (strcmp(log_context->log_file, "/dev/null") == 0)
        return 0;

    if (log_context->read_only)
        return EROFS;

    krb5_data_zero(&data);

    /* We'll leave log_fd offset where it was */
    off = lseek(log_context->log_fd, 0, SEEK_CUR);
    if (off == -1)
        return errno;

    mem_sp = krb5_storage_emem();
    if (mem_sp == NULL)
        return ENOMEM;

    sp = krb5_storage_from_fd(log_context->log_fd);
    if (sp == NULL) {
        krb5_storage_free(mem_sp);
        return ENOMEM;
    }

    /* Skip first entry's version and timestamp */
    if (krb5_storage_seek(sp, 8, SEEK_SET) == -1) {
        ret = errno;
        goto out;
    }

    /* If the first entry is not a nop, there's nothing we can do here */
    ret = krb5_ret_uint32(sp, &op);
    if (ret || op != kadm_nop)
        goto out;

    /* If the first entry is not a 16-byte nop, ditto */
    ret = krb5_ret_uint32(sp, &len);
    if (ret || len != LOG_UBER_SZ)
        goto out;

    /*
     * Try to make the writes here as close to atomic as possible: a
     * single write() call.
     */
    ret = krb5_store_uint64(mem_sp, off);
    if (ret)
        goto out;
    ret = krb5_store_int32(mem_sp, log_context->last_time);
    if (ret)
        goto out;
    ret = krb5_store_uint32(mem_sp, log_context->version);
    if (ret)
        goto out;

    krb5_storage_to_data(mem_sp, &data);
    bytes = krb5_storage_write(sp, data.data, data.length);
    if (bytes < 0)
        ret = errno;
    else if (bytes != data.length)
        ret = EIO;

    /*
     * We don't fsync() this write because we can recover if the write
     * doesn't complete, though for now we don't have code for properly
     * dealing with the offset not getting written completely.
     *
     * We should probably have two copies of the offset so we can use
     * one copy to verify the other, and when they don't match we could
     * traverse the whole log forwards, replaying just the last entry.
     */

out:
    if (ret == 0)
        kadm5_log_signal_master(context);
    krb5_data_free(&data);
    krb5_storage_free(sp);
    krb5_storage_free(mem_sp);
    if (lseek(log_context->log_fd, off, SEEK_SET) == -1)
        ret = ret ? ret : errno;

    return ret;
}

/*
 * Add a `nop' operation to the log. Does not close the log.
 */

kadm5_ret_t
kadm5_log_nop(kadm5_server_context *context, enum kadm_nop_type nop_type)
{
    krb5_storage *sp;
    kadm5_ret_t ret;
    kadm5_log_context *log_context = &context->log_context;
    off_t off;

    off = lseek(log_context->log_fd, 0, SEEK_CUR);
    if (off == -1)
        return errno;

    // size of nop = 4 (bytes in int) * (3 (preamble) + 1 (postamble) + 2 (lengths) + 2 (offset) + 1 (version) + 1 (time))

    sp = krb5_storage_emem();
    ret = kadm5_log_preamble(context, sp, kadm_nop);
    if (ret)
        goto out;

    if (off == 0) {
        /*
         * First entry (uber-entry) gets room for offset of next new
         * entry and time and version of last entry.
         */
        ret = krb5_store_uint32(sp, LOG_UBER_SZ);
        if (ret)
            goto out;
        /* These get overwritten with the same values below */
        ret = krb5_store_uint64(sp, LOG_WRAPPER_SZ + LOG_UBER_SZ);
        if (ret)
            goto out;
        ret = krb5_store_int32(sp, log_context->last_time); /* This is now here */
        if (ret)
            goto out;
        ret = krb5_store_uint32(sp, log_context->version);
        if (ret)
            goto out;
        ret = krb5_store_uint32(sp, LOG_UBER_SZ);
        if (ret)
            goto out;
        assert(krb5_storage_seek(sp, 0, SEEK_CUR) ==
               LOG_WRAPPER_SZ + LOG_UBER_SZ - sizeof(uint32_t) /* version */);
    } else if (nop_type == kadm_nop_plain) {
        ret = krb5_store_uint32(sp, 0);
        if (ret)
            goto out;
        ret = krb5_store_uint32(sp, 0);
        if (ret)
            goto out;
    } else {
        ret = krb5_store_uint32(sp, sizeof(uint32_t));
        if (ret)
            goto out;
        ret = krb5_store_uint32(sp, nop_type);
        if (ret)
            goto out;
        ret = krb5_store_uint32(sp, sizeof(uint32_t));
        if (ret)
            goto out;
    }

    ret = kadm5_log_postamble(log_context, sp);
    if (ret)
        goto out;

    ret = kadm5_log_flush(context, sp);
    if (ret)
        goto out;

    /* Overwrite uber-entry anyways */
    ret = kadm5_log_update_uber(context);

    if (off == 0 && nop_type != kadm_nop_plain)
        (void) kadm5_log_nop(context, nop_type); /* shouldn't happen */

out:
    krb5_storage_free(sp);
    return ret;
}

/*
 * Read a `nop' log operation from `sp' and "apply" it (there's nothing
 * to do).
 *
 * FIXME Actually, if the nop payload is 4 bytes and contains an enum
 * kadm_nop_type value of kadm_nop_trunc then we should truncate the
 * log, and if it contains a kadm_nop_close then we should rename a new
 * log into place.  However, this is not implemented yet.
 */

static kadm5_ret_t
kadm5_log_replay_nop(kadm5_server_context *context,
		     uint32_t ver,
		     uint32_t len,
		     krb5_storage *sp)
{
    if (krb5_storage_seek(sp, len, SEEK_CUR) == -1)
        return errno;
    return 0;
}

struct replay_cb_data {
    size_t count;
    uint32_t ver;
};

static kadm5_ret_t
recover_replay(kadm5_server_context *context,
               uint32_t ver, time_t timestamp, enum kadm_ops op,
               uint32_t len, krb5_storage *sp, void *ctx)
{
    struct replay_cb_data *data = ctx;
    kadm5_ret_t ret;

    /* Replaying can fail, but in this context we have to ignore errors */
    ret = kadm5_log_replay(context, op, ver, len, sp);
    data->count++;
    data->ver = ver;
    switch (ret) {
    case KADM5_LOG_CORRUPT:
    case HDB_ERR_NOENTRY:
    case HDB_ERR_EXISTS:
    case 0:
        break;
    default:
        krb5_warn(context->context, ret, "unexpected error while replaying");
        break;
    }
    if (ret == KADM5_LOG_CORRUPT)
        return -1;
    if (ret != HDB_ERR_NOENTRY && ret != HDB_ERR_EXISTS)
        return ret;
    return 0;
}


static kadm5_ret_t
log_recover(kadm5_server_context *context)
{
    kadm5_ret_t ret;
    krb5_storage *sp;
    struct replay_cb_data replay_data;

    replay_data.count = 0;
    replay_data.ver = 0;

    sp = kadm5_log_goto_end(context, context->log_context.log_fd);
    if (sp == NULL)
        return errno ? errno : EIO;

    ret = kadm5_log_foreach(context, kadm_forward | kadm_unconfirmed,
                            NULL, recover_replay, &replay_data);
    if (ret)
        goto out;
    if (replay_data.count > 0) {
        krb5_warnx(context->context, "Unconfirmed log entries "
                   "(%llu) replayed", (unsigned long long)replay_data.count);

        /* Update the log to note the latest version */
        kadm5_log_set_version(context, replay_data.ver);
        ret = kadm5_log_update_uber(context);
    }

out:
    krb5_storage_free(sp);
    return ret;
}

/*
 * Call `func' for each log record in the log in `context'.
 *
 * `func' is optional.
 *
 * If `func' returns -1 then log traversal terminates and this returns
 * 0.  Otherwise `func''s return is returned if there are no other
 * errors.
 */

kadm5_ret_t
kadm5_log_foreach(kadm5_server_context *context,
                  enum kadm_iter_opts iter_opts,
                  off_t *off_last,
		  kadm5_ret_t (*func)(kadm5_server_context *server_context,
                                      uint32_t ver, time_t timestamp,
                                      enum kadm_ops op, uint32_t len,
                                      krb5_storage *sp, void *ctx),
		  void *ctx)
{
    kadm5_ret_t ret = 0;
    int fd = context->log_context.log_fd;
    krb5_storage *sp;
    off_t this_entry = 0;
    off_t log_end = 0;

    if (strcmp(context->log_context.log_file, "/dev/null") == 0)
        return 0;

    if (off_last != NULL)
        *off_last = -1;

    if (((iter_opts & kadm_forward) && (iter_opts & kadm_backward)) ||
        (!(iter_opts & kadm_confirmed) && !(iter_opts & kadm_unconfirmed)))
        return EINVAL;

    if ((iter_opts & kadm_forward) && (iter_opts & kadm_confirmed) && (iter_opts & kadm_unconfirmed)) {
        /*
         * We want to traverse all log entries, confirmed or not, from
         * the start, then there's no need to kadm5_log_goto_end()
         * -- no reason to try to find the end.
         */
        sp = krb5_storage_from_fd(fd);
        if (sp == NULL)
            return errno;

        log_end = krb5_storage_seek(sp, 0, SEEK_END);
        if (log_end == -1 ||
            krb5_storage_seek(sp, 0, SEEK_SET) == -1) {
            ret = errno;
            krb5_storage_free(sp);
            return ret;
        }
    } else {
        /* Get the end of the log based on the uber entry */
        sp = kadm5_log_goto_end(context, fd);
        if (sp == NULL)
            return errno;
        log_end = krb5_storage_seek(sp, 0, SEEK_CUR);
    }

    if (off_last != NULL)
        *off_last = log_end;

    if ((iter_opts & kadm_forward) && (iter_opts & kadm_confirmed)) {
        /* Start at the beginning */
        if (krb5_storage_seek(sp, 0, SEEK_SET) == -1) {
            ret = errno;
            krb5_storage_free(sp);
            return ret;
        }
    } else if ((iter_opts & kadm_backward) && (iter_opts & kadm_unconfirmed)) {
        /*
         * XXX This codepath is not used, therefore not tested.  Kill
         * it?  Or make iprop-log's dump support backward scanning?
         * That might be useful for very large logs.
         */
        /*
         * We're at the confirmed end but need to be at the unconfirmed
         * end.  Skip forward to the real end, re-entering to do it.
         */
        ret = kadm5_log_foreach(context, kadm_forward | kadm_unconfirmed,
                                &log_end, NULL, NULL);
        if (ret)
            return ret;
        if (krb5_storage_seek(sp, log_end, SEEK_SET) == -1) {
            ret = errno;
            krb5_storage_free(sp);
            return ret;
        }
    }

    for (;;) {
	uint32_t ver, ver2, len, len2;
	int32_t tstamp;
        time_t timestamp;
        enum kadm_ops op;

        if ((iter_opts & kadm_backward)) {
            off_t o;

            if (krb5_storage_seek(sp, 0, SEEK_CUR) == 0)
                break;
            ret = kadm5_log_previous(context->context, sp, &ver, &timestamp, &op, &len);
            if (ret)
                break;

            /* Offset is now at payload of current entry */

            o = krb5_storage_seek(sp, 0, SEEK_CUR);
            if (o == -1) {
                ret = errno;
                break;
            }
            this_entry = o - LOG_HEADER_SZ;
            if (this_entry < 0) {
                ret = KADM5_LOG_CORRUPT;
                break;
            }
        } else {
            /* Offset is now at start of current entry, read header */
            this_entry = krb5_storage_seek(sp, 0, SEEK_CUR);
            if (!(iter_opts & kadm_unconfirmed) && this_entry == log_end)
                break;
            ret = get_header(sp, 0, &ver, &tstamp, &op, &len);
            if (ret == HEIM_ERR_EOF) {
                ret = 0;
                break;
            }
            if (ret)
                break;
            /* Offset is now at payload of current entry */
        }

        /* Validate trailer before calling the callback */
        if (krb5_storage_seek(sp, len, SEEK_CUR) == -1) {
            ret = errno;
            break;
        }

	ret = krb5_ret_uint32(sp, &len2);
        if (ret)
            break;
	ret = krb5_ret_uint32(sp, &ver2);
        if (ret)
            break;
	if (len != len2 || ver != ver2) {
            ret = KADM5_LOG_CORRUPT;
	    break;
        }

        /* Rewind to start of payload and call callback if we have one */
        if (krb5_storage_seek(sp, this_entry + LOG_HEADER_SZ, SEEK_SET) == -1) {
            ret = errno;
            break;
        }

        if (func != NULL) {
            off_t o;
            ret = (*func)(context, ver, timestamp, op, len, sp, ctx);
            if (ret) {
                if (ret == -1)
                    ret = 0;
                break;
            }
            o = krb5_storage_seek(sp, 0, SEEK_CUR);
            if (o == -1) {
                ret = errno;
                break;
            }
            if (o != this_entry + LOG_HEADER_SZ + len) {
                ret = EINVAL;
                krb5_set_error_message(context->context, ret,
                                       "kadm5_log_foreach() callback did "
                                       "not consume log entry");
                break;
            }
        } else {
            /* No callback -> skip len bytes */
            if (krb5_storage_seek(sp, len, SEEK_CUR) == 0) {
                ret = errno;
                break;
            }
        }
        if ((iter_opts & kadm_forward)) {
            off_t o;

            /* Forward past the trailer */
            o = krb5_storage_seek(sp, 8, SEEK_CUR);
            if (o == -1) {
                ret = errno;
                break;
            }
            if (off_last != NULL && o > log_end)
                *off_last = o;
        } else if ((iter_opts & kadm_backward)) {
            /*
             * Rewind to the start of this entry so kadm5_log_previous()
             * can find the previous one.
             */
            if (krb5_storage_seek(sp, this_entry, SEEK_SET) == -1) {
                ret = errno;
                break;
            }
        }
    }
    if ((ret == HEIM_ERR_EOF || ret == KADM5_LOG_CORRUPT) &&
        (iter_opts & kadm_forward) &&
        context->log_context.lock_mode == LOCK_EX) {
        /*
         * Truncate partially written last log entry so we can write
         * again.
         */
        ret = krb5_storage_truncate(sp, this_entry);
        if (ret == 0 &&
            krb5_storage_seek(sp, this_entry, SEEK_SET) == -1)
            ret = errno;
        krb5_warnx(context->context, "Truncating log at partial or "
                   "corrupt %s entry",
                   this_entry > log_end ? "unconfirmed" : "confirmed");
    }
    krb5_storage_free(sp);
    return ret;
}

krb5_storage *
kadm5_log_goto_first(kadm5_server_context *server_context, int fd)
{
    krb5_storage *sp;

    if (fd == -1) {
        errno = EINVAL;
        return NULL;
    }

    sp = krb5_storage_from_fd(fd);
    if (sp == NULL)
        return NULL;

    if (krb5_storage_seek(sp, 0, SEEK_SET) == -1)
        return NULL;

    if (seek_next(sp) == -1) {
        krb5_storage_free(sp);
        return NULL;
    }
    return sp;
}

/*
 * Go to end of log.
 *
 * XXX This really needs to return a kadm5_ret_t and either output a
 * krb5_storage * via an argument, or take one as input.
 */

krb5_storage *
kadm5_log_goto_end(kadm5_server_context *server_context, int fd)
{
    krb5_error_code ret = 0;
    krb5_storage *sp;
    enum kadm_ops op;
    uint32_t ver, len;
    int32_t tstamp;
    uint64_t off;

    if (fd == -1) {
        errno = EINVAL;
        return NULL;
    }

    sp = krb5_storage_from_fd(fd);
    if (sp == NULL)
        return NULL;

    if (krb5_storage_seek(sp, 0, SEEK_SET) == -1) {
        ret = errno;
        goto fail;
    }
    ret = get_header(sp, 0, &ver, &tstamp, &op, &len);
    if (ret == HEIM_ERR_EOF) {
        (void) krb5_storage_seek(sp, 0, SEEK_SET);
        return sp;
    }
    if (ret == KADM5_LOG_CORRUPT)
        goto truncate;
    if (ret)
        goto fail;

    if (op == kadm_nop && len == LOG_UBER_SZ) {
        off_t cur;

        /* New style log */
        ret = krb5_ret_uint64(sp, &off);
        if (ret)
            goto truncate;
        
        cur = krb5_storage_seek(sp, 0, SEEK_CUR);
        if (cur == -1)
            goto fail;

        if (krb5_storage_seek(sp, off, SEEK_SET) == -1)
            goto fail;

        if (off >= cur + LOG_TRAILER_SZ)
            return sp;
        /* Invalid offset in uber entry */
    }

    /* Old log or invalid offset in uber entry */
    if (krb5_storage_seek(sp, 0, SEEK_END) == -1) {
        krb5_warnx(server_context->context,
                   "Old log found; truncate it to upgrade");
        return sp;
    }
    return sp;

truncate:
    /* If we can, truncate */
    if (server_context->log_context.lock_mode == LOCK_EX) {
        ret = kadm5_log_reinit(server_context);
        if (ret == 0) {
            krb5_warn(server_context->context, ret,
                      "Invalid log; truncating to recover");
            if (krb5_storage_seek(sp, 0, SEEK_END) == -1)
                return NULL;
            return sp;
        }
    }
    krb5_warn(server_context->context, ret,
              "Invalid log; truncate to recover");

fail:
    errno = ret;
    krb5_storage_free(sp);
    return NULL;
}

/*
 * Return previous log entry.
 *
 * The pointer in `sp' is assumed to be at the top of the entry after
 * previous entry (e.g., at EOF).  On success, the `sp' pointer is set to
 * data portion of previous entry.  In case of error, it's not changed
 * at all.
 */
kadm5_ret_t
kadm5_log_previous(krb5_context context,
		   krb5_storage *sp,
		   uint32_t *verp,
		   time_t *tstampp,
		   enum kadm_ops *opp,
		   uint32_t *lenp)
{
    krb5_error_code ret;
    off_t oldoff;
    uint32_t ver2, len2;
    int32_t tstamp;

    oldoff = krb5_storage_seek(sp, 0, SEEK_CUR);
    if (oldoff == -1)
        goto log_corrupt;

    if (seek_prev(sp, verp, lenp) == -1)
        goto log_corrupt;

    ret = get_header(sp, 0, &ver2, &tstamp, opp, &len2);
    if (ret) {
        (void) krb5_storage_seek(sp, oldoff, SEEK_SET);
        return ret;
    }
    if (tstampp)
        *tstampp = tstamp;
    if (ver2 != *verp || len2 != *lenp)
        goto log_corrupt;

    return 0;

log_corrupt:
    (void) krb5_storage_seek(sp, oldoff, SEEK_SET);
    return KADM5_LOG_CORRUPT;
}

/*
 * Replay a record from the log
 */

kadm5_ret_t
kadm5_log_replay(kadm5_server_context *context,
		 enum kadm_ops op,
		 uint32_t ver,
		 uint32_t len,
		 krb5_storage *sp)
{
    switch (op) {
    case kadm_create :
	return kadm5_log_replay_create(context, ver, len, sp);
    case kadm_delete :
	return kadm5_log_replay_delete(context, ver, len, sp);
    case kadm_rename :
	return kadm5_log_replay_rename(context, ver, len, sp);
    case kadm_modify :
	return kadm5_log_replay_modify(context, ver, len, sp);
    case kadm_nop :
	return kadm5_log_replay_nop(context, ver, len, sp);
    default :
        /*
         * FIXME This default arm makes it difficult to add new kadm_ops
         *       values.
         */
	krb5_set_error_message(context->context, KADM5_FAILURE,
			       "Unsupported replay op %d", (int)op);
        (void) krb5_storage_seek(sp, len, SEEK_CUR);
	return KADM5_FAILURE;
    }
}

struct load_entries_data {
    krb5_data *entries;
    unsigned char *p;
    uint32_t from_vno;
    size_t nentries;
    size_t bytes;
};

static kadm5_ret_t
load_entries_cb(kadm5_server_context *server_context,
            uint32_t ver,
            time_t timestamp,
            enum kadm_ops op,
            uint32_t len,
            krb5_storage *sp,
            void *ctx)
{
    struct load_entries_data *entries = ctx;
    kadm5_ret_t ret;
    ssize_t bytes;

    /* Offset is at start of payload */

    if (entries->from_vno == 0 && entries->nentries == 0)
        return -1; /* stop iteration */

    if (entries->nentries > 0)
        entries->nentries--;

    if (ver < entries->from_vno)
        return -1; /* stop iteration (we're going backwards) */
    
    if (entries->entries == NULL) {
        /*
         * First find the size of krb5_data buffer needed.
         *
         * If the log was huge we'd have to perhaps open a temp file for
         * this.  For now KISS.
         */
        if (krb5_storage_seek(sp, len, SEEK_CUR) == -1)
            return errno;
        entries->bytes += len + 6 * 4;
        return 0;
    }

    if (entries->p == NULL)
        entries->p = (unsigned char *)entries->entries->data + entries->bytes;

    /*
     * We'll read the header, payload, and trailer into the buffer we
     * have, that many bytes before the previous entry we read.
     */
    entries->p -= len + 6 * 4;

    if (entries->p < (unsigned char *)entries->entries->data) {
        /*
         * This can't happen normally: we stop the log entry iteration
         * above before we get here.  This could happen if someone wrote
         * garbage to the log while we were traversing it.  We return an
         * error instead of asserting.
         */
        return KADM5_LOG_CORRUPT; }

    /*
     * sp here is a krb5_storage_from_fd() of the log file, and the
     * offset pointer points at the current log entry payload.
     *
     * Seek back to the start of the entry.
     */
    if (krb5_storage_seek(sp, -4 * 4, SEEK_CUR) == -1)
        return errno;

    /* Read the whole entry (header, payload, trailer) */
    errno = 0;
    bytes = krb5_storage_read(sp, entries->entries->data, len + 6 * 4);
    ret = errno;

    if (bytes != len + 6 * 4)
        return ret ? ret : EIO;

    /*
     * Now the offset is at the end of the entry, but it needs to be at
     * the end of the entry's payload.
     */
    if (krb5_storage_seek(sp, -2 * 4, SEEK_CUR) == -1)
        ret = errno;
    return 0;
}

static kadm5_ret_t
load_entries(kadm5_server_context *context, krb5_data *p,
             size_t nentries, uint32_t from_vno)
{
    struct load_entries_data entries;
    kadm5_ret_t ret;

    if (nentries == 0 && from_vno == 0)
        return 0;

    entries.entries = NULL;
    entries.p = NULL;
    entries.nentries = nentries;
    entries.bytes = 0;
    entries.from_vno = from_vno;

    /* Figure out how many bytes it will take */
    ret = kadm5_log_foreach(context, kadm_backward | kadm_confirmed,
                            NULL, load_entries_cb, &entries);
    if (ret)
        return ret;

    entries.nentries = nentries;
    entries.entries = p;

    if (entries.bytes > INT_MAX)
        return E2BIG;   /* XXX */

    ret = krb5_data_alloc(p, entries.bytes);
    if (ret)
        return ret;

    if (entries.bytes == 0)
        return ret;

    /* Now load */
    ret = kadm5_log_foreach(context, kadm_backward | kadm_confirmed,
                            NULL, load_entries_cb, &entries);
    if (ret) {
        krb5_data_free(p);
        krb5_data_zero(p);
    }
    return ret;
}

static kadm5_ret_t
write_entries(kadm5_server_context *context, krb5_data *entries)
{
    kadm5_ret_t ret;
    krb5_storage *sp;

    if (entries->length == 0)
        return 0;

    sp = krb5_storage_from_data(entries);
    ret = kadm5_log_flush(context, sp);
    krb5_storage_free(sp);
    if (ret)
        return ret;

    return kadm5_log_update_uber(context);
}

/*
 * truncate the log - i.e. create an empty file with just (nop vno + 2)
 *
 * Does not require that the caller have called kadm5_log_init().
 */

kadm5_ret_t
kadm5_log_truncate(kadm5_server_context *server_context,
                   size_t keep, uint32_t from_vno, int recover)
{
    kadm5_ret_t ret;
    uint32_t vno;
    krb5_data entries;

    krb5_data_zero(&entries);

    ret = kadm5_log_init(server_context);
    if (ret)
	return ret;

    if (strcmp(server_context->log_context.log_file, "/dev/null") == 0)
        return 0;

    ret = kadm5_log_get_version(server_context, &vno);
    if (ret)
	return ret;

    if (from_vno > 0 && from_vno > vno)
        from_vno = vno;

    if (recover) {
        ret = log_recover(server_context);
        if (ret)
            return ret;
    }

    ret = load_entries(server_context, &entries, keep,
                       from_vno ? from_vno + 1 : 0);
    if (ret)
        return ret;

    ret = kadm5_log_reinit(server_context);
    if (ret)
	return ret;

    ret = kadm5_log_set_version(server_context, vno);
    if (ret) {
        krb5_data_free(&entries);
	return ret;
    }

    /* This nop will have `vno' as its version number */
    ret = kadm5_log_nop(server_context, kadm_nop_trunc);
    if (ret) {
        krb5_data_free(&entries);
	return ret;
    }

    ret = write_entries(server_context, &entries);
    krb5_data_free(&entries);
    if (ret) {
        krb5_warn(server_context->context, ret, "Unable to keep entries");
        return kadm5_log_truncate(server_context, 0, 0, 0);
    }

    return 0;

}

#ifndef NO_UNIX_SOCKETS

static char *default_signal = NULL;
static HEIMDAL_MUTEX signal_mutex = HEIMDAL_MUTEX_INITIALIZER;

const char *
kadm5_log_signal_socket(krb5_context context)
{
    int ret = 0;

    HEIMDAL_MUTEX_lock(&signal_mutex);
    if (!default_signal)
	ret = asprintf(&default_signal, "%s/signal", hdb_db_dir(context));
    if (ret == -1)
	default_signal = NULL;
    HEIMDAL_MUTEX_unlock(&signal_mutex);

    return krb5_config_get_string_default(context,
					  NULL,
					  default_signal,
					  "kdc",
					  "signal_socket",
					  NULL);
}

#else  /* NO_UNIX_SOCKETS */

#define SIGNAL_SOCKET_HOST "127.0.0.1"
#define SIGNAL_SOCKET_PORT "12701"

kadm5_ret_t
kadm5_log_signal_socket_info(krb5_context context,
			     int server_end,
			     struct addrinfo **ret_addrs)
{
    struct addrinfo hints;
    struct addrinfo *addrs = NULL;
    kadm5_ret_t ret = KADM5_FAILURE;
    int wsret;

    memset(&hints, 0, sizeof(hints));

    hints.ai_flags = AI_NUMERICHOST;
    if (server_end)
	hints.ai_flags |= AI_PASSIVE;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    wsret = getaddrinfo(SIGNAL_SOCKET_HOST,
			SIGNAL_SOCKET_PORT,
			&hints, &addrs);

    if (wsret != 0) {
	krb5_set_error_message(context, KADM5_FAILURE,
			       "%s", gai_strerror(wsret));
	goto done;
    }

    if (addrs == NULL) {
	krb5_set_error_message(context, KADM5_FAILURE,
			       "getaddrinfo() failed to return address list");
	goto done;
    }

    *ret_addrs = addrs;
    addrs = NULL;
    ret = 0;

 done:
    if (addrs)
	freeaddrinfo(addrs);
    return ret;
}

#endif
