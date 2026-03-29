/*
 * Copyright (c) 1997-2008 Kungliga Tekniska Högskolan
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
 * heim_storage -- serialization/deserialization abstraction.
 * Derived from krb5_storage.  All integers stored in big-endian.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "heim_storage.h"

/* Internal structure -- matches the public opaque typedef. */
struct heim_storage_data {
    void *data;
    ssize_t (*fetch)(struct heim_storage_data *, void *, size_t);
    ssize_t (*store)(struct heim_storage_data *, const void *, size_t);
    off_t   (*seek)(struct heim_storage_data *, off_t, int);
    int     (*trunc)(struct heim_storage_data *, off_t);
    void    (*free)(struct heim_storage_data *);
    int     eof_code;
    size_t  max_alloc;
};

#ifndef HEIM_ERR_EOF
#define HEIM_ERR_EOF (-1553)
#endif
#ifndef HEIM_ERR_TOO_BIG
#define HEIM_ERR_TOO_BIG (-1554)
#endif
#ifndef HEIM_ERR_NOT_SEEKABLE
#define HEIM_ERR_NOT_SEEKABLE (-1555)
#endif

/* --- Elastic memory (emem) backend --- */

typedef struct emem_storage {
    unsigned char *base;
    size_t size;
    size_t len;
    unsigned char *ptr;
} emem_storage;

static ssize_t
emem_fetch(heim_storage *sp, void *data, size_t size)
{
    emem_storage *s = (emem_storage *)sp->data;
    size_t avail;

    assert(data != NULL && s->ptr != NULL);
    avail = s->base + s->len - s->ptr;
    if (avail < size)
        size = avail;
    memmove(data, s->ptr, size);
    sp->seek(sp, size, SEEK_CUR);
    return size;
}

static ssize_t
emem_store(heim_storage *sp, const void *data, size_t size)
{
    emem_storage *s;

    if (size == 0) {
        sp->seek(sp, 0, SEEK_CUR);
        return 0;
    }

    s = (emem_storage *)sp->data;
    assert(data != NULL);

    if (size > (size_t)(s->base + s->size - s->ptr)) {
        void *base;
        size_t sz, off;

        off = s->ptr - s->base;
        sz = off + size;
        if (sz < 4096)
            sz *= 2;
        base = realloc(s->base, sz);
        if (base == NULL)
            return -1;
        s->size = sz;
        s->base = base;
        s->ptr = (unsigned char *)base + off;
    }
    memmove(s->ptr, data, size);
    sp->seek(sp, size, SEEK_CUR);
    return size;
}

static off_t
emem_seek(heim_storage *sp, off_t offset, int whence)
{
    emem_storage *s = (emem_storage *)sp->data;

    switch (whence) {
    case SEEK_SET:
        if ((size_t)offset > s->size)
            offset = s->size;
        if (offset < 0)
            offset = 0;
        s->ptr = s->base + offset;
        if ((size_t)offset > s->len)
            s->len = offset;
        break;
    case SEEK_CUR:
        sp->seek(sp, s->ptr - s->base + offset, SEEK_SET);
        break;
    case SEEK_END:
        sp->seek(sp, s->len + offset, SEEK_SET);
        break;
    default:
        errno = EINVAL;
        return -1;
    }
    return s->ptr - s->base;
}

static int
emem_trunc(heim_storage *sp, off_t offset)
{
    emem_storage *s = (emem_storage *)sp->data;

    if (offset == 0) {
        if (s->size > 1024) {
            void *base = realloc(s->base, 1024);
            if (base) {
                s->base = base;
                s->size = 1024;
            }
        }
        s->len = 0;
        s->ptr = s->base;
    } else if ((size_t)offset > s->size || (s->size / 2) > (size_t)offset) {
        void *base;
        size_t off;

        off = s->ptr - s->base;
        base = realloc(s->base, offset);
        if (base == NULL)
            return ENOMEM;
        if ((size_t)offset > s->size)
            memset((char *)base + s->size, 0, offset - s->size);
        s->size = offset;
        s->base = base;
        s->ptr = (unsigned char *)base + off;
    }
    s->len = offset;
    if ((off_t)(s->ptr - s->base) > offset)
        s->ptr = s->base + offset;
    return 0;
}

static void
emem_free(heim_storage *sp)
{
    emem_storage *s = sp->data;

    assert(s->base != NULL);
    memset(s->base, 0, s->len);
    free(s->base);
}

heim_storage *
heim_storage_emem(void)
{
    heim_storage *sp;
    emem_storage *s;

    sp = calloc(1, sizeof(*sp));
    if (sp == NULL)
        return NULL;

    s = calloc(1, sizeof(*s));
    if (s == NULL) {
        free(sp);
        return NULL;
    }

    s->size = 1024;
    s->base = calloc(1, s->size);
    if (s->base == NULL) {
        free(sp);
        free(s);
        return NULL;
    }
    s->len = 0;
    s->ptr = s->base;

    sp->data = s;
    sp->fetch = emem_fetch;
    sp->store = emem_store;
    sp->seek = emem_seek;
    sp->trunc = emem_trunc;
    sp->free = emem_free;
    sp->eof_code = HEIM_ERR_EOF;
    sp->max_alloc = UINT32_MAX / 64;
    return sp;
}

/* --- Fixed memory backend --- */

typedef struct mem_storage {
    const unsigned char *base;
    unsigned char *ptr;
    size_t len;
    int readonly;
} mem_storage;

static ssize_t
mem_fetch(heim_storage *sp, void *data, size_t size)
{
    mem_storage *s = (mem_storage *)sp->data;
    size_t avail = s->base + s->len - s->ptr;

    if (avail < size)
        size = avail;
    memmove(data, s->ptr, size);
    s->ptr += size;
    return size;
}

static ssize_t
mem_store(heim_storage *sp, const void *data, size_t size)
{
    mem_storage *s = (mem_storage *)sp->data;
    size_t avail;

    if (s->readonly) {
        errno = EROFS;
        return -1;
    }
    avail = s->base + s->len - s->ptr;
    if (avail < size)
        size = avail;
    memmove(s->ptr, data, size);
    s->ptr += size;
    return size;
}

static off_t
mem_seek(heim_storage *sp, off_t offset, int whence)
{
    mem_storage *s = (mem_storage *)sp->data;

    switch (whence) {
    case SEEK_SET:
        if (offset < 0)
            offset = 0;
        if ((size_t)offset > s->len)
            offset = s->len;
        s->ptr = ((unsigned char *)(uintptr_t)s->base) + offset;
        break;
    case SEEK_CUR:
        return mem_seek(sp, s->ptr - s->base + offset, SEEK_SET);
    case SEEK_END:
        return mem_seek(sp, s->len + offset, SEEK_SET);
    default:
        errno = EINVAL;
        return -1;
    }
    return s->ptr - s->base;
}

static int
mem_trunc(heim_storage *sp, off_t offset)
{
    mem_storage *s = (mem_storage *)sp->data;

    if (s->readonly)
        return EROFS;
    if ((size_t)offset > s->len)
        return ERANGE;
    s->len = offset;
    if ((off_t)(s->ptr - s->base) > offset)
        s->ptr = ((unsigned char *)(uintptr_t)s->base) + offset;
    return 0;
}

heim_storage *
heim_storage_from_mem(void *buf, size_t len)
{
    heim_storage *sp;
    mem_storage *s;

    sp = calloc(1, sizeof(*sp));
    if (sp == NULL)
        return NULL;

    s = calloc(1, sizeof(*s));
    if (s == NULL) {
        free(sp);
        return NULL;
    }

    s->base = buf;
    s->ptr = buf;
    s->len = len;
    s->readonly = 0;

    sp->data = s;
    sp->fetch = mem_fetch;
    sp->store = mem_store;
    sp->seek = mem_seek;
    sp->trunc = mem_trunc;
    sp->free = NULL;
    sp->eof_code = HEIM_ERR_EOF;
    sp->max_alloc = UINT32_MAX / 64;
    return sp;
}

heim_storage *
heim_storage_from_readonly_mem(const void *buf, size_t len)
{
    heim_storage *sp;
    mem_storage *s;

    sp = heim_storage_from_mem((void *)(uintptr_t)buf, len);
    if (sp == NULL)
        return NULL;
    s = (mem_storage *)sp->data;
    s->readonly = 1;
    return sp;
}

/* --- Public API --- */

void
heim_storage_free(heim_storage *sp)
{
    if (sp == NULL)
        return;
    if (sp->free)
        sp->free(sp);
    free(sp->data);
    free(sp);
}

off_t
heim_storage_seek(heim_storage *sp, off_t offset, int whence)
{
    return sp->seek(sp, offset, whence);
}

int
heim_storage_truncate(heim_storage *sp, off_t offset)
{
    return sp->trunc(sp, offset);
}

ssize_t
heim_storage_read(heim_storage *sp, void *buf, size_t len)
{
    return sp->fetch(sp, buf, len);
}

ssize_t
heim_storage_write(heim_storage *sp, const void *buf, size_t len)
{
    return sp->store(sp, buf, len);
}

void
heim_storage_set_eof_code(heim_storage *sp, int code)
{
    sp->eof_code = code;
}

int
heim_storage_get_eof_code(heim_storage *sp)
{
    return sp->eof_code;
}

void
heim_storage_set_max_alloc(heim_storage *sp, size_t size)
{
    sp->max_alloc = size;
}

int
heim_storage_to_data(heim_storage *sp, void **data_p, size_t *len_p)
{
    off_t pos, size;
    void *buf;
    ssize_t bytes;

    *data_p = NULL;
    *len_p = 0;

    pos = sp->seek(sp, 0, SEEK_CUR);
    if (pos < 0)
        return HEIM_ERR_NOT_SEEKABLE;
    size = sp->seek(sp, 0, SEEK_END);
    if (size < 0)
        return HEIM_ERR_NOT_SEEKABLE;
    if (sp->max_alloc && (size_t)size > sp->max_alloc)
        return HEIM_ERR_TOO_BIG;

    buf = malloc(size > 0 ? size : 1);
    if (buf == NULL)
        return ENOMEM;

    if (size > 0) {
        sp->seek(sp, 0, SEEK_SET);
        bytes = sp->fetch(sp, buf, size);
        sp->seek(sp, pos, SEEK_SET);
        if (bytes < 0) {
            free(buf);
            return sp->eof_code;
        }
        *len_p = bytes;
    }
    *data_p = buf;
    return 0;
}

/* --- Integer store/ret (always big-endian) --- */

int
heim_store_uint8(heim_storage *sp, uint8_t value)
{
    ssize_t ret = sp->store(sp, &value, 1);
    if (ret < 0)
        return errno;
    if (ret != 1)
        return sp->eof_code;
    return 0;
}

int
heim_ret_uint8(heim_storage *sp, uint8_t *value)
{
    ssize_t ret = sp->fetch(sp, value, 1);
    if (ret < 0)
        return errno;
    if (ret != 1)
        return sp->eof_code;
    return 0;
}

int
heim_store_uint16(heim_storage *sp, uint16_t value)
{
    uint8_t v[2];
    ssize_t ret;

    v[0] = (value >> 8) & 0xff;
    v[1] = value & 0xff;
    ret = sp->store(sp, v, 2);
    if (ret < 0)
        return errno;
    if (ret != 2)
        return sp->eof_code;
    return 0;
}

int
heim_ret_uint16(heim_storage *sp, uint16_t *value)
{
    uint8_t v[2];
    ssize_t ret;

    ret = sp->fetch(sp, v, 2);
    if (ret < 0)
        return errno;
    if (ret != 2)
        return sp->eof_code;
    *value = ((uint16_t)v[0] << 8) | v[1];
    return 0;
}

int
heim_store_uint32(heim_storage *sp, uint32_t value)
{
    uint8_t v[4];
    ssize_t ret;

    v[0] = (value >> 24) & 0xff;
    v[1] = (value >> 16) & 0xff;
    v[2] = (value >> 8) & 0xff;
    v[3] = value & 0xff;
    ret = sp->store(sp, v, 4);
    if (ret < 0)
        return errno;
    if (ret != 4)
        return sp->eof_code;
    return 0;
}

int
heim_ret_uint32(heim_storage *sp, uint32_t *value)
{
    uint8_t v[4];
    ssize_t ret;

    ret = sp->fetch(sp, v, 4);
    if (ret < 0)
        return errno;
    if (ret != 4)
        return sp->eof_code;
    *value = ((uint32_t)v[0] << 24) | ((uint32_t)v[1] << 16) |
             ((uint32_t)v[2] << 8) | v[3];
    return 0;
}

/* --- Byte buffer store/ret --- */

int
heim_store_bytes(heim_storage *sp, const void *data, size_t len)
{
    ssize_t ret;

    if (len == 0)
        return 0;
    ret = sp->store(sp, data, len);
    if (ret < 0)
        return errno;
    if ((size_t)ret != len)
        return sp->eof_code;
    return 0;
}

int
heim_ret_bytes(heim_storage *sp, void *data, size_t len)
{
    ssize_t ret;

    if (len == 0)
        return 0;
    ret = sp->fetch(sp, data, len);
    if (ret < 0)
        return errno;
    if ((size_t)ret != len)
        return sp->eof_code;
    return 0;
}

/* Length-prefixed data (uint32 length prefix, then bytes). */

int
heim_store_data(heim_storage *sp, const void *data, size_t len)
{
    int ret;

    ret = heim_store_uint32(sp, (uint32_t)len);
    if (ret)
        return ret;
    return heim_store_bytes(sp, data, len);
}

int
heim_ret_data(heim_storage *sp, void **data_p, size_t *len_p)
{
    uint32_t len;
    void *buf;
    int ret;

    *data_p = NULL;
    *len_p = 0;

    ret = heim_ret_uint32(sp, &len);
    if (ret)
        return ret;
    if (sp->max_alloc && len > sp->max_alloc)
        return HEIM_ERR_TOO_BIG;

    buf = malloc(len > 0 ? len : 1);
    if (buf == NULL)
        return ENOMEM;

    ret = heim_ret_bytes(sp, buf, len);
    if (ret) {
        free(buf);
        return ret;
    }
    *data_p = buf;
    *len_p = len;
    return 0;
}
