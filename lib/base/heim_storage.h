/*
 * Copyright (c) 2002 Kungliga Tekniska Högskolan
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

#ifndef __heim_storage_h__
#define __heim_storage_h__

#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>

/*
 * heim_storage -- a serialization/deserialization abstraction.
 *
 * Derived from krb5_storage.  Provides big-endian integer marshalling,
 * byte buffer I/O, and pluggable backends (elastic memory, fixed memory).
 * All multi-byte integers are stored in network (big-endian) byte order.
 */

typedef struct heim_storage_data heim_storage;

/* Create an elastic (auto-allocating) memory storage. */
heim_storage *heim_storage_emem(void);

/* Create a read-write storage over an existing buffer. */
heim_storage *heim_storage_from_mem(void *buf, size_t len);

/* Create a read-only storage over an existing buffer. */
heim_storage *heim_storage_from_readonly_mem(const void *buf, size_t len);

/* Free a storage and its backing resources. */
void heim_storage_free(heim_storage *sp);

/* Seek within the storage. */
off_t heim_storage_seek(heim_storage *sp, off_t offset, int whence);

/* Truncate storage to the given offset. */
int heim_storage_truncate(heim_storage *sp, off_t offset);

/* Low-level read/write. */
ssize_t heim_storage_read(heim_storage *sp, void *buf, size_t len);
ssize_t heim_storage_write(heim_storage *sp, const void *buf, size_t len);

/* Set/get the error code returned on EOF. */
void heim_storage_set_eof_code(heim_storage *sp, int code);
int  heim_storage_get_eof_code(heim_storage *sp);

/* Set maximum allocation size (0 = no limit). */
void heim_storage_set_max_alloc(heim_storage *sp, size_t size);

/*
 * Copy the entire contents of storage into a newly allocated buffer.
 * Caller must free *data_p with free().
 */
int heim_storage_to_data(heim_storage *sp, void **data_p, size_t *len_p);

/*
 * Store/retrieve integers in big-endian (network) byte order.
 * Return 0 on success, or an error code.
 */
int heim_store_uint8(heim_storage *sp, uint8_t value);
int heim_store_uint16(heim_storage *sp, uint16_t value);
int heim_store_uint32(heim_storage *sp, uint32_t value);

int heim_ret_uint8(heim_storage *sp, uint8_t *value);
int heim_ret_uint16(heim_storage *sp, uint16_t *value);
int heim_ret_uint32(heim_storage *sp, uint32_t *value);

/*
 * Store/retrieve raw bytes (no length prefix).
 */
int heim_store_bytes(heim_storage *sp, const void *data, size_t len);
int heim_ret_bytes(heim_storage *sp, void *data, size_t len);

/*
 * Store/retrieve a length-prefixed byte buffer.
 * The length prefix is a big-endian uint32.
 * heim_ret_data allocates; caller must free *data_p with free().
 */
int heim_store_data(heim_storage *sp, const void *data, size_t len);
int heim_ret_data(heim_storage *sp, void **data_p, size_t *len_p);

#endif /* __heim_storage_h__ */
