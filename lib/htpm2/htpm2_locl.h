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

#ifndef __htpm2_locl_h__
#define __htpm2_locl_h__

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "htpm2.h"

/*
 * Internal context structure.  Read-only after htpm2_context_init().
 */
struct htpm2_context_data {
    /* Cached OpenSSL digest objects */
    const EVP_MD *md_sha256;
    const EVP_MD *md_sha384;
    const EVP_MD *md_sha512;
};

/*
 * Internal helpers for constructing error results.
 */
htpm2_result htpm2_result_local(int code, uint32_t flags, int local_err,
                                const char *fmt, ...);
htpm2_result htpm2_result_tpm(uint32_t tpm_rc, const char *fmt, ...);
htpm2_result htpm2_result_ossl(int code, const char *fmt, ...);

/* Internal commands not in the public API */
htpm2_result htpm2_startup(const htpm2_context ctx, htpm2_transport tp,
                           htpm2_result prior, uint16_t startup_type);

/* Internal transport send/recv for command layer */
htpm2_result htpm2_transport_send_recv(htpm2_transport tp,
                                       const void *cmd, size_t cmd_len,
                                       void *rsp, size_t *rsp_len);

#endif /* __htpm2_locl_h__ */
