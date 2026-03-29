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

#include <heim_storage.h>

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

/* Internal object management */
htpm2_object htpm2_object_alloc(htpm2_transport tp, uint32_t handle);
void htpm2_object_set_pub(htpm2_object obj, const void *pub, size_t pub_len);
void htpm2_object_set_priv(htpm2_object obj, const void *priv, size_t priv_len);
void htpm2_object_set_name(htpm2_object obj, const void *name, size_t name_len);
void htpm2_object_set_auth(htpm2_object obj, const void *auth, size_t auth_len);
void htpm2_object_set_creation_ticket(htpm2_object obj, const void *ticket,
                                       size_t ticket_len);
uint32_t htpm2_object_get_handle(htpm2_object obj);
htpm2_transport htpm2_object_get_transport(htpm2_object obj);
void htpm2_object_get_auth_internal(htpm2_object obj,
                                    const uint8_t **auth, size_t *auth_len);

/* Internal key template marshalling */
int htpm2_marshal_key_template(heim_storage *sp, htpm2_key_type type,
                               const void *policy, size_t policy_len);

/* Internal session accessors */
uint32_t htpm2_session_get_handle(htpm2_session session);
htpm2_transport htpm2_session_get_transport(htpm2_session session);
const uint8_t *htpm2_session_get_nonce_caller(htpm2_session session,
                                              size_t *len);
const uint8_t *htpm2_session_get_nonce_tpm(htpm2_session session, size_t *len);
void htpm2_session_set_nonce_tpm(htpm2_session session,
                                 const uint8_t *nonce, size_t len);
htpm2_result htpm2_session_refresh_nonce_caller(const htpm2_context ctx,
                                                htpm2_session session);
unsigned int htpm2_session_get_flags(htpm2_session session);
const uint8_t *htpm2_session_get_session_key(htpm2_session session,
                                             size_t *len);
void htpm2_session_get_bind_auth(htpm2_session session,
                                 const uint8_t **auth, size_t *auth_len);

/* Session crypto */
htpm2_result htpm2_compute_cp_hash(const htpm2_context ctx,
                                   uint32_t command_code,
                                   const void *name1, size_t name1_len,
                                   const void *name2, size_t name2_len,
                                   const void *name3, size_t name3_len,
                                   const void *cp_bytes, size_t cp_bytes_len,
                                   uint8_t cp_hash[32]);
htpm2_result htpm2_compute_rp_hash(const htpm2_context ctx,
                                   uint32_t response_code,
                                   uint32_t command_code,
                                   const void *rp_bytes, size_t rp_bytes_len,
                                   uint8_t rp_hash[32]);
htpm2_result htpm2_marshal_auth_area(const htpm2_context ctx,
                                     heim_storage *sp,
                                     htpm2_session session,
                                     const uint8_t *cp_hash);

#endif /* __htpm2_locl_h__ */
