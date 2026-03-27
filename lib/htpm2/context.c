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

#include "htpm2_locl.h"

htpm2_result
htpm2_context_init(htpm2_context *ctx)
{
    htpm2_context c;

    *ctx = NULL;

    c = calloc(1, sizeof(*c));
    if (c == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "htpm2_context_init: out of memory");

    c->md_sha256 = EVP_sha256();
    c->md_sha384 = EVP_sha384();
    c->md_sha512 = EVP_sha512();

    if (c->md_sha256 == NULL || c->md_sha384 == NULL ||
        c->md_sha512 == NULL) {
        free(c);
        return htpm2_result_ossl(1, "htpm2_context_init: "
                                 "failed to initialize OpenSSL digests");
    }

    *ctx = c;
    return HTPM2_OK;
}

void
htpm2_context_free(htpm2_context *ctx)
{
    if (ctx == NULL || *ctx == NULL)
        return;
    memset(*ctx, 0, sizeof(**ctx));
    free(*ctx);
    *ctx = NULL;
}

void
htpm2_free(const htpm2_context ctx, void *ptr)
{
    (void)ctx;
    free(ptr);
}

/* --- Internal error result constructors --- */

htpm2_result
htpm2_result_local(int code, uint32_t flags, int local_err,
                   const char *fmt, ...)
{
    htpm2_result r = {0};
    va_list ap;

    r.code = code;
    r.flags = flags | HTPM2_F_LOCAL;
    r.local_err = local_err;
    if (fmt) {
        va_start(ap, fmt);
        vasprintf(&r.message, fmt, ap);
        va_end(ap);
    }
    return r;
}

htpm2_result
htpm2_result_tpm(uint32_t tpm_rc, const char *fmt, ...)
{
    htpm2_result r = {0};
    va_list ap;

    r.code = (int32_t)tpm_rc;
    r.flags = HTPM2_F_TPM_RC;
    r.tpm_rc = tpm_rc;
    if (fmt) {
        va_start(ap, fmt);
        vasprintf(&r.message, fmt, ap);
        va_end(ap);
    }
    return r;
}

htpm2_result
htpm2_result_ossl(int code, const char *fmt, ...)
{
    htpm2_result r = {0};
    va_list ap;
    unsigned long ossl_err;

    ossl_err = ERR_peek_last_error();

    r.code = code ? code : 1;
    r.flags = HTPM2_F_OSSL;
    r.ossl_err = (uint32_t)ossl_err;
    if (fmt) {
        va_start(ap, fmt);
        vasprintf(&r.message, fmt, ap);
        va_end(ap);
    }
    return r;
}
