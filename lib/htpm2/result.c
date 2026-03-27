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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "htpm2.h"

void
htpm2_result_free(htpm2_result *r)
{
    if (r == NULL)
        return;
    free(r->message);
    memset(r, 0, sizeof(*r));
}

htpm2_result
htpm2_result_prepend(htpm2_result old, const char *fmt, ...)
{
    htpm2_result r;
    va_list ap;
    char *prefix = NULL;
    char *combined = NULL;
    int len;

    if (old.code == 0)
        return old;

    va_start(ap, fmt);
    len = vasprintf(&prefix, fmt, ap);
    va_end(ap);

    if (len < 0 || prefix == NULL)
        return old;

    if (old.message) {
        len = asprintf(&combined, "%s: %s", prefix, old.message);
        free(prefix);
        if (len < 0 || combined == NULL)
            return old;
        free(old.message);
        r = old;
        r.message = combined;
    } else {
        r = old;
        r.message = prefix;
    }
    return r;
}
