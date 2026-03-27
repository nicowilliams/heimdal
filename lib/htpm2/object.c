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
#include "marshal.h"

/*
 * Internal object structure.
 */
struct htpm2_object_data {
    uint32_t handle;        /* TPM handle (transient, persistent, or hierarchy) */
    htpm2_transport tp;     /* transport this object is loaded on */

    /* Cached public area (TPM2B_PUBLIC) */
    void *pub_blob;
    size_t pub_blob_len;

    /* Cached private area (TPM2B_PRIVATE, from Create) */
    void *priv_blob;
    size_t priv_blob_len;

    /* Cached name (hash of public area) */
    void *name;
    size_t name_len;

    /* Auth value for this object */
    void *auth_value;
    size_t auth_value_len;

    /* Creation ticket (from Create/CreatePrimary) */
    void *creation_ticket;
    size_t creation_ticket_len;

    int flushed;            /* set after FlushContext */
};

htpm2_object
htpm2_object_alloc(htpm2_transport tp, uint32_t handle)
{
    htpm2_object obj = calloc(1, sizeof(*obj));
    if (obj == NULL)
        return NULL;
    obj->handle = handle;
    obj->tp = tp;
    return obj;
}

void
htpm2_object_set_pub(htpm2_object obj, const void *pub, size_t pub_len)
{
    free(obj->pub_blob);
    obj->pub_blob = NULL;
    obj->pub_blob_len = 0;
    if (pub && pub_len > 0) {
        obj->pub_blob = malloc(pub_len);
        if (obj->pub_blob) {
            memcpy(obj->pub_blob, pub, pub_len);
            obj->pub_blob_len = pub_len;
        }
    }
}

void
htpm2_object_set_priv(htpm2_object obj, const void *priv, size_t priv_len)
{
    free(obj->priv_blob);
    obj->priv_blob = NULL;
    obj->priv_blob_len = 0;
    if (priv && priv_len > 0) {
        obj->priv_blob = malloc(priv_len);
        if (obj->priv_blob) {
            memcpy(obj->priv_blob, priv, priv_len);
            obj->priv_blob_len = priv_len;
        }
    }
}

void
htpm2_object_set_name(htpm2_object obj, const void *name, size_t name_len)
{
    free(obj->name);
    obj->name = NULL;
    obj->name_len = 0;
    if (name && name_len > 0) {
        obj->name = malloc(name_len);
        if (obj->name) {
            memcpy(obj->name, name, name_len);
            obj->name_len = name_len;
        }
    }
}

void
htpm2_object_set_auth(htpm2_object obj, const void *auth, size_t auth_len)
{
    free(obj->auth_value);
    obj->auth_value = NULL;
    obj->auth_value_len = 0;
    if (auth && auth_len > 0) {
        obj->auth_value = malloc(auth_len);
        if (obj->auth_value) {
            memcpy(obj->auth_value, auth, auth_len);
            obj->auth_value_len = auth_len;
        }
    }
}

void
htpm2_object_set_creation_ticket(htpm2_object obj, const void *ticket,
                                  size_t ticket_len)
{
    free(obj->creation_ticket);
    obj->creation_ticket = NULL;
    obj->creation_ticket_len = 0;
    if (ticket && ticket_len > 0) {
        obj->creation_ticket = malloc(ticket_len);
        if (obj->creation_ticket) {
            memcpy(obj->creation_ticket, ticket, ticket_len);
            obj->creation_ticket_len = ticket_len;
        }
    }
}

uint32_t
htpm2_object_get_handle(htpm2_object obj)
{
    return obj ? obj->handle : 0;
}

htpm2_transport
htpm2_object_get_transport(htpm2_object obj)
{
    return obj ? obj->tp : NULL;
}

void
htpm2_object_get_auth_internal(htpm2_object obj,
                               const uint8_t **auth, size_t *auth_len)
{
    if (obj == NULL || obj->auth_value == NULL) {
        *auth = NULL;
        *auth_len = 0;
        return;
    }
    *auth = obj->auth_value;
    *auth_len = obj->auth_value_len;
}

/* --- Public API --- */

htpm2_result
htpm2_object_get_public(htpm2_object obj,
                        const void **pub, size_t *pub_len)
{
    if (obj == NULL)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "object_get_public: NULL object");
    *pub = obj->pub_blob;
    *pub_len = obj->pub_blob_len;
    return HTPM2_OK;
}

htpm2_result
htpm2_object_get_private(htpm2_object obj,
                         const void **priv, size_t *priv_len)
{
    if (obj == NULL)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "object_get_private: NULL object");
    *priv = obj->priv_blob;
    *priv_len = obj->priv_blob_len;
    return HTPM2_OK;
}

htpm2_result
htpm2_object_get_name(htpm2_object obj,
                      const void **name, size_t *name_len)
{
    if (obj == NULL)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "object_get_name: NULL object");
    *name = obj->name;
    *name_len = obj->name_len;
    return HTPM2_OK;
}

void
htpm2_object_close(htpm2_object *obj)
{
    htpm2_object o;

    if (obj == NULL || *obj == NULL)
        return;

    o = *obj;

    /*
     * If the object has a transient handle and hasn't been flushed,
     * flush it now.  We don't report errors here since this is a
     * destructor.
     */
    if (!o->flushed && o->tp != NULL &&
        (o->handle >> 24) == 0x80) {
        /* Transient handle range: 0x80xxxxxx */
        heim_storage *cmd = heim_storage_emem();
        if (cmd) {
            if (htpm2_marshal_cmd_header(cmd, TPM_ST_NO_SESSIONS,
                                         TPM2_CC_FlushContext) == 0 &&
                heim_store_uint32(cmd, o->handle) == 0) {
                heim_storage *rsp = NULL;
                uint32_t rc;
                htpm2_result r = htpm2_command_execute(NULL, o->tp, cmd,
                                                       &rsp, &rc);
                if (htpm2_is_ok(r))
                    heim_storage_free(rsp);
                htpm2_result_free(&r);
            }
            heim_storage_free(cmd);
        }
    }

    free(o->pub_blob);
    free(o->priv_blob);
    free(o->name);
    free(o->auth_value);
    free(o->creation_ticket);
    memset(o, 0, sizeof(*o));
    free(o);
    *obj = NULL;
}
