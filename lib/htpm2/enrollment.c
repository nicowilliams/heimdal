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

/*
 * Enrollment protocol support.
 *
 * The well-known key:
 *   A constant KEYEDHASH key whose only purpose is to carry a policy.
 *   The private part (authValue / sensitive data) is hardcoded and
 *   publicly known -- security comes from the policy, not the key
 *   material.  Anyone can create this key on any TPM; the Name is
 *   deterministic from the policy.
 *
 *   Template:
 *     type = KEYEDHASH
 *     nameAlg = SHA-256
 *     objectAttributes = userWithAuth | sign | fixedTPM | fixedParent
 *                        | sensDataOrigin
 *     authPolicy = <caller-provided policy digest>
 *     scheme = HMAC-SHA-256
 *     unique = SHA-256 of a fixed seed (deterministic, same everywhere)
 *
 *   The sensitive area has a fixed, well-known authValue (empty) and
 *   a fixed seed.  Since sensDataOrigin is set, the TPM generates
 *   the key from the seed -- but for a primary key under the NULL
 *   hierarchy with identical templates, the result is identical
 *   everywhere.
 *
 * The owner key:
 *   A primary RSA-2048 storage key under the Owner hierarchy.
 *   Same template as a standard EK but under OWNER instead of
 *   ENDORSEMENT.  fixedTPM, fixedParent, restricted, decrypt.
 *   Changing the owner seed invalidates this key.
 */

#include "htpm2_locl.h"
#include "marshal.h"
#include "crypto.h"

/*
 * The well-known key's unique value.  This is SHA-256 of the string
 * "htpm2-well-known-key-v1" -- used as the unique field in the
 * TPMT_PUBLIC so the key is deterministic.
 */
static const uint8_t wk_unique_seed[] = "htpm2-well-known-key-v1";

/*
 * Build the well-known key's TPMT_PUBLIC and compute its Name.
 *
 * The TPMT_PUBLIC is a KEYEDHASH with:
 *   type = KEYEDHASH (0x0008)
 *   nameAlg = SHA-256
 *   attrs = fixedTPM | fixedParent | sensDataOrigin | userWithAuth | sign
 *   authPolicy = the caller's policy digest
 *   scheme = HMAC-SHA-256
 *   unique = TPM2B with 32 bytes = SHA-256("htpm2-well-known-key-v1")
 *
 * The Name = 0x000B || SHA-256(TPMT_PUBLIC).
 *
 * This function also returns the serialized TPMT_PUBLIC so the caller
 * can use it with CreatePrimary.
 */
htpm2_result
htpm2_wellknown_key_template(const htpm2_context ctx,
                             const void *policy, size_t policy_len,
                             void **pub_template, size_t *pub_template_len,
                             void **name, size_t *name_len)
{
    heim_storage *sp;
    uint8_t unique[32];
    void *pub_bytes = NULL;
    size_t pub_bytes_len = 0;
    uint8_t digest[32];
    htpm2_result r;
    int ret;

    if (pub_template) {
        *pub_template = NULL;
        *pub_template_len = 0;
    }
    *name = NULL;
    *name_len = 0;

    /* Compute deterministic unique value */
    r = htpm2_sha256(ctx, wk_unique_seed, sizeof(wk_unique_seed) - 1, unique);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "wellknown_key: unique hash");

    sp = heim_storage_emem();
    if (sp == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "wellknown_key: alloc");

    /* type = KEYEDHASH */
    ret = heim_store_uint16(sp, TPM2_ALG_KEYEDHASH);
    if (ret) goto err;

    /* nameAlg = SHA-256 */
    ret = heim_store_uint16(sp, TPM2_ALG_SHA256);
    if (ret) goto err;

    /* objectAttributes:
     *   fixedTPM(1) | fixedParent(4) | sensDataOrigin(5) |
     *   userWithAuth(6) | sign(18)
     */
    ret = heim_store_uint32(sp, (1U << 1) | (1U << 4) | (1U << 5) |
                                (1U << 6) | (1U << 18));
    if (ret) goto err;

    /* authPolicy */
    ret = htpm2_marshal_tpm2b(sp, policy, policy_len);
    if (ret) goto err;

    /* TPMS_KEYEDHASH_PARMS: scheme = HMAC-SHA-256 */
    ret = heim_store_uint16(sp, TPM2_ALG_HMAC);
    if (ret) goto err;
    ret = heim_store_uint16(sp, TPM2_ALG_SHA256);
    if (ret) goto err;

    /* unique (TPM2B) = deterministic 32 bytes */
    ret = htpm2_marshal_tpm2b(sp, unique, 32);
    if (ret) goto err;

    ret = heim_storage_to_data(sp, &pub_bytes, &pub_bytes_len);
    heim_storage_free(sp);
    sp = NULL;
    if (ret)
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "wellknown_key: to_data");

    /* Name = 0x000B || SHA-256(TPMT_PUBLIC) */
    r = htpm2_sha256(ctx, pub_bytes, pub_bytes_len, digest);
    if (htpm2_is_err(r)) {
        free(pub_bytes);
        return htpm2_result_prepend(r, "wellknown_key: name hash");
    }

    *name = malloc(34);
    if (*name == NULL) {
        free(pub_bytes);
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "wellknown_key: alloc name");
    }
    ((uint8_t *)*name)[0] = 0x00;
    ((uint8_t *)*name)[1] = 0x0B;
    memcpy((uint8_t *)*name + 2, digest, 32);
    *name_len = 34;

    if (pub_template) {
        *pub_template = pub_bytes;
        *pub_template_len = pub_bytes_len;
    } else {
        free(pub_bytes);
    }

    return HTPM2_OK;

err:
    heim_storage_free(sp);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "wellknown_key: marshal");
}

/*
 * Create the well-known key on the TPM.
 *
 * Creates a primary KEYEDHASH key under the NULL hierarchy with the
 * well-known template.  Since the template is deterministic (including
 * the unique field), the resulting key is identical on every TPM.
 *
 * The key's policy is set to the caller's policy digest, so
 * ActivateCredential with this key requires satisfying that policy.
 */
htpm2_result
htpm2_wellknown_key_create(const htpm2_context ctx,
                           htpm2_transport tp,
                           htpm2_result prior,
                           const void *policy, size_t policy_len,
                           htpm2_object *key)
{
    void *pub_template = NULL;
    size_t pub_template_len = 0;
    void *name = NULL;
    size_t name_len = 0;
    heim_storage *cmd, *rsp;
    uint32_t rc, handle;
    htpm2_result r;
    int ret;

    if (prior.code)
        return prior;

    *key = NULL;

    r = htpm2_wellknown_key_template(ctx, policy, policy_len,
                                     &pub_template, &pub_template_len,
                                     &name, &name_len);
    if (htpm2_is_err(r))
        return r;

    /*
     * CreatePrimary under NULL hierarchy (0x40000007).
     * We can't use htpm2_create_primary() because it builds the
     * template from htpm2_key_type.  We marshal the command directly.
     */
    cmd = heim_storage_emem();
    if (cmd == NULL) {
        free(pub_template);
        free(name);
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "wellknown_key_create: alloc");
    }

    ret = htpm2_marshal_cmd_header(cmd, TPM_ST_SESSIONS,
                                   TPM2_CC_CreatePrimary);
    if (ret) goto marshal_err;

    /* primaryHandle = NULL hierarchy */
    ret = heim_store_uint32(cmd, HTPM2_HIERARCHY_NULL);
    if (ret) goto marshal_err;

    /* Password auth for hierarchy */
    ret = heim_store_uint32(cmd, 9); /* authorizationSize */
    if (ret) goto marshal_err;
    ret = heim_store_uint32(cmd, 0x40000009); /* TPM_RS_PW */
    if (ret) goto marshal_err;
    ret = heim_store_uint16(cmd, 0); /* nonceCaller */
    if (ret) goto marshal_err;
    ret = heim_store_uint8(cmd, 0x01); /* continueSession */
    if (ret) goto marshal_err;
    ret = heim_store_uint16(cmd, 0); /* hmac (empty password) */
    if (ret) goto marshal_err;

    /* inSensitive: empty auth, empty data */
    {
        /* TPM2B_SENSITIVE_CREATE wrapping:
         *   size(2) + userAuth TPM2B(2+0) + data TPM2B(2+0) = 6 bytes */
        ret = heim_store_uint16(cmd, 4); /* outer size */
        if (ret) goto marshal_err;
        ret = htpm2_marshal_tpm2b(cmd, NULL, 0); /* userAuth */
        if (ret) goto marshal_err;
        ret = htpm2_marshal_tpm2b(cmd, NULL, 0); /* data */
        if (ret) goto marshal_err;
    }

    /* inPublic: TPM2B wrapping our template */
    ret = htpm2_marshal_tpm2b(cmd, pub_template, pub_template_len);
    if (ret) goto marshal_err;

    /* outsideInfo (empty) */
    ret = htpm2_marshal_tpm2b(cmd, NULL, 0);
    if (ret) goto marshal_err;

    /* creationPCR (count=0) */
    ret = heim_store_uint32(cmd, 0);
    if (ret) goto marshal_err;

    r = htpm2_command_execute(ctx, tp, cmd, &rsp, &rc);
    heim_storage_free(cmd);
    cmd = NULL;
    if (htpm2_is_err(r)) {
        free(pub_template);
        free(name);
        return htpm2_result_prepend(r, "wellknown_key_create");
    }

    /* Response: objectHandle */
    ret = heim_ret_uint32(rsp, &handle);
    heim_storage_free(rsp);
    if (ret) {
        free(pub_template);
        free(name);
        return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                                  "wellknown_key_create: unmarshal");
    }

    *key = htpm2_object_alloc(tp, handle);
    if (*key == NULL) {
        free(pub_template);
        free(name);
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "wellknown_key_create: alloc object");
    }

    htpm2_object_set_pub(*key, pub_template, pub_template_len);
    htpm2_object_set_name(*key, name, name_len);

    free(pub_template);
    free(name);
    return HTPM2_OK;

marshal_err:
    heim_storage_free(cmd);
    free(pub_template);
    free(name);
    return htpm2_result_local(ret, HTPM2_F_MARSHAL, ret,
                              "wellknown_key_create: marshal");
}

/*
 * Create the owner-hierarchy key on the TPM.
 *
 * This is a primary RSA-2048 storage key under the Owner hierarchy,
 * with the same template as a standard EK:
 *   fixedTPM, fixedParent, sensDataOrigin, restricted, decrypt
 *   AES-128-CFB symmetric, no scheme, SHA-256 nameAlg
 *
 * Changing the Owner seed invalidates this key, which is the
 * mechanism for decommissioning.
 */
htpm2_result
htpm2_owner_key_create(const htpm2_context ctx,
                       htpm2_transport tp,
                       htpm2_result prior,
                       htpm2_object *key)
{
    if (prior.code)
        return prior;

    return htpm2_create_primary(ctx, tp, HTPM2_OK, NULL,
                                HTPM2_HIERARCHY_OWNER,
                                HTPM2_KEY_RSA_2048_STORAGE,
                                NULL, 0, NULL, 0, key);
}
