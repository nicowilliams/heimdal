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

#ifndef __htpm2_h__
#define __htpm2_h__

#include <stdint.h>
#include <stddef.h>

/*
 * htpm2 -- a simple TPM 2.0 library for Heimdal.
 *
 * All functions return htpm2_result by value.  The context is read-only
 * after initialization.  Every function that performs I/O or computation
 * takes a prior htpm2_result for monadic error chaining: if the prior
 * result is an error, the function short-circuits and returns it unchanged.
 */

/* --- Result type --- */

typedef struct htpm2_result {
    int32_t  code;       /* 0 = success, nonzero = error */
    uint32_t flags;      /* bitfield: which error fields are populated */
    uint32_t tpm_rc;     /* raw TPM_RC when HTPM2_F_TPM_RC is set */
    int32_t  local_err;  /* errno / library error when HTPM2_F_LOCAL is set */
    uint32_t ossl_err;   /* OpenSSL error code when HTPM2_F_OSSL is set */
    char    *message;    /* heap-allocated on error, NULL on success */
} htpm2_result;

/* Error dimension flags */
#define HTPM2_F_TPM_RC      0x01
#define HTPM2_F_LOCAL       0x02
#define HTPM2_F_OSSL        0x04
#define HTPM2_F_TRANSPORT   0x08
#define HTPM2_F_MARSHAL     0x10
#define HTPM2_F_SESSION     0x20
#define HTPM2_F_WOULDBLOCK  0x40

/* The zero-value result: success, no allocation. */
#define HTPM2_OK ((htpm2_result){0, 0, 0, 0, 0, NULL})

static inline int htpm2_is_ok(htpm2_result r) { return r.code == 0; }
static inline int htpm2_is_err(htpm2_result r) { return r.code != 0; }

void htpm2_result_free(htpm2_result *r);
htpm2_result htpm2_result_prepend(htpm2_result old, const char *fmt, ...);

/* --- Opaque types --- */

typedef struct htpm2_context_data  *htpm2_context;
typedef struct htpm2_transport_data *htpm2_transport;
typedef struct htpm2_session_data  *htpm2_session;
typedef struct htpm2_object_data   *htpm2_object;
typedef struct htpm2_pcr_selection_data *htpm2_pcr_selection;

/* --- Context --- */

htpm2_result htpm2_context_init(htpm2_context *ctx);
void         htpm2_context_free(htpm2_context *ctx);

/* --- Transport --- */

htpm2_result htpm2_transport_open(const htpm2_context ctx,
                                  htpm2_result prior,
                                  const char *uri,
                                  htpm2_transport *tp);
void         htpm2_transport_close(htpm2_transport *tp);
int          htpm2_transport_get_read_fd(htpm2_transport tp);
int          htpm2_transport_get_write_fd(htpm2_transport tp);

typedef struct htpm2_transport_ops {
    const char *name;
    htpm2_result (*open)(const htpm2_context, const char *arg,
                         htpm2_transport *);
    htpm2_result (*send_recv)(htpm2_transport,
                              const void *cmd, size_t cmd_len,
                              void *rsp, size_t *rsp_len);
    int          (*get_read_fd)(htpm2_transport);
    int          (*get_write_fd)(htpm2_transport);
    void         (*close)(htpm2_transport *);
} htpm2_transport_ops;

htpm2_result htpm2_transport_register(htpm2_context ctx,
                                      const htpm2_transport_ops *ops);

/* --- Sessions --- */

typedef enum {
    HTPM2_SESSION_HMAC    = 0,
    HTPM2_SESSION_POLICY  = 1,
    HTPM2_SESSION_TRIAL   = 2
} htpm2_session_type;

#define HTPM2_SESSION_ENCRYPT       0x01
#define HTPM2_SESSION_DECRYPT       0x02
#define HTPM2_SESSION_AUDIT         0x04
#define HTPM2_SESSION_CONTINUE      0x08
#define HTPM2_SESSION_ENC_DEC       (HTPM2_SESSION_ENCRYPT | HTPM2_SESSION_DECRYPT)

htpm2_result htpm2_session_start(const htpm2_context ctx,
                                 htpm2_transport tp,
                                 htpm2_result prior,
                                 htpm2_session_type type,
                                 htpm2_object salt_key,
                                 htpm2_object bind,
                                 unsigned int flags,
                                 htpm2_session *session);
void htpm2_session_close(htpm2_session *session);
htpm2_result htpm2_session_get_policy_digest(htpm2_session session,
                                             htpm2_result prior,
                                             void *digest,
                                             size_t *digest_len);

/* --- Key / Object types --- */

typedef enum {
    HTPM2_KEY_RSA_2048_SIGN     = 0,
    HTPM2_KEY_RSA_2048_DECRYPT  = 1,
    HTPM2_KEY_RSA_2048_STORAGE  = 2,
    HTPM2_KEY_RSA_3072_SIGN     = 3,
    HTPM2_KEY_RSA_3072_DECRYPT  = 4,
    HTPM2_KEY_RSA_3072_STORAGE  = 5,
    HTPM2_KEY_ECC_P256_SIGN     = 10,
    HTPM2_KEY_ECC_P256_DECRYPT  = 11,
    HTPM2_KEY_ECC_P256_STORAGE  = 12,
    HTPM2_KEY_ECC_P384_SIGN     = 13,
    HTPM2_KEY_ECC_P384_DECRYPT  = 14,
    HTPM2_KEY_ECC_P384_STORAGE  = 15,
    HTPM2_KEY_HMAC_SHA256       = 20,
    HTPM2_KEY_KEYEDHASH         = 21
} htpm2_key_type;

#define HTPM2_HIERARCHY_OWNER       0x40000001
#define HTPM2_HIERARCHY_ENDORSEMENT 0x4000000B
#define HTPM2_HIERARCHY_PLATFORM    0x4000000C
#define HTPM2_HIERARCHY_NULL        0x40000007

/* --- Key / Object management --- */

htpm2_result htpm2_create_primary(const htpm2_context ctx,
                                  htpm2_transport tp,
                                  htpm2_result prior,
                                  htpm2_session auth_session,
                                  uint32_t hierarchy,
                                  htpm2_key_type type,
                                  const void *auth_value,
                                  size_t auth_value_len,
                                  const void *policy,
                                  size_t policy_len,
                                  htpm2_object *key);

htpm2_result htpm2_create(const htpm2_context ctx,
                          htpm2_transport tp,
                          htpm2_result prior,
                          htpm2_session auth_session,
                          htpm2_object parent,
                          htpm2_key_type type,
                          const void *auth_value,
                          size_t auth_value_len,
                          const void *policy,
                          size_t policy_len,
                          htpm2_object *key);

htpm2_result htpm2_load(const htpm2_context ctx,
                        htpm2_transport tp,
                        htpm2_result prior,
                        htpm2_session auth_session,
                        htpm2_object parent,
                        const void *pub_blob, size_t pub_blob_len,
                        const void *priv_blob, size_t priv_blob_len,
                        htpm2_object *key);

htpm2_result htpm2_read_public(const htpm2_context ctx,
                               htpm2_transport tp,
                               htpm2_result prior,
                               htpm2_object key,
                               void **pub_blob, size_t *pub_blob_len,
                               void **name, size_t *name_len);

htpm2_result htpm2_object_get_public(htpm2_object obj,
                                     const void **pub, size_t *pub_len);
htpm2_result htpm2_object_get_private(htpm2_object obj,
                                      const void **priv, size_t *priv_len);
htpm2_result htpm2_object_get_name(htpm2_object obj,
                                   const void **name, size_t *name_len);
void htpm2_object_close(htpm2_object *obj);

htpm2_result htpm2_evict_control(const htpm2_context ctx,
                                 htpm2_transport tp,
                                 htpm2_result prior,
                                 htpm2_session auth_session,
                                 htpm2_object key,
                                 uint32_t persistent_handle);

htpm2_result htpm2_context_save(const htpm2_context ctx,
                                htpm2_transport tp,
                                htpm2_result prior,
                                htpm2_object obj,
                                void **saved, size_t *saved_len);
htpm2_result htpm2_context_load(const htpm2_context ctx,
                                htpm2_transport tp,
                                htpm2_result prior,
                                const void *saved, size_t saved_len,
                                htpm2_object *obj);

htpm2_result htpm2_import(const htpm2_context ctx,
                          htpm2_transport tp,
                          htpm2_result prior,
                          htpm2_session auth_session,
                          htpm2_object parent,
                          const void *pub_blob, size_t pub_blob_len,
                          const void *duplicate, size_t duplicate_len,
                          const void *encrypted_seed,
                          size_t encrypted_seed_len,
                          const void *sym_seed, size_t sym_seed_len,
                          void **priv_blob, size_t *priv_blob_len);

htpm2_result htpm2_duplicate(const htpm2_context ctx,
                             htpm2_transport tp,
                             htpm2_result prior,
                             htpm2_session auth_session,
                             htpm2_object key,
                             htpm2_object new_parent,
                             void **duplicate, size_t *duplicate_len,
                             void **encrypted_seed,
                             size_t *encrypted_seed_len);

/* Software-only Duplicate: wrap a software key for import into a TPM.
 * No TPM round-trip needed -- the caller provides the private key material
 * and the new parent's public key.
 */
htpm2_result htpm2_duplicate_software(const htpm2_context ctx,
                                      const void *parent_pub,
                                      size_t parent_pub_len,
                                      const void *key_pub,
                                      size_t key_pub_len,
                                      const void *sensitive,
                                      size_t sensitive_len,
                                      const void *key_name,
                                      size_t key_name_len,
                                      void **duplicate,
                                      size_t *duplicate_len,
                                      void **encrypted_seed,
                                      size_t *encrypted_seed_len);

/* --- Crypto operations --- */

htpm2_result htpm2_sign(const htpm2_context ctx,
                        htpm2_transport tp,
                        htpm2_result prior,
                        htpm2_session auth_session,
                        htpm2_object sign_key,
                        const void *digest, size_t digest_len,
                        void **signature, size_t *signature_len);

htpm2_result htpm2_verify_signature(const htpm2_context ctx,
                                    htpm2_transport tp,
                                    htpm2_result prior,
                                    htpm2_object verify_key,
                                    const void *digest, size_t digest_len,
                                    const void *signature,
                                    size_t signature_len,
                                    void **validation_ticket,
                                    size_t *validation_ticket_len);

htpm2_result htpm2_quote(const htpm2_context ctx,
                         htpm2_transport tp,
                         htpm2_result prior,
                         htpm2_session auth_session,
                         htpm2_object sign_key,
                         const uint8_t *pcr_selections,
                         size_t pcr_selections_len,
                         const void *qualifying_data,
                         size_t qualifying_data_len,
                         void **quoted, size_t *quoted_len,
                         void **signature, size_t *signature_len);

htpm2_result htpm2_certify(const htpm2_context ctx,
                           htpm2_transport tp,
                           htpm2_result prior,
                           htpm2_session auth_session,
                           htpm2_object object,
                           htpm2_object sign_key,
                           const void *qualifying_data,
                           size_t qualifying_data_len,
                           void **certify_info, size_t *certify_info_len,
                           void **signature, size_t *signature_len);

htpm2_result htpm2_certify_creation(const htpm2_context ctx,
                                    htpm2_transport tp,
                                    htpm2_result prior,
                                    htpm2_session auth_session,
                                    htpm2_object object,
                                    htpm2_object sign_key,
                                    const void *qualifying_data,
                                    size_t qualifying_data_len,
                                    const void *creation_ticket,
                                    size_t creation_ticket_len,
                                    void **certify_info,
                                    size_t *certify_info_len,
                                    void **signature,
                                    size_t *signature_len);

htpm2_result htpm2_certify_x509(const htpm2_context ctx,
                                htpm2_transport tp,
                                htpm2_result prior,
                                htpm2_session auth_session,
                                htpm2_object object,
                                htpm2_object sign_key,
                                const void *partial_cert,
                                size_t partial_cert_len,
                                void **added_to_cert,
                                size_t *added_to_cert_len,
                                void **tbs_digest,
                                size_t *tbs_digest_len,
                                void **signature,
                                size_t *signature_len);

htpm2_result htpm2_rsa_decrypt(const htpm2_context ctx,
                               htpm2_transport tp,
                               htpm2_result prior,
                               htpm2_session auth_session,
                               htpm2_object key,
                               const void *ciphertext,
                               size_t ciphertext_len,
                               void **plaintext,
                               size_t *plaintext_len);

htpm2_result htpm2_ecdh_zgen(const htpm2_context ctx,
                             htpm2_transport tp,
                             htpm2_result prior,
                             htpm2_session auth_session,
                             htpm2_object key,
                             const void *peer_point,
                             size_t peer_point_len,
                             void **shared_secret,
                             size_t *shared_secret_len);

/* --- Credential --- */

htpm2_result htpm2_make_credential(const htpm2_context ctx,
                                   const void *ek_pub,
                                   size_t ek_pub_len,
                                   const void *credential,
                                   size_t credential_len,
                                   const void *key_name,
                                   size_t key_name_len,
                                   void **credential_blob,
                                   size_t *credential_blob_len,
                                   void **encrypted_secret,
                                   size_t *encrypted_secret_len);

htpm2_result htpm2_activate_credential(const htpm2_context ctx,
                                       htpm2_transport tp,
                                       htpm2_result prior,
                                       htpm2_session auth_session_ak,
                                       htpm2_session auth_session_ek,
                                       htpm2_object activate_key,
                                       htpm2_object key_handle,
                                       const void *credential_blob,
                                       size_t credential_blob_len,
                                       const void *encrypted_secret,
                                       size_t encrypted_secret_len,
                                       void **credential_out,
                                       size_t *credential_out_len);

/* --- PCR --- */

htpm2_result htpm2_pcr_read(const htpm2_context ctx,
                            htpm2_transport tp,
                            htpm2_result prior,
                            const uint8_t *pcr_selections,
                            size_t pcr_selections_len,
                            void **pcr_values,
                            size_t *pcr_values_len,
                            uint32_t *update_counter);

htpm2_result htpm2_pcr_extend(const htpm2_context ctx,
                              htpm2_transport tp,
                              htpm2_result prior,
                              htpm2_session auth_session,
                              uint32_t pcr_index,
                              uint16_t hash_alg,
                              const void *digest,
                              size_t digest_len);

/* --- Utility --- */

htpm2_result htpm2_get_random(const htpm2_context ctx,
                              htpm2_transport tp,
                              htpm2_result prior,
                              void *buf, size_t len);

htpm2_result htpm2_hash(const htpm2_context ctx,
                        htpm2_transport tp,
                        htpm2_result prior,
                        uint16_t hash_alg,
                        const void *data, size_t data_len,
                        void *digest, size_t *digest_len,
                        void **validation_ticket,
                        size_t *validation_ticket_len);

/* --- PCR selection helpers --- */

htpm2_result htpm2_pcr_selection_create(const htpm2_context ctx,
                                        uint16_t hash_alg,
                                        htpm2_pcr_selection *sel);
htpm2_result htpm2_pcr_selection_add(htpm2_pcr_selection sel,
                                     uint32_t pcr_index);
htpm2_result htpm2_pcr_selection_encode(htpm2_pcr_selection sel,
                                        void **encoded,
                                        size_t *encoded_len);
void         htpm2_pcr_selection_free(htpm2_pcr_selection *sel);

/* --- Policy --- */

htpm2_result htpm2_policy_pcr(const htpm2_context ctx,
                              htpm2_session session,
                              htpm2_result prior,
                              const uint8_t *pcr_selections,
                              size_t pcr_selections_len,
                              const void *pcr_digest,
                              size_t pcr_digest_len);

htpm2_result htpm2_policy_command_code(const htpm2_context ctx,
                                       htpm2_session session,
                                       htpm2_result prior,
                                       uint32_t command_code);

htpm2_result htpm2_policy_authorize(const htpm2_context ctx,
                                    htpm2_session session,
                                    htpm2_result prior,
                                    const void *approved_policy,
                                    size_t approved_policy_len,
                                    const void *policy_ref,
                                    size_t policy_ref_len,
                                    const void *key_sign_name,
                                    size_t key_sign_name_len,
                                    const void *ticket,
                                    size_t ticket_len,
                                    const void *signature,
                                    size_t signature_len);

htpm2_result htpm2_policy_signed(const htpm2_context ctx,
                                 htpm2_session session,
                                 htpm2_result prior,
                                 htpm2_object auth_key,
                                 const void *policy_ref,
                                 size_t policy_ref_len,
                                 int32_t expiration,
                                 const void *signature,
                                 size_t signature_len);

htpm2_result htpm2_policy_secret(const htpm2_context ctx,
                                 htpm2_session session,
                                 htpm2_result prior,
                                 htpm2_object auth_entity,
                                 const void *policy_ref,
                                 size_t policy_ref_len,
                                 int32_t expiration);

htpm2_result htpm2_policy_or(const htpm2_context ctx,
                             htpm2_session session,
                             htpm2_result prior,
                             const void **digests,
                             const size_t *digest_lens,
                             size_t num_digests);

/* --- Memory --- */

void htpm2_free(const htpm2_context ctx, void *ptr);

#endif /* __htpm2_h__ */
