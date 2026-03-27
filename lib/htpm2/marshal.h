/*
 * TPM 2.0 command/response marshalling.
 * Built on top of heim_storage from lib/base/.
 */

#ifndef __htpm2_marshal_h__
#define __htpm2_marshal_h__

#include "htpm2.h"
#include "heim_storage.h"

/*
 * TPM command/response header:
 *   tag:  uint16  (TPM_ST_NO_SESSIONS=0x8001 or TPM_ST_SESSIONS=0x8002)
 *   size: uint32  (total size including header)
 *   code: uint32  (command code or response code)
 */
#define TPM_ST_NO_SESSIONS  0x8001
#define TPM_ST_SESSIONS     0x8002

/* TPM command codes (CC) */
#define TPM2_CC_Startup         0x00000144
#define TPM2_CC_SelfTest        0x00000143
#define TPM2_CC_GetRandom       0x0000017B
#define TPM2_CC_Hash            0x0000017C
#define TPM2_CC_PCR_Read        0x0000017E
#define TPM2_CC_PCR_Extend      0x00000182
#define TPM2_CC_StartAuthSession 0x00000176
#define TPM2_CC_CreatePrimary   0x00000131
#define TPM2_CC_Create          0x00000153
#define TPM2_CC_Load            0x00000157
#define TPM2_CC_ReadPublic      0x00000173
#define TPM2_CC_FlushContext    0x00000165
#define TPM2_CC_ContextSave     0x00000162
#define TPM2_CC_ContextLoad     0x00000161
#define TPM2_CC_EvictControl    0x00000120
#define TPM2_CC_Import          0x00000156
#define TPM2_CC_Duplicate       0x0000014B
#define TPM2_CC_Sign            0x0000015D
#define TPM2_CC_VerifySignature 0x00000177
#define TPM2_CC_Quote           0x00000158
#define TPM2_CC_Certify         0x00000148
#define TPM2_CC_CertifyCreation 0x0000014A
#define TPM2_CC_CertifyX509     0x00000197
#define TPM2_CC_RSA_Decrypt     0x00000159
#define TPM2_CC_ECDH_ZGen       0x00000154
#define TPM2_CC_MakeCredential  0x00000168
#define TPM2_CC_ActivateCredential 0x00000147
#define TPM2_CC_PolicyPCR       0x0000017F
#define TPM2_CC_PolicyCommandCode 0x0000016C
#define TPM2_CC_PolicyAuthorize 0x0000016A
#define TPM2_CC_PolicySigned    0x00000160
#define TPM2_CC_PolicySecret    0x00000151
#define TPM2_CC_PolicyOR        0x00000171

/* TPM2_SU (startup type) */
#define TPM2_SU_CLEAR   0x0000
#define TPM2_SU_STATE   0x0001

/* TPM algorithm IDs */
#define TPM2_ALG_RSA        0x0001
#define TPM2_ALG_SHA1       0x0004
#define TPM2_ALG_HMAC       0x0005
#define TPM2_ALG_AES        0x0006
#define TPM2_ALG_KEYEDHASH  0x0008
#define TPM2_ALG_SHA256     0x000B
#define TPM2_ALG_SHA384     0x000C
#define TPM2_ALG_SHA512     0x000D
#define TPM2_ALG_NULL       0x0010
#define TPM2_ALG_ECC        0x0023
#define TPM2_ALG_SYMCIPHER  0x0025
#define TPM2_ALG_RSASSA     0x0014
#define TPM2_ALG_RSAES      0x0015
#define TPM2_ALG_RSAPSS     0x0016
#define TPM2_ALG_OAEP       0x0017
#define TPM2_ALG_ECDSA      0x0018
#define TPM2_ALG_ECDH       0x0019
#define TPM2_ALG_CFB        0x0043
#define TPM2_ALG_ECB        0x0044

/* TPM RC success */
#define TPM2_RC_SUCCESS     0x00000000

/*
 * Marshal a TPM2B (uint16 size + bytes).
 * If data is NULL and len > 0, writes a zero-filled TPM2B of that size.
 */
int htpm2_marshal_tpm2b(heim_storage *sp, const void *data, size_t len);

/*
 * Unmarshal a TPM2B.  Allocates *data; caller frees with free().
 */
int htpm2_unmarshal_tpm2b(heim_storage *sp, void **data, uint16_t *len);

/*
 * Build a minimal TPM command header into storage.
 * Returns the storage positioned after the header (caller appends params).
 * After appending params, call htpm2_marshal_fixup_size() to patch the
 * size field.
 */
int htpm2_marshal_cmd_header(heim_storage *sp, uint16_t tag, uint32_t cc);

/*
 * Patch the size field in a command that was built with
 * htpm2_marshal_cmd_header().
 */
int htpm2_marshal_fixup_size(heim_storage *sp);

/*
 * Parse a TPM response header.
 * Returns the response code.  *tag and *size are output parameters.
 */
int htpm2_unmarshal_rsp_header(heim_storage *sp, uint16_t *tag,
                               uint32_t *size, uint32_t *rc);

/*
 * Execute a TPM command: marshal from storage, send/recv via transport,
 * unmarshal response header into a new storage.
 *
 * On success, *rsp_sp is a storage positioned after the 10-byte header,
 * ready for parameter unmarshalling.  Caller must free it with
 * heim_storage_free().
 *
 * Returns HTPM2_OK or an error result (transport or TPM error).
 */
htpm2_result htpm2_command_execute(const htpm2_context ctx,
                                   htpm2_transport tp,
                                   heim_storage *cmd_sp,
                                   heim_storage **rsp_sp,
                                   uint32_t *rc);

/*
 * Build and execute a command with a single authorization session.
 *
 * This handles the TPM_ST_SESSIONS framing:
 *   header (tag=SESSIONS) | handles | authorizationSize | authArea | params
 *
 * `handles` is already marshalled into handle_sp.
 * `params` is already marshalled into param_sp.
 * `session` may be NULL for password auth (TPM_RS_PW).
 *
 * On success, *rsp_sp is positioned after the response header and
 * parameterSize field, ready for response parameter unmarshalling.
 */
htpm2_result htpm2_command_execute_with_auth(
    const htpm2_context ctx,
    htpm2_transport tp,
    uint32_t command_code,
    const uint32_t *handles, size_t num_handles,
    htpm2_session session,
    const void *param_bytes, size_t param_bytes_len,
    heim_storage **rsp_sp,
    uint32_t *rc);

#endif /* __htpm2_marshal_h__ */
