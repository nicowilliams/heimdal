/*
 * TPM 2.0 policy language -- parsed representation.
 */

#ifndef __htpm2_policy_p_h__
#define __htpm2_policy_p_h__

#include "htpm2.h"
#include <stdint.h>
#include <stddef.h>

/* --- Policy command codes --- */

/* We reuse TPM_CC values where they exist, and define our own for
 * convenience lookups */
#define HTPM2_POL_PCR               0x0000017F
#define HTPM2_POL_COMMAND_CODE      0x0000016C
#define HTPM2_POL_AUTH_VALUE        0x0000016B
#define HTPM2_POL_PASSWORD          0x0000016C  /* same digest as AuthValue */
#define HTPM2_POL_SIGNED            0x00000160
#define HTPM2_POL_SECRET            0x00000151
#define HTPM2_POL_AUTHORIZE         0x0000016A
#define HTPM2_POL_OR                0x00000171
#define HTPM2_POL_LOCALITY          0x0000016F
#define HTPM2_POL_NV                0x00000149
#define HTPM2_POL_COUNTER_TIMER     0x0000016D
#define HTPM2_POL_PHYSICAL_PRESENCE 0x00000187
#define HTPM2_POL_CP_HASH           0x0000012C
#define HTPM2_POL_NAME_HASH         0x00000170
#define HTPM2_POL_DUPLICATION_SELECT 0x00000188
#define HTPM2_POL_TICKET            0x00000169
#define HTPM2_POL_NV_WRITTEN        0x0000018F
#define HTPM2_POL_TEMPLATE          0x00000190
#define HTPM2_POL_AUTHORIZE_NV      0x00000192

/* --- Input value types --- */

typedef enum {
    HTPM2_INPUT_SIGNATURE = 0,
    HTPM2_INPUT_TICKET,
    HTPM2_INPUT_BYTES,
    HTPM2_INPUT_ARRAY_INDEX,
    HTPM2_INPUT_INTEGER,
    HTPM2_INPUT_BOOLEAN
} htpm2_input_type;

/* --- NV comparison operations (TPM2_EO) --- */

#define HTPM2_EO_EQ        0x0000
#define HTPM2_EO_NEQ       0x0001
#define HTPM2_EO_SIGNED_GT 0x0002
#define HTPM2_EO_UNSIGNED_GT 0x0003
#define HTPM2_EO_SIGNED_LT 0x0004
#define HTPM2_EO_UNSIGNED_LT 0x0005
#define HTPM2_EO_SIGNED_GE 0x0006
#define HTPM2_EO_UNSIGNED_GE 0x0007
#define HTPM2_EO_SIGNED_LE 0x0008
#define HTPM2_EO_UNSIGNED_LE 0x0009
#define HTPM2_EO_BITSET    0x000A
#define HTPM2_EO_BITCLEAR  0x000B

/* --- Object definition --- */

typedef struct htpm2_object_def {
    enum {
        HTPM2_OBJDEF_PERSISTENT,
        HTPM2_OBJDEF_PRIMARY,
        HTPM2_OBJDEF_LOAD,
        HTPM2_OBJDEF_NV,
        HTPM2_OBJDEF_WELLKNOWN
    } strategy;
    union {
        uint32_t persistent_handle;
        struct {
            uint32_t hierarchy;
            char *template_name;
        } primary;
        struct {
            struct htpm2_object_def *parent;
            void *pub;
            size_t pub_len;
            void *priv;
            size_t priv_len;
        } load;
        uint32_t nv_index;
        struct {
            void *policy_digest;
            size_t policy_digest_len;
        } wellknown;
    } u;
} htpm2_object_def;

/* --- Policy reference (for PolicyOr alternatives) --- */

typedef struct htpm2_policy_ref {
    char *name;
    char *uri;
    struct htpm2_policy_doc *inline_policy;
} htpm2_policy_ref;

/* --- Policy input declaration --- */

typedef struct htpm2_policy_input {
    char *name;
    char *description;
    htpm2_input_type value_type;
} htpm2_policy_input;

/* --- Policy node --- */

typedef struct htpm2_policy_node {
    uint32_t cc;
    union {
        struct { /* PolicyPCR */
            uint16_t hash_alg;
            uint32_t pcr_bitmask;
            void *pcr_digest;
            size_t pcr_digest_len;
        } pcr;

        struct { /* PolicyCommandCode */
            uint32_t command_code;
        } command_code;

        struct { /* PolicySigned, PolicySecret */
            htpm2_object_def *auth_object;
            void *policy_ref;
            size_t policy_ref_len;
            int32_t expiration;
            char *auth_input;
        } signed_or_secret;

        struct { /* PolicyAuthorize */
            htpm2_object_def *key_sign;
            char *approved_policy_input;
            void *policy_ref;
            size_t policy_ref_len;
            char *ticket_input;
        } authorize;

        struct { /* PolicyOr */
            htpm2_policy_ref *alternatives;
            size_t num_alternatives;
            char *select_input;
        } or_node;

        struct { /* PolicyLocality */
            uint8_t locality;
        } locality;

        struct { /* PolicyNV */
            uint32_t nv_index;
            void *operand_b;
            size_t operand_b_len;
            uint16_t offset;
            uint16_t operation;
        } nv;

        struct { /* PolicyCounterTimer */
            void *operand_b;
            size_t operand_b_len;
            uint16_t offset;
            uint16_t operation;
        } counter_timer;

        struct { /* PolicyCpHash, PolicyNameHash, PolicyTemplate */
            void *hash;
            size_t hash_len;
        } hash;

        struct { /* PolicyDuplicationSelect */
            void *object_name;
            size_t object_name_len;
            void *new_parent_name;
            size_t new_parent_name_len;
            int include_object;
        } duplication_select;

        struct { /* PolicyNvWritten */
            int written_set;
        } nv_written;

        struct { /* PolicyAuthorizeNV */
            uint32_t nv_index;
        } authorize_nv;

        struct { /* PolicyTicket */
            void *timeout;
            size_t timeout_len;
            void *cp_hash_a;
            size_t cp_hash_a_len;
            void *policy_ref;
            size_t policy_ref_len;
            void *auth_name;
            size_t auth_name_len;
            char *ticket_input;
        } ticket;

        /* PolicyAuthValue, PolicyPassword, PolicyPhysicalPresence:
         * no parameters */
    } u;
} htpm2_policy_node;

/* --- Parsed policy document --- */

typedef struct htpm2_policy_doc {
    char *name;
    char *description;
    uint16_t hash_alg;
    htpm2_policy_input *inputs;
    size_t num_inputs;
    htpm2_policy_node *nodes;
    size_t num_nodes;
} htpm2_policy_doc;

/* --- Public API --- */

htpm2_result htpm2_policy_parse(const char *json_text, size_t json_len,
                                htpm2_policy_doc **doc);
void htpm2_policy_doc_free(htpm2_policy_doc *doc);

htpm2_result htpm2_policy_compile(const htpm2_context ctx,
                                  htpm2_transport tp,
                                  const htpm2_policy_doc *doc,
                                  void *digest, size_t *digest_len);

#endif /* __htpm2_policy_p_h__ */
