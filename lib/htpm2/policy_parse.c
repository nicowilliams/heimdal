/*
 * Copyright (c) 2026 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.  BSD 3-clause license.
 */

/*
 * TPM 2.0 policy language parser.
 * Parses JSON via heim_json_create() into internal htpm2_policy_doc.
 */

#include "htpm2_locl.h"
#include "policy_p.h"
#include "marshal.h"

#include <heimbase.h>

#define MAX_POLICY_DEPTH 8

/* --- Helpers for extracting typed values from heim dicts --- */

/* Helper to look up a dict value by C string key */
static heim_object_t
dict_get(heim_dict_t d, const char *key)
{
    heim_string_t ks = heim_string_create(key);
    heim_object_t v;
    if (ks == NULL) return NULL;
    v = heim_dict_get_value(d, ks);
    heim_release(ks);
    return v;
}

static const char *
dict_get_string(heim_dict_t d, const char *key)
{
    heim_object_t v = dict_get(d, key);
    if (v == NULL || heim_get_tid(v) != HEIM_TID_STRING)
        return NULL;
    return heim_string_get_utf8((heim_string_t)v);
}

static int64_t
dict_get_int(heim_dict_t d, const char *key, int64_t dflt)
{
    heim_object_t v = dict_get(d, key);
    if (v == NULL || heim_get_tid(v) != HEIM_TID_NUMBER)
        return dflt;
    return heim_number_get_long((heim_number_t)v);
}

static int
dict_get_bool(heim_dict_t d, const char *key, int dflt)
{
    heim_object_t v = dict_get(d, key);
    if (v == NULL || heim_get_tid(v) != HEIM_TID_BOOL)
        return dflt;
    return heim_bool_val(v);
}

static heim_dict_t
dict_get_dict(heim_dict_t d, const char *key)
{
    heim_object_t v = dict_get(d, key);
    if (v == NULL || heim_get_tid(v) != HEIM_TID_DICT)
        return NULL;
    return (heim_dict_t)v;
}

static heim_array_t
dict_get_array(heim_dict_t d, const char *key)
{
    heim_object_t v = dict_get(d, key);
    if (v == NULL || heim_get_tid(v) != HEIM_TID_ARRAY)
        return NULL;
    return (heim_array_t)v;
}

static char *
xstrdup(const char *s)
{
    return s ? strdup(s) : NULL;
}

/* Parse hex string to binary.  Caller frees. */
static int
hex_decode(const char *hex, void **out, size_t *out_len)
{
    size_t len, i;
    uint8_t *buf;

    if (hex == NULL || *hex == '\0') {
        *out = NULL;
        *out_len = 0;
        return 0;
    }

    len = strlen(hex);
    if (len % 2 != 0)
        return EINVAL;
    len /= 2;

    buf = malloc(len);
    if (buf == NULL)
        return ENOMEM;

    for (i = 0; i < len; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%02x", &byte) != 1) {
            free(buf);
            return EINVAL;
        }
        buf[i] = (uint8_t)byte;
    }

    *out = buf;
    *out_len = len;
    return 0;
}

/*
 * Parse a policy_value: if the string starts with '$', store as a
 * variable reference.  Otherwise, hex-decode as literal bytes.
 */
static int
parse_policy_value(const char *s, htpm2_policy_value *pv)
{
    memset(pv, 0, sizeof(*pv));
    if (s == NULL || *s == '\0')
        return 0;
    if (s[0] == '$') {
        pv->var_name = xstrdup(s);
        return pv->var_name ? 0 : ENOMEM;
    }
    return hex_decode(s, &pv->data, &pv->data_len);
}

static void
free_policy_value(htpm2_policy_value *pv)
{
    free(pv->var_name);
    free(pv->data);
    memset(pv, 0, sizeof(*pv));
}

/*
 * Resolve a policy_value against runtime inputs.
 */
int
htpm2_policy_value_resolve(const htpm2_policy_value *pv,
                           const htpm2_policy_input_value *inputs,
                           size_t num_inputs,
                           const void **out, size_t *out_len)
{
    if (pv->var_name) {
        size_t i;
        for (i = 0; i < num_inputs; i++) {
            if (inputs[i].name &&
                strcmp(inputs[i].name, pv->var_name) == 0) {
                *out = inputs[i].value;
                *out_len = inputs[i].value_len;
                return 0;
            }
        }
        *out = NULL;
        *out_len = 0;
        return ENOENT; /* variable not found in inputs */
    }
    *out = pv->data;
    *out_len = pv->data_len;
    return 0;
}

/* --- Lookup tables --- */

static uint16_t
parse_hash_alg(const char *s)
{
    if (s == NULL || strcasecmp(s, "sha256") == 0) return TPM2_ALG_SHA256;
    if (strcasecmp(s, "sha384") == 0) return TPM2_ALG_SHA384;
    if (strcasecmp(s, "sha512") == 0) return TPM2_ALG_SHA512;
    if (strcasecmp(s, "sha1") == 0) return TPM2_ALG_SHA1;
    return TPM2_ALG_SHA256;
}

static uint32_t
parse_command_code(const char *s)
{
    if (s == NULL) return 0;

    /* Try hex first */
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        return (uint32_t)strtoul(s, NULL, 16);

    /* Named command codes */
    if (strcasecmp(s, "Sign") == 0) return TPM2_CC_Sign;
    if (strcasecmp(s, "Quote") == 0) return TPM2_CC_Quote;
    if (strcasecmp(s, "Certify") == 0) return TPM2_CC_Certify;
    if (strcasecmp(s, "Create") == 0) return TPM2_CC_Create;
    if (strcasecmp(s, "CreatePrimary") == 0) return TPM2_CC_CreatePrimary;
    if (strcasecmp(s, "Load") == 0) return TPM2_CC_Load;
    if (strcasecmp(s, "Duplicate") == 0) return TPM2_CC_Duplicate;
    if (strcasecmp(s, "Import") == 0) return TPM2_CC_Import;
    if (strcasecmp(s, "ActivateCredential") == 0) return TPM2_CC_ActivateCredential;
    if (strcasecmp(s, "RSA_Decrypt") == 0) return TPM2_CC_RSA_Decrypt;
    if (strcasecmp(s, "ECDH_ZGen") == 0) return TPM2_CC_ECDH_ZGen;
    if (strcasecmp(s, "EvictControl") == 0) return TPM2_CC_EvictControl;
    /* ... more can be added */
    return (uint32_t)strtoul(s, NULL, 0);
}

static uint32_t
parse_policy_cc(const char *s)
{
    if (s == NULL) return 0;
    if (strcasecmp(s, "PolicyPCR") == 0) return HTPM2_POL_PCR;
    if (strcasecmp(s, "PolicyCommandCode") == 0) return HTPM2_POL_COMMAND_CODE;
    if (strcasecmp(s, "PolicyAuthValue") == 0) return HTPM2_POL_AUTH_VALUE;
    if (strcasecmp(s, "PolicyPassword") == 0) return HTPM2_POL_PASSWORD;
    if (strcasecmp(s, "PolicySigned") == 0) return HTPM2_POL_SIGNED;
    if (strcasecmp(s, "PolicySecret") == 0) return HTPM2_POL_SECRET;
    if (strcasecmp(s, "PolicyAuthorize") == 0) return HTPM2_POL_AUTHORIZE;
    if (strcasecmp(s, "PolicyOR") == 0) return HTPM2_POL_OR;
    if (strcasecmp(s, "PolicyOr") == 0) return HTPM2_POL_OR;
    if (strcasecmp(s, "PolicyLocality") == 0) return HTPM2_POL_LOCALITY;
    if (strcasecmp(s, "PolicyNV") == 0) return HTPM2_POL_NV;
    if (strcasecmp(s, "PolicyCounterTimer") == 0) return HTPM2_POL_COUNTER_TIMER;
    if (strcasecmp(s, "PolicyPhysicalPresence") == 0) return HTPM2_POL_PHYSICAL_PRESENCE;
    if (strcasecmp(s, "PolicyCpHash") == 0) return HTPM2_POL_CP_HASH;
    if (strcasecmp(s, "PolicyNameHash") == 0) return HTPM2_POL_NAME_HASH;
    if (strcasecmp(s, "PolicyDuplicationSelect") == 0) return HTPM2_POL_DUPLICATION_SELECT;
    if (strcasecmp(s, "PolicyTicket") == 0) return HTPM2_POL_TICKET;
    if (strcasecmp(s, "PolicyNvWritten") == 0) return HTPM2_POL_NV_WRITTEN;
    if (strcasecmp(s, "PolicyTemplate") == 0) return HTPM2_POL_TEMPLATE;
    if (strcasecmp(s, "PolicyAuthorizeNV") == 0) return HTPM2_POL_AUTHORIZE_NV;
    if (strcasecmp(s, "PolicyAuthorizeNv") == 0) return HTPM2_POL_AUTHORIZE_NV;
    return 0;
}

static uint16_t
parse_nv_operation(const char *s)
{
    if (s == NULL || strcasecmp(s, "eq") == 0) return HTPM2_EO_EQ;
    if (strcasecmp(s, "neq") == 0) return HTPM2_EO_NEQ;
    if (strcasecmp(s, "gt") == 0) return HTPM2_EO_UNSIGNED_GT;
    if (strcasecmp(s, "lt") == 0) return HTPM2_EO_UNSIGNED_LT;
    if (strcasecmp(s, "ge") == 0) return HTPM2_EO_UNSIGNED_GE;
    if (strcasecmp(s, "le") == 0) return HTPM2_EO_UNSIGNED_LE;
    if (strcasecmp(s, "bitset") == 0) return HTPM2_EO_BITSET;
    if (strcasecmp(s, "bitclear") == 0) return HTPM2_EO_BITCLEAR;
    return HTPM2_EO_EQ;
}

static uint32_t
parse_hierarchy(const char *s)
{
    if (s == NULL || strcasecmp(s, "owner") == 0) return HTPM2_HIERARCHY_OWNER;
    if (strcasecmp(s, "endorsement") == 0) return HTPM2_HIERARCHY_ENDORSEMENT;
    if (strcasecmp(s, "platform") == 0) return HTPM2_HIERARCHY_PLATFORM;
    if (strcasecmp(s, "null") == 0) return HTPM2_HIERARCHY_NULL;
    return (uint32_t)strtoul(s, NULL, 0);
}

static uint32_t
parse_handle(const char *s)
{
    if (s == NULL) return 0;
    return (uint32_t)strtoul(s, NULL, 0);
}

/* --- Parse object definition --- */

static htpm2_result
parse_object_def(heim_dict_t d, htpm2_object_def **out)
{
    htpm2_object_def *def;
    heim_dict_t od;
    const char *s;

    *out = NULL;
    od = dict_get_dict(d, "objectDef");
    if (od == NULL)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "policy: missing objectDef");

    def = calloc(1, sizeof(*def));
    if (def == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "policy: alloc objectDef");

    /* Pre-computed Name (optional -- allows compilation without TPM) */
    hex_decode(dict_get_string(od, "name"), &def->name, &def->name_len);

    s = dict_get_string(od, "persistent");
    if (s) {
        def->strategy = HTPM2_OBJDEF_PERSISTENT;
        def->u.persistent_handle = parse_handle(s);
        *out = def;
        return HTPM2_OK;
    }

    {
        heim_dict_t primary = dict_get_dict(od, "primary");
        if (primary) {
            def->strategy = HTPM2_OBJDEF_PRIMARY;
            def->u.primary.hierarchy = parse_hierarchy(
                dict_get_string(primary, "hierarchy"));
            def->u.primary.template_name = xstrdup(
                dict_get_string(primary, "template"));
            *out = def;
            return HTPM2_OK;
        }
    }

    s = dict_get_string(od, "nvIndex");
    if (s) {
        def->strategy = HTPM2_OBJDEF_NV;
        def->u.nv_index = parse_handle(s);
        *out = def;
        return HTPM2_OK;
    }

    {
        heim_dict_t wk = dict_get_dict(od, "wellKnown");
        if (wk) {
            def->strategy = HTPM2_OBJDEF_WELLKNOWN;
            hex_decode(dict_get_string(wk, "policy"),
                       &def->u.wellknown.policy_digest,
                       &def->u.wellknown.policy_digest_len);
            *out = def;
            return HTPM2_OK;
        }
    }

    free(def);
    return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                              "policy: unrecognized objectDef strategy");
}

/* --- Parse a single policy node --- */

static htpm2_result
parse_node(heim_dict_t nd, htpm2_policy_node *node, int depth)
{
    const char *cc_str;
    uint32_t cc;

    memset(node, 0, sizeof(*node));

    cc_str = dict_get_string(nd, "cc");
    if (cc_str == NULL)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "policy node: missing 'cc'");

    cc = parse_policy_cc(cc_str);
    if (cc == 0)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "policy node: unknown cc '%s'", cc_str);

    node->cc = cc;

    switch (cc) {
    case HTPM2_POL_PCR: {
        heim_dict_t pcrs = dict_get_dict(nd, "pcrs");
        if (pcrs) {
            node->u.pcr.hash_alg = parse_hash_alg(
                dict_get_string(pcrs, "hashAlg"));
            heim_array_t sels = dict_get_array(pcrs, "selections");
            if (sels) {
                size_t n = heim_array_get_length(sels);
                size_t i;
                for (i = 0; i < n; i++) {
                    heim_dict_t sel = heim_array_get_value(sels, i);
                    if (sel && heim_get_tid(sel) == HEIM_TID_DICT) {
                        int pcr = (int)dict_get_int(sel, "pcr", -1);
                        if (pcr >= 0 && pcr <= 23)
                            node->u.pcr.pcr_bitmask |= (1U << pcr);
                    }
                }
            }
        }
        hex_decode(dict_get_string(nd, "pcrDigest"),
                   &node->u.pcr.pcr_digest, &node->u.pcr.pcr_digest_len);
        break;
    }

    case HTPM2_POL_COMMAND_CODE:
        node->u.command_code.command_code = parse_command_code(
            dict_get_string(nd, "commandCode"));
        break;

    case HTPM2_POL_AUTH_VALUE:
    case HTPM2_POL_PASSWORD:
    case HTPM2_POL_PHYSICAL_PRESENCE:
        /* No parameters */
        break;

    case HTPM2_POL_SIGNED:
    case HTPM2_POL_SECRET: {
        htpm2_result r = parse_object_def(nd, &node->u.signed_or_secret.auth_object);
        if (htpm2_is_err(r)) return r;
        hex_decode(dict_get_string(nd, "policyRef"),
                   &node->u.signed_or_secret.policy_ref,
                   &node->u.signed_or_secret.policy_ref_len);
        node->u.signed_or_secret.expiration =
            (int32_t)dict_get_int(nd, "expiration", 0);
        node->u.signed_or_secret.auth_input =
            xstrdup(dict_get_string(nd, "auth"));
        break;
    }

    case HTPM2_POL_AUTHORIZE: {
        htpm2_result r = parse_object_def(nd, &node->u.authorize.key_sign);
        if (htpm2_is_err(r)) return r;
        node->u.authorize.approved_policy_input =
            xstrdup(dict_get_string(nd, "approvedPolicy"));
        hex_decode(dict_get_string(nd, "policyRef"),
                   &node->u.authorize.policy_ref,
                   &node->u.authorize.policy_ref_len);
        node->u.authorize.ticket_input =
            xstrdup(dict_get_string(nd, "ticket"));
        break;
    }

    case HTPM2_POL_OR: {
        heim_array_t alts = dict_get_array(nd, "alternatives");
        size_t n, i;

        if (depth >= MAX_POLICY_DEPTH)
            return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                      "policy: PolicyOr depth limit exceeded");

        if (alts == NULL)
            return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                      "policy: PolicyOr missing alternatives");

        n = heim_array_get_length(alts);
        if (n < 2 || n > 8)
            return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                      "policy: PolicyOr needs 2-8 alternatives, "
                                      "got %zu", n);

        node->u.or_node.alternatives = calloc(n, sizeof(htpm2_policy_ref));
        if (node->u.or_node.alternatives == NULL)
            return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                      "policy: alloc alternatives");
        node->u.or_node.num_alternatives = n;

        for (i = 0; i < n; i++) {
            heim_dict_t alt = heim_array_get_value(alts, i);
            htpm2_policy_ref *ref = &node->u.or_node.alternatives[i];

            if (alt == NULL || heim_get_tid(alt) != HEIM_TID_DICT)
                continue;

            ref->name = xstrdup(dict_get_string(alt, "reference"));
            ref->uri = xstrdup(dict_get_string(alt, "uri"));

            /* Inline policy */
            heim_dict_t inline_pol = dict_get_dict(alt, "tpm2Policy");
            if (inline_pol) {
                /* Recursive parse -- will be implemented via
                 * htpm2_policy_parse_dict() */
            }
        }

        node->u.or_node.select_input =
            xstrdup(dict_get_string(nd, "select"));
        break;
    }

    case HTPM2_POL_LOCALITY:
        node->u.locality.locality =
            (uint8_t)dict_get_int(nd, "locality", 0);
        break;

    case HTPM2_POL_NV:
        node->u.nv.nv_index = parse_handle(dict_get_string(nd, "nvIndex"));
        hex_decode(dict_get_string(nd, "operandB"),
                   &node->u.nv.operand_b, &node->u.nv.operand_b_len);
        node->u.nv.offset = (uint16_t)dict_get_int(nd, "offset", 0);
        node->u.nv.operation = parse_nv_operation(
            dict_get_string(nd, "operation"));
        break;

    case HTPM2_POL_COUNTER_TIMER:
        hex_decode(dict_get_string(nd, "operandB"),
                   &node->u.counter_timer.operand_b,
                   &node->u.counter_timer.operand_b_len);
        node->u.counter_timer.offset =
            (uint16_t)dict_get_int(nd, "offset", 0);
        node->u.counter_timer.operation = parse_nv_operation(
            dict_get_string(nd, "operation"));
        break;

    case HTPM2_POL_CP_HASH:
        hex_decode(dict_get_string(nd, "cpHash"),
                   &node->u.hash.hash, &node->u.hash.hash_len);
        break;

    case HTPM2_POL_NAME_HASH:
        hex_decode(dict_get_string(nd, "nameHash"),
                   &node->u.hash.hash, &node->u.hash.hash_len);
        break;

    case HTPM2_POL_TEMPLATE:
        hex_decode(dict_get_string(nd, "templateHash"),
                   &node->u.hash.hash, &node->u.hash.hash_len);
        break;

    case HTPM2_POL_DUPLICATION_SELECT:
        parse_policy_value(dict_get_string(nd, "objectName"),
                           &node->u.duplication_select.object_name);
        parse_policy_value(dict_get_string(nd, "newParentName"),
                           &node->u.duplication_select.new_parent_name);
        node->u.duplication_select.include_object =
            dict_get_bool(nd, "includeObject", 1);
        break;

    case HTPM2_POL_NV_WRITTEN:
        node->u.nv_written.written_set =
            dict_get_bool(nd, "writtenSet", 1);
        break;

    case HTPM2_POL_AUTHORIZE_NV:
        node->u.authorize_nv.nv_index =
            parse_handle(dict_get_string(nd, "nvIndex"));
        break;

    case HTPM2_POL_TICKET:
        hex_decode(dict_get_string(nd, "timeout"),
                   &node->u.ticket.timeout, &node->u.ticket.timeout_len);
        hex_decode(dict_get_string(nd, "cpHashA"),
                   &node->u.ticket.cp_hash_a, &node->u.ticket.cp_hash_a_len);
        hex_decode(dict_get_string(nd, "policyRef"),
                   &node->u.ticket.policy_ref, &node->u.ticket.policy_ref_len);
        hex_decode(dict_get_string(nd, "authName"),
                   &node->u.ticket.auth_name, &node->u.ticket.auth_name_len);
        node->u.ticket.ticket_input =
            xstrdup(dict_get_string(nd, "ticket"));
        break;

    default:
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "policy: unhandled cc 0x%08x", cc);
    }

    return HTPM2_OK;
}

/* --- Parse a policy document from a heim_dict_t --- */

static htpm2_result
parse_policy_dict(heim_dict_t pol, htpm2_policy_doc **doc, int depth)
{
    htpm2_policy_doc *d;
    heim_array_t inputs, nodes;
    size_t i, n;
    htpm2_result r;

    if (depth > MAX_POLICY_DEPTH)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "policy: depth limit exceeded (%d)", depth);

    d = calloc(1, sizeof(*d));
    if (d == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "policy: alloc doc");

    d->name = xstrdup(dict_get_string(pol, "name"));
    d->description = xstrdup(dict_get_string(pol, "description"));
    d->hash_alg = parse_hash_alg(dict_get_string(pol, "hashAlg"));

    /* Parse inputs */
    inputs = dict_get_array(pol, "inputs");
    if (inputs) {
        n = heim_array_get_length(inputs);
        d->inputs = calloc(n, sizeof(htpm2_policy_input));
        if (d->inputs == NULL) {
            htpm2_policy_doc_free(d);
            return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                      "policy: alloc inputs");
        }
        d->num_inputs = n;

        for (i = 0; i < n; i++) {
            heim_dict_t inp = heim_array_get_value(inputs, i);
            if (inp == NULL || heim_get_tid(inp) != HEIM_TID_DICT)
                continue;

            d->inputs[i].name = xstrdup(dict_get_string(inp, "input"));
            d->inputs[i].description = xstrdup(
                dict_get_string(inp, "description"));

            const char *vt = dict_get_string(inp, "valueType");
            if (vt == NULL) d->inputs[i].value_type = HTPM2_INPUT_BYTES;
            else if (strcmp(vt, "signature") == 0) d->inputs[i].value_type = HTPM2_INPUT_SIGNATURE;
            else if (strcmp(vt, "ticket") == 0) d->inputs[i].value_type = HTPM2_INPUT_TICKET;
            else if (strcmp(vt, "bytes") == 0) d->inputs[i].value_type = HTPM2_INPUT_BYTES;
            else if (strcmp(vt, "arrayIndex") == 0) d->inputs[i].value_type = HTPM2_INPUT_ARRAY_INDEX;
            else if (strcmp(vt, "integer") == 0) d->inputs[i].value_type = HTPM2_INPUT_INTEGER;
            else if (strcmp(vt, "boolean") == 0) d->inputs[i].value_type = HTPM2_INPUT_BOOLEAN;
            else d->inputs[i].value_type = HTPM2_INPUT_BYTES;
        }
    }

    /* Parse policy nodes */
    nodes = dict_get_array(pol, "policy");
    if (nodes == NULL) {
        htpm2_policy_doc_free(d);
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "policy '%s': missing 'policy' array",
                                  d->name ? d->name : "(unnamed)");
    }

    n = heim_array_get_length(nodes);
    d->nodes = calloc(n, sizeof(htpm2_policy_node));
    if (d->nodes == NULL) {
        htpm2_policy_doc_free(d);
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "policy: alloc nodes");
    }
    d->num_nodes = n;

    for (i = 0; i < n; i++) {
        heim_dict_t nd = heim_array_get_value(nodes, i);
        if (nd == NULL || heim_get_tid(nd) != HEIM_TID_DICT) {
            htpm2_policy_doc_free(d);
            return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                      "policy: node %zu is not an object", i);
        }

        r = parse_node(nd, &d->nodes[i], depth);
        if (htpm2_is_err(r)) {
            char *saved_name = d->name ? strdup(d->name) : NULL;
            htpm2_policy_doc_free(d);
            r = htpm2_result_prepend(r, "policy '%s' node %zu",
                                     saved_name ? saved_name : "", i);
            free(saved_name);
            return r;
        }
    }

    /* Validate: PolicyAuthorize/PolicyAuthorizeNV must be first */
    if (d->num_nodes > 0) {
        for (i = 1; i < d->num_nodes; i++) {
            if (d->nodes[i].cc == HTPM2_POL_AUTHORIZE ||
                d->nodes[i].cc == HTPM2_POL_AUTHORIZE_NV) {
                char *saved_name = d->name ? strdup(d->name) : NULL;
                htpm2_policy_doc_free(d);
                htpm2_result er = htpm2_result_local(EINVAL,
                    HTPM2_F_LOCAL, EINVAL,
                    "policy '%s': PolicyAuthorize/PolicyAuthorizeNV "
                    "must be the first command (found at node %zu)",
                    saved_name ? saved_name : "", i);
                free(saved_name);
                return er;
            }
        }
    }

    *doc = d;
    return HTPM2_OK;
}

/* --- Public API --- */

htpm2_result
htpm2_policy_parse(const char *json_text, size_t json_len,
                   htpm2_policy_doc **doc)
{
    heim_object_t root;
    heim_error_t error = NULL;
    heim_dict_t pol;
    htpm2_result r;

    *doc = NULL;

    if (json_len == 0)
        json_len = strlen(json_text);

    root = heim_json_create_with_bytes(json_text, json_len,
                                       MAX_POLICY_DEPTH + 2, 0, &error);
    if (root == NULL) {
        htpm2_result res = htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                              "policy: JSON parse error");
        if (error)
            heim_release(error);
        return res;
    }

    if (heim_get_tid(root) != HEIM_TID_DICT) {
        heim_release(root);
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "policy: top-level must be an object");
    }

    pol = dict_get_dict((heim_dict_t)root, "tpm2Policy");
    if (pol == NULL) {
        heim_release(root);
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "policy: missing 'tpm2Policy' key");
    }

    r = parse_policy_dict(pol, doc, 0);
    heim_release(root);
    return r;
}

/* --- Cleanup --- */

static void
free_object_def(htpm2_object_def *def)
{
    if (def == NULL) return;
    free(def->name);
    switch (def->strategy) {
    case HTPM2_OBJDEF_PRIMARY:
        free(def->u.primary.template_name);
        break;
    case HTPM2_OBJDEF_LOAD:
        free_object_def(def->u.load.parent);
        free(def->u.load.pub);
        free(def->u.load.priv);
        break;
    case HTPM2_OBJDEF_WELLKNOWN:
        free(def->u.wellknown.policy_digest);
        break;
    default:
        break;
    }
    free(def);
}

static void
free_node(htpm2_policy_node *node)
{
    switch (node->cc) {
    case HTPM2_POL_PCR:
        free(node->u.pcr.pcr_digest);
        break;
    case HTPM2_POL_SIGNED:
    case HTPM2_POL_SECRET:
        free_object_def(node->u.signed_or_secret.auth_object);
        free(node->u.signed_or_secret.policy_ref);
        free(node->u.signed_or_secret.auth_input);
        break;
    case HTPM2_POL_AUTHORIZE:
        free_object_def(node->u.authorize.key_sign);
        free(node->u.authorize.approved_policy_input);
        free(node->u.authorize.policy_ref);
        free(node->u.authorize.ticket_input);
        break;
    case HTPM2_POL_OR: {
        size_t i;
        for (i = 0; i < node->u.or_node.num_alternatives; i++) {
            free(node->u.or_node.alternatives[i].name);
            free(node->u.or_node.alternatives[i].uri);
            if (node->u.or_node.alternatives[i].inline_policy)
                htpm2_policy_doc_free(
                    node->u.or_node.alternatives[i].inline_policy);
        }
        free(node->u.or_node.alternatives);
        free(node->u.or_node.select_input);
        break;
    }
    case HTPM2_POL_NV:
        free(node->u.nv.operand_b);
        break;
    case HTPM2_POL_COUNTER_TIMER:
        free(node->u.counter_timer.operand_b);
        break;
    case HTPM2_POL_CP_HASH:
    case HTPM2_POL_NAME_HASH:
    case HTPM2_POL_TEMPLATE:
        free(node->u.hash.hash);
        break;
    case HTPM2_POL_DUPLICATION_SELECT:
        free_policy_value(&node->u.duplication_select.object_name);
        free_policy_value(&node->u.duplication_select.new_parent_name);
        break;
    case HTPM2_POL_TICKET:
        free(node->u.ticket.timeout);
        free(node->u.ticket.cp_hash_a);
        free(node->u.ticket.policy_ref);
        free(node->u.ticket.auth_name);
        free(node->u.ticket.ticket_input);
        break;
    default:
        break;
    }
}

void
htpm2_policy_doc_free(htpm2_policy_doc *doc)
{
    size_t i;

    if (doc == NULL) return;

    free(doc->name);
    free(doc->description);

    for (i = 0; i < doc->num_inputs; i++) {
        free(doc->inputs[i].name);
        free(doc->inputs[i].description);
    }
    free(doc->inputs);

    for (i = 0; i < doc->num_nodes; i++)
        free_node(&doc->nodes[i]);
    free(doc->nodes);

    free(doc);
}
