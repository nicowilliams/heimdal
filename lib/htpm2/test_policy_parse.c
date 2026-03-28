/*
 * Tests for the TPM 2.0 policy JSON parser.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "htpm2.h"
#include "policy_p.h"

static int failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s: %s\n", __func__, msg); \
        failures++; \
    } \
} while (0)

#define CHECK_OK(r, msg) do { \
    if (htpm2_is_err(r)) { \
        fprintf(stderr, "FAIL: %s: %s: %s\n", __func__, msg, \
                (r).message ? (r).message : "(null)"); \
        failures++; \
    } \
} while (0)

static void
test_simple_policy(void)
{
    const char *json =
        "{"
        "  \"tpm2Policy\": {"
        "    \"name\": \"test_simple\","
        "    \"hashAlg\": \"sha256\","
        "    \"policy\": ["
        "      { \"cc\": \"PolicyCommandCode\", \"commandCode\": \"Sign\" },"
        "      { \"cc\": \"PolicyAuthValue\" }"
        "    ]"
        "  }"
        "}";

    htpm2_policy_doc *doc = NULL;
    htpm2_result r;

    r = htpm2_policy_parse(json, 0, &doc);
    CHECK_OK(r, "parse simple policy");
    CHECK(doc != NULL, "doc should be non-NULL");

    if (doc) {
        CHECK(strcmp(doc->name, "test_simple") == 0, "name");
        CHECK(doc->hash_alg == 0x000B, "hash_alg should be SHA-256");
        CHECK(doc->num_nodes == 2, "should have 2 nodes");
        CHECK(doc->nodes[0].cc == 0x0000016C, "node 0 = PolicyCommandCode");
        CHECK(doc->nodes[0].u.command_code.command_code == 0x0000015D,
              "command code = Sign");
        CHECK(doc->nodes[1].cc == 0x0000016B, "node 1 = PolicyAuthValue");
        htpm2_policy_doc_free(doc);
    }
    htpm2_result_free(&r);
}

static void
test_pcr_policy(void)
{
    const char *json =
        "{"
        "  \"tpm2Policy\": {"
        "    \"name\": \"test_pcr\","
        "    \"policy\": ["
        "      {"
        "        \"cc\": \"PolicyPCR\","
        "        \"pcrs\": {"
        "          \"hashAlg\": \"sha256\","
        "          \"selections\": ["
        "            { \"pcr\": 0 },"
        "            { \"pcr\": 7 }"
        "          ]"
        "        }"
        "      }"
        "    ]"
        "  }"
        "}";

    htpm2_policy_doc *doc = NULL;
    htpm2_result r;

    r = htpm2_policy_parse(json, 0, &doc);
    CHECK_OK(r, "parse PCR policy");

    if (doc) {
        CHECK(doc->num_nodes == 1, "1 node");
        CHECK(doc->nodes[0].cc == 0x0000017F, "PolicyPCR");
        CHECK(doc->nodes[0].u.pcr.pcr_bitmask == ((1U << 0) | (1U << 7)),
              "PCR 0 and 7 selected");
        CHECK(doc->nodes[0].u.pcr.hash_alg == 0x000B, "SHA-256");
        htpm2_policy_doc_free(doc);
    }
    htpm2_result_free(&r);
}

static void
test_policy_or(void)
{
    const char *json =
        "{"
        "  \"tpm2Policy\": {"
        "    \"name\": \"test_or\","
        "    \"inputs\": ["
        "      { \"input\": \"$alt\", \"valueType\": \"arrayIndex\" }"
        "    ],"
        "    \"policy\": ["
        "      {"
        "        \"cc\": \"PolicyOR\","
        "        \"alternatives\": ["
        "          { \"reference\": \"policy_a\" },"
        "          { \"reference\": \"policy_b\", \"uri\": \"https://example.com/b.json\" }"
        "        ],"
        "        \"select\": \"$alt\""
        "      }"
        "    ]"
        "  }"
        "}";

    htpm2_policy_doc *doc = NULL;
    htpm2_result r;

    r = htpm2_policy_parse(json, 0, &doc);
    CHECK_OK(r, "parse PolicyOr");

    if (doc) {
        CHECK(doc->num_inputs == 1, "1 input");
        CHECK(doc->inputs[0].value_type == HTPM2_INPUT_ARRAY_INDEX,
              "input type = arrayIndex");
        CHECK(strcmp(doc->inputs[0].name, "$alt") == 0, "input name");
        CHECK(doc->num_nodes == 1, "1 node");
        CHECK(doc->nodes[0].cc == 0x00000171, "PolicyOr");
        CHECK(doc->nodes[0].u.or_node.num_alternatives == 2, "2 alternatives");
        CHECK(strcmp(doc->nodes[0].u.or_node.alternatives[0].name,
                     "policy_a") == 0, "alt 0 name");
        CHECK(doc->nodes[0].u.or_node.alternatives[1].uri != NULL &&
              strcmp(doc->nodes[0].u.or_node.alternatives[1].uri,
                     "https://example.com/b.json") == 0, "alt 1 uri");
        CHECK(strcmp(doc->nodes[0].u.or_node.select_input, "$alt") == 0,
              "select input");
        htpm2_policy_doc_free(doc);
    }
    htpm2_result_free(&r);
}

static void
test_policy_authorize_must_be_first(void)
{
    const char *json =
        "{"
        "  \"tpm2Policy\": {"
        "    \"name\": \"test_bad_authorize\","
        "    \"policy\": ["
        "      { \"cc\": \"PolicyCommandCode\", \"commandCode\": \"Sign\" },"
        "      {"
        "        \"cc\": \"PolicyAuthorize\","
        "        \"objectDef\": { \"persistent\": \"0x81000001\" },"
        "        \"approvedPolicy\": \"$approved\","
        "        \"ticket\": \"$ticket\""
        "      }"
        "    ]"
        "  }"
        "}";

    htpm2_policy_doc *doc = NULL;
    htpm2_result r;

    r = htpm2_policy_parse(json, 0, &doc);
    CHECK(htpm2_is_err(r),
          "PolicyAuthorize not first should fail");
    CHECK(r.message != NULL && strstr(r.message, "must be the first") != NULL,
          "error message should mention 'must be the first'");
    htpm2_result_free(&r);
    htpm2_policy_doc_free(doc);
}

static void
test_policy_nv(void)
{
    const char *json =
        "{"
        "  \"tpm2Policy\": {"
        "    \"name\": \"test_nv\","
        "    \"policy\": ["
        "      {"
        "        \"cc\": \"PolicyNV\","
        "        \"nvIndex\": \"0x01000001\","
        "        \"operandB\": \"0000000000000001\","
        "        \"offset\": 0,"
        "        \"operation\": \"eq\""
        "      }"
        "    ]"
        "  }"
        "}";

    htpm2_policy_doc *doc = NULL;
    htpm2_result r;

    r = htpm2_policy_parse(json, 0, &doc);
    CHECK_OK(r, "parse PolicyNV");

    if (doc) {
        CHECK(doc->nodes[0].cc == 0x00000149, "PolicyNV");
        CHECK(doc->nodes[0].u.nv.nv_index == 0x01000001, "nv index");
        CHECK(doc->nodes[0].u.nv.operand_b_len == 8, "operand_b 8 bytes");
        CHECK(doc->nodes[0].u.nv.operation == 0x0000, "EO_EQ");
        htpm2_policy_doc_free(doc);
    }
    htpm2_result_free(&r);
}

static void
test_invalid_json(void)
{
    htpm2_policy_doc *doc = NULL;
    htpm2_result r;

    r = htpm2_policy_parse("not json", 0, &doc);
    CHECK(htpm2_is_err(r), "invalid JSON should fail");
    htpm2_result_free(&r);

    r = htpm2_policy_parse("{}", 0, &doc);
    CHECK(htpm2_is_err(r), "missing tpm2Policy should fail");
    htpm2_result_free(&r);
}

static void
test_all_parameterless_commands(void)
{
    const char *json =
        "{"
        "  \"tpm2Policy\": {"
        "    \"name\": \"test_paramless\","
        "    \"policy\": ["
        "      { \"cc\": \"PolicyAuthValue\" },"
        "      { \"cc\": \"PolicyPassword\" },"
        "      { \"cc\": \"PolicyPhysicalPresence\" }"
        "    ]"
        "  }"
        "}";

    htpm2_policy_doc *doc = NULL;
    htpm2_result r;

    r = htpm2_policy_parse(json, 0, &doc);
    CHECK_OK(r, "parse parameterless commands");
    if (doc) {
        CHECK(doc->num_nodes == 3, "3 nodes");
        htpm2_policy_doc_free(doc);
    }
    htpm2_result_free(&r);
}

int
main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    test_simple_policy();
    test_pcr_policy();
    test_policy_or();
    test_policy_authorize_must_be_first();
    test_policy_nv();
    test_invalid_json();
    test_all_parameterless_commands();

    if (failures) {
        fprintf(stderr, "%d test(s) FAILED\n", failures);
        return 1;
    }
    printf("All policy parser tests passed.\n");
    return 0;
}
