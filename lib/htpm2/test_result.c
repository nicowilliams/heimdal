/*
 * Tests for htpm2_result -- structured error type and monadic chaining.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "htpm2.h"

static int failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s: %s\n", __func__, msg); \
        failures++; \
    } \
} while (0)

static void
test_ok_value(void)
{
    htpm2_result r = HTPM2_OK;

    CHECK(r.code == 0, "code should be 0");
    CHECK(r.flags == 0, "flags should be 0");
    CHECK(r.message == NULL, "message should be NULL");
    CHECK(htpm2_is_ok(r), "should be OK");
    CHECK(!htpm2_is_err(r), "should not be error");
}

static void
test_result_free_on_ok(void)
{
    htpm2_result r = HTPM2_OK;

    htpm2_result_free(&r);
    CHECK(r.code == 0, "code should be 0 after free");
    CHECK(r.message == NULL, "message should be NULL after free");
}

static void
test_result_free_on_error(void)
{
    htpm2_result r = HTPM2_OK;

    r.code = 1;
    r.message = strdup("test error");
    htpm2_result_free(&r);
    CHECK(r.code == 0, "code should be 0 after free");
    CHECK(r.message == NULL, "message should be NULL after free");
}

static void
test_prepend_on_ok(void)
{
    htpm2_result r = HTPM2_OK;

    r = htpm2_result_prepend(r, "prefix");
    CHECK(htpm2_is_ok(r), "prepend on OK should return OK");
    CHECK(r.message == NULL, "prepend on OK should not allocate");
}

static void
test_prepend_on_error(void)
{
    htpm2_result r = HTPM2_OK;

    r.code = 42;
    r.flags = HTPM2_F_LOCAL;
    r.message = strdup("original");

    r = htpm2_result_prepend(r, "context %d", 1);
    CHECK(htpm2_is_err(r), "should still be error");
    CHECK(r.code == 42, "code should be preserved");
    CHECK(r.flags == HTPM2_F_LOCAL, "flags should be preserved");
    CHECK(r.message != NULL, "message should exist");
    if (r.message)
        CHECK(strstr(r.message, "context 1") != NULL &&
              strstr(r.message, "original") != NULL,
              "message should contain both prefix and original");
    htpm2_result_free(&r);
}

/* A fake function for testing monadic chaining. */
static int chain_call_count;

static htpm2_result
fake_operation(const htpm2_context ctx, htpm2_result prior, int should_fail)
{
    (void)ctx;
    if (prior.code)
        return prior;  /* monadic short-circuit */
    chain_call_count++;
    if (should_fail) {
        htpm2_result r = HTPM2_OK;
        r.code = 99;
        r.flags = HTPM2_F_LOCAL;
        r.message = strdup("fake failure");
        return r;
    }
    return HTPM2_OK;
}

static void
test_chain_all_ok(void)
{
    htpm2_result r = HTPM2_OK;

    chain_call_count = 0;
    r = fake_operation(NULL, r, 0);
    r = fake_operation(NULL, r, 0);
    r = fake_operation(NULL, r, 0);
    CHECK(htpm2_is_ok(r), "all OK chain should succeed");
    CHECK(chain_call_count == 3, "all 3 calls should execute");
    htpm2_result_free(&r);
}

static void
test_chain_error_propagation(void)
{
    htpm2_result r = HTPM2_OK;

    chain_call_count = 0;
    r = fake_operation(NULL, r, 0);  /* ok, count=1 */
    r = fake_operation(NULL, r, 0);  /* ok, count=2 */
    r = fake_operation(NULL, r, 1);  /* fails, count=3 */
    r = fake_operation(NULL, r, 0);  /* skipped */
    r = fake_operation(NULL, r, 0);  /* skipped */
    CHECK(htpm2_is_err(r), "chain should be in error");
    CHECK(r.code == 99, "error code from 3rd call should be preserved");
    CHECK(chain_call_count == 3, "4th and 5th calls should be skipped");
    htpm2_result_free(&r);
}

static void
test_error_flags(void)
{
    htpm2_result r = HTPM2_OK;

    r.code = 1;
    r.flags = HTPM2_F_TPM_RC | HTPM2_F_TRANSPORT;
    r.tpm_rc = 0x00000100;
    CHECK(r.flags & HTPM2_F_TPM_RC, "TPM_RC flag should be set");
    CHECK(r.flags & HTPM2_F_TRANSPORT, "TRANSPORT flag should be set");
    CHECK(!(r.flags & HTPM2_F_OSSL), "OSSL flag should not be set");
    CHECK(r.tpm_rc == 0x00000100, "tpm_rc should be preserved");
}

int
main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    test_ok_value();
    test_result_free_on_ok();
    test_result_free_on_error();
    test_prepend_on_ok();
    test_prepend_on_error();
    test_chain_all_ok();
    test_chain_error_propagation();
    test_error_flags();

    if (failures) {
        fprintf(stderr, "%d test(s) FAILED\n", failures);
        return 1;
    }
    printf("All htpm2_result tests passed.\n");
    return 0;
}
