/*
 * Integration test for htpm2 against swtpm.
 *
 * Starts a swtpm instance, connects via Unix socket, and runs basic
 * TPM commands to validate the full stack: marshalling, transport,
 * command execution.
 *
 * Skips (exit 77) if swtpm is not available.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "htpm2.h"

/* We need the internal startup function */
#include "htpm2_locl.h"
#include "marshal.h"

static int failures = 0;
static char tpm_state_dir[256];
static char socket_path[256];
static pid_t swtpm_pid = 0;

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
cleanup(void)
{
    char cmd[512];

    if (swtpm_pid > 0) {
        kill(swtpm_pid, SIGTERM);
        waitpid(swtpm_pid, NULL, 0);
        swtpm_pid = 0;
    }
    if (tpm_state_dir[0]) {
        snprintf(cmd, sizeof(cmd), "rm -rf %s", tpm_state_dir);
        (void)system(cmd);
    }
}

static int
start_swtpm(void)
{
    char *tmpdir;
    char setup_cmd[512];
    int ret;

    /* Create temp directory for TPM state */
    tmpdir = strdup("/tmp/htpm2_test_XXXXXX");
    if (mkdtemp(tmpdir) == NULL) {
        perror("mkdtemp");
        free(tmpdir);
        return -1;
    }
    strlcpy(tpm_state_dir, tmpdir, sizeof(tpm_state_dir));
    free(tmpdir);

    snprintf(socket_path, sizeof(socket_path), "%s/sock", tpm_state_dir);

    /* Initialize TPM state with swtpm_setup */
    snprintf(setup_cmd, sizeof(setup_cmd),
             "swtpm_setup --tpmstate dir=%s --tpm2 --createek 2>/dev/null",
             tpm_state_dir);
    ret = system(setup_cmd);
    if (ret != 0) {
        fprintf(stderr, "swtpm_setup failed (ret=%d)\n", ret);
        return -1;
    }

    /* Start swtpm */
    swtpm_pid = fork();
    if (swtpm_pid < 0) {
        perror("fork");
        return -1;
    }

    if (swtpm_pid == 0) {
        /* Child: exec swtpm */
        char tpmstate_arg[512];
        char server_arg[512];
        char ctrl_arg[512];

        snprintf(tpmstate_arg, sizeof(tpmstate_arg),
                 "dir=%s", tpm_state_dir);
        snprintf(server_arg, sizeof(server_arg),
                 "type=unixio,path=%s", socket_path);
        snprintf(ctrl_arg, sizeof(ctrl_arg),
                 "type=unixio,path=%s.ctrl", socket_path);
        execlp("swtpm", "swtpm", "socket",
               "--tpmstate", tpmstate_arg,
               "--tpm2",
               "--server", server_arg,
               "--ctrl", ctrl_arg,
               "--flags", "startup-clear",
               (char *)NULL);
        _exit(127);
    }

    /* Wait for socket to appear */
    for (int i = 0; i < 50; i++) {
        struct stat st;
        if (stat(socket_path, &st) == 0)
            return 0;
        usleep(100000);  /* 100ms */
    }

    fprintf(stderr, "swtpm socket did not appear at %s\n", socket_path);
    return -1;
}

static void
test_get_random(htpm2_context ctx, htpm2_transport tp)
{
    unsigned char buf[32] = {0};
    htpm2_result r;

    r = htpm2_get_random(ctx, tp, HTPM2_OK, buf, 32);
    CHECK_OK(r, "GetRandom(32)");

    /* Verify it's not all zeros (probabilistically impossible) */
    {
        int all_zero = 1;
        for (int i = 0; i < 32; i++) {
            if (buf[i] != 0) {
                all_zero = 0;
                break;
            }
        }
        CHECK(!all_zero, "GetRandom should return non-zero bytes");
    }
    htpm2_result_free(&r);
}

static void
test_get_random_twice_differs(htpm2_context ctx, htpm2_transport tp)
{
    unsigned char buf1[32], buf2[32];
    htpm2_result r;

    r = htpm2_get_random(ctx, tp, HTPM2_OK, buf1, 32);
    CHECK_OK(r, "GetRandom first");
    htpm2_result_free(&r);

    r = htpm2_get_random(ctx, tp, HTPM2_OK, buf2, 32);
    CHECK_OK(r, "GetRandom second");
    htpm2_result_free(&r);

    CHECK(memcmp(buf1, buf2, 32) != 0,
          "two GetRandom calls should return different data");
}

static void
test_get_random_large(htpm2_context ctx, htpm2_transport tp)
{
    /* Request more than one TPM batch (>48 bytes) to test looping */
    unsigned char buf[256] = {0};
    htpm2_result r;

    r = htpm2_get_random(ctx, tp, HTPM2_OK, buf, 256);
    CHECK_OK(r, "GetRandom(256) with looping");

    /* Verify not all zeros */
    {
        int all_zero = 1;
        for (int i = 0; i < 256; i++) {
            if (buf[i] != 0) { all_zero = 0; break; }
        }
        CHECK(!all_zero, "GetRandom(256) should return non-zero bytes");
    }
    htpm2_result_free(&r);
}

static void
test_monadic_chain_with_tpm(htpm2_context ctx, htpm2_transport tp)
{
    /* Test monadic chaining: GetRandom into GetRandom -- both should work */
    unsigned char buf1[16], buf2[16];
    htpm2_result r = HTPM2_OK;

    r = htpm2_get_random(ctx, tp, r, buf1, 16);
    r = htpm2_get_random(ctx, tp, r, buf2, 16);
    CHECK_OK(r, "chained GetRandom calls");
    CHECK(memcmp(buf1, buf2, 16) != 0, "chained results should differ");
    htpm2_result_free(&r);
}

static void
test_monadic_chain_error_propagation(htpm2_context ctx, htpm2_transport tp)
{
    /* Pass an error result -- GetRandom should short-circuit */
    unsigned char buf[16] = {0};
    htpm2_result r;

    r.code = 42;
    r.flags = HTPM2_F_LOCAL;
    r.tpm_rc = 0;
    r.local_err = 42;
    r.ossl_err = 0;
    r.message = strdup("injected error");

    r = htpm2_get_random(ctx, tp, r, buf, 16);
    CHECK(htpm2_is_err(r), "should still be error");
    CHECK(r.code == 42, "error code should be preserved");

    /* buf should still be all zeros (command was not executed) */
    {
        int all_zero = 1;
        for (int i = 0; i < 16; i++) {
            if (buf[i] != 0) { all_zero = 0; break; }
        }
        CHECK(all_zero, "buffer should be untouched after short-circuit");
    }
    htpm2_result_free(&r);
}

/* --- Key creation tests --- */

static void
test_create_primary_rsa(htpm2_context ctx, htpm2_transport tp)
{
    htpm2_object srk = NULL;
    htpm2_result r;
    const void *pub;
    size_t pub_len;

    r = htpm2_create_primary(ctx, tp, HTPM2_OK, NULL,
                             HTPM2_HIERARCHY_OWNER,
                             HTPM2_KEY_RSA_2048_STORAGE,
                             NULL, 0, NULL, 0, &srk);
    CHECK_OK(r, "CreatePrimary RSA-2048 storage");
    CHECK(srk != NULL, "object should be non-NULL");

    if (srk) {
        r = htpm2_object_get_public(srk, &pub, &pub_len);
        CHECK_OK(r, "get public");
        CHECK(pub != NULL && pub_len > 0, "public blob should be non-empty");
    }

    htpm2_object_close(&srk);
    CHECK(srk == NULL, "object should be NULL after close");
    htpm2_result_free(&r);
}

static void
test_create_primary_ecc(htpm2_context ctx, htpm2_transport tp)
{
    htpm2_object key = NULL;
    htpm2_result r;

    r = htpm2_create_primary(ctx, tp, HTPM2_OK, NULL,
                             HTPM2_HIERARCHY_OWNER,
                             HTPM2_KEY_ECC_P256_STORAGE,
                             NULL, 0, NULL, 0, &key);
    CHECK_OK(r, "CreatePrimary ECC P-256 storage");
    CHECK(key != NULL, "ECC object should be non-NULL");

    htpm2_object_close(&key);
    htpm2_result_free(&r);
}

static void
test_create_and_load_child(htpm2_context ctx, htpm2_transport tp)
{
    htpm2_object parent = NULL, child = NULL, loaded = NULL;
    htpm2_result r = HTPM2_OK;
    const void *pub, *priv;
    size_t pub_len, priv_len;

    /* Create storage parent */
    r = htpm2_create_primary(ctx, tp, r, NULL,
                             HTPM2_HIERARCHY_OWNER,
                             HTPM2_KEY_RSA_2048_STORAGE,
                             NULL, 0, NULL, 0, &parent);
    CHECK_OK(r, "CreatePrimary parent");

    /* Create signing child under parent */
    r = htpm2_create(ctx, tp, r, NULL, parent,
                     HTPM2_KEY_RSA_2048_SIGN,
                     NULL, 0, NULL, 0, &child);
    CHECK_OK(r, "Create child signing key");

    if (htpm2_is_ok(r)) {
        /* Child should have pub and priv blobs but no TPM handle yet */
        r = htpm2_object_get_public(child, &pub, &pub_len);
        CHECK_OK(r, "child get public");
        CHECK(pub_len > 0, "child public should be non-empty");

        r = htpm2_object_get_private(child, &priv, &priv_len);
        CHECK_OK(r, "child get private");
        CHECK(priv_len > 0, "child private should be non-empty");

        /* Load the child */
        r = htpm2_load(ctx, tp, HTPM2_OK, NULL, parent,
                       pub, pub_len, priv, priv_len, &loaded);
        CHECK_OK(r, "Load child");
        CHECK(loaded != NULL, "loaded object should be non-NULL");
    }

    htpm2_object_close(&loaded);
    htpm2_object_close(&child);
    htpm2_object_close(&parent);
    htpm2_result_free(&r);
}

static void
test_read_public(htpm2_context ctx, htpm2_transport tp)
{
    htpm2_object key = NULL;
    htpm2_result r;
    void *pub = NULL, *name = NULL;
    size_t pub_len = 0, name_len = 0;

    r = htpm2_create_primary(ctx, tp, HTPM2_OK, NULL,
                             HTPM2_HIERARCHY_OWNER,
                             HTPM2_KEY_RSA_2048_STORAGE,
                             NULL, 0, NULL, 0, &key);
    CHECK_OK(r, "CreatePrimary for ReadPublic test");

    if (htpm2_is_ok(r)) {
        r = htpm2_read_public(ctx, tp, HTPM2_OK, key,
                              &pub, &pub_len, &name, &name_len);
        CHECK_OK(r, "ReadPublic");
        CHECK(pub != NULL && pub_len > 0, "ReadPublic pub non-empty");
        CHECK(name != NULL && name_len > 0, "ReadPublic name non-empty");
    }

    free(pub);
    free(name);
    htpm2_object_close(&key);
    htpm2_result_free(&r);
}

static void
test_create_chain_monadic(htpm2_context ctx, htpm2_transport tp)
{
    htpm2_object parent = NULL, child = NULL;
    htpm2_result r = HTPM2_OK;

    /* Monadic chain: CreatePrimary then Create -- all in one chain */
    r = htpm2_create_primary(ctx, tp, r, NULL,
                             HTPM2_HIERARCHY_OWNER,
                             HTPM2_KEY_ECC_P256_STORAGE,
                             NULL, 0, NULL, 0, &parent);
    r = htpm2_create(ctx, tp, r, NULL, parent,
                     HTPM2_KEY_ECC_P256_SIGN,
                     NULL, 0, NULL, 0, &child);
    CHECK_OK(r, "monadic chain CreatePrimary + Create");

    htpm2_object_close(&child);
    htpm2_object_close(&parent);
    htpm2_result_free(&r);
}

/* --- Session tests --- */

static void
test_start_hmac_session(htpm2_context ctx, htpm2_transport tp)
{
    htpm2_session session = NULL;
    htpm2_result r;

    r = htpm2_session_start(ctx, tp, HTPM2_OK,
                            HTPM2_SESSION_HMAC,
                            NULL, NULL, 0, &session);
    CHECK_OK(r, "StartAuthSession HMAC (unbound, unsalted)");
    CHECK(session != NULL, "session should be non-NULL");

    htpm2_session_close(&session);
    CHECK(session == NULL, "session should be NULL after close");
    htpm2_result_free(&r);
}

static void
test_start_encrypted_session(htpm2_context ctx, htpm2_transport tp)
{
    htpm2_session session = NULL;
    htpm2_result r;

    r = htpm2_session_start(ctx, tp, HTPM2_OK,
                            HTPM2_SESSION_HMAC,
                            NULL, NULL,
                            HTPM2_SESSION_ENC_DEC,
                            &session);
    CHECK_OK(r, "StartAuthSession HMAC with encrypt/decrypt");
    CHECK(session != NULL, "encrypted session should be non-NULL");

    htpm2_session_close(&session);
    htpm2_result_free(&r);
}

static void
test_start_trial_session(htpm2_context ctx, htpm2_transport tp)
{
    htpm2_session session = NULL;
    htpm2_result r;

    r = htpm2_session_start(ctx, tp, HTPM2_OK,
                            HTPM2_SESSION_TRIAL,
                            NULL, NULL, 0, &session);
    CHECK_OK(r, "StartAuthSession trial");
    CHECK(session != NULL, "trial session should be non-NULL");

    htpm2_session_close(&session);
    htpm2_result_free(&r);
}

int
main(int argc, char **argv)
{
    htpm2_context ctx = NULL;
    htpm2_transport tp = NULL;
    htpm2_result r;
    char uri[512];

    (void)argc;
    (void)argv;

    /* Check for swtpm */
    if (system("command -v swtpm >/dev/null 2>&1") != 0 ||
        system("command -v swtpm_setup >/dev/null 2>&1") != 0) {
        fprintf(stderr, "swtpm not found, skipping\n");
        return 77;  /* autotools skip */
    }

    atexit(cleanup);

    if (start_swtpm() != 0) {
        fprintf(stderr, "Failed to start swtpm, skipping\n");
        return 77;
    }

    /* Init context */
    r = htpm2_context_init(&ctx);
    if (htpm2_is_err(r)) {
        fprintf(stderr, "FATAL: context_init: %s\n",
                r.message ? r.message : "(null)");
        htpm2_result_free(&r);
        return 1;
    }

    /* Connect to swtpm */
    snprintf(uri, sizeof(uri), "socket:%s", socket_path);
    r = htpm2_transport_open(ctx, HTPM2_OK, uri, &tp);
    if (htpm2_is_err(r)) {
        fprintf(stderr, "FATAL: transport_open(%s): %s\n", uri,
                r.message ? r.message : "(null)");
        htpm2_result_free(&r);
        htpm2_context_free(&ctx);
        return 1;
    }

    /* Run tests */
    test_get_random(ctx, tp);
    test_get_random_twice_differs(ctx, tp);
    test_get_random_large(ctx, tp);
    test_monadic_chain_with_tpm(ctx, tp);
    test_monadic_chain_error_propagation(ctx, tp);

    /* Key creation tests */
    test_create_primary_rsa(ctx, tp);
    test_create_primary_ecc(ctx, tp);
    test_create_and_load_child(ctx, tp);
    test_read_public(ctx, tp);
    test_create_chain_monadic(ctx, tp);

    /* Session tests */
    test_start_hmac_session(ctx, tp);
    test_start_encrypted_session(ctx, tp);
    test_start_trial_session(ctx, tp);

    /* Cleanup */
    htpm2_transport_close(&tp);
    htpm2_context_free(&ctx);

    if (failures) {
        fprintf(stderr, "%d test(s) FAILED\n", failures);
        return 1;
    }
    printf("All swtpm integration tests passed.\n");
    return 0;
}
