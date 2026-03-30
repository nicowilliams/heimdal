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

/* We need internal functions */
#include "htpm2_locl.h"
#include "crypto.h"
#include "marshal.h"
#include "policy_p.h"

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
test_salted_session(htpm2_context ctx, htpm2_transport tp)
{
    htpm2_object srk = NULL;
    htpm2_session session = NULL;
    unsigned char buf[16];
    htpm2_result r = HTPM2_OK;

    /* Create SRK for salting */
    r = htpm2_create_primary(ctx, tp, r, NULL,
                             HTPM2_HIERARCHY_OWNER,
                             HTPM2_KEY_RSA_2048_STORAGE,
                             NULL, 0, NULL, 0, &srk);
    CHECK_OK(r, "CreatePrimary SRK for salted session");

    if (htpm2_is_ok(r)) {
        /* Start salted HMAC session */
        r = htpm2_session_start(ctx, tp, HTPM2_OK,
                                HTPM2_SESSION_HMAC,
                                srk, NULL,
                                HTPM2_SESSION_ENC_DEC,
                                &session);
        CHECK_OK(r, "StartAuthSession salted + encrypted");
        CHECK(session != NULL, "salted session should be non-NULL");
    }

    /* TODO: Use the session for an authorized command once sessions
     * are wired into the command path. For now just verify it started. */

    htpm2_session_close(&session);
    htpm2_object_close(&srk);
    htpm2_result_free(&r);
}

static void
test_ecc_salted_session(htpm2_context ctx, htpm2_transport tp)
{
    htpm2_object ecc_key = NULL;
    htpm2_session session = NULL;
    htpm2_result r = HTPM2_OK;

    /* Create ECC P-256 storage key for salting */
    r = htpm2_create_primary(ctx, tp, r, NULL,
                             HTPM2_HIERARCHY_OWNER,
                             HTPM2_KEY_ECC_P256_STORAGE,
                             NULL, 0, NULL, 0, &ecc_key);
    CHECK_OK(r, "CreatePrimary ECC P-256 for salted session");

    if (htpm2_is_ok(r)) {
        r = htpm2_session_start(ctx, tp, HTPM2_OK,
                                HTPM2_SESSION_HMAC,
                                ecc_key, NULL,
                                HTPM2_SESSION_ENC_DEC,
                                &session);
        CHECK_OK(r, "StartAuthSession ECC salted + encrypted");
        CHECK(session != NULL, "ECC salted session should be non-NULL");
    }

    htpm2_session_close(&session);
    htpm2_object_close(&ecc_key);
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

/* --- Sign / Quote / PCR tests --- */

static void
test_sign_rsa(htpm2_context ctx, htpm2_transport tp)
{
    htpm2_object parent = NULL, sign_key = NULL, loaded = NULL;
    htpm2_result r = HTPM2_OK;
    const void *pub, *priv;
    size_t pub_len, priv_len;
    unsigned char digest[32];
    void *sig = NULL;
    size_t sig_len = 0;

    /* Create parent SRK */
    r = htpm2_create_primary(ctx, tp, r, NULL,
                             HTPM2_HIERARCHY_OWNER,
                             HTPM2_KEY_RSA_2048_STORAGE,
                             NULL, 0, NULL, 0, &parent);
    /* Create RSA signing key */
    r = htpm2_create(ctx, tp, r, NULL, parent,
                     HTPM2_KEY_RSA_2048_SIGN,
                     NULL, 0, NULL, 0, &sign_key);
    CHECK_OK(r, "create RSA signing key");

    if (htpm2_is_ok(r)) {
        htpm2_object_get_public(sign_key, &pub, &pub_len);
        htpm2_object_get_private(sign_key, &priv, &priv_len);

        r = htpm2_load(ctx, tp, HTPM2_OK, NULL, parent,
                       pub, pub_len, priv, priv_len, &loaded);
        CHECK_OK(r, "load signing key");
    }

    if (htpm2_is_ok(r)) {
        /* Hash something to sign */
        memset(digest, 0x42, 32);

        r = htpm2_sign(ctx, tp, HTPM2_OK, NULL, loaded,
                       digest, 32, &sig, &sig_len);
        CHECK_OK(r, "Sign with RSA key");
        CHECK(sig != NULL && sig_len > 0, "signature should be non-empty");
    }

    free(sig);
    htpm2_object_close(&loaded);
    htpm2_object_close(&sign_key);
    htpm2_object_close(&parent);
    htpm2_result_free(&r);
}

static void
test_pcr_read(htpm2_context ctx, htpm2_transport tp)
{
    htpm2_pcr_selection sel = NULL;
    void *pcr_sel_encoded = NULL;
    size_t pcr_sel_len = 0;
    void *pcr_values = NULL;
    size_t pcr_values_len = 0;
    uint32_t counter = 0;
    htpm2_result r;

    r = htpm2_pcr_selection_create(ctx, TPM2_ALG_SHA256, &sel);
    CHECK_OK(r, "pcr_selection_create");

    if (htpm2_is_ok(r)) {
        htpm2_pcr_selection_add(sel, 0);  /* PCR 0 */
        r = htpm2_pcr_selection_encode(sel, &pcr_sel_encoded, &pcr_sel_len);
        CHECK_OK(r, "pcr_selection_encode");
    }

    if (htpm2_is_ok(r)) {
        r = htpm2_pcr_read(ctx, tp, HTPM2_OK,
                           pcr_sel_encoded, pcr_sel_len,
                           &pcr_values, &pcr_values_len,
                           &counter);
        CHECK_OK(r, "PCR_Read");
        CHECK(pcr_values != NULL, "pcr_values should be non-NULL");
    }

    free(pcr_sel_encoded);
    free(pcr_values);
    htpm2_pcr_selection_free(&sel);
    htpm2_result_free(&r);
}

static void
test_quote(htpm2_context ctx, htpm2_transport tp)
{
    htpm2_object parent = NULL, ak = NULL, loaded_ak = NULL;
    htpm2_pcr_selection sel = NULL;
    void *pcr_sel_encoded = NULL;
    size_t pcr_sel_len = 0;
    void *quoted = NULL, *sig = NULL;
    size_t quoted_len = 0, sig_len = 0;
    const void *pub, *priv;
    size_t pub_len, priv_len;
    htpm2_result r = HTPM2_OK;
    const char *qdata = "test-nonce";

    /* Create parent and signing key for quote */
    r = htpm2_create_primary(ctx, tp, r, NULL,
                             HTPM2_HIERARCHY_OWNER,
                             HTPM2_KEY_RSA_2048_STORAGE,
                             NULL, 0, NULL, 0, &parent);
    r = htpm2_create(ctx, tp, r, NULL, parent,
                     HTPM2_KEY_RSA_2048_SIGN,
                     NULL, 0, NULL, 0, &ak);
    CHECK_OK(r, "create AK for quote");

    if (htpm2_is_ok(r)) {
        htpm2_object_get_public(ak, &pub, &pub_len);
        htpm2_object_get_private(ak, &priv, &priv_len);
        r = htpm2_load(ctx, tp, HTPM2_OK, NULL, parent,
                       pub, pub_len, priv, priv_len, &loaded_ak);
        CHECK_OK(r, "load AK");
    }

    if (htpm2_is_ok(r)) {
        r = htpm2_pcr_selection_create(ctx, TPM2_ALG_SHA256, &sel);
        if (htpm2_is_ok(r)) {
            htpm2_pcr_selection_add(sel, 0);
            htpm2_pcr_selection_add(sel, 1);
            htpm2_pcr_selection_add(sel, 2);
            r = htpm2_pcr_selection_encode(sel, &pcr_sel_encoded, &pcr_sel_len);
        }
    }

    if (htpm2_is_ok(r)) {
        r = htpm2_quote(ctx, tp, HTPM2_OK, NULL, loaded_ak,
                        pcr_sel_encoded, pcr_sel_len,
                        qdata, strlen(qdata),
                        &quoted, &quoted_len,
                        &sig, &sig_len);
        CHECK_OK(r, "Quote");
        CHECK(quoted != NULL && quoted_len > 0, "quoted should be non-empty");
        CHECK(sig != NULL && sig_len > 0, "quote signature should be non-empty");
    }

    free(quoted);
    free(sig);
    free(pcr_sel_encoded);
    htpm2_pcr_selection_free(&sel);
    htpm2_object_close(&loaded_ak);
    htpm2_object_close(&ak);
    htpm2_object_close(&parent);
    htpm2_result_free(&r);
}

/* --- Parameter encryption test --- */

/*
 * Test encrypted session by issuing GetRandom through an encrypted
 * salted HMAC session.  GetRandom doesn't require auth, but we can
 * still use a session with the encrypt attribute to encrypt the
 * response parameter (the random bytes).
 *
 * We use htpm2_command_execute_with_auth directly since the public
 * htpm2_get_random doesn't take a session parameter.
 */
static void
test_encrypted_get_random(htpm2_context ctx, htpm2_transport tp)
{
    htpm2_object srk = NULL;
    htpm2_session session = NULL;
    htpm2_result r = HTPM2_OK;
    heim_storage *param_sp = NULL;
    heim_storage *rsp = NULL;
    uint32_t rc;
    void *param_data = NULL;
    size_t param_len = 0;
    void *random_data = NULL;
    uint16_t random_len;

    /* Create SRK for salting */
    r = htpm2_create_primary(ctx, tp, r, NULL,
                             HTPM2_HIERARCHY_OWNER,
                             HTPM2_KEY_RSA_2048_STORAGE,
                             NULL, 0, NULL, 0, &srk);
    CHECK_OK(r, "CreatePrimary SRK for encrypted GetRandom");

    if (htpm2_is_ok(r)) {
        /* Start salted + encrypted HMAC session */
        r = htpm2_session_start(ctx, tp, HTPM2_OK,
                                HTPM2_SESSION_HMAC,
                                srk, NULL,
                                HTPM2_SESSION_ENCRYPT,
                                &session);
        CHECK_OK(r, "StartAuthSession salted+encrypt");
    }

    if (htpm2_is_ok(r)) {
        /* Marshal GetRandom params: bytesRequested (uint16) = 32 */
        param_sp = heim_storage_emem();
        if (param_sp) {
            heim_store_uint16(param_sp, 32);
            heim_storage_to_data(param_sp, &param_data, &param_len);
            heim_storage_free(param_sp);
        }

        /*
         * GetRandom has no handles requiring auth, but we pass the
         * session to get response encryption.  We pass 0 handles.
         */
        r = htpm2_command_execute_with_auth(ctx, tp, TPM2_CC_GetRandom,
                                            NULL, 0, session,
                                            param_data, param_len,
                                            &rsp, &rc);
        free(param_data);
        CHECK_OK(r, "GetRandom with encrypted session");

        if (htpm2_is_ok(r) && rsp) {
            /* Unmarshal TPM2B_DIGEST response (should be decrypted) */
            int ret = htpm2_unmarshal_tpm2b(rsp, &random_data, &random_len);
            heim_storage_free(rsp);
            rsp = NULL;

            CHECK(ret == 0, "unmarshal encrypted GetRandom response");
            CHECK(random_data != NULL && random_len > 0,
                  "encrypted GetRandom should return data");

            if (random_data && random_len > 0) {
                int all_zero = 1;
                for (int i = 0; i < random_len; i++)
                    if (((uint8_t *)random_data)[i] != 0)
                        { all_zero = 0; break; }
                CHECK(!all_zero,
                      "decrypted random bytes should be non-zero");
            }
            free(random_data);
        }
        if (rsp)
            heim_storage_free(rsp);
    }

    htpm2_session_close(&session);
    htpm2_object_close(&srk);
    htpm2_result_free(&r);
}

/* --- Policy compiler tests --- */

static void
test_policy_compile_simple(htpm2_context ctx, htpm2_transport tp)
{
    const char *json =
        "{"
        "  \"tpm2Policy\": {"
        "    \"name\": \"test_compile\","
        "    \"policy\": ["
        "      { \"cc\": \"PolicyCommandCode\", \"commandCode\": \"Sign\" },"
        "      { \"cc\": \"PolicyAuthValue\" }"
        "    ]"
        "  }"
        "}";

    htpm2_policy_doc *doc = NULL;
    uint8_t digest1[32], digest2[32];
    size_t digest_len;
    htpm2_result r;

    r = htpm2_policy_parse(json, 0, &doc);
    CHECK_OK(r, "parse for compile");

    if (htpm2_is_ok(r) && doc) {
        /* Compile twice -- should get the same digest */
        digest_len = 32;
        r = htpm2_policy_compile(ctx, tp, doc, digest1, &digest_len);
        CHECK_OK(r, "compile pass 1");
        CHECK(digest_len == 32, "digest should be 32 bytes");

        /* Verify non-zero */
        {
            int all_zero = 1;
            for (int i = 0; i < 32; i++)
                if (digest1[i] != 0) { all_zero = 0; break; }
            CHECK(!all_zero, "compiled digest should be non-zero");
        }

        digest_len = 32;
        r = htpm2_policy_compile(ctx, tp, doc, digest2, &digest_len);
        CHECK_OK(r, "compile pass 2");

        CHECK(memcmp(digest1, digest2, 32) == 0,
              "two compilations should produce the same digest");
    }

    htpm2_policy_doc_free(doc);
    htpm2_result_free(&r);
}

static void
test_policy_compile_pcr(htpm2_context ctx, htpm2_transport tp)
{
    /* PolicyPCR with empty digest (use current values) */
    const char *json =
        "{"
        "  \"tpm2Policy\": {"
        "    \"name\": \"test_pcr_compile\","
        "    \"policy\": ["
        "      {"
        "        \"cc\": \"PolicyPCR\","
        "        \"pcrs\": {"
        "          \"hashAlg\": \"sha256\","
        "          \"selections\": [ { \"pcr\": 0 } ]"
        "        }"
        "      }"
        "    ]"
        "  }"
        "}";

    htpm2_policy_doc *doc = NULL;
    uint8_t digest[32];
    size_t digest_len = 32;
    htpm2_result r;

    r = htpm2_policy_parse(json, 0, &doc);
    CHECK_OK(r, "parse PCR policy for compile");

    if (htpm2_is_ok(r) && doc) {
        r = htpm2_policy_compile(ctx, tp, doc, digest, &digest_len);
        CHECK_OK(r, "compile PCR policy");
        CHECK(digest_len == 32, "digest 32 bytes");
    }

    htpm2_policy_doc_free(doc);
    htpm2_result_free(&r);
}

static void
test_policy_compile_differs(htpm2_context ctx, htpm2_transport tp)
{
    /* Two different policies should produce different digests */
    const char *json1 =
        "{ \"tpm2Policy\": { \"name\": \"a\", \"policy\": ["
        "  { \"cc\": \"PolicyCommandCode\", \"commandCode\": \"Sign\" }"
        "] } }";
    const char *json2 =
        "{ \"tpm2Policy\": { \"name\": \"b\", \"policy\": ["
        "  { \"cc\": \"PolicyCommandCode\", \"commandCode\": \"Quote\" }"
        "] } }";

    htpm2_policy_doc *doc1 = NULL, *doc2 = NULL;
    uint8_t dig1[32], dig2[32];
    size_t dl = 32;
    htpm2_result r;

    r = htpm2_policy_parse(json1, 0, &doc1);
    CHECK_OK(r, "parse policy 1");
    r = htpm2_policy_parse(json2, 0, &doc2);
    CHECK_OK(r, "parse policy 2");

    if (doc1 && doc2) {
        dl = 32;
        r = htpm2_policy_compile(ctx, tp, doc1, dig1, &dl);
        CHECK_OK(r, "compile policy 1");
        dl = 32;
        r = htpm2_policy_compile(ctx, tp, doc2, dig2, &dl);
        CHECK_OK(r, "compile policy 2");

        CHECK(memcmp(dig1, dig2, 32) != 0,
              "different policies should have different digests");
    }

    htpm2_policy_doc_free(doc1);
    htpm2_policy_doc_free(doc2);
    htpm2_result_free(&r);
}

/* --- Policy evaluator tests --- */

static void
test_policy_evaluate_command_code(htpm2_context ctx, htpm2_transport tp)
{
    /*
     * End-to-end policy evaluation test:
     * 1. Compile a policy: PolicyCommandCode(Sign) + PolicyAuthValue
     * 2. Create a signing key with that policy
     * 3. Load the key
     * 4. Evaluate the policy to get a satisfied session
     * 5. Use the session to Sign (should succeed)
     */
    const char *json =
        "{ \"tpm2Policy\": { \"name\": \"sign_policy\", \"policy\": ["
        "  { \"cc\": \"PolicyCommandCode\", \"commandCode\": \"Sign\" },"
        "  { \"cc\": \"PolicyAuthValue\" }"
        "] } }";

    htpm2_policy_doc *doc = NULL;
    uint8_t policy_digest[32];
    size_t digest_len = 32;
    htpm2_object parent = NULL, child = NULL, loaded = NULL;
    htpm2_session policy_session = NULL;
    const void *pub, *priv;
    size_t pub_len, priv_len;
    void *sig = NULL;
    size_t sig_len = 0;
    unsigned char test_digest[32];
    htpm2_result r;

    /* Parse and compile the policy */
    r = htpm2_policy_parse(json, 0, &doc);
    CHECK_OK(r, "parse sign policy");
    if (htpm2_is_err(r)) goto done;

    r = htpm2_policy_compile(ctx, tp, doc, policy_digest, &digest_len);
    CHECK_OK(r, "compile sign policy");
    if (htpm2_is_err(r)) goto done;

    /* Create parent SRK */
    r = htpm2_create_primary(ctx, tp, HTPM2_OK, NULL,
                             HTPM2_HIERARCHY_OWNER,
                             HTPM2_KEY_RSA_2048_STORAGE,
                             NULL, 0, NULL, 0, &parent);
    CHECK_OK(r, "create SRK for policy test");
    if (htpm2_is_err(r)) goto done;

    /* Create signing key with the compiled policy */
    r = htpm2_create(ctx, tp, HTPM2_OK, NULL, parent,
                     HTPM2_KEY_RSA_2048_SIGN,
                     NULL, 0,
                     policy_digest, 32,
                     &child);
    CHECK_OK(r, "create key with policy");
    if (htpm2_is_err(r)) goto done;

    /* Load the key */
    htpm2_object_get_public(child, &pub, &pub_len);
    htpm2_object_get_private(child, &priv, &priv_len);
    r = htpm2_load(ctx, tp, HTPM2_OK, NULL, parent,
                   pub, pub_len, priv, priv_len, &loaded);
    CHECK_OK(r, "load policy-bound key");
    if (htpm2_is_err(r)) goto done;

    /* Evaluate the policy to get a satisfied session */
    r = htpm2_policy_evaluate(ctx, tp, doc, NULL, 0, NULL, &policy_session);
    CHECK_OK(r, "evaluate sign policy");
    if (htpm2_is_err(r)) goto done;

    CHECK(policy_session != NULL, "policy session should be non-NULL");

    /* Sign with the policy session */
    memset(test_digest, 0x42, 32);
    r = htpm2_sign(ctx, tp, HTPM2_OK, policy_session, loaded,
                   test_digest, 32, &sig, &sig_len);
    CHECK_OK(r, "sign with policy session");
    CHECK(sig != NULL && sig_len > 0, "signature should be non-empty");

done:
    free(sig);
    htpm2_session_close(&policy_session);
    htpm2_object_close(&loaded);
    htpm2_object_close(&child);
    htpm2_object_close(&parent);
    htpm2_policy_doc_free(doc);
    htpm2_result_free(&r);
}

/* --- Policy tests --- */

static void
test_trial_policy_pcr(htpm2_context ctx, htpm2_transport tp)
{
    htpm2_session trial = NULL;
    htpm2_pcr_selection sel = NULL;
    void *pcr_sel_encoded = NULL;
    size_t pcr_sel_len = 0;
    uint8_t digest[32];
    size_t digest_len = 32;
    htpm2_result r;

    /* Start trial session */
    r = htpm2_session_start(ctx, tp, HTPM2_OK,
                            HTPM2_SESSION_TRIAL,
                            NULL, NULL, 0, &trial);
    CHECK_OK(r, "start trial session");

    if (htpm2_is_ok(r)) {
        /* PolicyPCR for PCR 0 (empty digest = use current values) */
        r = htpm2_pcr_selection_create(ctx, TPM2_ALG_SHA256, &sel);
        if (htpm2_is_ok(r)) {
            htpm2_pcr_selection_add(sel, 0);
            r = htpm2_pcr_selection_encode(sel, &pcr_sel_encoded, &pcr_sel_len);
        }
        if (htpm2_is_ok(r)) {
            r = htpm2_policy_pcr(ctx, trial, HTPM2_OK,
                                 pcr_sel_encoded, pcr_sel_len,
                                 NULL, 0);
            CHECK_OK(r, "PolicyPCR on trial session");
        }
    }

    if (htpm2_is_ok(r)) {
        /* PolicyCommandCode for TPM2_CC_Sign */
        r = htpm2_policy_command_code(ctx, trial, HTPM2_OK, TPM2_CC_Sign);
        CHECK_OK(r, "PolicyCommandCode on trial session");
    }

    if (htpm2_is_ok(r)) {
        /* Get the policy digest */
        r = htpm2_session_get_policy_digest(trial, HTPM2_OK,
                                            digest, &digest_len);
        CHECK_OK(r, "PolicyGetDigest");
        CHECK(digest_len == 32, "digest should be 32 bytes");

        /* Verify it's not all zeros (policy was extended) */
        int all_zero = 1;
        for (int i = 0; i < 32; i++)
            if (digest[i] != 0) { all_zero = 0; break; }
        CHECK(!all_zero, "policy digest should be non-zero");
    }

    free(pcr_sel_encoded);
    htpm2_pcr_selection_free(&sel);
    htpm2_session_close(&trial);
    htpm2_result_free(&r);
}

/* --- EncryptTo test --- */

static void
test_encrypt_to(htpm2_context ctx, htpm2_transport tp)
{
    htpm2_object ek = NULL;
    htpm2_result r = HTPM2_OK;
    const void *ek_pub;
    size_t ek_pub_len;
    htpm2_encrypt_to_result enc_result;
    const char *message = "Safeboot enrollment secret payload";

    /* We need an EK for MakeCredential inside EncryptTo */
    r = htpm2_create_primary(ctx, tp, r, NULL,
                             HTPM2_HIERARCHY_ENDORSEMENT,
                             HTPM2_KEY_RSA_2048_DECRYPT,
                             NULL, 0, NULL, 0, &ek);
    CHECK_OK(r, "CreatePrimary EK for EncryptTo");

    if (htpm2_is_ok(r)) {
        htpm2_object_get_public(ek, &ek_pub, &ek_pub_len);

        /* A dummy policy digest (32 bytes) -- in practice this would
         * come from a trial session running PolicyPCR etc. */
        uint8_t policy[32];
        memset(policy, 0x42, 32);

        /* 1-share (well-known key only) */
        memset(&enc_result, 0, sizeof(enc_result));
        r = htpm2_encrypt_to(ctx, message, strlen(message),
                             ek_pub, ek_pub_len,
                             policy, 32,
                             NULL, 0,   /* no IAK */
                             NULL, 0,   /* no owner */
                             &enc_result);
        CHECK_OK(r, "EncryptTo (1 share, policy-only)");
        CHECK(enc_result.num_shares == 1, "should be 1 share");
        CHECK(enc_result.ciphertext != NULL, "ciphertext non-NULL");
        CHECK(enc_result.wk_credential_blob != NULL, "wk blob non-NULL");
        CHECK(enc_result.iak_credential_blob == NULL, "iak blob should be NULL");
        CHECK(enc_result.owner_credential_blob == NULL, "owner blob should be NULL");
        htpm2_encrypt_to_result_free(&enc_result);

        /* 3-share (well-known + IAK + owner) */
        uint8_t fake_iak_name[34] = {0x00, 0x0B};
        memset(fake_iak_name + 2, 0x43, 32);
        uint8_t fake_owner_name[34] = {0x00, 0x0B};
        memset(fake_owner_name + 2, 0x44, 32);

        memset(&enc_result, 0, sizeof(enc_result));
        r = htpm2_encrypt_to(ctx, message, strlen(message),
                             ek_pub, ek_pub_len,
                             policy, 32,
                             fake_iak_name, 34,
                             fake_owner_name, 34,
                             &enc_result);
        CHECK_OK(r, "EncryptTo (3 shares)");
        CHECK(enc_result.num_shares == 3, "should be 3 shares");
        CHECK(enc_result.ciphertext != NULL, "ciphertext non-NULL");
        CHECK(enc_result.wk_credential_blob != NULL, "wk blob non-NULL");
        CHECK(enc_result.iak_credential_blob != NULL, "iak blob non-NULL");
        CHECK(enc_result.owner_credential_blob != NULL, "owner blob non-NULL");
        htpm2_encrypt_to_result_free(&enc_result);
    }

    htpm2_object_close(&ek);
    htpm2_result_free(&r);
}

static void
test_decrypt_from_roundtrip(htpm2_context ctx, htpm2_transport tp)
{
    /*
     * Test the decrypt side with known shares (simulating what
     * ActivateCredential would return).
     */
    uint8_t share1[32], share2[32], share3[32];
    uint8_t key[32];
    void *ciphertext = NULL;
    size_t ciphertext_len = 0;
    void *plaintext = NULL;
    size_t plaintext_len = 0;
    const char *message = "Hello from EncryptTo";
    htpm2_result r;
    size_t i;

    (void)tp;

    /* Generate a random key and split it */
    r = htpm2_random_bytes(ctx, key, 32);
    CHECK_OK(r, "generate key");

    r = htpm2_random_bytes(ctx, share1, 32);
    CHECK_OK(r, "generate share1");
    r = htpm2_random_bytes(ctx, share2, 32);
    CHECK_OK(r, "generate share2");
    for (i = 0; i < 32; i++)
        share3[i] = key[i] ^ share1[i] ^ share2[i];

    /* Encrypt with the key directly (using internal AES-256-CBC) */
    {
        EVP_CIPHER_CTX *cctx;
        uint8_t iv[16];
        uint8_t *buf;
        int outl = 0, final_outl = 0;

        RAND_bytes(iv, 16);
        buf = malloc(16 + strlen(message) + 16);
        memcpy(buf, iv, 16);

        cctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(cctx, EVP_aes_256_cbc(), NULL, key, iv);
        EVP_EncryptUpdate(cctx, buf + 16, &outl,
                          (const unsigned char *)message,
                          (int)strlen(message));
        EVP_EncryptFinal_ex(cctx, buf + 16 + outl, &final_outl);
        EVP_CIPHER_CTX_free(cctx);

        ciphertext = buf;
        ciphertext_len = 16 + outl + final_outl;
    }

    /* Decrypt with 3 shares */
    {
        const void *shares[3] = { share1, share2, share3 };
        size_t share_lens[3] = { 32, 32, 32 };

        r = htpm2_envelope_open(ctx, ciphertext, ciphertext_len,
                               shares, share_lens, 3,
                               &plaintext, &plaintext_len);
        CHECK_OK(r, "DecryptFrom (3 shares)");
        CHECK(plaintext_len == strlen(message), "plaintext length match");
        if (plaintext && plaintext_len == strlen(message))
            CHECK(memcmp(plaintext, message, plaintext_len) == 0,
                  "plaintext content match");
    }

    free(ciphertext);
    free(plaintext);
    memset(key, 0, sizeof(key));
    htpm2_result_free(&r);
}

/* --- MakeCredential test (software only, no TPM needed for make) --- */

static void
test_make_credential(htpm2_context ctx, htpm2_transport tp)
{
    htpm2_object ek = NULL;
    htpm2_result r = HTPM2_OK;
    const void *ek_pub;
    size_t ek_pub_len;
    const void *ek_name;
    size_t ek_name_len;
    void *cred_blob = NULL, *enc_secret = NULL;
    size_t cred_blob_len = 0, enc_secret_len = 0;
    const char *secret = "test-secret-42";

    /* Create an EK (RSA-2048 decrypt key under endorsement hierarchy) */
    r = htpm2_create_primary(ctx, tp, r, NULL,
                             HTPM2_HIERARCHY_ENDORSEMENT,
                             HTPM2_KEY_RSA_2048_DECRYPT,
                             NULL, 0, NULL, 0, &ek);
    CHECK_OK(r, "CreatePrimary EK for MakeCredential");

    if (htpm2_is_ok(r)) {
        htpm2_object_get_public(ek, &ek_pub, &ek_pub_len);
        htpm2_object_get_name(ek, &ek_name, &ek_name_len);

        CHECK(ek_pub != NULL && ek_pub_len > 0, "EK pub non-empty");
        CHECK(ek_name != NULL && ek_name_len > 0, "EK name non-empty");

        /* MakeCredential in software */
        r = htpm2_make_credential(ctx,
                                  ek_pub, ek_pub_len,
                                  secret, strlen(secret),
                                  ek_name, ek_name_len,
                                  &cred_blob, &cred_blob_len,
                                  &enc_secret, &enc_secret_len);
        CHECK_OK(r, "MakeCredential (software)");
        CHECK(cred_blob != NULL && cred_blob_len > 0,
              "credential blob non-empty");
        CHECK(enc_secret != NULL && enc_secret_len > 0,
              "encrypted secret non-empty");
    }

    free(cred_blob);
    free(enc_secret);
    htpm2_object_close(&ek);
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
    test_salted_session(ctx, tp);
    test_ecc_salted_session(ctx, tp);
    test_start_trial_session(ctx, tp);

    /* Sign / Quote / PCR tests */
    test_sign_rsa(ctx, tp);
    test_pcr_read(ctx, tp);
    test_quote(ctx, tp);

    /* Policy compiler tests */
    test_policy_compile_simple(ctx, tp);
    test_policy_compile_pcr(ctx, tp);
    test_policy_compile_differs(ctx, tp);

    /* Policy evaluator tests */
    test_policy_evaluate_command_code(ctx, tp);

    /* Parameter encryption test */
    test_encrypted_get_random(ctx, tp);

    /* Policy tests */
    test_trial_policy_pcr(ctx, tp);

    /* Credential tests */
    test_make_credential(ctx, tp);

    /* EncryptTo / DecryptFrom tests */
    test_encrypt_to(ctx, tp);
    test_decrypt_from_roundtrip(ctx, tp);

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
