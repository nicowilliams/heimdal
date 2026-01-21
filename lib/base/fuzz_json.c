/*
 * Copyright (c) 2025 Kungliga Tekniska Högskolan
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
 * libFuzzer harness for JSON parser in lib/base/json.c
 *
 * Build with:
 *   clang -g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer,address \
 *         fuzz_json.c -o fuzz_json -lheimbase -lroken
 *
 * Run with:
 *   ./fuzz_json corpus_dir/
 */

#include <config.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <heimbase.h>
#include <getarg.h>
#include <roken.h>

/* libFuzzer entry points */
int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    return 0;
}

/*
 * Main fuzzing entry point.
 * Input is treated as JSON to parse.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    heim_object_t obj = NULL;
    heim_string_t serialized = NULL;
    heim_object_t obj2 = NULL;
    heim_error_t error = NULL;

    /* Limit input size to avoid OOM on deeply nested structures */
    if (size > 256 * 1024)
        return 0;

    /*
     * Test 1: Parse with default flags, various depth limits.
     * This exercises the core parsing logic.
     */
    obj = heim_json_create_with_bytes(data, size, 10, 0, &error);
    if (obj) {
        /*
         * Test 2: Serialize back to JSON.
         * This exercises the serialization logic and ensures
         * the parsed structure is well-formed.
         */
        serialized = heim_json_copy_serialize(obj, 0, NULL);
        if (serialized) {
            /*
             * Test 3: Re-parse the serialized output.
             * This is a sanity check - if we serialized it,
             * we should be able to parse it again.
             */
            obj2 = heim_json_create(heim_string_get_utf8(serialized), 10, 0, NULL);
            heim_release(obj2);
            heim_release(serialized);
        }
        heim_release(obj);
    }
    heim_release(error);

    /*
     * Test 4: Parse with HEIM_JSON_F_STRICT flag.
     * Strict mode rejects some inputs that permissive mode accepts.
     */
    error = NULL;
    obj = heim_json_create_with_bytes(data, size, 10, HEIM_JSON_F_STRICT, &error);
    if (obj) {
        serialized = heim_json_copy_serialize(obj, HEIM_JSON_F_STRICT, NULL);
        heim_release(serialized);
        heim_release(obj);
    }
    heim_release(error);

    /*
     * Test 5: Parse with shallow depth limit.
     * This should reject deeply nested structures.
     */
    error = NULL;
    obj = heim_json_create_with_bytes(data, size, 2, 0, &error);
    heim_release(obj);
    heim_release(error);

    /*
     * Test 6: Parse with HEIM_JSON_F_NO_C_NULL flag.
     * This affects handling of \u0000 escape sequences.
     */
    error = NULL;
    obj = heim_json_create_with_bytes(data, size, 10, HEIM_JSON_F_NO_C_NULL, &error);
    if (obj) {
        serialized = heim_json_copy_serialize(obj, HEIM_JSON_F_NO_C_NULL, NULL);
        heim_release(serialized);
        heim_release(obj);
    }
    heim_release(error);

    /*
     * Test 7: Try with one-line serialization flag.
     */
    error = NULL;
    obj = heim_json_create_with_bytes(data, size, 10, 0, &error);
    if (obj) {
        serialized = heim_json_copy_serialize(obj, HEIM_JSON_F_ONE_LINE, NULL);
        heim_release(serialized);
        heim_release(obj);
    }
    heim_release(error);

    return 0;
}

#ifndef HAS_LIBFUZZER_MAIN
/*
 * Standalone mode for testing without libFuzzer.
 * Reads input from stdin or file arguments.
 */

static int help_flag;
static int version_flag;

static struct getargs args[] = {
    { "help",    'h', arg_flag, &help_flag,    "Print help message", NULL },
    { "version",  0,  arg_flag, &version_flag, "Print version",      NULL }
};

static void
usage(int ret)
{
    arg_printusage(args, sizeof(args)/sizeof(args[0]), NULL, "[FILE...]");
    exit(ret);
}

int main(int argc, char **argv)
{
    uint8_t buf[256 * 1024];
    size_t len;
    FILE *fp;
    int i;
    int optidx = 0;

    setprogname(argv[0]);

    if (getarg(args, sizeof(args)/sizeof(args[0]), argc, argv, &optidx))
        usage(1);

    if (help_flag)
        usage(0);

    if (version_flag) {
        print_version(NULL);
        exit(0);
    }

    argc -= optidx;
    argv += optidx;

    LLVMFuzzerInitialize(&argc, &argv);

    if (argc < 1) {
        /* Read from stdin */
        len = fread(buf, 1, sizeof(buf), stdin);
        if (len > 0)
            LLVMFuzzerTestOneInput(buf, len);
    } else {
        /* Read from each file argument */
        for (i = 0; i < argc; i++) {
            fp = fopen(argv[i], "rb");
            if (fp == NULL)
                continue;
            len = fread(buf, 1, sizeof(buf), fp);
            fclose(fp);
            if (len > 0)
                LLVMFuzzerTestOneInput(buf, len);
        }
    }

    return 0;
}
#endif
