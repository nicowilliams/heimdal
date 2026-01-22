/*
 * Copyright (c) 2024 Kungliga Tekniska Högskolan
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
 * Threaded torture test for MEMORY ccache type.
 *
 * Creates NPROC * 1.5 threads that perform racy operations on MEMORY caches,
 * testing both named (MEMORY:test) and anonymous (MEMORY:anonymous) caches.
 */

#include "krb5_locl.h"
#include <pthread.h>
#include <getarg.h>
#include <err.h>

#define ITERATIONS 1000

static int verbose_flag = 0;
static int version_flag = 0;
static int help_flag = 0;

struct thread_ctx {
    int thread_id;
    int use_anonymous;
    int iterations;
    volatile int *stop;
};

static void *
torture_thread(void *arg)
{
    struct thread_ctx *ctx = arg;
    krb5_context context;
    krb5_ccache cc = NULL;
    krb5_error_code ret;
    krb5_principal client;
    const char *ccname;
    int i;

    ret = krb5_init_context(&context);
    if (ret)
        errx(1, "thread %d: krb5_init_context failed: %d", ctx->thread_id, ret);

    ret = krb5_parse_name(context, "test@EXAMPLE.COM", &client);
    if (ret)
        krb5_err(context, 1, ret, "thread %d: krb5_parse_name", ctx->thread_id);

    ccname = ctx->use_anonymous ? "MEMORY:anonymous" : "MEMORY:test";

    for (i = 0; i < ctx->iterations && !*ctx->stop; i++) {
        char config_name[64];
        krb5_data config_data;
        krb5_data retrieved_data;
        int op;

        ret = krb5_cc_resolve(context, ccname, &cc);
        if (ret) {
            if (verbose_flag)
                krb5_warn(context, ret, "thread %d iter %d: krb5_cc_resolve",
                          ctx->thread_id, i);
            continue;
        }

        ret = krb5_cc_initialize(context, cc, client);
        if (ret) {
            if (verbose_flag)
                krb5_warn(context, ret, "thread %d iter %d: krb5_cc_initialize",
                          ctx->thread_id, i);
            krb5_cc_close(context, cc);
            cc = NULL;
            continue;
        }

        op = i % 4;

        switch (op) {
        case 0:
        case 1: {
            /* Store config data */
            static const char test_value[] = "test-value";
            snprintf(config_name, sizeof(config_name), "test-config-%d",
                     ctx->thread_id);
            config_data.data = rk_UNCONST(test_value);
            config_data.length = sizeof(test_value) - 1;

            ret = krb5_cc_set_config(context, cc, NULL, config_name,
                                     &config_data);
            if (ret && verbose_flag)
                krb5_warn(context, ret,
                          "thread %d iter %d: krb5_cc_set_config",
                          ctx->thread_id, i);
            break;
        }

        case 2:
            /* Retrieve config data */
            snprintf(config_name, sizeof(config_name), "test-config-%d",
                     ctx->thread_id);
            krb5_data_zero(&retrieved_data);

            ret = krb5_cc_get_config(context, cc, NULL, config_name,
                                     &retrieved_data);
            if (ret == 0)
                krb5_data_free(&retrieved_data);
            else if (ret != KRB5_CC_NOTFOUND && ret != KRB5_CC_END &&
                     verbose_flag)
                krb5_warn(context, ret,
                          "thread %d iter %d: krb5_cc_get_config",
                          ctx->thread_id, i);
            break;

        case 3:
            /* Remove config (by setting NULL data) */
            snprintf(config_name, sizeof(config_name), "test-config-%d",
                     ctx->thread_id);

            ret = krb5_cc_set_config(context, cc, NULL, config_name, NULL);
            if (ret && ret != KRB5_CC_NOTFOUND && verbose_flag)
                krb5_warn(context, ret,
                          "thread %d iter %d: krb5_cc_set_config (remove)",
                          ctx->thread_id, i);
            break;
        }

        krb5_cc_close(context, cc);
        cc = NULL;
    }

    krb5_free_principal(context, client);
    krb5_free_context(context);

    if (verbose_flag)
        printf("thread %d (%s): completed %d iterations\n",
               ctx->thread_id,
               ctx->use_anonymous ? "anonymous" : "named",
               i);

    return NULL;
}

static struct getargs args[] = {
    { "verbose", 'v', arg_flag, &verbose_flag, "verbose", NULL },
    { "version", 0,   arg_flag, &version_flag, "print version", NULL },
    { "help",    0,   arg_flag, &help_flag, NULL, NULL }
};

static void
usage(int exitval)
{
    arg_printusage(args, sizeof(args) / sizeof(args[0]), NULL, "");
    exit(exitval);
}

int
main(int argc, char **argv)
{
    int nthreads;
    int nproc;
    pthread_t *threads;
    struct thread_ctx *contexts;
    volatile int stop = 0;
    int i;
    int optidx = 0;

    setprogname(argv[0]);

    if (getarg(args, sizeof(args) / sizeof(args[0]), argc, argv, &optidx))
        usage(1);

    if (help_flag)
        usage(0);

    if (version_flag) {
        printf("test_mcache (Heimdal)\n");
        return 0;
    }

#ifdef _SC_NPROCESSORS_ONLN
    nproc = sysconf(_SC_NPROCESSORS_ONLN);
    if (nproc < 1)
        nproc = 4;
#else
    nproc = 4;
#endif

    nthreads = nproc + nproc / 2;
    if (nthreads < 4)
        nthreads = 4;

    printf("Running with %d threads (%d processors)\n", nthreads, nproc);

    threads = calloc(nthreads, sizeof(*threads));
    contexts = calloc(nthreads, sizeof(*contexts));
    if (threads == NULL || contexts == NULL)
        errx(1, "out of memory");

    for (i = 0; i < nthreads; i++) {
        contexts[i].thread_id = i;
        contexts[i].use_anonymous = (i % 2 == 1);
        contexts[i].iterations = ITERATIONS;
        contexts[i].stop = &stop;
    }

    for (i = 0; i < nthreads; i++) {
        int ret = pthread_create(&threads[i], NULL, torture_thread,
                                 &contexts[i]);
        if (ret)
            errx(1, "pthread_create failed: %d", ret);
    }

    for (i = 0; i < nthreads; i++) {
        void *res;
        int ret = pthread_join(threads[i], &res);
        if (ret)
            errx(1, "pthread_join failed: %d", ret);
    }

    printf("All threads completed successfully\n");

    free(threads);
    free(contexts);

    return 0;
}
