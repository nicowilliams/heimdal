#define _DEFAULT_SOURCE
#define _GNU_SOURCE
#define _BSD_SOURCE

#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <string.h>
#include <krb5.h>
#include <hdb.h>
#include <roken.h>
#include <token_validator_plugin.h>

static int
validate_token(const char *soname,
               const char *cfg,
               const char *token,
               char **cprinc_from_token)
{
    token_free_name_f tok_free;
    token_validate_f tok_val;
    char *errstr = NULL;
    char *s = NULL;
    void *dl;
    int ret;

    if (token == NULL)
        errx(1, "Token is required");
    if ((dl = dlopen(soname, RTLD_NOW | RTLD_LOCAL)) == NULL)
        errx(1, "Could not load plugin (%s)", dlerror());
    if ((tok_free = dlsym(dl, "token_free_name")) == NULL ||
        (tok_val = dlsym(dl, "token_validate")) == NULL) {
        dlclose(dl);
        errx(1, "Plugin does not export required symbols");
    }
    ret = tok_val(NULL /* XXX */, cfg, "JWT" /* XXX */,
                  NULL, token, strlen(token), &s, &errstr);
    tok_free(&errstr);
    if (ret)
        return ret;
    if ((*cprinc_from_token = strdup(s)) == NULL)
        err(1, "Out of memory");
    tok_free(&s);
    return 0;
}

int
main(int argc, char **argv)
{
    char *p = NULL;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s SOPATH CONFIG TOKEN\n", argv[0]);
        return 1;
    }
    if ((errno = validate_token(argv[1], argv[2], argv[3], &p)))
        err(1, "Could not validate token");
    printf("%s\n", p);
    free(p);
    return 0;
}
