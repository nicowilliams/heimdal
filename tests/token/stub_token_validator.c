#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <token_validator_plugin.h>

int
token_validate(const char *realm,
               const char *plugin_config,
               const char *token_kind,
               const char *requested_principal,
               const char *token,
               size_t token_size,
               char **actual_principal,
               char **errstr)
{
    if (requested_principal) {
        if ((*actual_principal = strdup(requested_principal)) == NULL)
            return ENOMEM;
        return 0;
    }

    if ((*actual_principal = strdup(plugin_config)) == NULL)
        return ENOMEM;
    return 0;
}

void
token_free_name(char **str)
{
    free(*str);
    *str = NULL;
}
