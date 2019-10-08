/*
 * Copyright (c) 2019 Kungliga Tekniska Högskolan
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

#ifndef HEIMDAL_KDC_BEARER_TOKEN_PLUGIN_H
#define HEIMDAL_KDC_BEARER_TOKEN_PLUGIN_H 1

#define KDC_PLUGIN_BEARER "kdc_plugin_bearer_token"
#define KDC_PLUGIN_BEARER_VERSION_0 0

/*
 * @param init          Plugin initialization function (see krb5-plugin(7))
 * @param minor_version The plugin minor version number (0)
 * @param fini          Plugin finalization function
 * @param validate      Plugin token validation function
 * @param freestr       Function for freeing output values of validate function
 *
 * The validate field is the plugin entry point that performs the bearer token
 * validation operation however the plugin desires.  It is invoked in no
 * particular order relative to other bearer token validator plugins.  The
 * plugin validate function must return KRB5_PLUGIN_NO_HANDLE if the rule is
 * not applicable to it.
 *
 * The plugin validate function has the following arguments, in this
 * order:
 *
 * -# plug_ctx, the context value output by the plugin's init function
 * -# context, a krb5_context
 * -# realm, a const char *
 * -# token_type, a const char *
 * -# token, a krb5_data *
 * -# requested_principal, a krb5_const_principal
 * -# validation result, a pointer to a krb5_boolean
 * -# actual principal, a krb5_principal * output parameter (optional)
 * -# error_string, a char ** output parameter (optional)
 * -# freestr, a pointer to a void-returning function of a char * that frees it
 *
 * @ingroup krb5_support
 */
typedef struct krb5plugin_token_validator_ftable_desc {
    int			minor_version;
    krb5_error_code	(KRB5_LIB_CALL *init)(krb5_context, void **);
    void		(KRB5_LIB_CALL *fini)(void *);
    krb5_error_code	(KRB5_LIB_CALL *validate)(void *,           /*plug_ctx*/
                                                  krb5_context,
                                                  const char *,     /*realm*/
                                                  const char *,     /*token_type*/
                                                  krb5_data *,      /*token*/
                                                  krb5_const_principal,   /*on_behalf_of*/
                                                  krb5_boolean *,   /*valid*/
                                                  krb5_principal *, /*actual_principal*/
                                                  char **,          /*error_string*/
                                                  void (KRB5_LIB_CALL **)(char **) /*freestr*/
                                                  );
} krb5plugin_token_validator_ftable;

#endif /* HEIMDAL_KDC_BEARER_TOKEN_PLUGIN_H */
