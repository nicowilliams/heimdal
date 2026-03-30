/*
 * Copyright (c) 2026 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.  BSD 3-clause license.
 */

/*
 * TPM 2.0 policy compiler -- compute policyDigest from a parsed policy
 * document by executing the policy commands in a trial session.
 *
 * Also: policy evaluator -- execute a parsed policy in a real session
 * to satisfy it for authorization.
 */

#include "htpm2_locl.h"
#include "policy_p.h"
#include "marshal.h"
#include "crypto.h"

/* Forward declarations for policy commands in policy.c */
htpm2_result htpm2_policy_locality(const htpm2_context, htpm2_session,
                                   htpm2_result, uint8_t);
htpm2_result htpm2_policy_nv(const htpm2_context, htpm2_session,
                              htpm2_result, uint32_t, const void *, size_t,
                              uint16_t, uint16_t);
htpm2_result htpm2_policy_counter_timer(const htpm2_context, htpm2_session,
                                         htpm2_result, const void *, size_t,
                                         uint16_t, uint16_t);
htpm2_result htpm2_policy_physical_presence(const htpm2_context, htpm2_session,
                                             htpm2_result);
htpm2_result htpm2_policy_cp_hash(const htpm2_context, htpm2_session,
                                   htpm2_result, const void *, size_t);
htpm2_result htpm2_policy_name_hash(const htpm2_context, htpm2_session,
                                     htpm2_result, const void *, size_t);
htpm2_result htpm2_policy_duplication_select(const htpm2_context, htpm2_session,
                                              htpm2_result,
                                              const void *, size_t,
                                              const void *, size_t, int);
htpm2_result htpm2_policy_auth_value(const htpm2_context, htpm2_session,
                                      htpm2_result);
htpm2_result htpm2_policy_password(const htpm2_context, htpm2_session,
                                    htpm2_result);
htpm2_result htpm2_policy_nv_written(const htpm2_context, htpm2_session,
                                      htpm2_result, int);
htpm2_result htpm2_policy_template(const htpm2_context, htpm2_session,
                                    htpm2_result, const void *, size_t);
htpm2_result htpm2_policy_authorize_nv(const htpm2_context, htpm2_session,
                                        htpm2_result, uint32_t);
htpm2_result htpm2_policy_ticket(const htpm2_context, htpm2_session,
                                  htpm2_result,
                                  const void *, size_t,
                                  const void *, size_t,
                                  const void *, size_t,
                                  const void *, size_t,
                                  const void *, size_t);

/*
 * Execute a single policy node in a session (trial or real).
 */
static htpm2_result
execute_node(const htpm2_context ctx,
             htpm2_transport tp,
             htpm2_session session,
             const htpm2_policy_node *node,
             htpm2_result prior)
{
    if (prior.code)
        return prior;

    switch (node->cc) {
    case HTPM2_POL_PCR: {
        /* Build PCR selection from bitmask */
        void *pcr_sel = NULL;
        size_t pcr_sel_len = 0;
        htpm2_pcr_selection sel = NULL;
        htpm2_result r;
        int i;

        r = htpm2_pcr_selection_create(ctx,
                                       node->u.pcr.hash_alg ? node->u.pcr.hash_alg : TPM2_ALG_SHA256,
                                       &sel);
        if (htpm2_is_err(r)) return r;

        for (i = 0; i < 24; i++)
            if (node->u.pcr.pcr_bitmask & (1U << i))
                htpm2_pcr_selection_add(sel, i);

        r = htpm2_pcr_selection_encode(sel, &pcr_sel, &pcr_sel_len);
        htpm2_pcr_selection_free(&sel);
        if (htpm2_is_err(r)) return r;

        r = htpm2_policy_pcr(ctx, session, HTPM2_OK,
                              pcr_sel, pcr_sel_len,
                              node->u.pcr.pcr_digest,
                              node->u.pcr.pcr_digest_len);
        free(pcr_sel);
        return r;
    }

    case HTPM2_POL_COMMAND_CODE:
        return htpm2_policy_command_code(ctx, session, HTPM2_OK,
                                         node->u.command_code.command_code);

    case HTPM2_POL_AUTH_VALUE:
        return htpm2_policy_auth_value(ctx, session, HTPM2_OK);

    case HTPM2_POL_PASSWORD:
        return htpm2_policy_password(ctx, session, HTPM2_OK);

    case HTPM2_POL_PHYSICAL_PRESENCE:
        return htpm2_policy_physical_presence(ctx, session, HTPM2_OK);

    case HTPM2_POL_LOCALITY:
        return htpm2_policy_locality(ctx, session, HTPM2_OK,
                                     node->u.locality.locality);

    case HTPM2_POL_NV:
        return htpm2_policy_nv(ctx, session, HTPM2_OK,
                                node->u.nv.nv_index,
                                node->u.nv.operand_b,
                                node->u.nv.operand_b_len,
                                node->u.nv.offset,
                                node->u.nv.operation);

    case HTPM2_POL_COUNTER_TIMER:
        return htpm2_policy_counter_timer(ctx, session, HTPM2_OK,
                                          node->u.counter_timer.operand_b,
                                          node->u.counter_timer.operand_b_len,
                                          node->u.counter_timer.offset,
                                          node->u.counter_timer.operation);

    case HTPM2_POL_CP_HASH:
        return htpm2_policy_cp_hash(ctx, session, HTPM2_OK,
                                    node->u.hash.hash,
                                    node->u.hash.hash_len);

    case HTPM2_POL_NAME_HASH:
        return htpm2_policy_name_hash(ctx, session, HTPM2_OK,
                                      node->u.hash.hash,
                                      node->u.hash.hash_len);

    case HTPM2_POL_TEMPLATE:
        return htpm2_policy_template(ctx, session, HTPM2_OK,
                                     node->u.hash.hash,
                                     node->u.hash.hash_len);

    case HTPM2_POL_DUPLICATION_SELECT:
        return htpm2_policy_duplication_select(ctx, session, HTPM2_OK,
            node->u.duplication_select.object_name,
            node->u.duplication_select.object_name_len,
            node->u.duplication_select.new_parent_name,
            node->u.duplication_select.new_parent_name_len,
            node->u.duplication_select.include_object);

    case HTPM2_POL_NV_WRITTEN:
        return htpm2_policy_nv_written(ctx, session, HTPM2_OK,
                                       node->u.nv_written.written_set);

    case HTPM2_POL_SIGNED:
        /* In trial mode, PolicySigned only needs the key Name.
         * TODO: load the auth object to get its Name. */
        return htpm2_result_local(ENOSYS, HTPM2_F_LOCAL, ENOSYS,
                                  "PolicySigned: object loading not yet "
                                  "implemented in compiler");

    case HTPM2_POL_SECRET:
        /* Similar to PolicySigned -- needs loaded object */
        return htpm2_result_local(ENOSYS, HTPM2_F_LOCAL, ENOSYS,
                                  "PolicySecret: object loading not yet "
                                  "implemented in compiler");

    case HTPM2_POL_AUTHORIZE:
        /* PolicyAuthorize in trial: just needs keySign Name + policyRef */
        return htpm2_result_local(ENOSYS, HTPM2_F_LOCAL, ENOSYS,
                                  "PolicyAuthorize: object loading not yet "
                                  "implemented in compiler");

    case HTPM2_POL_AUTHORIZE_NV:
        return htpm2_policy_authorize_nv(ctx, session, HTPM2_OK,
                                          node->u.authorize_nv.nv_index);

    case HTPM2_POL_TICKET:
        return htpm2_result_local(ENOSYS, HTPM2_F_LOCAL, ENOSYS,
                                  "PolicyTicket: requires runtime ticket");

    case HTPM2_POL_OR:
        /* PolicyOr is handled specially by the compiler */
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "PolicyOr: should be handled by compiler, "
                                  "not execute_node");

    default:
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "execute_node: unknown cc 0x%08x", node->cc);
    }
}

/*
 * Compile a policy -- compute policyDigest via a trial session.
 *
 * For PolicyOr: compile each alternative separately in its own trial
 * session, collect their digests, then execute PolicyOr with those
 * digests in the main trial session.
 */
htpm2_result
htpm2_policy_compile(const htpm2_context ctx,
                     htpm2_transport tp,
                     const htpm2_policy_doc *doc,
                     void *digest, size_t *digest_len)
{
    htpm2_session trial = NULL;
    htpm2_result r = HTPM2_OK;
    size_t i;

    if (digest_len == NULL || *digest_len < 32)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "policy_compile: digest buffer too small");

    /* Start trial session */
    r = htpm2_session_start(ctx, tp, HTPM2_OK,
                            HTPM2_SESSION_TRIAL,
                            NULL, NULL, 0, &trial);
    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "policy_compile");

    /* Walk nodes */
    for (i = 0; i < doc->num_nodes; i++) {
        const htpm2_policy_node *node = &doc->nodes[i];

        if (node->cc == HTPM2_POL_OR) {
            /* Compile each alternative in a separate trial session,
             * then call PolicyOr with the collected digests. */
            size_t j;
            size_t n = node->u.or_node.num_alternatives;
            uint8_t alt_digest_bufs[8][32];
            const void *alt_digests[8];
            size_t alt_digest_lens[8];

            if (n > 8) {
                r = htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                    "policy_compile: PolicyOr has %zu alternatives (max 8)", n);
                break;
            }

            memset(alt_digest_bufs, 0, sizeof(alt_digest_bufs));
            for (j = 0; j < 8; j++)
                alt_digests[j] = alt_digest_bufs[j];

            for (j = 0; j < n; j++) {
                htpm2_policy_ref *ref = &node->u.or_node.alternatives[j];

                if (ref->inline_policy) {
                    size_t alt_dig_len = 32;

                    r = htpm2_policy_compile(ctx, tp, ref->inline_policy,
                                             alt_digest_bufs[j],
                                             &alt_dig_len);
                    if (htpm2_is_err(r)) break;
                    alt_digest_lens[j] = 32;
                } else if (ref->name) {
                    /* Referenced policy -- need resolver.
                     * For now, error. */
                    r = htpm2_result_local(ENOSYS, HTPM2_F_LOCAL, ENOSYS,
                        "policy_compile: PolicyOr reference '%s' "
                        "resolution not yet implemented", ref->name);
                    break;
                }
            }

            if (htpm2_is_ok(r)) {
                /* Execute PolicyOr with the collected digests */
                r = htpm2_policy_or(ctx, trial, HTPM2_OK,
                                    alt_digests,
                                    alt_digest_lens, n);
            }

            /* alt_digest_bufs are stack-allocated, no free needed */

            if (htpm2_is_err(r))
                break;
        } else {
            /* Execute nodes before PolicyOr (or all nodes if no PolicyOr) */
            r = execute_node(ctx, tp, trial, node, HTPM2_OK);
            if (htpm2_is_err(r))
                break;
        }
    }

    if (htpm2_is_ok(r)) {
        /* Get the policyDigest */
        r = htpm2_session_get_policy_digest(trial, HTPM2_OK,
                                            digest, digest_len);
    }

    htpm2_session_close(&trial);

    if (htpm2_is_err(r))
        return htpm2_result_prepend(r, "policy_compile '%s'",
                                    doc->name ? doc->name : "");
    return HTPM2_OK;
}

/* ================================================================
 * Policy evaluator -- satisfy a policy in a real session.
 * ================================================================ */

/*
 * Look up an input value by name.
 */
static const htpm2_policy_input_value *
find_input(const htpm2_policy_input_value *inputs, size_t num_inputs,
           const char *name)
{
    size_t i;
    if (name == NULL || inputs == NULL)
        return NULL;
    for (i = 0; i < num_inputs; i++)
        if (inputs[i].name && strcmp(inputs[i].name, name) == 0)
            return &inputs[i];
    return NULL;
}

/*
 * Evaluate a parsed policy document to satisfy it in a real session.
 *
 * For PolicyOr:
 *   1. All nodes before the PolicyOr are executed first.
 *   2. The selected alternative is evaluated (recursively) in the
 *      same session, setting policyDigest to that alternative's value.
 *   3. PolicyOr is called with all alternatives' compiled digests,
 *      which checks that policyDigest matches one and replaces it.
 *
 * For PolicyAuthorize / PolicyAuthorizeNV:
 *   Must be the first node.  The caller passes session_in with the
 *   sub-policy already evaluated.  We just execute the authorize
 *   command, which checks policyDigest and replaces it.
 */
htpm2_result
htpm2_policy_evaluate(const htpm2_context ctx,
                      htpm2_transport tp,
                      const htpm2_policy_doc *doc,
                      const htpm2_policy_input_value *inputs,
                      size_t num_inputs,
                      htpm2_session session_in,
                      htpm2_session *session_out)
{
    htpm2_session session = NULL;
    htpm2_result r = HTPM2_OK;
    size_t i;

    *session_out = NULL;

    /* Use existing session or create a new one */
    if (session_in != NULL) {
        session = session_in;
    } else {
        r = htpm2_session_start(ctx, tp, HTPM2_OK,
                                HTPM2_SESSION_POLICY,
                                NULL, NULL, 0, &session);
        if (htpm2_is_err(r))
            return htpm2_result_prepend(r, "policy_evaluate: start session");
    }

    /* Walk nodes */
    for (i = 0; i < doc->num_nodes; i++) {
        const htpm2_policy_node *node = &doc->nodes[i];

        if (node->cc == HTPM2_POL_OR) {
            /*
             * PolicyOr evaluation:
             * 1. Determine which alternative the user selected
             * 2. Evaluate that alternative in the current session
             *    (sets policyDigest to the alternative's value)
             * 3. Compile ALL alternatives to get their digests
             * 4. Call PolicyOr with those digests
             */
            const htpm2_policy_input_value *sel_input;
            size_t selected = 0;
            size_t n = node->u.or_node.num_alternatives;
            size_t j;
            uint8_t alt_digest_bufs[8][32];
            const void *alt_digests[8];
            size_t alt_digest_lens[8];

            memset(alt_digests, 0, sizeof(alt_digests));

            /* Find selected alternative index */
            sel_input = find_input(inputs, num_inputs,
                                   node->u.or_node.select_input);
            if (sel_input && sel_input->value && sel_input->value_len >= sizeof(int)) {
                selected = *(const int *)sel_input->value;
            }
            if (selected >= n) {
                r = htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                    "policy_evaluate: PolicyOr select %zu out of range "
                    "(have %zu alternatives)", selected, n);
                break;
            }

            /* Evaluate the selected alternative in this session */
            {
                htpm2_policy_ref *ref = &node->u.or_node.alternatives[selected];
                if (ref->inline_policy) {
                    /* Recurse: evaluate inline policy in same session */
                    htpm2_session dummy_out = NULL;
                    r = htpm2_policy_evaluate(ctx, tp, ref->inline_policy,
                                              inputs, num_inputs,
                                              session, &dummy_out);
                    /* dummy_out == session (we passed session_in) */
                } else if (ref->name) {
                    r = htpm2_result_local(ENOSYS, HTPM2_F_LOCAL, ENOSYS,
                        "policy_evaluate: PolicyOr reference '%s' "
                        "resolution not yet implemented", ref->name);
                }
                if (htpm2_is_err(r)) break;
            }

            /* Compile all alternatives to get their digests */
            for (j = 0; j < n; j++) {
                htpm2_policy_ref *ref = &node->u.or_node.alternatives[j];
                if (ref->inline_policy) {
                    size_t alt_dig_len = 32;
                    r = htpm2_policy_compile(ctx, tp, ref->inline_policy,
                                             alt_digest_bufs[j],
                                             &alt_dig_len);
                    if (htpm2_is_err(r)) break;
                    alt_digest_lens[j] = 32;
                } else {
                    r = htpm2_result_local(ENOSYS, HTPM2_F_LOCAL, ENOSYS,
                        "policy_evaluate: need compiled digest for "
                        "reference '%s'", ref->name ? ref->name : "?");
                    break;
                }
            }

            /* Call PolicyOr */
            if (htpm2_is_ok(r)) {
                r = htpm2_policy_or(ctx, session, HTPM2_OK,
                                    alt_digests,
                                    alt_digest_lens, n);
            }

            if (htpm2_is_err(r)) break;

        } else {
            /* Normal node -- execute it */
            r = execute_node(ctx, tp, session, node, HTPM2_OK);
            if (htpm2_is_err(r))
                break;
        }
    }

    if (htpm2_is_err(r)) {
        if (session_in == NULL)
            htpm2_session_close(&session);
        return htpm2_result_prepend(r, "policy_evaluate '%s'",
                                    doc->name ? doc->name : "");
    }

    *session_out = session;
    return HTPM2_OK;
}
