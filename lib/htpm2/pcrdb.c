/*
 * Copyright (c) 2026 Kungliga Tekniska Högskolan
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
 * PCR extension database (SQLite3) and eventlog validation.
 */

#include "htpm2_locl.h"
#include "pcrdb.h"
#include "crypto.h"

#include <sqlite3.h>
#include <time.h>
#include <ctype.h>

struct htpm2_pcrdb {
    sqlite3 *db;
    sqlite3_stmt *lookup_stmt;
    sqlite3_stmt *insert_stmt;
};

static const char *create_sql =
    "CREATE TABLE IF NOT EXISTS pcr_extensions ("
    "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  hash_alg    INTEGER NOT NULL,"
    "  pcr_index   INTEGER NOT NULL,"
    "  extension   BLOB NOT NULL,"
    "  verdict     TEXT NOT NULL DEFAULT 'unknown',"
    "  severity    TEXT DEFAULT 'info',"
    "  not_before  TEXT,"
    "  not_after   TEXT,"
    "  source      TEXT,"
    "  vendor      TEXT,"
    "  description TEXT,"
    "  reference   TEXT,"
    "  cve         TEXT,"
    "  pci_path    TEXT,"
    "  UNIQUE(hash_alg, pcr_index, extension)"
    ");";

htpm2_result
htpm2_pcrdb_open(const char *path, htpm2_pcrdb *db)
{
    struct htpm2_pcrdb *p;
    int rc;

    *db = NULL;

    p = calloc(1, sizeof(*p));
    if (p == NULL)
        return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                  "pcrdb_open: alloc");

    rc = sqlite3_open(path, &p->db);
    if (rc != SQLITE_OK) {
        const char *msg = p->db ? sqlite3_errmsg(p->db) : "unknown";
        htpm2_result r = htpm2_result_local(rc, HTPM2_F_LOCAL, rc,
                                             "pcrdb_open: %s: %s", path, msg);
        sqlite3_close(p->db);
        free(p);
        return r;
    }

    rc = sqlite3_exec(p->db, create_sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        htpm2_result r = htpm2_result_local(rc, HTPM2_F_LOCAL, rc,
                                             "pcrdb_open: create table: %s",
                                             sqlite3_errmsg(p->db));
        sqlite3_close(p->db);
        free(p);
        return r;
    }

    /* Prepare statements */
    sqlite3_prepare_v2(p->db,
        "SELECT verdict, severity, source, vendor, description, "
        "reference, cve, not_after "
        "FROM pcr_extensions "
        "WHERE hash_alg = ? AND pcr_index = ? AND extension = ?",
        -1, &p->lookup_stmt, NULL);

    sqlite3_prepare_v2(p->db,
        "INSERT OR REPLACE INTO pcr_extensions "
        "(hash_alg, pcr_index, extension, verdict, severity, "
        "not_before, not_after, source, vendor, description, "
        "reference, cve) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        -1, &p->insert_stmt, NULL);

    *db = p;
    return HTPM2_OK;
}

void
htpm2_pcrdb_close(htpm2_pcrdb *db)
{
    struct htpm2_pcrdb *p;
    if (db == NULL || *db == NULL)
        return;
    p = *db;
    sqlite3_finalize(p->lookup_stmt);
    sqlite3_finalize(p->insert_stmt);
    sqlite3_close(p->db);
    free(p);
    *db = NULL;
}

htpm2_result
htpm2_pcrdb_lookup(htpm2_pcrdb db,
                   uint16_t hash_alg,
                   uint32_t pcr_index,
                   const void *extension, size_t ext_len,
                   htpm2_pcr_lookup_result *result)
{
    int rc;

    memset(result, 0, sizeof(*result));

    if (db == NULL || db->lookup_stmt == NULL) {
        result->found = 0;
        return HTPM2_OK;
    }

    sqlite3_reset(db->lookup_stmt);
    sqlite3_bind_int(db->lookup_stmt, 1, hash_alg);
    sqlite3_bind_int(db->lookup_stmt, 2, pcr_index);
    sqlite3_bind_blob(db->lookup_stmt, 3, extension, ext_len, SQLITE_STATIC);

    rc = sqlite3_step(db->lookup_stmt);
    if (rc == SQLITE_ROW) {
        result->found = 1;
        result->verdict = (const char *)sqlite3_column_text(db->lookup_stmt, 0);
        result->severity = (const char *)sqlite3_column_text(db->lookup_stmt, 1);
        result->source = (const char *)sqlite3_column_text(db->lookup_stmt, 2);
        result->vendor = (const char *)sqlite3_column_text(db->lookup_stmt, 3);
        result->description = (const char *)sqlite3_column_text(db->lookup_stmt, 4);
        result->reference = (const char *)sqlite3_column_text(db->lookup_stmt, 5);
        result->cve = (const char *)sqlite3_column_text(db->lookup_stmt, 6);

        /* Check not_after */
        const char *not_after = (const char *)sqlite3_column_text(db->lookup_stmt, 7);
        if (not_after && strlen(not_after) > 0) {
            /* Simple comparison: ISO 8601 strings sort correctly */
            char now_str[32];
            time_t now = time(NULL);
            struct tm *tm = gmtime(&now);
            strftime(now_str, sizeof(now_str), "%Y-%m-%dT%H:%M:%SZ", tm);
            if (strcmp(now_str, not_after) > 0)
                result->expired = 1;
        }
    } else {
        result->found = 0;
    }

    return HTPM2_OK;
}

htpm2_result
htpm2_pcrdb_add(htpm2_pcrdb db,
                uint16_t hash_alg,
                uint32_t pcr_index,
                const void *extension, size_t ext_len,
                const char *verdict,
                const char *severity,
                const char *not_before,
                const char *not_after,
                const char *source,
                const char *vendor,
                const char *description,
                const char *reference,
                const char *cve)
{
    int rc;

    if (db == NULL || db->insert_stmt == NULL)
        return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                  "pcrdb_add: no database");

    sqlite3_reset(db->insert_stmt);
    sqlite3_bind_int(db->insert_stmt, 1, hash_alg);
    sqlite3_bind_int(db->insert_stmt, 2, pcr_index);
    sqlite3_bind_blob(db->insert_stmt, 3, extension, ext_len, SQLITE_STATIC);
    sqlite3_bind_text(db->insert_stmt, 4, verdict ? verdict : "unknown", -1, SQLITE_STATIC);
    sqlite3_bind_text(db->insert_stmt, 5, severity ? severity : "info", -1, SQLITE_STATIC);
    if (not_before) sqlite3_bind_text(db->insert_stmt, 6, not_before, -1, SQLITE_STATIC);
    else sqlite3_bind_null(db->insert_stmt, 6);
    if (not_after) sqlite3_bind_text(db->insert_stmt, 7, not_after, -1, SQLITE_STATIC);
    else sqlite3_bind_null(db->insert_stmt, 7);
    if (source) sqlite3_bind_text(db->insert_stmt, 8, source, -1, SQLITE_STATIC);
    else sqlite3_bind_null(db->insert_stmt, 8);
    if (vendor) sqlite3_bind_text(db->insert_stmt, 9, vendor, -1, SQLITE_STATIC);
    else sqlite3_bind_null(db->insert_stmt, 9);
    if (description) sqlite3_bind_text(db->insert_stmt, 10, description, -1, SQLITE_STATIC);
    else sqlite3_bind_null(db->insert_stmt, 10);
    if (reference) sqlite3_bind_text(db->insert_stmt, 11, reference, -1, SQLITE_STATIC);
    else sqlite3_bind_null(db->insert_stmt, 11);
    if (cve) sqlite3_bind_text(db->insert_stmt, 12, cve, -1, SQLITE_STATIC);
    else sqlite3_bind_null(db->insert_stmt, 12);

    rc = sqlite3_step(db->insert_stmt);
    if (rc != SQLITE_DONE)
        return htpm2_result_local(rc, HTPM2_F_LOCAL, rc,
                                  "pcrdb_add: %s", sqlite3_errmsg(db->db));

    return HTPM2_OK;
}

/* --- PCR policy parsing --- */

htpm2_result
htpm2_pcr_policy_parse(const char *spec, htpm2_pcr_policy *policy)
{
    const char *p = spec;
    int i;

    /* Default: validate all PCRs */
    for (i = 0; i < 24; i++)
        policy->mode[i] = HTPM2_PCR_VALIDATE;

    if (spec == NULL || *spec == '\0')
        return HTPM2_OK;

    /*
     * Parse "0-7=validate,8=ignore,9=initial,10=validate,11-23=ignore"
     */
    while (*p) {
        int lo, hi;
        htpm2_pcr_mode mode;
        const char *mode_str;

        /* Parse PCR range: "N" or "N-M" */
        lo = atoi(p);
        while (isdigit((unsigned char)*p)) p++;
        if (*p == '-') {
            p++;
            hi = atoi(p);
            while (isdigit((unsigned char)*p)) p++;
        } else {
            hi = lo;
        }

        if (*p != '=')
            return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                      "pcr_policy_parse: expected '=' at '%s'", p);
        p++;

        /* Parse mode */
        mode_str = p;
        while (*p && *p != ',') p++;

        if (strncmp(mode_str, "validate", p - mode_str) == 0)
            mode = HTPM2_PCR_VALIDATE;
        else if (strncmp(mode_str, "initial", p - mode_str) == 0)
            mode = HTPM2_PCR_INITIAL;
        else if (strncmp(mode_str, "ignore", p - mode_str) == 0)
            mode = HTPM2_PCR_IGNORE;
        else
            return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                      "pcr_policy_parse: unknown mode '%.*s'",
                                      (int)(p - mode_str), mode_str);

        if (lo < 0 || hi > 23 || lo > hi)
            return htpm2_result_local(EINVAL, HTPM2_F_LOCAL, EINVAL,
                                      "pcr_policy_parse: bad range %d-%d",
                                      lo, hi);

        for (i = lo; i <= hi; i++)
            policy->mode[i] = mode;

        if (*p == ',') p++;
    }

    return HTPM2_OK;
}

/* --- Eventlog parsing (TCG PC Client format) --- */

/*
 * TCG PC Client Specific Platform Firmware Profile
 * Event Log format:
 *
 * Legacy (PCR index 0-7 first event):
 *   pcrIndex:  uint32
 *   eventType: uint32
 *   digest:    20 bytes (SHA-1)
 *   eventSize: uint32
 *   event:     eventSize bytes
 *
 * Crypto-agile (EV_NO_ACTION header, then events with TPML_DIGEST_VALUES):
 *   pcrIndex:     uint32
 *   eventType:    uint32
 *   digests:      count(uint32) + [ algId(uint16) + digest ] * count
 *   eventSize:    uint32
 *   event:        eventSize bytes
 */

#define EV_NO_ACTION       0x00000003
#define EV_SEPARATOR       0x00000004
#define EV_EFI_ACTION      0x80000007

htpm2_result
htpm2_eventlog_parse_tcg(const void *data, size_t data_len,
                         htpm2_eventlog_entry **entries,
                         size_t *num_entries)
{
    const uint8_t *p = data;
    const uint8_t *end = p + data_len;
    htpm2_eventlog_entry *list = NULL;
    size_t count = 0, capacity = 0;
    int crypto_agile = 0;

    *entries = NULL;
    *num_entries = 0;

    while (p + 12 <= end) {
        uint32_t pcr_index, event_type, event_size;
        htpm2_eventlog_entry entry;

        memset(&entry, 0, sizeof(entry));

        /* pcrIndex */
        pcr_index = ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
                    ((uint32_t)p[1] << 8) | p[0];
        p += 4;

        /* eventType */
        event_type = ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
                     ((uint32_t)p[1] << 8) | p[0];
        p += 4;

        entry.pcr_index = pcr_index;
        entry.event_type = event_type;

        if (!crypto_agile) {
            /* Legacy: 20-byte SHA-1 digest */
            if (p + 20 > end) break;
            entry.hash_alg = 0x0004;  /* TPM2_ALG_SHA1 */
            memcpy(entry.digest, p, 20);
            entry.digest_len = 20;
            p += 20;

            if (p + 4 > end) break;
            event_size = ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
                         ((uint32_t)p[1] << 8) | p[0];
            p += 4;

            if (p + event_size > end) break;

            /* Check for crypto-agile marker */
            if (event_type == EV_NO_ACTION && count == 0) {
                /* First event is the Spec ID event -- switch to crypto-agile */
                crypto_agile = 1;
                p += event_size;
                continue;
            }

            p += event_size;
        } else {
            /* Crypto-agile: TPML_DIGEST_VALUES */
            uint32_t digest_count;
            uint32_t d;

            if (p + 4 > end) break;
            digest_count = ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
                           ((uint32_t)p[1] << 8) | p[0];
            p += 4;

            for (d = 0; d < digest_count && p + 2 <= end; d++) {
                uint16_t alg = ((uint16_t)p[1] << 8) | p[0];
                size_t dlen;
                p += 2;

                /* Determine digest length from algorithm */
                switch (alg) {
                case 0x0004: dlen = 20; break;  /* SHA-1 */
                case 0x000B: dlen = 32; break;  /* SHA-256 */
                case 0x000C: dlen = 48; break;  /* SHA-384 */
                case 0x000D: dlen = 64; break;  /* SHA-512 */
                default: dlen = 32; break;       /* guess */
                }

                if (p + dlen > end) goto done;

                /* Keep the SHA-256 digest (preferred) or first available */
                if (alg == 0x000B || entry.digest_len == 0) {
                    entry.hash_alg = alg;
                    if (dlen <= sizeof(entry.digest)) {
                        memcpy(entry.digest, p, dlen);
                        entry.digest_len = dlen;
                    }
                }
                p += dlen;
            }

            if (p + 4 > end) break;
            event_size = ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
                         ((uint32_t)p[1] << 8) | p[0];
            p += 4;

            if (p + event_size > end) break;
            p += event_size;
        }

        /* Add entry to list */
        if (count >= capacity) {
            capacity = capacity ? capacity * 2 : 64;
            htpm2_eventlog_entry *new_list = realloc(list,
                capacity * sizeof(*list));
            if (new_list == NULL) {
                free(list);
                return htpm2_result_local(ENOMEM, HTPM2_F_LOCAL, ENOMEM,
                                          "eventlog_parse: alloc");
            }
            list = new_list;
        }
        list[count++] = entry;
    }

done:
    *entries = list;
    *num_entries = count;
    return HTPM2_OK;
}

void
htpm2_eventlog_free(htpm2_eventlog_entry *entries, size_t num_entries)
{
    size_t i;
    if (entries == NULL)
        return;
    for (i = 0; i < num_entries; i++)
        free(entries[i].event_data);
    free(entries);
}

/* --- Eventlog validation --- */

static void
report_add_message(htpm2_validation_report *report, const char *fmt, ...)
{
    va_list ap;
    char *msg;

    va_start(ap, fmt);
    if (vasprintf(&msg, fmt, ap) < 0)
        msg = NULL;
    va_end(ap);

    if (msg == NULL)
        return;

    char **new_msgs = realloc(report->messages,
                              (report->num_messages + 1) * sizeof(char *));
    if (new_msgs == NULL) {
        free(msg);
        return;
    }
    report->messages = new_msgs;
    report->messages[report->num_messages++] = msg;
}

htpm2_result
htpm2_eventlog_validate(const htpm2_context ctx,
                        const htpm2_eventlog_entry *entries,
                        size_t num_entries,
                        const htpm2_pcr_policy *policy,
                        htpm2_pcrdb db,
                        uint16_t hash_alg,
                        const void *quoted_pcrs,
                        size_t quoted_pcrs_len,
                        const uint32_t *quoted_pcr_indices,
                        size_t num_quoted_pcrs,
                        htpm2_validation_report *report)
{
    uint8_t pcr_state[24][64]; /* current PCR values */
    size_t digest_len;
    size_t i;
    htpm2_result r;

    memset(report, 0, sizeof(*report));
    report->ok = 1;

    /* Determine digest length */
    switch (hash_alg) {
    case 0x000B: digest_len = 32; break; /* SHA-256 */
    case 0x000C: digest_len = 48; break;
    case 0x000D: digest_len = 64; break;
    default: digest_len = 32; break;
    }

    /* Initialize PCRs to zero (the reset value for SHA-256/384/512) */
    memset(pcr_state, 0, sizeof(pcr_state));

    /* Replay eventlog */
    for (i = 0; i < num_entries; i++) {
        const htpm2_eventlog_entry *e = &entries[i];

        if (e->pcr_index > 23)
            continue;
        if (e->hash_alg != hash_alg)
            continue;

        /* Check against DB if policy says validate */
        if (policy && policy->mode[e->pcr_index] == HTPM2_PCR_VALIDATE && db) {
            htpm2_pcr_lookup_result lr;

            r = htpm2_pcrdb_lookup(db, hash_alg, e->pcr_index,
                                   e->digest, e->digest_len, &lr);
            if (htpm2_is_ok(r)) {
                if (!lr.found) {
                    report->num_unknown++;
                    report_add_message(report,
                        "PCR %u event %zu: unknown extension (not in DB)",
                        e->pcr_index, i);
                } else if (lr.expired) {
                    report->num_failures++;
                    report->ok = 0;
                    report_add_message(report,
                        "PCR %u event %zu: expired (was %s, not_after passed)%s%s",
                        e->pcr_index, i,
                        lr.verdict ? lr.verdict : "unknown",
                        lr.cve ? " CVE: " : "",
                        lr.cve ? lr.cve : "");
                } else if (lr.verdict &&
                           strcmp(lr.verdict, "bad") == 0) {
                    report->num_failures++;
                    report->ok = 0;
                    report_add_message(report,
                        "PCR %u event %zu: KNOWN BAD (%s)%s%s",
                        e->pcr_index, i,
                        lr.description ? lr.description : "no description",
                        lr.cve ? " CVE: " : "",
                        lr.cve ? lr.cve : "");
                } else if (lr.severity &&
                           strcmp(lr.severity, "warn") == 0) {
                    report->num_warnings++;
                    report_add_message(report,
                        "PCR %u event %zu: WARNING (%s)",
                        e->pcr_index, i,
                        lr.description ? lr.description : "");
                }
                /* "good" + not expired = fine, no message */
            }
        }

        /* Extend: PCR[i] = SHA-256(PCR[i] || extension) */
        {
            uint8_t extend_buf[64 + 64]; /* current + extension */
            memcpy(extend_buf, pcr_state[e->pcr_index], digest_len);
            memcpy(extend_buf + digest_len, e->digest, e->digest_len);
            r = htpm2_sha256(ctx, extend_buf, digest_len + e->digest_len,
                             pcr_state[e->pcr_index]);
            if (htpm2_is_err(r)) {
                report->ok = 0;
                return r;
            }
        }
    }

    /* Check PCRs that should be initial (unextended) */
    if (policy) {
        for (i = 0; i < 24; i++) {
            if (policy->mode[i] == HTPM2_PCR_INITIAL) {
                uint8_t zeros[64];
                memset(zeros, 0, sizeof(zeros));
                if (memcmp(pcr_state[i], zeros, digest_len) != 0) {
                    report->num_failures++;
                    report->ok = 0;
                    report_add_message(report,
                        "PCR %zu: expected initial value but was extended",
                        i);
                }
            }
        }
    }

    /* Compare replayed PCR values against quoted values */
    if (quoted_pcrs && quoted_pcr_indices && num_quoted_pcrs > 0) {
        const uint8_t *qp = quoted_pcrs;

        for (i = 0; i < num_quoted_pcrs; i++) {
            uint32_t idx = quoted_pcr_indices[i];

            if (idx > 23) continue;
            if (policy && policy->mode[idx] == HTPM2_PCR_IGNORE)
                continue;

            if ((size_t)((qp - (const uint8_t *)quoted_pcrs) + digest_len) > quoted_pcrs_len)
                break;

            if (memcmp(pcr_state[idx], qp, digest_len) != 0) {
                report->num_failures++;
                report->ok = 0;
                report_add_message(report,
                    "PCR %u: replayed value does not match quote", idx);
            }
            qp += digest_len;
        }
    }

    return HTPM2_OK;
}

void
htpm2_validation_report_free(htpm2_validation_report *report)
{
    size_t i;
    if (report == NULL)
        return;
    for (i = 0; i < report->num_messages; i++)
        free(report->messages[i]);
    free(report->messages);
    memset(report, 0, sizeof(*report));
}
