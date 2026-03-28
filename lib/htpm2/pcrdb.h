/*
 * PCR extension database and eventlog validation.
 */

#ifndef __htpm2_pcrdb_h__
#define __htpm2_pcrdb_h__

#include "htpm2.h"
#include <stdint.h>
#include <stddef.h>

/*
 * PCR extension database.
 *
 * A SQLite3 database (or flat file) containing known PCR extension values
 * with metadata: verdict, timestamps, source, vendor info, CVEs.
 *
 * Schema:
 *   CREATE TABLE pcr_extensions (
 *     id          INTEGER PRIMARY KEY AUTOINCREMENT,
 *     hash_alg    INTEGER NOT NULL,     -- TPM2_ALG_SHA256 etc.
 *     pcr_index   INTEGER NOT NULL,     -- 0-23
 *     extension   BLOB NOT NULL,        -- the hash that was extended
 *     verdict     TEXT NOT NULL DEFAULT 'unknown',  -- good/bad/unknown
 *     severity    TEXT DEFAULT 'info',   -- info/warn/fail
 *     not_before  TEXT,                  -- ISO 8601 timestamp or NULL
 *     not_after   TEXT,                  -- ISO 8601 timestamp or NULL
 *     source      TEXT,                  -- firmware/bootloader/kernel/ima/...
 *     vendor      TEXT,                  -- vendor/origin
 *     description TEXT,                  -- human-readable
 *     reference   TEXT,                  -- vendor doc URI
 *     cve         TEXT,                  -- CVE URI(s), comma-separated
 *     pci_path    TEXT,                  -- hardware path
 *     UNIQUE(hash_alg, pcr_index, extension)
 *   );
 */

typedef struct htpm2_pcrdb *htpm2_pcrdb;

htpm2_result htpm2_pcrdb_open(const char *path, htpm2_pcrdb *db);
void         htpm2_pcrdb_close(htpm2_pcrdb *db);

/* Verdict for a looked-up extension */
typedef struct {
    const char *verdict;     /* "good", "bad", "unknown" */
    const char *severity;    /* "info", "warn", "fail" */
    const char *source;
    const char *vendor;
    const char *description;
    const char *reference;
    const char *cve;
    int         found;       /* 1 if in DB, 0 if not */
    int         expired;     /* 1 if now > not_after */
} htpm2_pcr_lookup_result;

htpm2_result htpm2_pcrdb_lookup(htpm2_pcrdb db,
                                uint16_t hash_alg,
                                uint32_t pcr_index,
                                const void *extension, size_t ext_len,
                                htpm2_pcr_lookup_result *result);

/* Add or update an entry */
htpm2_result htpm2_pcrdb_add(htpm2_pcrdb db,
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
                             const char *cve);

/*
 * PCR policy -- per-PCR validation mode.
 *
 * Specified on the command line as comma-separated assignments:
 *   "0-7=validate,8=ignore,9=initial,10=validate,11-23=ignore"
 *
 * Modes:
 *   validate: replay eventlog extensions, check each against DB
 *   initial:  PCR must equal the unextended (reset) value
 *   ignore:   don't check this PCR at all
 */
typedef enum {
    HTPM2_PCR_VALIDATE = 0,  /* replay + check against DB */
    HTPM2_PCR_INITIAL  = 1,  /* must be unextended */
    HTPM2_PCR_IGNORE   = 2   /* skip */
} htpm2_pcr_mode;

typedef struct {
    htpm2_pcr_mode mode[24];
} htpm2_pcr_policy;

/* Parse policy from string like "0-7=validate,8=ignore,10=initial" */
htpm2_result htpm2_pcr_policy_parse(const char *spec, htpm2_pcr_policy *policy);

/*
 * Eventlog entry -- a single PCR extension event.
 *
 * Eventlog parsers (TCG, IMA, etc.) produce arrays of these.
 */
typedef struct {
    uint32_t pcr_index;
    uint16_t hash_alg;
    uint8_t  digest[64];  /* up to SHA-512 */
    size_t   digest_len;
    uint32_t event_type;  /* TCG event type, or 0 for IMA */
    char    *event_data;  /* human-readable event description, or NULL */
} htpm2_eventlog_entry;

/*
 * Parse a TCG PC Client eventlog (binary format from
 * /sys/kernel/security/tpm0/binary_bios_measurements).
 *
 * Returns an array of entries; caller frees with htpm2_eventlog_free().
 */
htpm2_result htpm2_eventlog_parse_tcg(const void *data, size_t data_len,
                                      htpm2_eventlog_entry **entries,
                                      size_t *num_entries);

void htpm2_eventlog_free(htpm2_eventlog_entry *entries, size_t num_entries);

/*
 * Replay eventlog entries to compute expected PCR values.
 *
 * Starting from initial PCR values (all zeros for SHA-256), extends
 * each entry in order.  Returns 24 PCR digests.
 *
 * If `db` is non-NULL and policy mode is VALIDATE, checks each extension
 * against the database and collects warnings/failures.
 */
typedef struct {
    int      ok;             /* 1 if all checks passed */
    size_t   num_warnings;
    size_t   num_failures;
    size_t   num_unknown;    /* extensions not in DB */
    char   **messages;       /* human-readable messages */
    size_t   num_messages;
} htpm2_validation_report;

htpm2_result htpm2_eventlog_validate(
    const htpm2_context ctx,
    const htpm2_eventlog_entry *entries, size_t num_entries,
    const htpm2_pcr_policy *policy,
    htpm2_pcrdb db,           /* NULL = skip DB lookups */
    uint16_t hash_alg,
    const void *quoted_pcrs,  /* PCR values from the quote */
    size_t quoted_pcrs_len,
    const uint32_t *quoted_pcr_indices,
    size_t num_quoted_pcrs,
    htpm2_validation_report *report);

void htpm2_validation_report_free(htpm2_validation_report *report);

#endif /* __htpm2_pcrdb_h__ */
