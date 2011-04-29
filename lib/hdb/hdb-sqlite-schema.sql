BEGIN TRANSACTION;
-- These are not persistent pragmas, so they have to be executed
-- whenever the DB is opened.
PRAGMA recursive_triggers = ON;
PRAGMA foreign_keys = ON;
--
-- HDB-SQLite schema version number table.
--
-- HDB-SQLite schema version numbers are real numbers whose
-- absolute value is a major version number and whose decimal is
-- a minor version number.  Major number changes require a schema
-- migration.  Minor number changes require only sourcing this
-- file because only triggers, and possibly some aspects of
-- views, change in minor versions, whereas alterations to tables
-- require a new major version.
--
-- The schema is documented below.
CREATE TABLE IF NOT EXISTS Version (versnum REAL);
DROP TRIGGER IF EXISTS Version_insert;
CREATE TRIGGER Version_insert
BEFORE INSERT ON Version
FOR EACH ROW BEGIN
 -- Ignore this insert if the DB is already using that version
 SELECT RAISE(IGNORE)
 WHERE (SELECT max(versnum) FROM Version) = 1.1;
 -- Interrupt schema load if the major version changes
 SELECT RAISE(ROLLBACK, 'HDB-SQLite3 requires update/migration!')
 WHERE abs((SELECT max(versnum) FROM Version)) > abs(1.1);
END;
INSERT INTO Version (versnum) VALUES (1.1);
--
-- The schema for the hdb-sqlite3 backend looks roughly as
-- follows:
--
--  - Scalar (i.e., single-valued) attributes of Kerberos V5
--    principals are stored in columns of rows of the "Entry"
--    table.
--  - Principal names are stored in the "EntryName" table, and
--    refer to rows of the "Entry" table.  The canonical name of
--    a principal is referred to from Entry rows by the
--    canon_name_id column.
--  - All other multi-valued attributes of principals are stored
--    similarly, in tables named Entry* (not including *Log
--    tables).
--     - Ordered multi-valued attributes have ordering columns.
--  - The view named "EntryDetail" has columns bearing
--    aggregated scalar views of all non-BLOB multi-valued
--    attributes of a principal.
--  - A table named EntryLog store history for incremental
--    propagation and audit purposes.  This table has the same
--    columns as the EntryDetail view, plus: a transaction
--    number, a timestamp, a column to indicate whether an
--    EntryLog row is for an old entry or a new one, and the type
--    of update.
--  - Miscaellaneous tables.
--
-- All inserts/updates/deletes of Entry and Entry* rows must be
-- done in the following order: a) Entry* rows for one entry
-- (it's OK to change Entry* rows to point from various Entry
-- rows to one, but just one), b) one entry row.  This is
-- necessary to get EntryLog logging right due to the lack of
-- transaction-level triggers in SQLite3.  In practice this suits
-- the HDB APIs just fine.
--
-- All updates of EntryDetail rows NULLify the data column of the
-- corresponding Entry rows, otherwise the data column might be
-- stale!  The hdb-sqlite backend can then use the data column as
-- a fast path when doing lookups, and rebuild and set that
-- column when it's NULL.
--
-- Tables containing standard data.
--
-- A table of HDB entry flags.  To encode and decode flags:
--  SELECT sum(flag_value) AS encoded_flags
--  FROM HDBFlags
--  WHERE flag_name IN ('flag1', 'flag2', .., 'flagN');
--  SELECT flag_name
--  FROM HDBFlags
--  WHERE ? = @num = (@num & ~flag_value) + flag_value;
-- or this to get a single string with the flag names
-- separated by a pipe symbol:
--  SELECT group_concat(flag_name, '|') as decoded_flags
--  FROM HDBFlags
--  WHERE @num = (@num & ~flag_value) + flag_value;
CREATE TABLE IF NOT EXISTS HDBFlags
 (flag_name TEXT NOT NULL,
  flag_value INTEGER NOT NULL);
DELETE FROM HDBFlags;
INSERT INTO HDBFlags (flag_name, flag_value) VALUES
 ('initial', 1);
INSERT INTO HDBFlags (flag_name, flag_value) VALUES
 ('forwardable', 2);
INSERT INTO HDBFlags (flag_name, flag_value) VALUES
 ('proxiable', 4);
INSERT INTO HDBFlags (flag_name, flag_value) VALUES
 ('renewable', 8);
INSERT INTO HDBFlags (flag_name, flag_value) VALUES
 ('postdate', 16);
INSERT INTO HDBFlags (flag_name, flag_value) VALUES
 ('server', 32);
INSERT INTO HDBFlags (flag_name, flag_value) VALUES
 ('client', 64);
INSERT INTO HDBFlags (flag_name, flag_value) VALUES
 ('invalid', 128);
INSERT INTO HDBFlags (flag_name, flag_value) VALUES
 ('require-preauth', 256);
INSERT INTO HDBFlags (flag_name, flag_value) VALUES
 ('change-pw', 512);
INSERT INTO HDBFlags (flag_name, flag_value) VALUES
 ('require-hwauth', 1024);
INSERT INTO HDBFlags (flag_name, flag_value) VALUES
 ('ok-as-delegate', 2048);
INSERT INTO HDBFlags (flag_name, flag_value) VALUES
 ('user-to-user', 4096);
INSERT INTO HDBFlags (flag_name, flag_value) VALUES
 ('immutable', 8192);
INSERT INTO HDBFlags (flag_name, flag_value) VALUES
 ('trusted-for-delegation', 16384);
INSERT INTO HDBFlags (flag_name, flag_value) VALUES
 ('allow-kerberos4', 32768);
INSERT INTO HDBFlags (flag_name, flag_value) VALUES
 ('allow-digest', 65536);
INSERT INTO HDBFlags (flag_name, flag_value) VALUES
 ('locked-out', 131072);
--
-- Standard enctypes
CREATE TABLE IF NOT EXISTS Enctypes
 (num INTEGER PRIMARY KEY,
  name TEXT NOT NULL);
DELETE FROM Enctypes;
INSERT INTO Enctypes (name, num) VALUES ('ETYPE_NULL', 0);
INSERT INTO Enctypes (name, num) VALUES ('ETYPE_DES_CBC_CRC', 1);
INSERT INTO Enctypes (name, num) VALUES ('ETYPE_DES_CBC_MD4', 2);
INSERT INTO Enctypes (name, num) VALUES ('ETYPE_DES_CBC_MD5', 3);
INSERT INTO Enctypes (name, num) VALUES ('ETYPE_DES3_CBC_MD5', 5);
INSERT INTO Enctypes (name, num) VALUES ('ETYPE_OLD_DES3_CBC_SHA1', 7);
INSERT INTO Enctypes (name, num) VALUES ('ETYPE_SIGN_DSA_GENERATE', 8);
INSERT INTO Enctypes (name, num) VALUES ('ETYPE_ENCRYPT_RSA_PRIV', 9);
INSERT INTO Enctypes (name, num) VALUES ('ETYPE_ENCRYPT_RSA_PUB', 10);
INSERT INTO Enctypes (name, num) VALUES ('ETYPE_DES3_CBC_SHA1', 16);
INSERT INTO Enctypes (name, num) VALUES ('ETYPE_AES128_CTS_HMAC_SHA1_96', 17);
INSERT INTO Enctypes (name, num) VALUES ('ETYPE_AES256_CTS_HMAC_SHA1_96', 18);
INSERT INTO Enctypes (name, num) VALUES ('ETYPE_ARCFOUR_HMAC_MD5', 23);
INSERT INTO Enctypes (name, num) VALUES ('ETYPE_ARCFOUR_HMAC_MD5_56', 24);
INSERT INTO Enctypes (name, num) VALUES ('ETYPE_ENCTYPE_PK_CROSS', 48);
INSERT INTO Enctypes (name, num) VALUES ('ETYPE_ARCFOUR_MD4', -128);
INSERT INTO Enctypes (name, num) VALUES ('ETYPE_ARCFOUR_HMAC_OLD', -133);
INSERT INTO Enctypes (name, num) VALUES ('ETYPE_ARCFOUR_HMAC_OLD_EXP', -135);
INSERT INTO Enctypes (name, num) VALUES ('ETYPE_DES_CBC_NONE', -4096);
INSERT INTO Enctypes (name, num) VALUES ('ETYPE_DES3_CBC_NONE', -4097);
INSERT INTO Enctypes (name, num) VALUES ('ETYPE_DES_CFB64_NONE', -4098);
INSERT INTO Enctypes (name, num) VALUES ('ETYPE_DES_PCBC_NONE', -4099);
INSERT INTO Enctypes (name, num) VALUES ('ETYPE_DIGEST_MD5_NONE', -4100);
INSERT INTO Enctypes (name, num) VALUES ('ETYPE_CRAM_MD5_NONE', -4101);
--
-- Main data tables
--
-- Principal names
CREATE TABLE IF NOT EXISTS EntryName
 (id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  -- Referrals for individual principals should only have
  -- values for the refer_to column.  Non-referrals should
  -- have only values for entry.
  referral_to INTEGER
   REFERENCES EntryName (id) ON DELETE CASCADE
   DEFERRABLE INITIALLY DEFERRED,
  entry INTEGER
   REFERENCES Entry (id) ON DELETE CASCADE
   DEFERRABLE INITIALLY DEFERRED
  CHECK ((referral_to IS NULL AND entry IS NOT NULL) OR
         (entry is NULL AND referral_to IS NOT NULL)));
CREATE UNIQUE INDEX IF NOT EXISTS EntryName_idx_name ON EntryName (name);
--
-- Principal data
CREATE TABLE IF NOT EXISTS Entry
 (id INTEGER PRIMARY KEY,
  canon_name_id INTEGER
   REFERENCES EntryName (id) ON DELETE RESTRICT
   DEFERRABLE INITIALLY DEFERRED,
  data BLOB,
  current_kvno INTEGER,
  created_by TEXT NOT NULL,
  created_at INTEGER,
  modified_by TEXT,
  modified_at INTEGER,
  valid_start INTEGER,
  valid_end INTEGER,
  pw_end INTEGER,
  last_pw_change INTEGER,
  max_life INTEGER,
  max_renew INTEGER,
  flags INTEGER);
CREATE UNIQUE INDEX IF NOT EXISTS Entry_idx_canon_name_id
ON Entry (canon_name_id);
--
-- Table for principal enctypes (ordered)
CREATE TABLE IF NOT EXISTS EntryEnctypes
 (entry INTEGER NOT NULL
   REFERENCES Entry (id) ON DELETE CASCADE
   DEFERRABLE INITIALLY DEFERRED,
  list_order INTEGER,
  etype INTEGER NOT NULL
   REFERENCES Enctypes (num) ON DELETE RESTRICT
   DEFERRABLE INITIALLY DEFERRED);
CREATE UNIQUE INDEX IF NOT EXISTS EntryEnctypes_idx_etype
ON EntryEnctypes (entry, etype);
CREATE UNIQUE INDEX IF NOT EXISTS EntryEnctypes_idx_order
ON EntryEnctypes (entry, list_order);
--
-- Table for encrypted long-term keys
CREATE TABLE IF NOT EXISTS EntryKeys
 (entry INTEGER NOT NULL
   REFERENCES Entry (id) ON DELETE CASCADE
   DEFERRABLE INITIALLY DEFERRED,
  kvno INTEGER NOT NULL,
  etype INTEGER
   REFERENCES Enctypes (num) ON DELETE RESTRICT
   DEFERRABLE INITIALLY DEFERRED,
  mkvno INTEGER NOT NULL,
  salt TEXT,
  s2kparams BLOB,
  encrypted_pw BLOB,
  encrypted_key BLOB,
  CHECK ((encrypted_pw IS NULL AND
    encrypted_key IS NOT NULL AND etype IS NOT NULL) OR
   (encrypted_pw IS NOT NULL AND
    encrypted_key IS NULL AND etype IS NULL)));
CREATE UNIQUE INDEX IF NOT EXISTS EntryKeys_etype
ON EntryKeys (entry, kvno, etype);
CREATE UNIQUE INDEX IF NOT EXISTS EntryKeys_etype
ON EntryKeys (encrypted_pw, entry, kvno);
--
-- Principal relations for OK-to-delegate
CREATE TABLE IF NOT EXISTS EntryOKToDelegate
 (entry INTEGER NOT NULL
   REFERENCES Entry (id) ON DELETE CASCADE
   DEFERRABLE INITIALLY DEFERRED,
  delegatee INTEGER NOT NULL
   REFERENCES Entry (id) ON DELETE CASCADE
   DEFERRABLE INITIALLY DEFERRED,
  PRIMARY KEY (entry, delegatee));
CREATE INDEX IF NOT EXISTS EntryOKToDelegate_idx
ON EntryOKToDelegate (delegatee);
--
-- PKINIT Names, certificate digests, and certificates
CREATE TABLE IF NOT EXISTS EntryPKINITCertName
 (entry INTEGER NOT NULL
   REFERENCES Entry (id) ON DELETE CASCADE
   DEFERRABLE INITIALLY DEFERRED,
  subject TEXT NOT NULL,
  issuer TEXT,
  anchor TEXT,
  PRIMARY KEY (entry, subject));
CREATE INDEX IF NOT EXISTS EntryPKINITCertName_idx
ON EntryPKINITCertName (subject);
CREATE TABLE IF NOT EXISTS EntryPKINITCertHash
 (entry INTEGER NOT NULL,
  digest_alg TEXT NOT NULL,
  digest BLOB NOT NULL,
  PRIMARY KEY (entry, digest_alg, digest));
CREATE INDEX IF NOT EXISTS EntryPKINITCertHash_idx
ON EntryPKINITCertHash (digest);
CREATE TABLE IF NOT EXISTS EntryPKINITCert
 (entry INTEGER NOT NULL,
  cert BLOB NOT NULL,
  PRIMARY KEY (entry, cert));
CREATE INDEX IF NOT EXISTS EntryPKINITCert_idx
ON EntryPKINITCert (cert);
--
-- A table for generating transaction numbers, which are then
-- used in the *Log table rows.
CREATE TABLE IF NOT EXISTS TX
 (tx INTEGER PRIMARY KEY AUTOINCREMENT,
  mtime INTEGER NOT NULL DEFAULT(strftime('%s', 'now')),
  entry_id INTEGER NOT NULL);
--
-- A table for configuring history retension/pruning policy
CREATE TABLE IF NOT EXISTS LogConfig
 (opt TEXT PRIMARY KEY NOT NULL UNIQUE,
  val);
INSERT OR IGNORE INTO LogConfig (opt, val)
VALUES ('iprop_retain_time', '7 days');
INSERT OR IGNORE INTO LogConfig (opt, val)
VALUES ('iprop_retain_count', '10000');
INSERT OR IGNORE INTO LogConfig (opt, val)
VALUES ('hist_retain_time', '7 days');
INSERT OR IGNORE INTO LogConfig (opt, val)
VALUES ('hist_retain_count', '10000');
-- A table to hold history for principal data for iprop and
-- auditing purposes.
CREATE TABLE IF NOT EXISTS EntryLog
 (tx INTEGER,
  mtime INTEGER NOT NULL DEFAULT(strftime('%s', 'now')),
  is_new INTEGER NOT NULL DEFAULT (0),
  is_insert INTEGER NOT NULL DEFAULT (0),
  is_update INTEGER NOT NULL DEFAULT (0),
  is_delete INTEGER NOT NULL DEFAULT (0),
  -- The remaining columns are all the same, and in the same
  -- order as, the columns of the EntryDetail view (defined
  -- below).  If columns are added to EntryDetail they have to be
  -- added here in the same location relative to other columns!
  canon_name_id, canon_name, id, data, created_at, created_by,
  modified_at, modified_by, valid_start, valid_end, pw_end,
  last_pw_change, max_life, max_renew, flags, flags_str, aliases,
  enctype_nums, enctype_names, keys, ok_to_delegatees,
  pkinit_names, pkinit_cert_digests, pkinit_certs);
-- Combined principal name+data history - for documentation
CREATE INDEX IF NOT EXISTS EntryLog_tx ON EntryLog (tx);
CREATE INDEX IF NOT EXISTS EntryLog_mtime ON EntryLog (mtime);
COMMIT;

BEGIN;
-- Views
-- 
-- A VIEW of Entry with aggregated relations as columns
DROP VIEW IF EXISTS EntryDetail;
CREATE VIEW EntryDetail AS
SELECT 
 -- Canonical name
 e.canon_name_id AS canon_name_id,
 n.name AS canon_name,
 -- Scalar attributes from the Entry table rows
 e.id AS id,
 e.data AS data,
 e.created_at AS created_at,
 e.created_by AS created_by,
 e.modified_at AS modified_at,
 e.modified_by AS modified_by,
 e.valid_start AS valid_start,
 e.valid_end AS valid_end,
 e.pw_end AS pw_end,
 e.last_pw_change AS last_pw_change,
 e.max_life AS max_life,
 e.max_renew AS max_renew,
 e.flags as flags,
 -- The remaining VIEW columns emulate multi-valued attributes
 -- and correspond to Entry* table rows.
 (SELECT group_concat(flag_name, '+')
  FROM HDBFlags
  WHERE e.flags = (e.flags & ~flag_value) + flag_value)
 AS flags_str,
 -- Aliases
 (SELECT group_concat(quote(n2.name), ', ')
  FROM EntryName n2
  WHERE n2.entry = e.id AND n2.id != e.canon_name_id) AS aliases,
 -- Enctypes
 -- Note that group_concat() uses arbitrary order, so we throw
 -- in the list_order column to make it easier for the user to
 -- glean the order of enctypes.  *sadness*
 (SELECT group_concat(et.list_order || ':' || et.etype, ',')
  FROM EntryEnctypes et
  WHERE et.entry = e.id
  ORDER BY et.list_order ASC) AS enctype_nums,
 (SELECT group_concat(et.list_order || ':' || etypes.name, ',')
  FROM EntryEnctypes et JOIN Enctypes etypes ON et.etype = etypes.num
  WHERE et.entry = e.id
  ORDER BY et.list_order ASC) AS enctype_names,
 (SELECT group_concat(ek.kvno || ':' || ek.etype || ':' || ek.mkvno || ':' ||
   quote(ek.salt) || ':' || quote(ek.s2kparams) || ':' ||
   quote(ek.encrypted_pw) || ':' || quote(ek.encrypted_key), '; ')
  FROM EntryKeys ek
  WHERE ek.entry = e.id) AS keys,
 -- OK-to-delegate to
 (SELECT group_concat(quote(n3.name), ',')
  FROM
  EntryOKToDelegate d
  JOIN Entry e2 ON e2.id = d.delegatee
  JOIN EntryName n3 ON n3.entry = e2.id
  WHERE d.entry = e.id) AS ok_to_delegatees,
 (SELECT group_concat(quote(pkcn.subject) || ':' ||
   quote(pkcn.issuer) || ':' || quote(pkcn.anchor), '; ')
  FROM EntryPKINITCertName pkcn
  WHERE pkcn.entry = e.id) AS pkinit_names,
 (SELECT group_concat(pkcd.digest_alg || ':' || quote(pkcd.digest), '; ')
  FROM EntryPKINITCertHash pkcd
  WHERE pkcd.entry = e.id) AS pkinit_cert_digests,
 (SELECT group_concat(quote(pkc.cert), '; ')
  FROM EntryPKINITCert pkc
  WHERE pkc.entry = e.id) AS pkinit_certs
FROM Entry e
LEFT JOIN EntryName n ON n.id = e.canon_name_id
LEFT JOIN EntryPKINITCert pkc ON pkc.entry = e.id
GROUP BY e.id;
--
-- Views to help generate row IDs (used in triggers below)
DROP VIEW IF EXISTS LastEntryNameID;
CREATE VIEW LastEntryNameID AS
SELECT n.id as last_id
FROM EntryName n
UNION ALL
SELECT 1
ORDER BY n.id DESC LIMIT 1;
DROP VIEW IF EXISTS LastEntryID;
--
CREATE VIEW LastEntryID AS
SELECT e.id as last_id
FROM Entry e
UNION ALL
SELECT 1
ORDER BY e.id DESC LIMIT 1;
COMMIT;

BEGIN;
-- Triggers
--
-- INSERT a pre-transaction row to EntryLog
DROP TRIGGER IF EXISTS TX_insert;
CREATE TRIGGER TX_insert
AFTER INSERT ON TX
FOR EACH ROW BEGIN
 INSERT INTO EntryLog (tx, mtime, is_new,
  canon_name_id, canon_name, id, data, created_at, created_by,
  modified_at, modified_by, valid_start, valid_end, pw_end,
  last_pw_change, max_life, max_renew, flags, flags_str, aliases,
  enctype_nums, enctype_names, keys, ok_to_delegatees,
  pkinit_names, pkinit_cert_digests, pkinit_certs)
 SELECT NEW.tx, NEW.mtime, 0, ed.*
 FROM EntryDetail ed
 WHERE ed.id = NEW.entry_id;
END;
-- INSTEAD OF trigger to insert a principal
DROP TRIGGER IF EXISTS EntryDetail_insert;
CREATE TRIGGER EntryDetail_insert
INSTEAD OF INSERT ON EntryDetail
FOR EACH ROW BEGIN
 -- Validate NEW values
 SELECT RAISE(ROLLBACK, 'EntryDetail: missing canon_name')
 WHERE NEW.canon_name IS NULL;
 SELECT RAISE(ROLLBACK, 'EntryDetail: canon_name_id may not be specified on INSERT')
 WHERE NEW.canon_name_id IS NOT NULL;
 SELECT RAISE(ROLLBACK, 'EntryDetail: cannot set multi-value columns')
 WHERE NEW.aliases IS NOT NULL OR
  NEW.enctype_nums IS NOT NULL OR
  NEW.enctype_names IS NOT NULL OR
  NEW.ok_to_delegatees IS NOT NULL OR
  NEW.pkinit_names IS NOT NULL OR
  NEW.pkinit_cert_digests IS NOT NULL OR
  NEW.pkinit_certs IS NOT NULL;
 -- Validate that the app is following our transaction rules
 SELECT RAISE(ROLLBACK, 'EntryDetail: previous transaction is incomplete')
 WHERE EXISTS (SELECT tx.tx FROM TX tx);
 INSERT INTO Entry (id, canon_name_id, data, created_by,
  modified_at, modified_by, valid_start, valid_end,
  pw_end, last_pw_change, max_life, max_renew, flags, created_at)
 SELECT (SELECT lei.last_id + 1 FROM LastEntryID lei),
  (SELECT lni.last_id + 1 FROM LastEntryNameID lni),
  NEW.data, NEW.created_by, NEW.modified_at,
  NEW.modified_by, NEW.valid_start, NEW.valid_end, NEW.pw_end,
  NEW.last_pw_change, NEW.max_life, NEW.max_renew, NEW.flags,
  coalesce(NEW.created_at,
   (SELECT mtime FROM TX ORDER BY tx DESC LIMIT 1));
 INSERT INTO EntryName (name, id, entry)
 SELECT NEW.canon_name,
  (SELECT lni.last_id + 1 FROM LastEntryNameID lni),
  (SELECT lei.last_id FROM LastEntryID lei);
 -- Log/audit
 INSERT INTO TX (entry_id)
 SELECT (SELECT lei.last_id FROM LastEntryID lei)
 WHERE NOT EXISTS (SELECT tx.tx FROM TX tx);
 INSERT INTO EntryLog (tx, mtime, is_new, is_insert,
  canon_name_id, canon_name, id, data, created_at, created_by,
  modified_at, modified_by, valid_start, valid_end, pw_end,
  last_pw_change, max_life, max_renew, flags, flags_str, aliases,
  enctype_nums, enctype_names, keys, ok_to_delegatees,
  pkinit_names, pkinit_cert_digests, pkinit_certs)
 SELECT (SELECT tx.tx FROM TX tx ORDER BY tx.tx DESC LIMIT 1),
  (SELECT tx.mtime FROM TX tx ORDER BY tx.tx DESC LIMIT 1),
  1, 1, ed.*
 FROM EntryDetail ed
 WHERE ed.id = (SELECT lei.last_id FROM LastEntryID lei);
 DELETE FROM TX;
END;
-- INSTEAD OF trigger to update a principal
DROP TRIGGER IF EXISTS EntryDetail_update;
CREATE TRIGGER EntryDetail_update
INSTEAD OF UPDATE ON EntryDetail
FOR EACH ROW BEGIN
 -- Validate NEW values
 SELECT RAISE(ROLLBACK, 'EntryDetail: modified_by must not be NULL')
 WHERE NEW.modified_by IS NULL;
 SELECT RAISE(ROLLBACK, 'EntryDetail: cannot change the id of an Entry row')
 WHERE NEW.id IS NOT OLD.id;
 SELECT RAISE(ROLLBACK, 'EntryDetail: cannot set multi-value columns')
 WHERE
  (NEW.aliases IS NOT OLD.aliases AND
   NEW.aliases IS NOT NULL) OR
  (NEW.enctype_nums IS NOT OLD.enctype_nums AND
   NEW.enctype_nums IS NOT NULL) OR
  (NEW.enctype_names IS NOT OLD.enctype_names AND
   NEW.enctype_names IS NOT NULL) OR
  (NEW.ok_to_delegatees IS NOT OLD.ok_to_delegatees AND
   NEW.ok_to_delegatees IS NOT NULL) OR
  (NEW.pkinit_names IS NOT OLD.pkinit_names AND
   NEW.pkinit_names IS NOT NULL) OR
  (NEW.pkinit_cert_digests IS NOT OLD.pkinit_cert_digests AND
   NEW.pkinit_cert_digests IS NOT 0) OR
  (NEW.pkinit_certs IS NOT OLD.pkinit_certs AND
   NEW.pkinit_certs IS NOT 0);
 -- Validate that the app is following our transaction rules
 SELECT RAISE(ROLLBACK, 'EntryDetail: previous transaction is incomplete')
 FROM TX tx
 WHERE tx.entry_id != NEW.id;
 -- Log/audit old entry
 INSERT INTO TX (entry_id)
 SELECT OLD.id
 WHERE NOT EXISTS (SELECT tx.tx FROM TX tx);
 DELETE FROM EntryLog
 WHERE tx = (SELECT tx.tx FROM TX tx ORDER BY tx.tx DESC) AND
  id = OLD.id AND is_new = 1;
 -- Update all scalar fields
 UPDATE Entry SET
  canon_name_id = NEW.canon_name_id,
  data = NULL,
  created_at = NEW.created_at,
  created_by = NEW.created_by,
  modified_at = NEW.modified_at,
  modified_by = NEW.modified_by,
  valid_start = NEW.valid_start,
  valid_end = NEW.valid_end,
  pw_end = NEW.pw_end,
  last_pw_change = NEW.last_pw_change,
  max_life = NEW.max_life,
  max_renew = NEW.max_renew,
  flags = NEW.flags
 WHERE id = OLD.id;
 -- Change the EntryName for this Entry's canonical name if
 -- necessary.
 UPDATE EntryName SET
  name = NEW.canon_name
 WHERE name = OLD.canon_name AND
  (NEW.canon_name_id IS OLD.canon_name_id OR
   NOT EXISTS (SELECT n.id FROM EntryName n WHERE n.name = NEW.canon_name));
 -- Log/audit new entry
 INSERT INTO EntryLog (tx, mtime, is_new, is_update, canon_name_id,
  canon_name, id, data, created_at, created_by, modified_at,
  modified_by, valid_start, valid_end, pw_end, last_pw_change,
  max_life, max_renew, flags, flags_str, aliases, enctype_nums,
  enctype_names, keys, ok_to_delegatees, pkinit_names,
  pkinit_cert_digests, pkinit_certs)
 SELECT (SELECT tx.tx FROM TX tx ORDER BY tx.tx DESC LIMIT 1),
  (SELECT tx.mtime FROM TX tx ORDER BY tx.tx DESC LIMIT 1),
  1, 1, ed.*
 FROM EntryDetail ed
 WHERE ed.id = OLD.id;
 DELETE FROM TX;
END;
-- INSTEAD OF trigger to delete a principal
DROP TRIGGER IF EXISTS EntryDetail_delete;
CREATE TRIGGER EntryDetail_delete
INSTEAD OF DELETE ON EntryDetail
FOR EACH ROW BEGIN
 -- Validate that the app is following our transaction rules
 SELECT RAISE(ROLLBACK, 'EntryDetail: previous transaction is incomplete')
 FROM TX tx
 WHERE tx.entry_id != NEW.id;
 -- Log/audit
 INSERT INTO TX (entry_id)
 SELECT (SELECT lei.last_id FROM LastEntryID lei)
 WHERE NOT EXISTS (SELECT tx.tx FROM TX tx);
 INSERT INTO EntryLog (tx, mtime, is_new, is_delete,
  canon_name_id, canon_name, id, data, created_at, created_by,
  modified_at, modified_by, valid_start, valid_end, pw_end,
  last_pw_change, max_life, max_renew, flags, flags_str, aliases,
  enctype_nums, enctype_names, keys, ok_to_delegatees,
  pkinit_names, pkinit_cert_digests, pkinit_certs)
 SELECT (SELECT tx.tx FROM TX tx ORDER BY tx.tx DESC LIMIT 1),
  (SELECT tx.mtime FROM TX tx ORDER BY tx.tx DESC LIMIT 1),
  0, 1, ed.*
 FROM EntryDetail ed
 WHERE ed.id = OLD.id;
 DELETE FROM TX;
 -- Do the deletion
 DELETE FROM Entry WHERE id = OLD.id;
END;
--
-- Delete old log entries
DROP TRIGGER IF EXISTS EntryLog_prune;
CREATE TRIGGER EntryLog_prune
AFTER INSERT ON EntryLog
FOR EACH ROW BEGIN
 DELETE FROM EntryLog
 WHERE mtime < strftime('%s', 'now', '-' || (
   SELECT lc.val
   FROM LogConfig lc
   WHERE lc.opt = 'iprop_retain_time')) AND
  tx < ((SELECT t.tx FROM TX t ORDER by t.tx DESC LIMIT 1) - (
    SELECT val FROM LogConfig WHERE opt = 'iprop_retain_count'));
END;
--
-- Triggers for Entry* tables to ensure that we log properly
--
-- All the remaining triggers follow much the same pattern.
--
DROP TRIGGER IF EXISTS EntryName_log_insert;
CREATE TRIGGER EntryName_log_insert
BEFORE INSERT ON EntryName
FOR EACH ROW BEGIN
 -- Validate that the app is following our transaction rules
 SELECT RAISE(ROLLBACK, 'EntryName: previous transaction is incomplete')
 FROM TX tx
 WHERE tx.entry_id != NEW.entry;
 INSERT INTO TX (entry_id)
 SELECT NEW.entry
 WHERE NOT EXISTS (SELECT tx.tx FROM TX tx);
END;
DROP TRIGGER IF EXISTS EntryName_log_update;
CREATE TRIGGER EntryName_log_update
BEFORE UPDATE ON EntryName
FOR EACH ROW BEGIN
 -- Validate that the app is following our transaction rules
 SELECT RAISE(ROLLBACK, 'EntryName: previous transaction is incomplete')
 FROM TX tx
 WHERE tx.entry_id != NEW.entry;
 -- Validate that the EntryName id isn't changing
 SELECT RAISE(ROLLBACK, 'EntryName: cannot change an EntryName''s id')
 WHERE NEW.id IS NOT OLD.id;
 -- Validate that we're not taking one principal's canonical
 -- name and giving it to another
 SELECT RAISE(ROLLBACK, 'EntryName: cannot assign one principal''s canonical name to another')
 WHERE NEW.entry != OLD.entry AND
  EXISTS (SELECT e.id FROM Entry e WHERE e.canon_name_id = NEW.id);
 INSERT INTO TX (entry_id)
 SELECT NEW.entry
 WHERE NOT EXISTS (SELECT tx.tx FROM TX tx WHERE tx.entry_id = NEW.entry);
 -- If an alias is being switched from one principal to another,
 -- then log the change to the old one as well.
 INSERT INTO EntryLog (tx, mtime, is_new, is_insert, canon_name_id,
  canon_name, id, data, created_at, created_by, modified_at,
  modified_by, valid_start, valid_end, pw_end, last_pw_change,
  max_life, max_renew, flags, flags_str, aliases, enctype_nums,
  enctype_names, keys, ok_to_delegatees, pkinit_names,
  pkinit_cert_digests, pkinit_certs)
 SELECT (SELECT tx.tx FROM TX tx ORDER BY tx.tx DESC LIMIT 1),
  (SELECT tx.mtime FROM TX tx ORDER BY tx.tx DESC LIMIT 1),
  0, 1, ed.*
 FROM EntryDetail ed
 WHERE ed.id = OLD.entry AND OLD.entry IS NOT NEW.entry;
END;
DROP TRIGGER IF EXISTS EntryName_log_delete;
CREATE TRIGGER EntryName_log_delete
BEFORE DELETE ON EntryName
FOR EACH ROW BEGIN
 -- Validate that the app is following our transaction rules
 SELECT RAISE(ROLLBACK, 'EntryName: previous transaction is incomplete')
 FROM TX tx
 WHERE tx.entry_id != OLD.entry;
 INSERT INTO TX (entry_id)
 SELECT OLD.entry
 WHERE NOT EXISTS (SELECT tx.tx FROM TX tx);
END;
DROP TRIGGER IF EXISTS EntryEnctypes_log_insert;
CREATE TRIGGER EntryEnctypes_log_insert
BEFORE INSERT ON EntryEnctypes
FOR EACH ROW BEGIN
 -- Validate that the app is following our transaction rules
 SELECT RAISE(ROLLBACK, 'EntryEnctypes: previous transaction is incomplete')
 FROM TX tx
 WHERE tx.entry_id != NEW.entry;
 INSERT INTO TX (entry_id)
 SELECT NEW.entry
 WHERE NOT EXISTS (SELECT tx.tx FROM TX tx);
END;
DROP TRIGGER IF EXISTS EntryEnctypes_log_update;
CREATE TRIGGER EntryEnctypes_log_update
BEFORE UPDATE ON EntryEnctypes
FOR EACH ROW BEGIN
 -- Validate that the app is following our transaction rules
 SELECT RAISE(ROLLBACK, 'EntryEnctypes: previous transaction is incomplete')
 FROM TX tx
 WHERE tx.entry_id != NEW.entry;
 -- Validate that the EntryEnctypes id isn't changing
 SELECT RAISE(ROLLBACK, 'EntryEnctypes: cannot change an EntryEnctypes''s id')
 WHERE NEW.id IS NOT OLD.id;
 -- Validate that we're not taking one principal's canonical
 -- name and giving it to another
 SELECT RAISE(ROLLBACK, 'EntryEnctypes: cannot assign one principal''s canonical name to another')
 WHERE NEW.entry != OLD.entry AND
  EXISTS (SELECT e.id FROM Entry e WHERE e.canon_name_id = NEW.id);
 INSERT INTO TX (entry_id)
 SELECT NEW.entry
 WHERE NOT EXISTS (SELECT tx.tx FROM TX tx WHERE tx.entry_id = NEW.entry);
 -- If an alias is being switched from one principal to another,
 -- then log the change to the old one as well.
 INSERT INTO EntryLog (tx, mtime, is_new, is_insert, canon_name_id,
  canon_name, id, data, created_at, created_by, modified_at,
  modified_by, valid_start, valid_end, pw_end, last_pw_change,
  max_life, max_renew, flags, flags_str, aliases, enctype_nums,
  enctype_names, keys, ok_to_delegatees, pkinit_names,
  pkinit_cert_digests, pkinit_certs)
 SELECT (SELECT tx.tx FROM TX tx ORDER BY tx.tx DESC LIMIT 1),
  (SELECT tx.mtime FROM TX tx ORDER BY tx.tx DESC LIMIT 1),
  0, 1, ed.*
 FROM EntryDetail ed
 WHERE ed.id = OLD.entry AND OLD.entry IS NOT NEW.entry;
END;
DROP TRIGGER IF EXISTS EntryEnctypes_log_delete;
CREATE TRIGGER EntryEnctypes_log_delete
BEFORE DELETE ON EntryEnctypes
FOR EACH ROW BEGIN
 -- Validate that the app is following our transaction rules
 SELECT RAISE(ROLLBACK, 'EntryEnctypes: previous transaction is incomplete')
 FROM TX tx
 WHERE tx.entry_id != OLD.entry;
 INSERT INTO TX (entry_id)
 SELECT OLD.entry
 WHERE NOT EXISTS (SELECT tx.tx FROM TX tx);
END;
DROP TRIGGER IF EXISTS EntryKeys_log_insert;
CREATE TRIGGER EntryKeys_log_insert
BEFORE INSERT ON EntryKeys
FOR EACH ROW BEGIN
 -- Validate that the app is following our transaction rules
 SELECT RAISE(ROLLBACK, 'EntryKeys: previous transaction is incomplete')
 FROM TX tx
 WHERE tx.entry_id != NEW.entry;
 INSERT INTO TX (entry_id)
 SELECT NEW.entry
 WHERE NOT EXISTS (SELECT tx.tx FROM TX tx);
END;
DROP TRIGGER IF EXISTS EntryKeys_log_update;
CREATE TRIGGER EntryKeys_log_update
BEFORE UPDATE ON EntryKeys
FOR EACH ROW BEGIN
 -- Validate that the app is following our transaction rules
 SELECT RAISE(ROLLBACK, 'EntryKeys: previous transaction is incomplete')
 FROM TX tx
 WHERE tx.entry_id != NEW.entry;
 -- Validate that the EntryKeys id isn't changing
 SELECT RAISE(ROLLBACK, 'EntryKeys: cannot change an EntryKeys''s id')
 WHERE NEW.id IS NOT OLD.id;
 -- Validate that we're not taking one principal's canonical
 -- name and giving it to another
 SELECT RAISE(ROLLBACK, 'EntryKeys: cannot assign one principal''s canonical name to another')
 WHERE NEW.entry != OLD.entry AND
  EXISTS (SELECT e.id FROM Entry e WHERE e.canon_name_id = NEW.id);
 INSERT INTO TX (entry_id)
 SELECT NEW.entry
 WHERE NOT EXISTS (SELECT tx.tx FROM TX tx WHERE tx.entry_id = NEW.entry);
 -- If an alias is being switched from one principal to another,
 -- then log the change to the old one as well.
 INSERT INTO EntryLog (tx, mtime, is_new, is_insert, canon_name_id,
  canon_name, id, data, created_at, created_by, modified_at,
  modified_by, valid_start, valid_end, pw_end, last_pw_change,
  max_life, max_renew, flags, flags_str, aliases, enctype_nums,
  enctype_names, keys, ok_to_delegatees, pkinit_names,
  pkinit_cert_digests, pkinit_certs)
 SELECT (SELECT tx.tx FROM TX tx ORDER BY tx.tx DESC LIMIT 1),
  (SELECT tx.mtime FROM TX tx ORDER BY tx.tx DESC LIMIT 1),
  0, 1, ed.*
 FROM EntryDetail ed
 WHERE ed.id = OLD.entry AND OLD.entry IS NOT NEW.entry;
END;
DROP TRIGGER IF EXISTS EntryKeys_log_delete;
CREATE TRIGGER EntryKeys_log_delete
BEFORE DELETE ON EntryKeys
FOR EACH ROW BEGIN
 -- Validate that the app is following our transaction rules
 SELECT RAISE(ROLLBACK, 'EntryKeys: previous transaction is incomplete')
 FROM TX tx
 WHERE tx.entry_id != OLD.entry;
 INSERT INTO TX (entry_id)
 SELECT OLD.entry
 WHERE NOT EXISTS (SELECT tx.tx FROM TX tx);
END;
DROP TRIGGER IF EXISTS EntryOKToDelegate_log_insert;
CREATE TRIGGER EntryOKToDelegate_log_insert
BEFORE INSERT ON EntryOKToDelegate
FOR EACH ROW BEGIN
 -- Validate that the app is following our transaction rules
 SELECT RAISE(ROLLBACK, 'EntryOKToDelegate: previous transaction is incomplete')
 FROM TX tx
 WHERE tx.entry_id != NEW.entry;
 INSERT INTO TX (entry_id)
 SELECT NEW.entry
 WHERE NOT EXISTS (SELECT tx.tx FROM TX tx);
END;
DROP TRIGGER IF EXISTS EntryOKToDelegate_log_update;
CREATE TRIGGER EntryOKToDelegate_log_update
BEFORE UPDATE ON EntryOKToDelegate
FOR EACH ROW BEGIN
 -- Validate that the app is following our transaction rules
 SELECT RAISE(ROLLBACK, 'EntryOKToDelegate: previous transaction is incomplete')
 FROM TX tx
 WHERE tx.entry_id != NEW.entry;
 -- Validate that the EntryOKToDelegate id isn't changing
 SELECT RAISE(ROLLBACK, 'EntryOKToDelegate: cannot change an EntryOKToDelegate''s id')
 WHERE NEW.id IS NOT OLD.id;
 -- Validate that we're not taking one principal's canonical
 -- name and giving it to another
 SELECT RAISE(ROLLBACK, 'EntryOKToDelegate: cannot assign one principal''s canonical name to another')
 WHERE NEW.entry != OLD.entry AND
  EXISTS (SELECT e.id FROM Entry e WHERE e.canon_name_id = NEW.id);
 INSERT INTO TX (entry_id)
 SELECT NEW.entry
 WHERE NOT EXISTS (SELECT tx.tx FROM TX tx WHERE tx.entry_id = NEW.entry);
 -- If an alias is being switched from one principal to another,
 -- then log the change to the old one as well.
 INSERT INTO EntryLog (tx, mtime, is_new, is_insert, canon_name_id,
  canon_name, id, data, created_at, created_by, modified_at,
  modified_by, valid_start, valid_end, pw_end, last_pw_change,
  max_life, max_renew, flags, flags_str, aliases, enctype_nums,
  enctype_names, keys, ok_to_delegatees, pkinit_names,
  pkinit_cert_digests, pkinit_certs)
 SELECT (SELECT tx.tx FROM TX tx ORDER BY tx.tx DESC LIMIT 1),
  (SELECT tx.mtime FROM TX tx ORDER BY tx.tx DESC LIMIT 1),
  0, 1, ed.*
 FROM EntryDetail ed
 WHERE ed.id = OLD.entry AND OLD.entry IS NOT NEW.entry;
END;
DROP TRIGGER IF EXISTS EntryOKToDelegate_log_delete;
CREATE TRIGGER EntryOKToDelegate_log_delete
BEFORE DELETE ON EntryOKToDelegate
FOR EACH ROW BEGIN
 -- Validate that the app is following our transaction rules
 SELECT RAISE(ROLLBACK, 'EntryOKToDelegate: previous transaction is incomplete')
 FROM TX tx
 WHERE tx.entry_id != OLD.entry;
 INSERT INTO TX (entry_id)
 SELECT OLD.entry
 WHERE NOT EXISTS (SELECT tx.tx FROM TX tx);
END;
DROP TRIGGER IF EXISTS EntryPKINITCertName_log_insert;
CREATE TRIGGER EntryPKINITCertName_log_insert
BEFORE INSERT ON EntryPKINITCertName
FOR EACH ROW BEGIN
 -- Validate that the app is following our transaction rules
 SELECT RAISE(ROLLBACK, 'EntryPKINITCertName: previous transaction is incomplete')
 FROM TX tx
 WHERE tx.entry_id != NEW.entry;
 INSERT INTO TX (entry_id)
 SELECT NEW.entry
 WHERE NOT EXISTS (SELECT tx.tx FROM TX tx);
END;
DROP TRIGGER IF EXISTS EntryPKINITCertName_log_update;
CREATE TRIGGER EntryPKINITCertName_log_update
BEFORE UPDATE ON EntryPKINITCertName
FOR EACH ROW BEGIN
 -- Validate that the app is following our transaction rules
 SELECT RAISE(ROLLBACK, 'EntryPKINITCertName: previous transaction is incomplete')
 FROM TX tx
 WHERE tx.entry_id != NEW.entry;
 -- Validate that the EntryPKINITCertName id isn't changing
 SELECT RAISE(ROLLBACK, 'EntryPKINITCertName: cannot change an EntryPKINITCertName''s id')
 WHERE NEW.id IS NOT OLD.id;
 -- Validate that we're not taking one principal's canonical
 -- name and giving it to another
 SELECT RAISE(ROLLBACK, 'EntryPKINITCertName: cannot assign one principal''s canonical name to another')
 WHERE NEW.entry != OLD.entry AND
  EXISTS (SELECT e.id FROM Entry e WHERE e.canon_name_id = NEW.id);
 INSERT INTO TX (entry_id)
 SELECT NEW.entry
 WHERE NOT EXISTS (SELECT tx.tx FROM TX tx WHERE tx.entry_id = NEW.entry);
 -- If an alias is being switched from one principal to another,
 -- then log the change to the old one as well.
 INSERT INTO EntryLog (tx, mtime, is_new, is_insert, canon_name_id,
  canon_name, id, data, created_at, created_by, modified_at,
  modified_by, valid_start, valid_end, pw_end, last_pw_change,
  max_life, max_renew, flags, flags_str, aliases, enctype_nums,
  enctype_names, keys, ok_to_delegatees, pkinit_names,
  pkinit_cert_digests, pkinit_certs)
 SELECT (SELECT tx.tx FROM TX tx ORDER BY tx.tx DESC LIMIT 1),
  (SELECT tx.mtime FROM TX tx ORDER BY tx.tx DESC LIMIT 1),
  0, 1, ed.*
 FROM EntryDetail ed
 WHERE ed.id = OLD.entry AND OLD.entry IS NOT NEW.entry;
END;
DROP TRIGGER IF EXISTS EntryPKINITCertName_log_delete;
CREATE TRIGGER EntryPKINITCertName_log_delete
BEFORE DELETE ON EntryPKINITCertName
FOR EACH ROW BEGIN
 -- Validate that the app is following our transaction rules
 SELECT RAISE(ROLLBACK, 'EntryPKINITCertName: previous transaction is incomplete')
 FROM TX tx
 WHERE tx.entry_id != OLD.entry;
 INSERT INTO TX (entry_id)
 SELECT OLD.entry
 WHERE NOT EXISTS (SELECT tx.tx FROM TX tx);
END;
DROP TRIGGER IF EXISTS EntryPKINITCertHash_log_insert;
CREATE TRIGGER EntryPKINITCertHash_log_insert
BEFORE INSERT ON EntryPKINITCertHash
FOR EACH ROW BEGIN
 -- Validate that the app is following our transaction rules
 SELECT RAISE(ROLLBACK, 'EntryPKINITCertHash: previous transaction is incomplete')
 FROM TX tx
 WHERE tx.entry_id != NEW.entry;
 INSERT INTO TX (entry_id)
 SELECT NEW.entry
 WHERE NOT EXISTS (SELECT tx.tx FROM TX tx);
END;
DROP TRIGGER IF EXISTS EntryPKINITCertHash_log_update;
CREATE TRIGGER EntryPKINITCertHash_log_update
BEFORE UPDATE ON EntryPKINITCertHash
FOR EACH ROW BEGIN
 -- Validate that the app is following our transaction rules
 SELECT RAISE(ROLLBACK, 'EntryPKINITCertHash: previous transaction is incomplete')
 FROM TX tx
 WHERE tx.entry_id != NEW.entry;
 -- Validate that the EntryPKINITCertHash id isn't changing
 SELECT RAISE(ROLLBACK, 'EntryPKINITCertHash: cannot change an EntryPKINITCertHash''s id')
 WHERE NEW.id IS NOT OLD.id;
 -- Validate that we're not taking one principal's canonical
 -- name and giving it to another
 SELECT RAISE(ROLLBACK, 'EntryPKINITCertHash: cannot assign one principal''s canonical name to another')
 WHERE NEW.entry != OLD.entry AND
  EXISTS (SELECT e.id FROM Entry e WHERE e.canon_name_id = NEW.id);
 INSERT INTO TX (entry_id)
 SELECT NEW.entry
 WHERE NOT EXISTS (SELECT tx.tx FROM TX tx WHERE tx.entry_id = NEW.entry);
 -- If an alias is being switched from one principal to another,
 -- then log the change to the old one as well.
 INSERT INTO EntryLog (tx, mtime, is_new, is_insert, canon_name_id,
  canon_name, id, data, created_at, created_by, modified_at,
  modified_by, valid_start, valid_end, pw_end, last_pw_change,
  max_life, max_renew, flags, flags_str, aliases, enctype_nums,
  enctype_names, keys, ok_to_delegatees, pkinit_names,
  pkinit_cert_digests, pkinit_certs)
 SELECT (SELECT tx.tx FROM TX tx ORDER BY tx.tx DESC LIMIT 1),
  (SELECT tx.mtime FROM TX tx ORDER BY tx.tx DESC LIMIT 1),
  0, 1, ed.*
 FROM EntryDetail ed
 WHERE ed.id = OLD.entry AND OLD.entry IS NOT NEW.entry;
END;
DROP TRIGGER IF EXISTS EntryPKINITCertHash_log_delete;
CREATE TRIGGER EntryPKINITCertHash_log_delete
BEFORE DELETE ON EntryPKINITCertHash
FOR EACH ROW BEGIN
 -- Validate that the app is following our transaction rules
 SELECT RAISE(ROLLBACK, 'EntryPKINITCertHash: previous transaction is incomplete')
 FROM TX tx
 WHERE tx.entry_id != OLD.entry;
 INSERT INTO TX (entry_id)
 SELECT OLD.entry
 WHERE NOT EXISTS (SELECT tx.tx FROM TX tx);
END;
DROP TRIGGER IF EXISTS EntryPKINITCert_log_insert;
CREATE TRIGGER EntryPKINITCert_log_insert
BEFORE INSERT ON EntryPKINITCert
FOR EACH ROW BEGIN
 -- Validate that the app is following our transaction rules
 SELECT RAISE(ROLLBACK, 'EntryPKINITCert: previous transaction is incomplete')
 FROM TX tx
 WHERE tx.entry_id != NEW.entry;
 INSERT INTO TX (entry_id)
 SELECT NEW.entry
 WHERE NOT EXISTS (SELECT tx.tx FROM TX tx);
END;
DROP TRIGGER IF EXISTS EntryPKINITCert_log_update;
CREATE TRIGGER EntryPKINITCert_log_update
BEFORE UPDATE ON EntryPKINITCert
FOR EACH ROW BEGIN
 -- Validate that the app is following our transaction rules
 SELECT RAISE(ROLLBACK, 'EntryPKINITCert: previous transaction is incomplete')
 FROM TX tx
 WHERE tx.entry_id != NEW.entry;
 -- Validate that the EntryPKINITCert id isn't changing
 SELECT RAISE(ROLLBACK, 'EntryPKINITCert: cannot change an EntryPKINITCert''s id')
 WHERE NEW.id IS NOT OLD.id;
 -- Validate that we're not taking one principal's canonical
 -- name and giving it to another
 SELECT RAISE(ROLLBACK, 'EntryPKINITCert: cannot assign one principal''s canonical name to another')
 WHERE NEW.entry != OLD.entry AND
  EXISTS (SELECT e.id FROM Entry e WHERE e.canon_name_id = NEW.id);
 INSERT INTO TX (entry_id)
 SELECT NEW.entry
 WHERE NOT EXISTS (SELECT tx.tx FROM TX tx WHERE tx.entry_id = NEW.entry);
 -- If an alias is being switched from one principal to another,
 -- then log the change to the old one as well.
 INSERT INTO EntryLog (tx, mtime, is_new, is_insert, canon_name_id,
  canon_name, id, data, created_at, created_by, modified_at,
  modified_by, valid_start, valid_end, pw_end, last_pw_change,
  max_life, max_renew, flags, flags_str, aliases, enctype_nums,
  enctype_names, keys, ok_to_delegatees, pkinit_names,
  pkinit_cert_digests, pkinit_certs)
 SELECT (SELECT tx.tx FROM TX tx ORDER BY tx.tx DESC LIMIT 1),
  (SELECT tx.mtime FROM TX tx ORDER BY tx.tx DESC LIMIT 1),
  0, 1, ed.*
 FROM EntryDetail ed
 WHERE ed.id = OLD.entry AND OLD.entry IS NOT NEW.entry;
END;
DROP TRIGGER IF EXISTS EntryPKINITCert_log_delete;
CREATE TRIGGER EntryPKINITCert_log_delete
BEFORE DELETE ON EntryPKINITCert
FOR EACH ROW BEGIN
 -- Validate that the app is following our transaction rules
 SELECT RAISE(ROLLBACK, 'EntryPKINITCert: previous transaction is incomplete')
 FROM TX tx
 WHERE tx.entry_id != OLD.entry;
 INSERT INTO TX (entry_id)
 SELECT OLD.entry
 WHERE NOT EXISTS (SELECT tx.tx FROM TX tx);
END;
COMMIT;
