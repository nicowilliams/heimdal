--
-- This file contains SQL statements.  All comments are stripped, except
-- for comment likes that start with "-- @", which are turned into
-- "#define <rest-of-line> \".  One or more empty lines is needed
-- after each statement, even the last one.
--
-- This makes it easy to edit the SQL statements needed by the
-- HDB-SQLite backend.
--
-- @HDBSQLITE_GET_VERSION
SELECT max(number) FROM Version;


-- Most of the KDC queries can be satisfied a fast query - fast in that
-- no joins (nor views with joins) are needed.  But we need to support
-- old keys too, for which we need a join, so we use a UNION ALL ...
-- LIMIT 1 to unify a fast and fast-but-slower queries.
--
-- @HDBSQLITE_FETCH_FAST
SELECT
    e.id AS pid,
    e.canon_name_id AS canon_name_id,
    e.canon_name AS pname,
    e.cur_kvno AS kvno,
    e.cur_keys AS keys,
    e.gentime AS gentime,
    e.genusec AS genusec,
    e.gengen AS gengen,
    e.created_at AS crbytime,
    e.created_by AS crbypname,
    e.modified_at AS modbytime,
    e.modified_by AS modbypname,
    e.valid_start AS validstart,
    e.valid_end AS validend,
    e.pw_end AS pwend,
    e.max_life AS maxlife,
    e.max_renew AS maxrenew,
    e.flags AS flags,
    e.etypes AS etypes,
    e.pw_mkvno AS pw_mkvno,
    e.pw AS pwpw,
    e.last_pw_change AS lastpwchange
    NULL AS aliases,
    NULL AS pkacls,
    NULL AS pkcerthashes,
    NULL AS pkcerts,
    NULL AS delegto,
    NULL AS lmowf,
    NULL AS oldkeys
FROM Entry e
-- Recent versions of SQLite3 can optimize this as a multi-index union
WHERE (e.id = @princid OR e.canon_name = @pname) AND
      (e.kvno IS @kvno OR @kvno = 0)
UNION ALL
SELECT
    e.id,
    e.canon_name_id,
    e.canon_name,
    (SELECT group_concat(ek.kvno || ':' || ek.etype || ':' || ek.mkvno
			 || ':' || quote(ek.salt) || ':' || quote(ek.s2kparams)
			 || ':' || quote(ek.encrypted_pw) || ':' ||
			 quote(ek.encrypted_key), ';')
     FROM EntryKeys ek
     WHERE ek.entry = e.id AND ek.kvno = @kvno),
    e.gentime,
    e.genusec,
    e.gengen,
    e.created_at,
    e.created_by,
    e.modified_at,
    e.modified_by,
    e.valid_start,
    e.valid_end,
    e.pw_end,
    e.max_life,
    e.max_renew,
    e.flags,
    e.etypes,
    e.pw_mkvno,
    e.pw,
    e.last_pw_change AS last_pw_change
    e.aliases,
    e.pkinit_names,
    e.pkinit_cert_digests,
    e.pkinit_certs,
    e.ok_to_delegatees,
    NULL,
    e.keys
FROM EntryDetail e
WHERE (e.id = @princid OR e.canon_name = @pname)
LIMIT 1;


-- This is slow because EntryDetail is a VIEW that involves a number of
-- joins.  But it gets everything, and that's what matters when PKINIT
-- is used, or when we're in an admin path.
--
-- @HDBSQLITE_FETCH_SLOW
SELECT
    e.id AS pid,
    e.canon_name_id AS canon_name_id,
    e.canon_name AS pname,
    e.cur_kvno AS kvno,
    e.keys AS keys,
    e.gentime AS gentime,
    e.genusec AS genusec,
    e.gengen AS gengen,
    e.created_at AS crbytime,
    e.created_by AS crbypname,
    e.modified_at AS modbytime,
    e.modified_by AS modbypname,
    e.valid_start AS validstart,
    e.valid_end AS validend,
    e.pw_end AS pwend,
    e.max_life AS maxlife,
    e.max_renew AS maxrenew,
    e.flags AS flags,
    e.etypes AS etypes,
    e.pw_mkvno AS pw_mkvno,
    e.pw AS pwpw,
    e.last_pw_change AS last_pw_change
    e.aliases AS aliases,
    e.pkinit_names AS pkacls,
    e.pkinit_cert_digests AS pkcerthashes,
    e.pkinit_certs AS pkcerts,
    e.ok_to_delegatees AS delegto,
    NULL AS lmowf,
    e.keys AS keys
FROM EntryDetail e
WHERE (e.id = @princid OR e.canon_name = @pname) AND
      (e.kvno IS @kvno OR @kvno = 0)
UNION ALL
SELECT
    e.id,
    e.canon_name_id,
    e.canon_name,
    (SELECT group_concat(ek.kvno || ':' || ek.etype || ':' || ek.mkvno
			 || ':' || quote(ek.salt) || ':' || quote(ek.s2kparams)
			 || ':' || quote(ek.encrypted_pw) || ':' ||
			 quote(ek.encrypted_key), ';')
     FROM EntryKeys ek
     WHERE ek.entry = e.id AND ek.kvno = @kvno),
    e.gentime,
    e.genusec,
    e.gengen,
    e.created_at,
    e.created_by,
    e.modified_at,
    e.modified_by,
    e.valid_start,
    e.valid_end,
    e.pw_end,
    e.max_life,
    e.max_renew,
    e.flags,
    e.etypes,
    e.pw_mkvno,
    e.pw,
    e.last_pw_change AS last_pw_change
    e.aliases,
    e.pkinit_names,
    e.pkinit_cert_digests,
    e.pkinit_certs,
    e.ok_to_delegatees,
    NULL,
    e.keys
FROM EntryDetail e
WHERE (e.id = @princid OR e.canon_name = @pname)
LIMIT 1;


