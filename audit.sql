-- ROUA/0.1 audit (generated from packages/core; do not edit by hand)
-- Usage: psql "$ADMIN_DATABASE_URL" -v role=readonly -f audit.sql
-- Read-only: SELECT statements only. Run in psql as a superuser, connected to the
-- database you want to check. For a scored report, use: roua audit --role <role>
-- MAINTAIN (PostgreSQL 17+) is not included below; the CLI adds it automatically.

-- Role attributes and expiry: rolsuper, rolcreaterole, rolcreatedb, rolreplication and
-- rolbypassrls should all be false; valid_until should be set.
SELECT r.oid::text AS oid, r.rolname, r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls,
          r.rolcanlogin, r.rolinherit, r.rolconnlimit, r.rolvaliduntil::text AS valid_until,
          (r.rolvaliduntil IS NULL OR r.rolvaliduntil = 'infinity') AS no_expiry,
          (r.rolvaliduntil < now()) AS expired,
          extract(epoch FROM (r.rolvaliduntil - now())) / 86400 AS days_left,
          shobj_description(r.oid, 'pg_authid') AS comment
   FROM pg_roles r WHERE r.rolname = :'role';

-- R4: No dangerous predefined roles
SELECT b.rolname FROM pg_roles b, pg_roles t
WHERE t.rolname = :'role'
  AND b.rolname IN ('pg_write_all_data', 'pg_read_all_data', 'pg_write_server_files', 'pg_read_server_files', 'pg_execute_server_program', 'pg_signal_backend', 'pg_create_subscription', 'pg_checkpoint', 'pg_maintain', 'pg_signal_autovacuum_worker', 'pg_monitor', 'pg_read_all_settings', 'pg_read_all_stats', 'pg_stat_scan_tables', 'pg_use_reserved_connections')
  AND pg_has_role(t.oid, b.oid, 'MEMBER')
ORDER BY 1;

-- R5: Reachable roles are not privileged
WITH target AS (SELECT oid, rolname FROM pg_roles WHERE rolname = :'role'),
effective AS (
  SELECT r.oid, r.rolname FROM pg_roles r, target t
  WHERE pg_has_role(t.oid, r.oid, 'MEMBER') AND left(r.rolname, 3) <> 'pg_'
)
SELECT e.rolname, r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls,
       pg_has_role((SELECT oid FROM target), e.oid, 'USAGE') AS inherited
FROM effective e JOIN pg_roles r ON r.oid = e.oid
WHERE e.oid <> (SELECT oid FROM target) ORDER BY 1;

-- T1: No write privileges on tables or views
WITH target AS (SELECT oid, rolname FROM pg_roles WHERE rolname = :'role'),
effective AS (
  SELECT r.oid, r.rolname FROM pg_roles r, target t
  WHERE pg_has_role(t.oid, r.oid, 'MEMBER') AND left(r.rolname, 3) <> 'pg_'
)
SELECT n.nspname, c.relname, e.rolname AS via, string_agg(p.priv, ', ' ORDER BY p.priv) AS privs
FROM effective e
CROSS JOIN pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN unnest(ARRAY['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) AS p(priv)
WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND left(n.nspname, 3) <> 'pg_'
  AND has_table_privilege(e.oid, c.oid, p.priv)
GROUP BY 1, 2, 3 ORDER BY 1, 2, 3 LIMIT 1000;

-- T2: No column-level write privileges
WITH target AS (SELECT oid, rolname FROM pg_roles WHERE rolname = :'role'),
effective AS (
  SELECT r.oid, r.rolname FROM pg_roles r, target t
  WHERE pg_has_role(t.oid, r.oid, 'MEMBER') AND left(r.rolname, 3) <> 'pg_'
)
SELECT n.nspname, c.relname, e.rolname AS via, string_agg(p.priv, ', ' ORDER BY p.priv) AS privs
FROM effective e
CROSS JOIN pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN unnest(ARRAY['INSERT', 'UPDATE', 'REFERENCES']) AS p(priv)
WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND left(n.nspname, 3) <> 'pg_'
  AND has_any_column_privilege(e.oid, c.oid, p.priv)
  AND NOT has_table_privilege(e.oid, c.oid, p.priv)
GROUP BY 1, 2, 3 ORDER BY 1, 2, 3 LIMIT 1000;

-- T3: Owns nothing
WITH target AS (SELECT oid, rolname FROM pg_roles WHERE rolname = :'role'),
effective AS (
  SELECT r.oid, r.rolname FROM pg_roles r, target t
  WHERE pg_has_role(t.oid, r.oid, 'MEMBER') AND left(r.rolname, 3) <> 'pg_'
)
SELECT kind, name, owner FROM (
  SELECT 'table/view' AS kind, n.nspname || '.' || c.relname AS name, e.rolname AS owner
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace JOIN effective e ON e.oid = c.relowner
  WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND left(n.nspname, 3) <> 'pg_' AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
  UNION ALL
  SELECT 'schema', n.nspname, e.rolname FROM pg_namespace n JOIN effective e ON e.oid = n.nspowner WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND left(n.nspname, 3) <> 'pg_'
  UNION ALL
  SELECT 'function', p.oid::regprocedure::text, e.rolname
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN effective e ON e.oid = p.proowner WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND left(n.nspname, 3) <> 'pg_'
  UNION ALL
  SELECT 'database', d.datname, e.rolname FROM pg_database d JOIN effective e ON e.oid = d.datdba
) x ORDER BY 1, 2 LIMIT 1000;

-- S1: Cannot create objects in any schema
WITH target AS (SELECT oid, rolname FROM pg_roles WHERE rolname = :'role'),
effective AS (
  SELECT r.oid, r.rolname FROM pg_roles r, target t
  WHERE pg_has_role(t.oid, r.oid, 'MEMBER') AND left(r.rolname, 3) <> 'pg_'
)
SELECT DISTINCT n.nspname, has_schema_privilege('public', n.oid, 'CREATE') AS via_public
FROM effective e CROSS JOIN pg_namespace n
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND left(n.nspname, 3) <> 'pg_' AND has_schema_privilege(e.oid, n.oid, 'CREATE') ORDER BY 1;

-- D1: Database-level privileges
WITH target AS (SELECT oid, rolname FROM pg_roles WHERE rolname = :'role'),
effective AS (
  SELECT r.oid, r.rolname FROM pg_roles r, target t
  WHERE pg_has_role(t.oid, r.oid, 'MEMBER') AND left(r.rolname, 3) <> 'pg_'
)
SELECT current_database() AS db,
       bool_or(has_database_privilege(e.oid, current_database(), 'CREATE')) AS can_create,
       bool_or(has_database_privilege(e.oid, current_database(), 'TEMP')) AS can_temp,
       has_database_privilege('public', current_database(), 'TEMP') AS public_temp
FROM effective e;

-- Q1: Cannot advance or set sequences
WITH target AS (SELECT oid, rolname FROM pg_roles WHERE rolname = :'role'),
effective AS (
  SELECT r.oid, r.rolname FROM pg_roles r, target t
  WHERE pg_has_role(t.oid, r.oid, 'MEMBER') AND left(r.rolname, 3) <> 'pg_'
)
SELECT n.nspname || '.' || c.relname AS seq,
       bool_or(has_sequence_privilege(e.oid, c.oid, 'UPDATE')) AS upd,
       bool_or(has_sequence_privilege(e.oid, c.oid, 'USAGE')) AS usg
FROM effective e CROSS JOIN pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'S' AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND left(n.nspname, 3) <> 'pg_'
  AND (has_sequence_privilege(e.oid, c.oid, 'UPDATE') OR has_sequence_privilege(e.oid, c.oid, 'USAGE'))
GROUP BY 1 ORDER BY 1 LIMIT 1000;

-- F1: No executable SECURITY DEFINER functions
WITH target AS (SELECT oid, rolname FROM pg_roles WHERE rolname = :'role'),
effective AS (
  SELECT r.oid, r.rolname FROM pg_roles r, target t
  WHERE pg_has_role(t.oid, r.oid, 'MEMBER') AND left(r.rolname, 3) <> 'pg_'
)
SELECT DISTINCT p.oid::regprocedure::text AS fn, pg_get_userbyid(p.proowner) AS owner
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace CROSS JOIN effective e
WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND left(n.nspname, 3) <> 'pg_' AND has_function_privilege(e.oid, p.oid, 'EXECUTE')
ORDER BY 1 LIMIT 1000;

-- F2: Cannot create large objects
SELECT has_function_privilege(:'role', 'lo_create(oid)', 'EXECUTE') AS lo_create,
       has_function_privilege(:'role', 'lo_from_bytea(oid, bytea)', 'EXECUTE') AS lo_from_bytea,
       current_setting('lo_compat_privileges') AS compat;

-- X1: No secret-pattern columns readable
WITH target AS (SELECT oid, rolname FROM pg_roles WHERE rolname = :'role'),
effective AS (
  SELECT r.oid, r.rolname FROM pg_roles r, target t
  WHERE pg_has_role(t.oid, r.oid, 'MEMBER') AND left(r.rolname, 3) <> 'pg_'
)
SELECT n.nspname || '.' || c.relname || '.' || a.attname AS col, string_agg(DISTINCT e.rolname, ', ') AS via
FROM effective e
CROSS JOIN pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE a.attnum > 0 AND NOT a.attisdropped
  AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND left(n.nspname, 3) <> 'pg_'
  AND lower(regexp_replace(a.attname, E'([a-z0-9])([A-Z])', E'\\1_\\2', 'g')) ~ '(^|_)(pwd|pin|mfa|otp|totp|hotp|salt|cvv|cvv2|cvc|pan|passphrase|apikey|privatekey|seed|nonce|otpauth)(_|$)|password|passwd|secret|token|credential|api_?key|private_?key|encryption_?key|session_?key|access_?key|signing_?key|master_?key|secret_?key|card_?number|card_?num|webhook_?sig|signature_?key|recovery_?codes?|backup_?codes?|pass_?hash|hashed_?pass'
  AND has_column_privilege(e.oid, c.oid, a.attnum, 'SELECT')
GROUP BY 1 ORDER BY 1 LIMIT 1000;

-- N1: No foreign server access
WITH target AS (SELECT oid, rolname FROM pg_roles WHERE rolname = :'role'),
effective AS (
  SELECT r.oid, r.rolname FROM pg_roles r, target t
  WHERE pg_has_role(t.oid, r.oid, 'MEMBER') AND left(r.rolname, 3) <> 'pg_'
)
SELECT DISTINCT s.srvname FROM pg_foreign_server s CROSS JOIN effective e
WHERE has_server_privilege(e.oid, s.oid, 'USAGE') ORDER BY 1;

-- N2: Login rules (pg_hba.conf)
SELECT line_number, type, database, user_name, address, auth_method
FROM pg_hba_file_rules
WHERE error IS NULL AND (:'role' = ANY (user_name) OR 'all' = ANY (user_name))
ORDER BY line_number;

-- C1: Read-only default and audit logging
SELECT unnest(s.setconfig) AS setting FROM pg_db_role_setting s JOIN pg_roles r ON r.oid = s.setrole
   WHERE r.rolname = :'role' AND s.setdatabase IN (0, (SELECT oid FROM pg_database WHERE datname = current_database()));

-- G1: Queries are time-limited (see the C1 query above)

-- G2: Idle transactions are ended (see the C1 query above)

-- G3: Lock waits are limited (see the C1 query above)

-- G4: Temporary file use is limited (see the C1 query above)
