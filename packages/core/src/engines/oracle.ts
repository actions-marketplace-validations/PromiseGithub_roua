/**
 * ROUA for Oracle Database 19c and 23ai (also Autonomous Database).
 *
 * - READ, not SELECT: READ cannot LOCK TABLE or SELECT ... FOR UPDATE, so the
 *   account cannot block writers. Granted per table and view when setup runs;
 *   no ANY privileges and no schema-level grants, so new tables stay closed.
 * - Oracle has no column-level read grants: tables with hidden columns are
 *   skipped and listed, with a hint to expose them through a view.
 * - A dedicated profile caps sessions and CPU per call; a scheduler job locks
 *   the account and kills its sessions at expiry.
 */
import { anyPatternRegex, engineMetadata, header, SECRET_REGEX, splitColumn } from "./common.js";
import type { AccountSpec, EnginePlan } from "./types.js";

export const oraLit = (s: string) => `'${s.replace(/'/g, "''")}'`;
const up = (s: string) => s.toUpperCase();
const list = (xs: readonly string[]) => xs.map((x) => oraLit(up(x))).join(", ");

function hiddenPredicate(spec: AccountSpec): string {
  const snake = `LOWER(REGEXP_REPLACE(c.column_name, '([a-z0-9])([A-Z])', '\\1_\\2', 1, 0, 'c'))`;
  const full = "c.owner || '.' || c.table_name || '.' || c.column_name";
  let secret = `REGEXP_LIKE(${snake}, '${SECRET_REGEX}')`;
  const allow = (spec.columnsAllow ?? []).map((x) => splitColumn(x).map(up).join("."));
  const deny = (spec.columnsDeny ?? []).map((x) => splitColumn(x).map(up).join("."));
  if (allow.length) secret = `(${secret} AND ${full} NOT IN (${allow.map(oraLit).join(", ")}))`;
  return deny.length ? `(${secret} OR ${full} IN (${deny.map(oraLit).join(", ")}))` : secret;
}

function objectFilter(spec: AccountSpec): string {
  const full = "o.owner || '.' || o.object_name";
  if (spec.mode === "listed") return `REGEXP_LIKE(${full}, ${oraLit(anyPatternRegex(spec.objects ?? [])!)}, 'i')`;
  const parts = [`o.owner IN (${list(spec.schemas ?? [])})`];
  const ex = anyPatternRegex(spec.exclude ?? []);
  if (ex) parts.push(`NOT REGEXP_LIKE(${full}, ${oraLit(ex)}, 'i')`);
  return parts.join("\n         AND ");
}

/** PL/SQL lines that print names matching nothing, so typos are reported. */
function mismatchReport(spec: AccountSpec): string {
  const lines: string[] = [];
  if (spec.mode === "listed") {
    for (const p of spec.objects ?? []) {
      lines.push(`  SELECT COUNT(*) INTO n FROM dba_objects WHERE object_type IN ('TABLE', 'VIEW', 'MATERIALIZED VIEW') AND REGEXP_LIKE(owner || '.' || object_name, ${oraLit(anyPatternRegex([p])!)}, 'i');
  IF n = 0 THEN DBMS_OUTPUT.PUT_LINE('ROUA WARNING: listed table ' || ${oraLit(p)} || ' matches nothing: check the spelling.'); END IF;`);
    }
  } else {
    for (const s of spec.schemas ?? []) {
      lines.push(`  SELECT COUNT(*) INTO n FROM dba_users WHERE username = ${oraLit(up(s))};
  IF n = 0 THEN DBMS_OUTPUT.PUT_LINE('ROUA WARNING: schema ' || ${oraLit(up(s))} || ' does not exist.'); END IF;`);
    }
  }
  for (const d of spec.columnsDeny ?? []) {
    const ref = splitColumn(d).map(up).join(".");
    lines.push(`  SELECT COUNT(*) INTO n FROM dba_tab_columns WHERE owner || '.' || table_name || '.' || column_name = ${oraLit(ref)};
  IF n = 0 THEN DBMS_OUTPUT.PUT_LINE('ROUA WARNING: hidden column ' || ${oraLit(ref)} || ' does not exist (if it is spelled differently, it is NOT hidden).'); END IF;`);
  }
  return lines.length ? `  -- Report names that match nothing.\n${lines.join("\n")}\n` : "";
}

function lockAndKill(user: string): string {
  return `EXECUTE IMMEDIATE 'ALTER USER ${user} ACCOUNT LOCK';
  FOR s IN (SELECT sid, serial# AS ser FROM v$session WHERE username = '${user}') LOOP
    BEGIN
      EXECUTE IMMEDIATE 'ALTER SYSTEM KILL SESSION ''' || s.sid || ',' || s.ser || ''' IMMEDIATE';
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
  END LOOP;`;
}

export function planOracle(spec: AccountSpec, now: Date): EnginePlan {
  const U = up(spec.name);
  const P = up(`${spec.name}_profile`).slice(0, 128);
  const J = up(`roua_expire_${spec.name}`).slice(0, 128);
  const meta = engineMetadata(spec, now);
  const pw = spec.password ?? "";
  const limits = [
    `SESSIONS_PER_USER ${spec.maxConnections ?? "UNLIMITED"}`,
    `CPU_PER_CALL ${spec.statementTimeoutS ? spec.statementTimeoutS * 100 : "UNLIMITED"}`,
    "IDLE_TIME 60",
    "FAILED_LOGIN_ATTEMPTS 10",
    "PASSWORD_LOCK_TIME 1",
    "PASSWORD_LIFE_TIME UNLIMITED",
    "PASSWORD_GRACE_TIME UNLIMITED",
  ].join(" ");
  const expiresTs = new Date(spec.expiresAt).toISOString().slice(0, 19).replace("T", " ");
  const jobAction = `BEGIN\n  ${lockAndKill(U)}\nEND;`;

  const setup = `${header("setup.sql: create or update the ROUA account. Run as an administrator (SYSTEM, or ADMIN on Autonomous):", spec, now)}-- sqlplus admin@//HOST:1521/SERVICE @setup.sql      (or SQLcl: sql ... @setup.sql)
-- Oracle needs the plaintext password in this script: delete the file after running it.
-- Safe to run again: it resets the account's privileges and grants them afresh.
WHENEVER SQLERROR EXIT SQL.SQLCODE
SET SERVEROUTPUT ON SIZE UNLIMITED
SET DEFINE OFF

-- 1. A profile with limits for this account only.
DECLARE
  n NUMBER;
BEGIN
  SELECT COUNT(*) INTO n FROM dba_profiles WHERE profile = '${P}';
  IF n = 0 THEN
    EXECUTE IMMEDIATE 'CREATE PROFILE ${P} LIMIT SESSIONS_PER_USER 1';
  END IF;
  EXECUTE IMMEDIATE 'ALTER PROFILE ${P} LIMIT ${limits}';
END;
/

-- 2. The account, reset to nothing but CREATE SESSION.
DECLARE
  n NUMBER;
BEGIN
  SELECT COUNT(*) INTO n FROM dba_users WHERE username = '${U}';
  IF n = 0 THEN
    EXECUTE IMMEDIATE 'CREATE USER ${U} IDENTIFIED BY "${pw}" PROFILE ${P} ACCOUNT UNLOCK';
  ELSE
    EXECUTE IMMEDIATE 'ALTER USER ${U} IDENTIFIED BY "${pw}" PROFILE ${P} ACCOUNT UNLOCK';
  END IF;
  FOR r IN (SELECT granted_role FROM dba_role_privs WHERE grantee = '${U}') LOOP
    EXECUTE IMMEDIATE 'REVOKE "' || r.granted_role || '" FROM ${U}';
  END LOOP;
  FOR r IN (SELECT privilege FROM dba_sys_privs WHERE grantee = '${U}') LOOP
    EXECUTE IMMEDIATE 'REVOKE ' || r.privilege || ' FROM ${U}';
  END LOOP;
  FOR r IN (SELECT DISTINCT owner, table_name, privilege FROM dba_tab_privs WHERE grantee = '${U}') LOOP
    EXECUTE IMMEDIATE 'REVOKE ' || r.privilege || ' ON "' || r.owner || '"."' || r.table_name || '" FROM ${U}';
  END LOOP;
  FOR r IN (SELECT DISTINCT owner, table_name, privilege FROM dba_col_privs WHERE grantee = '${U}') LOOP
    EXECUTE IMMEDIATE 'REVOKE ' || r.privilege || ' ON "' || r.owner || '"."' || r.table_name || '" FROM ${U}';
  END LOOP;
  FOR r IN (SELECT client FROM proxy_users WHERE proxy = '${U}') LOOP
    EXECUTE IMMEDIATE 'ALTER USER "' || r.client || '" REVOKE CONNECT THROUGH ${U}';
  END LOOP;
  -- 23ai schema privileges (GRANT ... ON SCHEMA) would make future tables readable.
  BEGIN
    FOR r IN (SELECT privilege, schema FROM dba_schema_privs WHERE grantee = '${U}') LOOP
      EXECUTE IMMEDIATE 'REVOKE ' || r.privilege || ' ON SCHEMA "' || r.schema || '" FROM ${U}';
    END LOOP;
  EXCEPTION WHEN OTHERS THEN IF SQLCODE NOT IN (-942, -904) THEN RAISE; END IF;
  END;
  EXECUTE IMMEDIATE 'GRANT CREATE SESSION TO ${U}';
END;
/
-- Comments on users do not exist in Oracle; the ROUA metadata is kept in the expiry job's comment:
-- ${meta}

-- 3. READ per table and view, computed now. Tables with hidden columns are skipped.
DECLARE
  granted NUMBER := 0;
  n NUMBER;
BEGIN
${mismatchReport(spec)}  FOR t IN (
    SELECT o.owner, o.object_name,
           (SELECT COUNT(*) FROM dba_tab_columns c
             WHERE c.owner = o.owner AND c.table_name = o.object_name
               AND ${hiddenPredicate(spec)}) AS hidden
      FROM dba_objects o
      JOIN dba_users du ON du.username = o.owner AND du.oracle_maintained = 'N'
     WHERE o.object_type IN ('TABLE', 'VIEW', 'MATERIALIZED VIEW')
       AND o.object_name NOT LIKE 'BIN$%'
       AND o.owner <> '${U}'
       AND ${objectFilter(spec)}
     ORDER BY o.owner, o.object_name
  ) LOOP
    IF t.hidden = 0 THEN
      BEGIN
        EXECUTE IMMEDIATE 'GRANT READ ON "' || t.owner || '"."' || t.object_name || '" TO ${U}';
        granted := granted + 1;
      EXCEPTION WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('NOT GRANTED ' || t.owner || '.' || t.object_name || ': ' || SQLERRM);
      END;
    ELSE
      DBMS_OUTPUT.PUT_LINE('SKIPPED (has hidden columns) ' || t.owner || '.' || t.object_name ||
        ': create a view without them and add the view to the scope.');
    END IF;
  END LOOP;
  DBMS_OUTPUT.PUT_LINE('ROUA: READ granted on ' || granted || ' objects.');
  IF granted = 0 THEN
    RAISE_APPLICATION_ERROR(-20001, 'ROUA: the scope matched no readable tables, so the account can read nothing. Check the schemas, listed tables and exclusions (run discover.sql to see what exists).');
  END IF;
END;
/

-- 4. Expiry: lock the account and end its sessions at ${new Date(spec.expiresAt).toISOString()}.
BEGIN
  BEGIN
    DBMS_SCHEDULER.DROP_JOB(job_name => '${J}', force => TRUE);
  EXCEPTION WHEN OTHERS THEN IF SQLCODE <> -27475 THEN RAISE; END IF;
  END;
  DBMS_SCHEDULER.CREATE_JOB(
    job_name   => '${J}',
    job_type   => 'PLSQL_BLOCK',
    job_action => q'[${jobAction}]',
    start_date => TO_TIMESTAMP_TZ('${expiresTs} +00:00', 'YYYY-MM-DD HH24:MI:SS TZH:TZM'),
    enabled    => TRUE,
    auto_drop  => TRUE,
    comments   => ${oraLit(meta.slice(0, 240))});
END;
/
SELECT owner, table_name, privilege FROM dba_tab_privs WHERE grantee = '${U}' ORDER BY 1, 2;
`;

  const revoke = `${header("revoke.sql: lock the account now and end its open sessions. Run as an administrator.", spec, now)}WHENEVER SQLERROR EXIT SQL.SQLCODE
BEGIN
  ${lockAndKill(U)}
  BEGIN
    DBMS_SCHEDULER.DROP_JOB(job_name => '${J}', force => TRUE);
  EXCEPTION WHEN OTHERS THEN NULL;
  END;
END;
/
`;
  const drop = `${header("drop.sql: remove the account completely (run revoke.sql first).", spec, now)}DROP USER ${U} CASCADE;
DROP PROFILE ${P};
`;
  return {
    engine: "oracle",
    files: [
      { name: "setup.sql", run: "sqlplus admin@//HOST:1521/SERVICE @setup.sql", content: setup },
      { name: "audit.sql", run: "sqlplus admin@//HOST:1521/SERVICE @audit.sql", content: auditOracle(spec.name, now) },
      { name: "revoke.sql", run: "sqlplus admin@//HOST:1521/SERVICE @revoke.sql", content: revoke },
      { name: "drop.sql", run: "sqlplus admin@//HOST:1521/SERVICE @drop.sql", content: drop },
    ],
    warnings: [
      "Oracle needs the plaintext password inside setup.sql. Run it, then delete the file.",
      "Tables with secret-looking columns are skipped (Oracle cannot grant read on single columns). setup.sql lists them: expose them through views without those columns.",
    ],
    manualSteps: [
      "CPU_PER_CALL limits CPU time per call, not wall-clock time, and needs RESOURCE_LIMIT=TRUE (the default since 12.2).",
      "PUBLIC can execute UTL_HTTP, UTL_TCP and UTL_FILE by default. The audit checks that no network ACL lets this account reach the network.",
    ],
  };
}

/** Audit any Oracle user. Read-only; prints one line per check. */
export function auditOracle(name: string, now: Date = new Date()): string {
  const U = up(name);
  const J = up(`roua_expire_${name}`);
  const snake = `LOWER(REGEXP_REPLACE(c.column_name, '([a-z0-9])([A-Z])', '\\1_\\2', 1, 0, 'c'))`;
  return `-- audit.sql: is ${U} actually read-only? Read-only; safe to run anytime as an administrator.
-- ROUA 0.1 audit for Oracle. Generated ${now.toISOString()} by the ROUA generator (kaizam.com).
-- sqlplus admin@//HOST:1521/SERVICE @audit.sql
-- Every line should say PASS. FAIL means the account can change data, read secrets or never expires.
SET SERVEROUTPUT ON SIZE UNLIMITED
SET DEFINE OFF
SET FEEDBACK OFF
DECLARE
  u CONSTANT VARCHAR2(128) := '${U}';
  n NUMBER;
  d VARCHAR2(4000);
  fails NUMBER := 0;
  PROCEDURE chk(id VARCHAR2, title VARCHAR2, bad BOOLEAN, detail VARCHAR2, warn BOOLEAN := FALSE) IS
  BEGIN
    DBMS_OUTPUT.PUT_LINE(RPAD(CASE WHEN NOT bad THEN 'PASS' WHEN warn THEN 'WARN' ELSE 'FAIL' END, 6) || RPAD(id, 4) || title);
    IF bad AND detail IS NOT NULL THEN DBMS_OUTPUT.PUT_LINE('          ' || SUBSTR(detail, 1, 3000)); END IF;
    IF bad AND NOT warn THEN fails := fails + 1; END IF;
  END;
BEGIN
  SELECT COUNT(*) INTO n FROM dba_users WHERE username = u;
  IF n = 0 THEN DBMS_OUTPUT.PUT_LINE('FAIL  A1  No user ' || u); RETURN; END IF;

  SELECT COUNT(*), LISTAGG(privilege, ', ' ON OVERFLOW TRUNCATE) WITHIN GROUP (ORDER BY privilege) INTO n, d
    FROM dba_sys_privs WHERE grantee = u AND privilege <> 'CREATE SESSION';
  chk('R1', 'No system privileges beyond CREATE SESSION', n > 0, d);

  SELECT COUNT(*), LISTAGG(granted_role, ', ' ON OVERFLOW TRUNCATE) WITHIN GROUP (ORDER BY granted_role) INTO n, d
    FROM dba_role_privs WHERE grantee = u;
  chk('R2', 'Holds no roles (roles hide privileges)', n > 0, d);

  SELECT COUNT(*), SUBSTR(LISTAGG(owner || '.' || table_name || ': ' || privilege, ', ' ON OVERFLOW TRUNCATE) WITHIN GROUP (ORDER BY owner, table_name), 1, 3900) INTO n, d
    FROM dba_tab_privs WHERE grantee = u AND privilege NOT IN ('READ', 'SELECT') AND NVL(type, 'TABLE') <> 'DIRECTORY';
  chk('T1', 'Object privileges are READ or SELECT only', n > 0, d);

  SELECT COUNT(*), SUBSTR(LISTAGG(owner || '.' || table_name || '.' || column_name || ': ' || privilege, ', ' ON OVERFLOW TRUNCATE) WITHIN GROUP (ORDER BY owner), 1, 3900) INTO n, d
    FROM dba_col_privs WHERE grantee = u;
  chk('T2', 'No column privileges (they are all write privileges)', n > 0, d);

  SELECT COUNT(*), SUBSTR(LISTAGG(owner || '.' || table_name, ', ' ON OVERFLOW TRUNCATE) WITHIN GROUP (ORDER BY owner, table_name), 1, 3900) INTO n, d
    FROM dba_tab_privs WHERE grantee = u AND privilege = 'SELECT';
  chk('T3', 'Uses READ, not SELECT (SELECT can lock rows and tables)', n > 0, d, TRUE);

  SELECT COUNT(*), LISTAGG(table_name || ': ' || privilege, ', ' ON OVERFLOW TRUNCATE) WITHIN GROUP (ORDER BY table_name) INTO n, d
    FROM dba_tab_privs WHERE grantee IN (u, 'PUBLIC') AND type = 'DIRECTORY';
  chk('D1', 'Cannot read or write server directories', n > 0, d);

  SELECT COUNT(*), SUBSTR(LISTAGG(object_type || ' ' || object_name, ', ' ON OVERFLOW TRUNCATE) WITHIN GROUP (ORDER BY object_name), 1, 3900) INTO n, d
    FROM dba_objects WHERE owner = u;
  chk('O1', 'Owns no objects', n > 0, d);

  SELECT COUNT(*), LISTAGG(client, ', ' ON OVERFLOW TRUNCATE) WITHIN GROUP (ORDER BY client) INTO n, d
    FROM proxy_users WHERE proxy = u;
  chk('P1', 'Cannot connect as another user (proxy)', n > 0, d);

  SELECT COUNT(*), SUBSTR(LISTAGG(c.owner || '.' || c.table_name || '.' || c.column_name, ', ' ON OVERFLOW TRUNCATE) WITHIN GROUP (ORDER BY c.owner), 1, 3900) INTO n, d
    FROM dba_tab_columns c
   WHERE REGEXP_LIKE(${snake}, '${SECRET_REGEX}')
     AND EXISTS (SELECT 1 FROM dba_tab_privs p WHERE p.grantee = u AND p.owner = c.owner AND p.table_name = c.table_name AND p.privilege IN ('READ', 'SELECT'));
  chk('X1', 'No secret-looking columns readable', n > 0, d);

  SELECT COUNT(*), LISTAGG(host || ' (' || principal || ')', ', ' ON OVERFLOW TRUNCATE) WITHIN GROUP (ORDER BY host) INTO n, d
    FROM dba_host_aces WHERE principal IN (u, 'PUBLIC') AND privilege IN ('CONNECT', 'HTTP', 'SMTP', 'RESOLVE');
  chk('N1', 'Cannot reach the network from the database', n > 0, d);

  SELECT COUNT(*), MAX(TO_CHAR(next_run_date, 'YYYY-MM-DD HH24:MI TZR')) INTO n, d
    FROM dba_scheduler_jobs WHERE job_name = '${J}' AND enabled = 'TRUE';
  chk('E1', 'Expires on its own (ROUA expiry job is scheduled)', n = 0, 'No expiry: forgotten accounts are the most common leak');

  SELECT COUNT(*), MAX(p.limit) INTO n, d
    FROM dba_users du JOIN dba_profiles p ON p.profile = du.profile
   WHERE du.username = u AND p.resource_name = 'SESSIONS_PER_USER' AND p.limit IN ('UNLIMITED', 'DEFAULT');
  chk('L1', 'Session limit set (SESSIONS_PER_USER)', n > 0, 'Profile allows unlimited sessions', TRUE);

  DBMS_OUTPUT.PUT_LINE(CASE WHEN fails = 0 THEN 'READ-ONLY: every check passed.' ELSE 'NOT READ-ONLY: ' || fails || ' check(s) failed.' END);
END;
/
`;
}
