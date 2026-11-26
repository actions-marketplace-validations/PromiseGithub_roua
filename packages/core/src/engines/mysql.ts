/**
 * ROUA for MySQL 8+ and MariaDB 10.6+.
 *
 * - SELECT is granted per table (or per column when a table has hidden
 *   columns), computed from information_schema when setup runs. Nothing is
 *   granted at database level, so tables created later are not readable.
 * - MySQL gets a caching_sha2_password verifier and MariaDB a native password
 *   hash: the plaintext password is never in the script.
 * - Expiry: a one-shot event locks the account and ends its sessions. MySQL
 *   enables the event scheduler by default; MariaDB does not (the audit checks).
 * - Never granted: FILE, PROCESS, SUPER, EXECUTE, LOCK TABLES, SHOW VIEW,
 *   any role, any proxy. SELECT ... FOR UPDATE needs UPDATE, so plain SELECT
 *   cannot lock rows.
 */
import { mysqlCachingSha2Hash, mysqlNativeHash } from "../hashes.js";
import { anyPatternRegex, engineMetadata, header, SECRET_REGEX, splitColumn, sqlTimestamp } from "./common.js";
import type { AccountSpec, EnginePlan } from "./types.js";

const SYSTEM_DBS = ["mysql", "information_schema", "performance_schema", "sys", "roua_admin"];

export const myIdent = (s: string) => "`" + s.replace(/`/g, "``") + "`";
export const myLit = (s: string) => "'" + s.replace(/\\/g, "\\\\").replace(/'/g, "''") + "'";
const list = (xs: readonly string[]) => xs.map(myLit).join(", ");

interface Ctx {
  maria: boolean;
  user: string; // 'name'@'host'
  name: string;
  host: string;
}

function ctx(spec: AccountSpec): Ctx {
  const host = spec.allowedSources?.[0] ?? "%";
  return { maria: spec.engine === "mariadb", user: `${myLit(spec.name)}@${myLit(host)}`, name: spec.name, host };
}

/** snake_case(lower) of a column-name expression, in the dialect. */
function snake(expr: string, maria: boolean): string {
  return maria
    ? `LOWER(REGEXP_REPLACE(${expr}, '(?-i)([a-z0-9])([A-Z])', '\\\\1_\\\\2'))`
    : `LOWER(REGEXP_REPLACE(${expr}, '([a-z0-9])([A-Z])', '$1_$2', 1, 0, 'c'))`;
}

/** SQL predicate: is column c (alias of information_schema.COLUMNS) hidden? */
function hiddenPredicate(spec: AccountSpec, maria: boolean, alias = "c"): string {
  const full = `CONCAT(${alias}.TABLE_SCHEMA, '.', ${alias}.TABLE_NAME, '.', ${alias}.COLUMN_NAME)`;
  const allow = spec.columnsAllow ?? [];
  const deny = spec.columnsDeny ?? [];
  let secret = `${snake(`${alias}.COLUMN_NAME`, maria)} REGEXP '${SECRET_REGEX}'`;
  if (allow.length) secret = `(${secret} AND ${full} NOT IN (${list(allow)}))`;
  return deny.length ? `(${secret} OR ${full} IN (${list(deny)}))` : secret;
}

function tableFilter(spec: AccountSpec, alias = "t"): string {
  const full = `CONCAT(${alias}.TABLE_SCHEMA, '.', ${alias}.TABLE_NAME)`;
  const parts = [`${alias}.TABLE_SCHEMA NOT IN (${list(SYSTEM_DBS)})`];
  if (spec.mode === "listed") {
    parts.push(`${full} REGEXP ${myLit(anyPatternRegex(spec.objects ?? [])!)}`);
  } else {
    parts.push(`${alias}.TABLE_SCHEMA IN (${list(spec.schemas ?? [])})`);
    const ex = anyPatternRegex(spec.exclude ?? []);
    if (ex) parts.push(`NOT (${full} REGEXP ${myLit(ex)})`);
  }
  return parts.join("\n      AND ");
}

function revokeProcedure(): string {
  return `DROP PROCEDURE IF EXISTS roua_admin.roua_revoke $$
CREATE PROCEDURE roua_admin.roua_revoke(IN p_user VARCHAR(80), IN p_host VARCHAR(255))
  COMMENT 'ROUA: lock an account and end its sessions'
BEGIN
  DECLARE done INT DEFAULT 0;
  DECLARE v_id BIGINT;
  DECLARE cur CURSOR FOR SELECT ID FROM information_schema.PROCESSLIST WHERE USER = p_user;
  DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = 1;
  DECLARE CONTINUE HANDLER FOR 1094 BEGIN END;
  SET @roua_sql = CONCAT('ALTER USER ', QUOTE(p_user), '@', QUOTE(p_host), ' ACCOUNT LOCK');
  PREPARE roua_stmt FROM @roua_sql;
  EXECUTE roua_stmt;
  DEALLOCATE PREPARE roua_stmt;
  OPEN cur;
  kill_loop: LOOP
    FETCH cur INTO v_id;
    IF done THEN LEAVE kill_loop; END IF;
    SET @roua_sql = CONCAT('KILL ', v_id);
    PREPARE roua_stmt FROM @roua_sql;
    EXECUTE roua_stmt;
    DEALLOCATE PREPARE roua_stmt;
  END LOOP;
  CLOSE cur;
  UPDATE roua_admin.accounts SET revoked_at = UTC_TIMESTAMP() WHERE user_name = p_user AND host = p_host;
END $$`;
}

/** Rows for names that match nothing: a misspelled table or column is reported, not silently ignored. */
function mismatchReport(spec: AccountSpec): string {
  const rows: string[] = [];
  if (spec.mode === "listed") {
    for (const o of spec.objects ?? []) {
      rows.push(`SELECT ${myLit(o)} AS name, 'listed table' AS what FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM information_schema.TABLES t WHERE CONCAT(t.TABLE_SCHEMA, '.', t.TABLE_NAME) REGEXP ${myLit(anyPatternRegex([o])!)})`);
    }
  } else {
    for (const s of spec.schemas ?? []) {
      rows.push(`SELECT ${myLit(s)} AS name, 'database' AS what FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ${myLit(s)})`);
    }
  }
  for (const d of spec.columnsDeny ?? []) {
    rows.push(`SELECT ${myLit(d)} AS name, 'hidden column (NOT hidden: no such column)' AS what FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS c WHERE CONCAT(c.TABLE_SCHEMA, '.', c.TABLE_NAME, '.', c.COLUMN_NAME) = ${myLit(d)})`);
  }
  if (!rows.length) return "";
  return `-- Names that match nothing in this server (no rows here means every name was found).
SELECT name AS not_found, what FROM (
  ${rows.join("\n  UNION ALL\n  ")}
) roua_missing;
`;
}

export function planMySql(spec: AccountSpec, now: Date): EnginePlan {
  const c = ctx(spec);
  const perColumn = (spec.columnGrants ?? "always") === "always";
  const { maria } = c;
  const engineName = maria ? "MariaDB" : "MySQL";
  const warnings: string[] = [];
  const manualSteps: string[] = [];
  const pw = spec.password ?? "";
  const auth = maria
    ? `IDENTIFIED BY PASSWORD ${myLit(mysqlNativeHash(pw))}`
    : `IDENTIFIED WITH caching_sha2_password AS ${myLit(mysqlCachingSha2Hash(pw))}`;
  const resource: string[] = [];
  if (spec.maxConnections) resource.push(`MAX_USER_CONNECTIONS ${spec.maxConnections}`);
  if (maria && spec.statementTimeoutS) resource.push(`MAX_STATEMENT_TIME ${spec.statementTimeoutS}`);
  if (!maria && spec.statementTimeoutS) {
    warnings.push("MySQL has no per-account statement timeout. Set max_execution_time in the client, or use a proxy that enforces one.");
  }
  if ((spec.allowedSources?.length ?? 0) > 1) warnings.push(`Only the first host pattern (${c.host}) is used; create one ROUA per host if you need more.`);
  if (c.host === "%") warnings.push("The account can connect from any host. Set Allowed hosts (for example 10.0.%) to narrow it.");
  const meta = engineMetadata(spec, now);
  const eventName = `roua_expire_${spec.name}`;
  const roleTable = maria ? "SELECT Role AS r, '' AS h FROM mysql.roles_mapping WHERE User = p_user AND Host = p_host AND Role <> ''" : "SELECT FROM_USER AS r, FROM_HOST AS h FROM mysql.role_edges WHERE TO_USER = p_user AND TO_HOST = p_host";
  const revokeRole = maria ? "CONCAT('REVOKE ', QUOTE(v_role), ' FROM ', QUOTE(p_user), '@', QUOTE(p_host))" : "CONCAT('REVOKE ', QUOTE(v_role), '@', QUOTE(v_role_host), ' FROM ', QUOTE(p_user), '@', QUOTE(p_host))";
  const defaultRole = maria ? `SET DEFAULT ROLE NONE FOR ${c.user};` : `SET DEFAULT ROLE NONE TO ${c.user};`;
  const comment = maria ? "" : `\nALTER USER ${c.user} COMMENT ${myLit(meta)};`;

  const setup = `${header("setup.sql: create or update the ROUA account. Run as an administrator:", spec, now)}-- mysql -h HOST -u admin -p < setup.sql
-- Safe to run again: it resets the account's privileges and grants them afresh.

SET SESSION sql_mode = REPLACE(@@SESSION.sql_mode, 'NO_BACKSLASH_ESCAPES', '');
SET SESSION time_zone = '+00:00';
SET SESSION group_concat_max_len = 1048576;

-- roua_admin holds bookkeeping, the revoke procedure and expiry events. No ROUA account has access.
CREATE DATABASE IF NOT EXISTS roua_admin;
CREATE TABLE IF NOT EXISTS roua_admin.accounts (
  user_name VARCHAR(80) NOT NULL,
  host VARCHAR(255) NOT NULL,
  metadata VARCHAR(1000) NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL,
  revoked_at DATETIME NULL,
  PRIMARY KEY (user_name, host)
);

-- 1. The account. Only a password verifier is stored here, never the password.
CREATE USER IF NOT EXISTS ${c.user} ${auth};
ALTER USER ${c.user} ${auth}
  REQUIRE ${spec.requireTls ? "SSL" : "NONE"}${resource.length ? `\n  WITH ${resource.join(" ")}` : ""}
  ACCOUNT UNLOCK PASSWORD EXPIRE NEVER;${comment}
REPLACE INTO roua_admin.accounts (user_name, host, metadata, expires_at, created_at, revoked_at)
  VALUES (${myLit(spec.name)}, ${myLit(c.host)}, ${myLit(meta)}, ${myLit(sqlTimestamp(spec.expiresAt))}, UTC_TIMESTAMP(), NULL);

-- 2. Start from nothing: no privileges, no roles.
REVOKE ALL PRIVILEGES, GRANT OPTION FROM ${c.user};
${defaultRole}

DELIMITER $$
DROP PROCEDURE IF EXISTS roua_admin.roua_setup_tmp $$
CREATE PROCEDURE roua_admin.roua_setup_tmp(IN p_user VARCHAR(80), IN p_host VARCHAR(255))
BEGIN
  DECLARE done INT DEFAULT 0;
  DECLARE v_role VARCHAR(255);
  DECLARE v_role_host VARCHAR(255);
  DECLARE v_schema VARCHAR(64);
  DECLARE v_table VARCHAR(64);
  DECLARE v_cols MEDIUMTEXT;
  DECLARE v_hidden INT;
  DECLARE v_granted INT DEFAULT 0;
  DECLARE roles CURSOR FOR ${roleTable};
  DECLARE tabs CURSOR FOR
    SELECT t.TABLE_SCHEMA, t.TABLE_NAME,
      (SELECT GROUP_CONCAT(CONCAT('\`', REPLACE(c.COLUMN_NAME, '\`', '\`\`'), '\`') ORDER BY c.ORDINAL_POSITION SEPARATOR ', ')
         FROM information_schema.COLUMNS c
        WHERE c.TABLE_SCHEMA = t.TABLE_SCHEMA AND c.TABLE_NAME = t.TABLE_NAME
          AND NOT ${hiddenPredicate(spec, maria)}),
      (SELECT COUNT(*) FROM information_schema.COLUMNS c
        WHERE c.TABLE_SCHEMA = t.TABLE_SCHEMA AND c.TABLE_NAME = t.TABLE_NAME
          AND ${hiddenPredicate(spec, maria)})
    FROM information_schema.TABLES t
    WHERE t.TABLE_TYPE IN ('BASE TABLE', 'VIEW', 'SYSTEM VERSIONED')
      AND ${tableFilter(spec)}
    ORDER BY 1, 2;
  DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = 1;

  -- Revoke every role the account holds.
  OPEN roles;
  role_loop: LOOP
    FETCH roles INTO v_role, v_role_host;
    IF done THEN LEAVE role_loop; END IF;
    SET @roua_sql = ${revokeRole};
    PREPARE roua_stmt FROM @roua_sql;
    EXECUTE roua_stmt;
    DEALLOCATE PREPARE roua_stmt;
  END LOOP;
  CLOSE roles;
  SET done = 0;

  -- ${perColumn ? "SELECT on the visible columns of each table: columns added later stay hidden until setup runs again." : "SELECT per table; per column where some columns are hidden."}
  OPEN tabs;
  tab_loop: LOOP
    FETCH tabs INTO v_schema, v_table, v_cols, v_hidden;
    IF done THEN LEAVE tab_loop; END IF;
    IF v_hidden = 0 AND ${perColumn ? "FALSE" : "TRUE"} THEN
      SET @roua_sql = CONCAT('GRANT SELECT ON \`', REPLACE(v_schema, '\`', '\`\`'), '\`.\`', REPLACE(v_table, '\`', '\`\`'), '\` TO ', QUOTE(p_user), '@', QUOTE(p_host));
    ELSEIF v_cols IS NOT NULL THEN
      SET @roua_sql = CONCAT('GRANT SELECT (', v_cols, ') ON \`', REPLACE(v_schema, '\`', '\`\`'), '\`.\`', REPLACE(v_table, '\`', '\`\`'), '\` TO ', QUOTE(p_user), '@', QUOTE(p_host));
    ELSE
      ITERATE tab_loop;
    END IF;
    PREPARE roua_stmt FROM @roua_sql;
    EXECUTE roua_stmt;
    DEALLOCATE PREPARE roua_stmt;
    SET v_granted = v_granted + 1;
  END LOOP;
  CLOSE tabs;
  IF v_granted = 0 THEN
    -- MySQL limits MESSAGE_TEXT to 128 characters.
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'ROUA: the scope matched no readable tables, so the account can read nothing. Check the scope.';
  END IF;
END $$

${revokeProcedure()}
DELIMITER ;

-- 3. Grant read access as computed above, then remove the helper.
${mismatchReport(spec)}CALL roua_admin.roua_setup_tmp(${myLit(spec.name)}, ${myLit(c.host)});
DROP PROCEDURE roua_admin.roua_setup_tmp;

-- 4. Expiry: lock the account and end its sessions at ${new Date(spec.expiresAt).toISOString()}.
DROP EVENT IF EXISTS roua_admin.${myIdent(eventName)};
CREATE EVENT roua_admin.${myIdent(eventName)}
  ON SCHEDULE AT ${myLit(sqlTimestamp(spec.expiresAt))}
  ON COMPLETION NOT PRESERVE
  COMMENT 'ROUA expiry'
  DO CALL roua_admin.roua_revoke(${myLit(spec.name)}, ${myLit(c.host)});

-- 5. What the account can read (should be SELECT only), and whether expiry will fire.
SELECT TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE FROM information_schema.TABLE_PRIVILEGES
 WHERE GRANTEE = ${myLit(`'${spec.name}'@'${c.host}'`)} ORDER BY 1, 2;
SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME FROM information_schema.COLUMN_PRIVILEGES
 WHERE GRANTEE = ${myLit(`'${spec.name}'@'${c.host}'`)} ORDER BY 1, 2, 3;
SELECT IF(@@GLOBAL.event_scheduler = 'ON', 'OK: the event scheduler is on; expiry will fire.',
          'ACTION NEEDED: the event scheduler is off, so expiry will NOT fire. Set event_scheduler=ON in the server configuration.') AS expiry;
`;

  const revoke = `${header("revoke.sql: lock the account now and end its open sessions. Run as an administrator.", spec, now)}CALL roua_admin.roua_revoke(${myLit(spec.name)}, ${myLit(c.host)});
DROP EVENT IF EXISTS roua_admin.${myIdent(eventName)};
`;
  const drop = `${header("drop.sql: remove the account completely (run revoke.sql first).", spec, now)}DROP EVENT IF EXISTS roua_admin.${myIdent(eventName)};
DROP USER IF EXISTS ${c.user};
DELETE FROM roua_admin.accounts WHERE user_name = ${myLit(spec.name)} AND host = ${myLit(c.host)};
`;

  if (maria) {
    manualSteps.push("MariaDB ships with the event scheduler off. Set event_scheduler=ON in the server configuration, or the account will not expire on its own (the last query of setup.sql tells you).");
  }
  manualSteps.push(`Connect as the account and try a write: it must fail with a permission error. ${engineName} checks the grants on every statement.`);
  return {
    engine: spec.engine,
    files: [
      { name: "setup.sql", run: `mysql -h HOST -u admin -p < setup.sql`, content: setup },
      { name: "audit.sql", run: `mysql -h HOST -u admin -p --table < audit.sql`, content: auditMySql(spec.name, c.host, maria, now) },
      { name: "revoke.sql", run: `mysql -h HOST -u admin -p < revoke.sql`, content: revoke },
      { name: "drop.sql", run: `mysql -h HOST -u admin -p < drop.sql`, content: drop },
    ],
    warnings,
    manualSteps,
  };
}

/**
 * Audit any existing MySQL/MariaDB account. Read-only; one row per check.
 * Works for accounts ROUA did not create (they will usually fail E1).
 */
export function auditMySql(name: string, host: string, maria: boolean, now: Date = new Date()): string {
  const grantee = myLit(`'${name}'@'${host}'`);
  const u = myLit(name);
  const h = myLit(host);
  const secretCol = `${snake("c.COLUMN_NAME", maria)} REGEXP '${SECRET_REGEX}'`;
  const roles = maria
    ? `SELECT GROUP_CONCAT(Role) FROM mysql.roles_mapping WHERE User = ${u} AND Host = ${h} AND Role <> ''`
    : `SELECT GROUP_CONCAT(CONCAT(FROM_USER, '@', FROM_HOST)) FROM mysql.role_edges WHERE TO_USER = ${u} AND TO_HOST = ${h}`;
  const row = (id: string, check: string, failWhen: string, detail: string, warn = false) =>
    `SELECT '${id}' AS id, '${check}' AS \`check\`, IF(${failWhen}, '${warn ? "WARN" : "FAIL"}', 'PASS') AS status, ${detail} AS detail`;
  return `-- audit.sql: is ${name}@${host} actually read-only? Read-only; safe to run anytime as an administrator.
-- ROUA ${"0.1"} audit for ${maria ? "MariaDB" : "MySQL"}. Generated ${now.toISOString()} by the ROUA generator (kaizam.com).
-- mysql -h HOST -u admin -p --table < audit.sql
-- Every row should say PASS. FAIL means the account can change data, read secrets or never expires.

SET SESSION group_concat_max_len = 1048576;

${[
  row("A1", "Account exists", `(SELECT COUNT(*) FROM mysql.user WHERE User = ${u} AND Host = ${h}) = 0`, "'Run with the exact user and host'"),
  row("R1", "No global privileges", "COUNT(*) > 0", "COALESCE(GROUP_CONCAT(PRIVILEGE_TYPE), '')") + `\n  FROM information_schema.USER_PRIVILEGES WHERE GRANTEE = ${grantee} AND PRIVILEGE_TYPE <> 'USAGE'`,
  row("R2", "No database-wide privileges (new tables would become readable)", "COUNT(*) > 0", "COALESCE(GROUP_CONCAT(CONCAT(TABLE_SCHEMA, ': ', PRIVILEGE_TYPE)), '')") + `\n  FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE = ${grantee}`,
  row("T1", "Table privileges are SELECT only", "COUNT(*) > 0", "COALESCE(GROUP_CONCAT(CONCAT(TABLE_SCHEMA, '.', TABLE_NAME, ': ', PRIVILEGE_TYPE)), '')") + `\n  FROM information_schema.TABLE_PRIVILEGES WHERE GRANTEE = ${grantee} AND PRIVILEGE_TYPE <> 'SELECT'`,
  row("T2", "Column privileges are SELECT only", "COUNT(*) > 0", "COALESCE(GROUP_CONCAT(CONCAT(TABLE_SCHEMA, '.', TABLE_NAME, '.', COLUMN_NAME, ': ', PRIVILEGE_TYPE)), '')") + `\n  FROM information_schema.COLUMN_PRIVILEGES WHERE GRANTEE = ${grantee} AND PRIVILEGE_TYPE <> 'SELECT'`,
  row("R3", "Holds no roles", `(${roles}) IS NOT NULL`, `COALESCE((${roles}), '')`),
  row("R4", "Cannot act as another user (no PROXY)", `(SELECT COUNT(*) FROM mysql.proxies_priv WHERE User = ${u} AND Host = ${h}) > 0`, `COALESCE((SELECT GROUP_CONCAT(CONCAT(Proxied_user, '@', Proxied_host)) FROM mysql.proxies_priv WHERE User = ${u} AND Host = ${h}), '')`),
  row("X1", "No secret-looking columns readable", "COUNT(*) > 0", "COALESCE(GROUP_CONCAT(DISTINCT CONCAT(c.TABLE_SCHEMA, '.', c.TABLE_NAME, '.', c.COLUMN_NAME)), '')") +
    `\n  FROM information_schema.COLUMNS c\n WHERE ${secretCol}\n   AND (EXISTS (SELECT 1 FROM information_schema.TABLE_PRIVILEGES p WHERE p.GRANTEE = ${grantee} AND p.TABLE_SCHEMA = c.TABLE_SCHEMA AND p.TABLE_NAME = c.TABLE_NAME AND p.PRIVILEGE_TYPE = 'SELECT')\n     OR EXISTS (SELECT 1 FROM information_schema.COLUMN_PRIVILEGES p WHERE p.GRANTEE = ${grantee} AND p.TABLE_SCHEMA = c.TABLE_SCHEMA AND p.TABLE_NAME = c.TABLE_NAME AND p.COLUMN_NAME = c.COLUMN_NAME)\n     OR EXISTS (SELECT 1 FROM information_schema.SCHEMA_PRIVILEGES p WHERE p.GRANTEE = ${grantee} AND p.TABLE_SCHEMA = c.TABLE_SCHEMA AND p.PRIVILEGE_TYPE = 'SELECT')\n     OR EXISTS (SELECT 1 FROM information_schema.USER_PRIVILEGES p WHERE p.GRANTEE = ${grantee} AND p.PRIVILEGE_TYPE = 'SELECT'))`,
  row("E1", "Expires on its own (ROUA expiry event exists)", `(SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA = 'roua_admin' AND EVENT_NAME = ${myLit(`roua_expire_${name}`)}) = 0`, `COALESCE((SELECT CAST(EXECUTE_AT AS CHAR) FROM information_schema.EVENTS WHERE EVENT_SCHEMA = 'roua_admin' AND EVENT_NAME = ${myLit(`roua_expire_${name}`)}), 'No expiry: forgotten accounts are the most common leak')`),
  row("E2", "The event scheduler is on (needed for expiry)", "@@GLOBAL.event_scheduler <> 'ON'", "CAST(@@GLOBAL.event_scheduler AS CHAR)"),
  row("N1", "Limited to known hosts", `${h} = '%'`, `CONCAT('host = ', ${h})`, true),
  row("N2", "Requires TLS", `(SELECT ssl_type FROM mysql.user WHERE User = ${u} AND Host = ${h}) = ''`, "'REQUIRE SSL keeps the password and data off the wire'", true),
  row("L1", "Connection limit set", `COALESCE((SELECT max_user_connections FROM mysql.user WHERE User = ${u} AND Host = ${h}), 0) = 0`, "'MAX_USER_CONNECTIONS caps runaway agents'", true),
  row("Z1", "No anonymous accounts on the server", "(SELECT COUNT(*) FROM mysql.user WHERE User = '') > 0", "'Anonymous accounts let anyone connect'", true),
].join("\nUNION ALL\n")};
`;
}
