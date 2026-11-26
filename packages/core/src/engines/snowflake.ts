/**
 * ROUA for Snowflake (preview: generated from Snowflake's documentation, not
 * yet run against a live account in CI).
 *
 * - A dedicated role, rebuilt on every run, with USAGE on the warehouse,
 *   database and schemas and point-in-time SELECT per table and view. No
 *   FUTURE grants, so new tables stay closed.
 * - Tables with secret-looking columns are skipped (Snowflake has no column
 *   grants; use a masking policy or a view).
 * - A SERVICE user with key-pair login (no password), DEFAULT_SECONDARY_ROLES
 *   = () so no other role leaks in, DAYS_TO_EXPIRY for expiry, and an
 *   optional network policy.
 */
import { anyPatternRegex, daysUntil, engineMetadata, header, normalizePublicKey, SECRET_REGEX, splitColumn } from "./common.js";
import type { AccountSpec, EnginePlan } from "./types.js";

const lit = (s: string) => `'${s.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`;
const up = (s: string) => s.toUpperCase();

export function planSnowflake(spec: AccountSpec, now: Date): EnginePlan {
  const U = up(spec.name);
  const R = up(`${spec.name}_read`);
  const DB = up(spec.database!);
  const WH = up(spec.warehouse!);
  const NP = up(`${spec.name}_network`);
  const meta = engineMetadata(spec, now);
  const key = normalizePublicKey(spec.publicKey ?? "") ?? "";
  const schemas = spec.mode === "listed"
    ? [...new Set((spec.objects ?? []).map((o) => up(o.split(".")[0]!)).filter((s) => !s.includes("*")))]
    : (spec.schemas ?? []).map(up);
  const days = daysUntil(spec.expiresAt, now);

  const full = "t.TABLE_SCHEMA || '.' || t.TABLE_NAME";
  const filter = spec.mode === "listed"
    ? `REGEXP_INSTR(${full}, ${lit(anyPatternRegex(spec.objects ?? [])!)}, 1, 1, 0, 'i') > 0`
    : [`t.TABLE_SCHEMA IN (${schemas.map(lit).join(", ")})`, ...(spec.exclude?.length ? [`REGEXP_INSTR(${full}, ${lit(anyPatternRegex(spec.exclude)!)}, 1, 1, 0, 'i') = 0`] : [])].join(" AND ");
  const allow = (spec.columnsAllow ?? []).map((c) => splitColumn(c).map(up).join("."));
  const deny = (spec.columnsDeny ?? []).map((c) => splitColumn(c).map(up).join("."));
  const colFull = "c.TABLE_SCHEMA || '.' || c.TABLE_NAME || '.' || c.COLUMN_NAME";
  let hidden = `REGEXP_INSTR(LOWER(REGEXP_REPLACE(c.COLUMN_NAME, '([a-z0-9])([A-Z])', '\\\\1_\\\\2')), '${SECRET_REGEX}') > 0`;
  if (allow.length) hidden = `(${hidden} AND UPPER(${colFull}) NOT IN (${allow.map(lit).join(", ")}))`;
  if (deny.length) hidden = `(${hidden} OR UPPER(${colFull}) IN (${deny.map(lit).join(", ")}))`;

  const setup = `${header("setup.sql: create or update the ROUA account. Run in a worksheet or SnowSQL as SECURITYADMIN:", spec, now)}-- snowsql -a ACCOUNT -u admin -r SECURITYADMIN -f setup.sql
-- Key-pair login: no password exists for this account. Give the private key to the holder through a secrets manager.
USE ROLE SECURITYADMIN;

-- 1. A fresh role every run (dropping it removes every old grant).
CREATE OR REPLACE ROLE ${R} COMMENT = ${lit(meta)};
GRANT USAGE ON WAREHOUSE ${WH} TO ROLE ${R};
GRANT USAGE ON DATABASE ${DB} TO ROLE ${R};
${schemas.map((s) => `GRANT USAGE ON SCHEMA ${DB}.${s} TO ROLE ${R};`).join("\n")}

${spec.mode === "metadata"
    ? "-- 2. Structure only (L0): REFERENCES per table and view shows columns and types. No SELECT."
    : "-- 2. SELECT per table and view, as they exist now. Tables with hidden columns are skipped and listed."}
EXECUTE IMMEDIATE $$
DECLARE
  granted INTEGER DEFAULT 0;
  skipped VARCHAR DEFAULT '';
  c1 CURSOR FOR
    SELECT t.TABLE_SCHEMA AS S, t.TABLE_NAME AS N, t.TABLE_TYPE AS K,
           (SELECT COUNT(*) FROM ${DB}.INFORMATION_SCHEMA.COLUMNS c
             WHERE c.TABLE_SCHEMA = t.TABLE_SCHEMA AND c.TABLE_NAME = t.TABLE_NAME
               AND ${hidden}) AS H
      FROM ${DB}.INFORMATION_SCHEMA.TABLES t
     WHERE t.TABLE_SCHEMA <> 'INFORMATION_SCHEMA'
       AND ${filter}
     ORDER BY 1, 2;
BEGIN
  FOR r IN c1 DO
    IF (${spec.mode === "metadata" ? "TRUE" : "r.H = 0"}) THEN
      EXECUTE IMMEDIATE 'GRANT ${spec.mode === "metadata" ? "REFERENCES" : "SELECT"} ON ' ||
        CASE r.K WHEN 'VIEW' THEN 'VIEW' WHEN 'MATERIALIZED VIEW' THEN 'MATERIALIZED VIEW' WHEN 'EXTERNAL TABLE' THEN 'EXTERNAL TABLE' WHEN 'DYNAMIC TABLE' THEN 'DYNAMIC TABLE' ELSE 'TABLE' END ||
        ' ${DB}."' || REPLACE(r.S, '"', '""') || '"."' || REPLACE(r.N, '"', '""') || '" TO ROLE ${R}';
      granted := granted + 1;
    ELSE
      skipped := skipped || r.S || '.' || r.N || ' ';
    END IF;
  END FOR;
  RETURN 'SELECT granted on ' || granted || ' objects. Skipped (hidden columns): ' || skipped;
END;
$$;

-- 3. The user: key-pair only, no secondary roles, expires in ${days} day(s).
CREATE USER IF NOT EXISTS ${U};
ALTER USER ${U} SET
  TYPE = SERVICE
  RSA_PUBLIC_KEY = ${lit(key)}
  DEFAULT_ROLE = ${R}
  DEFAULT_WAREHOUSE = ${WH}
  DEFAULT_SECONDARY_ROLES = ()
  DAYS_TO_EXPIRY = ${days}
  DISABLED = FALSE
  COMMENT = ${lit(meta)};
${spec.statementTimeoutS ? `ALTER USER ${U} SET STATEMENT_TIMEOUT_IN_SECONDS = ${spec.statementTimeoutS};\n` : ""}GRANT ROLE ${R} TO USER ${U};
${spec.allowedSources?.length ? `CREATE OR REPLACE NETWORK POLICY ${NP} ALLOWED_IP_LIST = (${spec.allowedSources.map(lit).join(", ")}) COMMENT = 'ROUA';\nALTER USER ${U} SET NETWORK_POLICY = ${NP};\n` : ""}
-- 4. Every role the user holds. It should list only ${R} (and PUBLIC, which every user has).
SHOW GRANTS TO USER ${U};
`;
  const revoke = `${header("revoke.sql: disable the account now. Disabling also aborts its running queries.", spec, now)}USE ROLE SECURITYADMIN;
ALTER USER ${U} SET DISABLED = TRUE;
REVOKE ROLE ${R} FROM USER ${U};
`;
  const drop = `${header("drop.sql: remove the account, its role and network policy.", spec, now)}USE ROLE SECURITYADMIN;
DROP USER IF EXISTS ${U};
DROP ROLE IF EXISTS ${R};
DROP NETWORK POLICY IF EXISTS ${NP};
`;
  return {
    engine: "snowflake",
    files: [
      { name: "setup.sql", run: "snowsql -a ACCOUNT -u admin -r SECURITYADMIN -f setup.sql", content: setup },
      { name: "audit.sql", run: "snowsql -a ACCOUNT -u admin -r SECURITYADMIN -f audit.sql", content: auditSnowflake(spec.name, `${spec.name}_read`, now) },
      { name: "revoke.sql", run: "snowsql -a ACCOUNT -u admin -r SECURITYADMIN -f revoke.sql", content: revoke },
      { name: "drop.sql", run: "snowsql -a ACCOUNT -u admin -r SECURITYADMIN -f drop.sql", content: drop },
    ],
    warnings: [
      "Preview: generated from Snowflake's documentation and not yet run against a live account. Review it, and please report anything that fails.",
      "Tables with secret-looking columns are skipped. Protect them with a masking policy or a secure view, then add the view to the scope.",
    ],
    manualSteps: [
      "Give the account its own small warehouse with a resource monitor, so a runaway query cannot run up costs.",
      "Every Snowflake user has a personal stage (@~) and can download query results. Read-only is not the same as no export: keep the scope to what the holder may see.",
    ],
  };
}

/** Audit any Snowflake user and its default role. */
export function auditSnowflake(user: string, role: string, now: Date = new Date()): string {
  const U = up(user);
  const R = up(role);
  return `-- audit.sql: is ${U} actually read-only? Read-only; safe to run anytime (SECURITYADMIN).
-- ROUA 0.1 audit for Snowflake (preview). Generated ${now.toISOString()} by the ROUA generator (kaizam.com).
-- Every result should say PASS.
USE ROLE SECURITYADMIN;

SHOW GRANTS TO ROLE ${R};
SELECT 'T1' AS id, 'Role ${R} has only USAGE, SELECT and REFERENCES' AS check_name,
       IFF(COUNT(*) = 0, 'PASS', 'FAIL') AS status,
       LISTAGG("granted_on" || ' ' || "name" || ': ' || "privilege", ', ') AS detail
  FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()))
 WHERE "privilege" NOT IN ('USAGE', 'SELECT', 'REFERENCES') OR "granted_on" = 'ROLE';

SHOW GRANTS TO USER ${U};
SELECT 'R1' AS id, 'User holds no other roles' AS check_name,
       IFF(COUNT(*) = 0, 'PASS', 'FAIL') AS status,
       LISTAGG("role", ', ') AS detail
  FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()))
 WHERE "role" NOT IN ('${R}', 'PUBLIC');

SHOW FUTURE GRANTS TO ROLE ${R};
SELECT 'F1' AS id, 'No future grants (new tables would become readable)' AS check_name,
       IFF(COUNT(*) = 0, 'PASS', 'FAIL') AS status, LISTAGG("name", ', ') AS detail
  FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));

DESC USER ${U};
SELECT "property" AS id, 'User setting' AS check_name,
       CASE
         WHEN "property" = 'DEFAULT_SECONDARY_ROLES' AND "value" NOT IN ('[]', '') THEN 'FAIL'
         WHEN "property" = 'DAYS_TO_EXPIRY' AND ("value" IS NULL OR "value" = 'null') THEN 'FAIL'
         WHEN "property" = 'HAS_PASSWORD' AND "value" = 'true' THEN 'WARN'
         WHEN "property" = 'NETWORK_POLICY' AND ("value" IS NULL OR "value" = 'null') THEN 'WARN'
         ELSE 'PASS' END AS status,
       "property" || ' = ' || COALESCE("value", 'null') AS detail
  FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()))
 WHERE "property" IN ('DEFAULT_SECONDARY_ROLES', 'DAYS_TO_EXPIRY', 'HAS_PASSWORD', 'NETWORK_POLICY', 'DISABLED', 'TYPE');
`;
}
