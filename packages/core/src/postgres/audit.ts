/**
 * "Is your read-only user actually read-only?"
 *
 * The auditor inspects ANY existing PostgreSQL role (ROUA or not) using only
 * catalog queries and has_*_privilege() functions. Nothing is written.
 * Run it as a superuser for the most complete picture; most checks also work
 * as the role itself.
 *
 * It considers every role the target can reach: inherited roles AND roles it
 * can switch to with SET ROLE, because a NOINHERIT membership in a writer role
 * is one SET ROLE away from writing.
 */

import { SECRET_COLUMN_REGEX, PROFILE_INFO, type Profile } from "../constants.js";
import { quoteLiteral } from "../escape.js";
import { sampleSecretValues } from "./sample.js";
import { parseMetadata } from "../metadata.js";

export type Severity = "pass" | "info" | "warn" | "fail" | "error";

export interface CheckResult {
  id: string;
  title: string;
  severity: Severity;
  details: string[];
  fix?: string;
}

export interface AuditReport {
  roua_report_version: "0.1";
  role: string;
  server_version_num: number | null;
  generated_at: string;
  results: CheckResult[];
  summary: Record<Severity, number>;
  ok: boolean;
}

/** Runs one SQL statement and returns its rows. Throws on error (with `.code` if available). */
export type Executor = (sql: string) => Promise<Record<string, unknown>[]>;

export interface AuditOptions {
  now?: Date;
  /** schema.table.column entries that are known false positives of the secret detector. */
  allowColumns?: string[];
  /** Maximum rows listed per check. */
  maxDetails?: number;
  /**
   * Opt-in X2: read this many rows from each text column the role can read and
   * look for secret formats (values are never reported). Off by default.
   */
  sampleValues?: number;
}

const SYS = (alias: string) =>
  `${alias}.nspname NOT IN ('pg_catalog', 'information_schema') AND left(${alias}.nspname, 3) <> 'pg_'`;

const SNAKE = "lower(regexp_replace(a.attname, E'([a-z0-9])([A-Z])', E'\\\\1_\\\\2', 'g'))";

/** CTEs: the target role, and every non-predefined role it can use (itself included). */
function ctes(role: string): string {
  return (
    `WITH target AS (SELECT oid, rolname FROM pg_roles WHERE rolname = ${quoteLiteral(role)}),\n` +
    `effective AS (\n` +
    `  SELECT r.oid, r.rolname FROM pg_roles r, target t\n` +
    `  WHERE pg_has_role(t.oid, r.oid, 'MEMBER') AND left(r.rolname, 3) <> 'pg_'\n` +
    `)\n`
  );
}

const FAIL_BUILTIN = [
  "pg_write_all_data",
  "pg_read_all_data",
  "pg_write_server_files",
  "pg_read_server_files",
  "pg_execute_server_program",
  "pg_signal_backend",
  "pg_create_subscription",
  "pg_checkpoint",
  "pg_maintain",
  "pg_signal_autovacuum_worker",
];
const WARN_BUILTIN = ["pg_monitor", "pg_read_all_settings", "pg_read_all_stats", "pg_stat_scan_tables", "pg_use_reserved_connections"];

interface Ctx {
  role: string;
  version: number;
  roleRow: Record<string, unknown>;
  opts: Required<Pick<AuditOptions, "maxDetails">> & AuditOptions;
  now: Date;
}

interface CheckDef {
  id: string;
  title: string;
  sql?: (ctx: Ctx) => string;
  evaluate: (rows: Record<string, unknown>[], ctx: Ctx) => Omit<CheckResult, "id" | "title">;
}

const pass = (detail?: string): Omit<CheckResult, "id" | "title"> => ({ severity: "pass", details: detail ? [detail] : [] });
const list = (rows: Record<string, unknown>[], f: (r: Record<string, unknown>) => string, max: number) => {
  const items = rows.slice(0, max).map(f);
  if (rows.length > max) items.push(`... and ${rows.length - max} more`);
  return items;
};
const bool = (v: unknown) => v === true || v === "t" || v === "true";

/** Per-role session settings (database-specific and global). */
const ROLE_SETTINGS_SQL = ({ role }: Ctx) =>
  `SELECT unnest(s.setconfig) AS setting FROM pg_db_role_setting s JOIN pg_roles r ON r.oid = s.setrole
   WHERE r.rolname = ${quoteLiteral(role)} AND s.setdatabase IN (0, (SELECT oid FROM pg_database WHERE datname = current_database()))`;

function settingValue(rows: Record<string, unknown>[], key: string): string | null {
  for (const r of rows) {
    const s = String(r.setting);
    if (s.startsWith(`${key}=`)) return s.slice(key.length + 1);
  }
  return null;
}

/** PostgreSQL duration ("30s", "5min", "1h", "30000") in milliseconds; 0 means unlimited. */
export function durationMs(v: string): number {
  const m = /^\s*(\d+(?:\.\d+)?)\s*(us|ms|s|min|h|d)?\s*$/i.exec(v);
  if (!m) return 0;
  const n = Number(m[1]);
  const unit = (m[2] ?? "ms").toLowerCase();
  return n * ({ us: 0.001, ms: 1, s: 1000, min: 60_000, h: 3_600_000, d: 86_400_000 } as Record<string, number>)[unit]!;
}

const ROLE_SQL = (role: string) =>
  `SELECT r.oid::text AS oid, r.rolname, r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls,
          r.rolcanlogin, r.rolinherit, r.rolconnlimit, r.rolvaliduntil::text AS valid_until,
          (r.rolvaliduntil IS NULL OR r.rolvaliduntil = 'infinity') AS no_expiry,
          (r.rolvaliduntil < now()) AS expired,
          extract(epoch FROM (r.rolvaliduntil - now())) / 86400 AS days_left,
          shobj_description(r.oid, 'pg_authid') AS comment
   FROM pg_roles r WHERE r.rolname = ${quoteLiteral(role)}`;

export const CHECKS: CheckDef[] = [
  {
    id: "R1",
    title: "No superuser or admin attributes",
    evaluate: (_rows, { roleRow }) => {
      const bad = ["rolsuper", "rolcreaterole", "rolcreatedb", "rolreplication", "rolbypassrls"].filter((k) => bool(roleRow[k]));
      if (!bad.length) return pass();
      const names: Record<string, string> = {
        rolsuper: "SUPERUSER (can do anything; every other check is moot)",
        rolcreaterole: "CREATEROLE (can create roles and grant itself access)",
        rolcreatedb: "CREATEDB",
        rolreplication: "REPLICATION (can stream the whole cluster)",
        rolbypassrls: "BYPASSRLS (ignores row-level security)",
      };
      return {
        severity: "fail",
        details: bad.map((k) => names[k]!),
        fix: `ALTER ROLE "${String(roleRow.rolname).replace(/"/g, '""')}" NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;`,
      };
    },
  },
  {
    id: "R2",
    title: "Account expires",
    evaluate: (_rows, { roleRow }) => {
      if (!bool(roleRow.rolcanlogin)) return { severity: "info", details: ["Role cannot log in (group role)."] };
      if (bool(roleRow.expired)) return { severity: "info", details: [`Password expired at ${roleRow.valid_until}: password logins are refused.`] };
      if (bool(roleRow.no_expiry)) {
        return {
          severity: "fail",
          details: ["No expiry (VALID UNTIL is not set). Forgotten accounts are the most common leak."],
          fix: `ALTER ROLE ... VALID UNTIL '<date>';  -- and schedule revocation (VALID UNTIL does not end open sessions)`,
        };
      }
      const days = Number(roleRow.days_left);
      const meta = parseMetadata(roleRow.comment as string | null);
      const profile = meta?.fields.profile as Profile | undefined;
      const max = profile && PROFILE_INFO[profile] ? PROFILE_INFO[profile].maxExpiryDays : 365;
      if (days > max + 1) {
        return { severity: "warn", details: [`Expires in ${Math.round(days)} days (${roleRow.valid_until}), beyond the ${max}-day maximum${profile ? ` for profile ${profile}` : ""}.`] };
      }
      return pass(`Expires ${roleRow.valid_until} (${Math.max(0, Math.round(days))} days).`);
    },
  },
  {
    id: "R3",
    title: "Connection limit set",
    evaluate: (_rows, { roleRow }) => {
      if (!bool(roleRow.rolcanlogin)) return pass();
      const n = Number(roleRow.rolconnlimit);
      return n < 0
        ? { severity: "warn", details: ["Unlimited connections."], fix: "ALTER ROLE ... CONNECTION LIMIT 5;" }
        : pass(`Connection limit ${n}.`);
    },
  },
  {
    id: "R4",
    title: "No dangerous predefined roles",
    sql: ({ role }) =>
      `SELECT b.rolname FROM pg_roles b, pg_roles t
       WHERE t.rolname = ${quoteLiteral(role)}
         AND b.rolname IN (${[...FAIL_BUILTIN, ...WARN_BUILTIN].map(quoteLiteral).join(", ")})
         AND pg_has_role(t.oid, b.oid, 'MEMBER')
       ORDER BY 1`,
    evaluate: (rows) => {
      const names = rows.map((r) => String(r.rolname));
      const fails = names.filter((n) => FAIL_BUILTIN.includes(n));
      if (fails.length) {
        return {
          severity: "fail",
          details: fails.map((n) => (n === "pg_read_all_data" ? `${n} (reads every column, including secrets)` : `${n}`)),
          fix: `REVOKE ${fails.join(", ")} FROM <role>;`,
        };
      }
      if (names.length) return { severity: "warn", details: names.map((n) => `${n} (exposes server settings or statistics)`) };
      return pass();
    },
  },
  {
    id: "R5",
    title: "Reachable roles are not privileged",
    sql: ({ role }) =>
      `${ctes(role)}SELECT e.rolname, r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls,
              pg_has_role((SELECT oid FROM target), e.oid, 'USAGE') AS inherited
       FROM effective e JOIN pg_roles r ON r.oid = e.oid
       WHERE e.oid <> (SELECT oid FROM target) ORDER BY 1`,
    evaluate: (rows, { opts }) => {
      if (!rows.length) return pass("Not a member of any other role.");
      const priv = rows.filter((r) => ["rolsuper", "rolcreaterole", "rolcreatedb", "rolreplication", "rolbypassrls"].some((k) => bool(r[k])));
      const d = list(rows, (r) => `${r.rolname}${bool(r.inherited) ? "" : " (via SET ROLE)"}${priv.includes(r) ? " has admin attributes" : ""}`, opts.maxDetails);
      return priv.length
        ? { severity: "fail", details: d, fix: "REVOKE <privileged role> FROM <role>;" }
        : { severity: "info", details: ["Member of (checked below as well):", ...d] };
    },
  },
  {
    id: "T1",
    title: "No write privileges on tables or views",
    sql: (ctx) =>
      `${ctes(ctx.role)}SELECT n.nspname, c.relname, e.rolname AS via, string_agg(p.priv, ', ' ORDER BY p.priv) AS privs
       FROM effective e
       CROSS JOIN pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
       CROSS JOIN unnest(ARRAY['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'${ctx.version >= 170000 ? ", 'MAINTAIN'" : ""}]) AS p(priv)
       WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') AND ${SYS("n")}
         AND has_table_privilege(e.oid, c.oid, p.priv)
       GROUP BY 1, 2, 3 ORDER BY 1, 2, 3 LIMIT 1000`,
    evaluate: (rows, { role, opts }) =>
      rows.length
        ? {
            severity: "fail",
            details: list(rows, (r) => `${r.nspname}.${r.relname}: ${r.privs}${r.via !== role ? ` (via ${r.via})` : ""}`, opts.maxDetails),
            fix: "REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA <schema> FROM <role>;",
          }
        : pass(),
  },
  {
    id: "T2",
    title: "No column-level write privileges",
    sql: (ctx) =>
      `${ctes(ctx.role)}SELECT n.nspname, c.relname, e.rolname AS via, string_agg(p.priv, ', ' ORDER BY p.priv) AS privs
       FROM effective e
       CROSS JOIN pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
       CROSS JOIN unnest(ARRAY['INSERT', 'UPDATE', 'REFERENCES']) AS p(priv)
       WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') AND ${SYS("n")}
         AND has_any_column_privilege(e.oid, c.oid, p.priv)
         AND NOT has_table_privilege(e.oid, c.oid, p.priv)
       GROUP BY 1, 2, 3 ORDER BY 1, 2, 3 LIMIT 1000`,
    evaluate: (rows, { role, opts }) =>
      rows.length
        ? {
            severity: "fail",
            details: list(rows, (r) => `${r.nspname}.${r.relname}: ${r.privs} on some columns${r.via !== role ? ` (via ${r.via})` : ""}`, opts.maxDetails),
            fix: "REVOKE INSERT, UPDATE, REFERENCES ON <table> FROM <role>;  -- also removes column grants",
          }
        : pass(),
  },
  {
    id: "T3",
    title: "Owns nothing",
    sql: (ctx) =>
      `${ctes(ctx.role)}SELECT kind, name, owner FROM (
         SELECT 'table/view' AS kind, n.nspname || '.' || c.relname AS name, e.rolname AS owner
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace JOIN effective e ON e.oid = c.relowner
         WHERE ${SYS("n")} AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
         UNION ALL
         SELECT 'schema', n.nspname, e.rolname FROM pg_namespace n JOIN effective e ON e.oid = n.nspowner WHERE ${SYS("n")}
         UNION ALL
         SELECT 'function', p.oid::regprocedure::text, e.rolname
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN effective e ON e.oid = p.proowner WHERE ${SYS("n")}
         UNION ALL
         SELECT 'database', d.datname, e.rolname FROM pg_database d JOIN effective e ON e.oid = d.datdba
       ) x ORDER BY 1, 2 LIMIT 1000`,
    evaluate: (rows, { opts }) =>
      rows.length
        ? {
            severity: "fail",
            details: ["Owners can ALTER, DROP and grant themselves anything on what they own:", ...list(rows, (r) => `${r.kind} ${r.name} (owned by ${r.owner})`, opts.maxDetails)],
            fix: "REASSIGN OWNED BY <role> TO <owner role>;",
          }
        : pass(),
  },
  {
    id: "S1",
    title: "Cannot create objects in any schema",
    sql: (ctx) =>
      `${ctes(ctx.role)}SELECT DISTINCT n.nspname, has_schema_privilege('public', n.oid, 'CREATE') AS via_public
       FROM effective e CROSS JOIN pg_namespace n
       WHERE ${SYS("n")} AND has_schema_privilege(e.oid, n.oid, 'CREATE') ORDER BY 1`,
    evaluate: (rows, { opts }) =>
      rows.length
        ? {
            severity: "fail",
            details: list(rows, (r) => `${r.nspname}${bool(r.via_public) ? " (granted to PUBLIC: the PostgreSQL 14-and-older default for schema public)" : ""}`, opts.maxDetails),
            fix: rows.some((r) => bool(r.via_public)) ? "REVOKE CREATE ON SCHEMA public FROM PUBLIC;" : "REVOKE CREATE ON SCHEMA <schema> FROM <role>;",
          }
        : pass(),
  },
  {
    id: "D1",
    title: "Database-level privileges",
    sql: (ctx) =>
      `${ctes(ctx.role)}SELECT current_database() AS db,
              bool_or(has_database_privilege(e.oid, current_database(), 'CREATE')) AS can_create,
              bool_or(has_database_privilege(e.oid, current_database(), 'TEMP')) AS can_temp,
              has_database_privilege('public', current_database(), 'TEMP') AS public_temp
       FROM effective e`,
    evaluate: (rows) => {
      const r = rows[0] ?? {};
      if (bool(r.can_create)) {
        return { severity: "fail", details: [`Can CREATE schemas in database ${r.db}.`], fix: `REVOKE CREATE ON DATABASE ${r.db} FROM <role>;` };
      }
      if (bool(r.can_temp)) {
        return {
          severity: "warn",
          details: [
            `Can create TEMP tables in ${r.db}${bool(r.public_temp) ? " (PostgreSQL default for PUBLIC)" : ""}.`,
            "Temp objects let a session define functions, which can be used to probe views that are not security_barrier.",
          ],
          fix: bool(r.public_temp) ? `REVOKE TEMPORARY ON DATABASE ${r.db} FROM PUBLIC;  -- affects every role` : `REVOKE TEMPORARY ON DATABASE ${r.db} FROM <role>;`,
        };
      }
      return pass();
    },
  },
  {
    id: "Q1",
    title: "Cannot advance or set sequences",
    sql: (ctx) =>
      `${ctes(ctx.role)}SELECT n.nspname || '.' || c.relname AS seq,
              bool_or(has_sequence_privilege(e.oid, c.oid, 'UPDATE')) AS upd,
              bool_or(has_sequence_privilege(e.oid, c.oid, 'USAGE')) AS usg
       FROM effective e CROSS JOIN pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE c.relkind = 'S' AND ${SYS("n")}
         AND (has_sequence_privilege(e.oid, c.oid, 'UPDATE') OR has_sequence_privilege(e.oid, c.oid, 'USAGE'))
       GROUP BY 1 ORDER BY 1 LIMIT 1000`,
    evaluate: (rows, { opts }) => {
      if (!rows.length) return pass();
      const upd = rows.filter((r) => bool(r.upd));
      if (upd.length) {
        return { severity: "fail", details: list(upd, (r) => `${r.seq}: UPDATE (setval)`, opts.maxDetails), fix: "REVOKE UPDATE, USAGE ON ALL SEQUENCES IN SCHEMA <schema> FROM <role>;" };
      }
      return { severity: "warn", details: list(rows, (r) => `${r.seq}: USAGE (nextval consumes values)`, opts.maxDetails), fix: "REVOKE USAGE ON ALL SEQUENCES IN SCHEMA <schema> FROM <role>;" };
    },
  },
  {
    id: "F1",
    title: "No executable SECURITY DEFINER functions",
    sql: (ctx) =>
      `${ctes(ctx.role)}SELECT DISTINCT p.oid::regprocedure::text AS fn, pg_get_userbyid(p.proowner) AS owner
       FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace CROSS JOIN effective e
       WHERE p.prosecdef AND ${SYS("n")} AND has_function_privilege(e.oid, p.oid, 'EXECUTE')
       ORDER BY 1 LIMIT 1000`,
    evaluate: (rows, { opts }) =>
      rows.length
        ? {
            severity: "warn",
            details: ["These run with their owner's privileges and may write. Review each one:", ...list(rows, (r) => `${r.fn} (owner ${r.owner})`, opts.maxDetails)],
            fix: "REVOKE EXECUTE ON FUNCTION <fn> FROM PUBLIC;  -- then grant it only to roles that need it",
          }
        : pass(),
  },
  {
    id: "F2",
    title: "Cannot create large objects",
    sql: ({ role }) =>
      `SELECT has_function_privilege(${quoteLiteral(role)}, 'lo_create(oid)', 'EXECUTE') AS lo_create,
              has_function_privilege(${quoteLiteral(role)}, 'lo_from_bytea(oid, bytea)', 'EXECUTE') AS lo_from_bytea,
              current_setting('lo_compat_privileges') AS compat`,
    evaluate: (rows) => {
      const r = rows[0] ?? {};
      if (r.compat === "on") {
        return { severity: "fail", details: ["lo_compat_privileges = on: any role can write every large object."], fix: "ALTER SYSTEM SET lo_compat_privileges = off;" };
      }
      if (bool(r.lo_create) || bool(r.lo_from_bytea)) {
        return {
          severity: "warn",
          details: ["Can create large objects (PostgreSQL grants lo_create to PUBLIC). This writes to pg_largeobject even with no table privileges."],
          fix: "REVOKE EXECUTE ON FUNCTION lo_create(oid), lo_creat(integer), lo_from_bytea(oid, bytea), lo_import(text), lo_import(text, oid) FROM PUBLIC;",
        };
      }
      return pass();
    },
  },
  {
    id: "X1",
    title: "No secret-pattern columns readable",
    sql: (ctx) =>
      `${ctes(ctx.role)}SELECT n.nspname || '.' || c.relname || '.' || a.attname AS col, string_agg(DISTINCT e.rolname, ', ') AS via
       FROM effective e
       CROSS JOIN pg_attribute a
       JOIN pg_class c ON c.oid = a.attrelid
       JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE a.attnum > 0 AND NOT a.attisdropped
         AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND ${SYS("n")}
         AND ${SNAKE} ~ ${quoteLiteral(SECRET_COLUMN_REGEX)}
         AND has_column_privilege(e.oid, c.oid, a.attnum, 'SELECT')
       GROUP BY 1 ORDER BY 1 LIMIT 1000`,
    evaluate: (rows, { opts }) => {
      const allowed = new Set(opts.allowColumns ?? []);
      const bad = rows.filter((r) => !allowed.has(String(r.col)));
      const ok = rows.filter((r) => allowed.has(String(r.col)));
      if (!bad.length) return ok.length ? { severity: "info", details: ok.map((r) => `${r.col} (allowed by columns_allow)`) } : pass();
      return {
        severity: "fail",
        details: ["Column names that look like secrets (best-effort detector):", ...list(bad, (r) => String(r.col), opts.maxDetails)],
        fix: "REVOKE SELECT ON <table> FROM <role>; GRANT SELECT (<safe columns>) ON <table> TO <role>;  -- or add to columns_allow if a false positive",
      };
    },
  },
  {
    id: "N1",
    title: "No foreign server access",
    sql: (ctx) =>
      `${ctes(ctx.role)}SELECT DISTINCT s.srvname FROM pg_foreign_server s CROSS JOIN effective e
       WHERE has_server_privilege(e.oid, s.oid, 'USAGE') ORDER BY 1`,
    evaluate: (rows) =>
      rows.length
        ? { severity: "warn", details: rows.map((r) => `USAGE on foreign server ${r.srvname} (may allow writes to another database)`), fix: "REVOKE USAGE ON FOREIGN SERVER <name> FROM <role>;" }
        : pass(),
  },
  {
    id: "N2",
    title: "Login rules (pg_hba.conf)",
    sql: ({ role }) =>
      `SELECT line_number, type, database, user_name, address, auth_method
       FROM pg_hba_file_rules
       WHERE error IS NULL AND (${quoteLiteral(role)} = ANY (user_name) OR 'all' = ANY (user_name))
       ORDER BY line_number`,
    evaluate: (rows, { role }) => {
      const isLoopback = (r: Record<string, unknown>) => r.type === "local" || ["127.0.0.1", "::1", "localhost", "samehost"].includes(String(r.address));
      const trust = rows.filter((r) => r.auth_method === "trust");
      const remoteTrust = trust.filter((r) => !isLoopback(r));
      const describe = (r: Record<string, unknown>) => `line ${r.line_number}: ${r.type} ${r.address ?? ""} uses trust (no password)`;
      if (remoteTrust.length) {
        return { severity: "fail", details: remoteTrust.map(describe), fix: "Use scram-sha-256 instead of trust in pg_hba.conf." };
      }
      if (trust.length) {
        return {
          severity: "warn",
          details: ["Anyone on the database host can log in as this role without a password:", ...trust.map(describe)],
          fix: "Use scram-sha-256 (or peer for local sockets) instead of trust in pg_hba.conf.",
        };
      }
      const specific = rows.filter((r) => Array.isArray(r.user_name) ? (r.user_name as string[]).includes(role) : String(r.user_name).includes(role));
      if (!specific.length) return { severity: "warn", details: ["No pg_hba.conf rule specific to this role: it can connect from wherever other users can."] };
      return pass(`${specific.length} rule(s) specific to this role.`);
    },
  },
  {
    id: "C1",
    title: "Read-only default and audit logging",
    sql: ROLE_SETTINGS_SQL,
    evaluate: (rows) => {
      const settings = rows.map((r) => String(r.setting));
      const has = (k: string) => settings.some((s) => s.startsWith(`${k}=`));
      const details: string[] = [];
      if (!has("default_transaction_read_only")) details.push("default_transaction_read_only is not on (a helpful default, though not a security control).");
      if (!has("pgaudit.log")) details.push("No pgaudit.log setting for this role, so there is no per-role record of what it queried.");
      return details.length
        ? { severity: "warn", details, fix: "ALTER ROLE <role> SET default_transaction_read_only = on; ALTER ROLE <role> SET pgaudit.log = 'read';" }
        : pass();
    },
  },
  // Resource governance: a read-only account can still hurt production with
  // long scans, idle transactions holding snapshots, or lock waits.
  {
    id: "G1",
    title: "Queries are time-limited",
    sql: ROLE_SETTINGS_SQL,
    evaluate: (rows) => {
      const v = settingValue(rows, "statement_timeout");
      const ms = v === null ? null : durationMs(v);
      if (!ms) return { severity: "warn", details: ["No statement_timeout: one query can run for hours."], fix: "ALTER ROLE <role> SET statement_timeout = '30s';" };
      if (ms > 3_600_000) return { severity: "warn", details: [`statement_timeout is ${v}, more than an hour.`], fix: "ALTER ROLE <role> SET statement_timeout = '30s';" };
      return pass(`statement_timeout = ${v}`);
    },
  },
  {
    id: "G2",
    title: "Idle transactions are ended",
    sql: ROLE_SETTINGS_SQL,
    evaluate: (rows) => {
      const v = settingValue(rows, "idle_in_transaction_session_timeout");
      return v && durationMs(v)
        ? pass(`idle_in_transaction_session_timeout = ${v}`)
        : {
            severity: "warn",
            details: ["No idle_in_transaction_session_timeout: an abandoned transaction holds its snapshot and blocks vacuum indefinitely."],
            fix: "ALTER ROLE <role> SET idle_in_transaction_session_timeout = '60s';",
          };
    },
  },
  {
    id: "G3",
    title: "Lock waits are limited",
    sql: ROLE_SETTINGS_SQL,
    evaluate: (rows) => {
      const v = settingValue(rows, "lock_timeout");
      return v && durationMs(v)
        ? pass(`lock_timeout = ${v}`)
        : { severity: "warn", details: ["No lock_timeout: a query waiting on a lock can queue other sessions behind it."], fix: "ALTER ROLE <role> SET lock_timeout = '5s';" };
    },
  },
  {
    id: "G4",
    title: "Temporary file use is limited",
    sql: ROLE_SETTINGS_SQL,
    evaluate: (rows) => {
      const v = settingValue(rows, "temp_file_limit");
      return v && v !== "-1"
        ? pass(`temp_file_limit = ${v}`)
        : {
            severity: "info",
            details: ["No temp_file_limit for this role: a large sort or hash can fill the disk. Setting it needs superuser."],
            fix: "ALTER ROLE <role> SET temp_file_limit = '1GB';",
          };
    },
  },
  {
    id: "M1",
    title: "ROUA metadata present",
    evaluate: (_rows, { roleRow }) => {
      const meta = parseMetadata(roleRow.comment as string | null);
      if (!meta) {
        return {
          severity: "warn",
          details: ["No ROUA metadata comment: nobody can tell who owns this account, why it exists, or when it should go."],
          fix: `COMMENT ON ROLE <role> IS 'ROUA/0.1 profile=agent level=L2 owner=you@example.com expires=... purpose="..."';`,
        };
      }
      const missing = ["profile", "level", "owner", "expires"].filter((k) => !meta.fields[k]);
      if (missing.length) return { severity: "warn", details: [`ROUA metadata is missing: ${missing.join(", ")}`] };
      const f = meta.fields;
      return pass(`ROUA/${meta.version} profile=${f.profile} level=${f.level} owner=${f.owner}${f.approved_by ? ` approved_by=${f.approved_by}` : ""}`);
    },
  },
];

function summarize(results: CheckResult[]): Record<Severity, number> {
  const s: Record<Severity, number> = { pass: 0, info: 0, warn: 0, fail: 0, error: 0 };
  for (const r of results) s[r.severity]++;
  return s;
}

export async function getServerVersion(exec: Executor): Promise<number | null> {
  try {
    const rows = await exec("SELECT current_setting('server_version_num')::int AS v");
    return Number(rows[0]?.v) || null;
  } catch {
    return null;
  }
}

/** Audit one role. Read-only: issues SELECT statements only. */
export async function auditRole(exec: Executor, role: string, options: AuditOptions = {}): Promise<AuditReport> {
  const now = options.now ?? new Date();
  const opts = { maxDetails: 25, ...options };
  const version = await getServerVersion(exec);
  const base = { roua_report_version: "0.1" as const, role, server_version_num: version, generated_at: now.toISOString() };

  const roleRows = await exec(ROLE_SQL(role));
  const roleRow = roleRows[0];
  if (!roleRow) {
    const results: CheckResult[] = [{ id: "R0", title: "Role exists", severity: "fail", details: [`Role ${role} does not exist.`] }];
    return { ...base, results, summary: summarize(results), ok: false };
  }
  const ctx: Ctx = { role, version: version ?? 0, roleRow, opts, now };

  const results: CheckResult[] = [];
  for (const check of CHECKS) {
    try {
      const rows = check.sql ? await exec(check.sql(ctx)) : [];
      results.push({ id: check.id, title: check.title, ...check.evaluate(rows, ctx) });
    } catch (e) {
      const err = e as { message?: string; code?: string };
      const denied = err.code === "42501";
      results.push({
        id: check.id,
        title: check.title,
        severity: denied ? "warn" : "error",
        details: [denied ? "Could not run this check with the current connection's privileges (run as a superuser for full coverage)." : `Check failed to run: ${err.message ?? String(e)}`],
      });
    }
  }
  if (opts.sampleValues) {
    try {
      results.push(await sampleSecretValues(exec, role, { rows: opts.sampleValues, allowColumns: opts.allowColumns }));
    } catch (e) {
      results.push({ id: "X2", title: "No secret-looking values in readable columns (sampled)", severity: "error", details: [`Sampling failed: ${(e as Error).message}`] });
    }
  }
  const summary = summarize(results);
  return { ...base, results, summary, ok: summary.fail === 0 && summary.error === 0 };
}

/**
 * A standalone SQL script that runs the same catalog checks, for people who
 * do not want to install anything: paste it into psql as a superuser.
 * Every query should return zero rows (except the informational ones).
 */
export function renderAuditSql(role: string): string {
  const fakeCtx: Ctx = { role, version: 160000, roleRow: {}, opts: { maxDetails: 25 }, now: new Date(0) };
  const parts = [
    `-- ROUA/0.1 audit for role ${role}`,
    `-- Read-only: SELECT statements only. Run in psql as a superuser, connected to the`,
    `-- database you want to check. For a scored report, use: roua audit --role ${role}`,
    `-- MAINTAIN (PostgreSQL 17+) is not included below; the CLI adds it automatically.`,
    "",
    `-- Role attributes and expiry: rolsuper, rolcreaterole, rolcreatedb, rolreplication and`,
    `-- rolbypassrls should all be false; valid_until should be set.`,
    `${ROLE_SQL(role)};`,
    "",
  ];
  const printed = new Map<string, string>();
  for (const c of CHECKS) {
    if (!c.sql) continue;
    const sql = c.sql(fakeCtx).replace(/\n {7}/g, "\n");
    const first = printed.get(sql);
    if (first) {
      parts.push(`-- ${c.id}: ${c.title} (see the ${first} query above)`, "");
      continue;
    }
    printed.set(sql, c.id);
    parts.push(`-- ${c.id}: ${c.title}`, `${sql};`, "");
  }
  return parts.join("\n");
}
