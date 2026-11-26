/**
 * PostgreSQL planner: turns a validated roua.yaml into reviewable SQL.
 *
 * Pure: no I/O, no clock (pass `now`), no randomness (pass the password secret
 * in). The browser generator and the CLI call this same function, so for the
 * same input they produce byte-identical scripts.
 *
 * Design notes
 * - Privileges are the security boundary. `default_transaction_read_only` is
 *   set as a convenience only; any session can turn it off.
 * - The grant logic runs inside PostgreSQL (DO blocks) at apply time, so the
 *   script needs no prior introspection, sees the real columns, and hides
 *   secret-pattern columns that exist when it runs.
 * - Every apply first revokes everything the level role and the account hold,
 *   then grants exactly what the config says. Re-running is idempotent and
 *   removes drift.
 * - No ALTER DEFAULT PRIVILEGES: future tables are NOT exposed automatically
 *   (they might hold secrets). Re-run `roua apply` to pick them up.
 */

import { LEVEL_INFO, ROUA_SPEC_VERSION, SECRET_COLUMN_REGEX } from "../constants.js";
import { levelRoleOf, type RouaConfig } from "../config.js";
import {
  DOLLAR_TAG as T,
  assertNoDollarTag,
  globToRegex,
  quoteIdent,
  quoteLiteral,
  textArray,
} from "../escape.js";
import { buildMetadata } from "../metadata.js";
import { renderAuditSql } from "./audit.js";

export type PasswordSecret =
  | { kind: "scram"; verifier: string }
  | { kind: "password"; password: string }
  | { kind: "placeholder" };

export interface PlanOptions {
  now: Date;
  secret: PasswordSecret;
  /** Tool name/version written in the header. */
  generator?: string;
}

export interface Plan {
  account: string;
  levelRole: string;
  setupSql: string;
  revokeSql: string;
  dropSql: string;
  auditSql: string;
  warnings: string[];
  manualSteps: string[];
}

export const DEFAULT_LIMITS = { max_connections: 5, statement_timeout_s: 30 } as const;
export const MASKED_SCHEMA_PREFIX = "roua_masked_";

const SYSTEM_SCHEMA_FILTER =
  "n.nspname NOT IN ('pg_catalog', 'information_schema') AND left(n.nspname, 3) <> 'pg_'";

/** SQL expression: column name in snake_case, lowercased (matches isSecretColumnName). */
const SNAKE_ATTNAME = "lower(regexp_replace(a.attname, E'([a-z0-9])([A-Z])', E'\\\\1_\\\\2', 'g'))";

export function planPostgres(cfg: RouaConfig, opts: PlanOptions): Plan {
  const a = cfg.account;
  const t = cfg.target;
  const s = cfg.scope ?? {};
  const level = a.level;
  const levelRole = levelRoleOf(cfg);
  const warnings: string[] = [];
  const manualSteps: string[] = [];

  const acct = quoteIdent(a.name, "account name");
  const role = quoteIdent(levelRole, "level role");
  const db = quoteIdent(t.database, "database");
  const owner = t.object_owner ? quoteIdent(t.object_owner, "object owner") : null;
  const schemas = [...t.schemas];
  schemas.forEach((x) => quoteIdent(x, "schema"));

  const limits = { ...DEFAULT_LIMITS, ...(a.limits ?? {}) };
  const metadata = buildMetadata(cfg, opts.now);
  assertNoDollarTag(metadata);

  // ---------- password clause
  let passwordClause: string;
  switch (opts.secret.kind) {
    case "scram":
      if (!/^SCRAM-SHA-256\$\d+:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$/.test(opts.secret.verifier)) {
        throw new Error("Invalid SCRAM verifier");
      }
      passwordClause = `PASSWORD ${quoteLiteral(opts.secret.verifier)}`;
      break;
    case "password":
      passwordClause = `PASSWORD ${quoteLiteral(opts.secret.password)}`;
      warnings.push("The script contains the plaintext password. Prefer a SCRAM verifier (the default).");
      break;
    case "placeholder":
      passwordClause = "PASSWORD NULL /* replaced at apply time; NULL means password login is impossible */";
      break;
  }

  const out: string[] = [];
  const header = [
    `-- ${"=".repeat(74)}`,
    `-- ROUA/${ROUA_SPEC_VERSION} PostgreSQL setup plan`,
    `-- Account:    ${a.name}`,
    `-- Profile:    ${a.profile}`,
    `-- Level:      ${level} (${LEVEL_INFO[level].name}): ${LEVEL_INFO[level].canRead}`,
    `-- Level role: ${levelRole} (NOLOGIN, carries the grants)`,
    `-- Database:   ${t.database}   Schemas: ${schemas.join(", ")}`,
    `-- Expires:    ${new Date(a.expires_at).toISOString()}`,
    `-- Generated:  ${opts.now.toISOString()} by ${opts.generator ?? "roua"}`,
    `--`,
    `-- Run as a superuser (or the owner of every object in scope) while connected`,
    `-- to database ${t.database}. The whole script is one transaction: it either`,
    `-- fully applies or changes nothing. It is safe to run again.`,
    `--`,
    `-- Next: run audit.sql (or \`roua verify\`) before handing over credentials.`,
    `-- Problems or ideas? https://github.com/PromiseGithub/roua/issues`,
    `-- ${"=".repeat(74)}`,
  ];
  out.push(header.join("\n"), "", "BEGIN;", "");

  // ---------- 1. level role
  out.push(
    "-- 1. Level role: no login, no special attributes.",
    doBlock(
      `  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ${quoteLiteral(levelRole)}) THEN\n` +
        `    CREATE ROLE ${role} NOLOGIN;\n` +
        `  END IF;`,
    ),
    `ALTER ROLE ${role} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;`,
    `COMMENT ON ROLE ${role} IS ${quoteLiteral(`ROUA-level-role/${ROUA_SPEC_VERSION} level=${level}`)};`,
    "",
  );

  // ---------- 2. login account (created early so the reset can include it)
  out.push(
    "-- 2. Login account.",
    doBlock(
      `  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ${quoteLiteral(a.name)}) THEN\n` +
        `    CREATE ROLE ${acct} NOLOGIN;\n` +
        `  END IF;`,
    ),
    `ALTER ROLE ${acct} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT\n` +
      `  CONNECTION LIMIT ${limits.max_connections}\n` +
      `  VALID UNTIL ${quoteLiteral(new Date(a.expires_at).toISOString())}\n` +
      `  ${passwordClause};`,
    `COMMENT ON ROLE ${acct} IS ${quoteLiteral(metadata)};`,
    "",
  );

  // ---------- 3. reset
  out.push(
    "-- 3. Reset: remove every privilege and membership the level role and the",
    "--    account hold in this database, so the grants below are the whole truth.",
    doBlock(
      [
        `  r record;`,
        `  g text;`,
        `BEGIN`,
        `  FOREACH g IN ARRAY ${textArray([levelRole, a.name])} LOOP`,
        `    EXECUTE format('REVOKE ALL ON DATABASE %I FROM %I', current_database(), g);`,
        `    FOR r IN SELECT n.nspname FROM pg_namespace n WHERE ${SYSTEM_SCHEMA_FILTER} LOOP`,
        `      EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM %I', r.nspname, g);`,
        `      EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM %I', r.nspname, g);`,
        `      EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA %I FROM %I', r.nspname, g);`,
        `      EXECUTE format('REVOKE ALL ON SCHEMA %I FROM %I', r.nspname, g);`,
        `    END LOOP;`,
        `  END LOOP;`,
        `  -- The account belongs to the level role and nothing else.`,
        `  FOR r IN`,
        `    SELECT g2.rolname FROM pg_auth_members m`,
        `    JOIN pg_roles g2 ON g2.oid = m.roleid`,
        `    JOIN pg_roles u ON u.oid = m.member`,
        `    WHERE u.rolname = ${quoteLiteral(a.name)} AND g2.rolname <> ${quoteLiteral(levelRole)}`,
        `  LOOP`,
        `    EXECUTE format('REVOKE %I FROM %I', r.rolname, ${quoteLiteral(a.name)});`,
        `  END LOOP;`,
      ].join("\n"),
      true,
    ),
    "",
  );

  // ---------- 4. level grants
  out.push(`-- 4. Grants for ${level} (${LEVEL_INFO[level].name}).`);
  out.push(`GRANT CONNECT ON DATABASE ${db} TO ${role};`);

  const allSchemaInclude = schemas.map((x) => `${x}.*`);
  const deny = s.columns_deny ?? [];
  const allow = s.columns_allow ?? [];
  let readSchemas = schemas;

  if (level === "L4") {
    readSchemas = schemas.map((x) => `${MASKED_SCHEMA_PREFIX}${x}`);
    for (const ms of readSchemas) if (ms.length > 63) throw new Error(`Schema name too long for a masked schema: ${ms}`);
    out.push(...maskedViews(cfg, levelRole, s.include?.length ? s.include : allSchemaInclude, s.exclude ?? [], deny, allow));
  } else {
    for (const x of schemas) out.push(`GRANT USAGE ON SCHEMA ${quoteIdent(x)} TO ${role};`);
    if (level === "L0") {
      out.push("-- L0: schema USAGE only. Structure is visible through pg_catalog; no rows are readable.");
    } else {
      let include: string[];
      let relkinds = ["r", "p", "v", "m", "f"];
      if (level === "L1") include = s.public_objects ?? [];
      else if (level === "L3") {
        include = s.analytics_views ?? [];
        relkinds = ["v", "m"];
        warnings.push("L3: grants only the views in scope.analytics_views. Create them WITH (security_barrier) and aggregate with a minimum group size.");
      } else include = s.include?.length ? s.include : allSchemaInclude;
      const explicit = level === "L1" || level === "L3" || Boolean(s.include?.length);
      out.push(
        grantSelectBlock(levelRole, schemas, include, s.exclude ?? [], deny, allow, relkinds, (s.column_grants ?? "always") === "always", explicit, s.columns_deny ?? []),
      );
    }
  }
  out.push("");

  // ---------- 5. membership and session defaults
  out.push(
    "-- 5. Membership and session defaults (conveniences, NOT security controls).",
    `GRANT ${role} TO ${acct};`,
    `ALTER ROLE ${acct} SET default_transaction_read_only = on;`,
    `ALTER ROLE ${acct} SET statement_timeout = ${quoteLiteral(`${limits.statement_timeout_s}s`)};`,
    `ALTER ROLE ${acct} SET idle_in_transaction_session_timeout = '60s';`,
    `ALTER ROLE ${acct} SET lock_timeout = '5s';`,
    `ALTER ROLE ${acct} SET search_path = ${readSchemas.map((x) => quoteIdent(x)).join(", ")};`,
    "",
  );

  // ---------- 6. hardening (opt-in; affects every role)
  const h = cfg.hardening ?? {};
  if (h.revoke_temp_from_public || h.revoke_public_schema_create) {
    out.push("-- 6. Hardening (opt-in). These change defaults for EVERY role in the database.");
    if (h.revoke_temp_from_public) {
      out.push(
        `REVOKE TEMPORARY ON DATABASE ${db} FROM PUBLIC;`,
        "-- Roles that need temp tables must now be granted TEMPORARY explicitly.",
      );
    }
    if (h.revoke_public_schema_create) out.push(`REVOKE CREATE ON SCHEMA public FROM PUBLIC;`);
    out.push("");
  } else {
    warnings.push(
      "PUBLIC can create TEMP tables in this database by default, and this role inherits that. " +
        "Set hardening.revoke_temp_from_public: true (affects all roles) to remove it.",
    );
  }

  out.push("COMMIT;", "");

  // ---------- manual steps
  const sources = a.network?.allowed_sources ?? [];
  if (sources.length) {
    manualSteps.push(
      "Restrict where the account can connect from. Add these lines to pg_hba.conf ABOVE any broader rule, then reload:",
      ...sources.map((src) => `  hostssl ${t.database} ${a.name} ${src.includes("/") ? src : `${src}/32`} scram-sha-256`),
      `  hostssl ${t.database} ${a.name} all reject   # optional: refuse everything else`,
    );
  } else {
    warnings.push("No network.allowed_sources: the account can connect from anywhere pg_hba.conf allows.");
  }
  manualSteps.push(
    "Make sure password_encryption = 'scram-sha-256' and that no pg_hba.conf rule uses 'trust' for this account.",
    "Optional audit trail: with pgaudit installed, run ALTER ROLE " + a.name + " SET pgaudit.log = 'read';",
  );
  if (opts.secret.kind === "placeholder") manualSteps.unshift("This plan has no password. `roua apply` sets one; or replace PASSWORD NULL yourself.");

  // ---------- revoke / drop
  const revokeSql = [
    `-- ROUA/${ROUA_SPEC_VERSION} revoke: disable login and end every open session of ${a.name}.`,
    `-- Safe to run repeatedly. Requires superuser or membership in pg_signal_backend.`,
    `ALTER ROLE ${acct} NOLOGIN;`,
    `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = ${quoteLiteral(a.name)};`,
    "",
  ].join("\n");

  const dropSql = [
    `-- ROUA/${ROUA_SPEC_VERSION} drop: permanently remove ${a.name}. Run revoke.sql first.`,
    `-- Run DROP OWNED in EVERY database where the account was given access, then DROP ROLE once.`,
    `DROP OWNED BY ${acct};`,
    `DROP ROLE IF EXISTS ${acct};`,
    `-- The level role ${levelRole} may be shared with other accounts; drop it only if unused:`,
    `-- DROP OWNED BY ${role}; DROP ROLE ${role};`,
    "",
  ].join("\n");

  return {
    account: a.name,
    levelRole,
    setupSql: out.join("\n"),
    revokeSql,
    dropSql,
    auditSql: renderAuditSql(a.name),
    warnings,
    manualSteps,
  };
}

function doBlock(body: string, hasDeclare = false): string {
  if (hasDeclare) return `DO ${T}\nDECLARE\n${body}\nEND\n${T};`;
  return `DO ${T}\nBEGIN\n${body}\nEND\n${T};`;
}

/** Column filter shared by the grant and masked-view blocks. */
function hiddenColumnExpr(relRef: string): string {
  const ref = `(${relRef} || '.' || a.attname)`;
  return (
    `(${ref} = ANY (v_deny)\n` +
    `           OR (${SNAKE_ATTNAME} ~ v_secret\n` +
    `               AND NOT (${ref} = ANY (v_allow))))`
  );
}

function scopeDeclarations(levelRole: string, schemas: string[], include: string[], exclude: string[], deny: string[], allow: string[]) {
  return [
    `  v_role    text   := ${quoteLiteral(levelRole)};`,
    `  v_schemas text[] := ${textArray(schemas)};`,
    `  v_include text[] := ${textArray(include.map(globToRegex))};`,
    `  v_exclude text[] := ${textArray(exclude.map(globToRegex))};`,
    `  v_deny    text[] := ${textArray(deny)};`,
    `  v_allow   text[] := ${textArray(allow)};`,
    `  v_secret  text   := ${quoteLiteral(SECRET_COLUMN_REGEX)};`,
  ];
}

const SCOPE_TABLES = (relkinds: string[]) =>
  [
    `    SELECT n.nspname, c.relname, c.oid`,
    `    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace`,
    `    WHERE c.relkind IN (${relkinds.map((k) => `'${k}'`).join(", ")})`,
    `      AND n.nspname = ANY (v_schemas)`,
    `      AND (n.nspname || '.' || c.relname) ~ ANY (v_include)`,
    `      AND NOT ((n.nspname || '.' || c.relname) ~ ANY (v_exclude))`,
    `    ORDER BY n.nspname, c.relname`,
  ].join("\n");

function grantSelectBlock(
  levelRole: string,
  schemas: string[],
  include: string[],
  exclude: string[],
  deny: string[],
  allow: string[],
  relkinds: string[],
  perColumn: boolean,
  explicitInclude: boolean,
  userDeny: string[],
): string {
  const kinds = relkinds.map((k) => `'${k}'`).join(", ");
  const body = [
    ...scopeDeclarations(levelRole, schemas, include, exclude, deny, allow),
    `  v_listed  text[] := ${textArray(explicitInclude ? include : [])};`,
    `  v_user_deny text[] := ${textArray(userDeny)};`,
    `  v_per_column boolean := ${perColumn ? "true" : "false"};`,
    `  r record;`,
    `  v_total int;`,
    `  v_shown int;`,
    `  v_cols text;`,
    `  v_granted int := 0;`,
    `  v_i int;`,
    `BEGIN`,
    `  -- Report names that match nothing, so a typo is not silently ignored.`,
    `  FOR v_i IN 1 .. coalesce(array_length(v_listed, 1), 0) LOOP`,
    `    IF NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace`,
    `                   WHERE c.relkind IN (${kinds}) AND (n.nspname || '.' || c.relname) ~ v_include[v_i]) THEN`,
    `      RAISE WARNING 'ROUA: % matches no table or view: check the spelling', v_listed[v_i];`,
    `    END IF;`,
    `  END LOOP;`,
    `  FOR v_i IN 1 .. coalesce(array_length(v_user_deny, 1), 0) LOOP`,
    `    IF NOT EXISTS (SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace`,
    `                   WHERE a.attnum > 0 AND NOT a.attisdropped AND n.nspname || '.' || c.relname || '.' || a.attname = v_user_deny[v_i]) THEN`,
    `      RAISE WARNING 'ROUA: hidden column % does not exist (if it is spelled differently, it is NOT hidden)', v_user_deny[v_i];`,
    `    END IF;`,
    `  END LOOP;`,
    `  FOR r IN`,
    SCOPE_TABLES(relkinds),
    `  LOOP`,
    `    SELECT count(*),`,
    `           count(*) FILTER (WHERE NOT x.hidden),`,
    `           string_agg(quote_ident(x.attname), ', ' ORDER BY x.attnum) FILTER (WHERE NOT x.hidden)`,
    `      INTO v_total, v_shown, v_cols`,
    `    FROM (`,
    `      SELECT a.attname, a.attnum,`,
    `             ${hiddenColumnExpr("r.nspname || '.' || r.relname")} AS hidden`,
    `      FROM pg_attribute a`,
    `      WHERE a.attrelid = r.oid AND a.attnum > 0 AND NOT a.attisdropped`,
    `    ) x;`,
    `    IF v_shown = v_total AND NOT v_per_column THEN`,
    `      EXECUTE format('GRANT SELECT ON TABLE %I.%I TO %I', r.nspname, r.relname, v_role);`,
    `      v_granted := v_granted + 1;`,
    `    ELSIF v_shown > 0 THEN`,
    `      -- Per-column grant: columns added to this table later stay hidden until setup runs again.`,
    `      EXECUTE format('GRANT SELECT (%s) ON TABLE %I.%I TO %I', v_cols, r.nspname, r.relname, v_role);`,
    `      v_granted := v_granted + 1;`,
    `      IF v_shown < v_total THEN`,
    `        RAISE NOTICE 'ROUA: %.% readable without % hidden column(s)', r.nspname, r.relname, v_total - v_shown;`,
    `      END IF;`,
    `    ELSE`,
    `      RAISE NOTICE 'ROUA: %.% skipped: every column is hidden', r.nspname, r.relname;`,
    `    END IF;`,
    `  END LOOP;`,
    `  IF v_granted = 0 THEN`,
    `    RAISE EXCEPTION 'ROUA: the scope matched no readable tables, so the account would see nothing. Nothing was changed.'`,
    `      USING HINT = 'Check target.schemas, the listed objects and scope.exclude against the database (roua plan --check shows what matches).';`,
    `  END IF;`,
    `  RAISE NOTICE 'ROUA: SELECT granted on % table(s) and view(s)', v_granted;`,
  ].join("\n");
  return doBlock(body, true);
}

function maskedViews(
  cfg: RouaConfig,
  levelRole: string,
  include: string[],
  exclude: string[],
  deny: string[],
  allow: string[],
): string[] {
  const t = cfg.target;
  const mask = cfg.scope?.mask ?? {};
  const maskCols = Object.keys(mask).sort();
  const maskFns = maskCols.map((c) => mask[c]!);
  const usesHash = maskFns.includes("hash");
  const owner = t.object_owner;
  const out: string[] = [];
  const role = quoteIdent(levelRole);

  out.push("-- L4: base tables are NOT granted. The account reads generated views that");
  out.push("--     omit secret and denied columns and mask the columns in scope.mask.");
  out.push("--     Views use security_barrier so user-supplied functions cannot see");
  out.push("--     rows or values the view is meant to hide.");
  for (const x of t.schemas) {
    const ms = quoteIdent(`${MASKED_SCHEMA_PREFIX}${x}`);
    out.push(`CREATE SCHEMA IF NOT EXISTS ${ms};`);
    if (owner) out.push(`ALTER SCHEMA ${ms} OWNER TO ${quoteIdent(owner)};`);
    out.push(`REVOKE ALL ON SCHEMA ${ms} FROM PUBLIC;`, `GRANT USAGE ON SCHEMA ${ms} TO ${role};`);
  }
  if (usesHash) {
    out.push(
      "-- Secret key for the hash mask. Only the owner can read it, so the account",
      "-- cannot recompute hashes to guess the original values.",
      "CREATE SCHEMA IF NOT EXISTS roua_private;",
      "REVOKE ALL ON SCHEMA roua_private FROM PUBLIC;",
      "CREATE TABLE IF NOT EXISTS roua_private.mask_key (id int PRIMARY KEY CHECK (id = 1), k text NOT NULL);",
      "REVOKE ALL ON TABLE roua_private.mask_key FROM PUBLIC;",
      "INSERT INTO roua_private.mask_key (id, k)",
      "  VALUES (1, replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', ''))",
      "  ON CONFLICT (id) DO NOTHING;",
    );
    if (owner) {
      out.push(`ALTER SCHEMA roua_private OWNER TO ${quoteIdent(owner)};`, `ALTER TABLE roua_private.mask_key OWNER TO ${quoteIdent(owner)};`);
    }
  }

  const body = [
    ...scopeDeclarations(levelRole, t.schemas, include, exclude, deny, allow),
    `  v_owner   text   := ${owner ? quoteLiteral(owner) : "NULL"};`,
    `  v_mcols   text[] := ${textArray(maskCols)};`,
    `  v_mfns    text[] := ${textArray(maskFns)};`,
    `  v_masked  text[] := ARRAY(SELECT ${quoteLiteral(MASKED_SCHEMA_PREFIX)} || x FROM unnest(v_schemas) x);`,
    `  v_applied text[] := ARRAY[]::text[];`,
    `  r record;`,
    `  col record;`,
    `  v_ref text;`,
    `  v_expr text;`,
    `  v_list text;`,
    `  v_idx int;`,
    `BEGIN`,
    `  -- Drop the previous generation of masked views (they are fully managed here).`,
    `  FOR r IN SELECT n.nspname, c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace`,
    `           WHERE c.relkind = 'v' AND n.nspname = ANY (v_masked) LOOP`,
    `    EXECUTE format('DROP VIEW %I.%I', r.nspname, r.relname);`,
    `  END LOOP;`,
    `  FOR r IN`,
    SCOPE_TABLES(["r", "p", "v", "m", "f"]),
    `  LOOP`,
    `    v_list := NULL;`,
    `    FOR col IN SELECT a.attname, a.attnum, format_type(a.atttypid, a.atttypmod) AS typ,`,
    `                    ${hiddenColumnExpr("r.nspname || '.' || r.relname")} AS hidden`,
    `             FROM pg_attribute a`,
    `             WHERE a.attrelid = r.oid AND a.attnum > 0 AND NOT a.attisdropped`,
    `             ORDER BY a.attnum LOOP`,
    `      CONTINUE WHEN col.hidden;`,
    `      v_ref := r.nspname || '.' || r.relname || '.' || col.attname;`,
    `      v_idx := array_position(v_mcols, v_ref);`,
    `      IF v_idx IS NULL THEN`,
    `        v_expr := quote_ident(col.attname);`,
    `      ELSE`,
    `        v_applied := v_applied || v_ref;`,
    `        v_expr := CASE v_mfns[v_idx]`,
    `          WHEN 'email' THEN format('regexp_replace(%I::text, %L, %L)', col.attname, '^(.).*(@.*)$', E'\\\\1***\\\\2')`,
    `          WHEN 'partial_last4' THEN format('CASE WHEN %1$I IS NULL THEN NULL ELSE %2$L || right(%1$I::text, 4) END', col.attname, '***')`,
    `          WHEN 'redact' THEN format('NULL::%s', col.typ)`,
    `          WHEN 'hash' THEN format('encode(sha256(convert_to((SELECT k FROM roua_private.mask_key WHERE id = 1) || %I::text, %L)), %L)', col.attname, 'UTF8', 'hex')`,
    `          WHEN 'year_only' THEN format('date_trunc(%L, %I)::date', 'year', col.attname)`,
    `          WHEN 'initials' THEN format('regexp_replace(%I::text, %L, %L, %L)', col.attname, E'(\\\\w)\\\\w*', E'\\\\1.', 'g')`,
    `        END || ' AS ' || quote_ident(col.attname);`,
    `      END IF;`,
    `      v_list := coalesce(v_list || ', ', '') || v_expr;`,
    `    END LOOP;`,
    `    IF v_list IS NULL THEN`,
    `      RAISE NOTICE 'ROUA: %.% skipped: every column is hidden', r.nspname, r.relname;`,
    `      CONTINUE;`,
    `    END IF;`,
    `    EXECUTE format('CREATE VIEW %I.%I WITH (security_barrier = true) AS SELECT %s FROM %I.%I',`,
    `                   ${quoteLiteral(MASKED_SCHEMA_PREFIX)} || r.nspname, r.relname, v_list, r.nspname, r.relname);`,
    `    IF v_owner IS NOT NULL THEN`,
    `      EXECUTE format('ALTER VIEW %I.%I OWNER TO %I', ${quoteLiteral(MASKED_SCHEMA_PREFIX)} || r.nspname, r.relname, v_owner);`,
    `    END IF;`,
    `    EXECUTE format('GRANT SELECT ON TABLE %I.%I TO %I', ${quoteLiteral(MASKED_SCHEMA_PREFIX)} || r.nspname, r.relname, v_role);`,
    `  END LOOP;`,
    `  FOR v_idx IN 1 .. coalesce(array_length(v_mcols, 1), 0) LOOP`,
    `    IF NOT (v_mcols[v_idx] = ANY (v_applied)) THEN`,
    `      RAISE WARNING 'ROUA: mask rule for % matched no visible column', v_mcols[v_idx];`,
    `    END IF;`,
    `  END LOOP;`,
  ].join("\n");
  out.push(doBlock(body, true));
  return out;
}
