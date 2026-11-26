import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline/promises";
import { parseArgs } from "node:util";
import {
  LEVEL_INFO,
  PROFILE_INFO,
  PROFILES,
  LEVELS,
  ROUA_SPEC_VERSION,
  auditRole,
  formatReport,
  toJunit,
  toSarif,
  generatePassword,
  parseMetadata,
  planPostgres,
  quoteIdent,
  quoteLiteral,
  scramSha256Verifier,
  verifyCurrentUser,
  type AuditReport,
  type PasswordSecret,
  type Profile,
  type Level,
} from "@roua-dev/core";
import { connect, redactUrl, urlForUser, urlFromEnv, UsageError } from "./db.js";
import { loadConfig } from "./config-file.js";

export const VERSION = "0.4.0";

const HELP = `roua ${VERSION}: Read-Only User Accounts for PostgreSQL (ROUA spec ${ROUA_SPEC_VERSION}, draft)

Is your read-only user actually read-only?

  roua audit  --role <name> [--role <name> ...] | --all     Audit existing roles (run as admin)
  roua verify [-f roua.yaml]                                Verify while connected AS the account
  roua init   [--profile agent] [--level L2] [--name ...]   Write a starter roua.yaml
  roua plan   [-f roua.yaml] [--out dir]                    Print the SQL; changes nothing
  roua apply  [-f roua.yaml] [--yes] [--secret-out file]    Create/update the account, then verify it
  roua rotate <account> [--secret-out file] [--end-sessions] Give the account a new password
  roua revoke <account> [--drop] [--yes]                    Disable login and end open sessions
  roua list                                                 List ROUA accounts and their expiry
  roua expire --due [--dry-run]                             Revoke every ROUA account past its expiry
  roua mcp                                                  Run the ROUA MCP server on stdio (for AI agents)

Connections (read from environment variables, never from arguments):
  audit, list, apply, revoke, expire   --url-env NAME   default ADMIN_DATABASE_URL
  verify                               --url-env NAME   default ROUA_DATABASE_URL

Output: --json for machine-readable reports, --strict to fail on warnings, --no-color.
Audit:  --sarif-out FILE (GitHub code scanning), --junit-out FILE (CI test reports),
        --sample-values N (opt-in: sample N rows per readable text column for secret-looking values).
Exit codes: 0 ok, 1 checks failed, 2 usage or connection error.

Docs, spec and issues: https://github.com/PromiseGithub/roua
Feedback and ideas welcome: https://github.com/PromiseGithub/roua/discussions
`;

interface Io {
  out: (s: string) => void;
  err: (s: string) => void;
  confirm: (question: string) => Promise<boolean>;
  color: boolean;
}

const defaultIo = (): Io => ({
  out: (s) => process.stdout.write(s + "\n"),
  err: (s) => process.stderr.write(s + "\n"),
  confirm: async (q) => {
    if (!process.stdin.isTTY) return false;
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    const a = await rl.question(`${q} [y/N] `);
    rl.close();
    return /^y(es)?$/i.test(a.trim());
  },
  color: Boolean(process.stdout.isTTY) && !process.env.NO_COLOR,
});

export async function main(argv: string[], io: Io = defaultIo()): Promise<number> {
  const [cmd, ...rest] = argv;
  try {
    switch (cmd) {
      case "audit":
        return await cmdAudit(rest, io);
      case "verify":
        return await cmdVerify(rest, io);
      case "mcp": {
        const { serveMcp } = await import("./mcp.js");
        await serveMcp(VERSION);
        return 0;
      }
      case "init":
        return cmdInit(rest, io);
      case "plan":
        return await cmdPlan(rest, io);
      case "apply":
        return await cmdApply(rest, io);
      case "rotate":
        return await cmdRotate(rest, io);
      case "revoke":
        return await cmdRevoke(rest, io);
      case "list":
        return await cmdList(rest, io);
      case "expire":
        return await cmdExpire(rest, io);
      case "--version":
      case "-v":
        io.out(VERSION);
        return 0;
      case undefined:
      case "help":
      case "--help":
      case "-h":
        io.out(HELP);
        return 0;
      default:
        throw new UsageError(`Unknown command "${cmd}". Run roua --help.`);
    }
  } catch (e) {
    if (e instanceof UsageError) {
      io.err(`roua: ${e.message}`);
      return 2;
    }
    const err = e as { code?: string; message?: string };
    if (err.code === "ECONNREFUSED" || err.code === "ENOTFOUND" || err.code === "28P01" || err.code === "3D000") {
      io.err(`roua: could not connect: ${err.message}`);
      return 2;
    }
    io.err(`roua: ${err.message ?? String(e)}`);
    return 2;
  }
}

const COMMON = {
  json: { type: "boolean" },
  strict: { type: "boolean" },
  "no-color": { type: "boolean" },
  "url-env": { type: "string" },
} as const;

function parse<T extends Record<string, { type: "string" | "boolean"; multiple?: boolean; short?: string }>>(args: string[], options: T) {
  try {
    return parseArgs({ args, options: { ...COMMON, ...options }, allowPositionals: true, strict: true });
  } catch (e) {
    throw new UsageError((e as Error).message);
  }
}

function exitCodeFor(reports: AuditReport[], strict: boolean): number {
  return reports.every((r) => r.ok && (!strict || r.summary.warn === 0)) ? 0 : 1;
}

function printReports(reports: AuditReport[], io: Io, values: { json?: boolean; "no-color"?: boolean }) {
  if (values.json) {
    io.out(JSON.stringify(reports.length === 1 ? reports[0] : reports, null, 2));
    return;
  }
  const color = io.color && !values["no-color"];
  io.out(reports.map((r) => formatReport(r, { color })).join("\n\n" + "-".repeat(60) + "\n\n"));
}

// ---------------------------------------------------------------- audit
async function cmdAudit(args: string[], io: Io): Promise<number> {
  const { values } = parse(args, {
    role: { type: "string", multiple: true },
    all: { type: "boolean" },
    "sample-values": { type: "string" },
    "sarif-out": { type: "string" },
    "junit-out": { type: "string" },
  });
  const sample = values["sample-values"] === undefined ? 0 : Number(values["sample-values"]);
  if (!Number.isInteger(sample) || sample < 0 || sample > 200) throw new UsageError("--sample-values takes a number of rows from 1 to 200.");
  const roles = values.role ?? [];
  if (!roles.length && !values.all) throw new UsageError("Pass --role <name> (repeatable) or --all.");
  const conn = await connect(urlFromEnv(values["url-env"] ?? "ADMIN_DATABASE_URL"));
  try {
    let targets = roles;
    if (values.all) {
      const rows = await conn.exec(
        "SELECT rolname FROM pg_roles WHERE rolcanlogin AND NOT rolsuper AND rolname <> current_user AND left(rolname, 3) <> 'pg_' ORDER BY 1",
      );
      targets = [...new Set([...roles, ...rows.map((r) => String(r.rolname))])];
      if (!targets.length) {
        io.err("No non-superuser login roles found.");
        return 0;
      }
    }
    const reports: AuditReport[] = [];
    for (const role of targets) reports.push(await auditRole(conn.exec, role, { sampleValues: sample || undefined }));
    printReports(reports, io, values);
    if (values["sarif-out"]) writeFileSync(values["sarif-out"], toSarif(reports, { version: VERSION }));
    if (values["junit-out"]) writeFileSync(values["junit-out"], toJunit(reports, { strict: Boolean(values.strict) }));
    if (!values.json && reports.length > 1) {
      const bad = reports.filter((r) => !r.ok).map((r) => r.role);
      io.out(`\n${reports.length} role(s) audited. ${bad.length ? `Not read-only: ${bad.join(", ")}` : "All read-only."}`);
    }
    return exitCodeFor(reports, Boolean(values.strict));
  } finally {
    await conn.close();
  }
}

// ---------------------------------------------------------------- verify
async function cmdVerify(args: string[], io: Io): Promise<number> {
  const { values } = parse(args, { file: { type: "string", short: "f" } });
  const config = values.file ? loadConfig(values.file).config : existsSync("roua.yaml") ? loadConfig("roua.yaml").config : undefined;
  const conn = await connect(urlFromEnv(values["url-env"] ?? "ROUA_DATABASE_URL"));
  try {
    const report = await verifyCurrentUser(conn.exec, { config });
    printReports([report], io, values);
    return exitCodeFor([report], Boolean(values.strict));
  } finally {
    await conn.close();
  }
}

// ---------------------------------------------------------------- init
function cmdInit(args: string[], io: Io): number {
  const { values } = parse(args, {
    profile: { type: "string" },
    level: { type: "string" },
    name: { type: "string" },
    database: { type: "string" },
    owner: { type: "string" },
    file: { type: "string", short: "f" },
    force: { type: "boolean" },
  });
  const profile = (values.profile ?? "agent") as Profile;
  if (!PROFILES.includes(profile)) throw new UsageError(`--profile must be one of ${PROFILES.join(", ")}`);
  const level = (values.level ?? PROFILE_INFO[profile].defaultLevel) as Level;
  if (!LEVELS.includes(level)) throw new UsageError(`--level must be one of ${LEVELS.join(", ")}`);
  const file = values.file ?? "roua.yaml";
  if (existsSync(file) && !values.force) throw new UsageError(`${file} exists. Use --force to overwrite.`);
  const expires = new Date(Date.now() + PROFILE_INFO[profile].defaultExpiryDays * 86_400_000);
  expires.setUTCHours(0, 0, 0, 0);
  const yaml = initYaml({
    profile,
    level,
    name: values.name ?? `roua_${profile}_example`,
    database: values.database ?? "appdb",
    owner: values.owner ?? "you@example.com",
    expires: expires.toISOString(),
  });
  writeFileSync(file, yaml);
  io.out(`Wrote ${file} (profile ${profile}, level ${level}: ${LEVEL_INFO[level].name}). Edit it, then run: roua plan`);
  return 0;
}

export function initYaml(v: { profile: string; level: Level; name: string; database: string; owner: string; expires: string }): string {
  const scopeByLevel: Record<Level, string> = {
    L0: "scope: {}",
    L1: 'scope:\n  public_objects: ["public.products", "public.categories"]',
    L2: 'scope:\n  exclude: ["public.salaries", "public.api_keys"]\n  columns_deny: ["public.users.national_id"]',
    L3: 'scope:\n  analytics_views: ["public.sales_by_month"]',
    L4: 'scope:\n  exclude: ["public.api_keys"]\n  mask:\n    public.users.email: email\n    public.users.phone: partial_last4\n    public.users.date_of_birth: year_only',
    L5: 'scope:\n  exclude: ["public.api_keys"]',
  };
  return `# ROUA ${ROUA_SPEC_VERSION} account definition. Spec: https://github.com/PromiseGithub/roua/blob/main/SPEC.md
# Never put a password in this file.
roua_version: "${ROUA_SPEC_VERSION}"

account:
  name: ${v.name}
  profile: ${v.profile}            # ${PROFILES.join(" | ")}
  level: ${v.level}                # L0 metadata | L1 public | L2 operational | L3 analytical | L4 masked | L5 break-glass
  owner: ${v.owner}
  approved_by: ${v.level === "L5" ? "[first-approver@example.com, second-approver@example.com]" : "approver@example.com"}
  approval_ref: TICKET-123
  purpose: "Describe why this account exists"
  expires_at: "${v.expires}"
  limits:
    max_connections: 5
    statement_timeout_s: 30
  network:
    allowed_sources: []          # e.g. ["10.0.0.0/24"]; printed as pg_hba.conf lines

target:
  engine: postgresql
  database: ${v.database}
  schemas: [public]
  object_owner: app_owner        # role that owns your tables (owns masked views at L4)

${scopeByLevel[v.level]}

hardening:
  revoke_temp_from_public: false # true removes TEMP from PUBLIC (affects every role)

auth:
  method: scram_verifier
  password_env: ROUA_PASSWORD    # optional; a strong password is generated if unset
`;
}

// ---------------------------------------------------------------- plan
async function secretFor(config: ReturnType<typeof loadConfig>["config"], allowGenerate: boolean): Promise<{ secret: PasswordSecret; password?: string; generated: boolean }> {
  const envName = config.auth?.password_env ?? "ROUA_PASSWORD";
  let password = process.env[envName];
  let generated = false;
  if (!password) {
    if (!allowGenerate) return { secret: { kind: "placeholder" }, generated };
    password = generatePassword(32);
    generated = true;
  }
  if (config.auth?.method === "password") return { secret: { kind: "password", password }, password, generated };
  return { secret: { kind: "scram", verifier: await scramSha256Verifier(password) }, password, generated };
}

async function cmdPlan(args: string[], io: Io): Promise<number> {
  const { values } = parse(args, { file: { type: "string", short: "f" }, out: { type: "string" } });
  const { config, warnings } = loadConfig(values.file ?? "roua.yaml");
  const { secret } = await secretFor(config, false);
  const plan = planPostgres(config, { now: new Date(), secret, generator: `roua ${VERSION}` });
  if (values.out) {
    mkdirSync(values.out, { recursive: true });
    const files = { "setup.sql": plan.setupSql, "revoke.sql": plan.revokeSql, "drop.sql": plan.dropSql, "audit.sql": plan.auditSql };
    for (const [name, content] of Object.entries(files)) writeFileSync(join(values.out, name), content, { mode: 0o600 });
    io.out(`Wrote ${Object.keys(files).join(", ")} to ${values.out}`);
  } else {
    io.out(plan.setupSql);
  }
  printNotes([...warnings, ...plan.warnings], plan.manualSteps, io);
  return 0;
}

function printNotes(warnings: string[], manual: string[], io: Io) {
  if (warnings.length) io.err(`\nWarnings:\n${warnings.map((w) => `  - ${w}`).join("\n")}`);
  if (manual.length) io.err(`\nManual steps:\n${manual.map((m) => (m.startsWith("  ") ? `  ${m}` : `  - ${m}`)).join("\n")}`);
}

// ---------------------------------------------------------------- apply
async function cmdApply(args: string[], io: Io): Promise<number> {
  const { values } = parse(args, { file: { type: "string", short: "f" }, yes: { type: "boolean", short: "y" }, "secret-out": { type: "string" } });
  const { config, warnings } = loadConfig(values.file ?? "roua.yaml");
  const adminUrl = urlFromEnv(values["url-env"] ?? "ADMIN_DATABASE_URL");
  const { secret, password, generated } = await secretFor(config, true);
  const plan = planPostgres(config, { now: new Date(), secret, generator: `roua ${VERSION}` });

  io.err(plan.setupSql.replace(/PASSWORD '[^']*'/g, "PASSWORD '<redacted>'"));
  printNotes([...warnings, ...plan.warnings], [], io);
  io.err(`\nTarget: ${redactUrl(adminUrl)}`);
  if (!values.yes && !(await io.confirm(`Apply this plan for ${config.account.name}?`))) {
    io.err("Aborted. Nothing was changed.");
    return 2;
  }

  const admin = await connect(adminUrl, { onNotice: (m) => io.err(`  notice: ${m}`) });
  try {
    await admin.script(plan.setupSql);
  } finally {
    await admin.close();
  }
  io.err(`\nApplied. Verifying as ${config.account.name}...\n`);

  // Verify while connected AS the new account (the only way to prove it).
  let report: AuditReport;
  try {
    const self = await connect(urlForUser(adminUrl, config.account.name, password!));
    try {
      report = await verifyCurrentUser(self.exec, { config });
    } finally {
      await self.close();
    }
  } catch (e) {
    io.err(`Could not log in as ${config.account.name} (${(e as Error).message}). Falling back to the admin-side audit.`);
    io.err("Check pg_hba.conf, then run `roua verify` with ROUA_DATABASE_URL set.\n");
    const a = await connect(adminUrl);
    try {
      report = await auditRole(a.exec, config.account.name, { allowColumns: config.scope?.columns_allow });
    } finally {
      await a.close();
    }
  }
  printReports([report], io, values);
  if (!report.ok) {
    io.err(`\nVerification FAILED. Do not hand over credentials. Revoke with: roua revoke ${config.account.name}`);
    return 1;
  }

  printNotes([], plan.manualSteps, io);
  if (generated) {
    if (values["secret-out"]) {
      writeFileSync(values["secret-out"], password + "\n", { mode: 0o600, flag: "wx" });
      io.err(`\nPassword written to ${values["secret-out"]} (mode 600). Move it to a password manager, then delete the file.`);
    } else {
      io.err("\nPassword (shown once; store it in a password manager, never in chat or email):");
      io.out(password!);
    }
  }
  return exitCodeFor([report], Boolean(values.strict));
}

// ---------------------------------------------------------------- revoke
async function cmdRevoke(args: string[], io: Io): Promise<number> {
  const { values, positionals } = parse(args, { drop: { type: "boolean" }, yes: { type: "boolean", short: "y" } });
  const account = positionals[0];
  if (!account) throw new UsageError("Usage: roua revoke <account> [--drop]");
  const ident = quoteIdent(account, "account");
  const conn = await connect(urlFromEnv(values["url-env"] ?? "ADMIN_DATABASE_URL"));
  try {
    const exists = await conn.exec(`SELECT 1 FROM pg_roles WHERE rolname = ${quoteLiteral(account)}`);
    if (!exists.length) throw new UsageError(`Role ${account} does not exist.`);
    await revokeRole(conn.exec, account);
    io.out(`Revoked ${account}: login disabled and open sessions terminated.`);
    if (values.drop) {
      if (!values.yes && !(await io.confirm(`Permanently drop role ${account}? This cannot be undone.`))) {
        io.err("Not dropped.");
        return 0;
      }
      await conn.exec(`DROP OWNED BY ${ident}`);
      await conn.exec(`DROP ROLE ${ident}`);
      io.out(`Dropped ${account}. If it had access to other databases, run DROP OWNED BY ${ident} there first.`);
    }
    return 0;
  } finally {
    await conn.close();
  }
}

// ---------------------------------------------------------------- rotate
async function cmdRotate(args: string[], io: Io): Promise<number> {
  const { values, positionals } = parse(args, {
    "secret-out": { type: "string" },
    "end-sessions": { type: "boolean" },
    force: { type: "boolean" },
  });
  const account = positionals[0];
  if (!account) throw new UsageError("Usage: roua rotate <account> [--secret-out file] [--end-sessions]");
  const ident = quoteIdent(account, "account");
  const conn = await connect(urlFromEnv(values["url-env"] ?? "ADMIN_DATABASE_URL"));
  try {
    const rows = await conn.exec(`SELECT rolcanlogin, shobj_description(oid, 'pg_authid') AS comment FROM pg_roles WHERE rolname = ${quoteLiteral(account)}`);
    if (!rows.length) throw new UsageError(`Role ${account} does not exist.`);
    const comment = (rows[0]!.comment as string | null) ?? "";
    if (!parseMetadata(comment) && !values.force) throw new UsageError(`${account} has no ROUA metadata. Pass --force to rotate it anyway.`);
    if (!rows[0]!.rolcanlogin) throw new UsageError(`${account} cannot log in (revoked). Re-apply it instead of rotating.`);
    const password = generatePassword(32);
    const verifier = await scramSha256Verifier(password);
    await conn.exec(`ALTER ROLE ${ident} PASSWORD ${quoteLiteral(verifier)}`);
    if (comment && parseMetadata(comment)) {
      const today = new Date().toISOString().slice(0, 10);
      const updated = / rotated=\S+/.test(comment) ? comment.replace(/ rotated=\S+/, ` rotated=${today}`) : comment.replace(/ purpose=/, ` rotated=${today} purpose=`);
      await conn.exec(`COMMENT ON ROLE ${ident} IS ${quoteLiteral(updated)}`);
    }
    if (values["end-sessions"]) {
      await conn.exec(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = ${quoteLiteral(account)}`);
    }
    if (values["secret-out"]) {
      writeFileSync(values["secret-out"], password + "\n", { mode: 0o600 });
      io.out(`Rotated ${account}. The new password is in ${values["secret-out"]} (owner-only). Move it to a password manager, then delete the file.`);
    } else {
      io.out(`Rotated ${account}. New password (shown once, store it in a password manager now):\n\n  ${password}\n`);
    }
    io.out(values["end-sessions"] ? "Open sessions were ended." : "Open sessions keep working until they disconnect; pass --end-sessions to end them now.");
    return 0;
  } finally {
    await conn.close();
  }
}

async function revokeRole(exec: (sql: string) => Promise<unknown>, account: string) {
  await exec(`ALTER ROLE ${quoteIdent(account, "account")} NOLOGIN`);
  await exec(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = ${quoteLiteral(account)}`);
}

// ---------------------------------------------------------------- list / expire
interface RouaRole {
  name: string;
  canLogin: boolean;
  validUntil: string | null;
  fields: Record<string, string>;
  isRoua: boolean;
}

async function listRoles(exec: (sql: string) => Promise<Record<string, unknown>[]>): Promise<RouaRole[]> {
  const rows = await exec(
    `SELECT rolname, rolcanlogin, rolvaliduntil::text AS valid_until, shobj_description(oid, 'pg_authid') AS comment
     FROM pg_roles WHERE left(rolname, 5) = 'roua_' OR shobj_description(oid, 'pg_authid') LIKE 'ROUA/%' ORDER BY 1`,
  );
  return rows
    .map((r) => {
      const meta = parseMetadata(r.comment as string | null);
      return { name: String(r.rolname), canLogin: Boolean(r.rolcanlogin), validUntil: (r.valid_until as string) ?? null, fields: meta?.fields ?? {}, isRoua: Boolean(meta) };
    })
    .filter((r) => r.isRoua);
}

function expiryOf(r: RouaRole): Date | null {
  const s = r.fields.expires ?? r.validUntil;
  if (!s || s === "infinity") return null;
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}

async function cmdList(args: string[], io: Io): Promise<number> {
  const { values } = parse(args, {});
  const conn = await connect(urlFromEnv(values["url-env"] ?? "ADMIN_DATABASE_URL"));
  try {
    const roles = await listRoles(conn.exec);
    if (values.json) {
      io.out(JSON.stringify(roles, null, 2));
      return 0;
    }
    if (!roles.length) {
      io.out("No ROUA accounts found.");
      return 0;
    }
    const now = Date.now();
    const rows = roles.map((r) => {
      const exp = expiryOf(r);
      const status = !r.canLogin ? "revoked" : !exp ? "NO EXPIRY" : exp.getTime() < now ? "EXPIRED (still enabled)" : `${Math.ceil((exp.getTime() - now) / 86_400_000)}d left`;
      return [r.name, r.fields.profile ?? "?", r.fields.level ?? "?", r.fields.owner ?? "?", status];
    });
    const head = ["ACCOUNT", "PROFILE", "LEVEL", "OWNER", "STATUS"];
    const widths = head.map((h, i) => Math.max(h.length, ...rows.map((r) => r[i]!.length)));
    for (const r of [head, ...rows]) io.out(r.map((c, i) => c.padEnd(widths[i]!)).join("  "));
    return 0;
  } finally {
    await conn.close();
  }
}

async function cmdExpire(args: string[], io: Io): Promise<number> {
  const { values } = parse(args, { due: { type: "boolean" }, "dry-run": { type: "boolean" } });
  if (!values.due) throw new UsageError("Usage: roua expire --due [--dry-run]   (meant for cron)");
  const conn = await connect(urlFromEnv(values["url-env"] ?? "ADMIN_DATABASE_URL"));
  try {
    const now = Date.now();
    const due = (await listRoles(conn.exec)).filter((r) => {
      const exp = expiryOf(r);
      return r.canLogin && exp && exp.getTime() <= now;
    });
    for (const r of due) {
      if (values["dry-run"]) io.out(`would revoke ${r.name} (expired ${r.fields.expires ?? r.validUntil})`);
      else {
        await revokeRole(conn.exec, r.name);
        io.out(`revoked ${r.name} (expired ${r.fields.expires ?? r.validUntil})`);
      }
    }
    if (!due.length) io.out("Nothing to expire.");
    return 0;
  } finally {
    await conn.close();
  }
}
