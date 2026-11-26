/**
 * Validation and helpers shared by every non-PostgreSQL engine planner.
 *
 * Security notes:
 * - Every name that reaches a script is checked against a strict pattern
 *   first, then quoted for the target dialect anyway.
 * - Object patterns allow only letters, digits, _, $ and *, and are turned into
 *   regular expressions without backslashes, so no dialect's string escaping
 *   can change their meaning.
 */
import { ACCOUNT_NAME_RE, IDENTIFIER_RE, PROFILES, PROFILE_INFO, ROUA_SPEC_VERSION, SECRET_COLUMN_REGEX } from "../constants.js";
import { ENGINE_INFO, ENGINES, type AccountSpec } from "./types.js";

export interface SpecValidation {
  errors: string[];
  warnings: string[];
}

const PATTERN_RE = /^[A-Za-z0-9_$*]+\.[A-Za-z0-9_$*]+$/;
const COLUMN_RE = /^[A-Za-z_][A-Za-z0-9_$]*\.[A-Za-z_][A-Za-z0-9_$]*\.[A-Za-z_][A-Za-z0-9_$]*$/;
const SAFE_TEXT_RE = /^[^\u0000-\u001f'"`\\;]*$/;
const COLLECTION_RE = /^[A-Za-z0-9_][A-Za-z0-9_.\-*]{0,119}$/;
const REDIS_PATTERN_RE = /^[A-Za-z0-9_:.\-*{}]{1,200}$/;
const BQ_PROJECT_RE = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const CIDR_RE = /^[0-9a-fA-F:.]+(\/\d{1,3})?$/;
const MYSQL_HOST_RE = /^[A-Za-z0-9.%_:\-]{1,255}$/;

export function validateSpec(spec: AccountSpec, now: Date = new Date()): SpecValidation {
  const errors: string[] = [];
  const warnings: string[] = [];
  const info = ENGINE_INFO[spec.engine];
  if (!info || spec.engine === ("postgresql" as string) || !ENGINES.includes(spec.engine)) {
    return { errors: [`Unknown engine ${JSON.stringify(spec.engine)}`], warnings };
  }
  const f = info.fields;
  if (!ACCOUNT_NAME_RE.test(spec.name ?? "")) {
    errors.push("Account name: 3 to 63 characters, lowercase letters, digits and _, starting with a letter.");
  }
  if (spec.engine === "bigquery" && !/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(spec.name.replace(/_/g, "-"))) {
    errors.push("BigQuery service account ids are 6 to 30 characters and cannot end with _.");
  }
  if (!PROFILES.includes(spec.profile)) errors.push(`Unknown profile ${JSON.stringify(spec.profile)}`);
  for (const [k, v] of [["Owner", spec.owner], ["Purpose", spec.purpose], ["Approval reference", spec.approvalRef ?? ""]] as const) {
    if (!SAFE_TEXT_RE.test(v)) errors.push(`${k} must not contain quotes, backslashes, semicolons or control characters.`);
  }
  for (const a of spec.approvedBy ?? []) if (!SAFE_TEXT_RE.test(a) || /\s/.test(a)) errors.push(`Approver ${JSON.stringify(a)} must be a single word or email.`);
  if (!spec.owner?.trim()) errors.push("Owner is required: every ROUA has an accountable person.");
  if (!spec.purpose?.trim()) errors.push("Purpose is required.");

  const exp = new Date(spec.expiresAt);
  if (Number.isNaN(exp.getTime())) errors.push("Expiry date is required.");
  else if (PROFILES.includes(spec.profile)) {
    if (exp.getTime() <= now.getTime()) errors.push("Expiry must be in the future.");
    const maxDays = PROFILE_INFO[spec.profile].maxExpiryDays;
    if (exp.getTime() - now.getTime() > (maxDays + 1) * 86_400_000) {
      errors.push(`The ${spec.profile} profile allows at most ${maxDays} days.`);
    }
  }

  const ident = (v: string | undefined, what: string) => {
    if (!v || !IDENTIFIER_RE.test(v)) errors.push(`${what} ${JSON.stringify(v ?? "")}: letters, digits, _ or $, starting with a letter or _.`);
  };
  if (spec.engine === "bigquery") {
    if (!BQ_PROJECT_RE.test(spec.database ?? "")) errors.push("Project ID: 6 to 30 lowercase letters, digits and hyphens.");
  } else if (f.database) ident(spec.database, f.database);

  if (f.schemas) {
    if (!spec.schemas?.length) errors.push(`${f.schemas}: list at least one.`);
    for (const s of spec.schemas ?? []) ident(s, f.schemas.replace(/s( \(.*\))?$/, ""));
  }

  if (!["scope", "listed", "metadata"].includes(spec.mode)) errors.push(`Unknown mode ${JSON.stringify(spec.mode)}`);
  if (spec.mode === "metadata" && "unavailable" in f.metadata) {
    errors.push(`Structure-only access (L0) is not available on ${info.name}: ${f.metadata.unavailable}`);
  }
  const objects = spec.objects ?? [];
  if (spec.mode === "listed" || spec.engine === "redis") {
    if (!objects.length) errors.push(`${f.objects}: list at least one.`);
  }
  for (const o of objects) {
    if (spec.engine === "mongodb") {
      if (!COLLECTION_RE.test(o) || o.startsWith("system.")) errors.push(`Collection ${JSON.stringify(o)} is not allowed.`);
    } else if (spec.engine === "redis") {
      if (!REDIS_PATTERN_RE.test(o)) errors.push(`Key pattern ${JSON.stringify(o)}: letters, digits and : . - _ * { } only.`);
      if (o === "*") warnings.push("The key pattern * gives read access to every key, including any that hold secrets.");
    } else if (!PATTERN_RE.test(o)) errors.push(`${JSON.stringify(o)}: expected schema.table (* allowed).`);
  }
  for (const o of spec.exclude ?? []) {
    if (spec.engine === "mongodb" ? !COLLECTION_RE.test(o) : !PATTERN_RE.test(o)) errors.push(`Exclusion ${JSON.stringify(o)} is not valid.`);
  }
  for (const c of [...(spec.columnsDeny ?? []), ...(spec.columnsAllow ?? [])]) {
    if (!COLUMN_RE.test(c)) errors.push(`Column ${JSON.stringify(c)}: expected schema.table.column.`);
  }
  if (!f.columns && (spec.columnsDeny?.length || spec.columnsAllow?.length)) {
    warnings.push(`${info.name} cannot hide individual fields by permission; the column lists are ignored.`);
  }

  if (f.password === "verifier" || f.password === "plaintext") {
    const pw = spec.password ?? "";
    if (pw.length < 16) errors.push("Use a password of at least 16 characters (or click New).");
    if (!/^[\x21-\x7e]+$/.test(pw)) errors.push("Password: printable ASCII without spaces.");
    if (/["'\\`$;]/.test(pw)) errors.push("Password must not contain quotes, backslashes, $, ` or ;. Click New for a safe one.");
  }
  if (spec.engine === "snowflake") {
    const key = normalizePublicKey(spec.publicKey ?? "");
    if (!key) errors.push("Snowflake: paste the account's RSA public key, or click Generate key pair.");
    ident(spec.warehouse, "Warehouse");
  }
  if (spec.engine === "bigquery" && !/^[A-Za-z0-9-]{2,30}$/.test(spec.location ?? "")) errors.push("Location: for example US, EU or europe-west2.");

  for (const s of spec.allowedSources ?? []) {
    const ok = spec.engine === "mysql" || spec.engine === "mariadb" ? MYSQL_HOST_RE.test(s) : CIDR_RE.test(s);
    if (!ok) errors.push(`Allowed source ${JSON.stringify(s)} is not valid.`);
  }
  if (spec.maxConnections !== undefined && !(Number.isInteger(spec.maxConnections) && spec.maxConnections >= 1 && spec.maxConnections <= 10_000)) {
    errors.push("Max connections: a whole number from 1 to 10000.");
  }
  if (spec.statementTimeoutS !== undefined && !(Number.isInteger(spec.statementTimeoutS) && spec.statementTimeoutS >= 1 && spec.statementTimeoutS <= 86_400)) {
    errors.push("Statement timeout: 1 to 86400 seconds.");
  }
  if (spec.profile === "demo" || spec.profile === "training") {
    warnings.push(`The ${spec.profile} profile should point at synthetic or anonymized data, never real customers.`);
  }
  return { errors, warnings };
}

/** The ROUA level a spec corresponds to. */
export const levelOf = (spec: AccountSpec): "L0" | "L1" | "L2" => (spec.mode === "metadata" ? "L0" : spec.mode === "listed" ? "L1" : "L2");

/** ROUA/0.1 metadata string, as stored in comments where the engine has them. */
export function engineMetadata(spec: AccountSpec, now: Date): string {
  const parts = [
    `ROUA/${ROUA_SPEC_VERSION}`,
    `profile=${spec.profile}`,
    `level=${levelOf(spec)}`,
    `owner=${spec.owner.trim()}`,
  ];
  if (spec.approvedBy?.length) parts.push(`approved_by=${spec.approvedBy.join(",")}`);
  if (spec.approvalRef?.trim()) parts.push(`approval_ref=${spec.approvalRef.trim()}`);
  parts.push(`created=${now.toISOString().slice(0, 10)}`);
  parts.push(`expires=${new Date(spec.expiresAt).toISOString()}`);
  parts.push(`purpose="${spec.purpose.replace(/\s+/g, " ").trim()}"`);
  return parts.join(" ");
}

/**
 * Anchored regex for a schema.table pattern, using character classes instead
 * of backslashes: "sales.order_*" -> ^sales[.]order_[A-Za-z0-9_$]*$
 */
export function patternRegex(pattern: string): string {
  const body = pattern.replace(/[.$*]/g, (c) => (c === "." ? "[.]" : c === "$" ? "[$]" : "[A-Za-z0-9_$]*"));
  return `^${body}$`;
}

/** One regex matching any of the patterns, or null when there are none. */
export function anyPatternRegex(patterns: readonly string[]): string | null {
  if (!patterns.length) return null;
  return patterns.map((p) => `(${patternRegex(p)})`).join("|");
}

/** The detector regex, applied to snake_case lowercase column names. */
export const SECRET_REGEX = SECRET_COLUMN_REGEX;

/**
 * The same detector as plain lists, for dialects without regular expressions
 * (SQL Server before 2025). A unit test keeps it equivalent to SECRET_REGEX.
 * Tokens must be whole words between underscores; substrings match anywhere.
 */
export const SECRET_TOKENS = [
  "pwd", "pin", "mfa", "otp", "totp", "hotp", "salt", "cvv", "cvv2", "cvc", "pan",
  "passphrase", "apikey", "privatekey", "seed", "nonce", "otpauth",
] as const;
export const SECRET_SUBSTRINGS = [
  "password", "passwd", "secret", "token", "credential",
  "api_key", "apikey", "private_key", "privatekey", "encryption_key", "encryptionkey",
  "session_key", "sessionkey", "access_key", "accesskey", "signing_key", "signingkey",
  "master_key", "masterkey", "card_num", "cardnum", "webhook_sig", "webhooksig",
  "signature_key", "signaturekey", "recovery_code", "recoverycode", "backup_code", "backupcode",
  "pass_hash", "passhash", "hashed_pass", "hashedpass",
] as const;

/** The list-based detector in JavaScript (mirrors the SQL Server predicate). */
export function isSecretByLists(name: string): boolean {
  const snake = name.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
  const padded = `_${snake}_`;
  return SECRET_TOKENS.some((t) => padded.includes(`_${t}_`)) || SECRET_SUBSTRINGS.some((s) => snake.includes(s));
}

/** Header comment for SQL-like scripts. */
export function header(title: string, spec: AccountSpec, now: Date, comment = "--"): string {
  const c = comment;
  return [
    `${c} ${title}`,
    `${c} ROUA ${ROUA_SPEC_VERSION} (draft) for ${ENGINE_INFO[spec.engine].name}. Generated ${now.toISOString()} by the ROUA generator (kaizam.com).`,
    `${c} Account: ${spec.name}   profile: ${spec.profile}   expires: ${new Date(spec.expiresAt).toISOString()}`,
    `${c} Owner: ${spec.owner.trim()}   purpose: ${spec.purpose.replace(/\s+/g, " ").trim()}`,
    ENGINE_INFO[spec.engine].support === "preview"
      ? `${c} PREVIEW: generated from vendor documentation, not yet tested against a live service. Review before running.`
      : `${c} Read it before you run it.`,
    `${c} Problems or ideas? https://github.com/PromiseGithub/roua/issues`,
    "",
  ].join("\n");
}

/** Strip PEM armour and whitespace; return the base64 body or null. */
export function normalizePublicKey(key: string): string | null {
  const body = key.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, "").replace(/\s+/g, "");
  return /^[A-Za-z0-9+/]{200,1200}={0,2}$/.test(body) ? body : null;
}

export const isoDate = (iso: string) => new Date(iso).toISOString();
/** "2027-02-21 00:00:00" in UTC. */
export const sqlTimestamp = (iso: string) => new Date(iso).toISOString().slice(0, 19).replace("T", " ");

export function daysUntil(iso: string, now: Date): number {
  return Math.max(1, Math.ceil((new Date(iso).getTime() - now.getTime()) / 86_400_000));
}

/** Split "schema.table.column". */
export function splitColumn(c: string): [string, string, string] {
  const [s, t, col] = c.split(".") as [string, string, string];
  return [s, t, col];
}
