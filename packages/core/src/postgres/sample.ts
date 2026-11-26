/**
 * X2: optional value sampling for secrets in badly named columns.
 *
 * Name-based detection (X1) misses secrets stored in columns called `config`,
 * `data` or `notes`. With the administrator's explicit opt-in, this check reads
 * a few rows from each text column the audited role can read and looks for
 * well-known secret formats and long high-entropy strings.
 *
 * It is a heuristic: it reports columns, never values, and is always a warning,
 * never a guarantee. It runs plain SELECTs as the auditing (admin) connection.
 */
import type { CheckResult, Executor } from "./audit.js";
import { quoteLiteral } from "../escape.js";

export interface ValuePattern {
  name: string;
  re: RegExp;
}

export const VALUE_PATTERNS: ValuePattern[] = [
  { name: "private key (PEM)", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/ },
  { name: "JSON Web Token", re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/ },
  { name: "AWS access key ID", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { name: "GitHub token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b/ },
  { name: "Slack token", re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/ },
  { name: "Stripe secret key", re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/ },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: "password hash", re: /^\$(?:2[abxy]|argon2(?:id|i|d)|scrypt|pbkdf2(?:-sha\d+)?|[156])\$/ },
  { name: "SCRAM verifier", re: /^SCRAM-SHA-256\$\d+:/ },
  { name: "connection string with password", re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:[^\s@/]{3,}@[^\s/]+/i },
];

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Names of the secret formats found in a value (empty when none). */
export function detectSecretValue(value: string): string[] {
  const found = VALUE_PATTERNS.filter((p) => p.re.test(value)).map((p) => p.name);
  if (!found.length) {
    for (const token of value.split(/[\s"',;:=&?{}[\]()<>]+/)) {
      if (token.length >= 32 && token.length <= 512 && /^[A-Za-z0-9+/_=-]+$/.test(token) && !UUID.test(token)
          && /[0-9]/.test(token) && /[A-Za-z]/.test(token) && entropy(token) >= 4.2) {
        found.push("high-entropy string");
        break;
      }
    }
  }
  return found;
}

const qi = (s: string) => `"${s.replace(/"/g, '""')}"`;

export interface SampleOptions {
  /** Rows to read per column (default 20, max 200). */
  rows?: number;
  /** Columns to examine at most (default 300). */
  maxColumns?: number;
  /** schema.table.column entries already known to be safe. */
  allowColumns?: string[];
}

export async function sampleSecretValues(exec: Executor, role: string, opts: SampleOptions = {}): Promise<CheckResult> {
  const rows = Math.min(Math.max(opts.rows ?? 20, 1), 200);
  const maxColumns = Math.min(Math.max(opts.maxColumns ?? 300, 1), 5000);
  const allow = new Set(opts.allowColumns ?? []);
  const base = { id: "X2", title: "No secret-looking values in readable columns (sampled)" };
  const cols = await exec(
    `SELECT n.nspname AS s, c.relname AS t, a.attname AS c
       FROM pg_attribute a
       JOIN pg_class c ON c.oid = a.attrelid
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE c.relkind IN ('r', 'v', 'm', 'p', 'f') AND a.attnum > 0 AND NOT a.attisdropped
        AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\\_toast%'
        AND a.atttypid IN ('text'::regtype, 'varchar'::regtype, 'bpchar'::regtype, 'json'::regtype, 'jsonb'::regtype)
        AND has_column_privilege(${quoteLiteral(role)}, c.oid, a.attnum, 'SELECT')
      ORDER BY 1, 2, 3
      LIMIT ${maxColumns}`,
  );
  const hits: string[] = [];
  let examined = 0;
  for (const col of cols) {
    const name = `${col.s}.${col.t}.${col.c}`;
    if (allow.has(name)) continue;
    let values: Record<string, unknown>[];
    try {
      values = await exec(
        `SELECT left(${qi(String(col.c))}::text, 4000) AS v FROM ${qi(String(col.s))}.${qi(String(col.t))} WHERE ${qi(String(col.c))} IS NOT NULL LIMIT ${rows}`,
      );
    } catch {
      continue;
    }
    examined++;
    const kinds = new Map<string, number>();
    for (const r of values) for (const k of detectSecretValue(String(r.v ?? ""))) kinds.set(k, (kinds.get(k) ?? 0) + 1);
    if (kinds.size) {
      hits.push(`${name}: ${[...kinds].map(([k, n]) => `${k} (${n} of ${values.length} sampled)`).join(", ")}`);
    }
  }
  if (!hits.length) return { ...base, severity: "pass", details: [`${examined} readable text column(s) sampled, ${rows} rows each.`] };
  return {
    ...base,
    severity: "warn",
    details: [...hits.slice(0, 50), ...(hits.length > 50 ? [`... and ${hits.length - 50} more`] : [])],
    fix: "Hide these columns (scope.columns_deny) or exclude the tables. If a match is a false positive, list the column in scope.columns_allow.",
  };
}
