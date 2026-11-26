/**
 * roua.yaml: the account definition, and its validation.
 * Validation is hand-written (zero dependencies) and mirrors schemas/roua.schema.json.
 */

import {
  ACCOUNT_NAME_RE,
  IDENTIFIER_RE,
  L5_MAX_HOURS,
  LEVELS,
  LEVEL_INFO,
  MASK_FUNCTIONS,
  PROFILES,
  PROFILE_INFO,
  ROUA_SPEC_VERSION,
  type Level,
  type MaskFunction,
  type Profile,
} from "./constants.js";
import { DOLLAR_TAG, globToRegex } from "./escape.js";

export interface RouaConfig {
  roua_version: string;
  account: {
    name: string;
    profile: Profile;
    level: Level;
    owner: string;
    purpose: string;
    approved_by?: string | string[];
    approval_ref?: string;
    expires_at: string;
    /** NOLOGIN role that carries the grants. Defaults to the level's standard role. */
    level_role?: string;
    limits?: { max_connections?: number; statement_timeout_s?: number };
    network?: { allowed_sources?: string[] };
  };
  target: {
    engine: "postgresql";
    database: string;
    schemas: string[];
    /** Role that owns the tables; masked views are owned by it. */
    object_owner?: string;
  };
  scope?: {
    include?: string[];
    exclude?: string[];
    public_objects?: string[];
    analytics_views?: string[];
    columns_deny?: string[];
    columns_allow?: string[];
    mask?: Record<string, MaskFunction>;
    /** "always" (default): grant per column, so columns added later stay hidden. "when_needed": whole-table grants when nothing is hidden. */
    column_grants?: "always" | "when_needed";
  };
  hardening?: {
    revoke_temp_from_public?: boolean;
    revoke_public_schema_create?: boolean;
  };
  auth?: {
    method?: "scram_verifier" | "password";
    password_env?: string;
  };
}

export interface ValidationResult {
  ok: boolean;
  errors: string[];
  warnings: string[];
  config?: RouaConfig;
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

const ALLOWED_KEYS: Record<string, string[]> = {
  "": ["roua_version", "account", "target", "scope", "hardening", "auth"],
  account: ["name", "profile", "level", "owner", "purpose", "approved_by", "approval_ref", "expires_at", "level_role", "limits", "network"],
  "account.limits": ["max_connections", "statement_timeout_s"],
  "account.network": ["allowed_sources"],
  target: ["engine", "database", "schemas", "object_owner"],
  scope: ["include", "exclude", "public_objects", "analytics_views", "columns_deny", "columns_allow", "mask", "column_grants"],
  hardening: ["revoke_temp_from_public", "revoke_public_schema_create"],
  auth: ["method", "password_env"],
};

const META_VALUE_RE = /^[^\s"'\\]+$/;

function checkKeys(obj: Obj, path: string, errors: string[]) {
  const allowed = ALLOWED_KEYS[path] ?? [];
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) errors.push(`Unknown key ${path ? `${path}.` : ""}${k}`);
  }
}

function stringList(v: unknown, path: string, errors: string[]): string[] {
  if (v === undefined) return [];
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
    errors.push(`${path} must be a list of strings`);
    return [];
  }
  return v as string[];
}

export interface ValidateOptions {
  /** "Now", injected so validation stays pure and testable. */
  now?: Date;
}

export function validateConfig(input: unknown, opts: ValidateOptions = {}): ValidationResult {
  const now = opts.now ?? new Date();
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!isObj(input)) return { ok: false, errors: ["Config must be an object"], warnings };
  checkKeys(input, "", errors);

  if (input.roua_version !== ROUA_SPEC_VERSION) {
    errors.push(`roua_version must be "${ROUA_SPEC_VERSION}"`);
  }

  // ---- account
  const a = input.account;
  if (!isObj(a)) {
    errors.push("account is required");
  } else {
    checkKeys(a, "account", errors);
    if (typeof a.name !== "string" || !ACCOUNT_NAME_RE.test(a.name)) {
      errors.push("account.name must match ^[a-z][a-z0-9_]{2,62}$");
    } else if (typeof a.profile === "string" && !a.name.startsWith(`roua_${a.profile}_`)) {
      warnings.push(`account.name should follow the convention roua_<profile>_<label>, e.g. roua_${a.profile}_example`);
    }
    if (!PROFILES.includes(a.profile as Profile)) errors.push(`account.profile must be one of ${PROFILES.join(", ")}`);
    if (!LEVELS.includes(a.level as Level)) errors.push(`account.level must be one of ${LEVELS.join(", ")}`);
    for (const f of ["owner", "purpose"] as const) {
      if (typeof a[f] !== "string" || (a[f] as string).trim() === "") errors.push(`account.${f} is required`);
    }
    if (typeof a.owner === "string" && !META_VALUE_RE.test(a.owner)) errors.push("account.owner must not contain spaces or quotes");
    if (typeof a.purpose === "string" && (a.purpose.length > 200 || a.purpose.includes(DOLLAR_TAG))) {
      errors.push("account.purpose must be at most 200 characters");
    }
    if (a.approval_ref !== undefined && (typeof a.approval_ref !== "string" || !META_VALUE_RE.test(a.approval_ref))) {
      errors.push("account.approval_ref must be a string without spaces or quotes");
    }
    if (a.level_role !== undefined && (typeof a.level_role !== "string" || !ACCOUNT_NAME_RE.test(a.level_role))) {
      errors.push("account.level_role must match ^[a-z][a-z0-9_]{2,62}$");
    }
    if (typeof a.level_role === "string" && a.level_role === a.name) errors.push("account.level_role must differ from account.name");

    // approvers
    let approvers: string[] = [];
    if (typeof a.approved_by === "string") approvers = [a.approved_by];
    else if (Array.isArray(a.approved_by)) approvers = stringList(a.approved_by, "account.approved_by", errors);
    else if (a.approved_by !== undefined) errors.push("account.approved_by must be a string or a list of strings");
    for (const ap of approvers) if (!META_VALUE_RE.test(ap)) errors.push("account.approved_by entries must not contain spaces or quotes");
    if (approvers.length === 0) warnings.push("account.approved_by is empty: record who approved this account (SHOULD)");

    // expiry
    const exp = typeof a.expires_at === "string" ? Date.parse(a.expires_at) : NaN;
    if (Number.isNaN(exp)) {
      errors.push("account.expires_at is required and must be an ISO-8601 date-time, e.g. 2027-01-31T00:00:00Z");
    } else {
      if (exp <= now.getTime()) errors.push("account.expires_at must be in the future");
      const profile = a.profile as Profile;
      if (PROFILES.includes(profile)) {
        const maxMs = PROFILE_INFO[profile].maxExpiryDays * 86_400_000;
        if (exp - now.getTime() > maxMs) {
          errors.push(`account.expires_at is beyond the ${profile} profile maximum of ${PROFILE_INFO[profile].maxExpiryDays} days`);
        }
      }
      if (a.level === "L5" && exp - now.getTime() > L5_MAX_HOURS * 3_600_000) {
        errors.push(`L5 accounts must expire within ${L5_MAX_HOURS} hours`);
      }
    }
    if (a.level === "L5" && new Set(approvers).size < 2) errors.push("L5 accounts need at least two distinct approvers in account.approved_by");

    // limits
    if (a.limits !== undefined) {
      if (!isObj(a.limits)) errors.push("account.limits must be an object");
      else {
        checkKeys(a.limits, "account.limits", errors);
        const { max_connections: mc, statement_timeout_s: st } = a.limits;
        if (mc !== undefined && (!Number.isInteger(mc) || (mc as number) < 1 || (mc as number) > 1000)) errors.push("account.limits.max_connections must be an integer 1-1000");
        if (st !== undefined && (!Number.isInteger(st) || (st as number) < 1 || (st as number) > 86400)) errors.push("account.limits.statement_timeout_s must be an integer 1-86400");
      }
    }
    if (a.network !== undefined) {
      if (!isObj(a.network)) errors.push("account.network must be an object");
      else {
        checkKeys(a.network, "account.network", errors);
        for (const s of stringList(a.network.allowed_sources, "account.network.allowed_sources", errors)) {
          if (!/^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(s)) errors.push(`Invalid allowed source ${JSON.stringify(s)}: use an IP or CIDR`);
        }
      }
    }
  }

  // ---- target
  const t = input.target;
  if (!isObj(t)) {
    errors.push("target is required");
  } else {
    checkKeys(t, "target", errors);
    if (t.engine !== "postgresql") errors.push('target.engine must be "postgresql" (other engines are planned; see ROADMAP)');
    if (typeof t.database !== "string" || !IDENTIFIER_RE.test(t.database)) errors.push("target.database must be a valid identifier");
    const schemas = stringList(t.schemas, "target.schemas", errors);
    if (schemas.length === 0) errors.push("target.schemas must list at least one schema");
    for (const s of schemas) if (!IDENTIFIER_RE.test(s)) errors.push(`Invalid schema name ${JSON.stringify(s)}`);
    if (t.object_owner !== undefined && (typeof t.object_owner !== "string" || !IDENTIFIER_RE.test(t.object_owner))) {
      errors.push("target.object_owner must be a valid identifier");
    }
  }

  // ---- scope
  const s = input.scope;
  if (s !== undefined) {
    if (!isObj(s)) errors.push("scope must be an object");
    else {
      checkKeys(s, "scope", errors);
      for (const key of ["include", "exclude", "public_objects", "analytics_views"] as const) {
        for (const p of stringList(s[key], `scope.${key}`, errors)) {
          try {
            globToRegex(p);
          } catch (e) {
            errors.push(`scope.${key}: ${(e as Error).message}`);
          }
        }
      }
      if (s.column_grants !== undefined && s.column_grants !== "always" && s.column_grants !== "when_needed") {
        errors.push('scope.column_grants must be "always" or "when_needed".');
      }
      for (const key of ["columns_deny", "columns_allow"] as const) {
        for (const c of stringList(s[key], `scope.${key}`, errors)) {
          if (!isColumnRef(c)) errors.push(`scope.${key}: ${JSON.stringify(c)} must be schema.table.column`);
        }
      }
      if (s.mask !== undefined) {
        if (!isObj(s.mask)) errors.push("scope.mask must map schema.table.column to a masking function");
        else {
          for (const [col, fn] of Object.entries(s.mask)) {
            if (!isColumnRef(col)) errors.push(`scope.mask: ${JSON.stringify(col)} must be schema.table.column`);
            if (!MASK_FUNCTIONS.includes(fn as MaskFunction)) errors.push(`scope.mask.${col}: unknown function ${JSON.stringify(fn)} (use ${MASK_FUNCTIONS.join(", ")})`);
          }
        }
      }
    }
  }
  if (isObj(a) && isObj(s)) {
    if (a.level === "L1" && stringList(s.public_objects, "", []).length === 0) errors.push("L1 needs scope.public_objects");
    if (a.level === "L3" && stringList(s.analytics_views, "", []).length === 0) errors.push("L3 needs scope.analytics_views");
    if (a.level !== "L4" && isObj(s.mask) && Object.keys(s.mask).length > 0) warnings.push("scope.mask is only used at level L4");
  } else if (isObj(a) && (a.level === "L1" || a.level === "L3")) {
    errors.push(a.level === "L1" ? "L1 needs scope.public_objects" : "L3 needs scope.analytics_views");
  }

  // ---- hardening, auth
  if (input.hardening !== undefined) {
    if (!isObj(input.hardening)) errors.push("hardening must be an object");
    else {
      checkKeys(input.hardening, "hardening", errors);
      for (const [k, v] of Object.entries(input.hardening)) if (typeof v !== "boolean") errors.push(`hardening.${k} must be true or false`);
    }
  }
  if (input.auth !== undefined) {
    if (!isObj(input.auth)) errors.push("auth must be an object");
    else {
      checkKeys(input.auth, "auth", errors);
      if (input.auth.method !== undefined && !["scram_verifier", "password"].includes(input.auth.method as string)) {
        errors.push('auth.method must be "scram_verifier" or "password"');
      }
      if (input.auth.password_env !== undefined && (typeof input.auth.password_env !== "string" || !/^[A-Z_][A-Z0-9_]*$/.test(input.auth.password_env))) {
        errors.push("auth.password_env must be an environment variable name");
      }
    }
  }

  if (errors.length) return { ok: false, errors, warnings };
  return { ok: true, errors, warnings, config: input as unknown as RouaConfig };
}

function isColumnRef(c: string): boolean {
  const parts = c.split(".");
  return parts.length === 3 && parts.every((p) => IDENTIFIER_RE.test(p));
}

export function levelRoleOf(cfg: RouaConfig): string {
  return cfg.account.level_role ?? LEVEL_INFO[cfg.account.level].defaultRole;
}

export function approversOf(cfg: RouaConfig): string[] {
  const a = cfg.account.approved_by;
  return a === undefined ? [] : Array.isArray(a) ? a : [a];
}
