/**
 * Schema snapshots and scope preview.
 *
 * A snapshot is a flat list of (schema, table, column) rows describing a real
 * database. It comes from the read-only discovery script ROUA generates for each
 * engine, from `roua discover`, or from anything a developer can paste: JSON,
 * CSV/TSV with a header, or psql's aligned table output.
 *
 * `previewScope` resolves an account's scope against a snapshot exactly as the
 * generated setup script will, before anything runs: which tables become
 * readable, which columns stay hidden and why, and which listed names, schemas,
 * exclusions or deny-list entries match nothing. Pure and dependency-free, so
 * the web page, the CLI and the MCP server share it.
 */
import { isSecretColumnName } from "../constants.js";
import type { RouaConfig } from "../config.js";
import { ENGINE_INFO, type AccountSpec, type Engine } from "../engines/types.js";

export interface SchemaColumn {
  schema: string;
  table: string;
  column: string;
  type?: string;
  kind?: "table" | "view";
}

export interface SchemaSnapshot {
  engine?: Engine;
  columns: SchemaColumn[];
}

// ------------------------------------------------------------------ parsing

const KEYS: Record<keyof Omit<SchemaColumn, "kind" | "type"> | "type" | "kind", string[]> = {
  schema: ["schema", "table_schema", "schema_name", "nspname", "owner", "db", "database", "dataset", "table_catalog_schema", "s"],
  table: ["table", "table_name", "relname", "collection", "object", "object_name", "view", "t"],
  column: ["column", "column_name", "attname", "field", "field_name", "c"],
  type: ["type", "data_type", "column_type", "udt_name", "k"],
  kind: ["kind", "table_type", "object_type", "relkind"],
};

function pick(row: Record<string, unknown>, names: string[]): string | undefined {
  const lower = new Map(Object.keys(row).map((k) => [k.toLowerCase(), k]));
  for (const n of names) {
    const k = lower.get(n);
    if (k !== undefined && row[k] !== null && row[k] !== undefined && String(row[k]).trim() !== "") return String(row[k]).trim();
  }
  return undefined;
}

function toColumn(row: Record<string, unknown>): SchemaColumn | null {
  const schema = pick(row, KEYS.schema);
  const table = pick(row, KEYS.table);
  const column = pick(row, KEYS.column);
  if (!table || !column) return null;
  const kindRaw = (pick(row, KEYS.kind) ?? "").toLowerCase();
  const kind = /view|^v$|^m$/.test(kindRaw) ? "view" : kindRaw ? "table" : undefined;
  return { schema: schema ?? "", table, column, ...(pick(row, KEYS.type) ? { type: pick(row, KEYS.type) } : {}), ...(kind ? { kind } : {}) };
}

function splitDelimited(line: string, sep: string): string[] {
  const out: string[] = [];
  let cur = "";
  let q = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (q) {
      if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (ch === '"') q = false;
      else cur += ch;
    } else if (ch === '"') q = true;
    else if (ch === sep) { out.push(cur); cur = ""; }
    else cur += ch;
  }
  out.push(cur);
  return out.map((s) => s.trim());
}

/**
 * Parse whatever a developer pasted: a JSON array of rows (any common key names),
 * an object with a `columns`/`rows`/`data` array, CSV or TSV with a header row,
 * or psql/sqlcmd aligned output with `|` separators. Throws with a helpful
 * message when nothing usable is found.
 */
export function parseSchemaSnapshot(text: string, engine?: Engine): SchemaSnapshot {
  const raw = text.replace(/^﻿/, "").trim();
  if (!raw) throw new Error("The schema is empty. Run the discovery script and paste its output.");
  let rows: Record<string, unknown>[] | null = null;
  const tryJson = (s: string) => {
    try {
      const v = JSON.parse(s) as unknown;
      if (Array.isArray(v)) return v as Record<string, unknown>[];
      if (v && typeof v === "object") {
        const o = v as Record<string, unknown>;
        for (const k of ["columns", "rows", "data", "schema", "result"]) if (Array.isArray(o[k])) return o[k] as Record<string, unknown>[];
      }
    } catch {
      /* not JSON */
    }
    return null;
  };
  rows = tryJson(raw);
  // sqlcmd and sqlplus wrap long JSON across lines: try again without the line breaks.
  if (!rows && /^[[{]/.test(raw)) rows = tryJson(raw.replace(/\r?\n/g, ""));
  if (!rows) {
    const lines = raw.split(/\r?\n/).map((l) => l.replace(/\s+$/, "")).filter((l) => l.trim() && !/^[-+=\s|]+$/.test(l) && !/^\(\d+ rows?\)$/.test(l.trim()));
    const sep = lines[0]?.includes("|") ? "|" : lines[0]?.includes("\t") ? "\t" : lines[0]?.includes(",") ? "," : null;
    if (sep && lines.length > 1) {
      const header = splitDelimited(lines[0]!.replace(/^\||\|$/g, ""), sep).map((h) => h.toLowerCase());
      rows = lines.slice(1).map((l) => {
        const cells = splitDelimited(l.replace(/^\||\|$/g, ""), sep);
        return Object.fromEntries(header.map((h, i) => [h, cells[i] ?? ""]));
      });
    }
  }
  if (!rows) throw new Error("Could not read this schema. Paste the JSON printed by the discovery script, or CSV/TSV with schema, table and column headers.");
  const columns = rows.filter((r) => r && typeof r === "object").map(toColumn).filter((c): c is SchemaColumn => c !== null);
  if (!columns.length) throw new Error("No columns found. Each row needs at least a table and a column (and usually a schema).");
  const seen = new Set<string>();
  const unique = columns.filter((c) => {
    const k = `${c.schema}\u0000${c.table}\u0000${c.column}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  // When the source labels views, anything it did not label is a table.
  if (unique.some((c) => c.kind)) for (const c of unique) c.kind ??= "table";
  return { ...(engine ? { engine } : {}), columns: unique };
}

/** Tables (and views) in a snapshot, with their columns, sorted. */
export function snapshotTables(s: SchemaSnapshot): { schema: string; table: string; kind?: "table" | "view"; columns: SchemaColumn[] }[] {
  const map = new Map<string, { schema: string; table: string; kind?: "table" | "view"; columns: SchemaColumn[] }>();
  for (const c of s.columns) {
    const k = `${c.schema}.${c.table}`;
    const t = map.get(k) ?? { schema: c.schema, table: c.table, ...(c.kind ? { kind: c.kind } : {}), columns: [] };
    t.columns.push(c);
    map.set(k, t);
  }
  return [...map.values()].sort((a, b) => `${a.schema}.${a.table}`.localeCompare(`${b.schema}.${b.table}`));
}

// ------------------------------------------------------------------ preview

/** A scope, normalized from an AccountSpec or a PostgreSQL roua.yaml. */
export interface ScopeRequest {
  engine: Engine;
  /** metadata: L0; listed: only `objects`; scope: `schemas` minus `exclude` (with optional `include`). */
  mode: "metadata" | "listed" | "scope";
  schemas: string[];
  include: string[];
  objects: string[];
  exclude: string[];
  columnsDeny: string[];
  columnsAllow: string[];
  /** PostgreSQL L4 mask rules (schema.table.column). */
  masks?: string[];
  /** PostgreSQL L3 limits reads to views. */
  viewsOnly?: boolean;
  /** "always": every grant is per column, so columns added later stay hidden. */
  columnGrants: "always" | "when_needed";
}

export interface ObjectPreview {
  name: string;
  kind?: "table" | "view";
  /** all: every column readable; partial: some hidden; skipped: engine cannot hide columns, or all are hidden. */
  access: "all" | "partial" | "skipped";
  visible: string[];
  hidden: { column: string; reason: "secret" | "denied" }[];
}

export interface ScopePreview {
  objects: ObjectPreview[];
  readableObjects: number;
  hiddenColumns: number;
  missingSchemas: string[];
  unmatchedObjects: string[];
  unmatchedIncludes: string[];
  unmatchedExcludes: string[];
  unmatchedDenies: string[];
  unmatchedAllows: string[];
  unmatchedMasks: string[];
  /** Secret-looking columns readable on engines that cannot hide fields (MongoDB). */
  exposedSecrets: string[];
  errors: string[];
  warnings: string[];
  notes: string[];
}

const CASE_INSENSITIVE = new Set<Engine>(["mysql", "mariadb", "sqlserver", "oracle", "snowflake"]);

function globMatcher(pattern: string, ci: boolean): (name: string) => boolean {
  const re = new RegExp("^" + pattern.replace(/[.$+?^()[\]{}|\\-]/g, (c) => `\\${c}`).replace(/\*/g, ".*") + "$", ci ? "i" : "");
  return (name) => re.test(name);
}

export function scopeFromSpec(spec: AccountSpec): ScopeRequest {
  return {
    engine: spec.engine,
    mode: spec.engine === "redis" ? "listed" : spec.mode,
    schemas: spec.engine === "mongodb" ? (spec.database ? [spec.database] : []) : spec.schemas ?? [],
    include: [],
    objects: spec.engine === "mongodb" ? (spec.objects ?? []).map((o) => `${spec.database ?? ""}.${o}`) : spec.objects ?? [],
    exclude: spec.engine === "mongodb" ? (spec.exclude ?? []).map((o) => `${spec.database ?? ""}.${o}`) : spec.exclude ?? [],
    columnsDeny: spec.columnsDeny ?? [],
    columnsAllow: spec.columnsAllow ?? [],
    columnGrants: spec.columnGrants ?? "always",
  };
}

export function scopeFromPostgresConfig(cfg: RouaConfig): ScopeRequest {
  const s = cfg.scope ?? {};
  const level = cfg.account.level;
  const listed = level === "L1" ? s.public_objects ?? [] : level === "L3" ? s.analytics_views ?? [] : [];
  return {
    engine: "postgresql",
    mode: level === "L0" ? "metadata" : level === "L1" || level === "L3" ? "listed" : "scope",
    schemas: cfg.target.schemas,
    include: level === "L2" || level === "L4" || level === "L5" ? s.include ?? [] : [],
    objects: listed,
    exclude: s.exclude ?? [],
    columnsDeny: s.columns_deny ?? [],
    columnsAllow: s.columns_allow ?? [],
    masks: level === "L4" ? Object.keys(s.mask ?? {}) : [],
    viewsOnly: level === "L3",
    columnGrants: s.column_grants ?? "always",
  };
}

/** Resolve a scope against a real schema, exactly as the generated setup will. */
export function previewScope(req: ScopeRequest, snapshot: SchemaSnapshot): ScopePreview {
  const ci = CASE_INSENSITIVE.has(req.engine);
  const norm = (s: string) => (ci ? s.toLowerCase() : s);
  const info = ENGINE_INFO[req.engine];
  const canHideColumns = info.fields.columns && !["oracle", "snowflake", "bigquery"].includes(req.engine);
  const tables = snapshotTables(snapshot);
  const out: ScopePreview = {
    objects: [], readableObjects: 0, hiddenColumns: 0, missingSchemas: [], unmatchedObjects: [], unmatchedIncludes: [],
    unmatchedExcludes: [], unmatchedDenies: [], unmatchedAllows: [], unmatchedMasks: [], exposedSecrets: [], errors: [], warnings: [], notes: [],
  };
  if (req.engine === "redis") {
    out.notes.push("Redis has no schema: key patterns are checked when the account reads keys.");
    return out;
  }

  const schemaSet = new Set(tables.map((t) => norm(t.schema)));
  const needsSchemas = req.mode !== "listed" || req.engine === "mongodb";
  if (needsSchemas) for (const s of req.schemas) if (!schemaSet.has(norm(s))) out.missingSchemas.push(s);

  const full = (t: { schema: string; table: string }) => (t.schema ? `${t.schema}.${t.table}` : t.table);
  const used = (list: string[]) => list.map((p) => ({ p, m: globMatcher(p, ci), hit: false }));
  const objects = used(req.objects);
  const includes = used(req.include);
  const excludes = used(req.exclude);
  const allColumns = new Set(snapshot.columns.map((c) => norm(`${full(c)}.${c.column}`)));
  const denySet = new Set(req.columnsDeny.map(norm));
  const allowSet = new Set(req.columnsAllow.map(norm));

  for (const t of tables) {
    const name = full(t);
    if (req.viewsOnly && t.kind && t.kind !== "view") continue;
    let inScope: boolean;
    if (req.mode === "listed") {
      inScope = false;
      for (const o of objects) if (o.m(name)) { o.hit = true; inScope = true; }
    } else {
      inScope = req.schemas.some((s) => norm(s) === norm(t.schema));
      if (inScope && includes.length) {
        let hit = false;
        for (const i of includes) if (i.m(name)) { i.hit = true; hit = true; }
        inScope = hit;
      }
    }
    if (!inScope) continue;
    let excluded = false;
    for (const e of excludes) if (e.m(name)) { e.hit = true; excluded = true; }
    if (excluded) continue;

    const hidden: ObjectPreview["hidden"] = [];
    const visible: string[] = [];
    for (const c of t.columns) {
      const key = norm(`${name}.${c.column}`);
      const secret = isSecretColumnName(c.column) && !allowSet.has(key);
      const denied = denySet.has(key);
      if (req.engine === "mongodb") {
        visible.push(c.column);
        if (secret || denied) out.exposedSecrets.push(`${name}.${c.column}`);
        continue;
      }
      if (denied) hidden.push({ column: c.column, reason: "denied" });
      else if (secret) hidden.push({ column: c.column, reason: "secret" });
      else visible.push(c.column);
    }
    const access: ObjectPreview["access"] = req.mode === "metadata"
      ? "all"
      : !hidden.length ? "all" : canHideColumns && visible.length ? "partial" : "skipped";
    out.objects.push({ name, ...(t.kind ? { kind: t.kind } : {}), access, visible: access === "skipped" ? [] : visible, hidden });
  }

  out.unmatchedObjects = objects.filter((o) => !o.hit).map((o) => o.p);
  out.unmatchedIncludes = includes.filter((o) => !o.hit).map((o) => o.p);
  out.unmatchedExcludes = excludes.filter((o) => !o.hit).map((o) => o.p);
  out.unmatchedDenies = req.columnsDeny.filter((d) => !allColumns.has(norm(d)));
  out.unmatchedAllows = req.columnsAllow.filter((d) => !allColumns.has(norm(d)));
  out.unmatchedMasks = (req.masks ?? []).filter((d) => !allColumns.has(norm(d)));
  out.readableObjects = out.objects.filter((o) => o.access !== "skipped").length;
  out.hiddenColumns = out.objects.reduce((n, o) => n + o.hidden.length, 0);

  const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;
  if (out.missingSchemas.length) out.errors.push(`Not found in this database: ${out.missingSchemas.join(", ")}. Check the spelling and letter case.`);
  if (req.mode !== "metadata" && out.readableObjects === 0) {
    out.errors.push("The scope matches no readable tables, so the account would see nothing. Check the schemas, listed names and exclusions.");
  }
  if (out.unmatchedObjects.length) out.warnings.push(`Listed but not found: ${out.unmatchedObjects.join(", ")}.`);
  if (out.unmatchedIncludes.length) out.warnings.push(`Include patterns matching nothing: ${out.unmatchedIncludes.join(", ")}.`);
  if (out.unmatchedExcludes.length) out.notes.push(`Exclusions matching nothing (harmless, maybe a typo): ${out.unmatchedExcludes.join(", ")}.`);
  if (out.unmatchedDenies.length) out.warnings.push(`Hidden-column entries matching no column: ${out.unmatchedDenies.join(", ")}. If the column is spelled differently it is NOT hidden.`);
  if (out.unmatchedAllows.length) out.notes.push(`"Not secrets after all" entries matching no column: ${out.unmatchedAllows.join(", ")}.`);
  if (out.unmatchedMasks.length) out.warnings.push(`Mask rules matching no column: ${out.unmatchedMasks.join(", ")}.`);
  if (out.exposedSecrets.length) out.warnings.push(`MongoDB cannot hide fields, and these look secret: ${out.exposedSecrets.slice(0, 12).join(", ")}${out.exposedSecrets.length > 12 ? "…" : ""}. Leave the collection out or list a view.`);
  const skipped = out.objects.filter((o) => o.access === "skipped");
  if (skipped.length && req.mode !== "metadata") {
    out.warnings.push(`${plural(skipped.length, "table")} will be skipped because ${canHideColumns ? "every column is hidden" : `${info.name} cannot hide single columns`}: ${skipped.slice(0, 10).map((o) => o.name).join(", ")}${skipped.length > 10 ? "…" : ""}.`);
  }
  if (req.mode !== "metadata") {
    out.notes.push(`${plural(out.readableObjects, "table")} readable, ${plural(out.hiddenColumns, "column")} hidden${req.columnGrants === "always" && canHideColumns ? "; grants are per column, so columns added later stay hidden until setup runs again" : ""}.`);
  }
  return out;
}
