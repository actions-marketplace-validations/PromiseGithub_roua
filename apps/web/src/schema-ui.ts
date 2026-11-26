/**
 * "Your schema": load a schema snapshot (pasted output of the read-only
 * discovery script), pick tables from a list, and preview exactly what the
 * account will be able to read before any script is generated. All in the
 * browser; nothing is sent anywhere.
 */
import {
  discoveryScript,
  isSecretColumnName,
  parseSchemaSnapshot,
  previewScope,
  snapshotTables,
  type Engine,
  type ScopePreview,
  type ScopeRequest,
  type SchemaSnapshot,
} from "@roua-dev/core";

export interface SchemaUiHooks {
  engine: () => Engine;
  /** The scope as the form currently describes it. */
  request: () => ScopeRequest | null;
  /** Which input the table picker writes to, and how. */
  target: () => { field: string; kind: "include" | "exclude" } | null;
  /** Form context for the discovery script. */
  context: () => { database?: string; schemas: string[] };
  /** Called after the picker changed form fields. */
  changed: () => void;
}

const $ = <T extends HTMLElement = HTMLInputElement>(id: string) => document.getElementById(id) as T;
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
const split = (s: string) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

let snapshot: SchemaSnapshot | null = null;
let hooks: SchemaUiHooks;
let discoverFile = { name: "discover.sql", content: "" };

export const currentSnapshot = () => snapshot;

export function initSchemaUi(h: SchemaUiHooks) {
  hooks = h;
  $("loadSchema").addEventListener("click", load);
  $("clearSchema").addEventListener("click", () => clear(true));
  $("copyDiscover").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(discoverFile.content);
      $("copyDiscover").textContent = "Copied";
    } catch {
      $("copyDiscover").textContent = "Select and copy manually";
    }
    setTimeout(() => ($("copyDiscover").textContent = "Copy"), 1500);
  });
  $("dlDiscover").addEventListener("click", () => {
    const url = URL.createObjectURL(new Blob([discoverFile.content], { type: "text/plain;charset=utf-8" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = discoverFile.name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
}

/** Re-render the discovery script for the current engine and form context. */
export function refreshSchemaUi(engineChanged: boolean) {
  const engine = hooks.engine();
  const ctx = hooks.context();
  const script = discoveryScript(engine, { database: ctx.database, datasets: ctx.schemas, project: ctx.database });
  $("schemaSet").hidden = !script;
  if (!script) return;
  discoverFile = { name: script.name, content: script.content };
  $("discoverCode").textContent = script.content;
  $("discoverRun").innerHTML = `Run: <code>${esc(script.run)}</code>`;
  if (engineChanged) clear(false);
  else if (snapshot) render();
}

function load() {
  try {
    snapshot = parseSchemaSnapshot($<HTMLTextAreaElement>("schemaText").value, hooks.engine());
  } catch (e) {
    snapshot = null;
    $("schemaStatus").innerHTML = `<span class="bad">${esc((e as Error).message)}</span>`;
    $("tablePicker").hidden = true;
    $("previewBox").hidden = true;
    return;
  }
  const tables = snapshotTables(snapshot);
  const schemas = new Set(tables.map((t) => t.schema));
  $("schemaStatus").textContent = `Loaded ${tables.length} table(s) and view(s) in ${schemas.size} schema(s), ${snapshot.columns.length} column(s).`;
  $("clearSchema").hidden = false;
  render();
}

function clear(clearText: boolean) {
  snapshot = null;
  if (clearText) $<HTMLTextAreaElement>("schemaText").value = "";
  $("schemaStatus").textContent = "";
  $("tablePicker").hidden = true;
  $("previewBox").hidden = true;
  $("clearSchema").hidden = true;
}

/** The latest preview, or null when no schema is loaded. */
export function currentPreview(): ScopePreview | null {
  const req = hooks?.request();
  return snapshot && req ? previewScope(req, snapshot) : null;
}

/** Re-render the picker and the preview from the form's current state. */
export function render() {
  if (!snapshot) return;
  const preview = currentPreview();
  const target = hooks.target();
  const inScope = new Map((preview?.objects ?? []).map((o) => [o.name, o]));
  const tables = snapshotTables(snapshot);
  const bySchema = new Map<string, typeof tables>();
  for (const t of tables) bySchema.set(t.schema, [...(bySchema.get(t.schema) ?? []), t]);

  const picker = $("tablePicker");
  picker.hidden = false;
  picker.innerHTML =
    `<p class="help">${target ? "Tick the tables the account may read. Secret-looking columns are hidden automatically." : "This level does not pick tables."}</p>` +
    [...bySchema].map(([schema, list]) => `<details class="schemaGroup" ${list.some((t) => inScope.has(name(t))) || bySchema.size === 1 ? "open" : ""}>
      <summary><b>${esc(schema || "(no schema)")}</b> <span class="muted">${list.length} table(s)</span></summary>
      <ul class="tables">${list.map((t) => {
        const n = name(t);
        const o = inScope.get(n);
        const secrets = t.columns.filter((c) => isSecretColumnName(c.column)).length;
        const badge = o?.access === "skipped" ? `<span class="badge preview">skipped</span>` : o?.access === "partial" ? `<span class="badge tested">${o.hidden.length} hidden</span>` : secrets ? `<span class="badge preview">${secrets} secret-looking</span>` : "";
        return `<li><label class="check"><input type="checkbox" data-table="${esc(n)}" ${o ? "checked" : ""} ${target ? "" : "disabled"}> <span>${esc(t.table)}${t.kind === "view" ? ' <span class="muted">view</span>' : ""} <span class="muted">${t.columns.length} col</span> ${badge}</span></label></li>`;
      }).join("")}</ul></details>`).join("");
  picker.querySelectorAll<HTMLInputElement>("input[data-table]").forEach((cb) => cb.addEventListener("change", () => pick()));

  const box = $("previewBox");
  box.hidden = !preview;
  if (preview) box.innerHTML = renderPreview(preview);
}

const name = (t: { schema: string; table: string }) => (t.schema ? `${t.schema}.${t.table}` : t.table);

function pick() {
  const target = hooks.target();
  if (!target || !snapshot) return;
  const boxes = [...document.querySelectorAll<HTMLInputElement>("#tablePicker input[data-table]")];
  const checked = boxes.filter((b) => b.checked).map((b) => b.dataset.table!);
  const engine = hooks.engine();
  const strip = (n: string) => (engine === "mongodb" ? n.split(".").slice(1).join(".") : n);
  if (target.kind === "include") {
    $(target.field).value = checked.map(strip).join(" ");
  } else {
    // The schemas in scope become exactly those of the ticked tables (the loaded schema is the
    // source of truth, so a stale or misspelled schema name is replaced), then the unticked
    // tables in those schemas are excluded.
    const schemasEl = document.getElementById("schemas") as HTMLInputElement | null;
    const schemas = new Set(engine === "mongodb" ? split(schemasEl?.value ?? "") : checked.map((n) => n.split(".")[0]!));
    if (engine !== "mongodb" && schemasEl) schemasEl.value = [...schemas].join(" ");
    const unchecked = boxes.filter((b) => !b.checked).map((b) => b.dataset.table!).filter((n) => engine === "mongodb" || schemas.has(n.split(".")[0]!));
    $(target.field).value = unchecked.map(strip).join(" ");
  }
  hooks.changed();
  render();
}

function renderPreview(p: ScopePreview): string {
  const list = (cls: string, title: string, items: string[]) => (items.length ? `<div class="${cls}"><b>${title}</b><ul>${items.map((i) => `<li>${esc(i)}</li>`).join("")}</ul></div>` : "");
  const rows = p.objects.slice(0, 200).map((o) => `<tr><td>${esc(o.name)}</td><td>${o.access === "all" ? "all columns" : o.access === "partial" ? `${o.visible.length} of ${o.visible.length + o.hidden.length} columns` : "skipped"}</td><td>${o.hidden.map((h) => `${esc(h.column)} <span class="muted">(${h.reason})</span>`).join(", ")}</td></tr>`).join("");
  return `<h3>Preview: what this account will read</h3>
    ${list("errors", "Fix before generating", p.errors)}
    ${list("warn", "Check these", p.warnings)}
    ${list("muted", "Notes", p.notes)}
    ${p.objects.length ? `<div class="tablewrap"><table class="mini"><thead><tr><th scope="col">Table</th><th scope="col">Readable</th><th scope="col">Hidden</th></tr></thead><tbody>${rows}</tbody></table></div>` : ""}`;
}
