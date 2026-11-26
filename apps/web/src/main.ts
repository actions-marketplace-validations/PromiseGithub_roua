/**
 * ROUA web generator. Runs entirely in the browser; makes no network requests
 * (the page's Content-Security-Policy sets connect-src 'none' to enforce it).
 */
import {
  ENGINES,
  ENGINE_INFO,
  LEVELS,
  LEVEL_INFO,
  PROFILES,
  PROFILE_INFO,
  RouaInputError,
  auditScript,
  configToYaml,
  generatePassword,
  isScramSafePassword,
  planEngine,
  planPostgres,
  renderAuditSql,
  scramSha256Verifier,
  validateConfig,
  validateSpec,
  type AccountSpec,
  type Engine,
  type Level,
  type OtherEngine,
  type PasswordSecret,
  type Profile,
} from "@roua-dev/core";
import { formToConfig, splitList, type FormValues } from "./form.js";
import { ENGINE_DEFAULTS } from "./defaults.js";

const VERSION = "0.4.0";
const $ = <T extends HTMLElement = HTMLInputElement>(id: string) => document.getElementById(id) as T;
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

interface OutFile {
  name: string;
  run: string;
  content: string;
}
let engine: Engine = "postgresql";
let files: OutFile[] = [];
let current = "";
let privateKeyPem = "";
let checkFile: OutFile | null = null;

const SUPPORT_LABEL = { full: "Full", tested: "Tested in CI", preview: "Preview" } as const;

// ------------------------------------------------------------------ setup

function init() {
  const profile = $<HTMLSelectElement>("profile");
  const level = $<HTMLSelectElement>("level");
  for (const p of PROFILES) profile.add(new Option(`${PROFILE_INFO[p].title} (${p})`, p));
  for (const l of LEVELS) level.add(new Option(`${l}: ${LEVEL_INFO[l].name}`, l));
  profile.value = "agent";
  level.value = PROFILE_INFO.agent.defaultLevel;
  setDefaultExpiry();
  $("password").value = generatePassword(32);

  renderEngineButtons();
  renderTables();
  initCheck();

  profile.addEventListener("change", () => {
    const p = profile.value as Profile;
    level.value = PROFILE_INFO[p].defaultLevel;
    $<HTMLSelectElement>("mode").value = PROFILE_INFO[p].defaultLevel === "L1" ? "listed" : "scope";
    const name = $("name");
    if (/^roua_[a-z]+_/.test(name.value)) name.value = name.value.replace(/^roua_[a-z]+_/, `roua_${p}_`);
    setDefaultExpiry();
    refresh();
  });
  level.addEventListener("change", () => {
    setDefaultExpiry();
    refresh();
  });
  $("mode").addEventListener("change", refresh);
  $("contained").addEventListener("change", refresh);
  $("regen").addEventListener("click", () => ($("password").value = generatePassword(32)));
  $("copyPw").addEventListener("click", () => copy($("password").value, $("copyPw")));
  $("genKey").addEventListener("click", () => void generateKeyPair());
  $("dlKey").addEventListener("click", () => download(`${$("name").value || "roua"}_rsa_key.p8`, privateKeyPem));
  $("form").addEventListener("submit", (e) => {
    e.preventDefault();
    void generate();
  });
  $("copy").addEventListener("click", () => copy(fileByName(current)?.content ?? "", $("copy")));
  $("download").addEventListener("click", () => {
    const f = fileByName(current);
    if (f) download(f.name, f.content);
  });
  $("downloadAll").addEventListener("click", () => files.forEach((f, i) => setTimeout(() => download(f.name, f.content), i * 250)));
  // Pages for one database or audience preset the form (kaizam.com/mysql/, /app-review/ …).
  const preset = document.body.dataset.engine as Engine | undefined;
  const presetProfile = document.body.dataset.profile as Profile | undefined;
  if (presetProfile && (PROFILES as readonly string[]).includes(presetProfile)) {
    profile.value = presetProfile;
    profile.dispatchEvent(new Event("change"));
  }
  if (preset && (ENGINES as readonly string[]).includes(preset)) {
    selectEngine(preset, true);
    const sel = $<HTMLSelectElement>("cEngine");
    sel.value = preset;
    sel.dispatchEvent(new Event("change"));
  } else {
    selectEngine("postgresql", false);
  }
}

function renderEngineButtons() {
  const box = $("engines");
  box.replaceChildren(
    ...ENGINES.map((id) => {
      const info = ENGINE_INFO[id];
      const b = document.createElement("button");
      b.type = "button";
      b.className = "engine";
      b.setAttribute("role", "radio");
      b.dataset.engine = id;
      b.innerHTML = `<b>${esc(info.short)}</b><span class="badge ${info.support}">${SUPPORT_LABEL[info.support]}</span><span>${esc(info.versions)}</span>`;
      b.addEventListener("click", () => selectEngine(id, true));
      return b;
    }),
  );
}

/** The tables are written into the HTML at build time (crawlable, no-JS); only wire up the buttons. */
function renderTables() {
  const tbody = document.querySelector("#dbTable tbody")!;
  tbody.querySelectorAll<HTMLButtonElement>("button[data-use]").forEach((b) =>
    b.addEventListener("click", () => {
      selectEngine(b.dataset.use as Engine, true);
      $("generator").scrollIntoView();
    }),
  );
}

function selectEngine(id: Engine, resetFields: boolean) {
  engine = id;
  document.querySelectorAll<HTMLButtonElement>("#engines .engine").forEach((b) => b.setAttribute("aria-checked", String(b.dataset.engine === id)));
  if (resetFields) {
    const d = ENGINE_DEFAULTS[id];
    for (const [k, v] of Object.entries(d.values)) $(k).value = v;
  }
  $("result").hidden = true;
  $("errors").hidden = true;
  $("empty").hidden = false;
  refresh();
}

function setDefaultExpiry() {
  const p = $<HTMLSelectElement>("profile").value as Profile;
  const l = $<HTMLSelectElement>("level").value as Level;
  const d = new Date();
  if (engine === "postgresql" && l === "L5") {
    const t = new Date(d.getTime() + 8 * 3_600_000);
    $("expiresDate").value = t.toISOString().slice(0, 10);
    $("expiresTime").value = t.toISOString().slice(11, 16);
  } else {
    d.setUTCDate(d.getUTCDate() + PROFILE_INFO[p].defaultExpiryDays);
    $("expiresDate").value = d.toISOString().slice(0, 10);
  }
}

/** Show the fields that apply to the chosen engine, level and mode. */
function refresh() {
  const pg = engine === "postgresql";
  const info = ENGINE_INFO[engine];
  const f = info.fields;
  const d = ENGINE_DEFAULTS[engine];
  const p = $<HTMLSelectElement>("profile").value as Profile;
  const l = $<HTMLSelectElement>("level").value as Level;
  const mode = $<HTMLSelectElement>("mode").value;
  const metaOk = !pg && "how" in f.metadata;
  const metaOpt = document.querySelector<HTMLOptionElement>('#mode option[value="metadata"]')!;
  metaOpt.hidden = !metaOk;
  metaOpt.disabled = !metaOk;
  if (!metaOk && mode === "metadata") $<HTMLSelectElement>("mode").value = "scope";
  const meta = !pg && metaOk && $<HTMLSelectElement>("mode").value === "metadata";
  const listed = !pg && !meta && ($<HTMLSelectElement>("mode").value === "listed" || engine === "redis");

  document.querySelectorAll<HTMLElement>("[data-engines]").forEach((el) => {
    const want = (el.dataset.engines ?? "").split(" ");
    let show = want.includes(engine) || (want.includes("others") && !pg);
    if (show && pg && el.dataset.levels) show = el.dataset.levels.split(" ").includes(l);
    el.hidden = !show;
  });
  $("mode").closest("label")!.hidden = pg || engine === "redis";
  const show = (id: string, on: boolean) => ($(id).hidden = !on);
  show("databaseWrap", f.database !== null);
  $("databaseLabel").textContent = f.database ?? "";
  show("schemasWrap", f.schemas !== null && (pg || !listed));
  $("schemasLabel").textContent = f.schemas ?? "";
  $("schemasHelp").textContent = d.schemasHelp;
  show("objectsWrap", listed);
  $("objectsLabel").textContent = f.objects;
  $("objectsHelp").textContent = d.objectsHelp;
  show("excludeWrap", pg ? l !== "L0" : !listed && !meta && f.exclude !== null);
  $("excludeLabel").textContent = f.exclude ?? "";
  $("excludeHelp").textContent = d.excludeHelp;
  const cols = pg ? ["L1", "L2", "L4", "L5"].includes(l) : f.columns && !meta;
  show("columnsDenyWrap", cols);
  show("columnsAllowWrap", cols);
  $<HTMLInputElement>("columnsDeny").placeholder = d.columnPlaceholder;
  show("maxConnectionsWrap", f.maxConnections);
  show("statementTimeoutWrap", f.statementTimeout);
  show("allowedSourcesWrap", f.allowedSources !== null);
  $("allowedSourcesLabel").textContent = f.allowedSources ?? "";
  $("allowedSourcesHelp").textContent = d.allowedHelp;
  show("limitsSet", f.maxConnections || f.statementTimeout || f.allowedSources !== null || pg || engine === "mysql" || engine === "mariadb");
  const pwKind = engine === "sqlserver" && $("contained").checked ? "plaintext" : f.password;
  show("pwBlock", pwKind === "verifier" || pwKind === "plaintext");
  show("keyBlock", pwKind === "keypair");
  show("noneBlock", pwKind === "none");
  $("pwHelp").textContent = pg
    ? "By default the script contains only a SCRAM-SHA-256 verifier, so the password is not in the file, the server log or query history. Save it in a password manager now; it is not stored anywhere."
    : pwKind === "verifier"
      ? `The script contains only a password hash, never the password. Save the password in a password manager now; it is not stored anywhere.`
      : `${info.name} needs the plaintext password inside the setup script. Run it, then delete the file. Save the password in a password manager now.`;
  $("scopeNote").textContent = d.scopeNote;
  $("expiresTimeWrap").hidden = !(pg && l === "L5");
  $("levelHelp").textContent = pg
    ? `${LEVEL_INFO[l].canRead} ${PROFILE_INFO[p].description}`
    : `${meta ? `${LEVEL_INFO.L0.canRead} On ${info.name}: ${"how" in f.metadata ? f.metadata.how : ""}` : listed ? LEVEL_INFO.L1.canRead : LEVEL_INFO.L2.canRead} ${PROFILE_INFO[p].description}`;
  $("expiryHelp").textContent =
    pg && l === "L5" ? "L5 accounts must expire within 24 hours and need two approvers." : `The ${p} profile allows at most ${PROFILE_INFO[p].maxExpiryDays} days.`;
  $("dbLegend").textContent = info.name;
}

// ------------------------------------------------------------------ generate

function pgValues(): FormValues {
  const v = (id: string) => $(id).value;
  const c = (id: string) => $(id).checked;
  const vis = (id: string) => (isHidden(id) ? "" : $(id).value);
  return {
    name: v("name"),
    profile: v("profile") as Profile,
    level: v("level") as Level,
    owner: v("owner"),
    purpose: v("purpose"),
    approvedBy: v("approvedBy"),
    approvalRef: v("approvalRef"),
    expiresDate: v("expiresDate"),
    expiresTime: v("expiresTime"),
    maxConnections: v("maxConnections"),
    statementTimeout: v("statementTimeout"),
    allowedSources: v("allowedSources"),
    database: v("database"),
    schemas: v("schemas"),
    objectOwner: v("objectOwner"),
    include: vis("include"),
    exclude: vis("exclude"),
    publicObjects: vis("publicObjects"),
    analyticsViews: vis("analyticsViews"),
    columnsDeny: vis("columnsDeny"),
    columnsAllow: vis("columnsAllow"),
    mask: vis("mask"),
    revokeTemp: c("revokeTemp"),
    revokePublicCreate: c("revokePublicCreate"),
    plaintext: c("plaintext"),
  };
}

/** A field counts only if it and every ancestor are visible. */
function isHidden(id: string): boolean {
  for (let el: HTMLElement | null = $(id); el; el = el.parentElement) if (el.hidden) return true;
  return false;
}

function otherSpec(): AccountSpec {
  const v = (id: string) => (isHidden(id) ? "" : $(id).value.trim());
  const num = (id: string) => (v(id) ? Number(v(id)) : undefined);
  const e = engine as OtherEngine;
  const modeValue = $<HTMLSelectElement>("mode").value;
  const listed = e === "redis" || modeValue === "listed";
  return {
    engine: e,
    name: $("name").value.trim(),
    profile: $("profile").value as Profile,
    owner: $("owner").value.trim(),
    purpose: $("purpose").value.trim(),
    approvedBy: splitList($("approvedBy").value),
    approvalRef: $("approvalRef").value.trim() || undefined,
    expiresAt: $("expiresDate").value ? `${$("expiresDate").value}T00:00:00Z` : "",
    mode: listed ? "listed" : modeValue === "metadata" ? "metadata" : "scope",
    database: v("database") || undefined,
    schemas: splitList(v("schemas")),
    objects: splitList(v("objects")),
    exclude: splitList(v("exclude")),
    columnsDeny: splitList(v("columnsDeny")),
    columnsAllow: splitList(v("columnsAllow")),
    password: isHidden("password") ? undefined : $("password").value,
    maxConnections: num("maxConnections"),
    statementTimeoutS: num("statementTimeout"),
    allowedSources: splitList(v("allowedSources")),
    requireTls: !isHidden("requireTls") && $("requireTls").checked,
    contained: e === "sqlserver" && $("contained").checked,
    warehouse: v("warehouse") || undefined,
    publicKey: isHidden("publicKey") ? undefined : $("publicKey").value,
    location: v("location") || undefined,
    redis7: $("redis7").checked,
  };
}

function showErrors(list: string[]) {
  const el = $("errors");
  el.innerHTML = `<b>Fix these first:</b><ul>${list.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>`;
  el.hidden = false;
  el.scrollIntoView({ block: "nearest" });
}

async function generate() {
  $("errors").hidden = true;
  const now = new Date();
  let warnings: string[] = [];
  let manualSteps: string[] = [];
  if (engine === "postgresql") {
    const { config, errors } = formToConfig(pgValues());
    const v = validateConfig(config, { now });
    const all = [...errors, ...v.errors];
    const password = $("password").value;
    if (password.length < 16) all.push("Use a password of at least 16 characters (or click New).");
    if (!$("plaintext").checked && !isScramSafePassword(password)) all.push("SCRAM verifiers need a printable-ASCII password without spaces. Click New, or tick the plaintext option.");
    if (all.length) return showErrors(all);
    const secret: PasswordSecret = $("plaintext").checked ? { kind: "password", password } : { kind: "scram", verifier: await scramSha256Verifier(password) };
    const plan = planPostgres(v.config!, { now, secret, generator: `ROUA web generator ${VERSION}` });
    const yamlConfig = { ...v.config!, auth: { ...v.config!.auth, password_env: "ROUA_PASSWORD" } };
    files = [
      { name: "setup.sql", run: `psql "$ADMIN_DATABASE_URL" -v ON_ERROR_STOP=1 -f setup.sql`, content: plan.setupSql },
      { name: "audit.sql", run: `psql "$ADMIN_DATABASE_URL" -f audit.sql`, content: plan.auditSql },
      { name: "revoke.sql", run: `psql "$ADMIN_DATABASE_URL" -f revoke.sql`, content: plan.revokeSql },
      { name: "drop.sql", run: `psql "$ADMIN_DATABASE_URL" -f drop.sql`, content: plan.dropSql },
      {
        name: "roua.yaml",
        run: "npx @roua-dev/cli plan / apply / verify",
        content: configToYaml(yamlConfig, "ROUA 0.1 account definition. Never put a password in this file.\nUse with the roua CLI: roua plan / roua apply / roua verify"),
      },
    ];
    warnings = [...v.warnings, ...plan.warnings];
    manualSteps = plan.manualSteps;
  } else {
    const spec = otherSpec();
    const v = validateSpec(spec, now);
    if (v.errors.length) return showErrors(v.errors);
    try {
      const plan = planEngine(spec, now);
      files = plan.files;
      warnings = [...plan.validationWarnings, ...plan.warnings];
      manualSteps = plan.manualSteps;
    } catch (e) {
      return showErrors([e instanceof RouaInputError ? e.message : String(e)]);
    }
  }

  const tabs = $("tabs");
  tabs.replaceChildren(
    ...files.map((f) => {
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = f.name;
      b.setAttribute("role", "tab");
      b.addEventListener("click", () => show(f.name));
      return b;
    }),
  );
  const notes: string[] = [];
  if (ENGINE_INFO[engine].support === "preview") {
    notes.push(`<p class="preview"><b>Preview.</b> ${esc(ENGINE_INFO[engine].name)} scripts are generated from the vendor's documentation and have not yet been run against a live service. Review them before use. Have an account to test on? <a href="https://github.com/PromiseGithub/roua/issues/new?template=database.yml" target="_blank" rel="noopener noreferrer">Tell us what worked and what failed</a>: it is how preview engines become tested.</p>`);
  }
  if (warnings.length) notes.push(`<div class="warn"><h3>Warnings</h3><ul>${warnings.map((w) => `<li>${esc(w)}</li>`).join("")}</ul></div>`);
  if (manualSteps.length) {
    notes.push(`<h3>Before you rely on it</h3><ul>${manualSteps.map((m) => `<li>${m.startsWith("  ") ? `<code>${esc(m.trim())}</code>` : esc(m)}</li>`).join("")}</ul>`);
  }
  $("notes").innerHTML = notes.join("");
  $("setupName").textContent = files[0]!.name;
  $("empty").hidden = true;
  $("result").hidden = false;
  show(files[0]!.name);
  $("result").scrollIntoView({ block: "nearest" });
}

const fileByName = (name: string) => files.find((f) => f.name === name);

function show(name: string) {
  current = name;
  const f = fileByName(name);
  $("code").textContent = f?.content ?? "";
  $("run").innerHTML = f ? `Run: <code>${esc(f.run)}</code>` : "";
  document.querySelectorAll<HTMLButtonElement>("#tabs button").forEach((b) => b.setAttribute("aria-selected", String(b.textContent === name)));
}

// ------------------------------------------------------------------ Snowflake key pair

const pem = (label: string, der: ArrayBuffer) => {
  let s = "";
  for (const b of new Uint8Array(der)) s += String.fromCharCode(b);
  const b64 = btoa(s).replace(/(.{64})/g, "$1\n");
  return `-----BEGIN ${label}-----\n${b64.trimEnd()}\n-----END ${label}-----\n`;
};

async function generateKeyPair() {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    $("publicKey").value = "";
    $("publicKey").placeholder = "Key generation needs a secure page (https or a saved file). Use: openssl genrsa 2048 | openssl pkcs8 -topk8 -nocrypt -out rsa_key.p8 && openssl rsa -in rsa_key.p8 -pubout";
    return;
  }
  const kp = await subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  $("publicKey").value = pem("PUBLIC KEY", await subtle.exportKey("spki", kp.publicKey));
  privateKeyPem = pem("PRIVATE KEY", await subtle.exportKey("pkcs8", kp.privateKey));
  $("dlKey").hidden = false;
  flash($("genKey"), "Generated. Download the private key now");
}

// ------------------------------------------------------------------ check an existing account

function initCheck() {
  const sel = $<HTMLSelectElement>("cEngine");
  for (const id of ENGINES) sel.add(new Option(ENGINE_INFO[id].name, id));
  const refreshCheck = () => {
    const e = sel.value as Engine;
    document.querySelectorAll<HTMLElement>("[data-cengines]").forEach((el) => (el.hidden = !(el.dataset.cengines ?? "").split(" ").includes(e)));
    $("cDbLabel").textContent = e === "bigquery" ? "Project ID" : e === "mongodb" ? "Authentication database" : "Database";
    if (e === "mongodb" && $("cDatabase").value === "appdb") $("cDatabase").value = "admin";
    if (e !== "mongodb" && $("cDatabase").value === "admin") $("cDatabase").value = "appdb";
    $("cHint").innerHTML =
      e === "postgresql"
        ? "Or run it with Node.js: <code>npx @roua-dev/cli audit --role NAME</code>, or every login role at once with <code>--all</code>."
        : ENGINE_INFO[e].support === "preview"
          ? "Preview: review the script before running it."
          : "";
  };
  sel.addEventListener("change", refreshCheck);
  refreshCheck();
  $("checkForm").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const e = sel.value as Engine;
    const name = $("cName").value.trim();
    const errEl = $("cErrors");
    errEl.hidden = true;
    try {
      if (e === "postgresql") {
        if (!/^[A-Za-z_][A-Za-z0-9_$]{0,62}$/.test(name)) throw new RouaInputError("Role name: letters, digits, _ or $.");
        checkFile = { name: "audit.sql", run: `psql "$ADMIN_DATABASE_URL" -f audit.sql`, content: renderAuditSql(name) };
      } else {
        checkFile = auditScript(
          {
            engine: e,
            name,
            host: $("cHost").value,
            database: $("cDatabase").value,
            role: $("cRole").value,
            location: $("cLocation").value,
            contained: $("cContained").checked,
          },
          new Date(),
        );
      }
    } catch (err) {
      errEl.textContent = err instanceof Error ? err.message : String(err);
      errEl.hidden = false;
      return;
    }
    $("cCode").textContent = checkFile.content;
    $("cRun").innerHTML = `Run: <code>${esc(checkFile.run)}</code>`;
    $("cEmpty").hidden = true;
    $("cResult").hidden = false;
  });
  $("cCopy").addEventListener("click", () => copy(checkFile?.content ?? "", $("cCopy")));
  $("cDownload").addEventListener("click", () => checkFile && download(checkFile.name, checkFile.content));
}

// ------------------------------------------------------------------ utilities

async function copy(text: string, button: HTMLElement) {
  try {
    await navigator.clipboard.writeText(text);
    flash(button, "Copied");
  } catch {
    flash(button, "Select and copy manually");
  }
}

function flash(button: HTMLElement, text: string) {
  const old = button.textContent;
  button.textContent = text;
  setTimeout(() => (button.textContent = old), 1800);
}

function download(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

init();
