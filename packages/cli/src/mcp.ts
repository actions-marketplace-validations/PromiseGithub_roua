/**
 * `roua mcp`: a Model Context Protocol server over stdio.
 *
 * Deliberately dependency-free (JSON-RPC 2.0, one message per line) so the CLI
 * keeps its small supply chain. Tools:
 *
 *   list_engines              what ROUA supports, and how well it is tested
 *   audit_script              an audit script for an existing account (any engine)
 *   generate_account_scripts  ROUA setup/audit/revoke scripts, written to a folder;
 *                             passwords and private keys go to files with 0600
 *                             permissions and never into the conversation
 *   audit_postgres_role       live, read-only audit of a PostgreSQL role
 *                             (needs ADMIN_DATABASE_URL in the server's environment)
 *
 * Accepts the classic initialize handshake (protocol 2024-11-05 to 2025-11-25)
 * and also answers requests that arrive without one.
 */
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { createInterface } from "node:readline";
import {
  ENGINES,
  ENGINE_INFO,
  PROFILES,
  PROFILE_INFO,
  LEVELS,
  RouaInputError,
  auditRole,
  auditScript,
  formatReport,
  generatePassword,
  planEngine,
  planPostgres,
  renderAuditSql,
  scramSha256Verifier,
  discoveryScript,
  parseSchemaSnapshot,
  previewScope,
  snapshotTables,
  validateConfig,
  type AccountSpec,
  type Engine,
  type OtherEngine,
  type RouaConfig,
} from "@roua-dev/core";
import { connect } from "./db.js";

const SUPPORTED_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

type Json = Record<string, unknown>;
interface ToolResult {
  content: { type: "text"; text: string }[];
  isError?: boolean;
  structuredContent?: Json;
}

const str = { type: "string" } as const;
const strList = { type: "array", items: { type: "string" } } as const;

const TOOLS = [
  {
    name: "list_engines",
    title: "List ROUA databases",
    description: "List the databases ROUA supports, how well each is tested, and how read-only access works on each.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  {
    name: "audit_script",
    title: "Audit script for an existing account",
    description:
      "Write a read-only audit script that checks whether an existing database account is really read-only (write privileges, roles, ownership, secret columns, expiry). Returns the script text and how to run it. Connects to nothing.",
    inputSchema: {
      type: "object",
      properties: {
        engine: { type: "string", enum: [...ENGINES] },
        name: { ...str, description: "Account, role, login or user name to audit." },
        host: { ...str, description: "MySQL/MariaDB host part of 'user'@'host' (default %)." },
        database: { ...str, description: "SQL Server database, MongoDB auth database or BigQuery project id." },
        role: { ...str, description: "Snowflake role to inspect (default NAME_READ)." },
        location: { ...str, description: "BigQuery location (default US)." },
      },
      required: ["engine", "name"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  {
    name: "generate_account_scripts",
    title: "Generate ROUA account scripts",
    description:
      "Generate the scripts that create a read-only ROUA account (setup, audit, revoke, drop) and write them to a new folder. The password or private key is written to a file in that folder with owner-only permissions and is never returned. Nothing is run against any database: a human runs setup as an administrator.",
    inputSchema: {
      type: "object",
      properties: {
        engine: { type: "string", enum: [...ENGINES] },
        output_dir: { ...str, description: "Absolute path of a new or empty folder to write the scripts to." },
        name: { ...str, description: "Account name: lowercase, 3-63 chars, e.g. roua_agent_docs." },
        profile: { type: "string", enum: [...PROFILES] },
        owner: { ...str, description: "Accountable person (email)." },
        purpose: str,
        expires_at: { ...str, description: "ISO 8601 UTC, within the profile's maximum lifetime." },
        level: { type: "string", enum: [...LEVELS], description: "PostgreSQL only (default from the profile)." },
        mode: { type: "string", enum: ["scope", "listed", "metadata"], description: "Other engines: everything in scope minus exclusions (L2), only listed objects (L1), or structure only (L0, where the engine supports it)." },
        database: { ...str, description: "Database, project id (BigQuery) as the engine needs." },
        schemas: { ...strList, description: "Schemas, databases (MySQL), owners (Oracle) or datasets (BigQuery)." },
        objects: { ...strList, description: "Listed mode / PostgreSQL L1: schema.table (collections for MongoDB, key patterns for Redis)." },
        exclude: { ...strList, description: "schema.table patterns to leave out." },
        columns_deny: { ...strList, description: "schema.table.column to hide besides detected secrets." },
        allowed_sources: strList,
        max_connections: { type: "integer" },
        statement_timeout_s: { type: "integer" },
        warehouse: { ...str, description: "Snowflake warehouse." },
        location: { ...str, description: "BigQuery location." },
        password_env: { ...str, description: "Name of an environment variable of this server holding the password. Default: generate one." },
      },
      required: ["engine", "output_dir", "name", "profile", "owner", "purpose", "expires_at"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  {
    name: "audit_postgres_role",
    title: "Audit a PostgreSQL role (live)",
    description:
      "Connect with ADMIN_DATABASE_URL (from this server's environment) and audit a PostgreSQL role: every path to write, secret columns it can read, expiry and limits. Only reads catalog views; changes nothing.",
    inputSchema: {
      type: "object",
      properties: { role: { ...str, description: "Role name to audit." } },
      required: ["role"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  {
    name: "preview_scope",
    title: "Preview an account's scope against a schema",
    description:
      "Before generating anything, show exactly what an account would read in a real schema: which tables, which columns stay hidden and why, and which schemas, listed names, exclusions or hidden-column entries match nothing (typos). Pass the output of the discovery script (JSON, CSV or psql table). Connects to nothing.",
    inputSchema: {
      type: "object",
      properties: {
        engine: { type: "string", enum: [...ENGINES] },
        schema: { ...str, description: "Output of the discovery script (discover.sql / discover.js) or roua discover: JSON, CSV/TSV with schema,table,column headers, or psql table output." },
        level: { type: "string", enum: [...LEVELS], description: "PostgreSQL: L0 to L5." },
        mode: { type: "string", enum: ["scope", "listed", "metadata"], description: "Other engines." },
        database: { ...str, description: "MongoDB database." },
        schemas: strList,
        objects: { ...strList, description: "Listed objects (L1, or analytics views for PostgreSQL L3)." },
        include: strList,
        exclude: strList,
        columns_deny: strList,
        columns_allow: strList,
      },
      required: ["engine", "schema"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  {
    name: "discover_postgres_schema",
    title: "Read a PostgreSQL schema (live, names only)",
    description:
      "Connect with ADMIN_DATABASE_URL and list schemas, tables, views and columns with their types: names only, never rows. Use it to learn how a database is structured, or feed it to preview_scope.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
];

const text =(t: string, extra: Partial<ToolResult> = {}): ToolResult => ({ content: [{ type: "text", text: t }], ...extra });
const fail = (t: string): ToolResult => text(t, { isError: true });
const asList = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : []);
const asStr = (v: unknown): string | undefined => (typeof v === "string" && v.trim() ? v.trim() : undefined);

async function callTool(name: string, args: Json): Promise<ToolResult> {
  switch (name) {
    case "list_engines":
      return text(
        ENGINES.map((e) => {
          const i = ENGINE_INFO[e];
          return `${i.name} [${i.support}] ${i.versions}: ${i.summary}${i.covers ? ` Also covers: ${i.covers}.` : ""}`;
        }).join("\n") +
          "\n\nfull = CLI with live verify; tested = scripts run against the real engine in CI on every change; preview = from vendor docs, not yet tested live.",
      );

    case "audit_script": {
      const engine = String(args.engine) as Engine;
      if (!ENGINES.includes(engine)) return fail(`Unknown engine ${engine}`);
      const accountName = String(args.name ?? "");
      if (engine === "postgresql") {
        if (!/^[A-Za-z_][A-Za-z0-9_$]{0,62}$/.test(accountName)) return fail("Role name: letters, digits, _ or $.");
        return text(`Run: psql "$ADMIN_DATABASE_URL" -f audit.sql\n\n${renderAuditSql(accountName)}`);
      }
      const s = auditScript({
        engine,
        name: accountName,
        host: asStr(args.host),
        database: asStr(args.database),
        role: asStr(args.role),
        location: asStr(args.location),
      });
      return text(`File: ${s.name}\nRun: ${s.run}\n\n${s.content}`);
    }

    case "generate_account_scripts":
      return generate(args);

    case "audit_postgres_role": {
      const url = process.env.ADMIN_DATABASE_URL;
      if (!url) return fail("Set ADMIN_DATABASE_URL in this MCP server's environment to use the live audit.");
      const role = String(args.role ?? "");
      if (!/^[A-Za-z_][A-Za-z0-9_$]{0,62}$/.test(role)) return fail("Role name: letters, digits, _ or $.");
      const conn = await connect(url);
      try {
        const report = await auditRole(conn.exec, role);
        return text(formatReport(report, { color: false }), { structuredContent: report as unknown as Json });
      } finally {
        await conn.close();
      }
    }

    case "preview_scope": {
      const engine = String(args.engine) as Engine;
      if (!ENGINES.includes(engine)) return fail(`Unknown engine ${engine}`);
      let snap;
      try {
        snap = parseSchemaSnapshot(String(args.schema ?? ""), engine);
      } catch (e) {
        return fail((e as Error).message);
      }
      const level = asStr(args.level);
      const pgMode = level === "L0" ? "metadata" : level === "L1" || level === "L3" ? "listed" : "scope";
      const mode = engine === "postgresql" ? pgMode : args.mode === "listed" || engine === "redis" ? "listed" : args.mode === "metadata" ? "metadata" : "scope";
      const db = asStr(args.database) ?? "";
      const mongo = engine === "mongodb";
      const preview = previewScope(
        {
          engine,
          mode,
          schemas: mongo ? [db] : asList(args.schemas),
          include: asList(args.include),
          objects: mongo ? asList(args.objects).map((o) => `${db}.${o}`) : asList(args.objects),
          exclude: mongo ? asList(args.exclude).map((o) => `${db}.${o}`) : asList(args.exclude),
          columnsDeny: asList(args.columns_deny),
          columnsAllow: asList(args.columns_allow),
          viewsOnly: engine === "postgresql" && level === "L3",
          columnGrants: "always",
        },
        snap,
      );
      const lines = [
        ...preview.errors.map((e) => `ERROR: ${e}`),
        ...preview.warnings.map((w) => `WARNING: ${w}`),
        ...preview.notes.map((n) => `NOTE: ${n}`),
        "",
        ...preview.objects.map((o) => `${o.name}: ${o.access === "all" ? "all columns" : o.access === "partial" ? `${o.visible.length} visible, hidden ${o.hidden.map((h) => `${h.column} (${h.reason})`).join(", ")}` : "skipped"}`),
      ];
      return text(lines.join("\n").trim(), { structuredContent: preview as unknown as Json });
    }

    case "discover_postgres_schema": {
      const url = process.env.ADMIN_DATABASE_URL;
      if (!url) return fail("Set ADMIN_DATABASE_URL in this MCP server's environment to read the schema.");
      const conn = await connect(url);
      try {
        const sql = discoveryScript("postgresql")!.content.split("\n").filter((l) => !l.startsWith("--")).join("\n");
        const rows = await conn.exec(sql);
        const snap = parseSchemaSnapshot(JSON.stringify(Object.values(rows[0] ?? {})[0] ?? []), "postgresql");
        const tables = snapshotTables(snap);
        const summary = tables.map((t) => `${t.schema}.${t.table}${t.kind === "view" ? " (view)" : ""}: ${t.columns.map((c) => `${c.column}${c.type ? ` ${c.type}` : ""}`).join(", ")}`);
        return text(`${tables.length} table(s) and view(s). Names and types only, no rows.\n\n${summary.join("\n")}`, { structuredContent: { columns: snap.columns } as unknown as Json });
      } finally {
        await conn.close();
      }
    }
  }
  return fail(`Unknown tool ${name}`);
}

async function generate(args: Json): Promise<ToolResult> {
  const engine = String(args.engine) as Engine;
  if (!ENGINES.includes(engine)) return fail(`Unknown engine ${engine}`);
  const dirArg = String(args.output_dir ?? "");
  if (!isAbsolute(dirArg)) return fail("output_dir must be an absolute path.");
  const dir = resolve(dirArg);
  if (existsSync(dir) && readdirSync(dir).length) return fail(`${dir} is not empty. Choose a new or empty folder.`);

  const envName = asStr(args.password_env);
  if (envName && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(envName)) return fail("password_env must be an environment variable name.");
  const password = envName ? process.env[envName] : generatePassword(32);
  if (!password) return fail(`Environment variable ${envName} is not set.`);
  const now = new Date();
  const files: { name: string; run: string; content: string }[] = [];
  const secrets: { name: string; content: string }[] = [];
  let notes: string[] = [];

  try {
    if (engine === "postgresql") {
      const level = (asStr(args.level) ?? undefined) as RouaConfig["account"]["level"] | undefined;
      const scope: NonNullable<RouaConfig["scope"]> = {};
      if (asList(args.exclude).length) scope.exclude = asList(args.exclude);
      if (asList(args.objects).length) scope.public_objects = asList(args.objects);
      if (asList(args.columns_deny).length) scope.columns_deny = asList(args.columns_deny);
      const limits: Record<string, number> = {};
      if (typeof args.max_connections === "number") limits.max_connections = args.max_connections;
      if (typeof args.statement_timeout_s === "number") limits.statement_timeout_s = args.statement_timeout_s;
      const profile = String(args.profile) as RouaConfig["account"]["profile"];
      const cfg = {
        roua_version: "0.1",
        account: {
          name: String(args.name),
          profile,
          level: level ?? PROFILE_INFO[profile]?.defaultLevel ?? "L2",
          owner: String(args.owner),
          purpose: String(args.purpose),
          expires_at: String(args.expires_at),
          ...(Object.keys(limits).length ? { limits } : {}),
          ...(asList(args.allowed_sources).length ? { network: { allowed_sources: asList(args.allowed_sources) } } : {}),
        },
        target: { engine: "postgresql", database: asStr(args.database) ?? "postgres", schemas: asList(args.schemas).length ? asList(args.schemas) : ["public"] },
        ...(Object.keys(scope).length ? { scope } : {}),
        auth: { method: "scram_verifier" },
      } as unknown as RouaConfig;
      const v = validateConfig(cfg, { now });
      if (v.errors.length) return fail(`Fix these first:\n- ${v.errors.join("\n- ")}`);
      const plan = planPostgres(v.config!, { now, secret: { kind: "scram", verifier: await scramSha256Verifier(password) }, generator: "roua mcp" });
      files.push(
        { name: "setup.sql", run: `psql "$ADMIN_DATABASE_URL" -v ON_ERROR_STOP=1 -f setup.sql`, content: plan.setupSql },
        { name: "audit.sql", run: `psql "$ADMIN_DATABASE_URL" -f audit.sql`, content: plan.auditSql },
        { name: "revoke.sql", run: `psql "$ADMIN_DATABASE_URL" -f revoke.sql`, content: plan.revokeSql },
        { name: "drop.sql", run: `psql "$ADMIN_DATABASE_URL" -f drop.sql`, content: plan.dropSql },
      );
      notes = [...v.warnings, ...plan.warnings, ...plan.manualSteps];
      secrets.push({ name: "PASSWORD.txt", content: password + "\n" });
    } else {
      let publicKey: string | undefined;
      if (engine === "snowflake") {
        const kp = generateKeyPairSync("rsa", { modulusLength: 2048, publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
        publicKey = kp.publicKey;
        secrets.push({ name: "rsa_key.p8", content: kp.privateKey });
      }
      const spec: AccountSpec = {
        engine: engine as OtherEngine,
        name: String(args.name),
        profile: String(args.profile) as AccountSpec["profile"],
        owner: String(args.owner),
        purpose: String(args.purpose),
        expiresAt: String(args.expires_at),
        mode: engine === "redis" || args.mode === "listed" ? "listed" : args.mode === "metadata" ? "metadata" : "scope",
        database: asStr(args.database),
        schemas: asList(args.schemas),
        objects: asList(args.objects),
        exclude: asList(args.exclude),
        columnsDeny: asList(args.columns_deny),
        password: ENGINE_INFO[engine].fields.password === "verifier" || ENGINE_INFO[engine].fields.password === "plaintext" ? password : undefined,
        maxConnections: typeof args.max_connections === "number" ? args.max_connections : undefined,
        statementTimeoutS: typeof args.statement_timeout_s === "number" ? args.statement_timeout_s : undefined,
        allowedSources: asList(args.allowed_sources),
        warehouse: asStr(args.warehouse),
        location: asStr(args.location),
        publicKey,
      };
      const plan = planEngine(spec, now);
      files.push(...plan.files);
      notes = [...plan.validationWarnings, ...plan.warnings, ...plan.manualSteps];
      if (spec.password) secrets.push({ name: "PASSWORD.txt", content: password + "\n" });
    }
  } catch (e) {
    if (e instanceof RouaInputError) return fail(`Fix these first:\n- ${e.message.split("\n").join("\n- ")}`);
    throw e;
  }

  mkdirSync(dir, { recursive: true });
  for (const f of files) writeFileSync(join(dir, f.name), f.content);
  for (const s of secrets) writeFileSync(join(dir, s.name), s.content, { mode: 0o600 });
  const lines = [
    `Wrote ${files.length} script(s) for ${ENGINE_INFO[engine].name} to ${dir}:`,
    ...files.map((f) => `  ${f.name}    run: ${f.run}`),
    ...(secrets.length
      ? [`Credentials: ${secrets.map((s) => s.name).join(", ")} in the same folder (owner-only permissions). They are not shown here. Move them to a password manager or secrets store, then delete the files.`]
      : []),
    "Nothing has been run. A human administrator should read setup, run it, then run the audit: every check should pass.",
    ...(notes.length ? ["", "Notes:", ...notes.map((n) => `- ${n.trim()}`)] : []),
  ];
  return text(lines.join("\n"), { structuredContent: { output_dir: dir, files: files.map((f) => f.name), credential_files: secrets.map((s) => s.name) } });
}

/** Handle one JSON-RPC message; returns the response, or null for notifications. */
export async function handleMessage(msg: Json, version: string): Promise<Json | null> {
  const id = msg.id as string | number | undefined;
  const method = String(msg.method ?? "");
  const params = (msg.params ?? {}) as Json;
  const isNotification = id === undefined || id === null;
  const ok = (result: Json) => ({ jsonrpc: "2.0", id, result });
  const err = (code: number, message: string) => ({ jsonrpc: "2.0", id: id ?? null, error: { code, message } });
  if (msg.jsonrpc !== "2.0" || !method) return isNotification ? null : err(-32600, "Invalid request");
  if (isNotification) return null;
  switch (method) {
    case "initialize": {
      const asked = String(params.protocolVersion ?? "");
      return ok({
        protocolVersion: SUPPORTED_VERSIONS.includes(asked) ? asked : SUPPORTED_VERSIONS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "roua", title: "ROUA: read-only database accounts", version },
        instructions:
          "ROUA creates and checks read-only database accounts. Use audit_script or audit_postgres_role to check an existing account, and generate_account_scripts to prepare a new one (scripts go to a folder; a human runs them). Feedback and ideas: https://github.com/PromiseGithub/roua/discussions",
      });
    }
    case "ping":
      return ok({});
    case "tools/list":
      return ok({ tools: TOOLS });
    case "tools/call": {
      const name = String(params.name ?? "");
      if (!TOOLS.some((t) => t.name === name)) return err(-32602, `Unknown tool: ${name}`);
      try {
        return ok((await callTool(name, (params.arguments ?? {}) as Json)) as unknown as Json);
      } catch (e) {
        return ok(fail(`Error: ${(e as Error).message}`) as unknown as Json);
      }
    }
    case "resources/list":
      return ok({ resources: [] });
    case "prompts/list":
      return ok({ prompts: [] });
    default:
      return err(-32601, `Method not found: ${method}`);
  }
}

/** Serve MCP over stdin/stdout until stdin closes. Logs go to stderr only. */
export function serveMcp(version: string): Promise<void> {
  return new Promise((done) => {
    const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
    let pending = Promise.resolve();
    rl.on("line", (line) => {
      if (!line.trim()) return;
      pending = pending.then(async () => {
        let msg: Json;
        try {
          msg = JSON.parse(line) as Json;
        } catch {
          process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }) + "\n");
          return;
        }
        const res = await handleMessage(msg, version);
        if (res) process.stdout.write(JSON.stringify(res) + "\n");
      });
    });
    rl.on("close", () => void pending.then(done));
    process.stderr.write(`roua mcp ${version}: ready on stdio\n`);
  });
}
