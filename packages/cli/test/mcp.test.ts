import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { handleMessage } from "../src/mcp.js";

const call = (id: number, method: string, params: Record<string, unknown> = {}) =>
  handleMessage({ jsonrpc: "2.0", id, method, params }, "test") as Promise<{ result?: any; error?: any }>;
const tool = async (name: string, args: Record<string, unknown>) => (await call(1, "tools/call", { name, arguments: args })).result;
const expires = () => new Date(Date.now() + 20 * 86_400_000).toISOString();

describe("roua mcp", () => {
  it("negotiates the protocol version and lists tools", async () => {
    expect((await call(1, "initialize", { protocolVersion: "2025-06-18" })).result.protocolVersion).toBe("2025-06-18");
    expect((await call(1, "initialize", { protocolVersion: "1999-01-01" })).result.protocolVersion).toBe("2025-11-25");
    const tools = (await call(2, "tools/list")).result.tools.map((t: { name: string }) => t.name);
    expect(tools).toEqual(["list_engines", "audit_script", "generate_account_scripts", "audit_postgres_role", "preview_scope", "discover_postgres_schema"]);
    expect(await handleMessage({ jsonrpc: "2.0", method: "notifications/initialized" }, "t")).toBeNull();
    expect((await call(3, "nope")).error.code).toBe(-32601);
  });

  it("writes audit scripts for any engine", async () => {
    for (const engine of ["postgresql", "mysql", "sqlserver", "redis"]) {
      const r = await tool("audit_script", { engine, name: "readonly", database: "appdb" });
      expect(r.isError).toBeFalsy();
      expect(r.content[0].text).toMatch(/audit/i);
    }
  });

  it("generates scripts to a folder and never returns the password", async () => {
    for (const engine of ["postgresql", "mysql", "oracle", "snowflake"]) {
      const dir = join(mkdtempSync(join(tmpdir(), "roua-mcp-")), engine);
      const r = await tool("generate_account_scripts", {
        engine, output_dir: dir, name: "roua_agent_docs", profile: "agent", owner: "j@example.com", purpose: "Docs agent",
        expires_at: expires(), schemas: [engine === "oracle" ? "APP" : engine === "snowflake" ? "PUBLIC" : "public"],
        database: engine === "snowflake" ? "ANALYTICS" : "appdb", warehouse: "WH",
      });
      expect(r.isError, r.content[0].text).toBeFalsy();
      const files = readdirSync(dir);
      expect(files).toContain("setup.sql");
      const secretFile = engine === "snowflake" ? "rsa_key.p8" : "PASSWORD.txt";
      expect(files).toContain(secretFile);
      const secret = readFileSync(join(dir, secretFile), "utf8").trim();
      expect(JSON.stringify(r)).not.toContain(secret.slice(0, 40));
      if (engine === "postgresql" || engine === "mysql") expect(readFileSync(join(dir, "setup.sql"), "utf8")).not.toContain(secret);
    }
  });

  it("refuses relative or non-empty output folders and bad input", async () => {
    expect((await tool("generate_account_scripts", { engine: "mysql", output_dir: "rel", name: "x", profile: "agent", owner: "a", purpose: "b", expires_at: expires() })).isError).toBe(true);
    const r = await tool("generate_account_scripts", {
      engine: "mysql", output_dir: join(mkdtempSync(join(tmpdir(), "roua-mcp-")), "x"), name: "Bad'Name", profile: "agent",
      owner: "a@b.c", purpose: "p", expires_at: expires(), schemas: ["appdb"],
    });
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toMatch(/Account name/);
  });
});

describe("roua mcp: preview_scope", () => {
  it("shows hidden columns and catches typos before anything is generated", async () => {
    const schema = "schema,table,column\nshop,orders,id\nshop,customers,email\nshop,customers,password_hash\n";
    const r = await tool("preview_scope", { engine: "mysql", schema, schemas: ["shop"], columns_deny: ["shop.orders.totl"] });
    expect(r.isError).toBeFalsy();
    expect(r.content[0].text).toContain("shop.customers: 1 visible, hidden password_hash (secret)");
    expect(r.content[0].text).toMatch(/WARNING: Hidden-column entries matching no column: shop\.orders\.totl/);
    const bad = await tool("preview_scope", { engine: "mysql", schema, schemas: ["shopp"] });
    expect(bad.content[0].text).toMatch(/ERROR: Not found in this database: shopp/);
    expect((await tool("preview_scope", { engine: "mysql", schema: "nonsense" })).isError).toBe(true);
  });
});
