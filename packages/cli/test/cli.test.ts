/**
 * CLI tests over the real PostgreSQL wire protocol (PGlite socket server).
 * PGlite has a single session, so logging in as a *different* user (apply ->
 * verify) is covered by postgres.pg.test.ts against a real server in CI.
 */
import { PGlite } from "@electric-sql/pglite";
import { PGLiteSocketServer } from "@electric-sql/pglite-socket";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { main } from "../src/index.js";

let db: PGlite;
let server: PGLiteSocketServer;
const PORT = 54329 + Math.floor(Math.random() * 500);

function io() {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out,
    err,
    io: { out: (s: string) => out.push(s), err: (s: string) => err.push(s), confirm: async () => true, color: false },
  };
}

beforeAll(async () => {
  db = await PGlite.create();
  await db.exec(`
    CREATE TABLE public.products (id serial PRIMARY KEY, name text);
    CREATE TABLE public.users (id serial PRIMARY KEY, email text, password_hash text);
    CREATE ROLE readonly LOGIN PASSWORD 'readonly';
    GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly;
    GRANT INSERT ON public.products TO readonly;
  `);
  server = new PGLiteSocketServer({ db, port: PORT, host: "127.0.0.1" });
  await server.start();
  process.env.ADMIN_DATABASE_URL = `postgres://postgres:postgres@127.0.0.1:${PORT}/postgres`;
});

afterAll(async () => {
  await server?.stop();
  await db?.close();
});

describe("roua CLI", () => {
  it("prints help", async () => {
    const t = io();
    expect(await main(["--help"], t.io)).toBe(0);
    expect(t.out.join()).toContain("Is your read-only user actually read-only?");
  });

  it("audit: exits 1 and explains why for a careless readonly user", async () => {
    const t = io();
    expect(await main(["audit", "--role", "readonly"], t.io)).toBe(1);
    const text = t.out.join("\n");
    expect(text).toMatch(/FAIL\s+T1/);
    expect(text).toContain("public.products: INSERT");
    expect(text).toMatch(/FAIL\s+X1/);
    expect(text).toContain("public.users.password_hash");
    expect(text).toMatch(/FAIL\s+R2/);
    expect(text).toContain("NOT READ-ONLY");
  });

  it("audit --json produces a machine-readable report", async () => {
    const t = io();
    await main(["audit", "--role", "readonly", "--json"], t.io);
    const report = JSON.parse(t.out.join(""));
    expect(report.role).toBe("readonly");
    expect(report.ok).toBe(false);
    expect(report.summary.fail).toBeGreaterThan(0);
  });

  it("refuses connection strings on the command line and missing env vars", async () => {
    const t = io();
    expect(await main(["audit", "--role", "x", "--url-env", "NOPE_NOT_SET"], t.io)).toBe(2);
    expect(t.err.join()).toContain("Set NOPE_NOT_SET");
  });

  it("init -> plan -> apply SQL -> audit passes -> list -> expire -> revoke", async () => {
    const dir = mkdtempSync(join(tmpdir(), "roua-cli-"));
    const file = join(dir, "roua.yaml");
    let t = io();
    expect(await main(["init", "-f", file, "--profile", "agent", "--name", "roua_agent_cli", "--database", "postgres"], t.io)).toBe(0);
    // Adapt the starter file to this database.
    writeFileSync(file, readFileSync(file, "utf8").replace("object_owner: app_owner", "object_owner: postgres").replace(/scope:\n(  .*\n)+/, "scope:\n  exclude: []\n"));

    t = io();
    expect(await main(["plan", "-f", file, "--out", dir], t.io)).toBe(0);
    const setup = readFileSync(join(dir, "setup.sql"), "utf8");
    expect(setup).toContain('CREATE ROLE "roua_agent_cli" NOLOGIN');
    await db.exec(setup);

    t = io();
    expect(await main(["audit", "--role", "roua_agent_cli"], t.io)).toBe(0);
    expect(t.out.join("\n")).toContain("READ-ONLY");

    t = io();
    await main(["list"], t.io);
    expect(t.out.join("\n")).toMatch(/roua_agent_cli\s+agent\s+L2/);

    // Pretend the account expired.
    await db.exec(
      `COMMENT ON ROLE roua_agent_cli IS 'ROUA/0.1 profile=agent level=L2 owner=a@example.com expires=2020-01-01T00:00:00Z purpose="old"'; ALTER ROLE roua_agent_cli LOGIN;`,
    );
    t = io();
    await main(["expire", "--due", "--dry-run"], t.io);
    expect(t.out.join()).toContain("would revoke roua_agent_cli");
    t = io();
    await main(["expire", "--due"], t.io);
    expect(t.out.join()).toContain("revoked roua_agent_cli");
    expect((await db.query<{ rolcanlogin: boolean }>("SELECT rolcanlogin FROM pg_roles WHERE rolname = 'roua_agent_cli'")).rows[0]!.rolcanlogin).toBe(false);

    t = io();
    expect(await main(["revoke", "roua_agent_cli", "--drop", "--yes"], t.io)).toBe(0);
    expect((await db.query("SELECT 1 FROM pg_roles WHERE rolname = 'roua_agent_cli'")).rows).toHaveLength(0);
  });

  it("audit writes SARIF and JUnit, and samples values only when asked", async () => {
    await db.exec(`CREATE TABLE public.settings (id int, blob text);
      INSERT INTO public.settings VALUES (1, '{"stripe": "sk_live_abcdefghijklmnop1234"}');
      GRANT SELECT ON public.settings TO readonly;`);
    const dir = mkdtempSync(join(tmpdir(), "roua-out-"));
    const t = io();
    await main(["audit", "--role", "readonly", "--json", "--sarif-out", join(dir, "r.sarif"), "--junit-out", join(dir, "r.xml")], t.io);
    const sarif = JSON.parse(readFileSync(join(dir, "r.sarif"), "utf8"));
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].results.some((r: { ruleId: string; level: string }) => r.ruleId === "T1" && r.level === "error")).toBe(true);
    const junit = readFileSync(join(dir, "r.xml"), "utf8");
    expect(junit).toMatch(/<testsuite name="ROUA audit: readonly"[^>]*failures="[1-9]/);
    expect(JSON.parse(t.out.join("")).results.some((r: { id: string }) => r.id === "X2")).toBe(false);

    const s = io();
    await main(["audit", "--role", "readonly", "--json", "--sample-values", "5"], s.io);
    const x2 = JSON.parse(s.out.join("")).results.find((r: { id: string }) => r.id === "X2");
    expect(x2.severity).toBe("warn");
    expect(x2.details.join()).toContain("public.settings.blob: Stripe secret key");
    expect(s.out.join()).not.toContain("sk_live_abcdefghijklmnop1234");
    expect(await main(["audit", "--role", "readonly", "--sample-values", "9999"], io().io)).toBe(2);
  });

  it("rotate gives a ROUA account a new password and refuses others", async () => {
    await db.exec(`CREATE ROLE roua_rot_test LOGIN PASSWORD 'old';
      COMMENT ON ROLE roua_rot_test IS 'ROUA/0.1 profile=agent level=L2 owner=a@b.c created=2026-01-01 expires=2027-01-01T00:00:00.000Z purpose="t"';`);
    const before = (await db.query<{ p: string }>("SELECT rolpassword AS p FROM pg_authid WHERE rolname = 'roua_rot_test'")).rows[0]!.p;
    const dir = mkdtempSync(join(tmpdir(), "roua-rot-"));
    const t = io();
    expect(await main(["rotate", "roua_rot_test", "--secret-out", join(dir, "pw")], t.io)).toBe(0);
    const after = (await db.query<{ p: string }>("SELECT rolpassword AS p FROM pg_authid WHERE rolname = 'roua_rot_test'")).rows[0]!.p;
    expect(after).not.toBe(before);
    expect(after).toMatch(/^SCRAM-SHA-256\$4096:/);
    expect(readFileSync(join(dir, "pw"), "utf8").trim()).toMatch(/^[A-Za-z0-9]{32}$/);
    expect(t.out.join()).not.toContain(readFileSync(join(dir, "pw"), "utf8").trim());
    const comment = (await db.query<{ c: string }>("SELECT shobj_description(oid, 'pg_authid') AS c FROM pg_roles WHERE rolname = 'roua_rot_test'")).rows[0]!.c;
    expect(comment).toMatch(/ rotated=\d{4}-\d{2}-\d{2} purpose=/);
    expect(await main(["rotate", "readonly"], io().io)).toBe(2);
  });

  it("discover saves the schema and plan --check previews the scope against it", async () => {
    const dir = mkdtempSync(join(tmpdir(), "roua-check-"));
    const t = io();
    expect(await main(["discover", "--out", join(dir, "schema.json")], t.io)).toBe(0);
    const cols = JSON.parse(readFileSync(join(dir, "schema.json"), "utf8"));
    expect(cols.some((c: { table: string; column: string }) => c.table === "users" && c.column === "password_hash")).toBe(true);

    const yaml = (schemas: string, extra = "") => `roua_version: "0.1"
account:
  name: roua_check_test
  profile: agent
  level: L2
  owner: a@example.com
  purpose: test
  expires_at: "${new Date(Date.now() + 10 * 86400000).toISOString()}"
target:
  engine: postgresql
  database: postgres
  schemas: [${schemas}]
${extra}`;
    writeFileSync(join(dir, "ok.yaml"), yaml("public", "scope:\n  columns_deny: [public.users.emial]\n"));
    const ok = io();
    expect(await main(["plan", "--check", "-f", join(dir, "ok.yaml")], ok.io)).toBe(0);
    const okText = ok.out.join("\n");
    expect(okText).toMatch(/public\.users\s+\d of \d columns; hidden: password_hash \(secret\)/);
    expect(okText).toMatch(/WARN\s+Hidden-column entries matching no column: public\.users\.emial/);

    writeFileSync(join(dir, "bad.yaml"), yaml("pubic"));
    const bad = io();
    expect(await main(["plan", "--check", "-f", join(dir, "bad.yaml"), "--schema", join(dir, "schema.json")], bad.io)).toBe(1);
    expect(bad.out.join("\n")).toMatch(/ERROR\s+Not found in this database: pubic/);
  });

  it("rejects an invalid config with a clear message", async () => {
    const dir = mkdtempSync(join(tmpdir(), "roua-cli-"));
    const file = join(dir, "roua.yaml");
    writeFileSync(file, 'roua_version: "0.1"\naccount: { name: "Bad Name" }\n');
    const t = io();
    expect(await main(["plan", "-f", file], t.io)).toBe(2);
    expect(t.err.join()).toContain("account.name");
  });
});
