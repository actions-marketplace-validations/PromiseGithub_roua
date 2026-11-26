import { PGlite } from "@electric-sql/pglite";
import { describe, expect, it } from "vitest";
import {
  discoveryScript,
  parseSchemaSnapshot,
  previewScope,
  scopeFromPostgresConfig,
  scopeFromSpec,
  snapshotTables,
  type AccountSpec,
  type RouaConfig,
  type SchemaSnapshot,
} from "@roua-dev/core";

const SNAP: SchemaSnapshot = parseSchemaSnapshot(
  JSON.stringify([
    { schema: "app", table: "customers", column: "id" },
    { schema: "app", table: "customers", column: "name" },
    { schema: "app", table: "customers", column: "national_id" },
    { schema: "app", table: "users", column: "id" },
    { schema: "app", table: "users", column: "email" },
    { schema: "app", table: "users", column: "password_hash" },
    { schema: "app", table: "salaries", column: "amount" },
    { schema: "app", table: "tokens", column: "api_token" },
    { schema: "app", table: "sales_by_month", column: "total", kind: "view" },
    { schema: "other", table: "x", column: "y" },
  ]),
);

const spec = (over: Partial<AccountSpec> = {}): AccountSpec => ({
  engine: "mysql", name: "roua_t", profile: "agent", owner: "a@b.c", purpose: "p", expiresAt: "2030-01-01T00:00:00Z",
  mode: "scope", schemas: ["app"], exclude: ["app.salaries"], columnsDeny: ["app.customers.national_id"], ...over,
});

describe("parseSchemaSnapshot", () => {
  it("reads JSON with any common key names, CSV, TSV and psql tables", () => {
    const forms = [
      JSON.stringify([{ TABLE_SCHEMA: "app", TABLE_NAME: "t", COLUMN_NAME: "c", DATA_TYPE: "int" }]),
      JSON.stringify({ columns: [{ schema: "app", table: "t", column: "c" }] }),
      "schema,table,column\napp,t,c\n",
      "table_schema\ttable_name\tcolumn_name\napp\tt\tc\n",
      " schema | table | column \n--------+-------+--------\n app    | t     | c\n(1 row)\n",
      '[{"schema":"app","table":"t",\n"column":"c"}]',
    ];
    for (const f of forms) {
      const s = parseSchemaSnapshot(f);
      expect(s.columns, f).toEqual([expect.objectContaining({ schema: "app", table: "t", column: "c" })]);
    }
  });
  it("explains what is wrong with unusable input", () => {
    expect(() => parseSchemaSnapshot("")).toThrow(/empty/);
    expect(() => parseSchemaSnapshot("hello")).toThrow(/Could not read/);
    expect(() => parseSchemaSnapshot('[{"foo":1}]')).toThrow(/No columns/);
  });
  it("groups columns into tables and removes duplicates", () => {
    const s = parseSchemaSnapshot(JSON.stringify([{ schema: "a", table: "t", column: "c" }, { schema: "a", table: "t", column: "c" }]));
    expect(snapshotTables(s)).toHaveLength(1);
    expect(s.columns).toHaveLength(1);
  });
});

describe("previewScope", () => {
  it("shows what MySQL will grant, hide and skip", () => {
    const p = previewScope(scopeFromSpec(spec()), SNAP);
    const by = Object.fromEntries(p.objects.map((o) => [o.name, o]));
    expect(by["app.customers"]!.access).toBe("partial");
    expect(by["app.customers"]!.hidden).toEqual([{ column: "national_id", reason: "denied" }]);
    expect(by["app.users"]!.hidden).toEqual([{ column: "password_hash", reason: "secret" }]);
    expect(by["app.tokens"]!.access).toBe("skipped");
    expect(by["app.salaries"]).toBeUndefined();
    expect(by["other.x"]).toBeUndefined();
    expect(p.errors).toEqual([]);
  });

  it("catches typos: missing schemas, listed names, deny entries", () => {
    const p = previewScope(scopeFromSpec(spec({ schemas: ["App2"], columnsDeny: ["app.customers.nationalid"] })), SNAP);
    expect(p.missingSchemas).toEqual(["App2"]);
    expect(p.errors.join()).toMatch(/Not found.*App2/);
    expect(p.errors.join()).toMatch(/matches no readable tables/);
    expect(p.unmatchedDenies).toEqual(["app.customers.nationalid"]);

    const l = previewScope(scopeFromSpec(spec({ mode: "listed", objects: ["app.customers", "app.custmers"] })), SNAP);
    expect(l.unmatchedObjects).toEqual(["app.custmers"]);
    expect(l.readableObjects).toBe(1);
  });

  it("is case-insensitive where the engine is, and exact on PostgreSQL", () => {
    expect(previewScope(scopeFromSpec(spec({ engine: "oracle", schemas: ["APP"] })), SNAP).missingSchemas).toEqual([]);
    const pg = { roua_version: "0.1", account: { level: "L2" }, target: { engine: "postgresql", database: "d", schemas: ["APP"] } } as unknown as RouaConfig;
    expect(previewScope(scopeFromPostgresConfig(pg), SNAP).missingSchemas).toEqual(["APP"]);
  });

  it("skips tables with hidden columns on engines without column grants", () => {
    const p = previewScope(scopeFromSpec(spec({ engine: "oracle" })), SNAP);
    expect(p.objects.find((o) => o.name === "app.users")!.access).toBe("skipped");
    expect(p.warnings.join()).toMatch(/cannot hide single columns/);
  });

  it("warns that MongoDB fields cannot be hidden", () => {
    const mongo = parseSchemaSnapshot(JSON.stringify([{ schema: "appdb", table: "users", column: "passwordHash" }, { schema: "appdb", table: "users", column: "email" }]));
    const p = previewScope(scopeFromSpec(spec({ engine: "mongodb", database: "appdb", schemas: undefined, exclude: [] })), mongo);
    expect(p.exposedSecrets).toEqual(["appdb.users.passwordHash"]);
  });

  it("L0 sees structure only and L3 only views", () => {
    expect(previewScope(scopeFromSpec(spec({ engine: "sqlserver", mode: "metadata" })), SNAP).errors).toEqual([]);
    const l3 = { roua_version: "0.1", account: { level: "L3" }, target: { engine: "postgresql", database: "d", schemas: ["app"] }, scope: { analytics_views: ["app.sales_by_month", "app.customers"] } } as unknown as RouaConfig;
    const p = previewScope(scopeFromPostgresConfig(l3), SNAP);
    expect(p.objects.map((o) => o.name)).toEqual(["app.sales_by_month"]);
    expect(p.unmatchedObjects).toEqual(["app.customers"]);
  });
});

describe("discovery scripts", () => {
  it("exist for every engine with a schema", () => {
    for (const e of ["postgresql", "mysql", "mariadb", "sqlserver", "oracle", "mongodb", "snowflake", "bigquery"] as const) {
      expect(discoveryScript(e, { database: "appdb", project: "my-project-123", datasets: ["analytics"] })!.content).toMatch(/Read-only/);
    }
    expect(discoveryScript("redis")).toBeNull();
  });

  it("the PostgreSQL script runs and round-trips through the parser", async () => {
    const db = await PGlite.create();
    await db.exec(`CREATE SCHEMA app; CREATE TABLE app.users (id int, email text, password_hash text); CREATE VIEW app.v AS SELECT id FROM app.users;`);
    const sql = discoveryScript("postgresql")!.content.split("\n").filter((l) => !l.startsWith("--")).join("\n");
    const res = await db.query<{ coalesce: unknown }>(sql);
    const snap = parseSchemaSnapshot(JSON.stringify(Object.values(res.rows[0]!)[0]));
    expect(snapshotTables(snap).map((t) => `${t.schema}.${t.table}:${t.kind}`)).toEqual(["app.users:table", "app.v:view"]);
    await db.close();
  });
});
