/**
 * End-to-end tests on a real PostgreSQL engine (PGlite: PostgreSQL compiled to
 * WebAssembly, running in-process). Privileges are enforced after SET ROLE, so
 * these tests prove the generated SQL works and that writes really fail.
 *
 * Password login is tested separately against a real server in CI
 * (postgres.pg.test.ts), since PGlite has no network authentication.
 */
import { PGlite } from "@electric-sql/pglite";
import { beforeAll, describe, expect, it } from "vitest";
import {
  auditRole,
  planPostgres,
  scramSha256Verifier,
  validateConfig,
  verifyCurrentUser,
  type Executor,
  type RouaConfig,
} from "@roua-dev/core";

const NOW = new Date();
const IN_30_DAYS = new Date(NOW.getTime() + 30 * 86_400_000).toISOString();

let db: PGlite;
const exec: Executor = async (sql) => (await db.query(sql)).rows as Record<string, unknown>[];

const FIXTURE = `
CREATE ROLE app_owner NOLOGIN;
CREATE SCHEMA sales AUTHORIZATION app_owner;
CREATE TABLE public.products (id serial PRIMARY KEY, name text, price numeric);
CREATE TABLE public.users (
  id serial PRIMARY KEY, full_name text, email text, phone text, date_of_birth date,
  national_id text, password_hash text, "mfaSecret" text, tokens_used int, created_at timestamptz DEFAULT now()
);
CREATE TABLE public.salaries (id serial PRIMARY KEY, user_id int, amount numeric);
CREATE TABLE public.api_keys (id serial PRIMARY KEY, label text, secret text);
CREATE TABLE sales.orders (id serial PRIMARY KEY, user_id int, total numeric);
ALTER TABLE public.products OWNER TO app_owner;
ALTER TABLE public.users OWNER TO app_owner;
ALTER TABLE public.salaries OWNER TO app_owner;
ALTER TABLE public.api_keys OWNER TO app_owner;
ALTER TABLE sales.orders OWNER TO app_owner;
INSERT INTO public.products (name, price) VALUES ('Widget', 9.99), ('Gadget', 19.5);
INSERT INTO public.users (full_name, email, phone, date_of_birth, national_id, password_hash, "mfaSecret", tokens_used)
  VALUES ('Ada Lovelace', 'ada@example.com', '+15551234567', '1990-07-14', 'AB123456C', '$2b$hash', 'JBSWY3DP', 42);
INSERT INTO public.salaries (user_id, amount) VALUES (1, 100000);
INSERT INTO sales.orders (user_id, total) VALUES (1, 29.49);
`;

function config(overrides: Partial<RouaConfig["account"]> = {}, scope: RouaConfig["scope"] = {}): RouaConfig {
  const cfg = {
    roua_version: "0.1",
    account: {
      name: "roua_agent_test",
      profile: "agent",
      level: "L2",
      owner: "owner@example.com",
      approved_by: "cto@example.com",
      purpose: "Integration test",
      expires_at: IN_30_DAYS,
      ...overrides,
    },
    target: { engine: "postgresql", database: "postgres", schemas: ["public", "sales"], object_owner: "app_owner" },
    scope: {
      exclude: ["public.salaries", "public.api_keys"],
      columns_deny: ["public.users.national_id"],
      ...scope,
    },
  };
  const v = validateConfig(cfg, { now: NOW });
  if (!v.ok) throw new Error(v.errors.join("\n"));
  return v.config!;
}

async function apply(cfg: RouaConfig) {
  const verifier = await scramSha256Verifier("TestPassword123TestPassword123ab");
  const plan = planPostgres(cfg, { now: NOW, secret: { kind: "scram", verifier } });
  await db.exec(plan.setupSql);
  return plan;
}

async function asRole<T>(role: string, fn: () => Promise<T>): Promise<T> {
  await db.exec(`SET ROLE "${role}"`);
  try {
    return await fn();
  } finally {
    await db.exec("RESET ROLE");
  }
}

async function errorCode(sql: string): Promise<string | null> {
  try {
    await db.query(sql);
    return null;
  } catch (e) {
    return (e as { code?: string }).code ?? "unknown";
  }
}

const failing = (r: { results: { id: string; severity: string; details: string[] }[] }) =>
  r.results.filter((x) => x.severity === "fail" || x.severity === "error").map((x) => `${x.id}: ${x.details.join(" | ")}`);

beforeAll(async () => {
  db = await PGlite.create();
  await db.exec(FIXTURE);
});

describe("L2 operational account", () => {
  it("applies, and is idempotent (I1, I13)", async () => {
    const cfg = config();
    await apply(cfg);
    await apply(cfg); // re-run must not error or drift
    const role = await exec("SELECT rolcanlogin, rolconnlimit, rolvaliduntil IS NOT NULL AS has_expiry FROM pg_roles WHERE rolname = 'roua_agent_test'");
    expect(role[0]).toMatchObject({ rolcanlogin: true, rolconnlimit: 5, has_expiry: true });
  });

  it("stores the SCRAM verifier, never the plaintext", async () => {
    const rows = await exec("SELECT rolpassword FROM pg_authid WHERE rolname = 'roua_agent_test'");
    expect(String(rows[0]!.rolpassword)).toMatch(/^SCRAM-SHA-256\$4096:/);
  });

  it("can read allowed tables (I2) but not excluded ones (I3)", async () => {
    await asRole("roua_agent_test", async () => {
      expect((await exec("SELECT count(*)::int AS n FROM public.products"))[0]!.n).toBe(2);
      expect((await exec("SELECT total FROM sales.orders"))).toHaveLength(1);
      expect(await errorCode("SELECT * FROM public.salaries")).toBe("42501");
      expect(await errorCode("SELECT * FROM public.api_keys")).toBe("42501");
    });
  });

  it("cannot read secret or denied columns (I4), but can read the rest of the table", async () => {
    await asRole("roua_agent_test", async () => {
      expect(await errorCode("SELECT password_hash FROM public.users")).toBe("42501");
      expect(await errorCode(`SELECT "mfaSecret" FROM public.users`)).toBe("42501");
      expect(await errorCode("SELECT national_id FROM public.users")).toBe("42501");
      expect(await errorCode("SELECT tokens_used FROM public.users")).toBe("42501"); // false positive: fails safe
      const rows = await exec("SELECT full_name, email FROM public.users");
      expect(rows[0]).toMatchObject({ full_name: "Ada Lovelace", email: "ada@example.com" });
    });
  });

  it("cannot write or run DDL, even after turning read-only off (I5, I6, I7)", async () => {
    await asRole("roua_agent_test", async () => {
      for (const sql of [
        "INSERT INTO public.products (name) VALUES ('x')",
        "UPDATE public.products SET price = 0",
        "DELETE FROM public.products",
        "TRUNCATE public.products",
        "CREATE TABLE public.evil (x int)",
        "CREATE TABLE sales.evil (x int)",
        "DROP TABLE public.products",
        "ALTER TABLE public.products ADD COLUMN x int",
        "CREATE VIEW public.v AS SELECT 1",
        "CREATE FUNCTION public.f() RETURNS int LANGUAGE sql AS 'select 1'",
        "SELECT setval('public.products_id_seq', 1000)",
      ]) {
        await db.exec("BEGIN; SET LOCAL transaction_read_only = off;");
        const code = await errorCode(sql);
        await db.exec("ROLLBACK");
        expect(code, sql).toBe("42501");
      }
    });
    expect((await exec("SELECT count(*)::int AS n FROM public.products"))[0]!.n).toBe(2);
  });

  it("passes the admin-side audit", async () => {
    const report = await auditRole(exec, "roua_agent_test");
    expect(failing(report)).toEqual([]);
    expect(report.ok).toBe(true);
  });

  it("passes verify as the account, including live probes and scope checks", async () => {
    const report = await asRole("roua_agent_test", () => verifyCurrentUser(exec, { config: config() }));
    expect(failing(report)).toEqual([]);
    const ids = report.results.map((r) => r.id);
    expect(ids).toEqual(expect.arrayContaining(["P1", "P2", "P3", "V5"]));
    expect(report.results.find((r) => r.id === "P2")!.severity).toBe("pass");
  });

  it("flags a secret column added after setup (future tables are not auto-granted)", async () => {
    await db.exec("CREATE TABLE public.integrations (id int, webhook_signing_key text); ALTER TABLE public.integrations OWNER TO app_owner;");
    // Not readable: no default privileges are granted.
    await asRole("roua_agent_test", async () => {
      expect(await errorCode("SELECT * FROM public.integrations")).toBe("42501");
    });
    // A careless manual grant is caught by the audit.
    await db.exec("GRANT SELECT ON public.integrations TO roua_l2_ops");
    const report = await auditRole(exec, "roua_agent_test");
    const x1 = report.results.find((r) => r.id === "X1")!;
    expect(x1.severity).toBe("fail");
    expect(x1.details.join(" ")).toContain("public.integrations.webhook_signing_key");
    // Re-applying removes the drift.
    await apply(config());
    expect((await auditRole(exec, "roua_agent_test")).ok).toBe(true);
  });

  it("keeps a column added to a readable table hidden (per-column grants by default)", async () => {
    await db.exec("ALTER TABLE public.products ADD COLUMN supplier_notes text");
    await asRole("roua_agent_test", async () => {
      expect(await errorCode("SELECT name, price FROM public.products")).toBeNull();
      expect(await errorCode("SELECT supplier_notes FROM public.products")).toBe("42501");
    });
    // With column_grants: when_needed, a fully visible table gets a whole-table grant instead.
    await apply(config({}, { exclude: ["public.salaries", "public.api_keys"], columns_deny: ["public.users.national_id"], column_grants: "when_needed" }));
    await asRole("roua_agent_test", async () => {
      expect(await errorCode("SELECT supplier_notes FROM public.products")).toBeNull();
    });
    await db.exec("ALTER TABLE public.products DROP COLUMN supplier_notes");
    await apply(config());
  });
});

describe("schema mismatches are caught, not ignored", () => {
  it("refuses a scope that matches nothing, and changes nothing", async () => {
    const cfg = config({ name: "roua_empty_test" }, { include: ["public.does_not_exist"] });
    await expect(apply(cfg)).rejects.toThrow(/matched no readable tables/);
    // psql would disconnect here; PGlite keeps the session, so end the aborted transaction.
    await db.exec("ROLLBACK");
    expect((await db.query("SELECT 1 FROM pg_roles WHERE rolname = 'roua_empty_test'")).rows).toHaveLength(0);
  });

  it("warns about listed names and hidden columns that do not exist", async () => {
    const warnings: string[] = [];
    const verifier = await scramSha256Verifier("TestPassword123TestPassword123ab");
    const cfg = config({ name: "roua_typo_test", level: "L1", profile: "demo" }, {
      public_objects: ["public.products", "public.prodcts"],
      columns_deny: ["public.products.prise"],
    });
    const plan = planPostgres(validateConfig(cfg, { now: NOW }).config!, { now: NOW, secret: { kind: "scram", verifier } });
    await db.exec(plan.setupSql, { onNotice: (n) => warnings.push(n.message ?? "") });
    expect(warnings.join("\n")).toMatch(/public\.prodcts matches no table or view/);
    expect(warnings.join("\n")).toMatch(/hidden column public\.products\.prise does not exist/);
  });
});

describe("auditing an existing, careless 'readonly' user", () => {
  it("finds the problems", async () => {
    await db.exec(`
      CREATE ROLE app_writer NOLOGIN;
      GRANT INSERT, UPDATE ON public.products TO app_writer;
      CREATE ROLE readonly LOGIN PASSWORD 'readonly' NOINHERIT;
      GRANT app_writer TO readonly;
      GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly;
      GRANT UPDATE (price) ON public.products TO readonly;
      GRANT USAGE ON SEQUENCE public.products_id_seq TO readonly;
      CREATE FUNCTION public.bump_price() RETURNS void LANGUAGE sql SECURITY DEFINER AS 'UPDATE public.products SET price = price + 1';
      ALTER ROLE readonly SET default_transaction_read_only = on;
    `);
    const report = await auditRole(exec, "readonly");
    const sev = Object.fromEntries(report.results.map((r) => [r.id, r.severity]));
    expect(report.ok).toBe(false);
    expect(sev.R2).toBe("fail"); // no expiry
    expect(sev.R3).toBe("warn"); // unlimited connections
    expect(sev.T1).toBe("fail"); // INSERT/UPDATE via app_writer (NOINHERIT, so only via SET ROLE)
    expect(sev.T2).toBe("fail"); // column UPDATE
    expect(sev.X1).toBe("fail"); // password_hash, api_keys.secret...
    expect(sev.F1).toBe("warn"); // SECURITY DEFINER function
    expect(sev.Q1).toBe("warn"); // nextval
    expect(sev.M1).toBe("warn"); // no metadata
    const t1 = report.results.find((r) => r.id === "T1")!;
    expect(t1.details.join(" ")).toContain("via app_writer");
  });
});

describe("L4 masked account", () => {
  it("reads masked views only, and values are masked (I8)", async () => {
    const cfg = config(
      { name: "roua_audit_test", profile: "audit", level: "L4" },
      {
        exclude: ["public.salaries", "public.api_keys", "public.integrations"],
        columns_deny: [],
        mask: {
          "public.users.email": "email",
          "public.users.phone": "partial_last4",
          "public.users.national_id": "redact",
          "public.users.date_of_birth": "year_only",
          "public.users.full_name": "initials",
          "public.users.id": "hash",
        },
      },
    );
    await apply(cfg);
    await apply(cfg);
    await asRole("roua_audit_test", async () => {
      expect(await errorCode("SELECT * FROM public.users")).toBe("42501");
      expect(await errorCode("SELECT * FROM public.products")).toBe("42501");
      const u = (await exec("SELECT * FROM roua_masked_public.users"))[0]!;
      expect(u.email).toBe("a***@example.com");
      expect(u.phone).toBe("***4567");
      expect(u.national_id).toBeNull();
      expect(String(u.full_name)).toBe("A. L.");
      expect(String(u.id)).toMatch(/^[0-9a-f]{64}$/);
      expect(u).not.toHaveProperty("password_hash");
      expect(u).not.toHaveProperty("mfaSecret");
      expect(await errorCode("SELECT * FROM roua_private.mask_key")).toBe("42501");
      expect(await errorCode("SELECT * FROM roua_masked_public.salaries")).toBe("42P01");
      const report = await verifyCurrentUser(exec, { config: cfg });
      expect(failing(report)).toEqual([]);
      expect(report.results.find((r) => r.id === "V7")!.severity).toBe("pass");
    });
    const views = await exec("SELECT reloptions FROM pg_class WHERE oid = 'roua_masked_public.users'::regclass");
    expect(String(views[0]!.reloptions)).toContain("security_barrier=true");
  });
});

describe("L0 metadata account", () => {
  it("sees structure but no rows (I9)", async () => {
    const cfg = config({ name: "roua_agent_meta", level: "L0", level_role: "roua_l0_meta" });
    await apply(cfg);
    await asRole("roua_agent_meta", async () => {
      expect(await errorCode("SELECT * FROM public.products")).toBe("42501");
      const cols = await exec("SELECT attname FROM pg_attribute WHERE attrelid = 'public.users'::regclass AND attnum > 0");
      expect(cols.length).toBeGreaterThan(5);
      const report = await verifyCurrentUser(exec, { config: cfg });
      expect(failing(report)).toEqual([]);
    });
  });
});

describe("revoke", () => {
  it("disables login", async () => {
    const plan = planPostgres(config(), { now: NOW, secret: { kind: "placeholder" } });
    await db.exec(plan.revokeSql);
    const rows = await exec("SELECT rolcanlogin FROM pg_roles WHERE rolname = 'roua_agent_test'");
    expect(rows[0]!.rolcanlogin).toBe(false);
  });

  it("drops cleanly", async () => {
    const plan = planPostgres(config({ name: "roua_agent_meta", level: "L0", level_role: "roua_l0_meta" }), { now: NOW, secret: { kind: "placeholder" } });
    await db.exec(plan.revokeSql);
    await db.exec(plan.dropSql);
    expect(await exec("SELECT 1 FROM pg_roles WHERE rolname = 'roua_agent_meta'")).toHaveLength(0);
  });
});
