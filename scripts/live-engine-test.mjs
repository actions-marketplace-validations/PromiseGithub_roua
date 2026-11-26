#!/usr/bin/env node
/**
 * End-to-end test of the generated scripts against a real engine running in a
 * Docker container (a GitHub Actions service container in CI).
 *
 *   node scripts/live-engine-test.mjs <engine> <container-id>
 *
 * For each engine it: seeds sample data as admin; runs setup twice (it must be
 * idempotent); logs in AS the new account and proves that permitted reads work
 * while writes, DDL, secret columns, excluded tables and tables created later
 * are all refused; runs the generated audit and requires zero FAIL lines;
 * proves the expiry mechanism fires (where the engine has one); and proves
 * revoke cuts access. The scripts are run with each engine's official client
 * inside the container, exactly as a user would run them.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generatePassword, planEngine } from "../packages/core/dist/index.js";

const [engine, cid] = process.argv.slice(2);
if (!engine || !cid) {
  console.error("usage: live-engine-test.mjs <engine> <container-id>");
  process.exit(2);
}
const PW = generatePassword(24);
const NAME = "roua_ci_test";
const dir = mkdtempSync(join(tmpdir(), "roua-live-"));
let failures = 0;

const sleep = (s) => new Promise((r) => setTimeout(r, s * 1000));
function docker(args, input) {
  try {
    const out = execFileSync("docker", args, { input, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], maxBuffer: 64 << 20 });
    return { ok: true, out };
  } catch (e) {
    return { ok: false, out: `${e.stdout ?? ""}${e.stderr ?? ""}` };
  }
}
function copyIn(name, content) {
  const p = join(dir, name);
  writeFileSync(p, content);
  const r = docker(["cp", p, `${cid}:/tmp/${name}`]);
  if (!r.ok) throw new Error(`docker cp failed: ${r.out}`);
  return `/tmp/${name}`;
}
const ERR = /ERROR|ORA-\d|Msg \d+|denied|NOPERM|NOAUTH|WRONGPASS|not authorized|Unauthorized|SP2-|failed|No permissions|permission/i;
function check(title, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${title}${ok ? "" : `\n      ${detail.trim().split("\n").slice(0, 12).join("\n      ")}`}`);
  if (!ok) failures++;
}
function expectAllowed(title, r) {
  check(`allowed: ${title}`, r.ok && !ERR.test(r.out), r.out);
}
function expectDenied(title, r) {
  check(`denied:  ${title}`, !r.ok || ERR.test(r.out), r.out);
}

function spec(over = {}) {
  const base = {
    engine,
    name: NAME,
    profile: "agent",
    owner: "ci@example.com",
    purpose: "ROUA live CI test",
    expiresAt: new Date(Date.now() + 30 * 86_400_000).toISOString(),
    mode: "scope",
    database: "appdb",
    schemas: ["app"],
    objects: [],
    exclude: ["app.salaries"],
    columnsDeny: ["app.customers.national_id"],
    password: PW,
    maxConnections: 5,
    statementTimeoutS: 30,
    requireTls: false,
  };
  if (engine === "mongodb") Object.assign(base, { schemas: undefined, exclude: ["salaries"], columnsDeny: [] });
  if (engine === "redis") Object.assign(base, { objects: ["app:*"], exclude: [], columnsDeny: [], schemas: undefined, redis7: true });
  if (engine === "oracle") Object.assign(base, { columnsDeny: ["APP.CUSTOMERS.NATIONAL_ID"] });
  return { ...base, ...over };
}
const file = (plan, prefix) => plan.files.find((f) => f.name.startsWith(prefix)).content;

// ------------------------------------------------------------------ engines
const E = {
  async mysql(maria = false) {
    const cli = maria ? "mariadb" : "mysql";
    const admin = (sql) => docker(["exec", "-i", cid, cli, "-uroot", "-proot", "--table"], sql);
    const asUser = (sql, pw = PW) => docker(["exec", cid, cli, "-h127.0.0.1", `-u${NAME}`, `-p${pw}`, "-e", sql]);
    const seed = `CREATE DATABASE IF NOT EXISTS app;
      CREATE TABLE app.customers (id INT PRIMARY KEY, name VARCHAR(50), national_id VARCHAR(20));
      CREATE TABLE app.users (id INT PRIMARY KEY, email VARCHAR(80), password_hash VARCHAR(100), apiToken VARCHAR(100));
      CREATE TABLE app.salaries (id INT PRIMARY KEY, amount INT);
      INSERT INTO app.customers VALUES (1, 'Ada', 'X1');
      INSERT INTO app.users VALUES (1, 'ada@example.com', 'h', 't');
      INSERT INTO app.salaries VALUES (1, 100);`;
    check("seed data", admin(seed).ok);
    if (maria) admin("SET GLOBAL event_scheduler = ON;");
    const plan = planEngine(spec(), new Date());
    for (const i of [1, 2]) {
      const r = admin(file(plan, "setup"));
      check(`setup run ${i}`, r.ok, r.out);
    }
    admin("CREATE TABLE app.created_later (id INT); INSERT INTO app.created_later VALUES (1);");
    expectAllowed("SELECT name FROM app.customers", asUser("SELECT name FROM app.customers"));
    expectAllowed("SELECT email FROM app.users", asUser("SELECT id, email FROM app.users"));
    expectDenied("SELECT password_hash (secret)", asUser("SELECT password_hash FROM app.users"));
    expectDenied("SELECT apiToken (camelCase secret)", asUser("SELECT apiToken FROM app.users"));
    expectDenied("SELECT national_id (deny-listed)", asUser("SELECT national_id FROM app.customers"));
    expectDenied("SELECT * FROM app.salaries (excluded)", asUser("SELECT * FROM app.salaries"));
    expectDenied("table created after setup", asUser("SELECT * FROM app.created_later"));
    expectDenied("INSERT", asUser("INSERT INTO app.customers VALUES (2, 'Eve', 'Y')"));
    expectDenied("UPDATE", asUser("UPDATE app.customers SET name = 'x'"));
    expectDenied("DELETE", asUser("DELETE FROM app.customers"));
    expectDenied("CREATE TABLE", asUser("CREATE TABLE app.evil (id INT)"));
    // MySQL 8 needs UPDATE, DELETE or LOCK TABLES for locking reads; MariaDB does not (documented residual risk).
    if (!maria) expectDenied("SELECT ... FOR UPDATE (row locks)", asUser("START TRANSACTION; SELECT name FROM app.customers FOR UPDATE"));
    expectDenied("LOCK TABLES", asUser("LOCK TABLES app.customers READ"));
    expectDenied("SELECT INTO OUTFILE", asUser("SELECT name INTO OUTFILE '/tmp/x' FROM app.customers"));
    // Per-column grants: a column added after setup stays hidden.
    admin("ALTER TABLE app.customers ADD COLUMN later_notes VARCHAR(20);");
    expectDenied("column added after setup", asUser("SELECT later_notes FROM app.customers"));
    expectAllowed("existing columns still readable", asUser("SELECT name FROM app.customers"));
    const audit = admin(file(plan, "audit"));
    check("audit has no FAIL", audit.ok && !/\|\s*FAIL\s*\|/.test(audit.out), audit.out);
    console.log(audit.out);
    // Expiry: rerun setup expiring in 70 s, wait, and the account must be locked.
    const soon = planEngine(spec({ expiresAt: new Date(Date.now() + 70_000).toISOString() }), new Date());
    check("setup with near expiry", admin(file(soon, "setup")).ok);
    expectAllowed("login before expiry", asUser("SELECT 1"));
    await sleep(95);
    expectDenied("login after expiry (event fired)", asUser("SELECT 1"));
    // Revoke.
    check("setup again (unlock)", admin(file(plan, "setup")).ok);
    expectAllowed("login after re-setup", asUser("SELECT 1"));
    check("revoke", admin(file(plan, "revoke")).ok);
    expectDenied("login after revoke", asUser("SELECT 1"));
    const empty = planEngine(spec({ name: "roua_ci_empty", schemas: ["no_such_db"], columnsDeny: [] }), new Date());
    const e = admin(file(empty, "setup"));
    check("empty scope is refused", !e.ok && /matched no readable tables/.test(e.out), e.out);
    const typo = planEngine(spec({ name: "roua_ci_typo", mode: "listed", objects: ["app.customers", "app.custmers"], exclude: [], columnsDeny: ["app.customers.nationl_id"] }), new Date());
    const ty = admin(file(typo, "setup"));
    check("typos are reported", ty.ok && /app.custmers/.test(ty.out) && /nationl_id/.test(ty.out), ty.out);
  },

  async mariadb() {
    return E.mysql(true);
  },

  async sqlserver() {
    const SA = ["-S", "localhost", "-U", "sa", "-P", process.env.MSSQL_SA_PASSWORD ?? "Roua-ci-Passw0rd!", "-C", "-b"];
    const sqlcmd = "/opt/mssql-tools18/bin/sqlcmd";
    const adminFile = (name, content) => docker(["exec", cid, sqlcmd, ...SA, "-i", copyIn(name, content)]);
    const admin = (sql) => docker(["exec", cid, sqlcmd, ...SA, "-Q", sql]);
    const asUser = (sql, pw = PW) => docker(["exec", cid, sqlcmd, "-S", "localhost", "-U", NAME, "-P", pw, "-C", "-b", "-d", "appdb", "-Q", sql]);
    const seed = `CREATE DATABASE appdb;
GO
USE appdb;
GO
CREATE SCHEMA app;
GO
CREATE TABLE app.customers (id INT PRIMARY KEY, name NVARCHAR(50), national_id NVARCHAR(20));
CREATE TABLE app.users (id INT PRIMARY KEY, email NVARCHAR(80), password_hash NVARCHAR(100), apiToken NVARCHAR(100));
CREATE TABLE app.salaries (id INT PRIMARY KEY, amount INT);
INSERT INTO app.customers VALUES (1, N'Ada', N'X1');
INSERT INTO app.users VALUES (1, N'ada@example.com', N'h', N't');
INSERT INTO app.salaries VALUES (1, 100);
GO
CREATE PROCEDURE app.bump AS UPDATE app.customers SET name = N'x';
GO`;
    const s = adminFile("seed.sql", seed);
    check("seed data", s.ok, s.out);
    const plan = planEngine(spec(), new Date());
    for (const i of [1, 2]) {
      const r = adminFile(`setup${i}.sql`, file(plan, "setup"));
      check(`setup run ${i}`, r.ok && !/WARNING/.test(r.out), r.out);
    }
    admin("USE appdb; CREATE TABLE app.created_later (id INT); INSERT INTO app.created_later VALUES (1);");
    expectAllowed("SELECT name FROM app.customers", asUser("SELECT name FROM app.customers"));
    expectAllowed("SELECT email FROM app.users", asUser("SELECT id, email FROM app.users"));
    expectDenied("SELECT password_hash (secret)", asUser("SELECT password_hash FROM app.users"));
    expectDenied("SELECT apiToken (camelCase secret)", asUser("SELECT apiToken FROM app.users"));
    expectDenied("SELECT * FROM app.users", asUser("SELECT * FROM app.users"));
    expectDenied("SELECT national_id (deny-listed)", asUser("SELECT national_id FROM app.customers"));
    expectDenied("SELECT * FROM app.salaries (excluded)", asUser("SELECT * FROM app.salaries"));
    expectDenied("table created after setup", asUser("SELECT * FROM app.created_later"));
    expectDenied("INSERT", asUser("INSERT INTO app.customers VALUES (2, N'Eve', N'Y')"));
    expectDenied("UPDATE", asUser("UPDATE app.customers SET name = N'x'"));
    expectDenied("DELETE", asUser("DELETE FROM app.customers"));
    expectDenied("EXEC procedure", asUser("EXEC app.bump"));
    expectDenied("CREATE TABLE", asUser("CREATE TABLE app.evil (id INT)"));
    expectDenied("SELECT INTO new table", asUser("SELECT * INTO app.evil2 FROM app.customers"));
    // Per-column grants: a column added after setup stays hidden.
    admin("USE appdb; ALTER TABLE app.customers ADD later_notes NVARCHAR(20);");
    expectDenied("column added after setup", asUser("SELECT later_notes FROM app.customers"));
    expectAllowed("existing columns still readable", asUser("SELECT name FROM app.customers"));
    // Even a role added later by mistake cannot grant writes: DENY wins.
    admin(`USE appdb; ALTER ROLE db_datawriter ADD MEMBER ${NAME};`);
    expectDenied("INSERT even as db_datawriter (DENY wins)", asUser("INSERT INTO app.customers VALUES (3, N'Eve', N'Y')"));
    admin(`USE appdb; ALTER ROLE db_datawriter DROP MEMBER ${NAME};`);
    const audit = adminFile("audit.sql", file(plan, "audit"));
    check("audit has no FAIL", audit.ok && !/\bFAIL\b/.test(audit.out), audit.out);
    console.log(audit.out);
    // Expiry through SQL Server Agent.
    const soon = planEngine(spec({ expiresAt: new Date(Date.now() + 90_000).toISOString() }), new Date());
    const r = adminFile("setup-soon.sql", file(soon, "setup"));
    check("setup with near expiry", r.ok && /expiry job created/.test(r.out), r.out);
    expectAllowed("login before expiry", asUser("SELECT 1"));
    await sleep(170);
    expectDenied("login after expiry (Agent job fired)", asUser("SELECT 1"));
    check("setup again (re-enable)", adminFile("setup3.sql", file(plan, "setup")).ok);
    expectAllowed("login after re-setup", asUser("SELECT 1"));
    check("revoke", adminFile("revoke.sql", file(plan, "revoke")).ok);
    expectDenied("login after revoke", asUser("SELECT 1"));
    const empty = planEngine(spec({ name: "roua_ci_empty", schemas: ["no_such_schema"], columnsDeny: [] }), new Date());
    const e = adminFile("setup-empty.sql", file(empty, "setup"));
    check("empty scope is refused", !e.ok && /matched no readable tables/.test(e.out), e.out);
    const typo = planEngine(spec({ name: "roua_ci_typo", mode: "listed", objects: ["app.customers", "app.custmers"], exclude: [], columnsDeny: ["app.customers.nationl_id"] }), new Date());
    const ty = adminFile("setup-typo.sql", file(typo, "setup"));
    check("typos are reported", ty.ok && /app.custmers matches nothing/.test(ty.out) && /nationl_id does not exist/.test(ty.out), ty.out);
    // Structure only (L0): the catalog is visible, rows are not.
    const META = "roua_ci_meta";
    const asMeta = (sql) => docker(["exec", cid, sqlcmd, "-S", "localhost", "-U", META, "-P", PW, "-C", "-b", "-d", "appdb", "-h", "-1", "-Q", sql]);
    const meta = planEngine(spec({ name: META, mode: "metadata", exclude: [], columnsDeny: [] }), new Date());
    const m = adminFile("setup-meta.sql", file(meta, "setup"));
    check("L0 setup", m.ok, m.out);
    const cols = asMeta("SET NOCOUNT ON; SELECT CASE WHEN COUNT(*) >= 3 THEN 'META_OK' ELSE 'META_MISSING' END FROM sys.columns WHERE object_id = OBJECT_ID('app.customers')");
    check("L0: column metadata of app.customers is visible", cols.ok && cols.out.includes("META_OK"), cols.out);
    expectDenied("L0: SELECT name FROM app.customers", asMeta("SELECT name FROM app.customers"));
    expectDenied("L0: INSERT", asMeta("INSERT INTO app.customers VALUES (9, N'x', N'y')"));
    const ma = adminFile("audit-meta.sql", file(meta, "audit"));
    check("L0 audit has no FAIL", ma.ok && !/\bFAIL\b/.test(ma.out), ma.out);
  },

  async oracle() {
    const SYS = `system/${process.env.ORACLE_PASSWORD ?? "RouaCi123"}@//localhost/FREEPDB1`;
    const adminFile = (name, content) => docker(["exec", "-i", cid, "sqlplus", "-s", "-L", SYS, `@${copyIn(name, content)}`], "exit\n");
    const asUser = (sql, pw = PW) => docker(["exec", "-i", cid, "sqlplus", "-s", "-L", `${NAME}/${pw}@//localhost/FREEPDB1`], `WHENEVER SQLERROR EXIT 1\n${sql}\nexit\n`);
    const seed = `WHENEVER SQLERROR EXIT 1
CREATE USER app IDENTIFIED BY "AppPw12345" QUOTA UNLIMITED ON users;
CREATE TABLE app.customers (id NUMBER PRIMARY KEY, name VARCHAR2(50), national_id VARCHAR2(20));
CREATE TABLE app.orders (id NUMBER PRIMARY KEY, amount NUMBER);
CREATE TABLE app.users (id NUMBER PRIMARY KEY, email VARCHAR2(80), password_hash VARCHAR2(100));
CREATE TABLE app.salaries (id NUMBER PRIMARY KEY, amount NUMBER);
INSERT INTO app.customers VALUES (1, 'Ada', 'X1');
INSERT INTO app.orders VALUES (1, 10);
INSERT INTO app.users VALUES (1, 'ada@example.com', 'h');
INSERT INTO app.salaries VALUES (1, 100);
COMMIT;
`;
    const s = adminFile("seed.sql", seed);
    check("seed data", s.ok, s.out);
    const plan = planEngine(spec({ columnsDeny: [] }), new Date());
    for (const i of [1, 2]) {
      const r = adminFile(`setup${i}.sql`, file(plan, "setup"));
      check(`setup run ${i}`, r.ok && !/ORA-/.test(r.out), r.out);
      if (i === 1) console.log(r.out);
    }
    adminFile("later.sql", "CREATE TABLE app.created_later (id NUMBER);\n");
    expectAllowed("SELECT name FROM app.customers", asUser("SELECT name FROM app.customers;"));
    expectAllowed("SELECT FROM app.orders", asUser("SELECT amount FROM app.orders;"));
    expectDenied("app.users (has a secret column: skipped)", asUser("SELECT email FROM app.users;"));
    expectDenied("app.salaries (excluded)", asUser("SELECT * FROM app.salaries;"));
    expectDenied("table created after setup", asUser("SELECT * FROM app.created_later;"));
    expectDenied("INSERT", asUser("INSERT INTO app.orders VALUES (2, 5);"));
    expectDenied("UPDATE", asUser("UPDATE app.orders SET amount = 0;"));
    expectDenied("DELETE", asUser("DELETE FROM app.orders;"));
    expectDenied("CREATE TABLE", asUser("CREATE TABLE evil (id NUMBER);"));
    expectDenied("SELECT ... FOR UPDATE (READ, not SELECT)", asUser("SELECT amount FROM app.orders FOR UPDATE;"));
    expectDenied("LOCK TABLE", asUser("LOCK TABLE app.orders IN EXCLUSIVE MODE;"));
    const audit = adminFile("audit.sql", file(plan, "audit"));
    check("audit has no FAIL", audit.ok && !/^FAIL/m.test(audit.out) && /READ-ONLY: every check passed/.test(audit.out), audit.out);
    console.log(audit.out);
    const soon = planEngine(spec({ columnsDeny: [], expiresAt: new Date(Date.now() + 70_000).toISOString() }), new Date());
    check("setup with near expiry", adminFile("setup-soon.sql", file(soon, "setup")).ok);
    expectAllowed("login before expiry", asUser("SELECT 1 FROM dual;"));
    await sleep(110);
    expectDenied("login after expiry (scheduler job fired)", asUser("SELECT 1 FROM dual;"));
    check("setup again (unlock)", adminFile("setup3.sql", file(plan, "setup")).ok);
    expectAllowed("login after re-setup", asUser("SELECT 1 FROM dual;"));
    check("revoke", adminFile("revoke.sql", file(plan, "revoke")).ok);
    expectDenied("login after revoke", asUser("SELECT 1 FROM dual;"));
    const empty = planEngine(spec({ name: "roua_ci_empty", schemas: ["NO_SUCH_SCHEMA"], columnsDeny: [] }), new Date());
    const e = adminFile("setup-empty.sql", file(empty, "setup"));
    check("empty scope is refused", !e.ok && /ORA-20001/.test(e.out) && /matched no readable tables/.test(e.out), e.out);
    const typo = planEngine(spec({ name: "roua_ci_typo", mode: "listed", objects: ["APP.ORDERS", "APP.ORDRS"], exclude: [], columnsDeny: ["APP.ORDERS.AMOUNTT"] }), new Date());
    const ty = adminFile("setup-typo.sql", file(typo, "setup"));
    check("typos are reported", ty.ok && /APP.ORDRS matches nothing/.test(ty.out) && /APP.ORDERS.AMOUNTT does not exist/.test(ty.out), ty.out);
  },

  async mongodb() {
    const ADMIN = ["mongosh", "--quiet", "-u", "root", "-p", "root", "--authenticationDatabase", "admin"];
    const adminFile = (name, content) => docker(["exec", cid, ...ADMIN, "--file", copyIn(name, content)]);
    const adminEval = (js) => docker(["exec", cid, ...ADMIN, "--eval", js]);
    const asUser = (js, pw = PW) => docker(["exec", cid, "mongosh", "--quiet", `mongodb://${NAME}:${pw}@localhost/appdb?authSource=admin`, "--eval", js]);
    check("seed data", adminEval(`const d = db.getSiblingDB("appdb");
      d.customers.insertOne({ _id: 1, name: "Ada" }); d.orders.insertOne({ _id: 1, amount: 10 }); d.salaries.insertOne({ _id: 1, amount: 100 });`).ok);
    const plan = planEngine(spec(), new Date());
    for (const i of [1, 2]) {
      const r = adminFile(`setup${i}.js`, file(plan, "setup"));
      check(`setup run ${i}`, r.ok && !/Error/.test(r.out), r.out);
    }
    adminEval(`db.getSiblingDB("appdb").created_later.insertOne({ _id: 1 })`);
    expectAllowed("find customers", asUser(`printjson(db.customers.find().toArray())`));
    expectAllowed("aggregate orders", asUser(`printjson(db.orders.aggregate([{ $group: { _id: null, t: { $sum: "$amount" } } }]).toArray())`));
    expectDenied("find salaries (excluded)", asUser(`db.salaries.find().toArray()`));
    expectDenied("collection created after setup", asUser(`db.created_later.find().toArray()`));
    expectDenied("insertOne", asUser(`db.customers.insertOne({ _id: 2 })`));
    expectDenied("updateOne", asUser(`db.customers.updateOne({ _id: 1 }, { $set: { name: "x" } })`));
    expectDenied("deleteMany", asUser(`db.customers.deleteMany({})`));
    expectDenied("$out", asUser(`db.customers.aggregate([{ $out: "stolen" }]).toArray()`));
    expectDenied("$merge", asUser(`db.customers.aggregate([{ $merge: { into: "orders" } }]).toArray()`));
    expectDenied("createIndex", asUser(`db.customers.createIndex({ name: 1 })`));
    expectDenied("drop", asUser(`db.customers.drop()`));
    expectDenied("other database", asUser(`db.getSiblingDB("admin").system.users.find().toArray()`));
    const audit = adminFile("audit.js", file(plan, "audit"));
    check("audit has no FAIL", audit.ok && !/^FAIL/m.test(audit.out), audit.out);
    console.log(audit.out);
    check("revoke", adminFile("revoke.js", file(plan, "revoke")).ok);
    expectDenied("login after revoke", asUser(`db.customers.findOne()`));
    // Schema mismatches: an empty scope is refused before anything is created; typos are reported.
    const empty = planEngine(spec({ name: "roua_ci_empty", database: "no_such_db" }), new Date());
    const e = adminFile("setup-empty.js", file(empty, "setup"));
    check("empty scope is refused", !e.ok && /matched no collections/.test(e.out), e.out);
    const typo = planEngine(spec({ name: "roua_ci_typo", mode: "listed", objects: ["customers", "custmers"], exclude: [] }), new Date());
    const ty = adminFile("setup-typo.js", file(typo, "setup"));
    check("listed typo is reported", ty.ok && /custmers.*matches nothing/.test(ty.out), ty.out);
    // Structure only (L0): collection names and indexes, no documents.
    const META = "roua_ci_meta";
    const asMeta = (js) => docker(["exec", cid, "mongosh", "--quiet", `mongodb://${META}:${PW}@localhost/appdb?authSource=admin`, "--eval", js]);
    const meta = planEngine(spec({ name: META, mode: "metadata" }), new Date());
    const ms = adminFile("setup-meta.js", file(meta, "setup"));
    check("L0 setup", ms.ok && !/Error/.test(ms.out), ms.out);
    const names = asMeta(`print(db.getCollectionNames().join(","))`);
    check("L0: collection names are visible", names.ok && names.out.includes("customers"), names.out);
    expectAllowed("L0: listIndexes", asMeta(`printjson(db.customers.getIndexes())`));
    expectDenied("L0: find", asMeta(`db.customers.find().toArray()`));
    expectDenied("L0: insertOne", asMeta(`db.customers.insertOne({ _id: 9 })`));
  },

  async redis() {
    const ADMIN_PW = "roua-admin-pw";
    docker(["exec", cid, "redis-cli", "ACL", "SETUSER", "default", "on", `>${ADMIN_PW}`]);
    const env = ["-e", `REDISCLI_AUTH=${ADMIN_PW}`];
    const admin = (text) => docker(["exec", "-i", ...env, cid, "redis-cli", "--no-auth-warning"], text);
    const asUser = (...cmd) => docker(["exec", cid, "redis-cli", "--no-auth-warning", "--user", NAME, "--pass", PW, ...cmd]);
    check("seed data", admin("SET app:greeting hello\nHSET app:user:1 name Ada\nSET secret:key s3cret\n").ok);
    const plan = planEngine(spec(), new Date());
    for (const i of [1, 2]) {
      const r = admin(file(plan, "setup"));
      const errs = r.out.split("\n").filter((l) => /ERR/.test(l) && !/instance is not configured to use an ACL file/.test(l));
      check(`setup run ${i}`, r.ok && errs.length === 0, errs.join("\n") || r.out);
    }
    expectAllowed("GET app:greeting", asUser("GET", "app:greeting"));
    expectAllowed("HGETALL app:user:1", asUser("HGETALL", "app:user:1"));
    expectDenied("GET secret:key (outside pattern)", asUser("GET", "secret:key"));
    expectDenied("SET", asUser("SET", "app:greeting", "x"));
    expectDenied("DEL", asUser("DEL", "app:greeting"));
    expectDenied("FLUSHALL", asUser("FLUSHALL"));
    expectDenied("KEYS *", asUser("KEYS", "*"));
    expectDenied("CONFIG GET", asUser("CONFIG", "GET", "*"));
    expectDenied("EVAL", asUser("EVAL", "return redis.call('set','app:x','1')", "0"));
    expectDenied("PUBLISH", asUser("PUBLISH", "ch", "x"));
    expectDenied("MONITOR", asUser("MONITOR"));
    copyIn("audit.sh", file(plan, "audit"));
    const audit = docker(["exec", ...env, "-e", "REDIS_CLI=redis-cli --no-auth-warning", cid, "sh", "/tmp/audit.sh"]);
    check("audit has no FAIL", audit.ok && !/^FAIL/m.test(audit.out), audit.out);
    console.log(audit.out);
    check("revoke", admin(file(plan, "revoke")).ok);
    expectDenied("login after revoke", asUser("GET", "app:greeting"));
  },
};

if (!E[engine]) {
  console.error(`No live test for ${engine}`);
  process.exit(2);
}
console.log(`ROUA live test: ${engine} (container ${cid.slice(0, 12)})`);
await E[engine]();
console.log(failures ? `\n${failures} check(s) failed.` : "\nAll checks passed.");
process.exit(failures ? 1 : 0);
