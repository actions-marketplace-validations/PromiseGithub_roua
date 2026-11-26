/**
 * ROUA for MongoDB 6.0+ (self-managed; Atlas notes included).
 *
 * - A custom role with find/listIndexes/collStats on the chosen collections,
 *   listed by name when setup runs. Not the built-in read or readAnyDatabase
 *   roles: those cover collections created later.
 * - No insert/update/remove, so aggregation stages $out and $merge fail too.
 * - SCRAM-SHA-256 only; optional client IP restriction.
 * - MongoDB cannot hide single fields by privilege and has no scheduler:
 *   use views for fields, and schedule revoke.js for expiry (or Atlas
 *   temporary users).
 */
import { engineMetadata, header } from "./common.js";
import { scheduleTemplates } from "./schedule.js";
import type { AccountSpec, EnginePlan } from "./types.js";

const js = (v: unknown) => JSON.stringify(v);

/** Collection glob (letters, digits, _ . - *) to an anchored JS regex source. */
function collectionRegex(p: string): string {
  return "^" + p.replace(/[.\-]/g, (c) => `[${c}]`).replace(/\*/g, ".*") + "$";
}

export function planMongo(spec: AccountSpec, now: Date): EnginePlan {
  const role = `${spec.name}_read`;
  const meta = engineMetadata(spec, now);
  const restrictions = spec.allowedSources?.length ? [{ clientSource: spec.allowedSources }] : [];
  const include = spec.mode === "listed" ? (spec.objects ?? []).map(collectionRegex) : null;
  const exclude = (spec.exclude ?? []).map(collectionRegex);

  const setup = `${header("setup.js: create or update the ROUA account. Run as a user administrator:", spec, now, "//")}// mongosh "mongodb://admin@HOST/admin" --file setup.js
// MongoDB needs the plaintext password here: delete this file after running it.
// Safe to run again: the role is rebuilt from the collections that exist now.

const ROUA = {
  db: ${js(spec.database)},
  user: ${js(spec.name)},
  role: ${js(role)},
  password: ${js(spec.password ?? "")},
  include: ${js(include)},   // null = every collection; otherwise regexes
  actions: ${js(spec.mode === "metadata" ? ["listIndexes"] : ["find", "listIndexes", "collStats"])},   // structure only (L0) has no find
  exclude: ${js(exclude)},
  metadata: ${js(meta)},
  expiresAt: ${js(new Date(spec.expiresAt).toISOString())},
  authenticationRestrictions: ${js(restrictions)},
};

const target = db.getSiblingDB(ROUA.db);
const admin = db.getSiblingDB("admin");
const matches = (name, patterns) => patterns.some((p) => new RegExp(p).test(name));
const collections = target.getCollectionNames()
  .filter((n) => !n.startsWith("system."))
  .filter((n) => ROUA.include === null || matches(n, ROUA.include))
  .filter((n) => !matches(n, ROUA.exclude))
  .sort();

// find / listIndexes / collStats on each collection (listIndexes only for L0); listCollections on the database.
// No insert, update, remove, createIndex, or anything else.
const privileges = collections.map((c) => ({ resource: { db: ROUA.db, collection: c }, actions: ROUA.actions }));
privileges.push({ resource: { db: ROUA.db, collection: "" }, actions: ["listCollections"] });

if (admin.getRole(ROUA.role)) admin.updateRole(ROUA.role, { privileges, roles: [] });
else admin.createRole({ role: ROUA.role, privileges, roles: [] });

const userDoc = {
  roles: [{ role: ROUA.role, db: "admin" }],
  customData: { roua: ROUA.metadata, expiresAt: ROUA.expiresAt },
  mechanisms: ["SCRAM-SHA-256"],
  authenticationRestrictions: ROUA.authenticationRestrictions,
};
if (admin.getUser(ROUA.user)) admin.updateUser(ROUA.user, { pwd: ROUA.password, ...userDoc });
else admin.createUser({ user: ROUA.user, pwd: ROUA.password, ...userDoc });

print("ROUA: " + ROUA.user + " can read " + collections.length + " collection(s) in " + ROUA.db + ":");
collections.forEach((c) => print("  " + c));
print("Expiry: MongoDB has no scheduler. Run revoke.js at " + ROUA.expiresAt + " (see the notes).");
`;

  const revoke = `${header("revoke.js: remove all access now and end open sessions. Run as a user administrator.", spec, now, "//")}// mongosh "mongodb://admin@HOST/admin" --file revoke.js
const admin = db.getSiblingDB("admin");
const user = ${js(spec.name)};
const u = admin.getUser(user);
if (!u) {
  print("ROUA: no user " + user + " (already removed?)");
} else {
  if (u.roles.length) admin.revokeRolesFromUser(user, u.roles);
  // Replace the password with a random one nobody knows.
  admin.updateUser(user, { pwd: UUID().toString("hex") + UUID().toString("hex") });
  const k = admin.runCommand({ killAllSessions: [{ user, db: "admin" }] });
  print("ROUA: " + user + " revoked: no roles, unknown password" + (k.ok ? ", sessions ended." : ". Could not end sessions: " + k.errmsg));
}
`;
  const drop = `${header("drop.js: remove the account and its role (run revoke.js first).", spec, now, "//")}const admin = db.getSiblingDB("admin");
admin.dropUser(${js(spec.name)});
admin.dropRole(${js(role)});
`;
  const warnings: string[] = [
    "MongoDB needs the plaintext password inside setup.js. Run it, then delete the file.",
    "MongoDB cannot hide single fields by permission. If a collection holds secrets, leave it out, or create a view with $project and list the view instead.",
  ];
  if (!restrictions.length) warnings.push("Set Allowed client IPs to stop the account being used from anywhere.");
  return {
    engine: "mongodb",
    files: [
      { name: "setup.js", run: `mongosh "mongodb://admin@HOST/admin" --file setup.js`, content: setup },
      { name: "audit.js", run: `mongosh "mongodb://admin@HOST/admin" --file audit.js`, content: auditMongo(spec.name, now) },
      { name: "revoke.js", run: `mongosh "mongodb://admin@HOST/admin" --file revoke.js`, content: revoke },
      { name: "drop.js", run: `mongosh "mongodb://admin@HOST/admin" --file drop.js`, content: drop },
      { name: "schedule-revoke.md", run: "pick one scheduler and set it up", content: scheduleTemplates(spec, "revoke.js", 'mongosh "$MONGODB_ADMIN_URL" --file revoke.js') },
    ],
    warnings,
    manualSteps: [
      `Schedule revoke.js for ${new Date(spec.expiresAt).toISOString()} (cron, a CI schedule or a cloud scheduler). MongoDB has no built-in expiry for users.`,
      "MongoDB Atlas manages users in the Atlas UI or CLI instead: create a custom role with the same find/listIndexes/collStats actions and a temporary user, e.g. atlas dbusers create --username NAME --role ROLE --deleteAfter " + new Date(spec.expiresAt).toISOString() + ".",
      "Consider security.javascriptEnabled: false so $where and $function cannot run server-side JavaScript.",
    ],
  };
}

/** Audit any MongoDB user (defined in the admin database by default). */
export function auditMongo(name: string, now: Date = new Date(), authDb = "admin"): string {
  return `// audit.js: is ${name} actually read-only? Read-only; safe to run anytime as a user administrator.
// ROUA 0.1 audit for MongoDB. Generated ${now.toISOString()} by the ROUA generator (kaizam.com).
// mongosh "mongodb://admin@HOST/admin" --file audit.js
// Every line should say PASS. FAIL means the account can change data or never expires.

const USER = ${js(name)};
const AUTH_DB = ${js(authDb)};
const READ_ACTIONS = new Set(["find", "listCollections", "listIndexes", "collStats", "dbStats", "listSearchIndexes", "killCursors", "changeStream", "dbHash", "listDatabases", "planCacheRead"]);
let fails = 0;
const line = (status, id, title, detail) => {
  print(status.padEnd(6) + id.padEnd(4) + title + (detail && status !== "PASS" ? "\\n          " + detail : ""));
  if (status === "FAIL") fails++;
};
const info = db.getSiblingDB(AUTH_DB).getUser(USER, { showPrivileges: true, showAuthenticationRestrictions: true });
if (!info) {
  line("FAIL", "A1", "User exists", "No user " + USER + " in " + AUTH_DB);
} else {
  const privs = info.inheritedPrivileges || [];
  const writes = [];
  const broad = [];
  for (const p of privs) {
    const r = p.resource || {};
    const where = r.cluster ? "cluster" : r.anyResource ? "anyResource" : (r.db === "" ? "*" : r.db) + "." + (r.collection === "" ? "*" : r.collection);
    for (const a of p.actions) if (!READ_ACTIONS.has(a)) writes.push(where + ": " + a);
    if (r.cluster || r.anyResource || r.db === "" || (r.collection === "" && p.actions.includes("find"))) broad.push(where);
  }
  line(writes.length ? "FAIL" : "PASS", "T1", "Only read actions", writes.slice(0, 40).join(", "));
  line(broad.length ? "WARN" : "PASS", "R1", "No database-wide or cluster-wide read (new collections would become readable)", [...new Set(broad)].join(", "));
  const builtIn = (info.inheritedRoles || []).filter((r) => ["root", "dbOwner", "readWrite", "readWriteAnyDatabase", "dbAdmin", "dbAdminAnyDatabase", "userAdmin", "userAdminAnyDatabase", "clusterAdmin", "clusterManager", "hostManager", "restore", "backup", "__system"].includes(r.role));
  line(builtIn.length ? "FAIL" : "PASS", "R2", "No administrative or write roles", builtIn.map((r) => r.role + "@" + r.db).join(", "));
  const exp = info.customData && info.customData.expiresAt ? new Date(info.customData.expiresAt) : null;
  line(!exp ? "FAIL" : exp < new Date() ? "FAIL" : "PASS", "E1", "Has an expiry date that has not passed", !exp ? "No ROUA expiry recorded: forgotten accounts are the most common leak" : "Expired " + exp.toISOString() + ": run revoke.js");
  const restr = info.authenticationRestrictions || [];
  line(restr.length ? "PASS" : "WARN", "N1", "Limited to known client IPs", "No authenticationRestrictions");
  const mech = info.mechanisms || [];
  line(mech.includes("SCRAM-SHA-1") ? "WARN" : "PASS", "C1", "SCRAM-SHA-256 only", "SCRAM-SHA-1 is enabled");
  print("INFO  X1  MongoDB cannot hide single fields by privilege: check readable collections for secrets yourself.");
}
print(fails === 0 ? "READ-ONLY: every check passed." : "NOT READ-ONLY: " + fails + " check(s) failed.");
`;
}

