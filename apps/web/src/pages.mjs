// Content for every page of kaizam.com. The build (build.mjs) renders each
// entry with template.html. All pages share one script and one stylesheet.
// Text here is static HTML written by the project, not user input.

export const SITE = "https://kaizam.com";

const usual = (code, misses) => `
<h2>The usual way, and what it misses</h2>
<pre class="snippet">${code}</pre>
<ul class="misses">${misses.map((m) => `<li>${m}</li>`).join("")}</ul>`;

const does = (items) => `<h2>What the ROUA scripts do instead</h2><ul class="does">${items.map((m) => `<li>${m}</li>`).join("")}</ul>`;
const limits = (items) => `<h3>Limits to know</h3><ul>${items.map((m) => `<li>${m}</li>`).join("")}</ul>`;

function enginePage(o) {
  return {
    path: `${o.engine}/`,
    engine: o.engine,
    title: `Read-only user for ${o.name}: create and audit safely | ROUA`,
    description: o.description,
    eyebrow: `ROUA for ${o.name}`,
    h1: o.h1,
    lede: o.lede,
    section: `<section class="band pagebody"><div class="wrap narrowtext">${usual(o.usualCode, o.misses)}${does(o.does)}${limits(o.limits)}
      <p class="cta"><a class="btn primary" href="#generator">Create a read-only ${o.name} account</a> <a class="btn" href="#check">Audit an existing ${o.name} user</a></p>
      <p class="help">Know ${o.name} well? Something here wrong, missing or worth adding? <a href="https://github.com/PromiseGithub/roua/issues/new?template=database.yml&amp;title=${encodeURIComponent(o.name + ": ")}" rel="noopener">Tell us about ${o.name}</a> or <a href="https://github.com/PromiseGithub/roua/discussions/new?category=ideas" rel="noopener">share an idea</a>.</p></div></section>`,
  };
}

export const PAGES = [
  {
    path: "",
    engine: "",
    title: "ROUA: read-only database accounts you can prove",
    description:
      "Create and check read-only database accounts for AI agents, demos, auditors and app reviewers. PostgreSQL, MySQL, MariaDB, SQL Server, Oracle, MongoDB, Redis, Snowflake and BigQuery. Free, open source, runs in your browser.",
    eyebrow: "ROUA · Read-Only User Account · open standard",
    h1: "Read-only database access you can prove.",
    lede: `Give a database to an AI agent, a demo, an auditor or an app reviewer. ROUA makes sure the account
      <strong>changes nothing</strong>, <strong>never reads secrets</strong> and <strong>switches itself off</strong>, and then checks that it really does.`,
    section: "",
  },
  enginePage({
    engine: "postgresql",
    name: "PostgreSQL",
    h1: "A PostgreSQL read-only user that is actually read-only.",
    lede: "Create a PostgreSQL role that can read what it should, change nothing, never see secrets and expire on its own, and prove it before you hand it over.",
    description: "Create a truly read-only PostgreSQL user: no write path through roles, ownership or SECURITY DEFINER functions, secrets hidden, masking, expiry, and an audit that proves it. Free, runs in your browser.",
    usualCode: `CREATE ROLE readonly LOGIN PASSWORD '…';
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO readonly;`,
    misses: [
      "Default privileges make every <b>future</b> table readable too, including the next one that stores tokens.",
      "Every column is readable: password hashes, API keys, MFA secrets.",
      "Roles it can <code>SET ROLE</code> into, tables it owns and SECURITY DEFINER functions are all hidden write paths.",
      "The password sits in plaintext in the script, the server log and query history.",
      "It never expires.",
    ],
    does: [
      "Starts from nothing, then grants SELECT per table and column as they exist today. No default privileges.",
      "Hides secret-looking columns automatically; optional masked views (emails, phones, IDs) at level L4.",
      "Stores only a SCRAM-SHA-256 verifier, never the password.",
      "Sets <code>VALID UNTIL</code>, connection and statement limits, and records the owner and purpose on the role.",
      "<code>roua apply</code> then logs in <i>as</i> the account and attempts real writes, which PostgreSQL must refuse.",
    ],
    limits: [
      "A read-only role can still run expensive queries within its timeout and take advisory locks.",
      "Some audit checks need superuser (reading pg_hba.conf); on managed services they report a warning instead.",
    ],
  }),
  enginePage({
    engine: "mysql",
    name: "MySQL",
    h1: "Create a read-only MySQL user without the usual gaps.",
    lede: "Generate a MySQL account that can only SELECT what you choose, never reads password or token columns, locks itself at expiry, and passes an audit you can rerun at any time.",
    description: "Create a read-only MySQL user properly: per-table SELECT, secret columns hidden, caching_sha2 password hash, automatic expiry with an event, and an audit script. MySQL 8.0, 8.4 and 9. Free, runs in your browser.",
    usualCode: `CREATE USER 'readonly'@'%' IDENTIFIED BY '…';
GRANT SELECT ON appdb.* TO 'readonly'@'%';`,
    misses: [
      "<code>appdb.*</code> covers every table created from now on, not just today's.",
      "It can read every column: <code>password_hash</code>, <code>api_token</code>, card data.",
      "The plaintext password is in the script and your shell history.",
      "<code>'%'</code> lets it connect from anywhere, and it never expires.",
    ],
    does: [
      "Grants SELECT per table, or per visible column where a table has secrets, computed from information_schema when setup runs.",
      "Never grants FILE, PROCESS, EXECUTE, LOCK TABLES, roles or proxies; resets anything the account already had.",
      "Stores a caching_sha2_password hash, not the password; optional REQUIRE SSL and MAX_USER_CONNECTIONS.",
      "Creates a one-shot event that locks the account and kills its sessions at expiry.",
      "Tested on every change against MySQL 8.0, 8.4 and 9: writes, DDL, locking reads, INTO OUTFILE, secret columns and new tables are all refused.",
    ],
    limits: [
      "MySQL has no per-account statement timeout; set max_execution_time in the client.",
      "Expiry needs the event scheduler (on by default in MySQL 8); the audit checks it.",
    ],
  }),
  enginePage({
    engine: "mariadb",
    name: "MariaDB",
    h1: "A read-only MariaDB user that expires on its own.",
    lede: "Per-table read access, secrets hidden, a password hash instead of the password, a statement time limit, and an event that locks the account at expiry.",
    description: "Create a read-only MariaDB user: per-table and per-column SELECT, secret columns hidden, native password hash, MAX_STATEMENT_TIME, scheduled expiry and an audit script. MariaDB 10.6 to 11.4.",
    usualCode: `CREATE USER 'readonly'@'%' IDENTIFIED BY '…';
GRANT SELECT ON appdb.* TO 'readonly'@'%';`,
    misses: [
      "Database-wide SELECT covers future tables and every secret column.",
      "The password is in plaintext; the account connects from anywhere and never expires.",
      "MariaDB ships with the event scheduler off, so most expiry recipes silently never fire.",
    ],
    does: [
      "Grants SELECT per table or per visible column, computed when setup runs; nothing database-wide.",
      "Stores the native password hash, adds MAX_STATEMENT_TIME and MAX_USER_CONNECTIONS.",
      "Schedules an event that locks the account and ends its sessions, and the audit fails if the scheduler is off.",
      "Tested on every change against MariaDB 10.6, 10.11 and 11.4.",
    ],
    limits: [
      "Unlike MySQL, MariaDB lets SELECT alone take row locks with SELECT ... FOR UPDATE inside a transaction.",
      "Turn on event_scheduler in the server configuration, or the account will not expire on its own.",
    ],
  }),
  enginePage({
    engine: "sqlserver",
    name: "SQL Server",
    h1: "A read-only SQL Server login, enforced with DENY.",
    lede: "Better than db_datareader: per-object SELECT, secret columns left out, every write and DDL permission denied database-wide, and an Agent job that disables the login at expiry.",
    description: "Create a read-only SQL Server login safely: hashed password, per-object SELECT, secret columns excluded, database-wide DENY on writes, expiry with SQL Server Agent, audit with effective permissions. SQL Server 2022, Azure SQL.",
    usualCode: `CREATE LOGIN readonly WITH PASSWORD = '…';
CREATE USER readonly FOR LOGIN readonly;
ALTER ROLE db_datareader ADD MEMBER readonly;`,
    misses: [
      "db_datareader covers every table and view, including future ones and every secret column.",
      "Nothing stops a later <code>db_datawriter</code> membership or an owned schema from adding writes.",
      "Linked servers with stored credentials can be a write path to another server.",
      "The password is in plaintext, and the login never expires.",
    ],
    does: [
      "Creates the login from a SHA-512 password hash (<code>HASHED</code>), never the password.",
      "Grants SELECT per table and view; where secrets exist, SELECT on the other columns only.",
      "DENYs INSERT, UPDATE, DELETE, EXECUTE, ALTER and every CREATE at database scope; DENY wins over any role added later.",
      "Creates a SQL Server Agent job that disables the login and kills its sessions at expiry.",
      "The audit uses <code>EXECUTE AS USER</code> to check effective permissions, roles, ownership and linked servers. Tested on SQL Server 2022.",
    ],
    limits: [
      "Locking hints such as UPDLOCK need only SELECT, so the account can hold locks inside a transaction.",
      "Expiry needs SQL Server Agent (not in Express). Azure SQL Database contained users need the plaintext password in the script.",
    ],
  }),
  enginePage({
    engine: "oracle",
    name: "Oracle",
    h1: "A read-only Oracle user that cannot lock your tables.",
    lede: "Grant READ instead of SELECT, per table, with a dedicated profile and a scheduler job that locks the account at expiry. No ANY privileges, ever.",
    description: "Create a read-only Oracle Database user: READ (not SELECT) per table so it cannot lock rows, no ANY privileges, a limits profile, scheduled expiry and an audit for roles, proxies, directories and network ACLs. Oracle 23ai and 19c.",
    usualCode: `CREATE USER readonly IDENTIFIED BY "…";
GRANT CREATE SESSION, SELECT ANY TABLE TO readonly;`,
    misses: [
      "SELECT ANY TABLE reads every schema, now and in the future.",
      "SELECT allows <code>LOCK TABLE</code> and <code>SELECT ... FOR UPDATE</code>, so a read-only user can block your writers.",
      "Roles like CONNECT or RESOURCE, proxy grants and directory objects add more than they seem to.",
      "Password expiry is not account expiry: the user can just set a new password.",
    ],
    does: [
      "Grants READ per table and view, computed when setup runs; never ANY privileges or schema-level grants.",
      "Skips tables with secret-looking columns (Oracle has no column read grants) and lists them so you can add a view.",
      "Creates a dedicated profile (sessions, CPU per call, idle time) and a scheduler job that locks the account at expiry.",
      "The audit checks system privileges, roles, proxies, directories, owned objects, secret columns and network ACLs. Tested on Oracle 23ai.",
    ],
    limits: [
      "Oracle needs the plaintext password in the setup script; delete it after running.",
      "PUBLIC can execute UTL_HTTP and similar packages by default; the audit checks that no network ACL lets the account use them.",
    ],
  }),
  enginePage({
    engine: "mongodb",
    name: "MongoDB",
    h1: "A read-only MongoDB user limited to the collections you choose.",
    lede: "A custom role with find on named collections only, not the built-in read role, so new collections stay closed. No $out, no $merge, optional client IP restriction.",
    description: "Create a read-only MongoDB user: a custom role with find on named collections only (not read or readAnyDatabase), SCRAM-SHA-256, client IP restriction, revoke script and an audit. MongoDB 6.0 to 8.0, Atlas notes.",
    usualCode: `db.createUser({ user: "readonly", pwd: "…", roles: ["read"] })`,
    misses: [
      "The read role covers every collection in the database, including the ones created next month.",
      "Every field is readable, and the user can connect from anywhere.",
      "MongoDB users never expire.",
    ],
    does: [
      "Builds a custom role with find, listIndexes and collStats on each chosen collection, and listCollections on the database.",
      "No insert, update or remove, so aggregation $out and $merge are refused too.",
      "SCRAM-SHA-256 only, optional authenticationRestrictions for client IPs, expiry recorded in customData.",
      "Tested on every change against MongoDB 6.0, 7.0 and 8.0.",
    ],
    limits: [
      "Privileges cannot hide single fields: leave out collections with secrets, or list a view that $projects them away.",
      "There is no scheduler: run revoke.js at the expiry (the audit fails once it has passed). On Atlas, use a temporary database user.",
    ],
  }),
  enginePage({
    engine: "redis",
    name: "Redis",
    h1: "A read-only Redis user with ACLs that actually stop writes.",
    lede: "An ACL user that can run read commands on your key patterns only, with no KEYS, CONFIG, MONITOR, EVAL or pub/sub, and only a password hash in the script. Works with Valkey too.",
    description: "Create a read-only Redis or Valkey ACL user: +@read on chosen key patterns with %R~, no dangerous, admin, scripting or pub/sub commands, hashed password, and an audit with ACL DRYRUN. Redis 7, Valkey 8.",
    usualCode: `ACL SETUSER readonly on >password ~* +@read`,
    misses: [
      "<code>~*</code> is every key, including sessions and tokens.",
      "<code>+@read</code> includes KEYS, which can stall a production server.",
      "The password is in plaintext, and the default user may still be open with nopass.",
      "Redis users never expire.",
    ],
    does: [
      "<code>%R~</code> read-only key permissions on the patterns you list, and no channels.",
      "<code>-@all +@read +@connection</code>, then removes @write, @dangerous, @admin, @scripting and @pubsub.",
      "Stores the SHA-256 of the password (<code>#hash</code>), never the password.",
      "The audit uses ACL DRYRUN to prove SET, DEL, FLUSHALL, CONFIG, KEYS, EVAL and PUBLISH are refused, and flags an open default user. Tested on Redis 7.2, 7.4 and Valkey 8.",
    ],
    limits: [
      "Redis has no user expiry: schedule revoke.redis.",
      "Key patterns apply to every logical database.",
    ],
  }),
  enginePage({
    engine: "snowflake",
    name: "Snowflake",
    h1: "A read-only Snowflake user without future grants or secondary roles.",
    lede: "A dedicated role with point-in-time SELECT, a key-pair service user with no password, DEFAULT_SECONDARY_ROLES = () and DAYS_TO_EXPIRY. Preview: review before use.",
    description: "Create a read-only Snowflake user: dedicated role with point-in-time SELECT (no future grants), key-pair SERVICE user, no secondary roles, DAYS_TO_EXPIRY, network policy and an audit. Preview.",
    usualCode: `GRANT SELECT ON ALL TABLES IN SCHEMA analytics.public TO ROLE reader;
GRANT SELECT ON FUTURE TABLES IN SCHEMA analytics.public TO ROLE reader;
CREATE USER readonly PASSWORD = '…' DEFAULT_ROLE = reader;`,
    misses: [
      "Future grants make every new table readable automatically.",
      "New users get DEFAULT_SECONDARY_ROLES = ('ALL'), so every other role they are granted is active at once.",
      "Password sign-in, and no expiry.",
    ],
    does: [
      "Rebuilds a dedicated role on every run with SELECT on today's tables only; skips tables with secret-looking columns.",
      "Creates a TYPE = SERVICE user with an RSA key you can generate in this page; no password exists.",
      "Sets DEFAULT_SECONDARY_ROLES = (), DAYS_TO_EXPIRY, an optional statement timeout and network policy.",
    ],
    limits: [
      "Preview: generated from Snowflake's documentation and not yet run against a live account in CI.",
      "Every user has a personal stage and can download what it can read; scope it accordingly. Give it a small warehouse with a resource monitor.",
    ],
  }),
  enginePage({
    engine: "bigquery",
    name: "BigQuery",
    h1: "Read-only BigQuery access that ends on a date.",
    lede: "A service account with Data Viewer on chosen tables only, and query rights that end through an IAM condition. Impersonation instead of key files. Preview: review before use.",
    description: "Create read-only BigQuery access: a service account with table-level Data Viewer, query rights that expire through an IAM condition, impersonation instead of key files, and an audit. Preview.",
    usualCode: `gcloud projects add-iam-policy-binding my-project \\
  --member serviceAccount:reader@my-project.iam.gserviceaccount.com \\
  --role roles/bigquery.dataViewer
gcloud iam service-accounts keys create key.json …`,
    misses: [
      "Project-level Data Viewer covers every dataset, now and later.",
      "A JSON key file never expires and is easy to leak.",
      "Nothing caps the cost of the queries it runs.",
    ],
    does: [
      "Grants roles/bigquery.dataViewer per table (BigQuery DCL), skipping tables with secret-looking columns.",
      "Grants roles/bigquery.jobUser with an IAM condition that ends at the expiry time.",
      "Lets one person or agent impersonate the account until expiry, so no key file is created.",
    ],
    limits: [
      "Preview: generated from Google's documentation and not yet run against a live project in CI.",
      "Set a custom query quota so the account cannot run up a large bill.",
    ],
  }),
  {
    path: "ai-agents/",
    engine: "",
    title: "Give an AI agent read-only database access, safely | ROUA",
    description:
      "How to let an AI agent, MCP server or text-to-SQL tool query your database without being able to change anything, read secrets or keep access forever. Step by step, with an MCP server.",
    eyebrow: "Guide",
    h1: "Give an AI agent database access without giving it the keys.",
    lede: "Agents are good at exploring schemas and answering questions. They are also fast, literal and sometimes wrong. A ROUA lets them read what they need and nothing else.",
    section: `<section class="band pagebody"><div class="wrap narrowtext">
<h2>Why a plain “read-only” user is not enough for an agent</h2>
<ul class="misses">
<li><b>Agents try things.</b> If any write path exists (an inherited role, an owned table, a callable procedure), an agent following a bad instruction will find it.</li>
<li><b>Prompt injection is real.</b> Text inside your data can tell the agent to run something. The database must refuse, whatever the agent is told.</li>
<li><b>Agents repeat what they read.</b> Never let them see password hashes, tokens or customer secrets.</li>
<li><b>Agents outlive experiments.</b> The account must expire when the pilot ends.</li>
</ul>
<h2>Step by step</h2>
<ol>
<li>Create a ROUA with the <b>AI agent</b> profile below. Exclude tables the agent has no business seeing.</li>
<li>Run the setup script as an administrator, then the audit. Every check should pass.</li>
<li>Put the connection string in the agent's environment or MCP configuration, never in a prompt or a repository.</li>
<li>Re-run the audit on a schedule, or in CI with the ROUA GitHub Action.</li>
</ol>
<h2>Let the agent check its own access: the ROUA MCP server</h2>
<p>The <code>roua mcp</code> server gives MCP clients tools to list engines, write audit scripts, generate ROUA scripts to files (secrets never enter the conversation) and audit a PostgreSQL role live.</p>
<pre class="snippet">{
  "mcpServers": {
    "roua": {
      "command": "npx",
      "args": ["-y", "@roua-dev/cli", "mcp"],
      "env": { "ADMIN_DATABASE_URL": "postgres://admin@db.internal/appdb" }
    }
  }
}</pre>
<p class="help">ADMIN_DATABASE_URL is optional and only used by the live PostgreSQL audit tool, which only reads.</p>
</div></section>`,
  },
  {
    path: "app-review/",
    engine: "",
    profile: "review",
    title: "Demo accounts for App Store and Google Play review that can't break production | ROUA",
    description:
      "App reviewers need a working login. Give them one that can explore every screen without changing real data, sending messages or moving money, and that expires after review.",
    eyebrow: "Guide",
    h1: "A demo account for app review that cannot break anything.",
    lede: "App Store and Google Play reviewers need to sign in and try every feature. Give them an account that can look at everything, change nothing real, and disappear after review.",
    section: `<section class="band pagebody"><div class="wrap narrowtext">
<h2>Two layers</h2>
<ul class="does">
<li><b>Database:</b> a ROUA with the <b>App review</b> profile (below) so the account's queries can only read, on synthetic or seeded data.</li>
<li><b>Application:</b> <a href="https://github.com/PromiseGithub/roua/blob/main/docs/ROUA-APP.md" rel="noopener">ROUA-App</a> middleware for Express, Fastify and Fetch handlers. In <code>read_only</code> mode writes are refused; in <code>sandbox</code> mode they go to a resettable sandbox with payments in test mode and messages sent to a sink. Identity, credential, money and bulk-export routes stay blocked either way.</li>
</ul>
<h2>Checklist for the review account</h2>
<ol>
<li>Seed realistic but synthetic data: no real customers, ever.</li>
<li>Create the ROUA with an expiry a few weeks after submission (the review profile allows up to 45 days).</li>
<li>Put the credentials in the review notes, and nowhere else.</li>
<li>Run the audit before you submit, and revoke the account once the app is approved.</li>
</ol>
</div></section>`,
  },
];

const row = (cells) => `<tr>${cells.map((c, i) => (i === 0 ? `<th scope="row">${c}</th>` : `<td>${c}</td>`)).join("")}</tr>`;

PAGES.push(
  {
    path: "compare/",
    engine: "",
    title: "ROUA vs built-in read-only roles (pg_read_all_data, db_datareader, read…) | ROUA",
    description:
      "Why built-in read roles such as pg_read_all_data, GRANT SELECT ON db.*, db_datareader, SELECT ANY TABLE and MongoDB's read role are broader than they look, and what a ROUA does differently.",
    eyebrow: "Comparison",
    h1: "Built-in read roles are broader than they look.",
    lede: "Every database ships a quick way to make a reader. Each one reads more than intended, keeps reading as the schema grows, and never switches itself off. Here is exactly how, per database.",
    section: `<section class="band pagebody"><div class="wrap">
<div class="tablewrap"><table>
<thead><tr><th scope="col">Built-in shortcut</th><th scope="col">What it really allows</th><th scope="col">What a ROUA does instead</th></tr></thead>
<tbody>
${row(["PostgreSQL <code>pg_read_all_data</code>", "Every table and view in every schema, including tables created later and every secret column. Columns cannot be excluded.", "SELECT per table, or per visible column, as tables exist today. Secret columns hidden."])}
${row(["PostgreSQL <code>GRANT SELECT ON ALL TABLES</code> + default privileges", "Default privileges make future tables readable automatically. Inherited roles, owned objects and SECURITY DEFINER functions are not checked.", "No default privileges. The audit follows every role the account can reach and every object it owns."])}
${row(["MySQL / MariaDB <code>GRANT SELECT ON db.*</code>", "Every current and future table in the database, every column.", "Per-table and per-column grants computed when setup runs; nothing database-wide."])}
${row(["SQL Server <code>db_datareader</code>", "Every table and view, now and later, every column. Nothing stops another role membership from adding writes.", "Per-object SELECT, secret columns left out, and DENY on every write and DDL permission, which wins over any role added later."])}
${row(["Oracle <code>SELECT ANY TABLE</code> / <code>READ ANY TABLE</code>", "Every schema, now and later. SELECT also allows LOCK TABLE and SELECT … FOR UPDATE.", "READ per table (no locks), never ANY privileges."])}
${row(["MongoDB <code>read</code> / <code>readAnyDatabase</code>", "Every collection in the database (or every database), including future ones.", "A custom role with find on named collections only."])}
${row(["Redis <code>+@read ~*</code>", "Every key, plus KEYS, which can stall the server.", "Read commands on chosen key patterns only, no dangerous, admin, scripting or pub/sub commands."])}
${row(["Snowflake <code>FUTURE</code> grants", "New tables become readable automatically; new users default to all secondary roles.", "Point-in-time grants and DEFAULT_SECONDARY_ROLES = ()."])}
${row(["BigQuery project-level <code>dataViewer</code>", "Every dataset in the project, now and later, through a key file that never expires.", "Table-level grants and query rights that end through an IAM condition."])}
</tbody></table></div>
<h2>What no built-in role gives you</h2>
<ul class="does">
<li><b>An owner and a purpose</b>, recorded on the account itself.</li>
<li><b>An expiry</b> that the database (or a scheduled job) enforces.</li>
<li><b>One-step revoke</b> that also ends open sessions.</li>
<li><b>Proof:</b> an audit with stable check IDs you can run in CI, before handover and on a schedule.</li>
</ul>
<p class="cta"><a class="btn primary" href="#check">Audit the read-only account you already have</a></p>
</div></section>`,
  },
  {
    path: "threat-model/",
    engine: "",
    title: "ROUA threat model: what read-only accounts do and do not protect | ROUA",
    description:
      "What a ROUA protects against (writes, privilege escalation, secret columns, forgotten accounts) and what it does not (exfiltration of readable data, resource use, badly named secrets), with per-database limits.",
    eyebrow: "Threat model",
    h1: "What a read-only account protects, and what it can’t.",
    lede: "ROUA is honest about its limits. Read-only stops changes; it does not make data safe to show anyone. Here is where the line is.",
    section: `<section class="band pagebody"><div class="wrap narrowtext">
<h2>Protects against</h2>
<ul class="does">
<li><b>Any write or schema change</b>, including through inherited roles, owned objects, callable procedures and default grants.</li>
<li><b>Privilege escalation</b> through role membership, impersonation, proxies or definer-rights code.</li>
<li><b>Reading secret-looking columns</b> (passwords, tokens, keys, MFA seeds) by name, plus anything you list.</li>
<li><b>Forgotten accounts</b>: every ROUA has an owner and an enforced expiry, and revoke ends open sessions.</li>
<li><b>Drift</b>: the audit can run in CI and on a schedule, so a grant added later is noticed.</li>
</ul>
<h2>Does not protect against</h2>
<ul class="misses">
<li><b>Exfiltration of what it can read.</b> Anything the account can read, its holder can copy. Scope it, exclude tables, and on PostgreSQL use masking (L4).</li>
<li><b>Resource use within its limits.</b> Timeouts and connection caps reduce it; the G checks report missing limits.</li>
<li><b>Secrets in badly named columns.</b> The detector reads names. The opt-in value sampling (<code>--sample-values</code>) catches common formats, but it is a heuristic.</li>
<li><b>Administrators.</b> Anyone who can grant privileges can widen the account later. Re-run the audit.</li>
</ul>
<h2>Per-database limits</h2>
<ul>
<li><b>MariaDB:</b> SELECT alone allows locking reads (SELECT … FOR UPDATE). Expiry needs the event scheduler, which ships off.</li>
<li><b>SQL Server:</b> locking hints need only SELECT. Expiry needs SQL Server Agent.</li>
<li><b>Oracle:</b> no column-level read grants, so tables with secrets are skipped; the plaintext password is in the setup script.</li>
<li><b>MongoDB:</b> fields cannot be hidden by privilege; no built-in expiry, so the revoke must be scheduled (templates are generated).</li>
<li><b>Redis:</b> no built-in expiry; key patterns apply across logical databases.</li>
<li><b>Snowflake, BigQuery:</b> preview; every reader can export what it reads.</li>
</ul>
<p>The full threat model, including the tool's own supply chain, is in <a href="https://github.com/PromiseGithub/roua/blob/main/docs/threat-model.md" rel="noopener">docs/threat-model.md</a>. Found a gap? <a href="https://github.com/PromiseGithub/roua/security/advisories/new" rel="noopener">Report it privately</a>.</p>
</div></section>`,
  },
);

export const ENGINE_PAGES = PAGES.filter((p) => p.engine);

const SUPPORT = {
  postgresql: ["full", "Full"], mysql: ["tested", "Tested in CI"], mariadb: ["tested", "Tested in CI"], sqlserver: ["tested", "Tested in CI"],
  oracle: ["tested", "Tested in CI"], mongodb: ["tested", "Tested in CI"], redis: ["tested", "Tested in CI"],
  snowflake: ["preview", "Preview"], bigquery: ["preview", "Preview"],
};
const NAMES = { postgresql: "PostgreSQL", mysql: "MySQL", mariadb: "MariaDB", sqlserver: "SQL Server", oracle: "Oracle", mongodb: "MongoDB", redis: "Redis / Valkey", snowflake: "Snowflake", bigquery: "BigQuery" };
const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

const channel = (title, text, code, link) => `<article class="card channel"><h3>${title}</h3><p>${text}</p><pre class="snippet">${esc(code)}</pre>${link ? `<p class="more">${link}</p>` : ""}</article>`;

const SNIP_ACTION = [
  "- uses: PromiseGithub/roua@v0.5.0",
  "  env:",
  "    ADMIN_DATABASE_URL: $" + "{{ secrets.ADMIN_DATABASE_URL }}",
  "  with:",
  "    roles: readonly",
].join("\n");
const SNIP_MCP = ['{ "mcpServers": { "roua": {', '  "command": "npx",', '  "args": ["-y", "@roua-dev/cli", "mcp"] } } }'].join("\n");
const SNIP_DOCKER = ["docker run --rm -e ADMIN_DATABASE_URL \\", "  ghcr.io/promisegithub/roua audit --all"].join("\n");
const DB_CARDS = ENGINE_PAGES.map(
  (p) => `<a class="dbcard" href="/${p.path}"><b>${NAMES[p.engine]}</b><span class="badge ${SUPPORT[p.engine][0]}">${SUPPORT[p.engine][1]}</span><span>${esc(p.h1)}</span></a>`,
).join("\n      ");

PAGES[0].section = `<section class="band" id="start">
  <div class="wrap">
    <h2>Pick your database</h2>
    <p class="sub">Each page explains the usual way of making a read-only account, what it misses, and what ROUA does instead, with the generator ready for that database.</p>
    <div class="dbcards">
      ${DB_CARDS}
    </div>
    <div class="guides">
      <a class="guide" href="/ai-agents/"><b>Guide: AI agents</b><span>Give an agent or MCP server database access without giving it the keys.</span></a>
      <a class="guide" href="/app-review/"><b>Guide: app review accounts</b><span>Demo logins for App Store and Google Play review that cannot break production.</span></a>
    </div>
  </div>
</section>
<section id="tools">
  <div class="wrap">
    <h2>Use it where you work</h2>
    <p class="sub">The same rules everywhere: in your browser, in your terminal, in CI, for AI agents, and in containers. Free and open source.</p>
    <div class="cards channels">
      ${channel("In your browser", "This page. Nothing to install, nothing sent anywhere.", "https://kaizam.com", `<a href="#generator">Create an account</a> · <a href="#check">Audit one</a>`)}
      ${channel("Command line", "Audit, create, verify and revoke PostgreSQL accounts.", "npx @roua-dev/cli audit --role readonly", `<a href="https://www.npmjs.com/package/@roua-dev/cli" rel="noopener">npm</a>`)}
      ${channel("GitHub Action", "Fail the build when an account stops being read-only.", SNIP_ACTION, `<a href="https://github.com/marketplace/actions/roua-audit" rel="noopener">GitHub Marketplace</a>`)}
      ${channel("MCP server for AI agents", "Agents can audit accounts and prepare ROUA scripts; secrets never enter the chat.", SNIP_MCP, `<a href="/ai-agents/">How to set it up</a>`)}
      ${channel("Docker", "No Node.js needed.", SNIP_DOCKER, `<a href="https://github.com/PromiseGithub/roua#docker" rel="noopener">Details</a>`)}
      ${channel("JavaScript library", "Generate scripts for any of the nine databases from your own tools.", 'import { planEngine } from "@roua-dev/core";', `<a href="https://github.com/PromiseGithub/roua#other-databases" rel="noopener">API</a>`)}
    </div>
  </div>
</section>`;
