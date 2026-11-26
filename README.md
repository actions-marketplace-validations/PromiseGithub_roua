# ROUA: Read-Only User Accounts

**Is your read-only user actually read-only?**

ROUA (*Read-Only User Account*) is an open standard and toolkit for accounts you hand to an AI agent, a demo, an auditor or an app-store reviewer. These accounts can look at everything they should, change nothing, read no secrets, and expire on their own.

> Spec **0.1 (draft)** · PostgreSQL, MySQL, MariaDB, SQL Server, Oracle, MongoDB, Redis, Snowflake, BigQuery · The term ROUA was coined by [Promise Okoroji](https://github.com/PromiseGithub).

> **Feedback wanted.** ROUA is young and shaped by the people who use it. [Share an idea](https://github.com/PromiseGithub/roua/discussions/new?category=ideas), [tell us what to improve](https://github.com/PromiseGithub/roua/issues/new/choose), or [say hello in Discussions](https://github.com/PromiseGithub/roua/discussions/2). Collaborators are welcome.

## Check the accounts you already have

```console
$ export ADMIN_DATABASE_URL=postgres://admin@db.internal/appdb
$ npx @roua-dev/cli audit --role readonly

ROUA audit: role readonly (PostgreSQL 16)

FAIL  R2  Account expires
           No expiry (VALID UNTIL is not set). Forgotten accounts are the most common leak.
INFO  R5  Reachable roles are not privileged
           app_rw (via SET ROLE)
FAIL  T1  No write privileges on tables or views
           public.orders: DELETE, INSERT, UPDATE (via app_rw)
WARN  F1  No executable SECURITY DEFINER functions
           refund(integer) (owner postgres)
FAIL  X1  No secret-pattern columns readable
           public.users.password_hash
...
NOT READ-ONLY (or not safe to hand over)   3 fail, 7 warn, 7 pass, 1 info
```

The audit is read-only and needs nothing installed in the database. It follows every path a role has to write: table and column grants, roles reachable through `SET ROLE`, ownership, sequences, SECURITY DEFINER functions, large objects, foreign servers and `pg_hba.conf` `trust` rules. It also lists secret-looking columns the role can read, and reports missing time, idle-transaction and lock limits (G1 to G4). Each finding comes with a fix. Use `--all` to audit every login role, `--json` for scripts, and `--sarif-out` or `--junit-out` for code scanning and CI test reports. `--sample-values 20` (opt-in) also samples readable text columns for secrets in badly named columns, such as tokens, private keys and password hashes; it reports columns, never values.

No Node.js? The same checks ship as plain SQL: `psql "$ADMIN_DATABASE_URL" -v role=readonly -f` [`audit.sql`](audit.sql)

## Create one properly

```console
$ npx @roua-dev/cli init --profile agent --name roua_agent_docs --database appdb
$ npx @roua-dev/cli plan --check    # what the scope matches in the real schema: hidden columns, typos, empty scopes
$ npx @roua-dev/cli plan            # prints the SQL; changes nothing
$ npx @roua-dev/cli apply           # one transaction, then logs in AS the account and proves it
$ npx @roua-dev/cli rotate roua_agent_docs   # new password, same grants
$ npx @roua-dev/cli revoke roua_agent_docs
```

Setup resolves the scope against the real catalog when it runs, refuses a scope that would read nothing, reports names that match nothing, and grants per column, so a column added later stays hidden until setup runs again ([SPEC §18](SPEC.md#18-scope-resolution-and-schema-changes)).

`apply` generates a strong password, writes only a SCRAM-SHA-256 verifier into the SQL, applies everything in one transaction, then connects **as the new account**. It reruns the audit and attempts real writes and DDL, which PostgreSQL must refuse. Only then does it show the password, once.

Or use the **web generator** at **https://kaizam.com** (also built locally as `apps/web/dist/index.html`): a single HTML file that runs offline in your browser and makes no network requests. Pick a database, describe the account, and download the setup, audit, revoke and clean-up scripts. It can also write an audit script for an account you already have.

## Other databases

PostgreSQL has the full toolkit. For eight more engines, `@roua-dev/core` and the web generator produce setup, audit, revoke and drop scripts that follow the same rules: start from nothing, read per object as it exists today (never database-wide or future grants), hide secret-looking columns where the engine allows it, deny writes, record an owner, and expire on their own.

| Database | Support | How |
|---|---|---|
| MySQL 8.0, 8.4, 9 | Tested in CI | Per-table and per-column SELECT computed at setup; `caching_sha2_password` verifier; an event locks the account at expiry |
| MariaDB 10.6, 10.11, 11.4 | Tested in CI | Same, with a native password hash and `MAX_STATEMENT_TIME` |
| SQL Server 2022, Azure SQL | Tested in CI | Hashed login, per-object SELECT, database-wide DENY on every write, an Agent job disables the login at expiry |
| Oracle 23ai (and 19c) | Tested in CI | `READ` (not SELECT, so no row locks) per table, a dedicated profile, a scheduler job locks the account at expiry |
| MongoDB 6.0, 7.0, 8.0 | Tested in CI | A custom role with `find` on named collections only; no `$out`/`$merge`; Atlas notes |
| Redis 7.2, 7.4, Valkey 8 | Tested in CI | ACL user with `+@read` on key patterns (`%R~`), no dangerous, admin, scripting or pub/sub commands, hashed password |
| Snowflake | Preview | Rebuilt role with point-in-time SELECT, key-pair SERVICE user, no secondary roles, `DAYS_TO_EXPIRY` |
| BigQuery | Preview | Service account with table-level Data Viewer; query rights end through an IAM condition |

**Tested in CI** means every change runs the generated scripts with the engine's official client against a real server ([`engines.yml`](.github/workflows/engines.yml), [`scripts/live-engine-test.mjs`](scripts/live-engine-test.mjs)): it logs in as the account and proves that permitted reads work while writes, DDL, secret columns, excluded tables and tables created after setup are refused, that the audit passes, that expiry fires and that revoke cuts access. **Preview** engines are generated from vendor documentation and not yet run against a live service.

```ts
import { planEngine, auditScript } from "@roua-dev/core";

const plan = planEngine({ engine: "mysql", name: "roua_agent_docs", profile: "agent", owner: "jane@example.com",
  purpose: "Docs agent", expiresAt: "2027-02-01T00:00:00Z", mode: "scope", schemas: ["appdb"],
  exclude: ["appdb.salaries"], password: process.env.ROUA_PASSWORD });
plan.files; // setup.sql, audit.sql, revoke.sql, drop.sql
```

## In CI: the GitHub Action

```yaml
- uses: PromiseGithub/roua@v0.5.0
  env:
    ADMIN_DATABASE_URL: ${{ secrets.ADMIN_DATABASE_URL }}
  with:
    roles: readonly reporting_ro     # or: all: true
    fail-on: fail                    # fail | warn | never
    sarif-file: roua.sarif           # optional: upload with github/codeql-action/upload-sarif
```

The step fails when a role can write, read secrets or never expires, and writes a summary table and annotations. Outputs: `ok` and `report` (JSON).

## For AI agents: the MCP server

```json
{ "mcpServers": { "roua": { "command": "npx", "args": ["-y", "@roua-dev/cli", "mcp"] } } }
```

Tools ([reference](docs/MCP.md)): `list_engines`, `audit_script`, `generate_account_scripts` (writes scripts to a folder; passwords and keys go to owner-only files, never into the conversation) and `audit_postgres_role` (live and read-only; set `ADMIN_DATABASE_URL` in the server's environment). The server has no dependencies beyond the CLI's own. Registry name: `io.github.PromiseGithub/roua`.

## Docker

```console
docker run --rm -e ADMIN_DATABASE_URL ghcr.io/promisegithub/roua audit --all
```

## The standard in one table

**Profiles** say why the account exists, and each has a maximum lifetime: `agent` 90 days, `demo` 30, `review` 45, `audit` 30, `support` 7, `training` 14, `analytics` 180, `custom` 365.

**Levels** say what it can see:

| Level | Can read |
|---|---|
| L0 Metadata | Structure only, no rows |
| L1 Public | Only objects you list as public |
| L2 Operational | In-scope tables minus your deny-list and every secret column |
| L3 Analytical | Only the aggregate views you list |
| L4 Masked | Generated `security_barrier` views with emails, phones and IDs masked |
| L5 Break-glass | Unmasked, never secrets; two approvers, 24 hours maximum |

**Every ROUA, at every level:** no write path of any kind, never reads secrets, has an owner and an expiry, can be revoked instantly (open sessions included), and passes verification before anyone gets the password. Read the full [specification](SPEC.md).

## Demos and app-store review: ROUA-App

Reviewers and prospects need to *use* the app, not just look at it. The companion [ROUA-App](docs/ROUA-APP.md) spec defines accounts that can try every feature without consequence. In `read_only` mode writes are refused. In `sandbox` mode writes go to a resettable sandbox with payments in test mode and messages sent to a sink. In both modes, routes for identity, credentials, money, outbound messages and bulk exports stay blocked.

```ts
import { rouaExpress } from "@roua-dev/app";

app.use(express.json());
app.use(rouaExpress({ getAccount: (req) => req.user?.roua, readPostAllowlist: [/^\/api\/search$/] }));
```

Includes Express, Fastify and Fetch API (Next.js middleware, Hono, Workers) adapters, GraphQL mutation detection, and protection against method-override and path-encoding tricks.

## How it compares

ROUA works alongside Vault, Teleport, StrongDM, cloud IAM authentication and PostgreSQL Anonymizer: they manage *who* gets credentials and *how*, and ROUA defines and proves *what those credentials can do*. For example, ROUA level roles make good Vault dynamic-role grants, and `roua verify` can check the users Vault issues. See [docs/prior-art.md](docs/prior-art.md).

## Packages

| Path | What |
|---|---|
| [`packages/core`](packages/core) | Planner, auditor, verifier, SCRAM. Pure TypeScript, **zero runtime dependencies**, runs in Node and browsers |
| [`packages/cli`](packages/cli) | The `roua` command (`pg` and `yaml` are its only dependencies) |
| [`packages/app`](packages/app) | ROUA-App request guards |
| [`apps/web`](apps/web) | The offline, single-file generator |
| [`schemas`](schemas) | JSON Schemas for `roua.yaml` and reports |
| [`examples`](examples) | A `roua.yaml` for each profile |

## Develop

```console
npm install
npm run build
npm test                 # unit and end-to-end tests on a real PostgreSQL engine (PGlite), no Docker needed
ROUA_TEST_ADMIN_URL=postgres://postgres:postgres@localhost:5432/postgres npm run test:pg   # real server
```

CI runs the integration suite against PostgreSQL 13, 14, 15, 16 and 17.

## Security

Credibility is everything for a tool like this. If you can make `roua verify` pass on an account that can write or read a secret, that is a vulnerability: please report it privately as described in [SECURITY.md](SECURITY.md). Read the [threat model](docs/threat-model.md) for what ROUA does and does not protect against.

## Feedback and collaboration

ROUA gets better through the people who use it. All of these help:

- **Ideas and feedback:** what is missing, confusing or could be better. Start a thread in [💡 Ideas](https://github.com/PromiseGithub/roua/discussions/categories/ideas) or reply to the [welcome discussion](https://github.com/PromiseGithub/roua/discussions/2).
- **Problems:** a script that fails, an audit that is wrong, a confusing page. [Open an issue](https://github.com/PromiseGithub/roua/issues/new/choose).
- **Databases:** [request a new one](https://github.com/PromiseGithub/roua/issues/new?template=database.yml), or help test Snowflake and BigQuery.
- **Code and reviews:** see [CONTRIBUTING.md](CONTRIBUTING.md), the [roadmap](ROADMAP.md), and issues labelled [`help wanted`](https://github.com/PromiseGithub/roua/labels/help%20wanted) or [`good first issue`](https://github.com/PromiseGithub/roua/labels/good%20first%20issue). Spec changes go through [RFCs](rfcs/README.md).
- **Collaboration:** database vendors, AI-agent platforms, security teams and anyone who wants to co-maintain. Start a thread in [Discussions](https://github.com/PromiseGithub/roua/discussions); all contact is through GitHub.

## License

Code: [Apache-2.0](LICENSE). Specification documents (`SPEC.md`, `docs/ROUA-APP.md`): [CC BY 4.0](LICENSE-SPEC.md). See [NOTICE](NOTICE).

Contact: [@PromiseGithub](https://github.com/PromiseGithub) on GitHub.
