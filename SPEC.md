# ROUA: Read-Only User Account

**Specification 0.1 (draft)**

| | |
|---|---|
| Status | Draft for public comment. Expect changes before 1.0. |
| Term coined by | Promise Okoroji |
| Editor | Promise Okoroji ([@PromiseGithub](https://github.com/PromiseGithub)) |
| License | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) (this document). The reference implementation is Apache-2.0. |
| Feedback | [GitHub issues](https://github.com/PromiseGithub/roua/issues) and [discussions](https://github.com/PromiseGithub/roua/discussions) |

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are used as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

This document covers **ROUA-DB**: database accounts. Application-level accounts (demos, app-store review, AI agents using a web app) are covered by the companion draft [ROUA-App](docs/ROUA-APP.md). Version 0.1 defines PostgreSQL behaviour in detail; other engines are on the [roadmap](ROADMAP.md) and will be added only after they are tested the same way.

---

## 1. Why

Every organization eventually hands someone a "read-only" login: an AI agent learning a system, a sales demo, an auditor, an app-store reviewer, a vendor's support engineer. In practice these accounts are improvised. They are often able to write through some forgotten path, they rarely expire, nobody remembers who owns them, and they can usually read password hashes and API keys.

ROUA gives everyone the same vocabulary (profiles and levels), the same minimum guarantees, and a way to **check** them.

## 2. Definition

A **ROUA (Read-Only User Account)** is a limited-purpose account that satisfies all of the following.

1. **Cannot change anything.** It **MUST** be technically unable to create, modify or delete data or schema in the target system. This **MUST** be enforced by the target system's own permission model. Client settings, conventions and session defaults (for example PostgreSQL's `default_transaction_read_only`) **MUST NOT** be relied on, because the session can turn them off.
2. **Never reads secrets.** It **MUST NOT** be able to read secret values: password hashes, API keys, tokens, MFA seeds, private keys, encryption keys and similar. This applies at every level, including L5. See §5 for how secrets are identified.
3. **Has a purpose and a scope.** It **MUST** declare a profile (§3, why it exists) and a level (§4, what it can see).
4. **Has an owner.** It **MUST** name a human who is accountable for it.
5. **Expires.** It **MUST** have an expiry no later than its profile's maximum (§3), and it **MUST** be revocable at once, including ending sessions that are already open.
6. **Is verifiable.** It **MUST** pass the verification checks in §8 before credentials are handed over.
7. **Is identifiable.** It **SHOULD** carry ROUA metadata (§6) that tools and people can read.
8. **Is approved.** It **SHOULD** record who approved it. (Tools cannot validate an approval, so this is a SHOULD; L5 raises it to a MUST, see §4.)
9. **Is limited.** It **SHOULD** have connection and statement-time limits.
10. **Is audited.** Its activity **SHOULD** be logged.

### 2.1 Residual side effects

Some database actions cannot be blocked by privileges at all. In PostgreSQL every role can send `NOTIFY`, take advisory locks and consume resources. By default every role can also create temporary tables and large objects. A ROUA is still conformant when these remain possible, provided that:

- verification **MUST** report each one that is possible (§8, checks D1, F2, P3), and
- where a fix exists that does not depend on the account's goodwill (for example revoking `TEMPORARY` from `PUBLIC`), the report **MUST** state it.

Operators **SHOULD** make sure no application treats a `NOTIFY` from an arbitrary role as a trusted command.

## 3. Profiles: why the account exists

| Profile | Code | Default level | Default expiry | Maximum expiry | Notes |
|---|---|---|---|---|---|
| AI agent | `agent` | L2 | 90 days | 90 days | An AI agent or assistant learning or querying a system |
| Demo | `demo` | L1 | 30 days | 30 days | Use synthetic data, never real customers |
| App review | `review` | L1 | 30 days | 45 days | Database side of an app-store review; see ROUA-App for the application side |
| Auditor | `audit` | L4 | 30 days | 30 days | Internal or external audits |
| Support | `support` | L4 | 7 days | 7 days | Vendor or internal support sessions |
| Training | `training` | L2 | 14 days | 14 days | On synthetic or anonymized copies |
| Analytics | `analytics` | L3 | 180 days | 180 days | BI tools and analytics agents |
| Custom | `custom` | L2 | 30 days | 365 days | Organization-defined |

## 4. Levels: what the account can see

| Level | Name | Can read | Cannot read | Approval |
|---|---|---|---|---|
| **L0** | Metadata | Structure: schemas, tables, columns, types, relationships | Any row | SHOULD: owner |
| **L1** | Public | Only objects explicitly listed as public | Everything else | SHOULD: owner |
| **L2** | Operational | In-scope tables, minus a deny-list of objects and columns | Denied objects, denied columns, secrets | SHOULD: owner and data steward |
| **L3** | Analytical | Only listed aggregate views | Base tables | SHOULD: owner and data steward |
| **L4** | Masked | All in-scope tables through generated masked views | Base tables, raw values of masked columns, secrets | SHOULD: owner, data steward, security |
| **L5** | Break-glass | All in-scope data, unmasked | Secrets (never) | **MUST**: two distinct approvers; **MUST** expire within 24 hours; activity **MUST** be audited |

Rules that apply to every level:

- New objects created after the account was set up **MUST NOT** become readable automatically. (In PostgreSQL this means no `ALTER DEFAULT PRIVILEGES` for ROUA roles: a future table might hold secrets.) Re-applying the definition picks up new objects after they pass the secret detector.
- Views used at L3 and L4 **MUST** be protected against leaky-function attacks. In PostgreSQL they **MUST** be created `WITH (security_barrier)`.
- At L4, the `hash` masking function **MUST** use a secret key the ROUA cannot read. Otherwise the account can hash guesses (email addresses, phone numbers) and compare. The reference implementation keys the hash with a value stored in a table only the owner can read.
- An L3 aggregate view **SHOULD** suppress groups smaller than a minimum size (k-anonymity), for example with `HAVING count(*) >= 10`.

### 4.1 Masking functions

| Function | Output for `ada@example.com`, `+15551234567`, `1990-07-14`, `Ada Lovelace` |
|---|---|
| `email` | `a***@example.com` |
| `partial_last4` | `***4567` |
| `redact` | `NULL` |
| `hash` | 64 hex characters, keyed (stable within one database, so joins still work) |
| `year_only` | `1990-01-01` |
| `initials` | `A. L.` |

## 5. Secrets

A ROUA **MUST NOT** read secret values. Implementations identify secret columns in two ways, and **MUST** support both:

1. **A required, user-supplied deny-list** (`scope.columns_deny`). Name-based detection cannot see inside data, so this list is the authoritative control.
2. **A best-effort name detector.** The reference detector converts the column name to `snake_case` and flags names containing, for example, `password`, `secret`, `token`, `credential`, `api_key`, `private_key`, `encryption_key`, `card_number`, `webhook_sig…`, `recovery_codes`, or the words `pwd`, `pin`, `mfa`, `otp`, `totp`, `salt`, `cvv`, `cvc`, `pan`, `seed`, `nonce`. The full regular expression is published in [`packages/core/src/constants.ts`](packages/core/src/constants.ts).

The detector is a heuristic. False positives (such as `tokens_used`) fail safe: the column is hidden until it is listed in `scope.columns_allow`. Misses are possible, which is why item 1 exists. Implementations **MUST NOT** describe the detector as a guarantee.

Hidden columns **MUST** be enforced by the database (column-level grants, or views that omit them), never by query rewriting in a client.

## 6. Naming and metadata

- Login account names **MUST** match `^[a-z][a-z0-9_]{2,62}$` and **SHOULD** follow `roua_<profile>_<label>`, for example `roua_agent_docs` or `roua_review_appstore`.
- Grants **SHOULD** be held by a NOLOGIN level role (defaults: `roua_l0_meta`, `roua_l1_public`, `roua_l2_ops`, `roua_l3_analytics`, `roua_l4_masked`, `roua_l5_full`). Accounts that share a level role share its scope. Give accounts with different scopes different level roles.
- The account **SHOULD** carry this metadata string, stored as the role comment in PostgreSQL:

```
ROUA/0.1 profile=agent level=L2 owner=jane@example.com approved_by=cto@example.com approval_ref=TICKET-123 created=2026-11-23 expires=2027-02-21T00:00:00.000Z purpose="Docs assistant"
```

  Values other than `purpose` contain no spaces or quotes. `approved_by` may hold a comma-separated list.
- Clients using a ROUA **SHOULD** identify themselves, for example PostgreSQL `application_name = 'roua:<account>:<tool>'`.

## 7. Lifecycle

```
Request -> Approve -> Plan -> Review -> Apply -> Verify -> Hand over (once) -> Use -> Rotate -> Expire -> Revoke -> Drop
```

| Step | Requirement |
|---|---|
| Plan | The exact statements **MUST** be reviewable before anything runs. |
| Apply | **SHOULD** be one transaction. Re-applying **MUST** be idempotent and **MUST** remove privileges the definition no longer grants. |
| Verify | **MUST** pass (§8) before credentials are handed over. **SHOULD** be repeated on a schedule, because other people's grants drift. |
| Hand over | The password **SHOULD** be shown once and passed through a password manager or vault, never by email or chat. Scripts **SHOULD NOT** contain the plaintext password (PostgreSQL accepts a SCRAM-SHA-256 verifier instead). |
| Rotate | Credentials **SHOULD** be rotated at least every 90 days, and never less often than the profile's maximum lifetime. Rotation **MUST** replace the credential without widening privileges, **SHOULD** record the date in the metadata (`rotated=YYYY-MM-DD`), and **SHOULD** let open sessions finish unless asked to end them. Where the engine supports two valid credentials at once (key pairs, IAM tokens, dual passwords), tools **MAY** offer an overlap window, which **MUST NOT** exceed 24 hours. |
| Expire | Expiry **MUST** stop new logins. Where the engine cannot do this natively, a scheduled job **MUST** do it. |
| Revoke | **MUST** disable login **and** terminate open sessions. (PostgreSQL's `VALID UNTIL` alone does neither for sessions already open.) |
| Drop | **SHOULD** follow revoke. Dropping **MUST** remove the account's grants and anything it owns (on PostgreSQL, `DROP OWNED BY` in every database, then `DROP ROLE`), **MUST NOT** leave orphaned grants on the level role, and **SHOULD** keep the final audit report as evidence that the account existed and was removed. |

## 8. Verification

A conformant tool **MUST** run these checks and **MUST** exit non-zero if any check fails. Warnings do not fail unless the user asks for strict mode. Check identifiers are stable so reports can be compared over time.

**Catalog checks**, which work for any role, including accounts that were never created with ROUA. Each check covers the role itself **and every role it can reach**, whether by inheritance or by `SET ROLE`.

| ID | Check | Severity if not met |
|---|---|---|
| R1 | No superuser, CREATEROLE, CREATEDB, REPLICATION or BYPASSRLS | fail |
| R2 | Login roles have an expiry within the profile maximum | fail (none) / warn (too long) |
| R3 | Connection limit set | warn |
| R4 | No dangerous predefined roles (`pg_write_all_data`, `pg_read_all_data`, server file and program roles, `pg_signal_backend`, …) | fail |
| R5 | No reachable role has admin attributes | fail |
| T1 | No INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER (or MAINTAIN on 17+) on any table or view | fail |
| T2 | No column-level INSERT, UPDATE or REFERENCES | fail |
| T3 | Owns no tables, views, sequences, schemas, functions or databases | fail |
| S1 | No CREATE on any schema | fail |
| D1 | No CREATE on the database; TEMP reported | fail / warn |
| Q1 | No UPDATE on sequences; USAGE (`nextval`) reported | fail / warn |
| F1 | Executable SECURITY DEFINER functions reported | warn |
| F2 | Large-object creation reported; `lo_compat_privileges` off | warn / fail |
| X1 | No secret-pattern column is readable | fail |
| N1 | No USAGE on foreign servers | warn |
| N2 | No `trust` authentication for the role from remote hosts; role-specific `pg_hba.conf` rules exist | fail / warn |
| C1 | Read-only session default and audit logging configured | warn |
| G1 | Queries are time-limited (`statement_timeout` set, at most one hour) | warn |
| G2 | Idle transactions are ended (`idle_in_transaction_session_timeout` set) | warn |
| G3 | Lock waits are limited (`lock_timeout` set) | warn |
| G4 | Temporary file use is limited (`temp_file_limit` set; needs superuser) | info |
| M1 | ROUA metadata present and complete | warn |

**Optional value sampling.** With the administrator's explicit opt-in, a tool **MAY** run X2: read a small sample of rows from each text column the account can read and report columns whose values match known secret formats (private keys, JSON Web Tokens, cloud and SaaS API keys, password hashes, connection strings with passwords) or long high-entropy strings. X2 **MUST** report column names only, never values, and is always a warning: like §5, it is a heuristic, not a guarantee.

| ID | Check | Severity if not met |
|---|---|---|
| X2 | No secret-looking values in sampled readable columns | warn |

**Live probes**, run while connected as the account. Each runs in a transaction that is always rolled back, after explicitly setting `transaction_read_only = off`, so a refusal proves the privilege is missing rather than the default. Write probes affect zero rows (`UPDATE … WHERE false`, `DELETE … WHERE false`, `INSERT … SELECT … WHERE false`).

| ID | Probe | Expected |
|---|---|---|
| P1 | `CREATE TABLE` in every visible schema | insufficient privilege |
| P2 | `INSERT`, `UPDATE`, `DELETE` on readable tables | insufficient privilege |
| P3 | `CREATE TEMP TABLE`, `lo_create`, `NOTIFY` | reported as residual side effects (§2.1) |

**Scope checks**, run when the definition is available.

| ID | Check |
|---|---|
| V1 | Connected as the configured account |
| V5 | Every readable object is allowed by the level and scope (for L0: nothing readable; for L4: only masked views) |
| V7 | Sampled values of masked columns are masked as configured |

V2, V3, V4 and V6 are **reserved**. They were drafted for expiry enforcement, source-address restriction, TLS and "no object becomes readable automatically", and those properties are now covered by R2, N2 and the engine profiles in §10. The identifiers will not be reused for different meanings.

**Check IDs on other engines.** Each engine profile in §10 maps its checks to the same letters where the meaning carries over: R (role and account attributes), T (table and column privileges), O (ownership), F (functions and procedures), X (secrets), N (network), E (expiry), L or G (limits and resource governance), M (metadata).

The machine-readable report format is [`schemas/roua-report.schema.json`](schemas/roua-report.schema.json).

## 9. Account definition (`roua.yaml`)

The definition is a YAML file validated by [`schemas/roua.schema.json`](schemas/roua.schema.json). It **MUST NOT** contain passwords. Tools **MUST** reject unknown keys, invalid identifiers, an expiry beyond the profile maximum, and L5 definitions without two distinct approvers or with an expiry more than 24 hours away.

```yaml
roua_version: "0.1"
account:
  name: roua_agent_docs
  profile: agent
  level: L2
  owner: jane@example.com
  approved_by: cto@example.com
  approval_ref: TICKET-123
  purpose: "Docs assistant learning the data model"
  expires_at: "2027-02-21T00:00:00Z"
  limits: { max_connections: 5, statement_timeout_s: 30 }
  network: { allowed_sources: ["10.0.0.0/24"] }
target:
  engine: postgresql
  database: appdb
  schemas: [public, sales]
  object_owner: app_owner
scope:
  exclude: ["public.salaries", "public.api_keys"]
  columns_deny: ["public.users.national_id"]
hardening:
  revoke_temp_from_public: true
```

## 10. PostgreSQL profile (normative for 0.1)

Supported: PostgreSQL 13 and later. The reference implementation's SQL is the normative example. In summary:

- **Level role:** `NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`. It receives `CONNECT`, `USAGE` on in-scope schemas, and `SELECT` on in-scope relations. A table with any hidden column gets a column-level grant listing only its visible columns.
- **Never** use `pg_read_all_data` (it cannot exclude columns) or `ALTER DEFAULT PRIVILEGES`.
- **Login account:** `LOGIN … INHERIT CONNECTION LIMIT n VALID UNTIL '…' PASSWORD 'SCRAM-SHA-256$…'`. It is a member of the level role and nothing else, and it holds no direct grants. Session defaults (`default_transaction_read_only`, `statement_timeout`, `idle_in_transaction_session_timeout`, `lock_timeout`, `search_path`) are conveniences only.
- **Reset on apply:** before granting, revoke everything the level role and the account hold in the database (tables, sequences, functions, schemas, database) and every other role membership of the account.
- **L4:** views in `roua_masked_<schema>` built `WITH (security_barrier = true)` and owned by the object owner. Secret and denied columns are omitted, and masked columns are wrapped in the §4.1 functions. The account gets no base-table access.
- **Network:** restrict the account in `pg_hba.conf` (`hostssl <db> <account> <cidr> scram-sha-256`), above broader rules.
- **Hardening that affects every role** is opt-in and printed as a warning otherwise: `REVOKE TEMPORARY ON DATABASE … FROM PUBLIC`, and on PostgreSQL 14 and older `REVOKE CREATE ON SCHEMA public FROM PUBLIC`.
- **Revoke:** `ALTER ROLE … NOLOGIN` then `pg_terminate_backend()` for the account's sessions.
- **Rotate:** `ALTER ROLE … PASSWORD 'SCRAM-SHA-256$…'` with a new verifier; `VALID UNTIL` and grants are unchanged.

### 10.1 Other engine profiles (informative in 0.1)

These profiles describe what the reference generators do, and every one marked *tested* is verified on each change against a real server (writes, DDL, secret columns, excluded tables and tables created after setup are refused; the audit passes; expiry fires; revoke cuts access). They are **informative** in 0.1 and candidates to become normative in 0.2 through [RFC 0005](rfcs/0005-engine-profiles.md). Levels other than those listed are not offered on that engine.

| Engine | Levels | Read grant | Secrets | Writes | Credential | Expiry | Revoke |
|---|---|---|---|---|---|---|---|
| MySQL 8+ (tested) | L1, L2 | `SELECT` per table, or per visible column, computed from `information_schema` at setup; nothing database-wide | column-level grants omit secret columns | none granted; locking reads need UPDATE | `caching_sha2_password` hash | one-shot event (event scheduler) | `ACCOUNT LOCK` + `KILL` sessions |
| MariaDB 10.6+ (tested) | L1, L2 | as MySQL | as MySQL | none granted; **SELECT alone allows locking reads** | native password hash | one-shot event (scheduler is off by default; audit E2) | as MySQL |
| SQL Server 2017+, Azure SQL (tested) | L0, L1, L2 | `SELECT` per object, or on visible columns; L0 = `VIEW DEFINITION` on schemas, no SELECT | visible-column grants | database-wide `DENY` on every write and DDL permission | hashed login (`0x0200…`); contained users need plaintext | SQL Server Agent job | `ALTER LOGIN … DISABLE` (or `DENY CONNECT`) + `KILL` |
| Oracle 19c+ (tested) | L1, L2 | `READ` (not `SELECT`) per table and view; never ANY privileges or schema grants | tables with secret columns are skipped (no column read grants) | none granted | plaintext in setup script | `DBMS_SCHEDULER` job | `ACCOUNT LOCK` + `KILL SESSION` |
| MongoDB 6+ (tested) | L0, L1, L2 | custom role: `find`, `listIndexes`, `collStats` on named collections; L0 = `listCollections` and `listIndexes` only | fields cannot be hidden by privilege; use views | no insert/update/remove, so `$out`/`$merge` fail | SCRAM-SHA-256 (plaintext in setup script) | **none built in**: scheduled revoke (templates generated); audit E1 fails after expiry | roles revoked, password randomized, sessions killed |
| Redis 6.2+/Valkey (tested) | L1 | ACL `-@all +@read +@connection` minus `@write @dangerous @admin @scripting @pubsub`, `%R~` key patterns, no channels | key patterns only | blocked by command category and read-only key permissions | SHA-256 password hash | **none built in**: scheduled revoke | `ACL SETUSER … off` + `CLIENT KILL USER` |
| Snowflake (preview) | L0, L1, L2 | dedicated role rebuilt per run; point-in-time `SELECT` (L0: `REFERENCES`); no FUTURE grants | tables with secret columns skipped | none granted | key pair, `TYPE = SERVICE` | `DAYS_TO_EXPIRY` | `DISABLED = TRUE` |
| BigQuery (preview) | L0, L1, L2 | `roles/bigquery.dataViewer` per table (L0: `metadataViewer` per dataset) | tables with secret columns skipped | none granted | service account, impersonation preferred over keys | IAM condition on `jobUser` | disable service account |

## 11. Conformance

- A **ROUA-conformant account** satisfies §2 and passes §8 with no failures.
- A **ROUA-conformant tool** creates accounts that are conformant, runs every §8 check for its engines, and produces reports in the §8 format.
- Claims of conformance **SHOULD** name the spec version, for example "ROUA 0.1 conformant (PostgreSQL)".

## 12. Relationship to other tools

ROUA is a vocabulary plus a verification method. It is meant to work alongside existing access tools, not replace them. See [docs/prior-art.md](docs/prior-art.md). For example, the SQL a ROUA tool generates can serve as the creation statements of a HashiCorp Vault dynamic database role, and `roua verify` can check the users Vault issues.

## 13. Versioning and changes

- The specification uses semantic versioning. Until 1.0, minor versions may make breaking changes; each one is listed in [CHANGELOG.md](CHANGELOG.md).
- Changes are proposed as RFCs in [`rfcs/`](rfcs/README.md), with at least 14 days of public comment.
- New engines are added only with a tested reference implementation and integration tests on real servers.
- **1.0 criteria:** every engine profile in §10.1 is normative and tested; rotation, drop and approval records are specified and verified by tools; a public conformance kit exists so other tools can prove conformance; and the open RFCs listed in [rfcs/README.md](rfcs/README.md) are accepted or withdrawn.

## 14. Resource governance

A read-only account can still hurt a production system through long scans, open transactions and lock waits. Every ROUA **SHOULD** have a statement time limit, an idle-transaction limit and a connection cap, and on warehouses that bill per query a cost cap. Tools **SHOULD** generate these where the engine supports them and **SHOULD** report missing ones (G checks on PostgreSQL).

| Engine | Controls |
|---|---|
| PostgreSQL | `statement_timeout`, `idle_in_transaction_session_timeout`, `lock_timeout`, `temp_file_limit` (superuser), `CONNECTION LIMIT` |
| MySQL | `MAX_USER_CONNECTIONS`, optional `MAX_QUERIES_PER_HOUR`; `max_execution_time` in the client (no per-account timeout) |
| MariaDB | `MAX_STATEMENT_TIME`, `MAX_USER_CONNECTIONS` |
| SQL Server | Resource Governor workload group with a classifier for ROUA logins (Enterprise and Developer editions); `query governor cost limit` |
| Oracle | profile with `SESSIONS_PER_USER`, `CPU_PER_CALL`, `LOGICAL_READS_PER_CALL`, `IDLE_TIME`; optionally a Resource Manager consumer group |
| MongoDB | `maxTimeMS` in clients or a proxy; connection limits at the driver or proxy |
| Redis | `@slow`, `@dangerous`, `@admin` denied in the ACL |
| Snowflake | dedicated small warehouse with a resource monitor (credit quota, suspend); `STATEMENT_TIMEOUT_IN_SECONDS` |
| BigQuery | `maximumBytesBilled` on clients, custom per-user query quotas, a dedicated reservation |

## 15. Query logging

Auditors and incident responders need to know what an account read. A ROUA **SHOULD** have query logging enabled for its sessions, and accounts at L4 and L5 **SHOULD** treat it as required ([RFC 0004](rfcs/0004-logging-and-credentials.md) proposes making it a MUST for those levels). Engine mechanisms: PostgreSQL `pgaudit` (`pgaudit.log = 'read'` per role), MySQL Enterprise Audit or the Percona/MariaDB audit plugins, SQL Server Audit, Oracle Unified Auditing, MongoDB `auditLog` (Enterprise and Atlas), Redis `MONITOR` is not suitable (it is itself a dangerous command), Snowflake `ACCESS_HISTORY`, BigQuery Data Access audit logs.

## 16. Credential classes (informative)

Static passwords with long lives are the weakest part of most access setups. In order of preference for unattended use (agents, services):

1. **Identity-based tokens**: Amazon RDS and Aurora IAM authentication, Google Cloud SQL IAM, Microsoft Entra ID for Azure SQL and Azure Database, with token lifetimes measured in minutes.
2. **Dynamic credentials**: a secrets manager such as HashiCorp Vault's database secrets engine creates a short-lived user per lease. ROUA's generated SQL can serve as the creation statements, and the audit can check the users it issues.
3. **Key pairs** where the engine supports them (Snowflake), held in a secrets manager.
4. **Static passwords**, generated, stored only as verifiers in scripts, rotated (§7), and handed over once through a password manager.

## 17. Data egress (informative)

Read-only access prevents change, not disclosure: anything the account can read, its holder can copy. ROUA's controls for disclosure are the scope, exclusions, secret detection and, on PostgreSQL, masking (L4). For AI agents with broad read access, an **egress-aware proxy** between the agent and the database can add per-query row caps, per-day row or byte budgets, query logging tied to the agent's identity, and a kill switch. [RFC 0003](rfcs/0003-egress-gateway.md) proposes how a ROUA tool would describe and audit such a gateway.

## Acknowledgements

The term "ROUA" and the original concept were created by Promise Okoroji. Thanks to everyone who reviews and challenges this draft.

## 18. Scope resolution and schema changes

Real schemas differ from what a definition expects, and they change after setup. A conformant tool handles both explicitly:

| Situation | Requirement |
|---|---|
| Scope resolved when setup runs | Tools **MUST** compute grants from the database's catalog at setup time, not from a list baked in when the script was generated. |
| The scope matches nothing | Setup **MUST** fail with a clear message when an account above L0 would be able to read nothing. Where setup is transactional it **MUST** change nothing. |
| Listed objects, schemas or hidden columns that do not exist | Tools **MUST** report them (a misspelled hidden column is a column that is *not* hidden), and **SHOULD** continue with the names that do exist. |
| Tables created after setup | **MUST NOT** become readable until setup runs again (§10: no default or future grants). |
| Columns added after setup | **SHOULD NOT** become readable: tools **SHOULD** grant per column by default (`scope.column_grants: always`), so a new column, possibly a secret, stays hidden until setup runs again. Engines without column read grants (Oracle, Snowflake, BigQuery, MongoDB) cannot do this; the audit (X1, and X2 if enabled) detects secret-looking columns that became readable, and tools **SHOULD** recommend a scheduled re-audit there. |
| Tables or columns dropped after setup | Grants disappear with them; nothing to do. |
| Preview | Tools **SHOULD** let users resolve a scope against a schema snapshot before anything runs (names and types only, never rows), and **SHOULD** ship a read-only discovery script for each engine to produce that snapshot. |
