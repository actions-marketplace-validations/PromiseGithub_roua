# Changelog

Notable changes to the ROUA specification and tools. The project uses semantic versioning. Before 1.0, minor versions may contain breaking changes.

## 0.5.0 (2026-11-26)

**Handling real schemas (SPEC §18)**
- **Preview before you generate.** Each engine has a read-only discovery script (`discover.sql` / `discover.js`, included with every set of scripts) that lists schemas, tables and columns, never rows. kaizam.com, `roua plan --check` and the MCP `preview_scope` tool resolve the scope against that snapshot. They show which tables become readable and which columns stay hidden and why, and they flag missing schemas, misspelled listed tables, hidden-column entries that match no column, and scopes that would read nothing.
- **Setup refuses an empty scope** on every engine instead of creating an account that reads nothing. On PostgreSQL nothing is changed.
- **Typos are reported by setup itself:** listed tables, schemas and hidden columns that do not exist.
- **Per-column grants by default** (`column_grants: always`) on PostgreSQL, MySQL, MariaDB and SQL Server. A column added later, possibly a secret one, stays hidden until setup runs again. Set `when_needed` for whole-table grants.
- **kaizam.com: "Your schema".** Paste the discovery output (JSON, CSV or psql table), pick tables from a list with secret-looking columns flagged, and see a live preview. Generation is blocked when the preview finds a missing schema or an empty scope.
- **CLI:** `roua discover` saves the schema; `roua plan --check [--schema file]` previews the scope. **MCP:** `preview_scope` and `discover_postgres_schema` tools.
- Live CI checks on MySQL, MariaDB, SQL Server, Oracle and MongoDB that empty scopes are refused, typos are reported, and (where the engine has column grants) columns added after setup stay hidden.

## 0.4.0 (2026-11-25)

**Tools**
- Structure-only access (L0) on SQL Server, MongoDB, Snowflake and BigQuery, live-tested on SQL Server and MongoDB. Engines that cannot enforce it (MySQL, MariaDB, Oracle, Redis) say why.
- PostgreSQL audit: resource-governance checks G1 to G4; C1 now covers the read-only default and audit logging only.
- `roua audit --sample-values N` (opt-in X2): samples readable text columns for secret formats such as private keys, tokens, API keys and password hashes. It reports columns only, never values.
- `roua audit --sarif-out FILE --junit-out FILE`, with matching inputs in the GitHub Action.
- `roua rotate <account>`: new password, same grants, rotation date recorded in the metadata.
- MongoDB and Redis scripts include ready-made schedules for the revoke (cron, systemd, Kubernetes, GitHub Actions, Windows).
- Release workflow attaches a CycloneDX SBOM to each GitHub release.

**Specification (0.1 draft, clarifications and informative sections)**
- §7: rotation and drop requirements. §8: G1 to G4, optional X2, reserved V2 to V4 and V6, check-letter mapping for other engines. §10.1: informative engine profiles. §14 to §17: resource governance, query logging, credential classes, data egress. §13: 1.0 criteria.
- Open RFCs 0001 to 0005 and a discovery-manifest schema.

**kaizam.com**
- Support, profile and level tables are in the HTML (crawlable, no JavaScript needed), with a Levels column.
- New pages: ROUA vs built-in read roles, and the threat model. Footer link to the page checksums.

## 0.3.0 (2026-11-24)

- **kaizam.com is now a site:** a page per database (kaizam.com/mysql/, /sqlserver/, …) explaining the usual way, what it misses and what ROUA does, guides for AI agents and app-review accounts, plus sitemap.xml, robots.txt, canonical URLs, structured data and a 404 page. Every page is still one offline file with no network requests.
- **GitHub Action:** `uses: PromiseGithub/roua@v0.3.0` audits PostgreSQL roles in CI, writes a job summary and annotations, and fails the build when an account is not read-only.
- **MCP server:** `roua mcp` (`npx -y @roua-dev/cli mcp`) gives AI agents tools to list engines, write audit scripts, generate ROUA scripts to a folder (secrets never enter the conversation) and audit a PostgreSQL role live. No new dependencies. Listed in the MCP Registry as io.github.PromiseGithub/roua.
- **Docker image:** `ghcr.io/promisegithub/roua`, built from source with provenance and an SBOM.

## 0.2.0 (2026-11-24)

- New engines in `@roua-dev/core` and the web generator: MySQL, MariaDB, SQL Server and Azure SQL, Oracle, MongoDB and Redis/Valkey (tested in CI against real servers), plus Snowflake and BigQuery (preview). Each produces setup, audit, revoke and drop scripts.
- `auditScript()` and the web page's "Check an account you already have" write an audit for any existing account on any engine.
- Password verifiers instead of plaintext where engines accept them: MySQL caching_sha2_password, MariaDB native hash, SQL Server hashed logins, Redis SHA-256.
- kaizam.com redesigned: one offline page for every engine, an account checker, guidance for AI agents and an FAQ.

## 0.1.1 (2026-11-24)

No changes to the specification or to tool behaviour.

- Packages are now published from GitHub Actions with npm Trusted Publishing (OIDC). No npm token is stored in the repository, and every release carries provenance.
- The web generator is hosted at https://kaizam.com.

## 0.1.0 (2026-11-24)

First public draft.

**Specification**
- ROUA-DB 0.1: definition, profiles, levels L0 to L5, secret handling, metadata string, lifecycle, and verification checks (R1–R5, T1–T3, S1, D1, Q1, F1, F2, X1, N1, N2, C1, M1, P1–P3, V1, V5, V7).
- ROUA-App 0.1 companion draft: `read_only` and `sandbox` modes for application accounts.
- Approval is a SHOULD, because tools cannot validate it. L5 is the exception.
- The secret detector is defined as best effort; the user's deny-list is the authoritative control.
- L3 and L4 views must use `security_barrier`, and the `hash` mask must use a key the ROUA cannot read.
- New tables never become readable automatically.

**Tools**
- `@roua-dev/core`: PostgreSQL planner, auditor and verifier, plus SCRAM-SHA-256 verifiers. Zero runtime dependencies.
- `@roua-dev/cli`: `audit`, `verify`, `init`, `plan`, `apply`, `revoke`, `list`, `expire`.
- `@roua-dev/app`: request policy with Express, Fastify and Fetch API adapters.
- Offline single-file web generator.
