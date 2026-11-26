# Roadmap

ROUA grows by being useful, not by covering everything at once. An engine is added only when it has a tested reference implementation and integration tests on real servers that prove writes fail.

## 0.1 (this release, draft)

- [x] Spec 0.1 draft: definition, profiles, levels L0 to L5, secrets, metadata, lifecycle, verification checks
- [x] PostgreSQL 13+: `audit`, `verify`, `plan`, `apply`, `revoke`, `list`, `expire`, `init`
- [x] Offline single-file web generator
- [x] ROUA-App companion draft and `@roua-dev/app` (Express, Fastify, Fetch API)
- [x] End-to-end tests on PGlite; CI on PostgreSQL 13 to 17

## 0.2

- [x] Generators for MySQL, MariaDB, SQL Server and Azure SQL, Oracle, MongoDB and Redis/Valkey, tested in CI against real servers on every change
- [x] Preview generators for Snowflake and BigQuery
- [x] "Check an account you already have" audits for every engine
- [x] kaizam.com: one offline page for every engine

## 0.3

- [x] GitHub Action, MCP server (`roua mcp`), Docker image, MCP Registry listing
- [x] A kaizam.com page per database, guides, sitemap and structured data

## 0.4 (in progress)

- [x] Structure-only access (L0) on SQL Server, MongoDB, Snowflake and BigQuery
- [x] Resource-governance checks G1 to G4 (time, idle-transaction, lock and temp-file limits)
- [x] `roua rotate`; rotation and drop specified (SPEC §7)
- [x] SARIF and JUnit audit output, also in the GitHub Action
- [x] Opt-in value sampling for secrets in badly named columns (X2)
- [x] Expiry schedule templates for MongoDB and Redis (cron, systemd, Kubernetes, GitHub Actions, Windows)
- [x] Informative engine profiles in the spec (§10.1); resource governance, query logging, credential classes and data egress sections (§14 to §17)
- [x] Static, crawlable support and level tables; comparison and threat-model pages
- [x] Open RFCs 0001 to 0005 (discovery manifest, approval records, egress gateway, logging and credentials, normative engine profiles)

## Next

- [ ] Outside review: at least two database or security reviewers try to break the audits
- [ ] Accept or withdraw RFCs 0001 to 0005 after their comment period
- [ ] L3 and L4 beyond PostgreSQL: MySQL/MariaDB definer views, SQL Server Dynamic Data Masking or views, Oracle views or Data Redaction, Snowflake masking policies and secure views, BigQuery authorized views and policy tags, MongoDB views
- [ ] Snowflake and BigQuery out of preview, with a scheduled CI job against trial accounts
- [ ] Live audit (`roua audit`) for engines beyond PostgreSQL, in the CLI, the Action and the MCP server
- [ ] Fleet use: `roua inventory` across many targets, drift detection, scheduled audits with webhook notifications
- [ ] Secrets-manager integrations: HashiCorp Vault database roles that issue ROUA-conformant users; AWS, Azure and GCP rotation hooks
- [ ] Terraform and Pulumi modules, so ROUA accounts live in infrastructure code
- [ ] `roua evidence`: approvals, audit reports, rotations and revoke proof as one bundle, mapped to common control frameworks
- [ ] ROUA-App adapters: Next.js, Django, Rails, Laravel, Spring Boot, ASP.NET Core, Go
- [ ] A conformance kit and a public list of conformant tools
- [ ] `pg_cron` option for engine-side expiry on PostgreSQL
- [ ] Translations of the generator (French, Spanish, Portuguese)

## Later (each needs its own tests on real servers)

- New engines: ClickHouse, Elasticsearch and OpenSearch, DynamoDB, Cassandra, CockroachDB and YugabyteDB, Databricks Unity Catalog, Redshift, Azure Cosmos DB, Firestore
- ROUA-SaaS: read-only permission sets for common SaaS platforms (CRM, ticketing, source control, office suites, payments), each with scopes, secret exclusions, expiry and audit steps
- ROUA-Cloud IAM: read-only cloud roles minus secret reads (secrets managers, parameter stores, key decryption, sensitive buckets)
- A Kubernetes operator (`ROUAccount` resource)
- A neutral foundation home for the specification after 1.0
