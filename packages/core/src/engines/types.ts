/**
 * Multi-engine ROUA generator: shared types and engine catalogue.
 *
 * PostgreSQL has the full toolkit (planner, audit, verify, CLI). The engines
 * here produce setup, audit and revoke scripts that follow the same rules:
 * no write path, secrets hidden where the engine allows it, an owner, an
 * expiry, and instant revocation. Support levels say how much is proven:
 *
 *   tested  - every release runs the generated scripts against the real
 *             engine in CI, logs in as the account and proves writes fail.
 *   preview - generated from the vendor's documentation; not yet run against
 *             a live service. Review before use, and report problems.
 */
import type { Profile } from "../constants.js";

export const ENGINES = [
  "postgresql",
  "mysql",
  "mariadb",
  "sqlserver",
  "oracle",
  "mongodb",
  "redis",
  "snowflake",
  "bigquery",
] as const;
export type Engine = (typeof ENGINES)[number];
export type OtherEngine = Exclude<Engine, "postgresql">;

export type Support = "full" | "tested" | "preview";

/**
 * What the account may read.
 *   metadata - structure only (L0): names, columns and types, no rows
 *   listed   - only the objects you list (L1)
 *   scope    - everything in scope minus exclusions and secrets (L2)
 */
export type ReadMode = "scope" | "listed" | "metadata";

export interface AccountSpec {
  engine: OtherEngine;
  /** Account (user/login/role) name: lowercase, 3-63 chars. */
  name: string;
  profile: Profile;
  owner: string;
  purpose: string;
  approvedBy?: string[];
  approvalRef?: string;
  /** ISO 8601 UTC. */
  expiresAt: string;
  /** scope: everything in `schemas` minus exclusions and secrets. listed: only `objects`. */
  mode: ReadMode;
  /**
   * The container. MySQL/MariaDB: unused (use schemas). SQL Server: database.
   * MongoDB: database. Snowflake: database. BigQuery: project id.
   */
  database?: string;
  /**
   * MySQL/MariaDB: databases. SQL Server: schemas. Oracle: schema owners.
   * Snowflake: schemas. BigQuery: datasets. Unused for MongoDB and Redis.
   */
  schemas?: string[];
  /** listed mode: schema.table (MongoDB: collection names; Redis: key patterns). */
  objects?: string[];
  /** scope mode: schema.table patterns to leave out (* allowed). MongoDB: collections. */
  exclude?: string[];
  /** schema.table.column to hide in addition to detected secrets. */
  columnsDeny?: string[];
  /** Columns the secret detector flags by mistake. */
  columnsAllow?: string[];
  /**
   * "always" (default): every read grant names its columns, so a column added
   * to the table later stays hidden until setup runs again. "when_needed":
   * whole-table grants where nothing is hidden (simpler, but new columns become
   * readable). Engines without column grants (Oracle, Snowflake, BigQuery,
   * MongoDB, Redis) ignore it.
   */
  columnGrants?: "always" | "when_needed";
  /** Plaintext password; engines that accept a verifier get only the verifier. */
  password?: string;
  maxConnections?: number;
  statementTimeoutS?: number;
  /** MySQL/MariaDB host pattern(s); MongoDB clientSource CIDRs; Snowflake network policy CIDRs. */
  allowedSources?: string[];
  requireTls?: boolean;
  /** SQL Server: create a contained database user (Azure SQL Database) instead of a login. */
  contained?: boolean;
  /** Snowflake: warehouse the account may use. */
  warehouse?: string;
  /** Snowflake: RSA public key (base64 body or PEM) for key-pair authentication. */
  publicKey?: string;
  /** BigQuery: dataset location for INFORMATION_SCHEMA, e.g. US or EU. */
  location?: string;
  /** Redis: version 7+ (enables %R~ read-only key permissions and ACL DRYRUN). */
  redis7?: boolean;
}

export interface ScriptFile {
  name: string;
  /** How to run it, one line. */
  run: string;
  content: string;
}

export interface EnginePlan {
  engine: OtherEngine;
  files: ScriptFile[];
  warnings: string[];
  /** Things the tool cannot do for you. */
  manualSteps: string[];
}

export interface EngineInfo {
  id: Engine;
  name: string;
  /** Short, for buttons. */
  short: string;
  versions: string;
  support: Support;
  /** One line on how ROUA maps to the engine. */
  summary: string;
  /** Also covers. */
  covers: string;
  /** Labels for the generic fields, or null when a field does not apply. */
  fields: {
    database: string | null;
    schemas: string | null;
    objects: string;
    exclude: string | null;
    columns: boolean;
    password: "verifier" | "plaintext" | "keypair" | "none";
    maxConnections: boolean;
    statementTimeout: boolean;
    allowedSources: string | null;
    requireTls: boolean;
    /** How structure-only (L0) access works, or why it is not offered. */
    metadata: { how: string } | { unavailable: string };
  };
}

export const ENGINE_INFO: Record<Engine, EngineInfo> = {
  postgresql: {
    id: "postgresql",
    name: "PostgreSQL",
    short: "PostgreSQL",
    versions: "13 to 17",
    support: "full",
    summary: "Full ROUA: levels L0 to L5 with masking, CLI apply, audit and live verify.",
    covers: "Amazon RDS and Aurora, Google Cloud SQL and AlloyDB, Azure Database, Supabase, Neon, Crunchy, Timescale",
    fields: {
      database: "Database",
      schemas: "Schemas",
      objects: "Tables",
      exclude: "Exclude tables",
      columns: true,
      password: "verifier",
      maxConnections: true,
      statementTimeout: true,
      allowedSources: "Allowed source IPs",
      requireTls: false,
      metadata: { how: "Level L0: USAGE on schemas, no SELECT." },
    },
  },
  mysql: {
    id: "mysql",
    name: "MySQL",
    short: "MySQL",
    versions: "8.0, 8.4, 9",
    support: "tested",
    summary: "Per-table and per-column SELECT computed at setup, caching_sha2 verifier, locked by a scheduled event at expiry.",
    covers: "Amazon RDS and Aurora MySQL, Google Cloud SQL, Azure Database for MySQL, Percona Server",
    fields: {
      database: null,
      schemas: "Databases",
      objects: "Tables",
      exclude: "Exclude tables",
      columns: true,
      password: "verifier",
      maxConnections: true,
      statementTimeout: true,
      allowedSources: "Allowed hosts",
      requireTls: true,
      metadata: { unavailable: "MySQL shows a table's structure only to accounts holding a privilege on it, and every such privilege except SHOW VIEW reads or writes data." },
    },
  },
  mariadb: {
    id: "mariadb",
    name: "MariaDB",
    short: "MariaDB",
    versions: "10.6, 10.11, 11.4",
    support: "tested",
    summary: "Per-table and per-column SELECT computed at setup, password hash only, locked by a scheduled event at expiry.",
    covers: "Amazon RDS for MariaDB, SkySQL",
    fields: {
      database: null,
      schemas: "Databases",
      objects: "Tables",
      exclude: "Exclude tables",
      columns: true,
      password: "verifier",
      maxConnections: true,
      statementTimeout: true,
      allowedSources: "Allowed hosts",
      requireTls: true,
      metadata: { unavailable: "MariaDB shows a table's structure only to accounts holding a privilege on it, and every such privilege except SHOW VIEW reads or writes data." },
    },
  },
  sqlserver: {
    id: "sqlserver",
    name: "SQL Server",
    short: "SQL Server",
    versions: "2022 (tested), 2017+, Azure SQL",
    support: "tested",
    summary: "Login with a hashed password, per-object SELECT, column DENY for secrets, database-wide DENY on every write.",
    covers: "Azure SQL Database and Managed Instance, Amazon RDS for SQL Server",
    fields: {
      database: "Database",
      schemas: "Schemas",
      objects: "Tables",
      exclude: "Exclude tables",
      columns: true,
      password: "verifier",
      maxConnections: false,
      statementTimeout: false,
      allowedSources: null,
      requireTls: false,
      metadata: { how: "VIEW DEFINITION on the schemas and no SELECT anywhere: the catalog is visible, rows are not." },
    },
  },
  oracle: {
    id: "oracle",
    name: "Oracle Database",
    short: "Oracle",
    versions: "23ai (tested), 19c",
    support: "tested",
    summary: "READ (not SELECT, so no row locks) per table, a dedicated profile, and a scheduler job that locks the account at expiry.",
    covers: "Oracle Autonomous Database, Amazon RDS for Oracle, Exadata",
    fields: {
      database: null,
      schemas: "Schemas (owners)",
      objects: "Tables",
      exclude: "Exclude tables",
      columns: true,
      password: "plaintext",
      maxConnections: true,
      statementTimeout: true,
      allowedSources: null,
      requireTls: false,
      metadata: { unavailable: "Oracle has no per-table privilege that shows structure without READ, and SELECT_CATALOG_ROLE exposes the whole data dictionary." },
    },
  },
  mongodb: {
    id: "mongodb",
    name: "MongoDB",
    short: "MongoDB",
    versions: "6.0, 7.0, 8.0",
    support: "tested",
    summary: "A custom role with find on chosen collections only (no readAnyDatabase), SCRAM-SHA-256 and optional client IP restriction.",
    covers: "MongoDB Atlas (use the Atlas notes), Percona Server for MongoDB",
    fields: {
      database: "Database",
      schemas: null,
      objects: "Collections",
      exclude: "Exclude collections",
      columns: false,
      password: "plaintext",
      maxConnections: false,
      statementTimeout: false,
      allowedSources: "Allowed client IPs",
      requireTls: false,
      metadata: { how: "listCollections and listIndexes without find: collection names and indexes, no documents." },
    },
  },
  redis: {
    id: "redis",
    name: "Redis",
    short: "Redis / Valkey",
    versions: "7.2, 7.4, Valkey 8",
    support: "tested",
    summary: "An ACL user limited to read commands on your key patterns, no dangerous or admin commands, no pub/sub, hashed password.",
    covers: "Valkey, Amazon ElastiCache and MemoryDB (RBAC), Azure Cache for Redis, Redis Cloud",
    fields: {
      database: null,
      schemas: null,
      objects: "Key patterns",
      exclude: null,
      columns: false,
      password: "verifier",
      maxConnections: false,
      statementTimeout: false,
      allowedSources: null,
      requireTls: false,
      metadata: { unavailable: "Redis has no schema to expose." },
    },
  },
  snowflake: {
    id: "snowflake",
    name: "Snowflake",
    short: "Snowflake",
    versions: "current",
    support: "preview",
    summary: "A dedicated role with point-in-time SELECT (no future grants), key-pair login, no secondary roles, and DAYS_TO_EXPIRY.",
    covers: "",
    fields: {
      database: "Database",
      schemas: "Schemas",
      objects: "Tables",
      exclude: "Exclude tables",
      columns: true,
      password: "keypair",
      maxConnections: false,
      statementTimeout: true,
      allowedSources: "Allowed source IPs",
      requireTls: false,
      metadata: { how: "REFERENCES on each table: structure is visible, SELECT is not granted." },
    },
  },
  bigquery: {
    id: "bigquery",
    name: "Google BigQuery",
    short: "BigQuery",
    versions: "current",
    support: "preview",
    summary: "A service account with table-level Data Viewer, and query rights that expire through an IAM condition.",
    covers: "",
    fields: {
      database: "Project ID",
      schemas: "Datasets",
      objects: "Tables",
      exclude: "Exclude tables",
      columns: true,
      password: "none",
      maxConnections: false,
      statementTimeout: false,
      allowedSources: null,
      requireTls: false,
      metadata: { how: "roles/bigquery.metadataViewer on each dataset: schemas and table metadata, no rows." },
    },
  },
};
