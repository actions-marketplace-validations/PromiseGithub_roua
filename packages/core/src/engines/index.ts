import { RouaInputError } from "../escape.js";
import { discoveryScript } from "../schema/discovery.js";
import { auditBigQuery, bqServiceAccountId, planBigQuery } from "./bigquery.js";
import { validateSpec } from "./common.js";
import { auditMongo, planMongo } from "./mongodb.js";
import { auditMySql, planMySql } from "./mysql.js";
import { auditOracle, planOracle } from "./oracle.js";
import { auditRedis, planRedis } from "./redis.js";
import { auditSnowflake, planSnowflake } from "./snowflake.js";
import { auditSqlServer, planSqlServer } from "./sqlserver.js";
import type { AccountSpec, EnginePlan, OtherEngine } from "./types.js";

export * from "./types.js";
export { validateSpec, engineMetadata, patternRegex, isSecretByLists, SECRET_TOKENS, SECRET_SUBSTRINGS, normalizePublicKey } from "./common.js";
export { mysqlCachingSha2Hash, mysqlNativeHash, sqlServerPasswordHash, redisPasswordHash, sha256Crypt, sha1, sha512 } from "../hashes.js";
export { redisAclRules } from "./redis.js";
export { bqServiceAccountId } from "./bigquery.js";

/** Validate and plan. Throws RouaInputError listing every problem. */
export function planEngine(spec: AccountSpec, now: Date = new Date()): EnginePlan & { validationWarnings: string[] } {
  const v = validateSpec(spec, now);
  if (v.errors.length) throw new RouaInputError(v.errors.join("\n"));
  const plan = PLANNERS[spec.engine](spec, now);
  // Ship the read-only discovery script too, so the scope can be checked against the real schema.
  const discover = discoveryScript(spec.engine, { database: spec.database, datasets: spec.schemas, project: spec.database });
  if (discover) plan.files.push(discover);
  return { ...plan, validationWarnings: v.warnings };
}

const PLANNERS: Record<OtherEngine, (s: AccountSpec, now: Date) => EnginePlan> = {
  mysql: planMySql,
  mariadb: planMySql,
  sqlserver: planSqlServer,
  oracle: planOracle,
  mongodb: planMongo,
  redis: planRedis,
  snowflake: planSnowflake,
  bigquery: planBigQuery,
};

export interface AuditTarget {
  engine: OtherEngine;
  /** Account, login, user or service-account id. */
  name: string;
  /** MySQL/MariaDB host (default %). */
  host?: string;
  /** SQL Server database; BigQuery project. */
  database?: string;
  /** Snowflake role to inspect (default NAME_READ). */
  role?: string;
  /** BigQuery location (default US). */
  location?: string;
  /** SQL Server contained user. */
  contained?: boolean;
}

const NAME_RE = /^[A-Za-z_][A-Za-z0-9_$-]{0,62}$/;

/** An audit script for an existing account, whether or not ROUA created it. */
export function auditScript(t: AuditTarget, now: Date = new Date()): { name: string; run: string; content: string } {
  if (!NAME_RE.test(t.name)) throw new RouaInputError("Account name: letters, digits, _, $ or -.");
  const host = t.host?.trim() || "%";
  if (!/^[A-Za-z0-9.%_:\-]{1,255}$/.test(host)) throw new RouaInputError("Host: letters, digits and . % _ : - only.");
  const db = t.database?.trim() ?? "";
  if (db && !/^[A-Za-z0-9_$-]{1,128}$/.test(db)) throw new RouaInputError("Database/project: letters, digits, _, $ or -.");
  switch (t.engine) {
    case "mysql":
    case "mariadb":
      return { name: "audit.sql", run: "mysql -h HOST -u admin -p --table < audit.sql", content: auditMySql(t.name, host, t.engine === "mariadb", now) };
    case "sqlserver":
      if (!db) throw new RouaInputError("Database is required.");
      return { name: "audit.sql", run: "sqlcmd -S HOST -U admin -C -i audit.sql", content: auditSqlServer(t.name, db, !!t.contained, now) };
    case "oracle":
      return { name: "audit.sql", run: "sqlplus admin@//HOST:1521/SERVICE @audit.sql", content: auditOracle(t.name, now) };
    case "mongodb":
      return { name: "audit.js", run: `mongosh "mongodb://admin@HOST/admin" --file audit.js`, content: auditMongo(t.name, now, db || "admin") };
    case "redis":
      return { name: "audit.sh", run: "REDISCLI_AUTH=... REDIS_CLI='redis-cli -h HOST --user admin' sh audit.sh", content: auditRedis(t.name, now) };
    case "snowflake": {
      const role = t.role?.trim() || `${t.name}_read`;
      if (!NAME_RE.test(role)) throw new RouaInputError("Role: letters, digits, _ or $.");
      return { name: "audit.sql", run: "snowsql -a ACCOUNT -u admin -r SECURITYADMIN -f audit.sql", content: auditSnowflake(t.name, role, now) };
    }
    case "bigquery": {
      if (!/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(db)) throw new RouaInputError("Project ID is required.");
      const email = t.name.includes("@") ? t.name : `${bqServiceAccountId(t.name)}@${db}.iam.gserviceaccount.com`;
      return { name: "audit.sh", run: "bash audit.sh", content: auditBigQuery(email, db, t.location || "US", now) };
    }
  }
}
