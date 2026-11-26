/**
 * Read-only discovery scripts: one per engine, each printing the database's
 * schemas, tables and columns as a JSON array that `parseSchemaSnapshot` reads.
 * They return names and types only, never rows. Run them as any account that
 * can see the catalog (usually the administrator who will run setup).
 */
import type { Engine } from "../engines/types.js";

export interface DiscoveryScript {
  name: string;
  run: string;
  content: string;
}

const ident = /^[A-Za-z_][A-Za-z0-9_$-]{0,62}$/;
const safe = (v: string | undefined, fallback: string) => (v && ident.test(v) ? v : fallback);

const HEADER = (engine: string, comment = "--") =>
  `${comment} discover: list ${engine} schemas, tables and columns as JSON for the ROUA generator.\n` +
  `${comment} Read-only: names and types only, never rows. Paste the output into kaizam.com (Load your schema),\n` +
  `${comment} or pass it to roua / the MCP preview_scope tool.\n`;

/** The discovery script for an engine, or null where there is no schema (Redis). */
export function discoveryScript(engine: Engine, opts: { database?: string; datasets?: string[]; project?: string } = {}): DiscoveryScript | null {
  switch (engine) {
    case "postgresql":
      return {
        name: "discover.sql",
        run: `psql "$ADMIN_DATABASE_URL" -qAt -f discover.sql > schema.json`,
        content: `${HEADER("PostgreSQL")}
SELECT coalesce(json_agg(json_build_object(
         'schema', n.nspname, 'table', c.relname, 'column', a.attname,
         'type', format_type(a.atttypid, a.atttypmod),
         'kind', CASE WHEN c.relkind IN ('v', 'm') THEN 'view' ELSE 'table' END)
       ORDER BY n.nspname, c.relname, a.attnum), '[]')
  FROM pg_attribute a
  JOIN pg_class c ON c.oid = a.attrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') AND a.attnum > 0 AND NOT a.attisdropped
   AND n.nspname NOT IN ('pg_catalog', 'information_schema')
   AND n.nspname NOT LIKE 'pg\\_toast%' AND n.nspname NOT LIKE 'pg\\_temp%';
`,
      };
    case "mysql":
    case "mariadb":
      return {
        name: "discover.sql",
        run: `mysql -h HOST -u admin -p --skip-column-names --raw < discover.sql > schema.json`,
        content: `${HEADER(engine === "mysql" ? "MySQL" : "MariaDB")}
SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT(
         'schema', c.TABLE_SCHEMA, 'table', c.TABLE_NAME, 'column', c.COLUMN_NAME,
         'type', c.COLUMN_TYPE, 'kind', IF(t.TABLE_TYPE = 'VIEW', 'view', 'table'))), JSON_ARRAY())
  FROM information_schema.COLUMNS c
  JOIN information_schema.TABLES t ON t.TABLE_SCHEMA = c.TABLE_SCHEMA AND t.TABLE_NAME = c.TABLE_NAME
 WHERE c.TABLE_SCHEMA NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys', 'roua_admin');
`,
      };
    case "sqlserver": {
      const db = safe(opts.database, "appdb");
      return {
        name: "discover.sql",
        run: `sqlcmd -S HOST -U admin -C -d ${db} -h -1 -y 0 -i discover.sql -o schema.json`,
        content: `${HEADER("SQL Server")}SET NOCOUNT ON;
SELECT s.name AS [schema], o.name AS [table], c.name AS [column], ty.name AS [type],
       CASE o.type WHEN 'V' THEN 'view' ELSE 'table' END AS [kind]
  FROM sys.columns c
  JOIN sys.objects o ON o.object_id = c.object_id
  JOIN sys.schemas s ON s.schema_id = o.schema_id
  JOIN sys.types ty ON ty.user_type_id = c.user_type_id
 WHERE o.type IN ('U', 'V') AND o.is_ms_shipped = 0
 ORDER BY s.name, o.name, c.column_id
 FOR JSON PATH;
`,
      };
    }
    case "oracle":
      return {
        name: "discover.sql",
        run: `sqlplus -s admin@//HOST:1521/SERVICE @discover.sql > schema.json`,
        content: `${HEADER("Oracle")}SET LONG 1000000000 LONGCHUNKSIZE 32767 LINESIZE 32767 PAGESIZE 0 TRIMSPOOL ON HEADING OFF FEEDBACK OFF VERIFY OFF
SELECT JSON_ARRAYAGG(JSON_OBJECT(
         'schema' VALUE c.owner, 'table' VALUE c.table_name, 'column' VALUE c.column_name,
         'type' VALUE c.data_type, 'kind' VALUE CASE WHEN v.view_name IS NOT NULL THEN 'view' ELSE 'table' END)
       ORDER BY c.owner, c.table_name, c.column_id RETURNING CLOB)
  FROM dba_tab_columns c
  JOIN dba_users u ON u.username = c.owner AND u.oracle_maintained = 'N'
  LEFT JOIN dba_views v ON v.owner = c.owner AND v.view_name = c.table_name
 WHERE c.table_name NOT LIKE 'BIN$%';
EXIT
`,
      };
    case "mongodb": {
      const db = safe(opts.database, "appdb");
      return {
        name: "discover.js",
        run: `mongosh "mongodb://admin@HOST/admin" --quiet --file discover.js > schema.json`,
        content: `${HEADER("MongoDB", "//")}// MongoDB has no fixed schema: field names are taken from up to 50 sampled documents per collection.
const dbName = ${JSON.stringify(db)};
const target = db.getSiblingDB(dbName);
const out = [];
const walk = (doc, prefix, fields) => {
  for (const [k, v] of Object.entries(doc)) {
    const name = prefix ? prefix + "." + k : k;
    fields.add(name);
    if (v && typeof v === "object" && !Array.isArray(v) && !(v instanceof Date) && prefix.split(".").length < 2 && v.constructor === Object) walk(v, name, fields);
  }
};
for (const coll of target.getCollectionNames().filter((n) => !n.startsWith("system.")).sort()) {
  const fields = new Set();
  target.getCollection(coll).aggregate([{ $sample: { size: 50 } }]).forEach((d) => walk(d, "", fields));
  if (!fields.size) fields.add("_id");
  for (const f of [...fields].sort()) out.push({ schema: dbName, table: coll, column: f });
}
print(JSON.stringify(out));
`,
      };
    }
    case "snowflake": {
      const db = safe(opts.database, "ANALYTICS").toUpperCase();
      return {
        name: "discover.sql",
        run: `snowsql -a ACCOUNT -u admin -o output_format=plain -o header=false -o friendly=false -f discover.sql > schema.json`,
        content: `${HEADER("Snowflake")}
SELECT ARRAY_AGG(OBJECT_CONSTRUCT('schema', c.table_schema, 'table', c.table_name, 'column', c.column_name,
         'type', c.data_type, 'kind', IFF(t.table_type = 'VIEW', 'view', 'table')))
  FROM ${db}.INFORMATION_SCHEMA.COLUMNS c
  JOIN ${db}.INFORMATION_SCHEMA.TABLES t ON t.table_schema = c.table_schema AND t.table_name = c.table_name
 WHERE c.table_schema <> 'INFORMATION_SCHEMA';
`,
      };
    }
    case "bigquery": {
      const project = opts.project && /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(opts.project) ? opts.project : "my-project-id";
      const datasets = (opts.datasets ?? []).filter((d) => /^[A-Za-z0-9_]{1,1024}$/.test(d));
      const list = datasets.length ? datasets : ["analytics"];
      return {
        name: "discover.sql",
        run: `bq query --project_id ${project} --use_legacy_sql=false --format=json < discover.sql > schema.json`,
        content: `${HEADER("BigQuery")}
${list.map((d) => `SELECT table_schema AS schema, table_name AS \`table\`, column_name AS \`column\`, data_type AS type FROM \`${project}.${d}.INFORMATION_SCHEMA.COLUMNS\``).join("\nUNION ALL\n")};
`,
      };
    }
    case "redis":
      return null;
  }
}
