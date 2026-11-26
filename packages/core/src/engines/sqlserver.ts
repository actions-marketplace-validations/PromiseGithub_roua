/**
 * ROUA for Microsoft SQL Server 2017+ and Azure SQL.
 *
 * - A login with a hashed password (0x0200 + SHA-512), or, for Azure SQL
 *   Database, a contained database user.
 * - SELECT per table or view; where a table has hidden columns, SELECT on the
 *   visible columns only. No db_datareader (it covers future tables too).
 * - DENY on every write and DDL permission at database scope, which overrides
 *   any role membership added later.
 * - Expiry: a SQL Server Agent job disables the login and ends its sessions.
 */
import { sqlServerPasswordHash } from "../hashes.js";
import { engineMetadata, header, SECRET_SUBSTRINGS, SECRET_TOKENS } from "./common.js";
import type { AccountSpec, EnginePlan } from "./types.js";

export const msIdent = (s: string) => `[${s.replace(/]/g, "]]")}]`;
export const msLit = (s: string) => `N'${s.replace(/'/g, "''")}'`;
const list = (xs: readonly string[]) => xs.map(msLit).join(", ");

/** schema.table glob to a LIKE pattern: _ and [ are literal, * is %. */
export function likePattern(p: string): string {
  return p.replace(/[_[%]/g, (c) => `[${c}]`).replace(/\*/g, "%");
}

const DENIED = [
  "INSERT", "UPDATE", "DELETE", "EXECUTE", "ALTER", "TAKE OWNERSHIP", "REFERENCES",
  "CREATE TABLE", "CREATE VIEW", "CREATE PROCEDURE", "CREATE FUNCTION", "CREATE SCHEMA",
  "CREATE TYPE", "CREATE SYNONYM", "CREATE DEFAULT", "CREATE RULE",
  "ALTER ANY SCHEMA", "ALTER ANY USER", "ALTER ANY ROLE",
];

/** T-SQL predicate on sys.columns alias c: is it hidden? Uses dbo.roua_tmp_snake. */
function hiddenPredicate(spec: AccountSpec): string {
  const snake = "dbo.roua_tmp_snake(c.name)";
  const tokens = SECRET_TOKENS.map((t) => `N'_' + ${snake} + N'_' LIKE N'%[_]${t}[_]%'`);
  const subs = SECRET_SUBSTRINGS.map((s) => `${snake} LIKE N'%${likePattern(s)}%'`);
  let secret = `(${[...tokens, ...subs].join("\n        OR ")})`;
  const full = "s.name + N'.' + o.name + N'.' + c.name";
  if (spec.columnsAllow?.length) secret = `(${secret} AND ${full} NOT IN (${list(spec.columnsAllow)}))`;
  return spec.columnsDeny?.length ? `(${secret} OR ${full} IN (${list(spec.columnsDeny)}))` : secret;
}

function objectFilter(spec: AccountSpec): string {
  const full = "s.name + N'.' + o.name";
  if (spec.mode === "listed") return `(${(spec.objects ?? []).map((p) => `${full} LIKE ${msLit(likePattern(p))}`).join(" OR ")})`;
  const parts = [`s.name IN (${list(spec.schemas ?? [])})`];
  for (const p of spec.exclude ?? []) parts.push(`${full} NOT LIKE ${msLit(likePattern(p))}`);
  return parts.join(" AND ");
}

/** L0: the catalog of the chosen schemas is visible, no rows are. */
function metadataGrants(spec: AccountSpec, u: string): string {
  return `-- 4. Structure only (L0): VIEW DEFINITION shows tables, columns and types in these
--    schemas. No SELECT is granted on any table or view. (A database-wide DENY SELECT
--    is deliberately not used: it would also hide the catalog views this level exists for.)
${(spec.schemas ?? []).map((s) => `GRANT VIEW DEFINITION ON SCHEMA::${msIdent(s)} TO ${u};`).join("\n")}
PRINT N'ROUA: structure-only access granted on ${(spec.schemas ?? []).length} schema(s).';
GO
`;
}

function killSessions(name: string, contained: boolean): string {
  const col = contained ? "original_login_name" : "login_name";
  return `DECLARE @roua_kill nvarchar(max) = N'';
SELECT @roua_kill += N'KILL ' + CAST(session_id AS nvarchar(10)) + N';'
  FROM sys.dm_exec_sessions WHERE ${col} = ${msLit(name)} AND session_id <> @@SPID;
EXEC sys.sp_executesql @roua_kill;`;
}

/** Names that match nothing are printed, not silently ignored. */
function mismatchReport(spec: AccountSpec): string {
  const lines: string[] = [];
  const full = "s.name + N'.' + o.name";
  if (spec.mode === "listed") {
    for (const p of spec.objects ?? []) {
      lines.push(`IF NOT EXISTS (SELECT 1 FROM sys.objects o JOIN sys.schemas s ON s.schema_id = o.schema_id WHERE o.type IN ('U', 'V') AND ${full} LIKE ${msLit(likePattern(p))}) PRINT N'ROUA WARNING: listed table ${p.replace(/'/g, "''")} matches nothing: check the spelling.';`);
    }
  } else {
    for (const s of spec.schemas ?? []) {
      lines.push(`IF SCHEMA_ID(${msLit(s)}) IS NULL PRINT N'ROUA WARNING: schema ${s.replace(/'/g, "''")} does not exist in this database.';`);
    }
  }
  for (const d of spec.columnsDeny ?? []) {
    lines.push(`IF NOT EXISTS (SELECT 1 FROM sys.columns c JOIN sys.objects o ON o.object_id = c.object_id JOIN sys.schemas s ON s.schema_id = o.schema_id WHERE ${full} + N'.' + c.name = ${msLit(d)}) PRINT N'ROUA WARNING: hidden column ${d.replace(/'/g, "''")} does not exist (if it is spelled differently, it is NOT hidden).';`);
  }
  return lines.length ? `-- Report names that match nothing.\n${lines.join("\n")}\n` : "";
}

export function planSqlServer(spec: AccountSpec, now: Date): EnginePlan {
  const perColumn = (spec.columnGrants ?? "always") === "always";
  const contained = !!spec.contained;
  const name = spec.name;
  const u = msIdent(name);
  const db = spec.database!;
  const meta = engineMetadata(spec, now);
  const warnings: string[] = [];
  const manualSteps: string[] = [];
  const pw = spec.password ?? "";
  const useDb = contained ? "" : `USE ${msIdent(db)};\nGO\n`;
  const jobName = `roua_expire_${name}`;
  const expires = new Date(spec.expiresAt).toISOString().slice(0, 19);

  const login = contained
    ? `-- Azure SQL Database: a contained user (run this connected to the ${db} database).
-- Contained users need a plaintext password here. Delete this file after running it.
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = ${msLit(name)})
  CREATE USER ${u} WITH PASSWORD = ${msLit(pw)};
ELSE
  ALTER USER ${u} WITH PASSWORD = ${msLit(pw)};
GRANT CONNECT TO ${u};
GO`
    : `USE [master];
GO
-- 1. The login. Only a password hash is stored here, never the password.
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = ${msLit(name)})
  CREATE LOGIN ${u} WITH PASSWORD = ${sqlServerPasswordHash(pw)} HASHED,
    CHECK_POLICY = OFF, CHECK_EXPIRATION = OFF, DEFAULT_DATABASE = ${msIdent(db)};
ELSE
  ALTER LOGIN ${u} WITH PASSWORD = ${sqlServerPasswordHash(pw)} HASHED;
ALTER LOGIN ${u} ENABLE;
GO
-- No server roles and no server permissions beyond connecting.
DECLARE @roua_sql nvarchar(max) = N'';
SELECT @roua_sql += N'ALTER SERVER ROLE ' + QUOTENAME(r.name) + N' DROP MEMBER ${u};'
  FROM sys.server_role_members m
  JOIN sys.server_principals r ON r.principal_id = m.role_principal_id
  JOIN sys.server_principals p ON p.principal_id = m.member_principal_id
 WHERE p.name = ${msLit(name)};
SELECT @roua_sql += CASE WHEN sp.class = 101
    THEN N'REVOKE ' + sp.permission_name + N' ON LOGIN::' + QUOTENAME(SUSER_NAME(sp.major_id)) + N' TO ${u};'
    ELSE N'REVOKE ' + sp.permission_name + N' TO ${u};' END
  FROM sys.server_permissions sp
 WHERE sp.grantee_principal_id = SUSER_ID(${msLit(name)}) AND sp.permission_name <> 'CONNECT SQL' AND sp.class IN (100, 101);
EXEC sys.sp_executesql @roua_sql;
GO
${useDb}IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = ${msLit(name)})
  CREATE USER ${u} FOR LOGIN ${u};
GO`;

  const setup = `${header("setup.sql: create or update the ROUA account. Run as an administrator:", spec, now)}-- sqlcmd -S HOST -U admin -C -b -i setup.sql${contained ? ` -d ${db}` : ""}
-- Safe to run again: it resets the account's permissions and grants them afresh.
SET NOCOUNT ON;
GO
${login}
${useDb}-- 2. Start from nothing: no database roles, no explicit permissions except CONNECT.
DECLARE @roua_sql nvarchar(max) = N'';
SELECT @roua_sql += N'ALTER ROLE ' + QUOTENAME(r.name) + N' DROP MEMBER ${u};'
  FROM sys.database_role_members m
  JOIN sys.database_principals r ON r.principal_id = m.role_principal_id
 WHERE m.member_principal_id = USER_ID(${msLit(name)});
SELECT @roua_sql += CASE p.class
    WHEN 0 THEN N'REVOKE ' + p.permission_name + N' TO ${u} CASCADE;'
    WHEN 1 THEN N'REVOKE ' + p.permission_name + N' ON OBJECT::' + QUOTENAME(OBJECT_SCHEMA_NAME(p.major_id)) + N'.' + QUOTENAME(OBJECT_NAME(p.major_id)) + N' TO ${u} CASCADE;'
    WHEN 3 THEN N'REVOKE ' + p.permission_name + N' ON SCHEMA::' + QUOTENAME(SCHEMA_NAME(p.major_id)) + N' TO ${u} CASCADE;'
    WHEN 4 THEN N'REVOKE ' + p.permission_name + N' ON USER::' + QUOTENAME(USER_NAME(p.major_id)) + N' TO ${u} CASCADE;'
    ELSE N'' END
  FROM sys.database_permissions p
 WHERE p.grantee_principal_id = USER_ID(${msLit(name)})
   AND NOT (p.class = 0 AND p.permission_name = 'CONNECT')
   AND p.state IN ('G', 'W', 'D');
EXEC sys.sp_executesql @roua_sql;
GO
-- 3. Deny every write and DDL permission database-wide. DENY wins over any role
--    membership added later by mistake.
DENY ${DENIED.join(", ")} TO ${u};
GO
${spec.mode === "metadata" ? metadataGrants(spec, u) : `-- 4. Grant SELECT per table and view, computed now (tables created later are
--    not readable). Tables with hidden columns get SELECT on the other columns.
CREATE OR ALTER FUNCTION dbo.roua_tmp_snake (@s sysname) RETURNS nvarchar(400) AS
BEGIN
  DECLARE @i int = 1, @out nvarchar(400) = N'', @ch nchar(1), @prev nchar(1) = N'';
  WHILE @i <= LEN(@s)
  BEGIN
    SET @ch = SUBSTRING(@s, @i, 1);
    IF @ch COLLATE Latin1_General_BIN LIKE N'[A-Z]' AND @prev COLLATE Latin1_General_BIN LIKE N'[a-z0-9]' SET @out += N'_';
    SET @out += @ch;
    SET @prev = @ch;
    SET @i += 1;
  END
  RETURN LOWER(@out);
END;
GO
${mismatchReport(spec)}DECLARE @obj nvarchar(400), @cols nvarchar(max), @hidden int, @sql nvarchar(max), @granted int = 0, @partial int = 0;
DECLARE roua_objs CURSOR LOCAL FAST_FORWARD FOR
  SELECT QUOTENAME(s.name) + N'.' + QUOTENAME(o.name),
    (SELECT STRING_AGG(CAST(QUOTENAME(c.name) AS nvarchar(max)), N', ') WITHIN GROUP (ORDER BY c.column_id)
       FROM sys.columns c WHERE c.object_id = o.object_id AND NOT ${hiddenPredicate(spec)}),
    (SELECT COUNT(*) FROM sys.columns c WHERE c.object_id = o.object_id AND ${hiddenPredicate(spec)})
  FROM sys.objects o
  JOIN sys.schemas s ON s.schema_id = o.schema_id
 WHERE o.type IN ('U', 'V') AND o.is_ms_shipped = 0
   AND ${objectFilter(spec)};
OPEN roua_objs;
FETCH NEXT FROM roua_objs INTO @obj, @cols, @hidden;
WHILE @@FETCH_STATUS = 0
BEGIN
  -- ${perColumn ? "Per-column grants: columns added later stay hidden until setup runs again." : "Whole-object grants where nothing is hidden."}
  SET @sql = CASE WHEN @hidden = 0 AND ${perColumn ? "1 = 0" : "1 = 1"} THEN N'GRANT SELECT ON ' + @obj + N' TO ${u};'
                  WHEN @cols IS NOT NULL THEN N'GRANT SELECT ON ' + @obj + N' (' + @cols + N') TO ${u};' END;
  IF @sql IS NOT NULL
  BEGIN
    EXEC sys.sp_executesql @sql;
    SET @granted += 1;
    IF @hidden > 0 SET @partial += 1;
  END
  FETCH NEXT FROM roua_objs INTO @obj, @cols, @hidden;
END
CLOSE roua_objs;
DEALLOCATE roua_objs;
DROP FUNCTION dbo.roua_tmp_snake;
IF @granted = 0
  THROW 50001, N'ROUA: the scope matched no readable tables, so the account can read nothing. Check the database, schemas, listed tables and exclusions (run discover.sql to see what exists).', 1;
PRINT CONCAT(N'ROUA: SELECT granted on ', @granted, N' objects (', @partial, N' with hidden columns).');
GO
`}-- 5. Record what the account is for, where every admin can see it.
IF EXISTS (SELECT 1 FROM sys.extended_properties WHERE class = 4 AND major_id = USER_ID(${msLit(name)}) AND name = N'roua')
  EXEC sys.sp_dropextendedproperty @name = N'roua', @level0type = N'USER', @level0name = ${msLit(name)};
EXEC sys.sp_addextendedproperty @name = N'roua', @value = ${msLit(meta)}, @level0type = N'USER', @level0name = ${msLit(name)};
GO
${contained ? `-- 6. Expiry: Azure SQL Database has no SQL Server Agent. Schedule revoke.sql
--    for ${new Date(spec.expiresAt).toISOString()} with Elastic Jobs or an Automation runbook.
` : `-- 6. Expiry: a SQL Server Agent job disables the login and ends its sessions at
--    ${new Date(spec.expiresAt).toISOString()} (converted to the server's local time).
BEGIN TRY
  DECLARE @job sysname = ${msLit(jobName)};
  DECLARE @local datetime = DATEADD(minute, DATEDIFF(minute, GETUTCDATE(), GETDATE()), CONVERT(datetime, ${msLit(expires)}, 126));
  DECLARE @d int = CONVERT(int, CONVERT(char(8), @local, 112));
  DECLARE @t int = DATEPART(hour, @local) * 10000 + DATEPART(minute, @local) * 100 + DATEPART(second, @local);
  IF EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = @job) EXEC msdb.dbo.sp_delete_job @job_name = @job;
  EXEC msdb.dbo.sp_add_job @job_name = @job, @description = N'ROUA expiry', @delete_level = 1;
  EXEC msdb.dbo.sp_add_jobstep @job_name = @job, @step_name = N'disable', @subsystem = N'TSQL', @database_name = N'master',
    @command = N'ALTER LOGIN ${u} DISABLE; ${killSessions(name, false).replace(/'/g, "''").replace(/\n/g, " ")}';
  EXEC msdb.dbo.sp_add_jobschedule @job_name = @job, @name = N'once', @freq_type = 1, @active_start_date = @d, @active_start_time = @t;
  EXEC msdb.dbo.sp_add_jobserver @job_name = @job;
  PRINT N'ROUA: expiry job created. SQL Server Agent must be running for it to fire.';
END TRY
BEGIN CATCH
  PRINT N'ROUA WARNING: could not create the expiry job (' + ERROR_MESSAGE() + N'). Schedule revoke.sql yourself.';
END CATCH;
GO
`}`;

  const revoke = `${header("revoke.sql: disable the account now and end its open sessions. Run as an administrator.", spec, now)}${contained
    ? `DENY CONNECT TO ${u};\nGO\n${killSessions(name, true)}\nGO\n`
    : `USE [master];\nGO\nALTER LOGIN ${u} DISABLE;\nGO\n${killSessions(name, false)}\nGO\nIF EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = ${msLit(jobName)}) EXEC msdb.dbo.sp_delete_job @job_name = ${msLit(jobName)};\nGO\n`}`;
  const drop = `${header("drop.sql: remove the account completely (run revoke.sql first).", spec, now)}${useDb}DROP USER IF EXISTS ${u};
GO
${contained ? "" : `USE [master];\nGO\nIF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = ${msLit(name)}) DROP LOGIN ${u};\nGO\n`}`;

  if (contained) {
    warnings.push("Contained users need the plaintext password in setup.sql. Delete the file after running it.");
    manualSteps.push(`Azure SQL Database has no Agent: schedule revoke.sql for ${new Date(spec.expiresAt).toISOString()} (Elastic Jobs, Automation runbook or a pipeline).`);
  } else {
    manualSteps.push("Expiry uses SQL Server Agent. Express edition has no Agent, and on Linux it must be enabled (MSSQL_AGENT_ENABLED=true). If it is not running, schedule revoke.sql yourself.");
  }
  manualSteps.push("SQL Server has no per-login connection or query-time limit. Use Resource Governor (Enterprise) or limits in the client.");
  return {
    engine: "sqlserver",
    files: [
      { name: "setup.sql", run: `sqlcmd -S HOST -U admin -C -b -i setup.sql${contained ? ` -d ${db}` : ""}`, content: setup },
      { name: "audit.sql", run: `sqlcmd -S HOST -U admin -C -i audit.sql${contained ? ` -d ${db}` : ""}`, content: auditSqlServer(name, db, contained, now) },
      { name: "revoke.sql", run: `sqlcmd -S HOST -U admin -C -b -i revoke.sql${contained ? ` -d ${db}` : ""}`, content: revoke },
      { name: "drop.sql", run: `sqlcmd -S HOST -U admin -C -b -i drop.sql${contained ? ` -d ${db}` : ""}`, content: drop },
    ],
    warnings,
    manualSteps,
  };
}

/** Audit any database user. Read-only. Effective permissions are checked with EXECUTE AS USER. */
export function auditSqlServer(name: string, database: string, contained = false, now: Date = new Date()): string {
  const n = msLit(name);
  const secret = [
    ...SECRET_TOKENS.map((t) => `N'_' + LOWER(c.name) + N'_' LIKE N'%[_]${t}[_]%'`),
    ...SECRET_SUBSTRINGS.map((s) => `LOWER(c.name) LIKE N'%${likePattern(s)}%'`),
  ].join(" OR ");
  return `-- audit.sql: is ${name} actually read-only? Read-only; safe to run anytime as an administrator.
-- ROUA 0.1 audit for SQL Server. Generated ${now.toISOString()} by the ROUA generator (kaizam.com).
-- sqlcmd -S HOST -U admin -C -i audit.sql${contained ? ` -d ${database}` : ""}
-- Every row should say PASS. FAIL means the account can change data, read secrets or never expires.
SET NOCOUNT ON;
${contained ? "" : `USE ${msIdent(database)};\n`}GO
DECLARE @r TABLE (id varchar(4), [check] nvarchar(120), status varchar(4), detail nvarchar(2000));
DECLARE @uid int = USER_ID(${n});
IF @uid IS NULL
BEGIN
  SELECT 'A1' AS id, N'Database user exists' AS [check], 'FAIL' AS status, N'No user ${name.replace(/'/g, "''")} in this database' AS detail;
  RETURN;
END;
${contained ? "" : `INSERT @r SELECT 'R1', N'No server roles', CASE WHEN COUNT(*) > 0 THEN 'FAIL' ELSE 'PASS' END, ISNULL(STRING_AGG(r.name, N', '), N'')
  FROM sys.server_role_members m JOIN sys.server_principals r ON r.principal_id = m.role_principal_id
 WHERE m.member_principal_id = SUSER_ID(${n});
INSERT @r SELECT 'R2', N'No server permissions beyond CONNECT SQL', CASE WHEN COUNT(*) > 0 THEN 'FAIL' ELSE 'PASS' END, ISNULL(STRING_AGG(permission_name, N', '), N'')
  FROM sys.server_permissions WHERE grantee_principal_id = SUSER_ID(${n}) AND state IN ('G', 'W') AND permission_name <> 'CONNECT SQL';
`}INSERT @r SELECT 'R3', N'No database roles', CASE WHEN COUNT(*) > 0 THEN 'FAIL' ELSE 'PASS' END, ISNULL(STRING_AGG(r.name, N', '), N'')
  FROM sys.database_role_members m JOIN sys.database_principals r ON r.principal_id = m.role_principal_id
 WHERE m.member_principal_id = @uid;
INSERT @r SELECT 'O1', N'Owns no schemas or objects', CASE WHEN COUNT(*) > 0 THEN 'FAIL' ELSE 'PASS' END, ISNULL(STRING_AGG(x.n, N', '), N'')
  FROM (SELECT name AS n FROM sys.schemas WHERE principal_id = @uid
        UNION ALL SELECT OBJECT_SCHEMA_NAME(object_id) + N'.' + name FROM sys.objects WHERE principal_id = @uid) x;
INSERT @r SELECT 'S1', N'No linked servers usable with stored credentials', CASE WHEN COUNT(*) > 0 THEN 'WARN' ELSE 'PASS' END, ISNULL(STRING_AGG(s.name, N', '), N'')
  FROM sys.servers s JOIN sys.linked_logins l ON l.server_id = s.server_id
 WHERE s.is_linked = 1 AND l.local_principal_id IN (0, SUSER_ID(${n})) AND l.remote_name IS NOT NULL;

EXECUTE AS USER = ${n};
INSERT @r SELECT 'D1', N'No database-wide write or DDL permission', CASE WHEN COUNT(*) > 0 THEN 'FAIL' ELSE 'PASS' END, ISNULL(STRING_AGG(permission_name, N', '), N'')
  FROM sys.fn_my_permissions(NULL, 'DATABASE')
 WHERE permission_name IN ('INSERT', 'UPDATE', 'DELETE', 'EXECUTE', 'ALTER', 'CONTROL', 'TAKE OWNERSHIP', 'CREATE TABLE', 'CREATE VIEW',
   'CREATE PROCEDURE', 'CREATE FUNCTION', 'CREATE SCHEMA', 'CREATE TYPE', 'CREATE SYNONYM', 'ALTER ANY SCHEMA', 'ALTER ANY USER', 'ALTER ANY ROLE');
INSERT @r SELECT 'T1', N'No write permission on any table or view', CASE WHEN COUNT(*) > 0 THEN 'FAIL' ELSE 'PASS' END, ISNULL(LEFT(STRING_AGG(CAST(s.name + N'.' + o.name + N': ' + v.p AS nvarchar(max)), N', '), 2000), N'')
  FROM sys.objects o JOIN sys.schemas s ON s.schema_id = o.schema_id
  CROSS JOIN (VALUES ('INSERT'), ('UPDATE'), ('DELETE'), ('ALTER'), ('CONTROL'), ('TAKE OWNERSHIP')) v(p)
 WHERE o.type IN ('U', 'V') AND o.is_ms_shipped = 0
   AND HAS_PERMS_BY_NAME(QUOTENAME(s.name) + N'.' + QUOTENAME(o.name), 'OBJECT', v.p) = 1;
INSERT @r SELECT 'F1', N'Cannot execute procedures or functions', CASE WHEN COUNT(*) > 0 THEN 'FAIL' ELSE 'PASS' END, ISNULL(LEFT(STRING_AGG(CAST(s.name + N'.' + o.name AS nvarchar(max)), N', '), 2000), N'')
  FROM sys.objects o JOIN sys.schemas s ON s.schema_id = o.schema_id
 WHERE o.type IN ('P', 'PC', 'FN', 'IF', 'TF', 'FS', 'FT', 'X') AND o.is_ms_shipped = 0
   AND HAS_PERMS_BY_NAME(QUOTENAME(s.name) + N'.' + QUOTENAME(o.name), 'OBJECT', 'EXECUTE') = 1;
INSERT @r SELECT 'X1', N'No secret-looking columns readable', CASE WHEN COUNT(*) > 0 THEN 'FAIL' ELSE 'PASS' END, ISNULL(LEFT(STRING_AGG(CAST(s.name + N'.' + o.name + N'.' + c.name AS nvarchar(max)), N', '), 2000), N'')
  FROM sys.columns c JOIN sys.objects o ON o.object_id = c.object_id JOIN sys.schemas s ON s.schema_id = o.schema_id
 WHERE o.type IN ('U', 'V') AND o.is_ms_shipped = 0 AND (${secret})
   AND HAS_PERMS_BY_NAME(QUOTENAME(s.name) + N'.' + QUOTENAME(o.name), 'OBJECT', 'SELECT', c.name, 'COLUMN') = 1;
REVERT;

INSERT @r SELECT 'E1', N'Expires on its own', CASE WHEN ${contained ? "0 = 1" : `EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = ${msLit(`roua_expire_${name}`)} AND enabled = 1)`} THEN 'PASS' ELSE ${contained ? "'WARN'" : "'FAIL'"} END,
  ISNULL((SELECT CAST(value AS nvarchar(2000)) FROM sys.extended_properties WHERE class = 4 AND major_id = @uid AND name = N'roua'),
         N'No ROUA metadata. Forgotten accounts are the most common leak.');
SELECT id, [check], status, detail FROM @r;
GO
`;
}
