# ROUA MCP server

`roua mcp` runs a [Model Context Protocol](https://modelcontextprotocol.io) server over stdio, so AI agents and MCP clients can check and prepare read-only database accounts. It ships inside `@roua-dev/cli` and adds no dependencies. Registry name: `io.github.PromiseGithub/roua`.

```json
{
  "mcpServers": {
    "roua": {
      "command": "npx",
      "args": ["-y", "@roua-dev/cli", "mcp"],
      "env": { "ADMIN_DATABASE_URL": "postgres://admin@db.internal/appdb" }
    }
  }
}
```

`ADMIN_DATABASE_URL` is optional. Only `audit_postgres_role` uses it, and that tool only reads catalog views. Docker: `docker run --rm -i ghcr.io/promisegithub/roua mcp`.

## Protocol

- JSON-RPC 2.0, one message per line on stdin and stdout; logs go to stderr.
- Answers the `initialize` handshake for protocol versions `2025-11-25`, `2025-06-18`, `2025-03-26` and `2024-11-05` (it returns the client's version if supported, otherwise `2025-11-25`).
- Also answers `tools/list` and `tools/call` without a prior handshake, so stateless clients work.
- Methods: `initialize`, `ping`, `tools/list`, `tools/call`, `resources/list` (empty) and `prompts/list` (empty).

## Tools

### `list_engines` (read-only)

No input. Returns each database, its support level (`full`, `tested`, `preview`), the tested versions, how ROUA works there and which managed services it covers.

### `audit_script` (read-only, connects to nothing)

Writes an audit script for an **existing** account on any engine.

| Input | Type | Notes |
|---|---|---|
| `engine` | string, required | `postgresql`, `mysql`, `mariadb`, `sqlserver`, `oracle`, `mongodb`, `redis`, `snowflake`, `bigquery` |
| `name` | string, required | account, role, login, user or service-account id |
| `host` | string | MySQL/MariaDB host part of `'user'@'host'` (default `%`) |
| `database` | string | SQL Server database, MongoDB authentication database, or BigQuery project id |
| `role` | string | Snowflake role to inspect (default `NAME_READ`) |
| `location` | string | BigQuery location (default `US`) |

Returns the file name, how to run it, and the script text.

### `generate_account_scripts` (writes files, connects to nothing)

Generates setup, audit, revoke and drop scripts (plus `schedule-revoke.md` for MongoDB and Redis) and writes them to a **new or empty** folder. The password or private key goes to `PASSWORD.txt` or `rsa_key.p8` in that folder with owner-only permissions and is **never returned** in the tool result. Nothing runs against a database: a human administrator runs the setup script.

| Input | Type | Notes |
|---|---|---|
| `engine` | string, required | as above |
| `output_dir` | string, required | absolute path of a new or empty folder |
| `name` | string, required | lowercase, 3 to 63 characters, for example `roua_agent_docs` |
| `profile` | string, required | `agent`, `demo`, `review`, `audit`, `support`, `training`, `analytics`, `custom` |
| `owner`, `purpose` | string, required | accountable person and reason |
| `expires_at` | string, required | ISO 8601 UTC, within the profile's maximum lifetime |
| `level` | string | PostgreSQL only: `L0` to `L5` (default from the profile) |
| `mode` | string | other engines: `scope` (L2), `listed` (L1) or `metadata` (L0 where supported) |
| `database`, `schemas`, `objects`, `exclude`, `columns_deny` | string / string[] | scope, as on kaizam.com |
| `allowed_sources`, `max_connections`, `statement_timeout_s` | | limits |
| `warehouse` (Snowflake), `location` (BigQuery) | string | |
| `password_env` | string | name of an environment variable of the server holding the password; default: generate one |

Returns the files written, how to run each one, and notes. `structuredContent` lists `output_dir`, `files` and `credential_files`.

### `audit_postgres_role` (read-only, live)

| Input | Type | Notes |
|---|---|---|
| `role` | string, required | PostgreSQL role to audit |

Connects with `ADMIN_DATABASE_URL` and returns the same report as `roua audit --role NAME`: text, plus the JSON report (`schemas/roua-report.schema.json`) as `structuredContent`.

## Safety

- The server never returns passwords, keys or connection strings.
- It never runs setup or revoke against a database; generated scripts are for a human to review and run.
- Agents should treat ROUA output as advice to their user, not as authorization to access anything.

Feedback and ideas: [Discussions](https://github.com/PromiseGithub/roua/discussions).
