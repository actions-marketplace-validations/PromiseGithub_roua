# RFC 0003: Data egress controls and an optional query gateway

- Status: proposed, open for comment
- Author(s): Promise Okoroji
- Spec version affected: 0.2 (§17, new checks), plus a companion "ROUA-Gateway" document

## Summary

Define how a ROUA tool describes and audits an **egress-aware proxy** that sits between an account's holder (often an AI agent) and the database, enforcing row caps, row or byte budgets, query logging and a kill switch. Its use stays optional; the spec recommends it for the `agent` profile at L2 and above.

## Motivation

Read-only prevents change, not disclosure. For agents with broad read access the realistic risk is bulk extraction: sweeping `SELECT *` across many tables, or slow extraction over days. Database privileges cannot express "at most 10 000 rows per day".

## Proposal

A ROUA gateway:

- **MUST** parse each statement and forward only read statements, as defence in depth on top of database privileges, never as a replacement for them.
- **MUST** enforce a per-query row cap and per-account row or byte budgets per hour and per day.
- **MUST** log every statement with the account, the client identity (for example the agent or MCP session) and the outcome.
- **SHOULD** detect sweeping patterns (many tables in a short time, high-cardinality extraction) and lock the account automatically.
- **MUST** hold the database credentials itself: the agent authenticates to the gateway and never sees them.
- **MAY** mask columns for engines without native masking.

The account definition gains an optional `egress` block (`row_cap`, `daily_rows`, `daily_bytes`, `gateway`), and the audit gains **E3** (egress budget configured) and **E4** (gateway logging on) when a gateway is declared.

## Verification

A reference gateway for the PostgreSQL and MySQL wire protocols, and an MCP query tool, with tests proving the caps, budgets and kill switch.

## Drawbacks and alternatives

A proxy is new infrastructure and a new point of failure. Alternatives are views with `LIMIT` (easy to bypass across many queries) and engine-native quotas, which exist only on some warehouses.

## Compatibility

New and optional.
