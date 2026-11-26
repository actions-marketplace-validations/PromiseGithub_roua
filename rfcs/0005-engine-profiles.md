# RFC 0005: Normative engine profiles beyond PostgreSQL

- Status: proposed, open for comment
- Author(s): Promise Okoroji
- Spec version affected: 0.2 (§10)

## Summary

Promote the informative engine profiles in SPEC §10.1 (MySQL, MariaDB, SQL Server and Azure SQL, Oracle, MongoDB, Redis and Valkey) to **normative**, so other tools can build conformant implementations and claim, for example, "ROUA 0.2 conformant (MySQL)".

## Motivation

Six engines are already tested against real servers on every change, but only PostgreSQL has normative text. Without it, conformance claims for other engines mean little, and other implementers cannot know what is required.

## Proposal

For each engine the profile becomes a list of MUSTs covering: the read grant (per object, never database-wide or future), secret handling, the absence or denial of writes, the credential form, the expiry mechanism, revoke (disable plus ending sessions), and a mapping of that engine's audit checks to the §8 identifiers. Where an engine cannot meet a requirement (MongoDB and Redis have no built-in expiry; Oracle has no column read grants), the profile states the required fallback: a scheduled revoke that the audit verifies, or skipping tables with hidden columns.

Snowflake and BigQuery stay informative until they are tested against live services.

## Verification

The live engine tests in `scripts/live-engine-test.mjs` become the conformance tests for these profiles, published as part of a conformance kit.

## Drawbacks and alternatives

More normative text to maintain as engines evolve. Engine versions are pinned in each profile and updated through ordinary RFCs.

## Compatibility

Accounts created by the reference generators already follow these profiles.
