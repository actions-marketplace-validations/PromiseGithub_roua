# RFC 0004: Required query logging at L4/L5, and credential classes

- Status: proposed, open for comment
- Author(s): Promise Okoroji
- Spec version affected: 0.2 (§9, §15, §16, new checks)

## Summary

1. Make query logging a **MUST** for L4 and L5 accounts, with a check per engine.
2. Add a `credential` field to the account definition naming the credential class: `static_password`, `keypair`, `iam_token` or `dynamic`, and recommend `iam_token` or `dynamic` for the `agent` profile.

## Motivation

L4 and L5 accounts see personal data. Without a record of what they read, an incident cannot be investigated and compliance evidence cannot be produced. Static, long-lived passwords are the weakest credential class, and the definition should say which class is in use so tools can audit it.

## Proposal

- L4 and L5 accounts **MUST** have query logging for their sessions: PostgreSQL `pgaudit.log` including `read` for the role, or the equivalents listed in SPEC §15. New check **C2** fails when it is missing at these levels.
- `account.credential` is one of `static_password` (default), `keypair`, `iam_token`, `dynamic`. For `iam_token` and `dynamic`, tools **MUST NOT** generate a password and **SHOULD** emit the engine's IAM grant (for example `GRANT rds_iam TO …`) or a secrets-manager role definition instead.
- For `static_password`, the rotation rule in SPEC §7 applies, and the audit reports **M2** when the last rotation is older than 90 days.

## Verification

Checks C2 and M2; generator tests for each credential class; a live test of RDS IAM authentication where a test account is available.

## Drawbacks and alternatives

Logging has a cost and is not available on every edition (MongoDB auditing needs Enterprise or Atlas). Where an engine cannot log, the account cannot be L4 or L5 on that engine.

## Compatibility

Breaking for existing L4 and L5 accounts without logging: one minor version of warnings first.
