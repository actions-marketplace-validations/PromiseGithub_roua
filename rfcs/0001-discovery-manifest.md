# RFC 0001: Discovery manifest (`/.well-known/roua.json`)

- Status: proposed, open for comment
- Author(s): Promise Okoroji
- Spec version affected: 0.2 (new companion document, "ROUA-Discovery")

## Summary

An organisation publishes a small JSON file that tells people and AI agents how it handles read-only access: which profiles and levels it offers, how to request an account, who to contact and which engines it supports. It contains **no credentials and no hostnames** of private systems.

## Motivation

Agents, auditors, partners and app-review teams currently ask by email how to get read-only access. A machine-readable policy lets an agent explain the process to its user, lets an auditor see the policy before an engagement, and lets tools pre-fill requests.

## Proposal

A server **MAY** publish `https://<domain>/.well-known/roua.json`, validated by [`schemas/roua-discovery.schema.json`](../schemas/roua-discovery.schema.json):

```json
{
  "roua_discovery_version": "0.1",
  "organization": "Example Inc.",
  "policy_url": "https://example.com/security/read-only-access",
  "request": { "url": "https://example.com/access/request", "approval": "two approvers for L4 and above" },
  "profiles": ["agent", "audit", "review"],
  "levels": ["L0", "L1", "L2", "L4"],
  "max_lifetime_days": { "agent": 30, "audit": 30, "review": 45 },
  "engines": ["postgresql", "snowflake"],
  "logging": "all ROUA sessions are logged with pgaudit",
  "contact": "https://example.com/security"
}
```

- The manifest **MUST NOT** contain credentials, connection strings, internal hostnames or personal email addresses.
- Profile lifetimes **MUST NOT** exceed the spec maximums.
- Agents **MUST** treat the manifest as information, never as authorization.

## Verification

A `roua discovery check <url>` command validates the schema and flags forbidden content (anything that looks like a credential or a private address).

## Drawbacks and alternatives

Publishing a policy reveals which engines an organisation uses; the file is optional and `engines` can be omitted. A `security.txt` field was considered, but that format is not meant for structured policy.

## Compatibility

New and optional. Nothing existing changes.
