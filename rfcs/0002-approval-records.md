# RFC 0002: Verifiable approval records

- Status: proposed, open for comment
- Author(s): Promise Okoroji
- Spec version affected: 0.2 (§3, §7, §9)

## Summary

Make an approval record **required** for L3 and above, and define its format so tools can verify it: who approved, when, exactly what (a hash of the account definition), and a signature.

## Motivation

Approval is the main governance control for sensitive access, but in 0.1 it is a SHOULD that tools cannot check. `approved_by: cto@example.com` is easy to type and impossible to verify.

## Proposal

- Accounts at L3, L4 and L5 **MUST** have an approval record. L5 **MUST** have two records from **distinct** approvers (0.1 already requires two names; this makes them verifiable).
- Record format (`approvals/<account>.json`):

```json
{
  "roua_approval_version": "0.1",
  "account": "roua_audit_q4",
  "definition_sha256": "<SHA-256 of the canonical roua.yaml>",
  "approver": "jane@example.com",
  "approved_at": "2026-11-24T10:00:00Z",
  "expires_at": "2026-12-24T00:00:00Z",
  "signature": { "method": "sigstore", "bundle": "<base64 Sigstore bundle>" }
}
```

- Accepted signature methods: a Sigstore bundle (keyless, tied to the approver's identity), a minisign signature with a published key, or a reference to an approved pull request whose merge commit contains the definition (`"method": "git-review", "url": "…"`).
- `roua apply` refuses L3+ without valid records; `roua verify` reports **A1** (approval records valid and matching the current definition) and **A2** (L5 approvers distinct).
- Changing the definition invalidates its approvals, because the hash no longer matches.

## Verification

New checks A1 and A2, with tests for valid and invalid signatures, a changed definition and duplicate approvers.

## Drawbacks and alternatives

Adds a step for sensitive accounts, which is the point. Organisations with an access-request system can use the `git-review` method, or reference their ticket in `approval_ref` and sign the record from that system.

## Compatibility

Breaking for L3+ accounts created without approvals: tools warn for one minor version before failing.
