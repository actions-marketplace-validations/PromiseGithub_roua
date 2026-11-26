# ROUA RFCs

Substantive changes to the ROUA specification go here: new levels, profiles, checks or engines, and changes to MUST or SHOULD requirements.

1. Copy `0000-template.md` to `0000-short-title.md`.
2. Open a pull request; discussion happens there.
3. The comment period is at least **14 days**.
4. The maintainer decides and explains the decision in the pull request. Accepted RFCs get a number and are merged.

Typo fixes and clarifications that do not change meaning can be ordinary pull requests.

## Open proposals

Comment on these in [Discussions](https://github.com/PromiseGithub/roua/discussions) or on the linked issues. Nothing in them is part of the specification until accepted.

| RFC | Proposal |
|---|---|
| [0001](0001-discovery-manifest.md) | Discovery manifest at `/.well-known/roua.json` |
| [0002](0002-approval-records.md) | Verifiable, signed approval records; required at L3 and above |
| [0003](0003-egress-gateway.md) | Data egress controls and an optional query gateway |
| [0004](0004-logging-and-credentials.md) | Required query logging at L4/L5; credential classes |
| [0005](0005-engine-profiles.md) | Normative engine profiles beyond PostgreSQL |
