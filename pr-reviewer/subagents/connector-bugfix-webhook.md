# Connector Bugfix Webhook Subagent

Review a PR classified as `connector-bugfix-webhook`.

## Read First

- `pr-reviewer/reviewers/connector.md`
- `pr-reviewer/config/rubric.yaml`

## Focus

- auth and request signing fixes
- webhook parsing, verification, and source validation
- redirect, dispute, refund, or sync bugfixes
- regression risk in already-supported flows

## Extra Checks

- security-sensitive logic is not weakened
- bugfix scope matches test coverage and PR description
- no secrets or raw headers leak through diagnostics or PR evidence

## Output

Use the standard structured finding format from `pr-reviewer/reviewers/connector.md`.
