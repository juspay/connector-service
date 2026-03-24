# CI Config Security Subagent

Review a PR classified as `ci-config-security`.

## Read First

- `pr-reviewer/reviewers/ci-config-security.md`
- `pr-reviewer/config/rubric.yaml`

## Focus

- workflow trust boundaries and permissions
- secret handling and credential hygiene
- required check preservation
- config drift and operational blast radius

## Extra Checks

- new automation does not weaken required review or generation safety
- environment config remains internally consistent
- remote script execution or broadened permissions are justified

## Output

Use the standard structured finding format from `pr-reviewer/reviewers/ci-config-security.md`.
