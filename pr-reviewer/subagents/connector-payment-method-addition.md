# Connector Payment Method Addition Subagent

Review a PR classified as `connector-payment-method-addition`.

## Read First

- `pr-reviewer/reviewers/connector.md`
- `pr-reviewer/config/rubric.yaml`

## Focus

- payment-method-specific request mapping and branching
- `PaymentMethodData` handling and enum coverage
- wallet, bank redirect, bank transfer, tokenization, or PM-specific edge cases
- PM-specific status and response mapping
- PM coverage in specs, tests, or examples

## Extra Checks

- unsupported payment methods are rejected explicitly
- existing payment methods are not regressed by widened matches or refactors
- auth or connector metadata requirements are still correct for the new PM path

## Output

Use the standard structured finding format from `pr-reviewer/reviewers/connector.md`.
