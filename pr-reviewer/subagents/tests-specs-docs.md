# Tests Specs Docs Subagent

Review a PR classified as `tests-specs-docs`.

## Read First

- `pr-reviewer/reviewers/tests-docs.md`
- `pr-reviewer/config/rubric.yaml`

## Focus

- harness and scenario coverage
- connector specs and field probe fallout
- docs and generated docs correctness
- source-of-truth consistency for generated outputs

## Extra Checks

- tests actually protect against regression
- docs do not promise unsupported behavior
- generated docs changes trace back to source changes

## Output

Use the standard structured finding format from `pr-reviewer/reviewers/tests-docs.md`.
