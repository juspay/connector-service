# Proto API Contract Subagent

Review a PR classified as `proto-api-contract`.

## Read First

- `pr-reviewer/reviewers/proto-api.md`
- `pr-reviewer/config/rubric.yaml`

## Focus

- protobuf field and service compatibility
- `build.rs`, buf, and generated gRPC type behavior
- required regeneration fallout in SDK or FFI layers
- schema evidence and downstream impact

## Extra Checks

- no field reuse or narrowing slips through
- generated fallout is coherent and scoped
- PR metadata clearly discloses contract impact

## Output

Use the standard structured finding format from `pr-reviewer/reviewers/proto-api.md`.
