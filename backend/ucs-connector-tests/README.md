# UCS Connector Tests

This crate is being simplified to a scenario-json driven core runner.

## Current direction

- Test behavior should come from suite-level `scenario.json` files.
- Each scenario contains:
  - `grpc_req`: request payload
  - `assert`: response contract
- Thin test wrappers should call a common `run_scenario(suite, scenario_name)` interface.

Core design and milestone plan:

- `docs/scenario-json-core-readme.md`

## Current harness modules

- `src/harness/credentials.rs`
- `src/harness/metadata.rs`
- `src/harness/server.rs`
- `src/harness/executor.rs`

## Credentials

Supported environment variables:

- `CONNECTOR_AUTH_FILE_PATH`
- `UCS_CREDS_PATH`
