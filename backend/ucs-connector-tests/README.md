# UCS Connector Tests

This crate contains live UCS integration tests for connectors, with scenario-based suites and progressive composite flow execution.

## What this crate gives you

- Connector-focused Rust tests runnable with `cargo test`
- Strict assertions for flow behavior (`authorize`, `capture`, `void`, `refund`, etc.)
- Progressive composite chains that pass data from previous responses to later requests
- Annotation-driven capability matrix CLI (`ucs_test_summary`)

## Test layout

Connector tests live under:

`tests/<connector>/suites/*.rs`

Current connector suites:

- `tests/authorizedotnet/suites/authorize.rs`
- `tests/authorizedotnet/suites/create_customer.rs`
- `tests/authorizedotnet/suites/capture.rs`
- `tests/authorizedotnet/suites/get.rs`
- `tests/authorizedotnet/suites/void.rs`
- `tests/authorizedotnet/suites/refund.rs`
- `tests/authorizedotnet/suites/composite.rs`
- `tests/adyen/suites/authorize.rs`
- `tests/stripe/suites/authorize.rs`
- `tests/cybersource/suites/authorize.rs`

## Test writing pattern

All connector suites follow a common pattern so reviewers can quickly read:

1. request overrides,
2. request generation,
3. response assertions.

Reference: `docs/test-writing-pattern.md`.

Input iteration helper:

- `generated_input_variants()` runs each scenario against multiple valid input variants.
- Source generator: `src/harness/generators.rs` (`generate_input_variants`).

## Running tests

From workspace root:

```bash
UCS_CREDS_PATH="/absolute/path/to/connector_creds.json" \
cargo test -p ucs-connector-tests --test authorizedotnet -- --nocapture --test-threads=1

UCS_CREDS_PATH="/absolute/path/to/connector_creds.json" \
cargo test -p ucs-connector-tests --test stripe -- --nocapture --test-threads=1
```

Credentials env vars supported by test harness:

- `CONNECTOR_AUTH_FILE_PATH`
- `UCS_CREDS_PATH`

## Progressive composite model

Composite chains are connector-ordered and progressive:

1. Run all variants of the current flow
2. Take default variant result from that flow
3. Carry default context into next flow
4. Repeat

Examples (Authorize.Net):

- 5-step: `create_customer -> authorize(manual) -> capture -> get -> refund`
- 4-step: `create_customer -> authorize(manual) -> capture -> refund`
- 3-step: `create_customer -> authorize(manual) -> void`
- 2-step: `create_customer -> authorize(auto)`

## Capability summary CLI

This crate includes a CLI that builds capability matrix rows directly from test annotations.

Run directly:

```bash
cargo run -p ucs-connector-tests --bin ucs_test_summary -- --connector authorizedotnet --flow authorize
```

Capability-only (grouped) view:

```bash
cargo run -p ucs-connector-tests --bin ucs_test_summary -- --connector authorizedotnet --capabilities-only
```

Include test names (verbose mode):

```bash
cargo run -p ucs-connector-tests --bin ucs_test_summary -- --connector authorizedotnet --capabilities-only --show-test-names
```

CI-friendly markdown output:

```bash
cargo run -p ucs-connector-tests --bin ucs_test_summary -- --format markdown --capabilities-only
```

JSON output:

```bash
cargo run -p ucs-connector-tests --bin ucs_test_summary -- --format json --capabilities-only
```

## Make shortcut

From workspace root:

```bash
make ucs-summary
```

Optional vars:

- `UCS_CONNECTOR` (optional; if omitted, shows all connectors)
- `UCS_FLOW`
- `UCS_SUMMARY_FORMAT` (`table` or `json`)
- `UCS_CAPABILITIES_ONLY` (`true` or `false`)
- `UCS_SHOW_TEST_NAMES` (`true` or `false`, default `false`)
- `UCS_TEST_NAME_VIEW` (`none`, `section`, `inline`; optional)

Examples:

```bash
make ucs-summary UCS_CONNECTOR=authorizedotnet
make ucs-summary UCS_CONNECTOR=authorizedotnet UCS_FLOW=authorize
make ucs-summary UCS_SUMMARY_FORMAT=json UCS_CAPABILITIES_ONLY=true
make ucs-summary UCS_CONNECTOR=authorizedotnet UCS_FLOW=authorize UCS_SHOW_TEST_NAMES=true
make ucs-summary UCS_SUMMARY_FORMAT=markdown UCS_CAPABILITIES_ONLY=true
```

## Test annotations (source of truth)

Every test function should include capability tags above it:

```rust
/// @capability capability_id=ANET-CAP-009
/// @capability connector=authorizedotnet
/// @capability layer=suite
/// @capability flow=authorize
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=zip_46282_decline_trigger
/// @capability support=negative_trigger
/// @capability expected=status=FAILURE_and_connector_code=2
```

Required keys:

- `capability_id`
- `connector`
- `layer`
- `flow`
- `payment_method`
- `scenario`
- `support`
- `expected`

Optional key:

- `fallback`
- `payment_method_subtype`

`payment_method_subtype` is required for card flows (for example `no3ds`, `3ds`, `not_applicable`).

Summary output shows `method_profile` (for example `card/no3ds`) and includes test names for traceability.

## Adding a new connector

1. Create `tests/<connector>/suites/`
2. Add suite files with `async fn test_*`
3. Add `@capability` tags above each test
4. Ensure `@capability connector=<connector>` matches the folder name
5. Run:
   - `cargo test -p ucs-connector-tests --test <connector> -- --nocapture --test-threads=1`
   - `make ucs-summary UCS_CONNECTOR=<connector>`

For Authorize.Net-specific details, see `tests/authorizedotnet/README.md`.
