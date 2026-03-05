# Authorize.Net UCS Test Model

This folder contains connector-facing UCS integration tests for Authorize.Net.

## Suite Layout

- `suites/create_customer.rs`: customer creation scenarios
- `suites/authorize.rs`: authorize scenarios (success + trigger-based failure/safeguard)
- `suites/capture.rs`: capture scenarios
- `suites/get.rs`: payment sync/get scenarios
- `suites/void.rs`: void scenarios
- `suites/refund.rs`: refund scenarios
- `suites/composite.rs`: dependency chains with progressive variant execution

## Progressive Composite Execution

Composite execution is connector-ordered and progressive:

1. Run all variants of flow-1
2. Take the **default variant result** from flow-1
3. Use that default result/context to run all variants of flow-2
4. Repeat until last flow

This is implemented in `suites/composite.rs` and uses `FlowContext` from
`src/harness/context.rs` for automatic data carry-forward.

## Data Carry-Forward Rules

When previous responses contain fields required by a later request, tests pass
them automatically through `FlowContext`, including:

- `connector_customer_id` from customer create -> authorize
- `connector_transaction_id` from authorize/capture -> capture/get/void/refund
- `merchant_refund_id` generated and validated in refund flows

## Strictness Policy

- Core success flows assert exact statuses (for example, `CHARGED`, `AUTHORIZED`, `VOIDED`).
- Triggered failure flows assert strict connector/unified error signals when failure occurs.
- AVS/CVV safeguard: if account settings do not hard-fail these triggers, tests require
  `CHARGED` with no error and a transaction id (strict fallback path).

## Test Name Pattern

Test names are intentionally scenario-rich so CLI/nextest output is self-explanatory:

`test_<connector>__<layer>__<flow>__<input_or_precondition>__<expected_result>`

Examples:

- `test_authorizedotnet__suite_authorize__card_zip_46282_decline_trigger__returns_failure_code_2`
- `test_authorizedotnet__suite_get__after_manual_authorize_and_capture__returns_charged_without_error`
- `test_authorizedotnet__composite_progressive__5_steps__create_customer_then_authorize_manual_then_capture_then_get_then_refund__runs_all_step_variants_with_default_carry_forward`

## Capability Annotations (Source of Truth)

Capability matrix rows are generated directly from annotations above each test:

```rust
/// @capability connector=authorizedotnet
/// @capability layer=suite
/// @capability flow=authorize
/// @capability payment_method=card
/// @capability payment_method_subtype=no3ds
/// @capability scenario=zip_46282_decline_trigger
/// @capability support=negative_trigger
/// @capability expected=status=FAILURE_and_connector_code=2
```

The summary CLI parses `tests/authorizedotnet/suites/*.rs` and builds the matrix from these tags.

For card scenarios, include `payment_method_subtype` (for example `no3ds` or `3ds`) so summary output is explicit.

Summary output includes `method_profile` (for example `card/no3ds`) and associated test names for validation.

## Running

```bash
UCS_CREDS_PATH="/absolute/path/to/connector_creds.json" \
cargo test -p ucs-connector-tests --test authorizedotnet -- --nocapture --test-threads=1
```

`CONNECTOR_AUTH_FILE_PATH` is also supported as an alternative credentials env var.

## CLI Summary

You can view tested capability summary from CLI:

```bash
cargo run -p ucs-connector-tests --bin ucs_test_summary -- --connector authorizedotnet --flow authorize
```

Capability-only summary (flow + payment method view):

```bash
cargo run -p ucs-connector-tests --bin ucs_test_summary -- --connector authorizedotnet --capabilities-only
```

Verbose capability summary with mapped test names:

```bash
cargo run -p ucs-connector-tests --bin ucs_test_summary -- --connector authorizedotnet --capabilities-only --show-test-names
```

CI markdown summary:

```bash
cargo run -p ucs-connector-tests --bin ucs_test_summary -- --connector authorizedotnet --format markdown --capabilities-only
```
