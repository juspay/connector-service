# Python SDK Coverage

This document describes the Python SDK integration test infrastructure and
its coverage of the 32 FFI service flows.

## Overview

The connector-service Python SDK exposes all 32 FFI flows through 8 client
classes. The integration test harness validates end-to-end correctness by
executing each flow through the Python SDK subprocess and comparing the
results against the same scenarios used by the Rust FFI path.

## Client / Flow Matrix

| Client | Flows | Count |
|:-------|:------|------:|
| `PaymentClient` | authorize, capture, void, refund, get, setup_recurring, create_order, reverse, proxy_authorize, proxy_setup_recurring, token_authorize, token_setup_recurring | 12 |
| `PayoutClient` | payout_create, payout_create_link, payout_create_recipient, payout_enroll_disburse_account, payout_get, payout_stage, payout_transfer, payout_void | 8 |
| `MerchantAuthenticationClient` | create_server_authentication_token, create_server_session_authentication_token, create_client_authentication_token | 3 |
| `PaymentMethodAuthenticationClient` | authenticate, pre_authenticate, post_authenticate | 3 |
| `DisputeClient` | accept, defend, submit_evidence | 3 |
| `RecurringPaymentClient` | charge | 1 |
| `CustomerClient` | create | 1 |
| `PaymentMethodClient` | tokenize | 1 |
| **Total** | | **32** |

## Suite Name Mapping

Some integration test suite names differ from the FFI flow names:

| Suite Name | FFI Flow | Python Client | Python Method |
|:-----------|:---------|:--------------|:--------------|
| `create_customer` | `create` | CustomerClient | `create` |
| `recurring_charge` | `charge` | RecurringPaymentClient | `charge` |
| `tokenize_payment_method` | `tokenize` | PaymentMethodClient | `tokenize` |
| `server_authentication_token` | `create_server_authentication_token` | MerchantAuthenticationClient | `create_server_authentication_token` |
| `server_session_authentication_token` | `create_server_session_authentication_token` | MerchantAuthenticationClient | `create_server_session_authentication_token` |
| `client_authentication_token` | `create_client_authentication_token` | MerchantAuthenticationClient | `create_client_authentication_token` |

## Suites Without FFI Flow Support

These integration test suites exist for gRPC testing but have no
corresponding FFI flow, and therefore cannot be tested through the Python
SDK:

- `complete_authorize`
- `refund_sync`
- `revoke_mandate`
- `verify_redirect_response`
- `incremental_authorization`
- `payment_method_eligibility`

## Test Infrastructure

### Scripts

| File | Purpose |
|:-----|:--------|
| `scripts/check_python_sdk_coverage.py` | Compares FFI flows vs Python SDK flows, reports coverage %, supports `--json` and `--strict` |
| `scripts/map_flows_to_suites.py` | Maps FFI flow names to integration test suite names |

### Python Test Files

| File | Purpose |
|:-----|:--------|
| `sdk/python/tests/test_flow_structure.py` | Validates SERVICE_FLOWS registry structure (clients, flows, types) |
| `sdk/python/tests/test_all_flows_smoke.py` | Smoke tests: client instantiation, method existence, flow count |
| `sdk/python/tests/run_flow.py` | Subprocess entry point invoked by Rust `python_executor.rs` via stdin/stdout JSON |

### Rust Harness

| File | Purpose |
|:-----|:--------|
| `crates/internal/integration-tests/src/harness/python_executor.rs` | Python SDK executor: suite mapping, subprocess spawning, JSON protocol |
| `crates/internal/integration-tests/src/harness/sdk_executor.rs` | Rust FFI executor: extended to support all 32 flows |
| `crates/internal/integration-tests/src/bin/python_sdk_test.rs` | CLI binary for running Python SDK tests |

### Test Suites (Phase 4)

New global suites added for dispute and payout flows:

- Dispute: `accept_suite`, `defend_suite`, `submit_evidence_suite`
- Payout: `payout_create_suite`, `payout_create_link_suite`, `payout_create_recipient_suite`, `payout_enroll_disburse_account_suite`, `payout_get_suite`, `payout_stage_suite`, `payout_transfer_suite`, `payout_void_suite`

## Running Tests

### Python SDK structural/smoke tests

```bash
cd sdk/python
python -m pytest tests/test_flow_structure.py tests/test_all_flows_smoke.py -v
```

### Coverage check (script)

```bash
python scripts/check_python_sdk_coverage.py --strict
```

### Python SDK integration tests (via Rust harness)

```bash
# All suites for a connector
make test-python-sdk connector=stripe

# Single suite
make test-python-sdk connector=stripe suite=authorize

# With report generation
make test-python-sdk connector=stripe report=true

# Coverage report only
make check-python-sdk-coverage
```

### Direct binary usage

```bash
cargo run -p integration-tests --bin python_sdk_test -- --all --connector stripe
cargo run -p integration-tests --bin python_sdk_test -- --suite authorize --connector stripe --report
cargo run -p integration-tests --bin python_sdk_test -- --coverage
```

## CI Integration

The `python-sdk-comprehensive-test` job in `.github/workflows/ci.yml` runs:

1. Python SDK structural and smoke tests (`pytest`)
2. Coverage check via `check_python_sdk_coverage.py --strict`
3. Python SDK executor coverage report via `python_sdk_test --coverage`

This job requires the `check` job to pass first and runs on `macos-latest`
with Python 3.11.

## Environment Variables

| Variable | Description | Default |
|:---------|:------------|:--------|
| `CONNECTOR_AUTH_FILE_PATH` | Path to connector credentials JSON | `creds.json` |
| `UCS_CREDS_PATH` | Alternative credentials path | - |
| `UCS_SDK_ENVIRONMENT` | SDK environment (`sandbox`/`production`) | `sandbox` |
| `PYTHON_SDK_INTERPRETER` | Python interpreter for subprocess | `python3` |
