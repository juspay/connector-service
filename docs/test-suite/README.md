<!--
---
title: Test Suite Overview
description: Comprehensive test framework for validating connector functionality across all payment processors with scenario-driven testing and automated reporting
last_updated: 2026-03-12
generated_from: backend/ucs-connector-tests/
auto_generated: false
reviewed_by: engineering
reviewed_at: 2026-03-12
approved: true
---
-->

# Test Suite Overview

## Overview

The Connector Service Test Suite is a developer utility designed to validate connector functionality across all 110+ payment connectors. It uses a scenario-driven approach where test behavior is defined in JSON files, making it easy to add new test cases without modifying code.

**Key Benefits:**
- **Scenario-Driven**: Define tests in JSON, not code
- **Dependency Management**: Automatic handling of test dependencies (e.g., capture requires authorize)
- **Comprehensive Reporting**: Auto-generated markdown reports with test matrices
- **CI/CD Ready**: Snapshot testing strategy for continuous validation
- **Multi-Connector**: Test against all connectors or specific ones

---

## Architecture

The test suite is organized into three layers:

```
┌─────────────────────────────────────────────────────────────┐
│                     Test Definitions                        │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐        │
│  │ scenario.json│ │ suite_spec   │ │ connector    │        │
│  │ (test cases) │ │ .json        │ │ _spec.json   │        │
│  └──────────────┘ └──────────────┘ └──────────────┘        │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Test Harness                             │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐        │
│  │   Loader     │ │  Executor    │ │   Server     │        │
│  │(scenario_    │ │(gRPC calls)  │ │  (UCS spawn) │        │
│  │ loader.rs)   │ │              │ │              │        │
│  └──────────────┘ └──────────────┘ └──────────────┘        │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐        │
│  │   Assert     │ │ Credentials  │ │   Report     │        │
│  │(scenario_    │ │   (auth      │ │  Generator   │        │
│  │ _assert.rs)  │ │   loading)   │ │              │        │
│  └──────────────┘ └──────────────┘ └──────────────┘        │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Output Artifacts                         │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐        │
│  │ report.json  │ │test_report   │ │ Connector    │        │
│  │ (raw data)   │ │   .md        │ │   reports    │        │
│  └──────────────┘ └──────────────┘ └──────────────┘        │
└─────────────────────────────────────────────────────────────┘
```

### Core Components

| Component | File | Purpose |
|-----------|------|---------|
| **Scenario Loader** | `harness/scenario_loader.rs` | Loads and validates scenario JSON files |
| **Executor** | `harness/executor.rs` | Spawns UCS server and executes gRPC calls |
| **Assertion Engine** | `harness/scenario_assert.rs` | Validates responses against assert rules |
| **Report Generator** | `harness/report.rs` | Generates JSON and markdown test reports |
| **Credentials** | `harness/credentials.rs` | Loads connector authentication from environment |
| **Metadata** | `harness/metadata.rs` | Adds connector metadata to gRPC requests |

---

## Test Structure

### Scenario Definition

Each test scenario is defined in a `scenario.json` file within a suite directory:

```json
{
  "no3ds_auto_capture_credit_card": {
    "grpc_req": {
      "merchant_transaction_id": {"id": "auto_generate"},
      "amount": {"minor_amount": 6000, "currency": "USD"},
      "payment_method": {
        "card": {
          "card_number": {"value": "4111111111111111"},
          "card_exp_month": {"value": "08"},
          "card_exp_year": {"value": "30"},
          "card_cvc": {"value": "999"},
          "card_type": "credit"
        }
      },
      "capture_method": "AUTOMATIC"
    },
    "assert": {
      "status": {"equals": "SUCCESS"},
      "connector_response": {"must_exist": true},
      "error_message": {"must_not_exist": true}
    },
    "is_default": true
  }
}
```

### Suite Specification

Each suite has a `suite_spec.json` defining dependencies and metadata:

```json
{
  "suite": "authorize",
  "suite_type": "dependent",
  "depends_on": ["create_access_token", "create_customer"],
  "strict_dependencies": false
}
```

| Field | Description |
|-------|-------------|
| `suite` | Suite name (must match directory name) |
| `suite_type` | `independent` or `dependent` |
| `depends_on` | List of suites that must run first |
| `strict_dependencies` | If true, fail if dependencies are not met |

### Supported Test Suites

| Suite | Service | Description | Dependencies |
|-------|---------|-------------|--------------|
| **authorize** | PaymentService/Authorize | Payment authorization | create_access_token, create_customer |
| **capture** | PaymentService/Capture | Capture authorized payments | authorize |
| **void** | PaymentService/Void | Void authorized payments | authorize |
| **refund** | PaymentService/Refund | Refund captured payments | capture |
| **get** | PaymentService/Get | Retrieve payment status | authorize |
| **create_access_token** | MerchantAuthenticationService | Create authentication tokens | none |
| **create_customer** | CustomerService/Create | Create customer profiles | create_access_token |
| **setup_recurring** | PaymentService/SetupRecurring | Setup recurring mandates | authorize |
| **recurring_charge** | RecurringPaymentService/Charge | Charge using mandate | setup_recurring |
| **refund_sync** | RefundService/Get | Sync refund status | refund |

---

## Assertion Types

The test framework supports flexible assertion rules for validating responses:

| Assertion | JSON Format | Description |
|-----------|-------------|-------------|
| **Must Exist** | `{"must_exist": true}` | Field must be present in response |
| **Must Not Exist** | `{"must_not_exist": true}` | Field must be absent from response |
| **Equals** | `{"equals": "value"}` | Field must equal specific value |
| **One Of** | `{"one_of": ["A", "B"]}` | Field must match one of the values |
| **Contains** | `{"contains": "substring"}` | String field must contain substring |
| **Echo** | `{"echo": "field_name"}` | Field must match value from request |

### Assertion Examples

```json
{
  "assert": {
    "status": {"equals": "SUCCESS"},
    "connector_transaction_id": {"must_exist": true},
    "error_code": {"must_not_exist": true},
    "payment_method_type": {"one_of": ["credit", "debit"]},
    "error_message": {"contains": "declined"},
    "merchant_transaction_id": {"echo": "merchant_transaction_id"}
  }
}
```

---

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `CONNECTOR_AUTH_FILE_PATH` | Yes | Path to connector credentials JSON file |
| `UCS_CREDS_PATH` | Alternative | Alternative path for credentials |
| `UCS_SCENARIO_ROOT` | No | Override scenario files location |
| `UCS_RUN_TEST_REPORT_PATH` | No | Custom report output path |
| `UCS_ALL_CONNECTORS` | No | Comma-separated list of connectors to test |

### Connector Credentials Format

```json
{
  "stripe": {
    "api_key": "sk_test_...",
    "api_secret": "..."
  },
  "adyen": {
    "api_key": "...",
    "merchant_account": "..."
  }
}
```

### Connector Specification

Optional per-connector configuration in `src/connector_specs/{connector}.json`:

```json
{
  "connector": "stripe",
  "supported_suites": ["authorize", "capture", "void", "refund", "get"]
}
```

---

## Usage

### Running Tests

```bash
# Test specific connector
cargo run --bin run_test -- --connector stripe

# Test all connectors
cargo run --bin suite_run_test -- --all

# Run specific suite
cargo run --bin run_test -- --connector stripe --suite authorize

# Run specific scenario
cargo run --bin run_test -- --connector stripe --suite authorize --scenario no3ds_auto_capture_credit_card
```

### Output Location

Reports are generated in the configured output directory (default: `backend/ucs-connector-tests/`):

```
backend/ucs-connector-tests/
├── report.json              # Machine-readable test results
├── test_report.md           # Human-readable markdown report
└── docs/test-reports/       # Historical reports
    ├── stripe-report.md
    ├── adyen-report.md
    └── ...
```

---

## CI/CD Integration

### Snapshot Testing Strategy

The test suite uses a snapshot testing approach for CI/CD:

1. **Main Branch**: Maintains a certified snapshot of test results
2. **Pull Requests**: Validate against the snapshot (no live transactions during PR)
3. **Post-Merge**: Live transaction tests run to generate new snapshot
4. **Results**: Committed to repository (excluding credentials) in the docs section

### Pipeline Flow

```
Pull Request                    Main Branch (post-merge)
     │                                   │
     ▼                                   ▼
┌──────────┐                    ┌──────────────────┐
│ Checkout │                    │ Checkout         │
│ code     │                    │ merged code      │
└────┬─────┘                    └──────┬───────────┘
     │                                 │
     ▼                                 ▼
┌──────────┐                    ┌──────────────────┐
│ Run tests│                    │ Run tests with   │
│ against  │                    │ LIVE connectors  │
│ snapshot │                    │                  │
└────┬─────┘                    └──────┬───────────┘
     │                                 │
     ▼                                 ▼
┌──────────┐                    ┌──────────────────┐
│ Compare  │                    │ Generate new     │
│ results  │                    │ snapshot         │
└────┬─────┘                    └──────┬───────────┘
     │                                 │
     ▼                                 ▼
┌──────────┐                    ┌──────────────────┐
│ Pass/Fail│                    │ Commit snapshot  │
│ PR       │                    │ to repository    │
└──────────┘                    └──────────────────┘
```

### GitHub Actions Integration

```yaml
name: Connector Tests
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run connector tests
        env:
          CONNECTOR_AUTH_FILE_PATH: ${{ secrets.CONNECTOR_AUTH_FILE_PATH }}
        run: cargo run --bin suite_run_test -- --all
      - name: Upload reports
        uses: actions/upload-artifact@v4
        with:
          name: test-reports
          path: backend/ucs-connector-tests/test_report.md
```

---

## Report Structure

Generated markdown reports include:

### Summary Section
- Total connectors tested
- Total scenarios executed
- Pass/fail counts
- Overall pass rate percentage

### Scenario Performance Matrix
- Per-scenario breakdown
- Service and payment method information
- Connectors tested per scenario
- Individual pass/fail counts

### Test Matrix
- Complete grid of all scenarios vs connectors
- PASS/FAIL status for each cell
- Sorted by suite order (authorize → capture → void → refund → ...)

---

## Best Practices

### Writing Test Scenarios

1. **Use `auto_generate` for dynamic values**: Transaction IDs, customer emails, timestamps
2. **Set `is_default: true`**: Mark the primary scenario for each suite
3. **Keep assertions focused**: Test only what matters for the specific operation
4. **Use specific test cards**: Follow payment processor test card guidelines
5. **Document edge cases**: Add comments for special handling

### Managing Dependencies

1. **Order matters**: Define dependencies in the correct sequence
2. **Reuse dependencies**: Use `depends_on` to chain related tests
3. **Loose coupling**: Use `strict_dependencies: false` for optional dependencies

### Credential Management

1. **Never commit credentials**: Use environment variables or secrets
2. **Use test environments**: Always test against sandbox/test endpoints
3. **Rotate regularly**: Update API keys periodically

---

## Next Steps

- [Test Scenarios](./scenarios/README.md) - Detailed scenario documentation
- [Connector Specifications](./connectors/README.md) - Per-connector test coverage
- [Report Examples](./reports/README.md) - Sample test reports
- [CI/CD Setup](./ci-cd.md) - Complete pipeline configuration
