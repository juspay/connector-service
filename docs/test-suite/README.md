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

## Global Test Suites

### What Are Global Suites?

**Global suites** are reusable test scenarios stored in `src/global_suites/` that can be executed against any connector. They define the "happy path" and common edge cases for each payment operation, providing a standardized way to test connector functionality across all 110+ payment processors.

**Key Concept**: Write once, run everywhere. A single global suite scenario can validate Stripe, Adyen, PayPal, and all other connectors that support that operation.

### Directory Structure

```
backend/ucs-connector-tests/src/global_suites/
├── authorize_suite/
│   ├── scenario.json          # Test cases for authorization
│   └── suite_spec.json        # Suite metadata and dependencies
├── capture_suite/
│   ├── scenario.json
│   └── suite_spec.json
├── void_suite/
├── refund_suite/
├── get_suite/
├── create_access_token_suite/
├── create_customer_suite/
├── setup_recurring_suite/
├── recurring_charge_suite/
└── refund_sync_suite/
```

### Suite Types

| Type | Description | Example |
|------|-------------|---------|
| **Independent** | No dependencies, can run standalone | `create_access_token` |
| **Dependent** | Requires other suites to run first | `authorize` depends on `create_access_token` |

### Suite Specification Format

Each suite includes a `suite_spec.json` defining its behavior:

```json
{
  "suite": "capture",
  "suite_type": "dependent",
  "depends_on": ["authorize"],
  "strict_dependencies": true
}
```

| Field | Description |
|-------|-------------|
| `suite` | Suite name (matches directory) |
| `suite_type` | `independent` or `dependent` |
| `depends_on` | Array of suite names that must complete first |
| `strict_dependencies` | If `true`, fail if dependencies fail; if `false`, continue anyway |

### Dependency Pipeline

When running dependent suites, the test harness automatically:

1. **Executes dependencies first**: Runs `create_access_token` → `create_customer` → `authorize`
2. **Captures context**: Stores response values (transaction IDs, customer IDs) from each step
3. **Injects into requests**: Automatically populates dependent request fields like `connector_transaction_id`
4. **Prunes unresolved fields**: Removes context fields that couldn't be resolved

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ create_access_  │────▶│   authorize     │────▶│    capture      │
│     token       │     │                 │     │                 │
└────────┬────────┘     └────────┬────────┘     └─────────────────┘
         │                       │
         │ access_token          │ connector_transaction_id
         ▼                       ▼
    Injected into           Injected into
    authorize request       capture request
```

---

## Test Data Configuration

### Test Data Locations

Test data is configured across three locations:

| Location | Purpose | Example Files |
|----------|---------|---------------|
| **Global Suites** | Reusable scenarios for all connectors | `src/global_suites/*/scenario.json` |
| **Connector Specs** | Per-connector suite configuration | `src/connector_specs/{connector}.json` |
| **Credentials** | API keys and authentication secrets | External JSON file (via env var) |

### Global Suite Data (`scenario.json`)

Each scenario defines:

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
          "card_holder_name": {"value": "auto_generate"},
          "card_type": "credit"
        }
      },
      "capture_method": "AUTOMATIC"
    },
    "assert": {
      "status": {"one_of": ["CHARGED", "AUTHORIZED"]},
      "connector_transaction_id": {"must_exist": true},
      "error": {"must_not_exist": true}
    },
    "is_default": true
  }
}
```

### Auto-Generated Values

Use `"auto_generate"` for dynamic test data:

| Field Type | Generated Format | Example |
|------------|------------------|---------|
| Transaction IDs | `{prefix}_{uuid}` | `mti_a1b2c3d4` |
| Customer Emails | `{name}.{number}@{domain}` | `alex.1234@example.com` |
| Phone Numbers | `{country_code}{number}` | `+15551234567` |
| Names | Random first/last name | `Emma Johnson` |
| Addresses | Realistic street address | `123 Main St` |

**Deferred Fields** (not auto-generated, resolved from dependencies):
- `connector_customer_id`
- `connector_transaction_id`
- `access_token`
- `refund_id`

### Connector Specifications (`connector_specs/`)

Define which suites each connector supports:

```json
{
  "connector": "stripe",
  "supported_suites": [
    "authorize",
    "capture",
    "void",
    "refund",
    "get",
    "refund_sync"
  ]
}
```

**Purpose**:
- Skip unsupported suites during `--all` runs
- Document connector capabilities
- Enable gradual rollout of new tests

---

## Credentials Configuration

### Credentials File Location

Connector credentials are loaded from a JSON file specified via environment variable:

```bash
# Primary method
export CONNECTOR_AUTH_FILE_PATH=/path/to/creds.json

# Alternative
export UCS_CREDS_PATH=/path/to/creds.json

# Default fallback
# backend/.github/test/creds.json
```

### Credentials File Format

```json
{
  "stripe": {
    "connector_account_details": {
      "auth_type": "HeaderKey",
      "api_key": "sk_test_..."
    }
  },
  "adyen": {
    "connector_account_details": {
      "auth_type": "SignatureKey",
      "api_key": "...",
      "key1": "...",
      "api_secret": "..."
    }
  },
  "braintree": {
    "connector_1": {
      "connector_account_details": {
        "auth_type": "BodyKey",
        "api_key": "...",
        "key1": "..."
      }
    }
  }
}
```

### Authentication Types

| Type | Fields | Use Case |
|------|--------|----------|
| **HeaderKey** | `api_key` | Stripe, simple API keys |
| **BodyKey** | `api_key`, `key1` | Braintree, key pairs |
| **SignatureKey** | `api_key`, `key1`, `api_secret` | Adyen, signed requests |

### Multiple Connector Configurations

For connectors with multiple accounts (sandbox, production, different regions):

```json
{
  "cybersource": {
    "connector_1": {
      "connector_account_details": { ... }
    },
    "connector_2": {
      "connector_account_details": { ... }
    }
  }
}
```

Select via environment variable:
```bash
export UCS_CONNECTOR_LABEL_CYBERSOURCE=connector_2
```

---

## Overrides

### What Are Overrides?

**Overrides** allow customizing global suite scenarios for specific connectors or edge cases without modifying the base scenario files. They enable:

- Connector-specific request modifications (e.g., different test card numbers)
- Connector-specific assertion adjustments (e.g., different error message formats)
- Edge case handling (e.g., specific decline codes)

### Override Types

| Type | Purpose | Location |
|------|---------|----------|
| **Request Override** | Modify request payload fields | Planned: `src/overrides/{connector}/{suite}.json` |
| **Assert Override** | Modify assertion rules | Planned: `src/overrides/{connector}/{suite}.json` |
| **Dependency Override** | Override specific dependency scenario | `suite_spec.json` `depends_on` with scenario name |

### Request Override (Planned)

```json
{
  "scenario_name": "no3ds_auto_capture_credit_card",
  "request_override": {
    "payment_method.card.card_number.value": "4000000000003220"
  },
  "assert_override": {
    "status": {
      "remove": ["equals"],
      "add": { "one_of": ["AUTHENTICATION_FAILED", "DECLINED"] }
    }
  }
}
```

### Dependency Scenario Override

Reference a specific scenario from a dependency suite:

```json
{
  "suite": "capture",
  "suite_type": "dependent",
  "depends_on": [
    {
      "suite": "authorize",
      "scenario": "no3ds_manual_capture_credit_card"
    }
  ]
}
```

This runs the `no3ds_manual_capture_credit_card` scenario from the authorize suite before capture.

### Assert Override Strategy

Assert overrides use a **merge strategy** with the base assertions:

1. Start with base assertions from global suite
2. Apply connector-specific additions
3. Remove overridden fields
4. Execute merged assertions

```rust
// Pseudo-code for assert merging
fn merge_asserts(base: AssertMap, override: AssertMap) -> AssertMap {
    let mut merged = base.clone();
    for (field, rules) in override {
        if rules.remove_all {
            merged.remove(&field);
        } else {
            merged.insert(field, rules);
        }
    }
    merged
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
