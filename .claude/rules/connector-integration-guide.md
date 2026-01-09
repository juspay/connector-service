---
paths:
  - backend/connector-integration/src/connectors/**/*.rs
  - backend/domain_types/src/**/*.rs
---
# Connector Integration Guide

This guide serves as the central reference for the entire connector integration lifecycle.

## 1. Flow Identification

| Flow | Semantic Meaning | Key I/O |
|------|------------------|---------|
| **Authorize** | Verifies payment details and reserves funds | Card/Token/Amount → Transaction ID |
| **Capture** | Captures previously authorized funds | Payment ID → Status |
| **Void** | Cancels an authorized but uncaptured payment | Payment ID → Status |
| **Refund** | Returns funds to the customer | Payment ID/Amount → Refund ID |
| **PSync** | Retrieves payment status | Payment ID → Status |
| **RSync** | Retrieves refund status | Refund ID → Status |
| **CreateAccessToken** | Retrieves API access token | Auth Credentials → Token |

## 2. File Structure Pattern

```
backend/connector-integration/src/
├── connectors.rs              # Add module declaration
├── connectors/
│   └── <connector_name>.rs    # Main connector implementation
│   └── <connector_name>/
│       └── transformers.rs    # Request/response transformers
├── types.rs                   # Add connector type alias

backend/domain_types/src/
├── connector_types.rs         # Add connector enum variant
├── types.rs                   # Add connector config

config/
├── development.toml           # Add base_url
├── production.toml            # Add base_url
├── sandbox.toml               # Add base_url
```

## 3. Core UCS Architecture Rules

### CRITICAL: Types to Use

```rust
// ✅ CORRECT
use domain_types::router_data_v2::RouterDataV2;
use interfaces::connector_integration_v2::ConnectorIntegrationV2;
use domain_types::MinorUnit;  // For all amount fields

// ❌ WRONG - Never use these
use hyperswitch_domain_models::RouterData;  // Legacy
use interfaces::ConnectorIntegration;       // Legacy
pub amount: i64;  // Use MinorUnit instead
pub amount: f64;  // Never use floats for money
```

### Generic Connector Struct

```rust
pub struct ConnectorName<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> {
    _marker: std::marker::PhantomData<T>,
}
```

## 4. Macro Framework

### Prerequisites Setup
```rust
macros::create_all_prerequisites!(
    connector_name: ConnectorName,
    generic_type: T,
    api: [
        (flow: Authorize, ...),
        (flow: Capture, ...),
    ],
    amount_converters: [amount_converter: StringMinorUnit],
    member_functions: { ... }
);
```

### Flow Implementation
```rust
macros::macro_connector_implementation!(
    connector: ConnectorName,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    // ...
);
```

## 5. Quality Checklist

Before submitting, ensure:

- [ ] Using `RouterDataV2` (not `RouterData`)
- [ ] Using `ConnectorIntegrationV2` (not `ConnectorIntegration`)
- [ ] All amounts use `MinorUnit` type
- [ ] Amount converters declared (not empty)
- [ ] Currency uses `common_enums::Currency` enum
- [ ] Reference IDs extracted from router_data (never hardcoded/mutated)
- [ ] No `unwrap()` - use `?` operator
- [ ] PII fields wrapped in `Secret<>`
- [ ] Production URL differs from sandbox in config
