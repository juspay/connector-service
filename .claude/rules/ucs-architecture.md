---
paths:
  - backend/connector-integration/src/connectors/**/*.rs
  - backend/domain_types/src/**/*.rs
---
# UCS Architecture Rules

## CRITICAL: Type Selection

```rust
// ✅ CORRECT - Use V2 types
use domain_types::router_data_v2::RouterDataV2;
use interfaces::connector_integration_v2::ConnectorIntegrationV2;
use domain_types::MinorUnit;

// ❌ WRONG - Legacy types
use hyperswitch_domain_models::RouterData;
use interfaces::ConnectorIntegration;
```

## Generic Connector Pattern

```rust
pub struct ConnectorName<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> {
    _marker: std::marker::PhantomData<T>,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    ConnectorName<T> 
{
    pub fn new() -> Self {
        Self { _marker: std::marker::PhantomData }
    }
}
```

## Mandatory Rules

1. **Reference IDs**: Extract from `router_data.connector_request_reference_id.clone()` - NEVER hardcode or mutate
2. **Amounts**: Use `MinorUnit` type with declared converters - NEVER use `i64` or `f64`
3. **Status Mapping**: Unknown statuses → `Pending` (not `Failure`)
4. **Error Handling**: Use `?` operator - NEVER use `.unwrap()`
5. **PII Fields**: Wrap in `Secret<>` (card numbers, API keys, etc.)
6. **Refund Status**: Parent payment stays `Charged` - only `refund_status` changes

## Status Mapping Pattern

```rust
let status = match response.status.as_str() {
    "success" | "succeeded" | "completed" => enums::AttemptStatus::Charged,
    "authorized" | "requires_capture" => enums::AttemptStatus::Authorized,
    "pending" | "processing" => enums::AttemptStatus::Pending,
    "requires_action" => enums::AttemptStatus::AuthenticationPending,
    "failed" | "declined" => enums::AttemptStatus::Failure,
    _ => enums::AttemptStatus::Pending,  // Unknown → Pending (allows retry)
};
```
