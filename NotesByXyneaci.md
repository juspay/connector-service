# Hyperswitch to UCS Connector Conversion Notes - ACI

## Conversion Progress Tracker

### ✅ Completed Tasks
- [x] Created tracking document

### 🔄 In Progress Tasks
- [x] Reading UCS Implementation Guide
- [x] Fetching Hyperswitch ACI implementation
- [x] Analyze Hyperswitch connector patterns

### 📋 Pending Tasks
- [ ] Update domain types
- [ ] Register connector in UCS
- [ ] Update configuration
- [ ] Convert main connector file
- [ ] Convert transformers
- [ ] Build and test

## Flows to Implement
Based on Hyperswitch analysis: Authorize, PSync, Capture, Void, Refund, SetupMandate

## Key Information Extracted from Hyperswitch

### Authentication Pattern
```rust
// Hyperswitch uses BodyKey auth with api_key and entity_id
pub struct AciAuthType {
    pub api_key: Secret<String>,
    pub entity_id: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for AciAuthType {
    fn try_from(item: &ConnectorAuthType) -> Result<Self, Self::Error> {
        if let ConnectorAuthType::BodyKey { api_key, key1 } = item {
            Ok(Self {
                api_key: api_key.to_owned(),
                entity_id: key1.to_owned(),
            })
        } else {
            Err(errors::ConnectorError::FailedToObtainAuthType)?
        }
    }
}

// Auth header: Bearer {api_key}
```

### API Endpoints and Methods
```rust
// Authorize: POST {base_url}v1/payments (or v1/registrations/{mandate_id}/payments for mandates)
// PSync: GET {base_url}v1/payments/{connector_transaction_id}?entityId={entity_id}
// Capture: POST {base_url}v1/payments/{connector_transaction_id}
// Void: POST {base_url}v1/payments/{connector_transaction_id}
// Refund: POST {base_url}v1/payments/{connector_payment_id}
// SetupMandate: POST {base_url}v1/registrations
```

### Request/Response Structures
```rust
// Main request struct
pub struct AciPaymentsRequest {
    #[serde(flatten)]
    pub txn_details: TransactionDetails,
    #[serde(flatten)]
    pub payment_method: PaymentDetails,
    #[serde(flatten)]
    pub instruction: Option<Instruction>,
    pub shopper_result_url: Option<String>,
}

// Main response struct
pub struct AciPaymentsResponse {
    id: String,
    registration_id: Option<Secret<String>>,
    ndc: String,
    timestamp: String,
    build_number: String,
    pub(super) result: ResultCode,
    pub(super) redirect: Option<AciRedirectionData>,
}

// Error response
pub struct AciErrorResponse {
    ndc: String,
    timestamp: String,
    build_number: String,
    pub(super) result: ResultCode,
}
```

### Payment Method Support
```rust
// Supported payment methods from Hyperswitch:
// - Cards (Visa, Mastercard, AmEx, JCB, DinersClub, Discover, UnionPay, Maestro)
// - Wallets (MbWay, AliPay)
// - Bank Redirects (EPS, EFT, Ideal, Giropay, Sofort, Interac, Przelewy24, Trustly)
// - Pay Later (Klarna)
// - Network Tokens
// - Mandate Payments
```

## UCS Conversion Mappings

### Data Access Pattern Conversions
```rust
// Hyperswitch → UCS mappings will be documented here
```

### Type Conversions
```rust
// Type mapping documentation will be added here
```

### Critical Notes
- Exact connector name from Hyperswitch: "aci"
- Base URL pattern: {base_url} (from connectors config)
- Supported flows: Authorize, PSync, Capture, Void, Refund, SetupMandate
- HTTP methods per flow:
  - Authorize: POST
  - PSync: GET
  - Capture: POST
  - Void: POST
  - Refund: POST
  - SetupMandate: POST
- Content-Type: application/x-www-form-urlencoded
- Currency Unit: Base (StringMajorUnit)
- Amount Converter: StringMajorUnitForConnector

## Issues and Resolutions
- [ ] Document any compilation errors and fixes
- [ ] Note any missing dependencies
- [ ] Track any API differences between Hyperswitch and UCS

## Testing Notes
- [ ] Build status
- [ ] Test results
- [ ] Integration test outcomes

---
*Last updated: 2025-09-17*