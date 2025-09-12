# Hyperswitch to UCS Connector Conversion Notes - Rapyd

## Conversion Overview
- **Source**: Hyperswitch Rapyd connector
- **Target**: UCS connector implementation
- **Base URL**: https://sandboxapi.rapyd.net
- **Flows to implement**: Authorize, Capture, PSync, Void, Refund, RSync

## Progress Tracking

### ✅ Completed Tasks
- Created tracking document
- Read UCS Implementation Guide
- Fetch Hyperswitch implementation
- Analyze and extract key information
- Update domain types with Rapyd connector
- Register connector in UCS types
- Update configuration files
- Convert main connector file to UCS patterns
- Convert transformers to UCS patterns
- Build and test the conversion

### 🔄 In Progress Tasks
- None

### ⏳ Pending Tasks
- None

## Key Information Extracted from Hyperswitch

### Authentication Pattern
```rust
// Rapyd uses BodyKey auth with access_key and secret_key
// Custom signature generation with HMAC-SHA256
pub struct RapydAuthType {
    pub access_key: Secret<String>,
    pub secret_key: Secret<String>,
}

// Auth headers: access_key, salt, timestamp, signature
// Signature = base64(hmac_sha256(secret_key, "method+path+salt+timestamp+access_key+secret_key+body"))
```

### API Endpoints and Methods
```rust
// Extracted from Hyperswitch implementation:
// Authorize -> POST -> /v1/payments
// Capture -> POST -> /v1/payments/{id}/capture  
// PSync -> GET -> /v1/payments/{id}
// Void -> DELETE -> /v1/payments/{id}
// Refund (Execute) -> POST -> /v1/refunds
// RSync -> GET -> /v1/refunds/{id} (uses default implementation)
```

### Request/Response Structures
```rust
// Main request/response types:
// - RapydPaymentsRequest (for Authorize)
// - RapydPaymentsResponse (for Authorize, Capture, PSync, Void)
// - CaptureRequest (for Capture)
// - RapydRefundRequest (for Refund)
// - RefundResponse (for Refund, RSync)
```

### Payment Method Support
```rust
// Supported payment methods:
// - Card (Credit/Debit) with 3DS support
// - Apple Pay wallet
// - Google Pay wallet
// - Currency unit: Base (not Minor)
// - Amount converter: FloatMajorUnit
```

### Supported Flows
- [x] Authorize - POST /v1/payments
- [x] Capture - POST /v1/payments/{id}/capture
- [x] PSync - GET /v1/payments/{id}
- [x] Void - DELETE /v1/payments/{id}
- [x] Refund (Execute) - POST /v1/refunds
- [x] RSync - GET /v1/refunds/{id} (default implementation)
- [ ] SetupMandate - Not implemented (returns error)
- [x] Webhooks - Supported for payments, refunds, disputes

## Conversion Notes

### Critical Patterns to Convert
1. **Data Access Pattern**: `item.request` → `item.router_data.request`
2. **Type Conversion**: `RouterData<F, T, Req, Res>` → `RouterDataV2<F, FCD, Req, Res>`
3. **Macro Conversion**: Hyperswitch macros → UCS macros

### Files Created/Modified
- [x] `backend/domain_types/src/connector_types.rs` - Added Rapyd enum
- [x] `backend/domain_types/src/types.rs` - Added Rapyd connector params
- [x] `backend/connector-integration/src/types.rs` - Registered connector
- [x] `config/development.toml` - Added configuration
- [x] `backend/connector-integration/src/connectors.rs` - Module declaration
- [x] `backend/connector-integration/src/connectors/rapyd.rs` - Main connector
- [x] `backend/connector-integration/src/connectors/rapyd/transformers.rs` - Transformers

## Issues and Solutions
- Successfully converted all Hyperswitch patterns to UCS
- Maintained exact API endpoints and authentication from Hyperswitch
- Preserved all payment method support (Card, Apple Pay, Google Pay)
- Converted all 6 flows: Authorize, Capture, PSync, Void, Refund, RSync

## Next Steps
1. Read UCS implementation guide
2. Fetch Hyperswitch Rapyd implementation
3. Extract and document all key patterns
4. Begin systematic conversion

---
*Last updated: 2025-09-12*