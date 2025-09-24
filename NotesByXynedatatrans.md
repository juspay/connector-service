# Datatrans Connector Conversion Notes

## Project Overview
Converting Hyperswitch datatrans connector to UCS (Unified Connector Service) format.

**Target Flows**: Authorize, Capture, Execute, PSync, RSync, SetupMandate, Void
**Base URL**: https://api.sandbox.datatrans.com/

## Conversion Progress

### Phase 1: Analysis and Setup
- [ ] Read UCS Implementation Guide
- [ ] Fetch Hyperswitch datatrans connector implementation
- [ ] Extract authentication patterns
- [ ] Extract API endpoints and methods
- [ ] Extract request/response structures
- [ ] Extract payment method support

### Phase 2: UCS Project Setup
- [ ] Update domain_types/src/connector_types.rs
- [ ] Register connector in connector-integration/src/types.rs
- [ ] Update config/development.toml
- [ ] Add module declaration in connectors.rs

### Phase 3: Core Conversion
- [ ] Convert main connector file (datatrans.rs)
- [ ] Convert transformers (datatrans/transformers.rs)
- [ ] Implement all required flows
- [ ] Convert authentication patterns
- [ ] Convert error handling

### Phase 4: Testing and Validation
- [ ] Build and fix compilation errors
- [ ] Test basic functionality
- [ ] Validate all flows work correctly

## Key Hyperswitch Information (Extracted)

### Authentication Pattern
```rust
// Basic Auth with merchant_id:passcode encoded in base64
pub struct DatatransAuthType {
    pub(super) merchant_id: Secret<String>,
    pub(super) passcode: Secret<String>,
}

// From ConnectorAuthType::BodyKey { api_key, key1 }
// key1 = merchant_id, api_key = passcode
```

### API Endpoints
```rust
// Base URL: https://api.sandbox.datatrans.com/
// Authorize: {base_url}v1/transactions/authorize (direct) or {base_url}v1/transactions (3DS/mandate)
// Capture: {base_url}v1/transactions/{transaction_id}/settle
// Void: {base_url}v1/transactions/{transaction_id}/cancel
// PSync: {base_url}v1/transactions/{transaction_id}
// Refund: {base_url}v1/transactions/{transaction_id}/credit
// RSync: {base_url}v1/transactions/{refund_id}
// SetupMandate: {base_url}v1/transactions
```

### Request/Response Structures
```rust
// Main request struct
pub struct DatatransPaymentsRequest {
    pub amount: Option<MinorUnit>,
    pub currency: enums::Currency,
    pub card: DataTransPaymentDetails,
    pub refno: String,
    pub auto_settle: bool,
    pub redirect: Option<RedirectUrls>,
    pub option: Option<DataTransCreateAlias>,
}

// Main response struct
pub enum DatatransResponse {
    TransactionResponse(DatatransSuccessResponse),
    ErrorResponse(DatatransError),
    ThreeDSResponse(Datatrans3DSResponse),
}

// Sync response
pub enum DatatransSyncResponse {
    Error(DatatransError),
    Response(SyncResponse),
}

// Refund request/response
pub struct DatatransRefundRequest {
    pub amount: MinorUnit,
    pub currency: enums::Currency,
    pub refno: String,
}

pub enum DatatransRefundsResponse {
    Success(DatatransSuccessResponse),
    Error(DatatransError),
}

// Capture request
pub struct DataPaymentCaptureRequest {
    pub amount: MinorUnit,
    pub currency: enums::Currency,
    pub refno: String,
}
```

### Payment Methods Supported
- [x] Cards (Credit/Debit)
- [x] 3DS Authentication
- [x] Mandate Payments
- [ ] Other methods (Not supported in Hyperswitch)

### Flows Implemented in Hyperswitch
- [x] Authorize
- [x] Capture  
- [x] Void
- [x] PSync
- [x] RSync
- [x] Execute (Refund)
- [x] SetupMandate
- [ ] Execute flow (not found - using Refund flow instead)

## UCS Conversion Patterns

### Data Access Conversions
```rust
// Hyperswitch → UCS
item.connector_meta → item.router_data.resource_common_data.connectors.datatrans
item.request → item.router_data.request
item.connector_request_reference_id → item.router_data.resource_common_data.connector_request_reference_id
```

### Type Conversions
```rust
// Hyperswitch → UCS
RouterData<F, T, Req, Res> → RouterDataV2<F, FCD, Req, Res>
types::PaymentsAuthorizeRouterData → RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
```

## Issues and Solutions
(To be documented as they arise)

## Final Checklist
- [ ] All flows implemented: Authorize, Capture, Execute, PSync, RSync, SetupMandate, Void
- [ ] Authentication working
- [ ] Error handling implemented
- [ ] Build successful
- [ ] Tests passing

---
*Last updated: 2025-09-24*