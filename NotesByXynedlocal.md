# Hyperswitch to UCS Connector Conversion Notes - dlocal

## Conversion Overview
Converting the dlocal connector from Hyperswitch to UCS architecture.

## Flows to Implement
Based on Hyperswitch analysis: Authorize, PSync, Capture, Void, Refund (Execute), RSync

## Key Conversion Progress

### Step 1: Analysis Phase
- [x] Read UCS Implementation Guide
- [x] Fetch Hyperswitch dlocal connector implementation
- [x] Extract authentication patterns
- [x] Extract API endpoints and methods
- [x] Extract request/response structures
- [x] Extract payment method support

### Step 2: UCS Project Setup
- [ ] Update domain types (connector_types.rs)
- [ ] Register connector in UCS (types.rs)
- [ ] Update configuration (development.toml)

### Step 3: Hyperswitch to UCS Conversion
- [ ] Convert main connector file
- [ ] Convert transformers
- [ ] Convert auth patterns
- [ ] Convert request/response structures
- [ ] Convert flow implementations

### Step 4: Testing and Validation
- [ ] Build without errors
- [ ] Test basic functionality
- [ ] Validate all flows work

## Key Hyperswitch Patterns Found

### Authentication Pattern
```rust
// SignatureKey with HMAC-SHA256 signing
pub struct DlocalAuthType {
    pub(super) x_login: Secret<String>,
    pub(super) x_trans_key: Secret<String>, 
    pub(super) secret: Secret<String>,
}

// Headers: Authorization (V2-HMAC-SHA256), X-Login, X-Trans-Key, X-Version, X-Date
```

### API Endpoints
```rust
// Base URL from connectors config
// Authorize: POST {base_url}secure_payments
// PSync: GET {base_url}payments/{id}/status
// Capture: POST {base_url}payments
// Void: POST {base_url}payments/{id}/cancel
// Refund: POST {base_url}refunds
// RSync: GET {base_url}refunds/{id}/status
```

### Request/Response Structures
```rust
// Main request: DlocalPaymentsRequest
// Main response: DlocalPaymentsResponse
// Sync request: DlocalPaymentsSyncRequest (URL param only)
// Capture request: DlocalPaymentsCaptureRequest
// Cancel request: DlocalPaymentsCancelRequest (URL param only)
// Refund request: DlocalRefundRequest
// Refund sync: DlocalRefundsSyncRequest (URL param only)
```

### Payment Method Support
```rust
// Supports: Card (Credit/Debit)
// Card networks: Visa, Mastercard, Amex, Discover, JCB, DinersClub, UnionPay, Interac, CartesBancaires
// Features: 3DS, Manual/Auto capture, Refunds
// Currency: Minor units
```

## UCS Conversion Mappings

### Data Access Pattern Conversions
```rust
// Hyperswitch → UCS
// item.connector_meta → item.router_data.resource_common_data.connectors.dlocal
// item.request → item.router_data.request
// item.connector_request_reference_id → item.router_data.resource_common_data.connector_request_reference_id
```

### Type Conversions
```rust
// Hyperswitch → UCS
// RouterData<F, T, Req, Res> → RouterDataV2<F, FCD, Req, Res>
// types::PaymentsAuthorizeRouterData → RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
```

## Issues Encountered
(To be documented during conversion)

## Resolution Notes
(To be documented during conversion)

## Final Status
- [ ] Conversion Complete
- [ ] All Tests Passing
- [ ] Ready for Production

---
*Last Updated: 2025-09-11*
*Conversion Status: In Progress*