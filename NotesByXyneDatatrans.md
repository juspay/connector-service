# Hyperswitch to UCS Datatrans Connector Conversion Notes

## Conversion Overview
Converting Hyperswitch Datatrans connector to UCS framework with macro-driven implementation.

## Flows to Implement
Based on Hyperswitch analysis:
- Authorize
- PSync 
- Capture
- Void
- Refund
- RSync
- SetupMandate

## Progress Tracking

### ✅ Completed Tasks
- Created conversion tracking document
- Read UCS Implementation Guide
- Fetched Hyperswitch Datatrans implementation
- Analyzed Hyperswitch connector structure

### 🔄 In Progress Tasks
- Extracting key information from Hyperswitch

### ⏳ Pending Tasks
- Update domain types
- Register connector in UCS
- Convert main connector file
- Convert transformers
- Build and test

## Key Information Extracted from Hyperswitch

### Authentication Pattern
```rust
// Datatrans uses Basic Auth with merchant_id:passcode encoded in base64
ConnectorAuthType::BodyKey { api_key, key1 } => {
    merchant_id: key1.clone(),  // key1 = merchant_id
    passcode: api_key.clone(),  // api_key = passcode
}
// Auth header: "Basic {base64(merchant_id:passcode)}"
```

### API Endpoints and Methods
```rust
// Flow -> HTTP Method -> URL Pattern
// Authorize -> POST -> {base_url}v1/transactions (3DS/CIT) OR {base_url}v1/transactions/authorize (Direct/MIT)
// PSync -> GET -> {base_url}v1/transactions/{connector_payment_id}
// Capture -> POST -> {base_url}v1/transactions/{connector_payment_id}/settle
// Void -> POST -> {base_url}v1/transactions/{transaction_id}/cancel
// Refund -> POST -> {base_url}v1/transactions/{transaction_id}/credit
// RSync -> GET -> {base_url}v1/transactions/{connector_refund_id}
// SetupMandate -> POST -> {base_url}v1/transactions
```

### Request/Response Structures
```rust
// Main Request: DatatransPaymentsRequest
// Main Response: DatatransResponse (enum with TransactionResponse/ErrorResponse/ThreeDSResponse)
// Sync Response: DatatransSyncResponse
// Refund Request: DatatransRefundRequest
// Refund Response: DatatransRefundsResponse
// Capture Request: DataPaymentCaptureRequest
// Capture Response: DataTransCaptureResponse
// Cancel Response: DataTransCancelResponse
// Error Response: DatatransErrorResponse
```

### Payment Method Support
```rust
// Supported: Card (Credit/Debit)
// Card Networks: Visa, Mastercard, AmericanExpress, JCB, DinersClub, Discover, UnionPay, Maestro, Interac, CartesBancaires
// Features: 3DS, Mandates, Refunds, Manual/Auto Capture
// Payment Method Data: Card, MandatePayment
```

### Flows Implemented in Hyperswitch
```rust
// ✅ Authorize (PaymentsAuthorizeData -> PaymentsResponseData)
// ✅ PSync (PaymentsSyncData -> PaymentsResponseData) 
// ✅ Capture (PaymentsCaptureData -> PaymentsResponseData)
// ✅ Void (PaymentsCancelData -> PaymentsResponseData)
// ✅ Refund/Execute (RefundsData -> RefundsResponseData)
// ✅ RSync (RefundsData -> RefundsResponseData)
// ✅ SetupMandate (SetupMandateRequestData -> PaymentsResponseData)
// ❌ Session (not implemented)
// ❌ AccessToken (not implemented)
// ❌ PaymentToken (not implemented)
```

## UCS Conversion Mapping

### Data Access Pattern Conversion
```rust
// Hyperswitch pattern → UCS pattern
// item.connector_meta → item.router_data.resource_common_data.connectors.datatrans
// item.request → item.router_data.request
// item.connector_request_reference_id → item.router_data.resource_common_data.connector_request_reference_id
```

### Type Conversion
```rust
// Hyperswitch → UCS
// RouterData<F, T, Req, Res> → RouterDataV2<F, FCD, Req, Res>
// types::PaymentsAuthorizeRouterData → RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
```

## Implementation Notes

### Critical Requirements
1. **Macro-Driven Implementation**: Main datatrans.rs file must use UCS macro framework
2. **Code Reusability**: Create single generic TryFrom for shared responses
3. **Exact Pattern Matching**: Maintain all Hyperswitch functionality in UCS format

### Conversion Challenges
- To be documented as encountered

### Solutions Applied
- To be documented as implemented

## Testing and Validation

### Build Status
- [ ] Initial compilation
- [ ] All flows implemented
- [ ] Tests passing

### Validation Checklist
- [ ] All Hyperswitch flows converted to UCS
- [ ] All request/response structures preserved
- [ ] Authentication patterns working
- [ ] API endpoints and methods maintained
- [ ] Build completes without errors
- [ ] Tests pass for all converted flows

## Next Steps
1. Read UCS Implementation Guide
2. Fetch and analyze Hyperswitch Datatrans implementation
3. Begin UCS conversion process

---
*Last Updated: 2025-09-23*
*Conversion Status: In Progress*