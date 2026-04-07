# Proto Interface Validation Analysis

## Document Information
- **Version**: 5.0.0
- **Date**: 2026-04-07
- **Status**: Final - Corrections Applied
- **Scope**: Validated fraud.proto against Signifyd and Riskified APIs with corrections applied

## Executive Summary

This document validates the fraud interface proto specification against Signifyd and Riskified APIs. **Several corrections have been applied** based on actual API documentation.

### Critical Corrections Applied

1. ✅ **Signifyd Endpoints**: Added `/v3/orders/events/` prefix to all endpoints
2. ✅ **Required Fields**: Added `checkout_id`, `purchase` object with `created_at`, `order_channel`, `products`
3. ✅ **Removed `device_fingerprint`**: Not actually required by either provider
4. ✅ **Removed `synchronous` flag**: Riskified doesn't use this mechanism
5. ✅ **Currency Units**: Signifyd (Minor), Riskified (Major)
6. ✅ **Auth Details**: Signifyd (Basic Auth), Riskified (HMAC-SHA256 hex)
7. ✅ **Riskified Get**: Documented as NOT SUPPORTED

---

## 1. Status Enum Alignment

### 1.1 FraudCheckStatus (Hyperswitch-Defined)

```rust
// From Hyperswitch: crates/common_enums/src/enums.rs
pub enum FraudCheckStatus {
    Fraud,              // Confirmed fraudulent
    ManualReview,       // Under manual review
    #[default]
    Pending,            // Awaiting decision
    Legit,              // Confirmed legitimate
    TransactionFailure, // Payment/auth failed
}
```

**Proto Definition**:
```protobuf
enum FraudCheckStatus {
  FRAUD_CHECK_STATUS_UNSPECIFIED = 0;
  FRAUD_CHECK_STATUS_PENDING = 1;
  FRAUD_CHECK_STATUS_FRAUD = 2;
  FRAUD_CHECK_STATUS_LEGIT = 3;
  FRAUD_CHECK_STATUS_MANUAL_REVIEW = 4;
  FRAUD_CHECK_STATUS_TRANSACTION_FAILURE = 5;
}
```

**Rust Domain Type** (in `fraud/fraud_types.rs`):
```rust
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FraudCheckStatus {
    Pending,
    Fraud,
    Legit,
    ManualReview,
    TransactionFailure,
}
```

**✅ VALIDATION**: 
- Exactly matches Hyperswitch definition
- No new states introduced
- All provider states mappable

**Updated Provider Mapping**:

| Hyperswitch | Signifyd | Riskified |
|-------------|----------|-----------|
| `PENDING` | `PENDING`, `CHALLENGE` | `pending`, `processing` |
| `FRAUD` | `REJECT` | `declined`, `canceled` |
| `LEGIT` | `ACCEPT` | `approved` |
| `MANUAL_REVIEW` | `HOLD`, `REVIEW` | `review` |
| `TRANSACTION_FAILURE` | Gateway errors | Gateway errors |

---

### 1.2 FraudAction (Hyperswitch-Defined)

```rust
pub enum FraudAction {
    Accept,     // Approve transaction
    Reject,     // Decline transaction
}
```

**Proto Definition**:
```protobuf
enum FraudAction {
  FRAUD_ACTION_UNSPECIFIED = 0;
  FRAUD_ACTION_ACCEPT = 1;
  FRAUD_ACTION_REJECT = 2;
}
```

**✅ VALIDATION**: 
- Exactly 2 actionable values (ACCEPT, REJECT)
- All providers support accept/reject semantics
- Riskified's "review" state maps to REJECT action with MANUAL_REVIEW status

---

## 2. CORRECTED Method-to-Provider API Mapping

### 2.1 Signifyd API Mapping (CORRECTED)

| Proto Method | Signifyd Endpoint | HTTP | Purpose |
|--------------|-------------------|------|---------|
| `EvaluatePreAuthorization` | `/v3/orders/events/checkouts` | POST | Pre-auth fraud evaluation |
| `EvaluatePostAuthorization` | `/v3/orders/events/transactions` | POST | Post-auth case update |
| `RecordTransactionData` | `/v3/orders/events/sales` | POST | Transaction recording |
| `RecordFulfillmentData` | `/v3/orders/events/fulfillments` | POST | Shipment notification |
| `RecordReturnData` | `/v3/orders/events/returns/records` | POST | Return/refund recording |
| `Get` | `/v3/decisions/{orderId}` | GET | Decision retrieval |

**🔧 CORRECTION**: Added `/v3/orders/events/` prefix to all endpoints except `Get`.

**Status Translation**:
```
Signifyd Decision → Hyperswitch Status
---------------------------------------
ACCEPT           → LEGIT
REJECT           → FRAUD
HOLD             → MANUAL_REVIEW
CHALLENGE        → PENDING
CREDIT           → PENDING
ERROR/FAILED     → TRANSACTION_FAILURE
```

---

### 2.2 Riskified API Mapping (CORRECTED)

| Proto Method | Riskified Endpoint | HTTP | Notes |
|--------------|-------------------|------|-------|
| `EvaluatePreAuthorization` | `/api/orders/decide` | POST | Synchronous decision |
| `EvaluatePostAuthorization` | `/api/orders/decision` (success)<br>`/api/orders/checkout_denied` (failure) | POST | Split endpoint! |
| `RecordTransactionData` | `/api/orders/decide` | POST | Async submission |
| `RecordFulfillmentData` | `/api/orders/fulfill` | POST | |
| `RecordReturnData` | `/api/orders/partial_refund` | POST | |
| `Get` | **NOT SUPPORTED** | - | ❌ No endpoint available |

**🔧 CORRECTIONS**:
1. Removed `/api/orders/submit` - use `/decide` instead
2. Split `EvaluatePostAuthorization` into two endpoints based on success/failure
3. **Removed Get** - Riskified has no polling endpoint

**Status Translation**:
```
Riskified Decision → Hyperswitch Status
----------------------------------------
approved           → LEGIT
declined           → FRAUD
canceled           → FRAUD
pending            → PENDING
processing         → PENDING
review             → MANUAL_REVIEW
gateway_error      → TRANSACTION_FAILURE
```

---

## 3. CORRECTED Required Field Analysis

### 3.1 Critical Fields Added (CORRECTED)

**EvaluatePreAuthorizationRequest** (Signifyd-specific):
```protobuf
string checkout_id = 10;          // REQUIRED - Unique checkout attempt ID
Purchase purchase = 11;           // REQUIRED - Contains:
  // - created_at: ISO8601 timestamp
  // - order_channel: WEB, PHONE, POS, etc.
  // - total_price: Amount
  // - products: Array of products
  // - shipments: Shipping details
string coverage_requests = 12;    // Optional: FRAUD, INR, SNAD, ALL, NONE
```

**EvaluatePreAuthorizationRequest** (Riskified-specific):
```protobuf
repeated LineItem line_items = 20;        // REQUIRED
repeated ShippingLine shipping_lines = 21; // REQUIRED
string vendor_name = 22;                   // REQUIRED - Merchant name
string gateway = 23;                       // Optional - Gateway name
string cart_token = 25;                    // REQUIRED - Session ID
string total_discounts = 26;               // Optional - Discount amount
```

**🔧 REMOVED**:
- `device_fingerprint` - Not used by Signifyd or Riskified
- `synchronous` flag - Riskified doesn't use this mechanism

---

### 3.2 All Required Fields by Message (CORRECTED)

| Message | Signifyd Required | Riskified Required |
|---------|-------------------|-------------------|
| `EvaluatePreAuthorization` | `checkout_id`, `order_id`, `purchase` (with `created_at`, `order_channel`, `products`) | `cart_token` (or `session_id`), `vendor_name`, `line_items[]` |
| `EvaluatePostAuthorization` | `checkout_id`, `order_id`, `connector_transaction_id`, transaction details | `decided_at`, auth result |
| `RecordTransactionData` | `order_id`, `purchase` | `cart_token`, `vendor_name` |
| `RecordFulfillmentData` | `order_id`, `fulfillment_status` | `created_at` |
| `RecordReturnData` | `order_id`, `return_id` | `refunded_at` |
| `Get` | `order_id` | **N/A - Not supported** |

---

## 4. Authentication Validation

### 4.1 Signifyd Authentication (CORRECTED)

**Spec said**: "Team-based API key in header"

**Correct Implementation**:
```
Authorization: Basic {base64_encoded_api_key}
Content-Type: application/json
```

```rust
let encoded = BASE64_ENGINE.encode(api_key);
format!("Basic {}", encoded)
```

---

### 4.2 Riskified Authentication (CORRECTED)

**Spec said**: "HMAC-SHA256 authentication"

**Correct Implementation**:
```
Content-Type: application/json
X-RISKIFIED-SHOP-DOMAIN: {shop_domain}
X-RISKIFIED-HMAC-SHA256: {hex_hmac_signature}
Accept: application/vnd.riskified.com; version=2
```

```rust
// HEX encoding (not Base64!)
let key = hmac::Key::new(hmac::HMAC_SHA256, secret_token.as_bytes());
let signature = hmac::sign(&key, payload.as_bytes());
hex::encode(signature.as_ref())
```

---

## 5. Currency Unit Validation (CORRECTED)

| Provider | Currency Unit | Example ($100.00) | Correct? |
|----------|---------------|-------------------|----------|
| **Signifyd** | `CurrencyUnit::Minor` | `10000` (cents) | ✅ Correct |
| **Riskified** | `CurrencyUnit::Major` | `"100.00"` (dollars) | 🔧 Fixed (was Minor) |

**Riskified Amount Format**:
```json
{
  "total_price": "100.00",  // String in major units!
  "line_items": [
    {"price": "50.00", ...}
  ]
}
```

---

## 6. Architecture Pattern Validation

### 6.1 Folder Structure ✅

```
crates/types-traits/domain_types/src/
├── fraud/                      (NEW - following payouts/ pattern)
│   ├── mod.rs
│   ├── fraud_types.rs          ✅ Updated with provider-specific types
│   ├── router_request_types.rs
│   └── types.rs
├── connector_flow.rs           ✅ Flow markers added
└── lib.rs                      ✅ pub mod fraud;
```

### 6.2 Flow Marker Location ✅

**Correct** (following existing pattern):
```rust
#[derive(Debug, Clone)]
pub struct FraudEvaluatePreAuthorization;

#[derive(strum::Display)]
pub enum FlowName {
    FraudEvaluatePreAuthorization,
    FraudEvaluatePostAuthorization,
    FraudRecordTransactionData,
    FraudRecordFulfillmentData,
    FraudRecordReturnData,
    FraudGet,
}
```

### 6.3 NO interfaces/fraud.rs ✅

**Confirmed**: Following PaymentService pattern - implement `ConnectorIntegrationV2` directly in connector files.

---

## 7. Status Compatibility Matrix (UPDATED)

### 7.1 Can All Provider States Map to Hyperswitch?

| Provider State | Hyperswitch Mapping | Supported |
|----------------|---------------------|-----------|
| **Signifyd ACCEPT** | LEGIT | ✅ |
| **Signifyd REJECT** | FRAUD | ✅ |
| **Signifyd HOLD** | MANUAL_REVIEW | ✅ |
| **Signifyd CHALLENGE** | PENDING | ✅ |
| **Signifyd CREDIT** | PENDING | ✅ |
| **Signifyd PENDING** | PENDING | ✅ |
| **Signifyd ERROR** | TRANSACTION_FAILURE | ✅ |
| **Riskified approved** | LEGIT | ✅ |
| **Riskified declined** | FRAUD | ✅ |
| **Riskified canceled** | FRAUD | ✅ |
| **Riskified pending** | PENDING | ✅ |
| **Riskified processing** | PENDING | ✅ |
| **Riskified review** | MANUAL_REVIEW | ✅ |
| **Riskified gateway_error** | TRANSACTION_FAILURE | ✅ |

**✅ Conclusion**: All provider states mappable to Hyperswitch's 5 states

---

## 8. CORRECTED Method Responsibilities

### 8.1 EvaluatePreAuthorization
- **Purpose**: Evaluate fraud BEFORE payment authorization
- **Signifyd**: `/v3/orders/events/checkouts` (synchronous)
- **Riskified**: `/api/orders/decide` (synchronous response, async via webhook)
- **Returns**: Decision mapped to FraudCheckStatus
- **Key Fields**: 
  - Signifyd: `checkout_id`, `purchase.created_at`, `purchase.order_channel`
  - Riskified: `cart_token`, `vendor_name`, `line_items[]`

### 8.2 EvaluatePostAuthorization
- **Purpose**: Update fraud case with payment authorization results
- **Signifyd**: `/v3/orders/events/transactions`
- **Riskified**: `/api/orders/decision` (success) OR `/api/orders/checkout_denied` (failure)
- **Input**: Authorization result (success/failure), AVS/CVV data

### 8.3 RecordTransactionData
- **Purpose**: Record completed transaction for post-hoc evaluation
- **Signifyd**: `/v3/orders/events/sales`
- **Riskified**: `/api/orders/decide` (async mode)

### 8.4 RecordFulfillmentData
- **Purpose**: Notify fraud provider of shipment
- **Signifyd**: `/v3/orders/events/fulfillments`
- **Riskified**: `/api/orders/fulfill`

### 8.5 RecordReturnData
- **Purpose**: Record customer returns
- **Signifyd**: `/v3/orders/events/returns/records`
- **Riskified**: `/api/orders/partial_refund`

### 8.6 Get ❌ (Riskified NOT SUPPORTED)
- **Purpose**: Retrieve fraud decision
- **Signifyd**: `/v3/decisions/{id}` ✅ Supported
- **Riskified**: **NOT SUPPORTED** - decisions arrive via webhooks only

---

## 9. Implementation Recommendations (UPDATED)

### Priority 1 (Critical) - DONE

1. ✅ **Add checkout_id field** - Required for Signifyd
2. ✅ **Add purchase object** - Contains created_at, order_channel, products
3. ✅ **Remove device_fingerprint** - Not actually required
4. ✅ **Remove synchronous flag** - Riskified doesn't use this
5. ✅ **Document currency units** - Signifyd (Minor), Riskified (Major)
6. ✅ **Fix Signifyd endpoints** - Add /v3/orders/events/ prefix
7. ✅ **Document Riskified Get limitation** - Not supported

### Priority 2 (Architecture)

8. **Add abstraction traits** (following payment pattern):
   ```rust
   pub trait FraudEvaluatePreAuthorizationV2 {}
   pub trait FraudEvaluatePostAuthorizationV2 {}
   // ... etc
   ```

9. **Create transformers subdirectories**:
   ```
   connectors/signifyd/transformers.rs
   connectors/riskified/transformers.rs
   ```

### Priority 3 (Nice to Have)

10. **Provider-specific error handling** - Different error formats
11. **Webhook signature verification** - HMAC-SHA256 for both
12. **Retry logic** - Exponential backoff for 409/5xx

---

## 10. CORRECTED Service Definition

```protobuf
service FraudService {
  // Pre-authorization fraud evaluation
  // Signifyd: POST /v3/orders/events/checkouts
  // Riskified: POST /api/orders/decide
  rpc EvaluatePreAuthorization(FraudServiceEvaluatePreAuthorizationRequest)
      returns (FraudServiceEvaluatePreAuthorizationResponse);
  
  // Post-authorization fraud evaluation
  // Signifyd: POST /v3/orders/events/transactions
  // Riskified: POST /api/orders/decision (success) OR /api/orders/checkout_denied (failure)
  rpc EvaluatePostAuthorization(FraudServiceEvaluatePostAuthorizationRequest)
      returns (FraudServiceEvaluatePostAuthorizationResponse);
  
  // Record completed transaction
  // Signifyd: POST /v3/orders/events/sales
  // Riskified: POST /api/orders/decide (async)
  rpc RecordTransactionData(FraudServiceRecordTransactionDataRequest)
      returns (FraudServiceRecordTransactionDataResponse);
  
  // Record fulfillment/shipment
  // Signifyd: POST /v3/orders/events/fulfillments
  // Riskified: POST /api/orders/fulfill
  rpc RecordFulfillmentData(FraudServiceRecordFulfillmentDataRequest)
      returns (FraudServiceRecordFulfillmentDataResponse);
  
  // Record return/refund
  // Signifyd: POST /v3/orders/events/returns/records
  // Riskified: POST /api/orders/partial_refund
  rpc RecordReturnData(FraudServiceRecordReturnDataRequest)
      returns (FraudServiceRecordReturnDataResponse);
  
  // Retrieve fraud decision
  // Signifyd: GET /v3/decisions/{orderId}
  // Riskified: ❌ NOT SUPPORTED
  rpc Get(FraudServiceGetRequest) returns (FraudServiceGetResponse);
}
```

---

## 11. Validation Summary

### ✅ Aligned with Hyperswitch
- [x] FraudCheckStatus: 5 states exactly match
- [x] FraudAction: 2 actions exactly match
- [x] No new states introduced
- [x] All provider states mappable

### ✅ Architecture Pattern Correct
- [x] Follows payouts folder structure (`fraud/` subdirectory)
- [x] Flow markers in `connector_flow.rs`
- [x] NO separate trait file in `interfaces` (PaymentService pattern)
- [x] Domain types in `fraud/fraud_types.rs`

### ✅ Critical Corrections Applied
- [x] Signifyd endpoints fixed (added /v3/orders/events/ prefix)
- [x] checkout_id field added
- [x] purchase object added with required fields
- [x] device_fingerprint removed
- [x] synchronous flag removed
- [x] Currency units documented (Signifyd Minor, Riskified Major)
- [x] Authentication details corrected
- [x] Riskified Get limitation documented

### 🔧 Architecture Enhancements Needed
- [ ] Add abstraction traits (FraudEvaluatePreAuthorizationV2, etc.)
- [ ] Create transformers subdirectories
- [ ] Implement comprehensive error handling

---

## 12. Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-04-06 | Initial validation analysis |
| 2.0.0 | 2026-04-06 | Removed CyberSource DM |
| 3.0.0 | 2026-04-06 | Updated for renamed methods |
| 4.0.0 | 2026-04-06 | Hyperswitch-aligned enums, removed extra states |
| 4.1.0 | 2026-04-06 | Added architecture pattern validation |
| 4.2.0 | 2026-04-07 | Fixed flow marker derives (Clone not Copy) |
| **5.0.0** | **2026-04-07** | **CRITICAL FIXES: Signifyd endpoints, required fields, currency units, auth details, Riskified Get limitation** |
