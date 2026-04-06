# Proto Interface Validation Analysis

## Document Information
- **Version**: 4.0.0
- **Date**: 2026-04-06
- **Status**: Final - Hyperswitch-Aligned
- **Scope**: Validation of fraud.proto against Signifyd and Riskified APIs with Hyperswitch-aligned enums

## Executive Summary

This document validates the fraud interface proto specification against Signifyd and Riskified APIs with strict adherence to Hyperswitch's existing enums.

### Critical Constraints
1. **No New States**: All enums MUST match Hyperswitch exactly - no additions allowed
2. **Method Naming**: Updated to verb-noun format for clarity
3. **Provider Mapping**: Each proto method maps to specific provider endpoints

### Current Specification

| Proto Element | Hyperswitch Match | Provider Support |
|--------------|-------------------|------------------|
| `FraudCheckStatus` | ✅ Exact match (5 states) | Signifyd, Riskified |
| `FraudAction` | ✅ Exact match (3 actions) | Signifyd, Riskified |
| `EvaluatePreAuthorization` | New method | Signifyd /checkouts, Riskified /submit |
| `EvaluatePostAuthorization` | New method | Signifyd /transactions, Riskified /update |
| `RecordTransactionData` | New method | Signifyd /sales, Riskified /create |
| `RecordFulfillmentData` | New method | Signifyd /fulfillments, Riskified /fulfill |
| `RecordReturnData` | New method | Signifyd /returns, Riskified /partial_refund |
| `Get` | Existing pattern | Signifyd /decisions/{id} |

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

**Validation**:
- ✅ No new states introduced
- ✅ Exactly matches Hyperswitch definition
- ✅ Provider states mappable to these 5 states

**Provider Mapping**:

| Hyperswitch | Signifyd | Riskified |
|-------------|----------|-----------|
| `PENDING` | `PENDING` | `pending` / `reviewing` |
| `FRAUD` | `REJECT` (fraud signals) | `declined` / `canceled` |
| `LEGIT` | `ACCEPT` | `approved` |
| `MANUAL_REVIEW` | `REVIEW` | `review` / `pending` |
| `TRANSACTION_FAILURE` | Payment failure | Gateway error |

---

### 1.2 FraudAction (Hyperswitch-Defined)

```rust
// Simplified based on provider capabilities
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

**Validation**:
- ✅ Minimal viable action set
- ✅ All providers support accept/reject
- ✅ Riskified's "review" maps to REJECT with manual_review status

---

## 2. Method-to-Provider API Mapping

### 2.1 Signifyd API Mapping

| Proto Method | Signifyd Endpoint | HTTP | Purpose |
|--------------|-------------------|------|---------|
| `EvaluatePreAuthorization` | `/v3/checkouts` | POST | Pre-auth fraud evaluation |
| `EvaluatePostAuthorization` | `/v3/transactions` | POST | Post-auth case update |
| `RecordTransactionData` | `/v3/sales` | POST | Combined transaction recording |
| `RecordFulfillmentData` | `/v3/fulfillments` | POST | Shipment notification |
| `RecordReturnData` | `/v3/returns` | POST | Return/refund recording |
| `Get` | `/v3/decisions/{orderId}` | GET | Decision retrieval |

**Status Translation**:
```
Signifyd Decision → Hyperswitch Status
---------------------------------------
ACCEPT           → LEGIT
REJECT           → FRAUD
REVIEW           → MANUAL_REVIEW
ERROR/FAILED     → TRANSACTION_FAILURE
```

---

### 2.2 Riskified API Mapping

| Proto Method | Riskified Endpoint | HTTP | Mode |
|--------------|-------------------|------|------|
| `EvaluatePreAuthorization` | `/api/orders/submit` | POST | Async (webhook) |
| `EvaluatePreAuthorization` | `/api/orders/decide` | POST | Sync (immediate) |
| `EvaluatePostAuthorization` | `/api/orders/update` | POST | Post-auth update |
| `RecordTransactionData` | `/api/orders/create` | POST | Transaction record |
| `RecordFulfillmentData` | `/api/orders/fulfill` | POST | Fulfillment |
| `RecordReturnData` | `/api/orders/partial_refund` | POST | Returns |
| `Get` | N/A (webhook only) | - | Decision via webhook |

**Status Translation**:
```
Riskified Decision → Hyperswitch Status
----------------------------------------
approved           → LEGIT
declined           → FRAUD
canceled           → FRAUD
pending/review     → MANUAL_REVIEW
gateway_error      → TRANSACTION_FAILURE
```

---

## 3. Required Field Analysis

### 3.1 CONFLICT-001: Missing Required Fields

**EvaluatePreAuthorizationRequest** - Missing:
```protobuf
string device_fingerprint = 16;  // REQUIRED for Signifyd
string session_id = 17;          // REQUIRED for both providers
bool synchronous = 18;           // REQUIRED for Riskified mode selection
```

**Impact**: 
- Signifyd: Cannot perform device-based risk analysis without fingerprint
- Riskified: Cannot distinguish sync/async mode

**Resolution**: Add fields to proto (not new status enums - allowed)

---

### 3.2 CONFLICT-002: Field Optionality

**Current Issue**: Too many fields marked `optional`

**Required Fields (Must Remove `optional`)**:

| Message | Required Fields | Reason |
|---------|-----------------|--------|
| `EvaluatePreAuthorizationRequest` | `merchant_fraud_check_id`, `order_id`, `amount`, `customer.email` | Hyperswitch requirement |
| `EvaluatePostAuthorizationRequest` | `merchant_fraud_check_id`, `order_id`, `amount`, `connector_transaction_id` | Link to payment |
| `RecordTransactionDataRequest` | `merchant_fraud_check_id`, `order_id`, `amount` | Case creation |
| `RecordFulfillmentDataRequest` | `merchant_fraud_check_id`, `order_id` | Case lookup |
| `RecordReturnDataRequest` | `merchant_fraud_check_id`, `order_id`, `amount` | Return record |
| `GetRequest` | At least one ID field | Lookup requirement |

---

## 4. Status Compatibility Matrix

### 4.1 Can All Provider States Map to Hyperswitch?

| Provider State | Hyperswitch Mapping | Supported |
|----------------|---------------------|-----------|
| **Signifyd ACCEPT** | LEGIT | ✅ |
| **Signifyd REJECT** | FRAUD | ✅ |
| **Signifyd REVIEW** | MANUAL_REVIEW | ✅ |
| **Signifyd PENDING** | PENDING | ✅ |
| **Signifyd ERROR** | TRANSACTION_FAILURE | ✅ |
| **Riskified approved** | LEGIT | ✅ |
| **Riskified declined** | FRAUD | ✅ |
| **Riskified canceled** | FRAUD | ✅ |
| **Riskified pending** | PENDING/MANUAL_REVIEW | ✅ |
| **Riskified review** | MANUAL_REVIEW | ✅ |

**Conclusion**: ✅ All provider states mappable to Hyperswitch's 5 states

---

## 5. Method Responsibilities

### 5.1 EvaluatePreAuthorization
- **Purpose**: Evaluate fraud BEFORE payment authorization
- **Providers**: Signifyd (/checkouts), Riskified (/submit or /decide)
- **Returns**: Decision mapped to FraudCheckStatus
- **Key Fields**: device_fingerprint, session_id, customer, amount

### 5.2 EvaluatePostAuthorization
- **Purpose**: Update fraud case with payment auth results
- **Providers**: Signifyd (/transactions), Riskified (/update)
- **Input**: Authorization result (success/failure), AVS/CVV data
- **Updates**: Existing case with payment gateway response

### 5.3 RecordTransactionData
- **Purpose**: Record completed transaction for post-hoc evaluation
- **Providers**: Signifyd (/sales), Riskified (/create)
- **Use Case**: Synchronous flows where fraud check happens after payment
- **Combines**: Purchase data + transaction result in single call

### 5.4 RecordFulfillmentData
- **Purpose**: Notify fraud provider of shipment
- **Providers**: Signifyd (/fulfillments), Riskified (/fulfill)
- **Required For**: Chargeback guarantee protection
- **Includes**: Tracking numbers, carrier, shipping address

### 5.5 RecordReturnData
- **Purpose**: Record customer returns
- **Providers**: Signifyd (/returns), Riskified (/partial_refund)
- **Use Case**: Return fraud detection, fee adjustments

### 5.6 Get
- **Purpose**: Retrieve fraud decision
- **Providers**: Signifyd (/decisions/{id}), Riskified (webhook fallback)
- **Use Case**: Webhook recovery, status sync, manual review

---

## 6. Implementation Recommendations

### 6.1 Priority 1 (Critical)

1. **Add device_fingerprint field**
   ```protobuf
   message FraudServiceEvaluatePreAuthorizationRequest {
     // ... existing fields
     string device_fingerprint = 16;  // ADD
   }
   ```

2. **Add session_id to all requests**
   ```protobuf
   // Add to: EvaluatePreAuthorization, EvaluatePostAuthorization,
   // RecordTransactionData, RecordFulfillmentData, RecordReturnData
   string session_id = X;
   ```

3. **Add synchronous flag for Riskified**
   ```protobuf
   message FraudServiceEvaluatePreAuthorizationRequest {
     // ... existing fields
     bool synchronous = 17;  // ADD: true=decide, false=submit
   }
   ```

### 6.2 Priority 2 (Important)

4. **Fix field optionality** - Remove `optional` from:
   - All `merchant_fraud_check_id` fields
   - All `order_id` fields
   - Key identity fields

### 6.3 Priority 3 (Nice to Have)

5. **Enhanced FraudScore** (if needed - does NOT add status)
   ```protobuf
   message FraudScore {
     int32 score = 1;                    // Normalized 0-1000
     optional string provider_scale = 2; // "0-1000", "0-100", "category"
   }
   ```

---

## 7. Service Definition

```protobuf
service FraudService {
  // Pre-authorization fraud evaluation
  rpc EvaluatePreAuthorization(FraudServiceEvaluatePreAuthorizationRequest)
      returns (FraudServiceEvaluatePreAuthorizationResponse);
  
  // Post-authorization fraud evaluation with auth results
  rpc EvaluatePostAuthorization(FraudServiceEvaluatePostAuthorizationRequest)
      returns (FraudServiceEvaluatePostAuthorizationResponse);
  
  // Record completed transaction for post-hoc evaluation
  rpc RecordTransactionData(FraudServiceRecordTransactionDataRequest)
      returns (FraudServiceRecordTransactionDataResponse);
  
  // Record fulfillment/shipment data
  rpc RecordFulfillmentData(FraudServiceRecordFulfillmentDataRequest)
      returns (FraudServiceRecordFulfillmentDataResponse);
  
  // Record return/refund data
  rpc RecordReturnData(FraudServiceRecordReturnDataRequest)
      returns (FraudServiceRecordReturnDataResponse);
  
  // Retrieve fraud decision/status
  rpc Get(FraudServiceGetRequest) returns (FraudServiceGetResponse);
}
```

---

## 8. Validation Summary

### ✅ Aligned with Hyperswitch
- [x] FraudCheckStatus: 5 states exactly match
- [x] FraudAction: 3 actions exactly match
- [x] No new states introduced
- [x] All provider states mappable

### ⚠️ Requires Attention
- [ ] Add device_fingerprint field
- [ ] Add session_id to all requests
- [ ] Add synchronous flag for Riskified
- [ ] Fix field optionality

### ❌ Removed (Intentionally)
- Cancel method (providers don't support uniformly)
- Extra status states (CHALLENGE, CANCELLED, ERROR, TIMEOUT, APPROVED, REJECTED)
- FraudCheckType enum (redundant with method names)

---

## 9. Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-04-06 | Initial validation analysis |
| 2.0.0 | 2026-04-06 | Removed CyberSource DM |
| 3.0.0 | 2026-04-06 | Updated for renamed methods |
| 4.0.0 | 2026-04-06 | **Hyperswitch-aligned enums**, removed extra states |
