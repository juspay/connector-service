# Fraud Interface Specification

## Document Information
- **Version**: 3.0.0
- **Date**: 2026-04-07
- **Status**: Updated - Phase 3 Corrections Applied

## Overview

This document defines the gRPC interface for fraud detection services in Hyperswitch Prism, designed to support multiple fraud detection providers including **Signifyd** and **Riskified**.

**Important Note on Provider Differences**:
- **Signifyd** and **Riskified** have fundamentally different API models
- Some proto methods have **provider-specific field requirements** documented below
- **Riskified does not support the `Get` method** - it relies entirely on webhooks
- **Riskified uses Major Units** for amounts (dollars), Signifyd uses Minor Units (cents)

---

## Service Definition

```protobuf
service FraudService {
  // Pre-authorization fraud evaluation
  // Signifyd: POST /v3/orders/events/checkouts
  // Riskified: POST /decide (synchronous mode)
  rpc EvaluatePreAuthorization(FraudServiceEvaluatePreAuthorizationRequest)
      returns (FraudServiceEvaluatePreAuthorizationResponse);
  
  // Post-authorization fraud evaluation with auth results
  // Signifyd: POST /v3/orders/events/transactions
  // Riskified: POST /decision (transaction success) or /checkout_denied (failure)
  rpc EvaluatePostAuthorization(FraudServiceEvaluatePostAuthorizationRequest)
      returns (FraudServiceEvaluatePostAuthorizationResponse);
  
  // Record completed transaction for post-hoc evaluation
  // Signifyd: POST /v3/orders/events/sales
  // Riskified: POST /decide (async submission)
  rpc RecordTransactionData(FraudServiceRecordTransactionDataRequest)
      returns (FraudServiceRecordTransactionDataResponse);
  
  // Record fulfillment/shipment data
  // Signifyd: POST /v3/orders/events/fulfillments
  // Riskified: POST /fulfill
  rpc RecordFulfillmentData(FraudServiceRecordFulfillmentDataRequest)
      returns (FraudServiceRecordFulfillmentDataResponse);
  
  // Record return/refund data
  // Signifyd: POST /v3/orders/events/returns/records
  // Riskified: POST /partial_refund
  rpc RecordReturnData(FraudServiceRecordReturnDataRequest)
      returns (FraudServiceRecordReturnDataResponse);
  
  // Retrieve fraud decision/status
  // Signifyd: GET /v3/decisions/{orderId}
  // Riskified: NOT SUPPORTED - decisions arrive via webhooks only
  rpc Get(FraudServiceGetRequest) returns (FraudServiceGetResponse);
}
```

---

## Core Enumerations

### FraudCheckStatus

Matches Hyperswitch's existing enum exactly - **NO additions allowed**.

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

**Provider Mapping**:

| Status | Signifyd Mapping | Riskified Mapping |
|--------|------------------|-------------------|
| `PENDING` | `PENDING`, `CHALLENGE` | `pending`, `processing` |
| `FRAUD` | `REJECT` | `declined`, `canceled` |
| `LEGIT` | `ACCEPT` | `approved` |
| `MANUAL_REVIEW` | `HOLD`, `REVIEW` | `review` |
| `TRANSACTION_FAILURE` | Gateway errors | Gateway errors |

### FraudAction

```protobuf
enum FraudAction {
  FRAUD_ACTION_UNSPECIFIED = 0;
  FRAUD_ACTION_ACCEPT = 1;
  FRAUD_ACTION_REJECT = 2;
}
```

---

## Request/Response Messages

### Common Types

```protobuf
message Money {
  int64 minor_amount = 1;
  string currency = 2;
}

message Customer {
  string id = 1;
  string email = 2;
  string first_name = 3;
  string last_name = 4;
  string phone = 5;
}

message Address {
  string line1 = 1;
  string line2 = 2;
  string city = 3;
  string state = 4;
  string zip = 5;
  string country = 6;
}

message BrowserInformation {
  string user_agent = 1;
  string ip_address = 2;
  string accept_language = 3;
  string color_depth = 4;
  string java_enabled = 5;
  string javascript_enabled = 6;
  string screen_height = 7;
  string screen_width = 8;
  string time_zone = 9;
}

// Signifyd-specific: Product details
message Product {
  string id = 1;
  string sku = 2;
  string title = 3;
  int32 quantity = 4;
  int64 price = 5;
  string category = 6;
  string brand = 7;
  bool requires_shipping = 8;
}

// Signifyd-specific: Shipment details  
message Shipment {
  string carrier = 1;
  string tracking_number = 2;
  string tracking_url = 3;
  Address destination = 4;
  repeated string products = 5;
}

// Signifyd-specific: Purchase wrapper
message Purchase {
  string created_at = 1;  // ISO8601 format
  string order_channel = 2;  // WEB, PHONE, POS, MOBILE_APP
  int64 total_price = 3;
  int64 total_shipping_cost = 4;
  string currency = 5;
  string confirmation_email = 6;
  string confirmation_phone = 7;
  repeated Product products = 8;
  repeated Shipment shipments = 9;
}

// Riskified-specific: Line item
message LineItem {
  string price = 1;  // String in MAJOR units for Riskified
  int32 quantity = 2;
  string title = 3;
  string product_type = 4;  // physical, digital, other
  bool requires_shipping = 5;
  string product_id = 6;
  string category = 7;
  string brand = 8;
}

// Riskified-specific: Shipping line
message ShippingLine {
  string code = 1;
  string price = 2;  // String in MAJOR units
  string source = 3;
  string title = 4;
}
```

---

### EvaluatePreAuthorization

**Purpose**: Evaluate fraud risk BEFORE payment authorization

```protobuf
message FraudServiceEvaluatePreAuthorizationRequest {
  // ========== COMMON REQUIRED FIELDS ==========
  string merchant_fraud_id = 1;  // Unique ID for this fraud check
  string order_id = 2;           // Merchant's order ID
  Money amount = 3;              // Amount (minor units for Signifyd, will convert for Riskified)
  Customer customer = 4;
  Address billing_address = 5;
  Address shipping_address = 6;
  BrowserInformation browser_info = 7;
  string session_id = 8;         // Riskified: cart_token / beacon session
  
  // ========== SIGNIFYD-SPECIFIC FIELDS ==========
  // Required for Signifyd, ignored by Riskified
  string checkout_id = 10;       // Signifyd: Unique checkout attempt ID
  Purchase purchase = 11;        // Signifyd: Purchase details with products
  string coverage_requests = 12; // Signifyd: FRAUD, INR, SNAD, ALL, NONE
  
  // ========== RISKIFIED-SPECIFIC FIELDS ==========
  // Required for Riskified, ignored by Signifyd
  repeated LineItem line_items = 20;       // Riskified: Cart line items
  repeated ShippingLine shipping_lines = 21; // Riskified: Shipping methods
  string vendor_name = 22;                 // Riskified: Merchant name
  string gateway = 23;                     // Riskified: Payment gateway name
  string referring_site = 24;              // Riskified: Referrer URL
  string cart_token = 25;                  // Riskified: Session identifier
  string total_discounts = 26;             // Riskified: Discount amount (major units)
}

message FraudServiceEvaluatePreAuthorizationResponse {
  string fraud_id = 1;                    // Provider's check/case ID
  FraudCheckStatus status = 2;
  FraudAction recommended_action = 3;
  FraudScore score = 4;
  repeated FraudReason reasons = 5;
  string case_id = 6;                     // Signifyd case ID
  string redirect_url = 7;                // 3DS/challenge URL if applicable
  google.protobuf.Struct connector_metadata = 8;
}
```

**Signifyd Endpoint**: `POST https://api.signifyd.com/v3/orders/events/checkouts`
- Synchronous response
- Returns `checkpointAction`: ACCEPT, REJECT, HOLD, CHALLENGE

**Riskified Endpoint**: `POST /decide`
- May return immediately with `submitted` or `processing`
- Final decision arrives via webhook

---

### EvaluatePostAuthorization

**Purpose**: Update fraud case with payment authorization results

```protobuf
message FraudServiceEvaluatePostAuthorizationRequest {
  // ========== COMMON REQUIRED FIELDS ==========
  string merchant_fraud_id = 1;
  string order_id = 2;
  string connector_transaction_id = 3;  // Payment gateway transaction ID
  string session_id = 4;
  bool authorization_success = 5;       // true = approved, false = declined
  
  // Authorization details (when successful)
  string authorization_code = 6;
  string avs_result = 7;                // AVS response code
  string cvv_result = 8;                // CVV response code
  
  // Error details (when failed)
  string error_code = 9;
  string error_message = 10;
  
  // ========== SIGNIFYD-SPECIFIC FIELDS ==========
  string checkout_id = 15;              // Links to original checkout
  TransactionDetails transaction = 16;  // Signifyd transaction wrapper
  
  // ========== RISKIFIED-SPECIFIC FIELDS ==========
  // Riskified uses separate endpoints for success vs failure:
  // - Success: POST /decision
  // - Failure: POST /checkout_denied
  string decided_at = 20;               // ISO8601 timestamp
  string currency = 21;                 // For Riskified major unit conversion
}

message TransactionDetails {
  string transaction_id = 1;
  string gateway_status_code = 2;       // e.g., "A01" for approved
  string payment_method = 3;            // CREDIT_CARD, etc.
  int64 amount = 4;
  string currency = 5;
  string gateway = 6;                   // Gateway name
  string card_bin = 7;                  // First 6 digits
  string card_last_four = 8;
  string card_expiry_month = 9;
  string card_expiry_year = 10;
}

message FraudServiceEvaluatePostAuthorizationResponse {
  string fraud_id = 1;
  FraudCheckStatus status = 2;
  FraudAction recommended_action = 3;
  FraudScore score = 4;
  string case_id = 5;
  google.protobuf.Struct connector_metadata = 6;
}
```

**Signifyd Endpoint**: `POST /v3/orders/events/transactions`
- Updates existing case with transaction details

**Riskified Endpoints**:
- **Success**: `POST /decision` - Reports approved transaction
- **Failure**: `POST /checkout_denied` - Reports declined transaction

---

### RecordTransactionData

**Purpose**: Record completed transaction for post-hoc evaluation

```protobuf
message FraudServiceRecordTransactionDataRequest {
  // ========== COMMON REQUIRED FIELDS ==========
  string merchant_fraud_id = 1;
  string order_id = 2;
  string session_id = 3;
  Money amount = 4;
  Customer customer = 5;
  
  // ========== SIGNIFYD-SPECIFIC FIELDS ==========
  Purchase purchase = 10;
  string decision_delivery = 11;  // SYNC or ASYNC_ONLY
  string coverage_requests = 12;
  
  // ========== RISKIFIED-SPECIFIC FIELDS ==========
  repeated LineItem line_items = 20;
  repeated ShippingLine shipping_lines = 21;
  string vendor_name = 22;
  string gateway = 23;
  string cart_token = 24;
  string currency = 25;
  string total_price = 26;  // Major units
}

message FraudServiceRecordTransactionDataResponse {
  string fraud_id = 1;
  FraudCheckStatus status = 2;
  FraudAction recommended_action = 3;
  string case_id = 4;
  google.protobuf.Struct connector_metadata = 5;
}
```

**Signifyd Endpoint**: `POST /v3/orders/events/sales`
- Used when fraud check happens after payment authorization
- Supports SYNC or ASYNC_ONLY decision delivery

**Riskified Endpoint**: `POST /decide` (async mode)
- Submits order for async evaluation
- Decision arrives via webhook

---

### RecordFulfillmentData

**Purpose**: Notify fraud provider of order shipment

```protobuf
message FraudServiceRecordFulfillmentDataRequest {
  // ========== COMMON REQUIRED FIELDS ==========
  string merchant_fraud_id = 1;
  string order_id = 2;
  string session_id = 3;
  string fulfillment_id = 4;
  
  // ========== COMMON SHIPMENT DATA ==========
  string carrier = 5;              // e.g., "UPS", "FedEx"
  string tracking_number = 6;
  string tracking_url = 7;
  string fulfillment_status = 8;   // PARTIAL, COMPLETE, REPLACEMENT, CANCELED
  
  // ========== SIGNIFYD-SPECIFIC ==========
  repeated string products = 10;   // Product IDs/SKUs in shipment
  Address destination = 11;        // Override shipping address
  
  // ========== RISKIFIED-SPECIFIC ==========
  string created_at = 20;          // ISO8601 fulfillment timestamp
}

message FraudServiceRecordFulfillmentDataResponse {
  string fraud_id = 1;
  bool recorded = 2;
  google.protobuf.Struct connector_metadata = 3;
}
```

**Signifyd Endpoint**: `POST /v3/orders/events/fulfillments`
- Required for chargeback guarantee protection

**Riskified Endpoint**: `POST /fulfill`
- Reports shipment/fulfillment data

---

### RecordReturnData

**Purpose**: Record customer returns/refunds

```protobuf
message FraudServiceRecordReturnDataRequest {
  // ========== COMMON REQUIRED FIELDS ==========
  string merchant_fraud_id = 1;
  string order_id = 2;
  string session_id = 3;
  string return_id = 4;
  
  // Return details
  Money refund_amount = 5;
  string refund_method = 6;        // e.g., "ORIGINAL_PAYMENT"
  string reason = 7;
  
  // Items being returned
  repeated ReturnItem items = 8;
  
  // ========== SIGNIFYD-SPECIFIC ==========
  string refund_transaction_id = 10;
  
  // ========== RISKIFIED-SPECIFIC ==========
  string refunded_at = 20;         // ISO8601 timestamp
}

message ReturnItem {
  string product_id = 1;
  string sku = 2;
  int32 quantity = 3;
  int64 amount = 4;
  string reason = 5;
}

message FraudServiceRecordReturnDataResponse {
  string fraud_id = 1;
  bool recorded = 2;
  google.protobuf.Struct connector_metadata = 3;
}
```

**Signifyd Endpoint**: `POST /v3/orders/events/returns/records`

**Riskified Endpoint**: `POST /partial_refund`

---

### Get (Status Retrieval)

```protobuf
message FraudServiceGetRequest {
  string merchant_fraud_id = 1;
  string order_id = 2;
  string fraud_id = 3;  // Optional: provider's case ID
}

message FraudServiceGetResponse {
  string fraud_id = 1;
  FraudCheckStatus status = 2;
  FraudAction recommended_action = 3;
  FraudScore score = 4;
  repeated FraudReason reasons = 5;
  string case_id = 6;
  string decision_timestamp = 7;  // ISO8601
  google.protobuf.Struct connector_metadata = 8;
}
```

**Signifyd Endpoint**: `GET /v3/decisions/{orderId}`
- Returns current decision for order

**Riskified**: **NOT SUPPORTED**
- Riskified does not provide a GET endpoint
- Implementations should return error or use webhook cache

---

## Supporting Types

```protobuf
message FraudScore {
  int32 score = 1;
  string provider_scale = 2;  // e.g., "0-100", "0-1000"
}

message FraudReason {
  string code = 1;
  string message = 2;
  string description = 3;
  float weight = 4;
}
```

---

## Authentication

### Signifyd

**Method**: Basic Auth with Base64-encoded API Key

```
Authorization: Basic {base64_encoded_api_key}
Content-Type: application/json
```

**Implementation**:
```rust
let auth_api_key = format!(
    "Basic {}",
    BASE64_ENGINE.encode(auth.api_key.peek())
);
```

**Configuration**:
```toml
[signifyd]
base_url = "https://api.signifyd.com/"
api_key = "your_api_key"
```

### Riskified

**Method**: HMAC-SHA256 Signature (Hex-encoded)

**Headers**:
```
Content-Type: application/json
X-RISKIFIED-SHOP-DOMAIN: {shop_domain}
X-RISKIFIED-HMAC-SHA256: {hex_hmac_signature}
Accept: application/vnd.riskified.com; version=2
```

**Signature Generation**:
```rust
pub fn generate_authorization_signature(
    &self,
    auth: &RiskifiedAuthType,
    payload: &str,
) -> CustomResult<String, ConnectorError> {
    let key = hmac::Key::new(
        hmac::HMAC_SHA256,
        auth.secret_token.expose().as_bytes(),
    );
    let signature_value = hmac::sign(&key, payload.as_bytes());
    let digest = signature_value.as_ref();
    Ok(hex::encode(digest))  // HEX encoding, NOT Base64
}
```

**Configuration**:
```toml
[riskified]
base_url = "https://riskified.com/"
secret_token = "your_secret_token"
shop_domain = "your_shop.myshopify.com"
```

---

## Currency Unit Handling

| Provider | Currency Unit | Notes |
|----------|---------------|-------|
| **Signifyd** | `CurrencyUnit::Minor` | Uses cents (e.g., $100.00 = 10000) |
| **Riskified** | `CurrencyUnit::Major` | Uses dollars (e.g., $100.00 = "100.00") |

**Implementation Pattern**:
```rust
impl ConnectorCommon for Signifyd {
    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor
    }
}

impl ConnectorCommon for Riskified {
    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Major
    }
}
```

---

## Webhook Events

### Signifyd Webhooks

**Header**: `SIGNIFYD-TOPIC: ORDER_CHECKPOINT_ACTION_UPDATE`

**Events**:
| Signifyd Event | Hyperswitch Mapping |
|----------------|---------------------|
| `checkpointAction: ACCEPT` | `FRM_APPROVED` |
| `checkpointAction: REJECT` | `FRM_REJECTED` |
| `checkpointAction: HOLD` | `FRM_REVIEW_REQUIRED` |

**Signature Header**: `x-signifyd-sec-hmac-sha256`
- Algorithm: HMAC-SHA256
- Key: Webhook secret

### Riskified Webhooks

**Body Structure**:
```json
{
  "id": "order_id",
  "status": "Approved"  // or "Declined"
}
```

**Events**:
| Riskified Status | Hyperswitch Mapping |
|------------------|---------------------|
| `Approved` | `FRM_APPROVED` |
| `Declined` | `FRM_REJECTED` |

**Signature Header**: `x-riskified-hmac-sha256`
- Algorithm: HMAC-SHA256
- Encoding: Base64

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-04-06 | Initial specification |
| 2.0.0 | 2026-04-06 | Renamed methods to verb-noun format |
| 3.0.0 | 2026-04-07 | **Fixed provider-specific fields**, corrected endpoints, added auth details, documented currency units |
