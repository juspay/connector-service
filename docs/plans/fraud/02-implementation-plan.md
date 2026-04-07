# Fraud Interface Implementation Plan

## Document Information
- **Version**: 3.0.0
- **Date**: 2026-04-07
- **Status**: Updated - Phase 3 Corrections Applied

## Overview

This document provides the phased implementation plan for fraud detection connectors (Signifyd and Riskified) in Hyperswitch Prism. **This implementation follows the PaymentService/Payouts pattern exactly** - no new architectural patterns are introduced.

## Critical Implementation Notes

### Provider Differences
- **Signifyd** and **Riskified** have different API models requiring **provider-specific request handling**
- **Riskified does NOT support Get method** - relies on webhooks exclusively
- **Currency units differ**: Signifyd (Minor), Riskified (Major)
- **Authentication differs**: Signifyd (Basic Auth), Riskified (HMAC-SHA256)

### Architecture Constraint
**NO separate trait file in `interfaces/src/`** - Connectors implement `ConnectorIntegrationV2` directly (following PaymentService pattern).

---

## Phase 1: Protocol Buffers (Week 1)

### 1.1 Create `proto/fraud.proto`

```protobuf
syntax = "proto3";

package fraud;

import "common.proto";

// ============ SERVICE ============
service FraudService {
  rpc EvaluatePreAuthorization(FraudServiceEvaluatePreAuthorizationRequest)
      returns (FraudServiceEvaluatePreAuthorizationResponse);
  
  rpc EvaluatePostAuthorization(FraudServiceEvaluatePostAuthorizationRequest)
      returns (FraudServiceEvaluatePostAuthorizationResponse);
  
  rpc RecordTransactionData(FraudServiceRecordTransactionDataRequest)
      returns (FraudServiceRecordTransactionDataResponse);
  
  rpc RecordFulfillmentData(FraudServiceRecordFulfillmentDataRequest)
      returns (FraudServiceRecordFulfillmentDataResponse);
  
  rpc RecordReturnData(FraudServiceRecordReturnDataRequest)
      returns (FraudServiceRecordReturnDataResponse);
  
  rpc Get(FraudServiceGetRequest) returns (FraudServiceGetResponse);
}

// ============ ENUMS ============
enum FraudCheckStatus {
  FRAUD_CHECK_STATUS_UNSPECIFIED = 0;
  FRAUD_CHECK_STATUS_PENDING = 1;
  FRAUD_CHECK_STATUS_FRAUD = 2;
  FRAUD_CHECK_STATUS_LEGIT = 3;
  FRAUD_CHECK_STATUS_MANUAL_REVIEW = 4;
  FRAUD_CHECK_STATUS_TRANSACTION_FAILURE = 5;
}

enum FraudAction {
  FRAUD_ACTION_UNSPECIFIED = 0;
  FRAUD_ACTION_ACCEPT = 1;
  FRAUD_ACTION_REJECT = 2;
}

// ============ COMMON TYPES ============
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

// Signifyd-specific types
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

message Shipment {
  string carrier = 1;
  string tracking_number = 2;
  string tracking_url = 3;
  Address destination = 4;
  repeated string products = 5;
}

message Purchase {
  string created_at = 1;
  string order_channel = 2;
  int64 total_price = 3;
  int64 total_shipping_cost = 4;
  string currency = 5;
  string confirmation_email = 6;
  string confirmation_phone = 7;
  repeated Product products = 8;
  repeated Shipment shipments = 9;
}

// Riskified-specific types
message LineItem {
  string price = 1;
  int32 quantity = 2;
  string title = 3;
  string product_type = 4;
  bool requires_shipping = 5;
  string product_id = 6;
  string category = 7;
  string brand = 8;
}

message ShippingLine {
  string code = 1;
  string price = 2;
  string source = 3;
  string title = 4;
}

// ============ REQUEST/RESPONSE MESSAGES ============

message FraudServiceEvaluatePreAuthorizationRequest {
  // Common fields
  string merchant_fraud_id = 1;
  string order_id = 2;
  Money amount = 3;
  Customer customer = 4;
  Address billing_address = 5;
  Address shipping_address = 6;
  BrowserInformation browser_info = 7;
  string session_id = 8;
  
  // Signifyd-specific
  string checkout_id = 10;
  Purchase purchase = 11;
  string coverage_requests = 12;
  
  // Riskified-specific
  repeated LineItem line_items = 20;
  repeated ShippingLine shipping_lines = 21;
  string vendor_name = 22;
  string gateway = 23;
  string referring_site = 24;
  string cart_token = 25;
  string total_discounts = 26;
}

message FraudServiceEvaluatePreAuthorizationResponse {
  string fraud_id = 1;
  FraudCheckStatus status = 2;
  FraudAction recommended_action = 3;
  FraudScore score = 4;
  repeated FraudReason reasons = 5;
  string case_id = 6;
  string redirect_url = 7;
  google.protobuf.Struct connector_metadata = 8;
}

message FraudServiceEvaluatePostAuthorizationRequest {
  string merchant_fraud_id = 1;
  string order_id = 2;
  string connector_transaction_id = 3;
  string session_id = 4;
  bool authorization_success = 5;
  string authorization_code = 6;
  string avs_result = 7;
  string cvv_result = 8;
  string error_code = 9;
  string error_message = 10;
  string checkout_id = 15;
  TransactionDetails transaction = 16;
  string decided_at = 20;
  string currency = 21;
}

message TransactionDetails {
  string transaction_id = 1;
  string gateway_status_code = 2;
  string payment_method = 3;
  int64 amount = 4;
  string currency = 5;
  string gateway = 6;
  string card_bin = 7;
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

message FraudServiceRecordTransactionDataRequest {
  string merchant_fraud_id = 1;
  string order_id = 2;
  string session_id = 3;
  Money amount = 4;
  Customer customer = 5;
  Purchase purchase = 10;
  string decision_delivery = 11;
  string coverage_requests = 12;
  repeated LineItem line_items = 20;
  repeated ShippingLine shipping_lines = 21;
  string vendor_name = 22;
  string gateway = 23;
  string cart_token = 24;
  string currency = 25;
  string total_price = 26;
}

message FraudServiceRecordTransactionDataResponse {
  string fraud_id = 1;
  FraudCheckStatus status = 2;
  FraudAction recommended_action = 3;
  string case_id = 4;
  google.protobuf.Struct connector_metadata = 5;
}

message FraudServiceRecordFulfillmentDataRequest {
  string merchant_fraud_id = 1;
  string order_id = 2;
  string session_id = 3;
  string fulfillment_id = 4;
  string carrier = 5;
  string tracking_number = 6;
  string tracking_url = 7;
  string fulfillment_status = 8;
  repeated string products = 10;
  Address destination = 11;
  string created_at = 20;
}

message FraudServiceRecordFulfillmentDataResponse {
  string fraud_id = 1;
  bool recorded = 2;
  google.protobuf.Struct connector_metadata = 3;
}

message FraudServiceRecordReturnDataRequest {
  string merchant_fraud_id = 1;
  string order_id = 2;
  string session_id = 3;
  string return_id = 4;
  Money refund_amount = 5;
  string refund_method = 6;
  string reason = 7;
  repeated ReturnItem items = 8;
  string refund_transaction_id = 10;
  string refunded_at = 20;
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

message FraudServiceGetRequest {
  string merchant_fraud_id = 1;
  string order_id = 2;
  string fraud_id = 3;
}

message FraudServiceGetResponse {
  string fraud_id = 1;
  FraudCheckStatus status = 2;
  FraudAction recommended_action = 3;
  FraudScore score = 4;
  repeated FraudReason reasons = 5;
  string case_id = 6;
  string decision_timestamp = 7;
  google.protobuf.Struct connector_metadata = 8;
}

message FraudScore {
  int32 score = 1;
  string provider_scale = 2;
}

message FraudReason {
  string code = 1;
  string message = 2;
  string description = 3;
  float weight = 4;
}
```

### 1.2 Update `services.proto`

```protobuf
import "fraud.proto";

service ConnectorService {
  // ... existing payment methods
  
  // Fraud Service Methods
  rpc FraudEvaluatePreAuthorization(fraud.FraudServiceEvaluatePreAuthorizationRequest)
      returns (fraud.FraudServiceEvaluatePreAuthorizationResponse);
  
  rpc FraudEvaluatePostAuthorization(fraud.FraudServiceEvaluatePostAuthorizationRequest)
      returns (fraud.FraudServiceEvaluatePostAuthorizationResponse);
  
  rpc FraudRecordTransactionData(fraud.FraudServiceRecordTransactionDataRequest)
      returns (fraud.FraudServiceRecordTransactionDataResponse);
  
  rpc FraudRecordFulfillmentData(fraud.FraudServiceRecordFulfillmentDataRequest)
      returns (fraud.FraudServiceRecordFulfillmentDataResponse);
  
  rpc FraudRecordReturnData(fraud.FraudServiceRecordReturnDataRequest)
      returns (fraud.FraudServiceRecordReturnDataResponse);
  
  rpc FraudGet(fraud.FraudServiceGetRequest) 
      returns (fraud.FraudServiceGetResponse);
}
```

### 1.3 Update `build.rs`

```rust
// crates/types-traits/grpc-api-types/build.rs
const PROTO_FILES: &[&str] = &[
    // ... existing protos
    "proto/fraud.proto",
];
```

### 1.4 Webhook Event Types

Add to webhook events proto or documentation:

| Event Type | Description |
|------------|-------------|
| `FRM_APPROVED` | Fraud check approved transaction |
| `FRM_REJECTED` | Fraud check rejected transaction |
| `FRM_REVIEW_REQUIRED` | Transaction flagged for manual review |

---

## Phase 2: Domain Types (Week 1-2)

### 2.1 Folder Structure (Following Payouts Pattern)

```
crates/types-traits/domain_types/src/
├── fraud/
│   ├── mod.rs                  (re-exports)
│   ├── fraud_types.rs          (FraudFlowData, enums, request/response types)
│   ├── router_request_types.rs (fraud-specific request data)
│   └── types.rs                (ForeignTryFrom implementations)
├── connector_flow.rs           (Fraud* flow markers)
└── lib.rs                      (pub mod fraud;)
```

### 2.2 Create `fraud/mod.rs`

```rust
pub mod fraud_types;
pub mod router_request_types;
pub mod types;

pub use fraud_types::*;
pub use router_request_types::*;
```

### 2.3 Create `fraud/fraud_types.rs`

```rust
use serde::{Deserialize, Serialize};

/// Main flow data for fraud operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudFlowData {
    pub merchant_fraud_id: String,
    pub order_id: String,
    pub session_id: String,
    pub connector: String,
}

/// Fraud check status - matches Hyperswitch enum exactly
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FraudCheckStatus {
    Pending,
    Fraud,
    Legit,
    ManualReview,
    TransactionFailure,
}

/// Fraud action recommendation
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FraudAction {
    Accept,
    Reject,
}

/// Fraud score from provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudScore {
    pub score: i32,
    pub provider_scale: Option<String>,
}

/// Reason for fraud decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudReason {
    pub code: String,
    pub message: String,
    pub description: Option<String>,
    pub weight: Option<f32>,
}

// ============ Signifyd-specific types ============
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignifydPurchase {
    pub created_at: String,  // ISO8601
    pub order_channel: OrderChannel,
    pub total_price: i64,
    pub total_shipping_cost: Option<i64>,
    pub currency: Option<String>,
    pub confirmation_email: Option<String>,
    pub confirmation_phone: Option<String>,
    pub products: Vec<SignifydProduct>,
    pub shipments: Vec<SignifydShipment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OrderChannel {
    Web,
    Phone,
    Pos,
    MobileApp,
    Social,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignifydProduct {
    pub id: String,
    pub sku: String,
    pub title: String,
    pub quantity: i32,
    pub price: i64,
    pub category: Option<String>,
    pub brand: Option<String>,
    pub requires_shipping: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignifydShipment {
    pub carrier: Option<String>,
    pub tracking_number: Option<String>,
    pub tracking_url: Option<String>,
    pub destination: Option<Address>,
    pub products: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageRequests {
    Fraud,
    Inr,    // Item Not Received
    Snad,   // Significantly Not As Described
    All,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionDelivery {
    Sync,
    AsyncOnly,
}

// ============ Riskified-specific types ============
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskifiedOrder {
    pub id: String,
    pub email: Option<String>,
    pub created_at: String,  // ISO8601
    pub updated_at: String,
    pub currency: Option<String>,
    pub gateway: Option<String>,
    pub browser_ip: Option<String>,
    pub total_price: String,  // MAJOR UNITS!
    pub total_discounts: String,
    pub cart_token: String,
    pub referring_site: String,
    pub source: RiskifiedSource,
    pub vendor_name: String,
    pub line_items: Vec<RiskifiedLineItem>,
    pub shipping_lines: Vec<RiskifiedShippingLine>,
    pub customer: RiskifiedCustomer,
    pub billing_address: Option<RiskifiedAddress>,
    pub shipping_address: Option<RiskifiedAddress>,
    pub client_details: Option<RiskifiedClientDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskifiedSource {
    DesktopWeb,
    MobileWeb,
    Ios,
    Android,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskifiedLineItem {
    pub price: String,  // MAJOR UNITS!
    pub quantity: i32,
    pub title: String,
    pub product_type: RiskifiedProductType,
    pub requires_shipping: bool,
    pub product_id: String,
    pub category: Option<String>,
    pub brand: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskifiedProductType {
    Physical,
    Digital,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskifiedShippingLine {
    pub code: String,
    pub price: String,  // MAJOR UNITS!
    pub source: String,
    pub title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskifiedCustomer {
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub created_at: Option<String>,
    pub verified_email: bool,
    pub id: String,
    pub account_type: RiskifiedAccountType,
    pub orders_count: Option<i32>,
    pub phone: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskifiedAccountType {
    Guest,
    Registered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskifiedClientDetails {
    pub user_agent: Option<String>,
    pub accept_language: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskifiedAddress {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub city: Option<String>,
    pub country_code: Option<String>,
    pub province_code: Option<String>,
    pub zip: Option<String>,
    pub phone: Option<String>,
    pub company: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskifiedPaymentDetails {
    pub credit_card_bin: Option<String>,
    pub credit_card_number: Option<String>,
    pub credit_card_company: Option<RiskifiedCardNetwork>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskifiedCardNetwork {
    Visa,
    Mastercard,
    Amex,
    Discover,
    Jcb,
    DinersClub,
    Other,
}

// ============ Request/Response Types ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudEvaluatePreAuthorizationRequest {
    pub merchant_fraud_id: String,
    pub order_id: String,
    pub amount: i64,
    pub currency: String,
    pub customer: Customer,
    pub billing_address: Address,
    pub shipping_address: Address,
    pub browser_info: BrowserInformation,
    pub session_id: String,
    // Signifyd fields
    pub checkout_id: Option<String>,
    pub purchase: Option<SignifydPurchase>,
    pub coverage_requests: Option<CoverageRequests>,
    // Riskified fields
    pub line_items: Option<Vec<RiskifiedLineItem>>,
    pub shipping_lines: Option<Vec<RiskifiedShippingLine>>,
    pub vendor_name: Option<String>,
    pub gateway: Option<String>,
    pub referring_site: Option<String>,
    pub cart_token: Option<String>,
    pub total_discounts: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudEvaluatePreAuthorizationResponse {
    pub fraud_id: String,
    pub status: FraudCheckStatus,
    pub recommended_action: FraudAction,
    pub score: Option<FraudScore>,
    pub reasons: Vec<FraudReason>,
    pub case_id: Option<String>,
    pub redirect_url: Option<String>,
    pub connector_metadata: Option<serde_json::Value>,
}

// ... similar structs for other flows
```

### 2.4 Update `connector_flow.rs`

```rust
// Add to crates/types-traits/domain_types/src/connector_flow.rs

// ============ FRAUD FLOW MARKERS ============
#[derive(Debug, Clone)]
pub struct FraudEvaluatePreAuthorization;

#[derive(Debug, Clone)]
pub struct FraudEvaluatePostAuthorization;

#[derive(Debug, Clone)]
pub struct FraudRecordTransactionData;

#[derive(Debug, Clone)]
pub struct FraudRecordFulfillmentData;

#[derive(Debug, Clone)]
pub struct FraudRecordReturnData;

#[derive(Debug, Clone)]
pub struct FraudGet;

// Add to FlowName enum
#[derive(strum::Display)]
#[strum(serialize_all = "snake_case")]
pub enum FlowName {
    // ... existing variants
    FraudEvaluatePreAuthorization,
    FraudEvaluatePostAuthorization,
    FraudRecordTransactionData,
    FraudRecordFulfillmentData,
    FraudRecordReturnData,
    FraudGet,
}
```

---

## Phase 3: Connector Implementations (Week 2-4)

### 3.1 Architecture Principles

**CRITICAL**: Follow PaymentService pattern exactly:
1. **NO `interfaces/src/fraud.rs`** - Implement `ConnectorIntegrationV2` directly
2. Use macro-based implementations (see `stripe.rs`, `adyen.rs`)
3. Create `transformers.rs` subdirectory for complex mappings

### 3.2 Signifyd Connector

**File**: `crates/integrations/connector-integration/src/connectors/signifyd.rs`

```rust
mod transformers;

use domain_types::{
    connector_flow,
    fraud::fraud_types::*,
    fraud::router_request_types::*,
};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
};

pub struct Signifyd;

// Currency unit: MINOR (cents)
impl ConnectorCommon for Signifyd {
    fn id(&self) -> &'static str {
        "signifyd"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.signifyd.base_url.as_str()
    }

    fn get_auth_header(&self, auth_type: &ConnectorSpecificConfig) -> CustomResult<...> {
        // Basic Auth with Base64
        let auth = SignifydAuthType::try_from(auth_type)?;
        let encoded = BASE64_ENGINE.encode(auth.api_key.peek());
        Ok(vec![(
            "Authorization".to_string(),
            format!("Basic {}", encoded).into_masked(),
        )])
    }
}

// Use macro for implementations (following stripe.rs pattern)
macros::macro_connector_implementation!(
    connector: Signifyd,
    flow_name: FraudEvaluatePreAuthorization,
    // ... configuration
);
```

**Endpoints**:
| Method | Endpoint |
|--------|----------|
| EvaluatePreAuthorization | POST /v3/orders/events/checkouts |
| EvaluatePostAuthorization | POST /v3/orders/events/transactions |
| RecordTransactionData | POST /v3/orders/events/sales |
| RecordFulfillmentData | POST /v3/orders/events/fulfillments |
| RecordReturnData | POST /v3/orders/events/returns/records |
| Get | GET /v3/decisions/{orderId} |

### 3.3 Riskified Connector

**File**: `crates/integrations/connector-integration/src/connectors/riskified.rs`

```rust
mod transformers;

pub struct Riskified;

// Currency unit: MAJOR (dollars)
impl ConnectorCommon for Riskified {
    fn id(&self) -> &'static str {
        "riskified"
    }

    fn get_currency_unit(&self) -> CurrencyUnit {
        CurrencyUnit::Major  // DIFFERENT FROM SIGNIFYD!
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.riskified.base_url.as_str()
    }

    fn get_auth_header(&self, auth_type: &ConnectorSpecificConfig) -> CustomResult<...> {
        // HMAC-SHA256 hex signature
        // See implementation guide for details
        todo!("Implement HMAC-SHA256 auth")
    }
}
```

**Endpoints**:
| Method | Endpoint | Notes |
|--------|----------|-------|
| EvaluatePreAuthorization | POST /decide | Synchronous response |
| EvaluatePostAuthorization | POST /decision OR /checkout_denied | Split by success/failure |
| RecordTransactionData | POST /decide | Async submission |
| RecordFulfillmentData | POST /fulfill | |
| RecordReturnData | POST /partial_refund | |
| Get | **NOT SUPPORTED** | Returns error |

### 3.4 Connector Registration

Update `crates/integrations/connector-integration/src/connectors.rs`:

```rust
pub mod signifyd;
pub use self::signifyd::Signifyd;

pub mod riskified;
pub use self::riskified::Riskified;
```

---

## Phase 4: gRPC Service Handler (Week 4)

**File**: `crates/router-grpc/src/fraud_service.rs`

Skeleton implementation:

```rust
pub struct FraudServiceHandler;

#[async_trait::async_trait]
impl FraudService for FraudServiceHandler {
    async fn evaluate_pre_authorization(
        &self,
        request: Request<FraudServiceEvaluatePreAuthorizationRequest>,
    ) -> Result<Response<FraudServiceEvaluatePreAuthorizationResponse>, Status> {
        // Route to appropriate connector
        todo!()
    }

    // ... other methods
}
```

---

## Phase 5: Testing (Week 5)

### 5.1 Unit Tests

Create tests for:
- Request/response transformation
- Status mapping
- Currency unit conversion
- Error handling

### 5.2 Integration Test Scenarios

Create YAML scenarios in `crates/internal/ucs-connector-tests/scenarios/fraud/`:

**Signifyd scenarios**:
- `signifyd/pre_auth_approved.yaml`
- `signifyd/pre_auth_rejected.yaml`
- `signifyd/transaction_update.yaml`
- `signifyd/fulfillment_record.yaml`
- `signifyd/return_record.yaml`
- `signifyd/decision_get.yaml`

**Riskified scenarios**:
- `riskified/checkout_decide_approved.yaml`
- `riskified/checkout_decide_declined.yaml`
- `riskified/decision_success.yaml`
- `riskified/checkout_denied.yaml`
- `riskified/fulfill.yaml`
- `riskified/partial_refund.yaml`

---

## Risk Matrix

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Provider API changes | Medium | High | Use versioned endpoints, monitor changelogs |
| Currency unit mismatch | High | High | Explicit `CurrencyUnit` in connector config |
| Riskified Get method not supported | Certain | Medium | Document limitation, implement webhook cache |
| Field mapping complexity | Medium | Medium | Comprehensive transformer tests |
| HMAC-SHA256 auth errors | Medium | High | Test auth signature generation thoroughly |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-04-06 | Initial plan with 6 flows |
| 2.0.0 | 2026-04-06 | Updated method names |
| 3.0.0 | 2026-04-07 | **Fixed provider-specific fields**, corrected endpoints, added auth details, documented currency units |
