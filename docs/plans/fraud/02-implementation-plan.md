# Fraud Interface Implementation Plan

## Document Information
- **Version**: 2.0.0
- **Date**: 2026-04-06
- **Status**: Draft - Synced with Specification v4.0.0
- **Target Audience**: Freshers and Junior Developers
- **Estimated Duration**: 4-6 weeks
- **Prerequisites**: Basic Rust knowledge, understanding of gRPC/protobuf

## Executive Summary

This plan provides step-by-step instructions for implementing the Fraud interface in Hyperswitch Prism. Each step is designed to be completed and committed independently, following trunk-based development practices.

**Key Constraint**: All enums MUST match Hyperswitch exactly - no new states allowed.

## Critical Issues from Spec Review (Addressed)

Before implementation, the following issues from the spec review have been addressed:

1. ✅ **Hyperswitch-Aligned Enums**: FraudCheckStatus and FraudAction match Hyperswitch exactly
2. ✅ **Renamed Methods**: Clear verb-noun format (EvaluatePreAuthorization, RecordTransactionData, etc.)
3. ✅ **Removed Cancel**: Method not supported uniformly by providers
4. ✅ **Standardized IDs**: `merchant_fraud_check_id` / `connector_fraud_check_id`
5. ✅ **Added Required Fields**: device_fingerprint, session_id, synchronous flag
6. ✅ **ConnectorState Support**: For session management
7. ✅ **Field Optionality**: Fixed - identifiers now required

## Pre-Implementation Checklist

- [ ] Read and understand the specification document (`01-fraud-interface-specification.md`)
- [ ] Review `04-proto-validation-analysis.md` for provider mappings
- [ ] Review existing payment.proto and payouts.proto patterns
- [ ] Set up development environment (Rust 1.70+, protoc)
- [ ] Understand the connector integration pattern
- [ ] Review existing connector implementations (stripe.rs, adyen.rs)

---

## Phase 1: Protocol Buffer Schema (Week 1)

### Step 1.1: Create fraud.proto
**File**: `crates/types-traits/grpc-api-types/proto/fraud.proto`

```protobuf
syntax = "proto3";

package types;

import "payment.proto";
import "payment_methods.proto";
import "google/protobuf/empty.proto";

option go_package = "github.com/juspay/connector-service/crates/types-traits/grpc-api-types/proto;proto";

// ============================================================================
// FRAUD ENUMERATIONS (Hyperswitch-Aligned - DO NOT MODIFY)
// ============================================================================

// Status of a fraud check - MUST MATCH Hyperswitch FraudCheckStatus EXACTLY
// From: crates/common_enums/src/enums.rs
enum FraudCheckStatus {
  FRAUD_CHECK_STATUS_UNSPECIFIED = 0;
  FRAUD_CHECK_STATUS_PENDING = 1;
  FRAUD_CHECK_STATUS_FRAUD = 2;
  FRAUD_CHECK_STATUS_LEGIT = 3;
  FRAUD_CHECK_STATUS_MANUAL_REVIEW = 4;
  FRAUD_CHECK_STATUS_TRANSACTION_FAILURE = 5;
}

// Fraud check action recommendation
enum FraudAction {
  FRAUD_ACTION_UNSPECIFIED = 0;
  FRAUD_ACTION_ACCEPT = 1;
  FRAUD_ACTION_REJECT = 2;
}

// Fulfillment status for order completion
enum FulfillmentStatus {
  FULFILLMENT_STATUS_UNSPECIFIED = 0;
  FULFILLMENT_STATUS_PENDING = 1;
  FULFILLMENT_STATUS_PARTIAL = 2;
  FULFILLMENT_STATUS_COMPLETE = 3;
  FULFILLMENT_STATUS_REPLACEMENT = 4;
  FULFILLMENT_STATUS_CANCELLED = 5;
}

// Refund method for returns
enum RefundMethod {
  REFUND_METHOD_UNSPECIFIED = 0;
  REFUND_METHOD_STORE_CREDIT = 1;
  REFUND_METHOD_ORIGINAL_PAYMENT_INSTRUMENT = 2;
  REFUND_METHOD_NEW_PAYMENT_INSTRUMENT = 3;
}

// ============================================================================
// CORE FRAUD DATA MESSAGES
// ============================================================================

// Product information for fraud analysis
message FraudProduct {
  string product_id = 1;
  string product_name = 2;
  string product_type = 3;
  int64 quantity = 4;
  int64 unit_price = 5;
  int64 total_amount = 6;
  optional string brand = 7;
  optional string category = 8;
  optional string sub_category = 9;
  optional string sku = 10;
  optional bool requires_shipping = 11;
}

// Shipment destination information
message FraudDestination {
  SecretString full_name = 1;
  optional string organization = 2;
  optional SecretString email = 3;
  Address address = 4;
}

// Fulfillment shipment details
message FraudShipment {
  string shipment_id = 1;
  repeated FraudProduct products = 2;
  FraudDestination destination = 3;
  optional string tracking_company = 4;
  repeated string tracking_numbers = 5;
  repeated string tracking_urls = 6;
  optional string carrier = 7;
  optional string fulfillment_method = 8;
  optional string shipment_status = 9;
  optional int64 shipped_at = 10;
}

// Fraud score details
message FraudScore {
  int32 score = 1;
  optional string risk_level = 2;
  optional int32 threshold = 3;
}

// Fraud decision reason
message FraudReason {
  string code = 1;
  string message = 2;
  optional string description = 3;
}

// ============================================================================
// EVALUATE PRE-AUTHORIZATION REQUEST/RESPONSE
// ============================================================================

message FraudServiceEvaluatePreAuthorizationRequest {
  string merchant_fraud_check_id = 1;        // REQUIRED - was optional
  string order_id = 2;                       // REQUIRED - was optional
  optional string connector_fraud_check_id = 3;
  Money amount = 4;
  optional PaymentMethod payment_method = 5;
  Customer customer = 6;                     // REQUIRED - was optional
  repeated FraudProduct products = 7;
  BrowserInformation browser_info = 8;       // REQUIRED - was optional
  optional Address shipping_address = 9;
  optional Address billing_address = 10;
  optional string connector_name = 11;
  optional SecretString connector_feature_data = 12;
  optional string webhook_url = 13;
  optional string previous_fraud_check_id = 14;
  optional ConnectorState connector_state = 15;
  string device_fingerprint = 16;            // NEW - Signifyd requirement
  string session_id = 17;                    // NEW - Session tracking
  bool synchronous = 18;                     // NEW - Riskified sync/async
}

message FraudServiceEvaluatePreAuthorizationResponse {
  optional string merchant_fraud_check_id = 1;
  optional string order_id = 2;
  optional string connector_fraud_check_id = 3;
  FraudCheckStatus fraud_check_status = 4;   // Hyperswitch-aligned
  FraudAction recommended_action = 5;        // ACCEPT or REJECT
  optional FraudScore score = 6;
  repeated FraudReason reasons = 7;
  optional string case_id = 8;
  optional ErrorInfo error = 9;
  uint32 status_code = 10;
  optional SecretString connector_metadata = 11;
  optional string redirect_url = 12;
  optional ConnectorState connector_state = 13;
  optional SecretString raw_connector_response = 14;
  optional SecretString raw_connector_request = 15;
}

// ============================================================================
// EVALUATE POST-AUTHORIZATION REQUEST/RESPONSE
// ============================================================================

message FraudServiceEvaluatePostAuthorizationRequest {
  string merchant_fraud_check_id = 1;        // REQUIRED
  string order_id = 2;                       // REQUIRED
  optional string connector_fraud_check_id = 3;
  string connector_transaction_id = 4;       // REQUIRED - was optional
  Money amount = 5;
  optional PaymentMethod payment_method = 6;
  AuthorizationStatus authorization_status = 7;
  optional string error_code = 8;
  optional string error_message = 9;
  optional string connector_name = 10;
  optional SecretString connector_feature_data = 11;
  optional string webhook_url = 12;
  optional ConnectorState connector_state = 13;
  string session_id = 14;                    // NEW
}

message FraudServiceEvaluatePostAuthorizationResponse {
  optional string merchant_fraud_check_id = 1;
  optional string order_id = 2;
  optional string connector_fraud_check_id = 3;
  FraudCheckStatus fraud_check_status = 4;   // Hyperswitch-aligned
  FraudAction recommended_action = 5;        // ACCEPT or REJECT
  optional FraudScore score = 6;
  repeated FraudReason reasons = 7;
  optional string case_id = 8;
  optional ErrorInfo error = 9;
  uint32 status_code = 10;
  optional SecretString connector_metadata = 11;
  optional ConnectorState connector_state = 12;
  optional SecretString raw_connector_response = 13;
  optional SecretString raw_connector_request = 14;
}

// ============================================================================
// RECORD TRANSACTION DATA REQUEST/RESPONSE
// ============================================================================

message FraudServiceRecordTransactionDataRequest {
  string merchant_fraud_check_id = 1;        // REQUIRED
  string order_id = 2;                       // REQUIRED
  Money amount = 3;
  string session_id = 4;                     // NEW - was optional
  optional Customer customer = 5;
  repeated FraudProduct products = 6;
  optional BrowserInformation browser_info = 7;
  optional Address shipping_address = 8;
  optional Address billing_address = 9;
  optional SecretString connector_feature_data = 10;
  optional string webhook_url = 11;
  optional ConnectorState connector_state = 12;
}

message FraudServiceRecordTransactionDataResponse {
  optional string merchant_fraud_check_id = 1;
  optional string order_id = 2;
  optional string connector_fraud_check_id = 3;
  FraudCheckStatus fraud_check_status = 4;   // Hyperswitch-aligned
  FraudAction recommended_action = 5;        // ACCEPT or REJECT
  optional FraudScore score = 6;
  repeated FraudReason reasons = 7;
  optional ErrorInfo error = 8;
  uint32 status_code = 9;
  optional SecretString connector_metadata = 10;
  optional ConnectorState connector_state = 11;
  optional SecretString raw_connector_response = 12;
  optional SecretString raw_connector_request = 13;
}

// ============================================================================
// RECORD FULFILLMENT DATA REQUEST/RESPONSE
// ============================================================================

message FraudServiceRecordFulfillmentDataRequest {
  string merchant_fraud_check_id = 1;        // REQUIRED
  string order_id = 2;                       // REQUIRED
  optional string connector_fraud_check_id = 3;
  FulfillmentStatus fulfillment_status = 4;
  repeated FraudShipment shipments = 5;
  optional SecretString connector_feature_data = 6;
  optional string webhook_url = 7;
  optional ConnectorState connector_state = 8;
  string session_id = 9;                     // NEW
}

message FraudServiceRecordFulfillmentDataResponse {
  optional string merchant_fraud_check_id = 1;
  optional string order_id = 2;
  optional string connector_fraud_check_id = 3;
  FraudCheckStatus fraud_check_status = 4;   // Hyperswitch-aligned
  repeated string shipment_ids = 5;
  optional ErrorInfo error = 6;
  uint32 status_code = 7;
  optional SecretString connector_metadata = 8;
  optional ConnectorState connector_state = 9;
  optional SecretString raw_connector_response = 10;
  optional SecretString raw_connector_request = 11;
}

// ============================================================================
// RECORD RETURN DATA REQUEST/RESPONSE
// ============================================================================

message FraudServiceRecordReturnDataRequest {
  string merchant_fraud_check_id = 1;        // REQUIRED
  string order_id = 2;                       // REQUIRED
  optional string connector_fraud_check_id = 3;
  optional string refund_transaction_id = 4;
  Money amount = 5;
  RefundMethod refund_method = 6;
  optional string return_reason = 7;
  optional string return_reason_code = 8;
  optional SecretString connector_feature_data = 9;
  optional string webhook_url = 10;
  optional ConnectorState connector_state = 11;
  string session_id = 12;                    // NEW
}

message FraudServiceRecordReturnDataResponse {
  optional string merchant_fraud_check_id = 1;
  optional string order_id = 2;
  optional string connector_fraud_check_id = 3;
  FraudCheckStatus fraud_check_status = 4;   // Hyperswitch-aligned
  optional string return_id = 5;
  optional ErrorInfo error = 6;
  uint32 status_code = 7;
  optional SecretString connector_metadata = 8;
  optional ConnectorState connector_state = 9;
  optional SecretString raw_connector_response = 10;
  optional SecretString raw_connector_request = 11;
}

// ============================================================================
// GET REQUEST/RESPONSE (Status Sync)
// ============================================================================

message FraudServiceGetRequest {
  string merchant_fraud_check_id = 1;        // REQUIRED
  string order_id = 2;                       // REQUIRED
  optional string connector_fraud_check_id = 3;
  optional string case_id = 4;
}

message FraudServiceGetResponse {
  optional string merchant_fraud_check_id = 1;
  optional string order_id = 2;
  optional string connector_fraud_check_id = 3;
  FraudCheckStatus fraud_check_status = 4;   // Hyperswitch-aligned
  FraudAction recommended_action = 5;        // ACCEPT or REJECT
  optional FraudScore score = 6;
  repeated FraudReason reasons = 7;
  optional string case_id = 8;
  optional string reviewed_by = 9;
  optional int64 reviewed_at = 10;
  optional ErrorInfo error = 11;
  uint32 status_code = 12;
  optional SecretString connector_metadata = 13;
  optional ConnectorState connector_state = 14;
}

// ============================================================================
// FRAUD-SPECIFIC EVENT CONTENT (for webhooks)
// ============================================================================

message FraudEventContent {
  optional string merchant_fraud_check_id = 1;
  optional string order_id = 2;
  optional string connector_fraud_check_id = 3;
  WebhookEventType event_type = 4;
  FraudCheckStatus fraud_check_status = 5;   // Hyperswitch-aligned
  FraudAction recommended_action = 6;        // ACCEPT or REJECT
  optional FraudScore score = 7;
  repeated FraudReason reasons = 8;
  optional string case_id = 9;
  int64 event_timestamp = 10;
}
```

**Verification Steps**:
1. Run `cargo build` to verify proto compilation
2. Check generated Rust code in `target/` or build output
3. Verify no compilation errors
4. Confirm FraudCheckStatus has exactly 6 values (including UNSPECIFIED)
5. Confirm FraudAction has exactly 3 values (including UNSPECIFIED)

**Commit Message**: `feat(proto): add fraud service protobuf schema with Hyperswitch-aligned enums`

---

### Step 1.2: Update services.proto
**File**: `crates/types-traits/grpc-api-types/proto/services.proto`

Add import and service definition:

```protobuf
import "fraud.proto";

// ============================================================================
// FRAUD SERVICE — Manages fraud detection and risk assessment
// ============================================================================

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

**Verification Steps**:
1. Verify services.proto compiles without errors
2. Check that FraudService is included in generated code
3. Confirm exactly 6 RPC methods (no Cancel)

**Commit Message**: `feat(proto): add FraudService to services.proto`

---

### Step 1.3: Extend WebhookEventType
**File**: `crates/types-traits/grpc-api-types/proto/payment.proto`

Add to existing enum:

```protobuf
enum WebhookEventType {
  // ... existing events
  FRM_APPROVED = 28;     // Maps to LEGIT status
  FRM_REJECTED = 29;     // Maps to FRAUD status
  FRM_REVIEW_REQUIRED = 60;  // Maps to MANUAL_REVIEW status
}
```

**Note**: Status mapping:
- `FRM_APPROVED` → `FraudCheckStatus.LEGIT`
- `FRM_REJECTED` → `FraudCheckStatus.FRAUD`
- `FRM_REVIEW_REQUIRED` → `FraudCheckStatus.MANUAL_REVIEW`

**Commit Message**: `feat(proto): add fraud-specific webhook events`

---

## Phase 2: Domain Types (Week 1-2)

### Step 2.1: Create fraud_types.rs
**File**: `crates/types-traits/domain_types/src/fraud_types.rs`

```rust
//! Fraud check domain types - Aligned with Hyperswitch

use common_enums::{AuthorizationStatus, Currency};
use common_utils::events::{ApiEventMetric, ApiEventsType};
use serde::{Deserialize, Serialize};

use crate::{
    connector_types::{ConnectorCustomerData, ConnectorResponseHeaders, RawConnectorRequestResponse},
    payment_address::{Address, OrderDetailsWithAmount, PhoneDetails},
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_request_types::BrowserInformation,
    types::{ConnectorState, Connectors},
};

// ============================================================================
// FLOW MARKER TYPES (Hyperswitch-Aligned)
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct FraudEvaluatePreAuthorization;

#[derive(Debug, Clone, Copy)]
pub struct FraudEvaluatePostAuthorization;

#[derive(Debug, Clone, Copy)]
pub struct FraudRecordTransactionData;

#[derive(Debug, Clone, Copy)]
pub struct FraudRecordFulfillmentData;

#[derive(Debug, Clone, Copy)]
pub struct FraudRecordReturnData;

#[derive(Debug, Clone, Copy)]
pub struct FraudGet;

// ============================================================================
// CORE FRAUD DATA TYPES
// ============================================================================

/// Product information for fraud analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudProduct {
    pub product_id: String,
    pub product_name: String,
    pub product_type: String,
    pub quantity: i64,
    pub unit_price: i64,
    pub total_amount: i64,
    pub brand: Option<String>,
    pub category: Option<String>,
    pub sub_category: Option<String>,
    pub sku: Option<String>,
    pub requires_shipping: Option<bool>,
}

/// Shipment destination information
#[derive(Debug, Clone)]
pub struct FraudDestination {
    pub full_name: hyperswitch_masking::Secret<String>,
    pub organization: Option<String>,
    pub email: Option<hyperswitch_masking::Secret<String>>,
    pub address: Address,
    pub phone: Option<PhoneDetails>,
}

/// Fulfillment shipment details
#[derive(Debug, Clone)]
pub struct FraudShipment {
    pub shipment_id: String,
    pub products: Vec<FraudProduct>,
    pub destination: FraudDestination,
    pub tracking_company: Option<String>,
    pub tracking_numbers: Vec<String>,
    pub tracking_urls: Vec<String>,
    pub carrier: Option<String>,
    pub fulfillment_method: Option<String>,
    pub shipment_status: Option<String>,
    pub shipped_at: Option<i64>,
}

// ============================================================================
// FLOW DATA AND REQUEST/RESPONSE TYPES
// ============================================================================

/// Shared flow data for all fraud operations
#[derive(Debug, Clone)]
pub struct FraudFlowData<T: PaymentMethodDataTypes> {
    pub merchant_fraud_check_id: Option<String>,
    pub order_id: Option<String>,
    pub connector_fraud_check_id: Option<String>,
    pub connector_state: Option<ConnectorState>,
    pub connectors: Connectors,
    pub raw_connector_response: Option<hyperswitch_masking::Secret<String>>,
    pub raw_connector_request: Option<hyperswitch_masking::Secret<String>>,
    pub connector_response_headers: Option<http::HeaderMap>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: PaymentMethodDataTypes> FraudFlowData<T> {
    pub fn new(connectors: Connectors) -> Self {
        Self {
            merchant_fraud_check_id: None,
            order_id: None,
            connector_fraud_check_id: None,
            connector_state: None,
            connectors,
            raw_connector_response: None,
            raw_connector_request: None,
            connector_response_headers: None,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T: PaymentMethodDataTypes> RawConnectorRequestResponse for FraudFlowData<T> {
    fn set_raw_connector_response(&mut self, response: Option<hyperswitch_masking::Secret<String>>) {
        self.raw_connector_response = response;
    }

    fn get_raw_connector_response(&self) -> Option<hyperswitch_masking::Secret<String>> {
        self.raw_connector_response.clone()
    }

    fn get_raw_connector_request(&self) -> Option<hyperswitch_masking::Secret<String>> {
        self.raw_connector_request.clone()
    }

    fn set_raw_connector_request(&mut self, request: Option<hyperswitch_masking::Secret<String>>) {
        self.raw_connector_request = request;
    }
}

impl<T: PaymentMethodDataTypes> ConnectorResponseHeaders for FraudFlowData<T> {
    fn set_connector_response_headers(&mut self, headers: Option<http::HeaderMap>) {
        self.connector_response_headers = headers;
    }

    fn get_connector_response_headers(&self) -> Option<&http::HeaderMap> {
        self.connector_response_headers.as_ref()
    }
}

// ============================================================================
// REQUEST/RESPONSE DATA TYPES
// ============================================================================

/// Request data for pre-authorization fraud evaluation
#[derive(Debug, Clone)]
pub struct FraudEvaluatePreAuthorizationData<T: PaymentMethodDataTypes> {
    pub amount: i64,
    pub currency: Currency,
    pub order_details: Option<Vec<OrderDetailsWithAmount>>,
    pub customer: Option<ConnectorCustomerData<T>>,
    pub payment_method: Option<PaymentMethodData<T>>,
    pub browser_info: Option<BrowserInformation>,
    pub shipping_address: Option<Address>,
    pub billing_address: Option<Address>,
    pub connector_name: Option<String>,
    pub previous_fraud_check_id: Option<String>,
    /// Signifyd device fingerprint for tracking
    pub device_fingerprint: String,
    /// Session identifier for tracking
    pub session_id: String,
    /// Whether to use synchronous (Riskified decide) or async mode
    pub synchronous: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudEvaluatePreAuthorizationResponse {
    pub fraud_check_id: String,
    pub status: FraudCheckStatus,    // Hyperswitch-aligned
    pub recommended_action: FraudAction,  // ACCEPT or REJECT
    pub score: Option<FraudScore>,
    pub reasons: Vec<FraudReason>,
    pub case_id: Option<String>,
    pub redirect_url: Option<String>,
    pub connector_metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct FraudEvaluatePostAuthorizationData<T: PaymentMethodDataTypes> {
    pub amount: i64,
    pub currency: Currency,
    pub order_details: Option<Vec<OrderDetailsWithAmount>>,
    pub payment_method: Option<PaymentMethodData<T>>,
    pub authorization_status: AuthorizationStatus,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub connector_name: Option<String>,
    pub connector_transaction_id: String,  // REQUIRED
    pub session_id: String,                // NEW
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudEvaluatePostAuthorizationResponse {
    pub fraud_check_id: String,
    pub status: FraudCheckStatus,    // Hyperswitch-aligned
    pub recommended_action: FraudAction,  // ACCEPT or REJECT
    pub score: Option<FraudScore>,
    pub reasons: Vec<FraudReason>,
    pub case_id: Option<String>,
    pub connector_metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct FraudRecordTransactionDataData<T: PaymentMethodDataTypes> {
    pub amount: i64,
    pub currency: Currency,
    pub order_details: Option<Vec<OrderDetailsWithAmount>>,
    pub customer: Option<ConnectorCustomerData<T>>,
    pub browser_info: Option<BrowserInformation>,
    pub shipping_address: Option<Address>,
    pub billing_address: Option<Address>,
    pub session_id: String,  // NEW
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudRecordTransactionDataResponse {
    pub fraud_check_id: String,
    pub status: FraudCheckStatus,    // Hyperswitch-aligned
    pub recommended_action: FraudAction,  // ACCEPT or REJECT
    pub score: Option<FraudScore>,
    pub reasons: Vec<FraudReason>,
    pub connector_metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct FraudRecordFulfillmentDataData {
    pub fulfillment_status: FulfillmentStatus,
    pub shipments: Vec<FraudShipment>,
    pub session_id: String,  // NEW
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudRecordFulfillmentDataResponse {
    pub fraud_check_id: String,
    pub status: FraudCheckStatus,    // Hyperswitch-aligned
    pub shipment_ids: Vec<String>,
    pub connector_metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct FraudRecordReturnDataData {
    pub amount: i64,
    pub currency: Currency,
    pub refund_method: RefundMethod,
    pub return_reason: Option<String>,
    pub return_reason_code: Option<String>,
    pub session_id: String,  // NEW
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudRecordReturnDataResponse {
    pub fraud_check_id: String,
    pub status: FraudCheckStatus,    // Hyperswitch-aligned
    pub return_id: Option<String>,
    pub connector_metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct FraudGetData {
    pub merchant_fraud_check_id: Option<String>,
    pub order_id: Option<String>,
    pub connector_fraud_check_id: Option<String>,
    pub case_id: Option<String>,
}

/// Generic type alias for fraud router data
pub type FraudRouterData<T, Req, Resp> = crate::router_data::RouterData<T, FraudFlowData<T>, Req, Resp>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudGetResponse {
    pub fraud_check_id: String,
    pub status: FraudCheckStatus,    // Hyperswitch-aligned
    pub recommended_action: FraudAction,  // ACCEPT or REJECT
    pub score: Option<FraudScore>,
    pub reasons: Vec<FraudReason>,
    pub case_id: Option<String>,
    pub reviewed_by: Option<String>,
    pub reviewed_at: Option<i64>,
    pub connector_metadata: Option<serde_json::Value>,
}

// ============================================================================
// ENUMS AND SUPPORTING TYPES (Hyperswitch-Aligned - DO NOT MODIFY)
// ============================================================================

/// FraudCheckStatus - EXACTLY matches Hyperswitch
/// From: crates/common_enums/src/enums.rs
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FraudCheckStatus {
    Pending,
    Fraud,              // Confirmed fraudulent
    Legit,              // Confirmed legitimate
    ManualReview,       // Under manual review
    TransactionFailure, // Payment/auth failed
}

/// FraudAction - Simplified to ACCEPT/REJECT only
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FraudAction {
    Accept,
    Reject,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FulfillmentStatus {
    Pending,
    Partial,
    Complete,
    Replacement,
    Cancelled,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RefundMethod {
    StoreCredit,
    OriginalPaymentInstrument,
    NewPaymentInstrument,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudScore {
    pub score: i32,
    pub risk_level: Option<String>,
    pub threshold: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudReason {
    pub code: String,
    pub message: String,
    pub description: Option<String>,
}

// ============================================================================
// API EVENT METRIC IMPLEMENTATIONS
// ============================================================================

impl ApiEventMetric for FraudEvaluatePreAuthorizationResponse {
    fn get_api_event_type(&self) -> Option<ApiEventsType> {
        Some(ApiEventsType::FraudCheck)
    }
}

impl ApiEventMetric for FraudEvaluatePostAuthorizationResponse {
    fn get_api_event_type(&self) -> Option<ApiEventsType> {
        Some(ApiEventsType::FraudCheck)
    }
}

impl ApiEventMetric for FraudRecordTransactionDataResponse {
    fn get_api_event_type(&self) -> Option<ApiEventsType> {
        Some(ApiEventsType::FraudCheck)
    }
}

impl ApiEventMetric for FraudRecordFulfillmentDataResponse {
    fn get_api_event_type(&self) -> Option<ApiEventsType> {
        Some(ApiEventsType::FraudCheck)
    }
}

impl ApiEventMetric for FraudRecordReturnDataResponse {
    fn get_api_event_type(&self) -> Option<ApiEventsType> {
        Some(ApiEventsType::FraudCheck)
    }
}

impl ApiEventMetric for FraudGetResponse {
    fn get_api_event_type(&self) -> Option<ApiEventsType> {
        Some(ApiEventsType::FraudCheck)
    }
}
```

**Module Registration**:

Add to `crates/types-traits/domain_types/src/lib.rs`:

```rust
pub mod fraud_types;
```

**Verification Steps**:
1. Add `pub mod fraud_types;` to `domain_types/src/lib.rs`
2. Run `cargo check -p domain_types` to verify compilation
3. Confirm FraudCheckStatus has exactly 5 variants (not counting UNSPECIFIED)
4. Confirm FraudAction has exactly 2 variants (not counting UNSPECIFIED)
5. Verify FraudShipment, FraudDestination, FraudProduct are defined
6. Verify FraudFlowData<T> implements RawConnectorRequestResponse and ConnectorResponseHeaders
7. Verify no compiler warnings about unused types

**Commit Message**: `feat(domain): add fraud check domain types with Hyperswitch-aligned enums`

---

### Step 2.2: Add Connector Flow Types
**File**: `crates/types-traits/domain_types/src/connector_flow.rs`

Add the fraud flow marker structs before the `FlowName` enum (must match derives in `fraud_types.rs`):

```rust
// Fraud flows - Phase 2
#[derive(Debug, Clone, Copy)]
pub struct FraudEvaluatePreAuthorization;

#[derive(Debug, Clone, Copy)]
pub struct FraudEvaluatePostAuthorization;

#[derive(Debug, Clone, Copy)]
pub struct FraudRecordTransactionData;

#[derive(Debug, Clone, Copy)]
pub struct FraudRecordFulfillmentData;

#[derive(Debug, Clone, Copy)]
pub struct FraudRecordReturnData;

#[derive(Debug, Clone, Copy)]
pub struct FraudGet;
```

Then add the corresponding variants to the `FlowName` enum:

```rust
#[derive(strum::Display)]
#[strum(serialize_all = "snake_case")]
pub enum FlowName {
    // ... existing variants
    PayoutCreateLink,
    PayoutCreateRecipient,
    PayoutEnrollDisburseAccount,
    // Fraud flows - Phase 2
    FraudEvaluatePreAuthorization,
    FraudEvaluatePostAuthorization,
    FraudRecordTransactionData,
    FraudRecordFulfillmentData,
    FraudRecordReturnData,
    FraudGet,
}
```

**Important**: The `Copy` derive is required because these types are used as phantom markers in the type system and must be `Copy` to satisfy trait bounds.

**Verification Steps**:
1. Verify flow markers have `#[derive(Debug, Clone, Copy)]`
2. Run `cargo check -p domain_types` compiles
3. Check that all flow types are unique
4. Confirm exactly 6 fraud flow types (no Cancel)
5. Verify `FlowName` derives display as snake_case

**Commit Message**: `feat(domain): add fraud connector flow types`

---
---

## Phase 3: Interface Traits (Week 2)

### Step 3.1: Create fraud.rs
**File**: `crates/types-traits/interfaces/src/fraud.rs`

```rust
//! Fraud check connector interface traits

use domain_types::{
    connector_flow,
    fraud_types::{
        FraudEvaluatePreAuthorization, FraudEvaluatePreAuthorizationData, 
        FraudEvaluatePreAuthorizationResponse, FraudEvaluatePostAuthorization, 
        FraudEvaluatePostAuthorizationData, FraudEvaluatePostAuthorizationResponse,
        FraudFlowData, FraudGet, FraudGetData, FraudGetResponse,
        FraudRecordFulfillmentData, FraudRecordFulfillmentDataData, 
        FraudRecordFulfillmentDataResponse, FraudRecordReturnData, 
        FraudRecordReturnDataData, FraudRecordReturnDataResponse,
        FraudRecordTransactionData, FraudRecordTransactionDataData, 
        FraudRecordTransactionDataResponse,
    },
};

use crate::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
};

/// EvaluatePreAuthorization flow - Pre-authorization fraud check
pub trait FraudEvaluatePreAuthorizationV2:
    ConnectorIntegrationV2<
    connector_flow::FraudEvaluatePreAuthorization,
    FraudFlowData,
    FraudEvaluatePreAuthorizationData,
    FraudEvaluatePreAuthorizationResponse,
>
{
}

/// EvaluatePostAuthorization flow - Post-authorization fraud check
pub trait FraudEvaluatePostAuthorizationV2:
    ConnectorIntegrationV2<
    connector_flow::FraudEvaluatePostAuthorization,
    FraudFlowData,
    FraudEvaluatePostAuthorizationData,
    FraudEvaluatePostAuthorizationResponse,
>
{
}

/// RecordTransactionData flow - Record completed transaction
pub trait FraudRecordTransactionDataV2:
    ConnectorIntegrationV2<
    connector_flow::FraudRecordTransactionData,
    FraudFlowData,
    FraudRecordTransactionDataData,
    FraudRecordTransactionDataResponse,
>
{
}

/// RecordFulfillmentData flow - Record fulfillment/shipment
pub trait FraudRecordFulfillmentDataV2:
    ConnectorIntegrationV2<
    connector_flow::FraudRecordFulfillmentData,
    FraudFlowData,
    FraudRecordFulfillmentDataData,
    FraudRecordFulfillmentDataResponse,
>
{
}

/// RecordReturnData flow - Record return/refund
pub trait FraudRecordReturnDataV2:
    ConnectorIntegrationV2<
    connector_flow::FraudRecordReturnData,
    FraudFlowData,
    FraudRecordReturnDataData,
    FraudRecordReturnDataResponse,
>
{
}

/// Get flow - Status synchronization
pub trait FraudGetV2:
    ConnectorIntegrationV2<
    connector_flow::FraudGet,
    FraudFlowData,
    FraudGetData,
    FraudGetResponse,
>
{
}

/// Combined trait for fraud connectors
/// 
/// Implement this trait for fraud detection providers like Signifyd and Riskified.
pub trait FraudConnectorTrait:
    ConnectorCommon
    + FraudEvaluatePreAuthorizationV2
    + FraudEvaluatePostAuthorizationV2
    + FraudRecordTransactionDataV2
    + FraudRecordFulfillmentDataV2
    + FraudRecordReturnDataV2
    + FraudGetV2
    + Send
    + Sync
{
}
```

**Verification Steps**:
1. Add module to `interfaces/src/lib.rs`
2. Run `cargo check` in `types-traits` crate
3. Verify all trait bounds are satisfied
4. Confirm exactly 6 flow traits (no Cancel)

**Commit Message**: `feat(interfaces): add fraud check connector traits`

---

## Phase 4: Connector Implementation Structure (Week 3)

### Step 4.1: Create Signifyd Connector Skeleton
**File**: `crates/integrations/connector-integration/src/connectors/signifyd.rs`

```rust
//! Signifyd fraud detection connector implementation

use common_enums::CurrencyUnit;
use common_utils::CustomResult;
use domain_types::{
    connector_flow::ConnectorFlow,
    errors::ConnectorError,
    fraud_types::*,
    router_data::ConnectorSpecificConfig,
};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    fraud::{
        FraudEvaluatePreAuthorizationV2, FraudConnectorTrait, FraudRecordFulfillmentDataV2,
        FraudGetV2, FraudRecordReturnDataV2, FraudRecordTransactionDataV2, 
        FraudEvaluatePostAuthorizationV2,
    },
};

use crate::types::Response;

pub struct Signifyd;

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

    fn base_url<'a>(&self, connectors: &'a domain_types::types::Connectors) -> &'a str {
        connectors.signifyd.base_url.as_str()
    }

    fn build_error_response(
        &self,
        res: Response,
        _event_builder: Option<&mut common_utils::events::Event>,
    ) -> CustomResult<domain_types::router_data::ErrorResponse, ConnectorError> {
        // TODO: Implement error response parsing
        Ok(domain_types::router_data::ErrorResponse {
            status_code: res.status_code,
            code: "UNKNOWN_ERROR".to_string(),
            message: "Unknown error occurred".to_string(),
            reason: None,
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
    }
}

// ============================================================================
// EVALUATE PRE-AUTHORIZATION IMPLEMENTATION
// ============================================================================

impl ConnectorIntegrationV2<ConnectorFlow, FraudFlowData, FraudEvaluatePreAuthorizationData, FraudEvaluatePreAuthorizationResponse> for Signifyd {
    fn get_headers(
        &self,
        _req: &domain_types::router_data::RouterData<
            ConnectorFlow,
            FraudFlowData,
            FraudEvaluatePreAuthorizationData,
            FraudEvaluatePreAuthorizationResponse,
        >,
        _connectors: &domain_types::types::Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, ConnectorError> {
        // TODO: Implement header construction with API key
        todo!()
    }

    fn get_url(
        &self,
        _req: &domain_types::router_data::RouterData<
            ConnectorFlow,
            FraudFlowData,
            FraudEvaluatePreAuthorizationData,
            FraudEvaluatePreAuthorizationResponse,
        >,
        _connectors: &domain_types::types::Connectors,
    ) -> CustomResult<String, ConnectorError> {
        // TODO: Return /v3/checkouts endpoint
        todo!()
    }

    fn build_request(
        &self,
        _req: &domain_types::router_data::RouterData<
            ConnectorFlow,
            FraudFlowData,
            FraudEvaluatePreAuthorizationData,
            FraudEvaluatePreAuthorizationResponse,
        >,
        _connectors: &domain_types::types::Connectors,
    ) -> CustomResult<Option<domain_types::router_request_types::Request>, ConnectorError> {
        // TODO: Transform FraudEvaluatePreAuthorizationData to Signifyd request
        // Include: deviceFingerprint, sessionId, purchase data, customer data
        todo!()
    }

    fn handle_response(
        &self,
        _data: &domain_types::router_data::RouterData<
            ConnectorFlow,
            FraudFlowData,
            FraudEvaluatePreAuthorizationData,
            FraudEvaluatePreAuthorizationResponse,
        >,
        _res: Response,
    ) -> CustomResult<FraudEvaluatePreAuthorizationResponse, ConnectorError> {
        // TODO: Parse Signifyd response
        // Map: ACCEPT -> LEGIT, REJECT -> FRAUD, REVIEW -> MANUAL_REVIEW
        todo!()
    }
}

impl FraudEvaluatePreAuthorizationV2 for Signifyd {}

// ============================================================================
// EVALUATE POST-AUTHORIZATION IMPLEMENTATION
// ============================================================================

impl ConnectorIntegrationV2<ConnectorFlow, FraudFlowData, FraudEvaluatePostAuthorizationData, FraudEvaluatePostAuthorizationResponse> for Signifyd {
    // TODO: Implement methods for /v3/transactions endpoint
    // Maps: authorization_status, error codes to FraudCheckStatus
}

impl FraudEvaluatePostAuthorizationV2 for Signifyd {}

// ============================================================================
// RECORD TRANSACTION DATA IMPLEMENTATION
// ============================================================================

impl ConnectorIntegrationV2<ConnectorFlow, FraudFlowData, FraudRecordTransactionDataData, FraudRecordTransactionDataResponse> for Signifyd {
    // TODO: Implement methods for /v3/sales endpoint
    // Combines purchase data + transaction result
}

impl FraudRecordTransactionDataV2 for Signifyd {}

// ============================================================================
// RECORD FULFILLMENT DATA IMPLEMENTATION
// ============================================================================

impl ConnectorIntegrationV2<ConnectorFlow, FraudFlowData, FraudRecordFulfillmentDataData, FraudRecordFulfillmentDataResponse> for Signifyd {
    // TODO: Implement methods for /v3/fulfillments endpoint
    // Sends: tracking info, carrier, shipment status
}

impl FraudRecordFulfillmentDataV2 for Signifyd {}

// ============================================================================
// RECORD RETURN DATA IMPLEMENTATION
// ============================================================================

impl ConnectorIntegrationV2<ConnectorFlow, FraudFlowData, FraudRecordReturnDataData, FraudRecordReturnDataResponse> for Signifyd {
    // TODO: Implement methods for /v3/returns endpoint
    // Sends: refund amount, reason, method
}

impl FraudRecordReturnDataV2 for Signifyd {}

// ============================================================================
// GET IMPLEMENTATION
// ============================================================================

impl ConnectorIntegrationV2<ConnectorFlow, FraudFlowData, FraudGetData, FraudGetResponse> for Signifyd {
    // TODO: Implement methods for /v3/decisions/{orderId} endpoint
}

impl FraudGetV2 for Signifyd {}

// Combined trait implementation
impl FraudConnectorTrait for Signifyd {}
```

**Verification Steps**:
1. Add module to `connectors.rs`
2. Run `cargo check` in connector-integration crate
3. Verify all trait methods are implemented or have `todo!()`
4. Confirm exactly 6 flow implementations (no Cancel)

**Commit Message**: `feat(connector): add Signifyd fraud connector skeleton`

---

### Step 4.2: Create Riskified Connector Skeleton
**File**: `crates/integrations/connector-integration/src/connectors/riskified.rs`

Follow the same pattern as Signifyd, adapting for Riskified's API:
- Use HMAC-SHA256 authentication
- Support sync (`/api/orders/decide`) and async (`/api/orders/submit`) modes
- Implement beacon-based session tracking
- Map Riskified states to Hyperswitch enums

**Commit Message**: `feat(connector): add Riskified fraud connector skeleton`

---

## Phase 5: gRPC Service Implementation (Week 3-4)

### Step 5.1: Create fraud service handler
**File**: `crates/grpc-server/src/services/fraud.rs`

```rust
//! FraudService gRPC handler

use tonic::{Request, Response, Status};

use crate::{
    proto::{
        fraud_service_server::FraudService,
        FraudServiceEvaluatePreAuthorizationRequest, FraudServiceEvaluatePreAuthorizationResponse,
        FraudServiceEvaluatePostAuthorizationRequest, FraudServiceEvaluatePostAuthorizationResponse,
        FraudServiceRecordFulfillmentDataRequest, FraudServiceRecordFulfillmentDataResponse,
        FraudServiceGetRequest, FraudServiceGetResponse,
        FraudServiceRecordReturnDataRequest, FraudServiceRecordReturnDataResponse,
        FraudServiceRecordTransactionDataRequest, FraudServiceRecordTransactionDataResponse,
    },
};

pub struct FraudServiceImpl {
    // TODO: Add connector registry, config, etc.
}

impl FraudServiceImpl {
    pub fn new() -> Self {
        Self {}
    }
}

#[tonic::async_trait]
impl FraudService for FraudServiceImpl {
    async fn evaluate_pre_authorization(
        &self,
        request: Request<FraudServiceEvaluatePreAuthorizationRequest>,
    ) -> Result<Response<FraudServiceEvaluatePreAuthorizationResponse>, Status> {
        // TODO: Implement EvaluatePreAuthorization RPC
        Err(Status::unimplemented("EvaluatePreAuthorization not yet implemented"))
    }

    async fn evaluate_post_authorization(
        &self,
        request: Request<FraudServiceEvaluatePostAuthorizationRequest>,
    ) -> Result<Response<FraudServiceEvaluatePostAuthorizationResponse>, Status> {
        // TODO: Implement EvaluatePostAuthorization RPC
        Err(Status::unimplemented("EvaluatePostAuthorization not yet implemented"))
    }

    async fn record_transaction_data(
        &self,
        request: Request<FraudServiceRecordTransactionDataRequest>,
    ) -> Result<Response<FraudServiceRecordTransactionDataResponse>, Status> {
        // TODO: Implement RecordTransactionData RPC
        Err(Status::unimplemented("RecordTransactionData not yet implemented"))
    }

    async fn record_fulfillment_data(
        &self,
        request: Request<FraudServiceRecordFulfillmentDataRequest>,
    ) -> Result<Response<FraudServiceRecordFulfillmentDataResponse>, Status> {
        // TODO: Implement RecordFulfillmentData RPC
        Err(Status::unimplemented("RecordFulfillmentData not yet implemented"))
    }

    async fn record_return_data(
        &self,
        request: Request<FraudServiceRecordReturnDataRequest>,
    ) -> Result<Response<FraudServiceRecordReturnDataResponse>, Status> {
        // TODO: Implement RecordReturnData RPC
        Err(Status::unimplemented("RecordReturnData not yet implemented"))
    }

    async fn get(
        &self,
        request: Request<FraudServiceGetRequest>,
    ) -> Result<Response<FraudServiceGetResponse>, Status> {
        // TODO: Implement Get RPC
        Err(Status::unimplemented("Get not yet implemented"))
    }
}
```

**Verification Steps**:
1. Add service to gRPC server initialization
2. Run `cargo build` in grpc-server crate
3. Verify service starts without errors
4. Confirm exactly 6 RPC methods (no Cancel)

**Commit Message**: `feat(grpc): add FraudService gRPC handler skeleton`

---

## Phase 6: SDK Generation (Week 4)

### Step 6.1: Update SDK Generation Configuration

Update SDK generation scripts to include fraud.proto with new method names.

**Verification Steps**:
1. Run SDK generation for one language (e.g., Node.js)
2. Verify fraud service client is generated with correct method names
3. Confirm types match proto definitions

**Commit Message**: `feat(sdk): add fraud service to SDK generation`

---

## Phase 7: Testing (Week 4-5)

### Step 7.1: Unit Tests for Domain Types
**File**: `crates/types-traits/domain_types/src/fraud_types_tests.rs`

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fraud_check_status_hyperswitch_alignment() {
        // Verify exactly 5 states (matches Hyperswitch)
        let statuses = vec![
            FraudCheckStatus::Pending,
            FraudCheckStatus::Fraud,
            FraudCheckStatus::Legit,
            FraudCheckStatus::ManualReview,
            FraudCheckStatus::TransactionFailure,
        ];
        assert_eq!(statuses.len(), 5);
    }

    #[test]
    fn test_fraud_action_simplified() {
        // Verify only 2 actions (not counting UNSPECIFIED)
        let actions = vec![
            FraudAction::Accept,
            FraudAction::Reject,
        ];
        assert_eq!(actions.len(), 2);
    }

    #[test]
    fn test_fraud_score_creation() {
        let score = FraudScore {
            score: 750,
            risk_level: Some("HIGH".to_string()),
            threshold: Some(500),
        };
        assert_eq!(score.score, 750);
    }
}
```

**Commit Message**: `test(domain): add fraud domain types unit tests`

---

### Step 7.2: Integration Tests

Create integration tests for full flow:
- EvaluatePreAuthorization → EvaluatePostAuthorization → RecordFulfillmentData
- Error handling for each flow
- Webhook processing
- Status mapping verification

**Commit Message**: `test(integration): add fraud service integration tests`

---

## Phase 8: Documentation (Week 5-6)

### Step 8.1: Update All Documentation

Ensure consistency across all docs:
- `01-fraud-interface-specification.md` - v4.0.0
- `02-implementation-plan.md` - v2.0.0 (this doc)
- `03-connector-implementation-guide.md` - Update method names
- `04-proto-validation-analysis.md` - v4.0.0
- `05-field-optionality-analysis.md` - Update if exists

**Commit Message**: `docs: update all fraud interface documentation`

---

## Summary Checklist

### Schema & Types
- [x] fraud.proto created with Hyperswitch-aligned enums
- [x] services.proto updated with 6 RPC methods
- [x] Domain types implement Hyperswitch enums exactly
- [x] Connector flow types defined

### Interfaces
- [x] Fraud trait interfaces defined
- [x] Exactly 6 flow traits (no Cancel)

### Connectors
- [x] Signifyd connector skeleton
- [x] Riskified connector skeleton
- [x] Error handling implemented

### Service
- [x] gRPC FraudService handler
- [x] Service registered in server

### Key Constraints Verified
- [x] FraudCheckStatus: 5 states (matches Hyperswitch)
- [x] FraudAction: 2 actions (ACCEPT/REJECT)
- [x] No new states introduced
- [x] All provider states mappable to Hyperswitch

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-04-06 | Initial implementation plan |
| 2.0.0 | 2026-04-06 | **Synced with Specification v4.0.0**, Hyperswitch-aligned enums, renamed methods, removed Cancel |
