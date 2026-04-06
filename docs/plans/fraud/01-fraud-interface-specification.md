# Fraud Interface Specification for Hyperswitch Prism

## Document Information
- **Version**: 2.0.0
- **Date**: 2026-04-06
- **Status**: Reviewed and Approved
- **Author**: AI Design Agent
- **Reviewer**: Spec Verifier Agent

## 1. Executive Summary

This document specifies the Fraud interface for Hyperswitch Prism, enabling unified integration with fraud detection providers like Signifyd and Riskified. The interface follows the same architectural patterns as Payments and Payouts services, ensuring consistency across the Prism library.

### Key Objectives
1. Provide a unified API for fraud detection across multiple providers
2. Support both Pre-Auth and Post-Auth fraud check workflows
3. Enable transaction lifecycle management (sale, checkout, fulfillment, returns)
4. Maintain consistency with existing Prism interface patterns
5. Support webhook-based asynchronous fraud decisions

## 2. Architecture Design

### 2.1 Service Definition

```protobuf
service FraudService {
  // EvaluatePreAuthorization evaluates fraud risk BEFORE payment authorization to prevent fraudulent transactions from being charged.
  // Business use case: High-risk merchants who want to decline suspicious orders before processing payment, reducing chargeback fees.
  rpc EvaluatePreAuthorization(FraudServiceEvaluatePreAuthorizationRequest) returns (FraudServiceEvaluatePreAuthorizationResponse);
  
  // EvaluatePostAuthorization evaluates fraud risk AFTER payment authorization using transaction results.
  // Business use case: Merchants who process payment first then evaluate fraud, or want to enrich pre-auth decisions with auth results.
  rpc EvaluatePostAuthorization(FraudServiceEvaluatePostAuthorizationRequest) returns (FraudServiceEvaluatePostAuthorizationResponse);
  
  // RecordTransactionData creates a complete fraud record after successful payment for post-hoc fraud evaluation.
  // Business use case: Merchants using synchronous payment flows who need fraud protection without separate pre-auth checks.
  rpc RecordTransactionData(FraudServiceRecordTransactionDataRequest) returns (FraudServiceRecordTransactionDataResponse);
  
  // RecordFulfillmentData notifies the fraud provider when an order is shipped with tracking and delivery information.
  // Business use case: Required for chargeback guarantee protection and improving fraud models with delivery confirmation.
  rpc RecordFulfillmentData(FraudServiceRecordFulfillmentDataRequest) returns (FraudServiceRecordFulfillmentDataResponse);
  
  // RecordReturnData captures customer return and refund information for fraud pattern analysis.
  // Business use case: Identifying return fraud patterns and enabling fee adjustments on Riskified's chargeback guarantee.
  rpc RecordReturnData(FraudServiceRecordReturnDataRequest) returns (FraudServiceRecordReturnDataResponse);
  
  // Get retrieves the current fraud decision and case status from the provider for polling or reconciliation.
  // Business use case: Recovering from webhook failures, manual review workflows, and syncing internal state with provider.
  rpc Get(FraudServiceGetRequest) returns (FraudServiceGetResponse);
}
```

### 2.2 Data Flow

Two primary integration patterns:

**Pattern A: Pre-Authorization Fraud Check (EvaluatePreAuthorization → EvaluatePostAuthorization)**
```
Customer Checkout → EvaluatePreAuthorization → Fraud Decision → Payment Auth → EvaluatePostAuthorization → RecordFulfillmentData
                              ↓                    ↓                              ↓
                        [ACCEPT]             APPROVED                       [SUCCESS]
                        [REJECT]             DECLINED                       [FAILURE]
                        [REVIEW]             Manual Review

Use EvaluatePreAuthorization when: Evaluating fraud BEFORE charging customer's card
Use EvaluatePostAuthorization when: Updating fraud case with payment auth result (AVS/CVV)
```

**Pattern B: Post-Authorization Fraud Check (RecordTransactionData)**
```
Payment Auth → RecordTransactionData → RecordFulfillmentData
                         ↓
                   [Fraud Decision]
                   (with full payment context)

Use RecordTransactionData when: Payment already captured, evaluate fraud post-hoc
```

**Pattern C: Status Synchronization (Get)**
```
Get (poll) ←→ Webhook (async) ←→ Get (reconcile)

Use Get when: Webhook failed, manual review, or status reconciliation
```

### Flow Relationships

| From Flow | To Flow | When to Transition |
|-----------|---------|-------------------|
| EvaluatePreAuthorization | EvaluatePostAuthorization | After payment authorization attempt |
| EvaluatePostAuthorization | RecordFulfillmentData | After successful auth and fraud evaluation |
| RecordTransactionData | RecordFulfillmentData | After fraud evaluation of completed payment |
| RecordFulfillmentData | RecordReturnData | If customer returns shipped items |
| Any | Get | For status polling or reconciliation |

### 2.3 Request/Response ID Pattern

Following the existing pattern from payments and payouts:

| Service | Merchant ID Pattern | Connector ID Pattern |
|---------|---------------------|---------------------|
| Payment | `merchant_transaction_id` | `connector_transaction_id` |
| Payout | `merchant_payout_id` | `connector_payout_id` |
| **Fraud** | `merchant_fraud_check_id` | `connector_fraud_check_id` |

## 3. Protocol Buffer Schema

### 3.1 File: `fraud.proto`

```protobuf
syntax = "proto3";

package types;

import "payment.proto";
import "payment_methods.proto";

option go_package = "github.com/juspay/connector-service/crates/types-traits/grpc-api-types/proto;proto";

// ============================================================================
// FRAUD ENUMERATIONS (Package level - following payment.proto pattern)
// ============================================================================

enum FraudCheckStatus {
  FRAUD_CHECK_STATUS_UNSPECIFIED = 0;
  FRAUD_CHECK_STATUS_PENDING = 1;
  FRAUD_CHECK_STATUS_FRAUD = 2;
  FRAUD_CHECK_STATUS_LEGIT = 3;
  FRAUD_CHECK_STATUS_MANUAL_REVIEW = 4;
  FRAUD_CHECK_STATUS_TRANSACTION_FAILURE = 5;
}

enum FraudCheckType {
  FRAUD_CHECK_TYPE_UNSPECIFIED = 0;
  FRAUD_CHECK_TYPE_PRE_AUTHORIZATION = 1;
  FRAUD_CHECK_TYPE_POST_AUTHORIZATION = 2;
}

enum FraudAction {
  FRAUD_ACTION_UNSPECIFIED = 0;
  FRAUD_ACTION_ACCEPT = 1;
  FRAUD_ACTION_REJECT = 2;
}

enum FulfillmentStatus {
  FULFILLMENT_STATUS_UNSPECIFIED = 0;
  FULFILLMENT_STATUS_PENDING = 1;
  FULFILLMENT_STATUS_PARTIAL = 2;
  FULFILLMENT_STATUS_COMPLETE = 3;
  FULFILLMENT_STATUS_REPLACEMENT = 4;
  FULFILLMENT_STATUS_CANCELLED = 5;
}

enum RefundMethod {
  REFUND_METHOD_UNSPECIFIED = 0;
  REFUND_METHOD_STORE_CREDIT = 1;
  REFUND_METHOD_ORIGINAL_PAYMENT_INSTRUMENT = 2;
  REFUND_METHOD_NEW_PAYMENT_INSTRUMENT = 3;
}

// ============================================================================
// CORE FRAUD DATA MESSAGES
// ============================================================================

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

message FraudDestination {
  SecretString full_name = 1;
  optional string organization = 2;
  optional SecretString email = 3;
  Address address = 4;
}

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

message FraudScore {
  int32 score = 1;
  optional string risk_level = 2;
  optional int32 threshold = 3;
}

message FraudReason {
  string code = 1;
  string message = 2;
  optional string description = 3;
}

// ============================================================================
// EVALUATE PRE-AUTHORIZATION REQUEST/RESPONSE
// ============================================================================

message FraudServiceEvaluatePreAuthorizationRequest {
  optional string merchant_fraud_check_id = 1;
  optional string order_id = 2;
  optional string connector_fraud_check_id = 3;
  Money amount = 4;
  optional PaymentMethod payment_method = 5;
  optional Customer customer = 6;
  repeated FraudProduct products = 7;
  optional BrowserInformation browser_info = 8;
  optional Address shipping_address = 9;
  optional Address billing_address = 10;
  optional string connector_name = 11;
  optional SecretString connector_feature_data = 12;
  optional string webhook_url = 13;
  optional string previous_fraud_check_id = 14;
  optional ConnectorState connector_state = 15;
}

message FraudServiceEvaluatePreAuthorizationResponse {
  optional string merchant_fraud_check_id = 1;
  optional string order_id = 2;
  optional string connector_fraud_check_id = 3;
  FraudCheckStatus fraud_check_status = 4;
  FraudAction recommended_action = 5;
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
  optional string merchant_fraud_check_id = 1;
  optional string order_id = 2;
  optional string connector_fraud_check_id = 3;
  optional string connector_transaction_id = 4;
  Money amount = 5;
  optional PaymentMethod payment_method = 6;
  AuthorizationStatus authorization_status = 7;
  optional string error_code = 8;
  optional string error_message = 9;
  optional string connector_name = 10;
  optional SecretString connector_feature_data = 11;
  optional string webhook_url = 12;
  optional ConnectorState connector_state = 13;
}

message FraudServiceEvaluatePostAuthorizationResponse {
  optional string merchant_fraud_check_id = 1;
  optional string order_id = 2;
  optional string connector_fraud_check_id = 3;
  FraudCheckStatus fraud_check_status = 4;
  FraudAction recommended_action = 5;
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
  optional string merchant_fraud_check_id = 1;
  optional string order_id = 2;
  Money amount = 3;
  optional string session_id = 4;
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
  FraudCheckStatus fraud_check_status = 4;
  FraudAction recommended_action = 5;
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
  optional string merchant_fraud_check_id = 1;
  optional string order_id = 2;
  optional string connector_fraud_check_id = 3;
  FulfillmentStatus fulfillment_status = 4;
  repeated FraudShipment shipments = 5;
  optional SecretString connector_feature_data = 6;
  optional string webhook_url = 7;
  optional ConnectorState connector_state = 8;
}

message FraudServiceRecordFulfillmentDataResponse {
  optional string merchant_fraud_check_id = 1;
  optional string order_id = 2;
  optional string connector_fraud_check_id = 3;
  FraudCheckStatus fraud_check_status = 4;
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
  optional string merchant_fraud_check_id = 1;
  optional string order_id = 2;
  optional string connector_fraud_check_id = 3;
  optional string refund_transaction_id = 4;
  Money amount = 5;
  RefundMethod refund_method = 6;
  optional string return_reason = 7;
  optional string return_reason_code = 8;
  optional SecretString connector_feature_data = 9;
  optional string webhook_url = 10;
  optional ConnectorState connector_state = 11;
}

message FraudServiceRecordReturnDataResponse {
  optional string merchant_fraud_check_id = 1;
  optional string order_id = 2;
  optional string connector_fraud_check_id = 3;
  FraudCheckStatus fraud_check_status = 4;
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
  optional string merchant_fraud_check_id = 1;
  optional string order_id = 2;
  optional string connector_fraud_check_id = 3;
  optional string case_id = 4;
}

message FraudServiceGetResponse {
  optional string merchant_fraud_check_id = 1;
  optional string order_id = 2;
  optional string connector_fraud_check_id = 3;
  FraudCheckStatus fraud_check_status = 4;
  FraudAction recommended_action = 5;
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
  FraudCheckStatus fraud_check_status = 5;
  FraudAction recommended_action = 6;
  optional FraudScore score = 7;
  repeated FraudReason reasons = 8;
  optional string case_id = 9;
  int64 event_timestamp = 10;
}
```

### 3.2 Service Registration (Update to `services.proto`)

```protobuf
import "fraud.proto";

service FraudService {
  rpc EvaluatePreAuthorization(FraudServiceEvaluatePreAuthorizationRequest) returns (FraudServiceEvaluatePreAuthorizationResponse);
  rpc EvaluatePostAuthorization(FraudServiceEvaluatePostAuthorizationRequest) returns (FraudServiceEvaluatePostAuthorizationResponse);
  rpc RecordTransactionData(FraudServiceRecordTransactionDataRequest) returns (FraudServiceRecordTransactionDataResponse);
  rpc RecordFulfillmentData(FraudServiceRecordFulfillmentDataRequest) returns (FraudServiceRecordFulfillmentDataResponse);
  rpc RecordReturnData(FraudServiceRecordReturnDataRequest) returns (FraudServiceRecordReturnDataResponse);
  rpc Get(FraudServiceGetRequest) returns (FraudServiceGetResponse);
}
```

## 4. Rust Interface Traits

### 4.1 File: `crates/types-traits/interfaces/src/fraud.rs`

```rust
use domain_types::{
    connector_flow,
    fraud_types::{
        FraudEvaluatePreAuthorizationData, FraudEvaluatePreAuthorizationResponse,
        FraudEvaluatePostAuthorizationData, FraudEvaluatePostAuthorizationResponse,
        FraudRecordTransactionDataData, FraudRecordTransactionDataResponse,
        FraudFlowData, FraudRecordFulfillmentDataData, FraudRecordFulfillmentDataResponse,
        FraudGetData, FraudGetResponse, FraudRecordReturnDataData, FraudRecordReturnDataResponse,
    },
};

use crate::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
};

pub trait FraudEvaluatePreAuthorizationV2:
    ConnectorIntegrationV2<
    connector_flow::FraudEvaluatePreAuthorization,
    FraudFlowData,
    FraudEvaluatePreAuthorizationData,
    FraudEvaluatePreAuthorizationResponse,
>
{
}

pub trait FraudEvaluatePostAuthorizationV2:
    ConnectorIntegrationV2<
    connector_flow::FraudEvaluatePostAuthorization,
    FraudFlowData,
    FraudEvaluatePostAuthorizationData,
    FraudEvaluatePostAuthorizationResponse,
>
{
}

pub trait FraudRecordTransactionDataV2:
    ConnectorIntegrationV2<
    connector_flow::FraudRecordTransactionData,
    FraudFlowData,
    FraudRecordTransactionDataData,
    FraudRecordTransactionDataResponse,
>
{
}

pub trait FraudRecordFulfillmentDataV2:
    ConnectorIntegrationV2<
    connector_flow::FraudRecordFulfillmentData,
    FraudFlowData,
    FraudRecordFulfillmentDataData,
    FraudRecordFulfillmentDataResponse,
>
{
}

pub trait FraudRecordReturnDataV2:
    ConnectorIntegrationV2<
    connector_flow::FraudRecordReturnData,
    FraudFlowData,
    FraudRecordReturnDataData,
    FraudRecordReturnDataResponse,
>
{
}

pub trait FraudGetV2:
    ConnectorIntegrationV2<
    connector_flow::FraudGet,
    FraudFlowData,
    FraudGetData,
    FraudGetResponse,
>
{
}

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

## 5. Webhook Events

### 5.1 Extend payment.proto WebhookEventType

```protobuf
enum WebhookEventType {
  // ... existing events
  FRM_APPROVED = 28;
  FRM_REJECTED = 29;
  FRM_REVIEW_REQUIRED = 60;
  FRM_CASE_UPDATED = 61;
  FRM_FULFILLMENT_ACKNOWLEDGED = 62;
}
```

### 5.2 Extend EventContent

```protobuf
message EventContent {
  oneof content {
    // ... existing content types
    FraudEventContent fraud_event = 6;
  }
}
```

## 6. Alignment Summary

| Aspect | Payments | Payouts | Fraud |
|--------|----------|---------|-------|
| Service Name | PaymentService | PayoutService | FraudService |
| Core Flows | 8 flows | 8 flows | 6 flows |
| Status Enum | PaymentStatus | PayoutStatus | FraudCheckStatus |
| Merchant ID | merchant_transaction_id | merchant_payout_id | merchant_fraud_check_id |
| Connector ID | connector_transaction_id | connector_payout_id | connector_fraud_check_id |
| Error Pattern | ErrorInfo | ErrorInfo | ErrorInfo |
| State Management | ConnectorState | ConnectorState | ConnectorState |
| Raw Response | raw_connector_response | raw_connector_response | raw_connector_response |

## 7. Open Questions Resolved

### 7.1 Synchronous vs Asynchronous
The spec supports both:
- **Synchronous**: EvaluatePreAuthorization returns immediate decisions
- **Asynchronous**: Webhook events for status updates

### 7.2 Provider-Specific Features
Use `connector_feature_data` (SecretString) for provider-specific fields not in unified schema.

### 7.3 Score Normalization
- **Signifyd**: Score 0-1000 (higher = riskier), normalized to 0-1000 range
- **Riskified**: Score 0-100 (higher = safer) OR category-based, mapped to 0-1000 range with inverted scale

## 8. Implementation Checklist

See `02-implementation-plan.md` for detailed step-by-step implementation instructions.

---

**Next Steps**: 
1. Review implementation plan
2. Begin Phase 1 (Protocol Buffers)
3. Follow trunk-based development with commits after each step
