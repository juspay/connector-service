//! Fraud check domain types - Following the payouts pattern

use crate::{
    connector_types::{ConnectorResponseHeaders, RawConnectorRequestResponse},
    payment_method_data::{DefaultPCIHolder, PaymentMethodData},
    types::Connectors,
};
use hyperswitch_masking::Secret;

// ============================================================================
// FRAUD FLOW DATA (Equivalent to PayoutFlowData)
// ============================================================================

#[derive(Debug, Clone)]
pub struct FraudFlowData {
    pub merchant_fraud_id: Option<String>,
    pub order_id: Option<String>,
    pub connector_fraud_id: Option<String>,
    pub connectors: Connectors,
    pub connector_state: Option<grpc_api_types::payments::ConnectorState>,
    pub raw_connector_response: Option<Secret<String>>,
    pub raw_connector_request: Option<Secret<String>>,
    pub connector_response_headers: Option<http::HeaderMap>,
}

impl FraudFlowData {
    pub fn new(connectors: Connectors) -> Self {
        Self {
            merchant_fraud_id: None,
            order_id: None,
            connector_fraud_id: None,
            connectors,
            connector_state: None,
            raw_connector_response: None,
            raw_connector_request: None,
            connector_response_headers: None,
        }
    }
}

impl RawConnectorRequestResponse for FraudFlowData {
    fn set_raw_connector_response(&mut self, response: Option<Secret<String>>) {
        self.raw_connector_response = response;
    }

    fn get_raw_connector_response(&self) -> Option<Secret<String>> {
        self.raw_connector_response.clone()
    }

    fn get_raw_connector_request(&self) -> Option<Secret<String>> {
        self.raw_connector_request.clone()
    }

    fn set_raw_connector_request(&mut self, request: Option<Secret<String>>) {
        self.raw_connector_request = request;
    }
}

impl ConnectorResponseHeaders for FraudFlowData {
    fn set_connector_response_headers(&mut self, headers: Option<http::HeaderMap>) {
        self.connector_response_headers = headers;
    }

    fn get_connector_response_headers(&self) -> Option<&http::HeaderMap> {
        self.connector_response_headers.as_ref()
    }
}

// ============================================================================
// REQUEST DATA TYPES (Equivalent to PayoutCreateRequest, etc.)
// ============================================================================

#[derive(Debug, Clone)]
pub struct FraudEvaluatePreAuthorizationRequest {
    pub amount: i64,
    pub currency: common_enums::Currency,
    pub customer: Option<crate::connector_types::ConnectorCustomerData>,
    pub payment_method: Option<PaymentMethodData<DefaultPCIHolder>>,
    pub browser_info: Option<crate::router_request_types::BrowserInformation>,
    pub shipping_address: Option<crate::payment_address::Address>,
    pub billing_address: Option<crate::payment_address::Address>,
    pub connector_name: Option<String>,
    pub previous_fraud_id: Option<String>,
    pub device_fingerprint: String,
    pub session_id: String,
    pub synchronous: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

#[derive(Debug, Clone)]
pub struct FraudEvaluatePostAuthorizationRequest {
    pub amount: i64,
    pub currency: common_enums::Currency,
    pub payment_method: Option<PaymentMethodData<DefaultPCIHolder>>,
    pub authorization_status: common_enums::AuthorizationStatus,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub connector_name: Option<String>,
    pub connector_transaction_id: String,
    pub session_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FraudEvaluatePostAuthorizationResponse {
    pub fraud_id: String,
    pub status: FraudCheckStatus,
    pub recommended_action: FraudAction,
    pub score: Option<FraudScore>,
    pub reasons: Vec<FraudReason>,
    pub case_id: Option<String>,
    pub connector_metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct FraudRecordTransactionDataRequest {
    pub amount: i64,
    pub currency: common_enums::Currency,
    pub customer: Option<crate::connector_types::ConnectorCustomerData>,
    pub browser_info: Option<crate::router_request_types::BrowserInformation>,
    pub shipping_address: Option<crate::payment_address::Address>,
    pub billing_address: Option<crate::payment_address::Address>,
    pub session_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FraudRecordTransactionDataResponse {
    pub fraud_id: String,
    pub status: FraudCheckStatus,
    pub recommended_action: FraudAction,
    pub score: Option<FraudScore>,
    pub reasons: Vec<FraudReason>,
    pub connector_metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct FraudRecordFulfillmentDataRequest {
    pub fulfillment_status: FulfillmentStatus,
    pub shipments: Vec<FraudShipment>,
    pub session_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FraudRecordFulfillmentDataResponse {
    pub fraud_id: String,
    pub status: FraudCheckStatus,
    pub shipment_ids: Vec<String>,
    pub connector_metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct FraudRecordReturnDataRequest {
    pub amount: i64,
    pub currency: common_enums::Currency,
    pub refund_method: RefundMethod,
    pub return_reason: Option<String>,
    pub return_reason_code: Option<String>,
    pub session_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FraudRecordReturnDataResponse {
    pub fraud_id: String,
    pub status: FraudCheckStatus,
    pub return_id: Option<String>,
    pub connector_metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct FraudGetRequest {
    pub merchant_fraud_id: Option<String>,
    pub order_id: Option<String>,
    pub connector_fraud_id: Option<String>,
    pub case_id: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FraudGetResponse {
    pub fraud_id: String,
    pub status: FraudCheckStatus,
    pub recommended_action: FraudAction,
    pub score: Option<FraudScore>,
    pub reasons: Vec<FraudReason>,
    pub case_id: Option<String>,
    pub reviewed_by: Option<String>,
    pub reviewed_at: Option<i64>,
    pub connector_metadata: Option<serde_json::Value>,
}

// ============================================================================
// SUPPORTING TYPES (Hyperswitch-Aligned - DO NOT MODIFY)
// ============================================================================

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FraudCheckStatus {
    Pending,
    Fraud,
    Legit,
    ManualReview,
    TransactionFailure,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FraudAction {
    Accept,
    Reject,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FulfillmentStatus {
    Pending,
    Partial,
    Complete,
    Replacement,
    Cancelled,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RefundMethod {
    StoreCredit,
    OriginalPaymentInstrument,
    NewPaymentInstrument,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FraudScore {
    pub score: i32,
    pub risk_level: Option<String>,
    pub threshold: Option<i32>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FraudReason {
    pub code: String,
    pub message: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

#[derive(Debug, Clone)]
pub struct FraudDestination {
    pub full_name: Secret<String>,
    pub organization: Option<String>,
    pub email: Option<Secret<String>>,
    pub address: crate::payment_address::Address,
}

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
