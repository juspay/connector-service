use common_utils::types::MinorUnit;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

// ============================================
// Payment Responses
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaysafePaymentsResponse {
    pub id: String,
    pub merchant_ref_num: String,
    pub amount: MinorUnit,
    pub available_to_settle: Option<MinorUnit>,
    pub currency_code: common_enums::Currency,
    pub status: PaysafePaymentStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_handle_token: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_reconciliation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Error>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum PaysafePaymentStatus {
    Completed,
    #[default]
    Processing,
    Failed,
    Cancelled,
    Pending,
}

// ============================================
// Payment Handle Response (for 3DS flows)
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaysafePaymentHandleResponse {
    pub id: String,
    pub merchant_ref_num: String,
    pub payment_handle_token: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<PaysafeUsage>,
    pub status: PaysafePaymentHandleStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<PaymentLink>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Error>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaysafeUsage {
    SingleUse,
    MultiUse,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum PaysafePaymentHandleStatus {
    Initiated,
    Payable,
    #[default]
    Processing,
    Failed,
    Expired,
    Completed,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentLink {
    pub rel: String,
    pub href: String,
}

// ============================================
// Sync Responses
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PaysafeSyncResponse {
    Payments(PaysafePaymentsSyncData),
    PaymentHandle(PaysafePaymentHandleSyncData),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaysafePaymentsSyncData {
    pub payments: Vec<PaysafePaymentsResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaysafePaymentHandleSyncData {
    pub payment_handles: Vec<PaysafePaymentHandleResponse>,
}

// ============================================
// Capture/Settlement Response
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaysafeSettlementResponse {
    pub id: String,
    pub merchant_ref_num: String,
    pub amount: MinorUnit,
    pub status: PaysafeSettlementStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Error>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum PaysafeSettlementStatus {
    #[default]
    Pending,
    Processing,
    Completed,
    Failed,
    Cancelled,
}

// ============================================
// Void Response
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaysafeVoidResponse {
    pub id: String,
    pub merchant_ref_num: String,
    pub amount: MinorUnit,
    pub status: PaysafeVoidStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Error>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum PaysafeVoidStatus {
    #[default]
    Pending,
    Processing,
    Completed,
    Failed,
    Cancelled,
}

// ============================================
// Refund Response
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaysafeRefundResponse {
    pub id: String,
    pub merchant_ref_num: String,
    pub amount: MinorUnit,
    pub status: PaysafeRefundStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settlement_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Error>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum PaysafeRefundStatus {
    #[default]
    Pending,
    Processing,
    Completed,
    Failed,
    Cancelled,
}

// RSync uses the same response structure as Refund
pub type PaysafeRSyncResponse = PaysafeRefundResponse;

// ============================================
// Error Response
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Error {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_errors: Option<Vec<FieldError>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldError {
    pub field: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaysafeErrorResponse {
    pub error: Error,
}

// ============================================
// Type Aliases
// ============================================

pub type PaysafeAuthorizeResponse = PaysafePaymentsResponse;
pub type PaysafeCaptureResponse = PaysafeSettlementResponse;
pub type PaysafeRepeatPaymentResponse = PaysafePaymentsResponse;
pub type PaysafeSetupMandateResponse = PaysafePaymentHandleResponse;
pub type PaysafeCreateOrderResponse = PaysafePaymentHandleResponse;
pub type PaysafeAuthenticateResponse = PaysafePaymentHandleResponse;
