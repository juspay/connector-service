use common_enums::{AttemptStatus, RefundStatus};
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeachpaymentsErrorResponse {
    pub error_ref: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PeachpaymentsPaymentStatus {
    Successful,
    Pending,
    Authorized,
    Approved,
    ApprovedConfirmed,
    Declined,
    Failed,
    Reversed,
    ThreedsRequired,
    Voided,
}

impl From<PeachpaymentsPaymentStatus> for AttemptStatus {
    fn from(item: PeachpaymentsPaymentStatus) -> Self {
        match item {
            PeachpaymentsPaymentStatus::Pending
            | PeachpaymentsPaymentStatus::Authorized
            | PeachpaymentsPaymentStatus::Approved => Self::Authorized,
            PeachpaymentsPaymentStatus::Declined | PeachpaymentsPaymentStatus::Failed => {
                Self::Failure
            }
            PeachpaymentsPaymentStatus::Voided | PeachpaymentsPaymentStatus::Reversed => {
                Self::Voided
            }
            PeachpaymentsPaymentStatus::ThreedsRequired => Self::AuthenticationPending,
            PeachpaymentsPaymentStatus::ApprovedConfirmed
            | PeachpaymentsPaymentStatus::Successful => Self::Charged,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PeachpaymentsRefundStatus {
    ApprovedConfirmed,
    Declined,
    Failed,
}

impl From<PeachpaymentsRefundStatus> for RefundStatus {
    fn from(item: PeachpaymentsRefundStatus) -> Self {
        match item {
            PeachpaymentsRefundStatus::ApprovedConfirmed => Self::Success,
            PeachpaymentsRefundStatus::Failed | PeachpaymentsRefundStatus::Declined => {
                Self::Failure
            }
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PeachpaymentsPaymentsResponse {
    Response(Box<PeachpaymentsPaymentsData>),
    WebhookResponse(Box<PeachpaymentsIncomingWebhook>),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeachpaymentsPaymentsData {
    pub transaction_id: String,
    pub response_code: Option<PeachpaymentsResponseCode>,
    pub transaction_result: PeachpaymentsPaymentStatus,
    pub merchant_information: Option<PeachpaymentsMerchantInformationResponse>,
    pub ecommerce_card_payment_only_transaction_data: Option<PeachpaymentsCardResponseData>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeachpaymentsMerchantInformationResponse {
    pub merchant_id: Option<String>,
    pub merchant_name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PeachpaymentsAuthorizeResponse {
    #[serde(rename = "transactionId")]
    pub transaction_id: String,
    #[serde(rename = "transactionResult")]
    pub transaction_result: PeachpaymentsPaymentStatus,
    #[serde(rename = "responseCode")]
    pub response_code: Option<PeachpaymentsResponseCode>,
    pub merchant_information: Option<PeachpaymentsMerchantInformationResponse>,
    #[serde(rename = "ecommerceCardPaymentOnlyTransactionData")]
    pub card_data: Option<PeachpaymentsCardResponseData>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PeachpaymentsCaptureResponse {
    #[serde(rename = "transactionId")]
    pub transaction_id: String,
    #[serde(rename = "transactionResult")]
    pub transaction_result: PeachpaymentsPaymentStatus,
    #[serde(rename = "responseCode")]
    pub response_code: Option<PeachpaymentsResponseCode>,
    pub merchant_information: Option<PeachpaymentsMerchantInformationResponse>,
    #[serde(rename = "authorizationCode")]
    pub authorization_code: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PeachpaymentsVoidResponse {
    #[serde(rename = "transactionId")]
    pub transaction_id: String,
    #[serde(rename = "transactionResult")]
    pub transaction_result: PeachpaymentsPaymentStatus,
    #[serde(rename = "responseCode")]
    pub response_code: Option<PeachpaymentsResponseCode>,
    pub merchant_information: Option<PeachpaymentsMerchantInformationResponse>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PeachpaymentsRefundResponse {
    #[serde(rename = "transactionId")]
    pub transaction_id: String,
    #[serde(rename = "originalTransactionId")]
    pub original_transaction_id: Option<String>,
    #[serde(rename = "referenceId")]
    pub reference_id: String,
    #[serde(rename = "transactionResult")]
    pub transaction_result: PeachpaymentsRefundStatus,
    #[serde(rename = "responseCode")]
    pub response_code: Option<PeachpaymentsResponseCode>,
    #[serde(rename = "refundBalanceData")]
    pub refund_balance_data: Option<PeachpaymentsRefundBalance>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PeachpaymentsRefundHistory {
    #[serde(rename = "transactionId")]
    pub transaction_id: String,
    #[serde(rename = "referenceId")]
    pub reference_id: String,
    pub amount: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PeachpaymentsRefundBalance {
    pub amount: String,
    pub balance: String,
    pub refund_history: Vec<PeachpaymentsRefundHistory>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PeachpaymentsRefundSyncResponse {
    #[serde(rename = "transactionId")]
    pub transaction_id: String,
    #[serde(rename = "transactionResult")]
    pub transaction_result: PeachpaymentsRefundStatus,
    #[serde(rename = "responseCode")]
    pub response_code: Option<PeachpaymentsResponseCode>,
}

pub type PeachpaymentsRsyncResponse = PeachpaymentsRefundSyncResponse;

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PeachpaymentsResponseCode {
    Text(String),
    Structured {
        value: String,
        description: String,
        #[serde(rename = "terminalOutcomeString")]
        terminal_outcome_string: Option<String>,
        #[serde(rename = "receiptString")]
        receipt_string: Option<String>,
    },
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PeachpaymentsSyncResponse {
    #[serde(rename = "transactionId")]
    pub transaction_id: String,
    #[serde(rename = "transactionResult")]
    pub transaction_result: PeachpaymentsPaymentStatus,
    #[serde(rename = "responseCode")]
    pub response_code: Option<PeachpaymentsResponseCode>,
    pub merchant_information: Option<PeachpaymentsMerchantInformationResponse>,
    #[serde(rename = "ecommerceCardPaymentOnlyTransactionData")]
    pub card_data: Option<PeachpaymentsCardResponseData>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PeachpaymentsCardResponseData {
    pub amount: Option<PeachpaymentsAmountResponse>,
    pub stan: Option<String>,
    pub rrn: Option<String>,
    pub approval_code: Option<String>,
    pub merchant_advice_code: Option<String>,
    pub description: Option<String>,
    pub trace_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PeachpaymentsAmountResponse {
    pub amount: String,
    #[serde(rename = "currencyCode")]
    pub currency_code: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PeachpaymentsIncomingWebhook {
    #[serde(rename = "webhookId")]
    pub webhook_id: String,
    #[serde(rename = "webhookType")]
    pub webhook_type: String,
    #[serde(rename = "reversalFailureReason")]
    pub reversal_failure_reason: Option<String>,
    pub transaction: Option<PeachpaymentsWebhookTransaction>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PeachpaymentsWebhookTransaction {
    #[serde(rename = "transactionId")]
    pub transaction_id: String,
    #[serde(rename = "originalTransactionId")]
    pub original_transaction_id: Option<String>,
    #[serde(rename = "referenceId")]
    pub reference_id: String,
    #[serde(rename = "transactionResult")]
    pub transaction_result: PeachpaymentsPaymentStatus,
    #[serde(rename = "errorMessage")]
    pub error_message: Option<String>,
    #[serde(rename = "transactionType")]
    pub transaction_type: Option<PeachpaymentsTransactionType>,
    #[serde(rename = "responseCode")]
    pub response_code: Option<PeachpaymentsResponseCode>,
    pub merchant_information: Option<PeachpaymentsMerchantInformationResponse>,
    #[serde(rename = "ecommerceCardPaymentOnlyTransactionData")]
    pub card_data: Option<PeachpaymentsCardResponseData>,
    #[serde(rename = "refundBalanceData")]
    pub refund_balance_data: Option<PeachpaymentsRefundBalance>,
    #[serde(rename = "paymentMethod")]
    pub payment_method: Secret<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PeachpaymentsTransactionType {
    pub value: i32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    UnableToSend,
    Timeout,
    SecurityError,
    IssuerUnavailable,
    TooLateResponse,
    Malfunction,
    UnableToComplete,
    OnlineDeclined,
    SuspectedFraud,
    CardDeclined,
    Partial,
    OfflineDeclined,
    CustomerCancel,
}

impl std::str::FromStr for FailureReason {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_lowercase().as_str() {
            "unable_to_send" => Ok(Self::UnableToSend),
            "timeout" => Ok(Self::Timeout),
            "security_error" => Ok(Self::SecurityError),
            "issuer_unavailable" => Ok(Self::IssuerUnavailable),
            "too_late_response" => Ok(Self::TooLateResponse),
            "malfunction" => Ok(Self::Malfunction),
            "unable_to_complete" => Ok(Self::UnableToComplete),
            "online_declined" => Ok(Self::OnlineDeclined),
            "suspected_fraud" => Ok(Self::SuspectedFraud),
            "card_declined" => Ok(Self::CardDeclined),
            "partial" => Ok(Self::Partial),
            "offline_declined" => Ok(Self::OfflineDeclined),
            "customer_cancel" => Ok(Self::CustomerCancel),
            _ => Ok(Self::Timeout),
        }
    }
}
