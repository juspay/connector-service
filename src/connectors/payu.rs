// Payu Connector Implementation
pub mod constants;
pub mod transformers;

use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub enum PayuAuthType {
    KeySecret { key: String, salt: String },
}

impl PayuAuthType {
    pub fn get_auth_header(&self) -> String {
        match self {
            PayuAuthType::KeySecret { key, .. } => key.clone(),
        }
    }

    pub fn generate_hash(&self, data: &str) -> String {
        match self {
            PayuAuthType::KeySecret { salt, .. } => {
                use sha2::{Digest, Sha512};
                let mut hasher = Sha512::new();
                hasher.update(format!("{}|{}", data, salt).as_bytes());
                format!("{:x}", hasher.finalize())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Payu<T> {
    connector_name: &'static str,
    payment_method_data: PhantomData<T>,
}

impl<T> Payu<T> {
    pub fn new() -> Self {
        Self {
            connector_name: "payu",
            payment_method_data: PhantomData,
        }
    }
}

impl<T> Default for Payu<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PayuStatus {
    Success,
    Failure,
    Pending,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayuResponse {
    pub status: PayuStatus,
    pub mihpayid: Option<String>,
    pub txnid: Option<String>,
    pub amount: Option<String>,
    pub error_message: Option<String>,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PayuPaymentsRequest {
    pub key: String,
    pub command: String,
    pub hash: String,
    pub var1: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayuPaymentsResponse {
    pub status: String,
    pub mihpayid: Option<String>,
    pub txnid: Option<String>,
    pub amount: Option<String>,
    pub error_message: Option<String>,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PayuPaymentsSyncRequest {
    pub key: String,
    pub command: String,
    pub hash: String,
    pub var1: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayuPaymentsSyncResponse {
    pub status: String,
    pub txn_details: Option<PayuTransactionDetails>,
    pub msg: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayuTransactionDetails {
    pub mihpayid: String,
    pub txnid: String,
    pub amount: String,
    pub status: String,
    pub mode: String,
    pub bank_ref_num: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PayuRefundSyncRequest {
    pub key: String,
    pub command: String,
    pub hash: String,
    pub var1: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayuRefundSyncResponse {
    pub status: String,
    pub msg: Option<String>,
    pub refund_details: Option<Vec<PayuRefundDetail>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayuRefundDetail {
    pub refund_id: String,
    pub txnid: String,
    pub amount: String,
    pub status: String,
    pub bank_ref_num: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "status")]
pub enum PayuWebhookResponse {
    #[serde(rename = "success")]
    Success(PayuWebhookSuccess),
    #[serde(rename = "failure")]
    Failure(PayuWebhookFailure),
    #[serde(rename = "pending")]
    Pending(PayuWebhookPending),
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayuWebhookSuccess {
    pub mihpayid: String,
    pub txnid: String,
    pub amount: String,
    pub status: String,
    pub mode: String,
    pub bank_ref_num: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayuWebhookFailure {
    pub mihpayid: Option<String>,
    pub txnid: String,
    pub error_code: String,
    pub error_message: String,
    pub status: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayuWebhookPending {
    pub mihpayid: String,
    pub txnid: String,
    pub amount: String,
    pub status: String,
    pub mode: String,
}

impl PayuWebhookResponse {
    pub fn get_transaction_id(&self) -> String {
        match self {
            PayuWebhookResponse::Success(success) => success.txnid.clone(),
            PayuWebhookResponse::Failure(failure) => failure.txnid.clone(),
            PayuWebhookResponse::Pending(pending) => pending.txnid.clone(),
        }
    }

    pub fn get_event_type(&self) -> String {
        match self {
            PayuWebhookResponse::Success(_) => "payment.success".to_string(),
            PayuWebhookResponse::Failure(_) => "payment.failure".to_string(),
            PayuWebhookResponse::Pending(_) => "payment.pending".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayuErrorResponse {
    pub error_code: String,
    pub error_message: String,
    pub status: String,
}

impl PayuErrorResponse {
    pub fn get_error_response(res: String) -> Result<serde_json::Value, serde_json::Error> {
        let response: PayuErrorResponse = serde_json::from_str(&res)?;
        serde_json::to_value(response)
    }
}