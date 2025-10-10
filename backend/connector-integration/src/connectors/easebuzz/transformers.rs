use std::collections::HashMap;

use common_enums::{Currency, AttemptStatus, PaymentMethodType};
use common_utils::{
    crypto,
    date_time,
    errors::CustomResult,
    pii::Email,
    request::RequestContent,
    types::StringMinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync, Refund},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, 
        RefundFlowData, RefundsData, RefundsResponseData, RefundSyncData, ResponseId, 
        WebhookDetailsResponse, EventType
    },
    errors::ConnectorError,
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Maskable, Secret, ExposeInterface, PeekInterface};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

// Auth Types - matching Haskell structure
#[derive(Debug, Clone)]
pub struct EaseBuzzAuthType {
    pub api_key: Secret<String>,
    pub merchant_key: Secret<String>,
    pub salt: Secret<String>,
}

impl TryFrom<&domain_types::router_data::ConnectorAuthType> for EaseBuzzAuthType {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(auth_type: &domain_types::router_data::ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            domain_types::router_data::ConnectorAuthType::HeaderKey { api_key, key1 } => {
                let auth = EaseBuzzAuthType {
                    api_key: api_key.peek().clone().into(),
                    merchant_key: key1.peek().clone().into(),
                    salt: key1.peek().clone().into(), // Using key1 as salt for now
                };
                Ok(auth)
            }
            _ => Err(ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Request Types - matching Haskell data structures

#[derive(Debug, Serialize)]
pub struct EaseBuzzSeamlessTxnRequest {
    pub txnid: String,
    pub amount: String,
    pub productinfo: String,
    pub firstname: String,
    pub email: String,
    pub phone: String,
    pub surl: String,
    pub furl: String,
    pub hash: String,
    pub key: String,
    #[serde(rename = "payment_source")]
    pub payment_source: String,
    #[serde(rename = "upi_intent")]
    pub upi_intent: Option<String>,
    #[serde(rename = "upi_vpa")]
    pub upi_vpa: Option<String>,
}

impl<F, T> TryFrom<RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for EaseBuzzSeamlessTxnRequest
where
    T: PaymentMethodDataTypes,
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = EaseBuzzAuthType::try_from(&item.connector_auth_type)?;
        let merchant_key = auth.merchant_key.peek();
        let salt = auth.salt.peek();
        
        let amount = item.amount.get_amount_as_string();
        
        let txnid = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_| ConnectorError::MissingRequiredField { field_name: "connector_transaction_id" })?;
        let productinfo = format!("Payment for {}", txnid);
        let firstname = item.router_data.resource_common_data.get_customer_id()
            .map(|id| id.get_string_repr())
            .unwrap_or_else(|| "Customer".to_string());
        let email = item.router_data.request.email.clone()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "customer@example.com".to_string());
        let phone = item.router_data.request.phone.clone()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "9999999999".to_string());
        let return_url = item.router_data.request.get_router_return_url()
            .unwrap_or_else(|| "https://example.com".to_string());
        let surl = return_url.clone();
        let furl = return_url;
        
        // Determine payment source and UPI details - matching Haskell logic
        let (payment_source, upi_intent, upi_vpa) = match item.router_data.request.payment_method_type {
            PaymentMethodType::UpiIntent => {
                ("upi".to_string(), Some("intent".to_string()), None)
            }
            PaymentMethodType::UpiCollect => {
                ("upi".to_string(), None, None)
            }
            _ => ("upi".to_string(), None, None),
        };
        
        // Generate hash - matching Haskell hash generation
        let hash_string = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            merchant_key,
            txnid,
            amount,
            productinfo,
            firstname,
            email,
            phone,
            surl,
            furl,
            payment_source,
            upi_intent.as_deref().unwrap_or(""),
            upi_vpa.as_deref().unwrap_or("")
        );
        let hash = generate_sha512_hash(&format!("{}|{}", hash_string, salt));
        
        Ok(Self {
            txnid,
            amount,
            productinfo,
            firstname,
            email,
            phone,
            surl,
            furl,
            hash,
            key: merchant_key.to_string(),
            payment_source,
            upi_intent,
            upi_vpa,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct EaseBuzzTxnSyncRequest {
    pub txnid: String,
    pub amount: String,
    pub email: String,
    pub phone: String,
    pub key: String,
    pub hash: String,
}

impl TryFrom<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for EaseBuzzTxnSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = EaseBuzzAuthType::try_from(&item.connector_auth_type)?;
        let merchant_key = auth.merchant_key.peek();
        let salt = auth.salt.peek();
        
        let amount = item.amount.get_amount_as_string();
        
        let txnid = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_| ConnectorError::MissingRequiredField { field_name: "connector_transaction_id" })?;
        let email = item.router_data.request.email.clone()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "customer@example.com".to_string());
        let phone = item.router_data.request.phone.clone()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "9999999999".to_string());
        
        // Generate hash - matching Haskell
        let hash_string = format!(
            "{}|{}|{}|{}|{}",
            merchant_key,
            txnid,
            amount,
            email,
            phone
        );
        let hash = generate_sha512_hash(&format!("{}|{}", hash_string, salt));
        
        Ok(Self {
            txnid,
            amount,
            email,
            phone,
            key: merchant_key.to_string(),
            hash,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct EaseBuzzRefundRequest {
    pub txnid: String,
    pub refund_amount: String,
    pub refund_reason: String,
    pub hash: String,
    pub key: String,
}

impl TryFrom<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>
    for EaseBuzzRefundRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = EaseBuzzAuthType::try_from(&item.connector_auth_type)?;
        let merchant_key = auth.merchant_key.peek();
        let salt = auth.salt.peek();
        
        let refund_amount = item.amount.get_amount_as_string();
        
        let txnid = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_| ConnectorError::MissingRequiredField { field_name: "connector_transaction_id" })?;
        let refund_reason = item.router_data.request.refund_reason.clone()
            .unwrap_or_else(|| "Customer requested refund".to_string());
        
        // Generate hash - matching Haskell
        let hash_string = format!(
            "{}|{}|{}",
            merchant_key,
            txnid,
            refund_amount
        );
        let hash = generate_sha512_hash(&format!("{}|{}", hash_string, salt));
        
        Ok(Self {
            txnid,
            refund_amount,
            refund_reason,
            hash,
            key: merchant_key.to_string(),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct EaseBuzzRefundSyncRequest {
    pub key: String,
    pub easebuzz_id: String,
    pub hash: String,
    pub merchant_refund_id: String,
}

impl TryFrom<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>
    for EaseBuzzRefundSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = EaseBuzzAuthType::try_from(&item.connector_auth_type)?;
        let merchant_key = auth.merchant_key.peek();
        let salt = auth.salt.peek();
        
        let easebuzz_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_| ConnectorError::MissingRequiredField { field_name: "connector_transaction_id" })?;
        let merchant_refund_id = item.router_data.request.refund_id.clone()
            .ok_or(ConnectorError::MissingRequiredField { field_name: "refund_id" })?;
        
        // Generate hash - matching Haskell
        let hash_string = format!(
            "{}|{}|{}",
            merchant_key,
            easebuzz_id,
            merchant_refund_id
        );
        let hash = generate_sha512_hash(&format!("{}|{}", hash_string, salt));
        
        Ok(Self {
            key: merchant_key.to_string(),
            easebuzz_id,
            hash,
            merchant_refund_id,
        })
    }
}

// Response Types - matching Haskell data structures

#[derive(Debug, Deserialize)]
pub struct EaseBuzzUpiIntentResponse {
    pub status: bool,
    pub msg_desc: String,
    pub qr_link: Option<String>,
    pub msg_title: String,
    pub easebuzz_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzTxnSyncResponse {
    pub status: bool,
    pub msg: TxnSyncMessageType,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum TxnSyncMessageType {
    Success(EaseBuzzSeamlessTxnResponse),
    Error(String),
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzSeamlessTxnResponse {
    pub status: String,
    pub txnid: String,
    pub amount: String,
    pub addedon: String,
    pub productinfo: String,
    pub firstname: String,
    pub lastname: Option<String>,
    pub email: String,
    pub phone: String,
    pub easebuzz_id: String,
    pub bank_ref_num: Option<String>,
    pub bank_code: Option<String>,
    pub error_message: Option<String>,
    pub card_no: Option<String>,
    pub name_on_card: Option<String>,
    pub card_bin: Option<String>,
    pub card_brand: Option<String>,
    pub card_type: Option<String>,
    pub card_expiry_month: Option<String>,
    pub card_expiry_year: Option<String>,
    pub issuing_bank: Option<String>,
    pub issuing_country: Option<String>,
    pub card_issuer: Option<String>,
    pub card_level: Option<String>,
    pub card_sub_type: Option<String>,
    pub card_token: Option<String>,
    pub card_vault: Option<String>,
    pub card_vault_status: Option<String>,
    pub pg_type: Option<String>,
    pub error_code: Option<String>,
    pub error_desc: Option<String>,
    pub net_amount_debit: Option<String>,
    pub discount: Option<String>,
    pub additional_charges: Option<String>,
    pub payment_source: Option<String>,
    pub meCode: Option<String>,
    pub mode: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundResponse {
    pub status: bool,
    pub reason: Option<String>,
    pub easebuzz_id: Option<String>,
    pub refund_id: Option<String>,
    pub refund_amount: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundSyncResponse {
    pub code: i32,
    pub status: String,
    pub response: EaseBuzzRefundSyncResponseData,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum EaseBuzzRefundSyncResponseData {
    Success(EaseBuzzRefundSyncSuccessResponse),
    Failure(EaseBuzzRefundSyncFailureResponse),
    Validation(EaseBuzzRefundSyncValidationErrorResponse),
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundSyncSuccessResponse {
    pub txnid: String,
    pub easebuzz_id: String,
    pub net_amount_debit: String,
    pub amount: String,
    pub refunds: Option<Vec<RefundSyncType>>,
}

#[derive(Debug, Deserialize)]
pub struct RefundSyncType {
    pub refund_id: String,
    pub refund_status: String,
    pub merchant_refund_id: String,
    pub merchant_refund_date: String,
    pub refund_settled_date: Option<String>,
    pub refund_amount: String,
    pub arn_number: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundSyncFailureResponse {
    pub status: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundSyncValidationErrorResponse {
    pub validation_errors: Option<serde_json::Value>,
    pub status: bool,
    pub error_code: Option<String>,
    pub error_desc: Option<String>,
}

// Webhook Types - matching Haskell enum
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum EaseBuzzWebhookTypes {
    #[serde(rename = "payment")]
    Payment(EaseBuzzSeamlessTxnResponse),
    #[serde(rename = "refund")]
    Refund(EaseBuzzRefundWebhookResponse),
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundWebhookResponse {
    pub easebuzz_id: String,
    pub refund_id: String,
    pub refund_status: String,
    pub refund_amount: String,
    pub merchant_refund_id: String,
}

// Error Response - matching Haskell
#[derive(Debug, Deserialize)]
pub struct EaseBuzzErrorResponse {
    pub error_code: String,
    pub message: String,
    pub transaction_id: Option<String>,
}

// Helper functions - matching Haskell logic
pub fn get_webhook_object_from_body<T: serde::de::DeserializeOwned>(
    body: &[u8],
) -> CustomResult<T, ConnectorError> {
    serde_json::from_slice::<T>(body)
        .change_context(ConnectorError::ResponseDeserializationFailed)
}

fn generate_sha512_hash(data: &[u8]) -> Result<Vec<u8>, ConnectorError> {
    use sha2::{Sha512, Digest};
    
    let mut hasher = Sha512::new();
    hasher.update(data);
    Ok(hasher.finalize().to_vec())
}

pub fn get_easebuzz_webhook_event_type(
    webhook: EaseBuzzWebhookTypes,
) -> EventType {
    match webhook {
        EaseBuzzWebhookTypes::Payment(_) => EventType::Payment,
        EaseBuzzWebhookTypes::Refund(_) => EventType::Refund,
    }
}

pub fn get_easebuzz_payment_webhook_details(
    webhook: EaseBuzzWebhookTypes,
) -> CustomResult<(ResponseId, AttemptStatus, Option<String>, Option<String>), ConnectorError> {
    match webhook {
        EaseBuzzWebhookTypes::Payment(payment) => {
            let status = match payment.status.as_str() {
                "success" => AttemptStatus::Charged,
                "pending" => AttemptStatus::Pending,
                "failure" => AttemptStatus::Failure,
                _ => AttemptStatus::Pending,
            };
            
            let resource_id = ResponseId::ConnectorTransactionId(payment.txnid.clone());
            let error_code = payment.error_code.clone();
            let error_message = payment.error_desc.clone();
            
            Ok((resource_id, status, error_code, error_message))
        }
        _ => Err(ConnectorError::WebhookBodyDecodingFailed),
    }
}

pub fn get_easebuzz_refund_webhook_details(
    webhook: EaseBuzzWebhookTypes,
) -> CustomResult<(String, AttemptStatus, Option<String>, Option<String>), ConnectorError> {
    match webhook {
        EaseBuzzWebhookTypes::Refund(refund) => {
            let status = match refund.refund_status.as_str() {
                "success" => AttemptStatus::Success,
                "pending" => AttemptStatus::Pending,
                "failure" => AttemptStatus::Failure,
                _ => AttemptStatus::Pending,
            };
            
            let connector_refund_id = refund.refund_id.clone();
            let error_code = None;
            let error_message = None;
            
            Ok((connector_refund_id, status, error_code, error_message))
        }
        _ => Err(ConnectorError::WebhookBodyDecodingFailed),
    }
}

// Implement GetFormData for form data requests - matching Haskell form encoding
impl crate::connectors::macros::GetFormData for EaseBuzzSeamlessTxnRequest {
    fn get_form_data(&self) -> reqwest::multipart::Form {
        let form = reqwest::multipart::Form::new()
            .text("txnid", self.txnid.clone())
            .text("amount", self.amount.clone())
            .text("productinfo", self.productinfo.clone())
            .text("firstname", self.firstname.clone())
            .text("email", self.email.clone())
            .text("phone", self.phone.clone())
            .text("surl", self.surl.clone())
            .text("furl", self.furl.clone())
            .text("hash", self.hash.clone())
            .text("key", self.key.clone())
            .text("payment_source", self.payment_source.clone());
        
        let form = if let Some(ref upi_intent) = self.upi_intent {
            form.text("upi_intent", upi_intent.clone())
        } else {
            form
        };
        
        let form = if let Some(ref upi_vpa) = self.upi_vpa {
            form.text("upi_vpa", upi_vpa.clone())
        } else {
            form
        };
        
        form
    }
}

impl crate::connectors::macros::GetFormData for EaseBuzzTxnSyncRequest {
    fn get_form_data(&self) -> reqwest::multipart::Form {
        reqwest::multipart::Form::new()
            .text("txnid", self.txnid.clone())
            .text("amount", self.amount.clone())
            .text("email", self.email.clone())
            .text("phone", self.phone.clone())
            .text("key", self.key.clone())
            .text("hash", self.hash.clone())
    }
}

impl crate::connectors::macros::GetFormData for EaseBuzzRefundRequest {
    fn get_form_data(&self) -> reqwest::multipart::Form {
        reqwest::multipart::Form::new()
            .text("txnid", self.txnid.clone())
            .text("refund_amount", self.refund_amount.clone())
            .text("refund_reason", self.refund_reason.clone())
            .text("hash", self.hash.clone())
            .text("key", self.key.clone())
    }
}

impl crate::connectors::macros::GetFormData for EaseBuzzRefundSyncRequest {
    fn get_form_data(&self) -> reqwest::multipart::Form {
        reqwest::multipart::Form::new()
            .text("key", self.key.clone())
            .text("easebuzz_id", self.easebuzz_id.clone())
            .text("hash", self.hash.clone())
            .text("merchant_refund_id", self.merchant_refund_id.clone())
    }
}