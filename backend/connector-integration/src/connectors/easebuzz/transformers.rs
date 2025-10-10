use std::collections::HashMap;

use common_enums::{AttemptStatus, Currency, PaymentMethodType};
use common_utils::{
    crypto,
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    request::RequestContent,
    types::{self, StringMinorUnit},
};
use base64::Engine;
use domain_types::{
    connector_types::{
        PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, RefundSyncData,
        RefundsResponseData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub enum EaseBuzzAuthType {
    Key { api_key: Secret<String> },
}

impl EaseBuzzAuthType {
    pub fn get_auth_header(&self) -> String {
        match self {
            EaseBuzzAuthType::Key { api_key } => {
                base64::engine::general_purpose::STANDARD.encode(format!("{}:", api_key.expose()).as_bytes())
            }
        }
    }
}

impl TryFrom<&ConnectorAuthType> for EaseBuzzAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self::Key {
                api_key: api_key.clone(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainConnectorAuthType.into()),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct EaseBuzzPaymentsRequest {
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
    #[serde(rename = "udf1")]
    pub udf1: Option<String>,
    #[serde(rename = "udf2")]
    pub udf2: Option<String>,
    #[serde(rename = "udf3")]
    pub udf3: Option<String>,
    #[serde(rename = "udf4")]
    pub udf4: Option<String>,
    #[serde(rename = "udf5")]
    pub udf5: Option<String>,
    #[serde(rename = "udf6")]
    pub udf6: Option<String>,
    #[serde(rename = "udf7")]
    pub udf7: Option<String>,
    #[serde(rename = "udf8")]
    pub udf8: Option<String>,
    #[serde(rename = "udf9")]
    pub udf9: Option<String>,
    #[serde(rename = "udf10")]
    pub udf10: Option<String>,
}

impl<T> TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for EaseBuzzPaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = EaseBuzzAuthType::try_from(&item.connector_auth_type)?;
        let api_key = match auth {
            EaseBuzzAuthType::Key { api_key } => api_key.expose().to_string(),
        };

        let amount = item.amount.get_amount_as_string();
        let currency = item.router_data.request.currency.to_string();
        
        let txnid = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let customer_id_string = customer_id.get_string_repr();

        let email = item.router_data.request.email
            .clone()
            .map(|e| e.expose().to_string())
            .unwrap_or_else(|| format!("{}@example.com", customer_id_string));

        let phone = item.router_data.request.phone
            .clone()
            .map(|p| p.expose().to_string())
            .unwrap_or_else(|| "9999999999".to_string());

        let return_url = item.router_data.request.get_router_return_url()
            .unwrap_or_else(|| "https://example.com/return".to_string());

        // Generate hash - this would typically involve the merchant's salt
        let hash_string = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}",
            api_key,
            txnid,
            amount,
            "product_info",
            customer_id_string,
            email,
            phone,
            return_url,
            return_url
        );
        let hash = crypto::Sha512::generate_hash(hash_string.as_bytes());

        Ok(Self {
            txnid,
            amount,
            productinfo: "UPI Payment".to_string(),
            firstname: customer_id_string,
            email,
            phone,
            surl: return_url.clone(),
            furl: return_url,
            hash,
            key: api_key,
            payment_source: "upi".to_string(),
            udf1: Some(currency),
            udf2: Some(item.router_data.request.payment_method_type.to_string()),
            udf3: None,
            udf4: None,
            udf5: None,
            udf6: None,
            udf7: None,
            udf8: None,
            udf9: None,
            udf10: None,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzPaymentsResponse {
    pub status: i32,
    pub error_desc: Option<String>,
    pub data: Option<EaseBuzzPaymentData>,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzPaymentData {
    pub txnid: String,
    pub amount: String,
    pub status: String,
    pub payment_source: String,
    pub easebuzz_id: String,
    pub card_no: Option<String>,
    pub bank_ref_num: Option<String>,
    pub bankcode: Option<String>,
    pub error_message: Option<String>,
    pub name_on_card: Option<String>,
    pub card_brand: Option<String>,
    pub card_token: Option<String>,
    pub net_amount_debit: Option<String>,
    pub addedon: Option<String>,
    pub mode: Option<String>,
    pub PG_TYPE: Option<String>,
    pub card_type: Option<String>,
    pub bank_name: Option<String>,
    pub emi_tenure_id: Option<String>,
    pub discount: Option<String>,
    pub card_bin: Option<String>,
    pub card_last_four_digits: Option<String>,
    pub card_expiry: Option<String>,
    pub card_isin: Option<String>,
    pub card_issuer: Option<String>,
    pub card_country: Option<String>,
    pub card_scheme: Option<String>,
    pub card_sub_scheme: Option<String>,
    pub card_product: Option<String>,
    pub card_level: Option<String>,
    pub card_class: Option<String>,
    pub card_variant: Option<String>,
    pub card_category: Option<String>,
    pub card_entry_mode: Option<String>,
    pub card_auth_method: Option<String>,
    pub card_auth_result: Option<String>,
    pub card_auth_code: Option<String>,
    pub card_auth_reason: Option<String>,
    pub card_auth_avs: Option<String>,
    pub card_auth_cvv: Option<String>,
    pub card_auth_3ds: Option<String>,
    pub card_auth_risk: Option<String>,
    pub card_auth_fraud: Option<String>,
    pub card_auth_score: Option<String>,
    pub card_auth_decision: Option<String>,
    pub card_auth_rule: Option<String>,
    pub card_auth_message: Option<String>,
    pub card_auth_reference: Option<String>,
    pub card_auth_transaction: Option<String>,
    pub card_auth_merchant: Option<String>,
    pub card_auth_gateway: Option<String>,
    pub card_auth_processor: Option<String>,
    pub card_auth_network: Option<String>,
    pub card_auth_acquirer: Option<String>,
    pub card_auth_issuer: Option<String>,
    pub card_auth_scheme: Option<String>,
    pub card_auth_brand: Option<String>,
    pub card_auth_product: Option<String>,
    pub card_auth_type: Option<String>,
    pub card_auth_category: Option<String>,
    pub card_auth_level: Option<String>,
    pub card_auth_class: Option<String>,
    pub card_auth_variant: Option<String>,
    pub card_auth_sub_scheme: Option<String>,
    pub card_auth_country: Option<String>,
    pub card_auth_currency: Option<String>,
    pub card_auth_amount: Option<String>,
    pub card_auth_date: Option<String>,
    pub card_auth_time: Option<String>,
    pub card_auth_timezone: Option<String>,
    pub card_auth_ip: Option<String>,
    pub card_auth_device: Option<String>,
    pub card_auth_browser: Option<String>,
    pub card_auth_os: Option<String>,
    pub card_auth_version: Option<String>,
    pub card_auth_language: Option<String>,
    pub card_auth_encoding: Option<String>,
    pub card_auth_charset: Option<String>,
    pub card_auth_compression: Option<String>,
    pub card_auth_encryption: Option<String>,
    pub card_auth_signature: Option<String>,
    pub card_auth_certificate: Option<String>,
    pub card_auth_key: Option<String>,
    pub card_auth_algorithm: Option<String>,
    pub card_auth_hash: Option<String>,
    pub card_auth_nonce: Option<String>,
    pub card_auth_timestamp: Option<String>,
    pub card_auth_counter: Option<String>,
    pub card_auth_sequence: Option<String>,
    pub card_auth_session: Option<String>,
    pub card_auth_token: Option<String>,
    pub card_auth_ticket: Option<String>,
    pub card_auth_challenge: Option<String>,
    pub card_auth_response: Option<String>,
    pub card_auth_verification: Option<String>,
    pub card_auth_validation: Option<String>,
    pub card_auth_authentication: Option<String>,
    pub card_auth_authorization: Option<String>,
    pub card_auth_settlement: Option<String>,
    pub card_auth_capture: Option<String>,
    pub card_auth_refund: Option<String>,
    pub card_auth_void: Option<String>,
    pub card_auth_chargeback: Option<String>,
    pub card_auth_retrieval: Option<String>,
    pub card_auth_dispute: Option<String>,
    pub card_auth_arbitration: Option<String>,
    pub card_auth_pre_arbitration: Option<String>,
    pub card_auth_fraud_dispute: Option<String>,
    pub card_auth_chargeback_reversal: Option<String>,
    pub card_auth_retrieval_reversal: Option<String>,
    pub card_auth_dispute_reversal: Option<String>,
    pub card_auth_arbitration_reversal: Option<String>,
    pub card_auth_pre_arbitration_reversal: Option<String>,
    pub card_auth_fraud_dispute_reversal: Option<String>,
    pub card_auth_chargeback_representation: Option<String>,
    pub card_auth_retrieval_representation: Option<String>,
    pub card_auth_dispute_representation: Option<String>,
    pub card_auth_arbitration_representation: Option<String>,
    pub card_auth_pre_arbitration_representation: Option<String>,
    pub card_auth_fraud_dispute_representation: Option<String>,
    pub card_auth_chargeback_second_presentation: Option<String>,
    pub card_auth_retrieval_second_presentation: Option<String>,
    pub card_auth_dispute_second_presentation: Option<String>,
    pub card_auth_arbitration_second_presentation: Option<String>,
    pub card_auth_pre_arbitration_second_presentation: Option<String>,
    pub card_auth_fraud_dispute_second_presentation: Option<String>,
    pub card_auth_chargeback_third_presentation: Option<String>,
    pub card_auth_retrieval_third_presentation: Option<String>,
    pub card_auth_dispute_third_presentation: Option<String>,
    pub card_auth_arbitration_third_presentation: Option<String>,
    pub card_auth_pre_arbitration_third_presentation: Option<String>,
    pub card_auth_fraud_dispute_third_presentation: Option<String>,
    pub card_auth_chargeback_fourth_presentation: Option<String>,
    pub card_auth_retrieval_fourth_presentation: Option<String>,
    pub card_auth_dispute_fourth_presentation: Option<String>,
    pub card_auth_arbitration_fourth_presentation: Option<String>,
    pub card_auth_pre_arbitration_fourth_presentation: Option<String>,
    pub card_auth_fraud_dispute_fourth_presentation: Option<String>,
    pub card_auth_chargeback_fifth_presentation: Option<String>,
    pub card_auth_retrieval_fifth_presentation: Option<String>,
    pub card_auth_dispute_fifth_presentation: Option<String>,
    pub card_auth_arbitration_fifth_presentation: Option<String>,
    pub card_auth_pre_arbitration_fifth_presentation: Option<String>,
    pub card_auth_fraud_dispute_fifth_presentation: Option<String>,
}

impl TryFrom<EaseBuzzPaymentsResponse> for PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: EaseBuzzPaymentsResponse) -> Result<Self, Self::Error> {
        let status = match response.status {
            1 => AttemptStatus::Charged,
            0 => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        let error_message = response.error_desc.or_else(|| {
            response.data.as_ref().and_then(|data| data.error_message.clone())
        });

        let response_id = response.data.as_ref().map(|data| domain_types::connector_types::ResponseId {
            gateway_payment_id: Some(data.easebuzz_id.clone()),
            transaction_id: Some(data.txnid.clone()),
            ..Default::default()
        });

        Ok(Self {
            status,
            response_id,
            error_message,
            amount_captured: response.data.as_ref().and_then(|data| {
                data.net_amount_debit
                    .as_ref()
                    .and_then(|amt| amt.parse::<f64>().ok())
                    .map(|amt| types::MinorUnit::from_major_unit_as_i64(amt))
            }),
            ..Default::default()
        })
    }
}

#[derive(Debug, Serialize)]
pub struct EaseBuzzPaymentsSyncRequest {
    pub txnid: String,
    pub amount: String,
    pub email: String,
    pub phone: String,
    pub key: String,
    pub hash: String,
}

impl TryFrom<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for EaseBuzzPaymentsSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = EaseBuzzAuthType::try_from(&item.connector_auth_type)?;
        let api_key = match auth {
            EaseBuzzAuthType::Key { api_key } => api_key.expose().to_string(),
        };

        let amount = item.amount.get_amount_as_string();
        
        let txnid = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let customer_id_string = customer_id.get_string_repr();

        let email = item.router_data.request.email
            .clone()
            .map(|e| e.expose().to_string())
            .unwrap_or_else(|| format!("{}@example.com", customer_id_string));

        let phone = item.router_data.request.phone
            .clone()
            .map(|p| p.expose().to_string())
            .unwrap_or_else(|| "9999999999".to_string());

        // Generate hash for sync request
        let hash_string = format!(
            "{}|{}|{}|{}|{}|{}",
            api_key,
            txnid,
            amount,
            email,
            phone,
            "salt" // This would be the merchant's salt
        );
        let hash = crypto::Sha512::generate_hash(hash_string.as_bytes());

        Ok(Self {
            txnid,
            amount,
            email,
            phone,
            key: api_key,
            hash,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzPaymentsSyncResponse {
    pub status: bool,
    pub msg: EaseBuzzSyncMessage,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum EaseBuzzSyncMessage {
    Success(EaseBuzzPaymentData),
    Error(String),
}

impl TryFrom<EaseBuzzPaymentsSyncResponse> for PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: EaseBuzzPaymentsSyncResponse) -> Result<Self, Self::Error> {
        let (status, payment_data) = match response.msg {
            EaseBuzzSyncMessage::Success(data) => {
                let status = match data.status.as_str() {
                    "success" => AttemptStatus::Charged,
                    "failure" => AttemptStatus::Failure,
                    "pending" => AttemptStatus::Pending,
                    _ => AttemptStatus::Pending,
                };
                (status, Some(data))
            }
            EaseBuzzSyncMessage::Error(_) => (AttemptStatus::Failure, None),
        };

        let response_id = payment_data.as_ref().map(|data| domain_types::connector_types::ResponseId {
            gateway_payment_id: Some(data.easebuzz_id.clone()),
            transaction_id: Some(data.txnid.clone()),
            ..Default::default()
        });

        Ok(Self {
            status,
            response_id,
            amount_captured: payment_data.as_ref().and_then(|data| {
                data.net_amount_debit
                    .as_ref()
                    .and_then(|amt| amt.parse::<f64>().ok())
                    .map(|amt| types::MinorUnit::from_major_unit_as_i64(amt))
            }),
            ..Default::default()
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

impl TryFrom<&RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>>
    for EaseBuzzRefundSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = EaseBuzzAuthType::try_from(&item.connector_auth_type)?;
        let api_key = match auth {
            EaseBuzzAuthType::Key { api_key } => api_key.expose().to_string(),
        };

        let easebuzz_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        let merchant_refund_id = item.router_data.request.refund_id
            .get_string_repr()
            .to_string();

        // Generate hash for refund sync request
        let hash_string = format!(
            "{}|{}|{}|{}",
            api_key,
            easebuzz_id,
            merchant_refund_id,
            "salt" // This would be the merchant's salt
        );
        let hash = crypto::Sha512::generate_hash(hash_string.as_bytes());

        Ok(Self {
            key: api_key,
            easebuzz_id,
            hash,
            merchant_refund_id,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundSyncResponse {
    pub code: i32,
    pub status: String,
    pub response: EaseBuzzRefundSyncData,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum EaseBuzzRefundSyncData {
    Success(EaseBuzzRefundSyncSuccess),
    Failure(EaseBuzzRefundSyncFailure),
    Validation(EaseBuzzRefundSyncValidation),
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundSyncSuccess {
    pub txnid: String,
    pub easebuzz_id: String,
    pub net_amount_debit: String,
    pub amount: String,
    pub refunds: Option<Vec<EaseBuzzRefundInfo>>,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundSyncFailure {
    pub status: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundSyncValidation {
    pub validation_errors: Option<serde_json::Value>,
    pub status: bool,
    pub error_code: Option<String>,
    pub error_desc: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundInfo {
    pub refund_id: String,
    pub refund_status: String,
    pub merchant_refund_id: String,
    pub merchant_refund_date: String,
    pub refund_settled_date: Option<String>,
    pub refund_amount: String,
    pub arn_number: Option<String>,
}

impl TryFrom<EaseBuzzRefundSyncResponse> for RefundsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: EaseBuzzRefundSyncResponse) -> Result<Self, Self::Error> {
        let (status, refund_data) = match response.response {
            EaseBuzzRefundSyncData::Success(data) => {
                let status = match data.refunds.as_ref().and_then(|refunds| refunds.first()) {
                    Some(refund) => match refund.refund_status.as_str() {
                        "success" => AttemptStatus::Charged,
                        "failure" => AttemptStatus::Failure,
                        "pending" => AttemptStatus::Pending,
                        _ => AttemptStatus::Pending,
                    },
                    None => AttemptStatus::Pending,
                };
                (status, Some(data))
            }
            EaseBuzzRefundSyncData::Failure(_) => (AttemptStatus::Failure, None),
            EaseBuzzRefundSyncData::Validation(_) => (AttemptStatus::Failure, None),
        };

        let response_id = refund_data.as_ref().map(|data| domain_types::connector_types::ResponseId {
            gateway_payment_id: Some(data.easebuzz_id.clone()),
            transaction_id: Some(data.txnid.clone()),
            ..Default::default()
        });

        Ok(Self {
            status,
            response_id,
            amount_captured: refund_data.as_ref().and_then(|data| {
                data.net_amount_debit
                    .parse::<f64>()
                    .ok()
                    .map(|amt| types::MinorUnit::from_major_unit_as_i64(amt))
            }),
            ..Default::default()
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzErrorResponse {
    pub status: i32,
    pub error_desc: Option<String>,
}