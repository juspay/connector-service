use common_enums::AttemptStatus;
use common_utils::{
    errors::CustomResult,
    types::MinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    router_data::ConnectorAuthType,
    router_response_types::Response,
    errors::ConnectorError,
};
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

use super::constants;

// Request/Response types based on Haskell implementation

#[derive(Debug, Clone, Serialize)]
pub struct TpslMerchantPayload {
    pub identifier: String,
    pub webhook_endpoint_url: Option<String>,
    pub response_type: Option<String>,
    pub response_endpoint_url: Option<String>,
    pub description: Option<String>,
    pub webhook_type: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TpslCartPayload {
    pub item: Vec<TpslItemPayload>,
    pub reference: String,
    pub identifier: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TpslItemPayload {
    pub description: String,
    pub provider_identifier: String,
    pub surcharge_or_discount_amount: String,
    pub amount: String,
    pub com_amt: String,
    pub sku: String,
    pub reference: String,
    pub identifier: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TpslPaymentPayload {
    pub method: TpslMethodPayload,
    pub instrument: TpslInstrumentPayload,
    pub instruction: Option<TpslInstructionPayload>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TpslMethodPayload {
    pub token: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub code: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TpslInstrumentPayload {
    pub identifier: String,
    pub token: Option<String>,
    pub alias: Option<String>,
    pub provider: Option<String>,
    #[serde(rename = "type")]
    pub instrument_type: Option<String>,
    pub action: Option<String>,
    pub processor: Option<String>,
    pub issuer: Option<String>,
    pub acquirer: Option<String>,
    pub authentication: Option<TpslAuthenticationPayload>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TpslAuthenticationPayload {
    pub token: Option<String>,
    #[serde(rename = "type")]
    pub auth_type: Option<String>,
    pub sub_type: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TpslInstructionPayload {
    pub identifier: String,
    pub amount: String,
    pub currency: String,
    #[serde(rename = "type")]
    pub instruction_type: String,
    pub description: Option<String>,
    pub action: Option<String>,
    pub reference: Option<String>,
    pub start_date_time: Option<String>,
    pub end_date_time: Option<String>,
    pub frequency: Option<String>,
    pub debit_day: Option<String>,
    pub debit_flag: Option<String>,
    pub validity: Option<String>,
    pub limit: Option<String>,
    pub occurrence: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TpslTransactionPayload {
    pub identifier: String,
    pub amount: String,
    pub currency: String,
    #[serde(rename = "type")]
    pub txn_type: String,
    pub sub_type: String,
    pub request_type: String,
    pub description: Option<String>,
    pub date_time: String,
    pub token: Option<String>,
    pub security_token: Option<String>,
    pub reference: String,
    pub device_identifier: Option<String>,
    pub sms_sending: Option<String>,
    pub forced_3ds_call: Option<String>,
    pub is_registration: Option<String>,
    pub merchant_initiated: Option<String>,
    pub tenure_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TpslConsumerPayload {
    pub identifier: String,
    pub email_id: Option<String>,
    pub mobile_number: Option<String>,
    pub account_no: Option<String>,
    pub account_type: Option<String>,
    pub account_holder_name: Option<String>,
    pub aadhar_no: Option<String>,
    pub vpa: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TpslFlagsType {
    pub account_no: bool,
    pub mobile_number: bool,
    pub email_id: bool,
    pub card_details: bool,
    pub mandate_details: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TpslPaymentsRequest {
    pub merchant: TpslMerchantPayload,
    pub cart: TpslCartPayload,
    pub payment: TpslPaymentPayload,
    pub transaction: TpslTransactionPayload,
    pub consumer: TpslConsumerPayload,
    pub merchant_input_flags: Option<TpslFlagsType>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TpslPaymentsSyncRequest {
    pub merchant: TpslMerchantDataType,
    pub payment: TpslPaymentSyncType,
    pub transaction: TpslTransactionSyncType,
    pub consumer: TpslConsumerDataType,
}

#[derive(Debug, Clone, Serialize)]
pub struct TpslMerchantDataType {
    pub identifier: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TpslPaymentSyncType {
    pub instruction: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TpslTransactionSyncType {
    pub identifier: String,
    pub amount: Option<String>,
    pub currency: Option<String>,
    #[serde(rename = "type")]
    pub txn_type: Option<String>,
    pub sub_type: Option<String>,
    pub request_type: String,
    pub date_time: String,
    pub token: String,
    pub device_identifier: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TpslConsumerDataType {
    pub identifier: String,
}

// Response types

#[derive(Debug, Clone, Deserialize)]
pub struct TpslPaymentsResponse {
    pub code: i32,
    pub status: String,
    pub response: TpslResponseData,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum TpslResponseData {
    AuthResponse(TpslAuthResponse),
    DecryptedResponse(TpslDecryptedResponse),
    UpiResponse(TpslUpiResponse),
    ErrorResponse(TpslErrorResponse),
}

#[derive(Debug, Clone, Deserialize)]
pub struct TpslAuthResponse {
    #[serde(flatten)]
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TpslDecryptedResponse {
    pub merchant_code: String,
    pub merchant_transaction_identifier: Option<String>,
    pub merchant_transaction_request_type: String,
    pub response_type: String,
    pub transaction_state: String,
    pub merchant_additional_details: Option<String>,
    pub payment_method: TpslPaymentMethodResponse,
    pub error: Option<serde_json::Value>,
    pub identifier: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TpslUpiResponse {
    pub merchant_code: String,
    pub merchant_transaction_identifier: String,
    pub merchant_transaction_request_type: String,
    pub response_type: String,
    pub transaction_state: String,
    pub merchant_additional_details: Option<serde_json::Value>,
    pub payment_method: TpslUpiPaymentMethod,
    pub error: Option<serde_json::Value>,
    pub merchant_response_string: Option<serde_json::Value>,
    pub pdf_download_url: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TpslErrorResponse {
    pub error_code: String,
    pub error_message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TpslPaymentMethodResponse {
    pub token: String,
    pub instrument_alias_name: Option<String>,
    pub instrument_token: Option<serde_json::Value>,
    pub bank_selection_code: String,
    pub acs: Option<TpslAcsPayload>,
    pub otp: Option<serde_json::Value>,
    pub payment_transaction: TpslPaymentTransaction,
    pub authentication: Option<serde_json::Value>,
    pub error: TpslPaymentMethodError,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TpslUpiPaymentMethod {
    pub token: Option<String>,
    pub instrument_alias_name: String,
    pub instrument_token: String,
    pub bank_selection_code: String,
    pub acs: TpslAcsPayload,
    pub otp: Option<serde_json::Value>,
    pub payment_transaction: TpslUpiPaymentTransaction,
    pub authentication: Option<serde_json::Value>,
    pub error: TpslPaymentMethodError,
    pub payment_mode: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TpslAcsPayload {
    pub bank_acs_form_name: String,
    pub bank_acs_http_method: serde_json::Value,
    pub bank_acs_params: Option<serde_json::Value>,
    pub bank_acs_url: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TpslPaymentTransaction {
    pub amount: String,
    pub balance_amount: String,
    pub bank_reference_identifier: String,
    pub date_time: String,
    pub error_message: String,
    pub identifier: Option<String>,
    pub refund_identifier: String,
    pub status_code: String,
    pub status_message: String,
    pub instruction: Option<serde_json::Value>,
    pub reference: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TpslUpiPaymentTransaction {
    pub amount: String,
    pub balance_amount: Option<String>,
    pub bank_reference_identifier: Option<String>,
    pub date_time: Option<String>,
    pub error_message: Option<String>,
    pub identifier: Option<String>,
    pub refund_identifier: String,
    pub status_code: String,
    pub status_message: String,
    pub instruction: Option<serde_json::Value>,
    pub reference: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TpslPaymentMethodError {
    pub code: String,
    pub desc: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TpslPaymentsSyncResponse {
    pub merchant_code: String,
    pub merchant_transaction_identifier: String,
    pub merchant_transaction_request_type: String,
    pub response_type: String,
    pub transaction_state: String,
    pub payment_method: TpslUpiPaymentMethod,
    pub error: Option<serde_json::Value>,
    pub merchant_response_string: Option<serde_json::Value>,
    pub status_code: Option<String>,
    pub status_message: Option<String>,
    pub identifier: Option<String>,
    pub bank_reference_identifier: Option<String>,
    pub merchant_additional_details: Option<String>,
}

// Transformer implementations

impl<T> TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for TpslPaymentsRequest
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let amount = item.request.amount.to_string();
        let currency = item.request.currency.to_string();
        
        let customer_id = item.resource_common_data.get_customer_id()?;
        let customer_id_string = customer_id.get_string_repr();
        
        let transaction_id = item.request.related_transaction_id.clone().unwrap_or_else(|| "default_transaction_id".to_string());
        
        let return_url = item.request.get_router_return_url()?;
        
        let email = item.request.email.clone();
        let phone: Option<Secret<String>> = None;
        
        let merchant_id = get_merchant_id(&item.connector_auth_type)?;
        
        // Extract UPI specific data - placeholder for now
        let vpa: Option<String> = None;
        
        let merchant_payload = TpslMerchantPayload {
            identifier: merchant_id,
            webhook_endpoint_url: Some(return_url.clone()),
            response_type: Some(constants::RESPONSE_TYPE_ASYNC.to_string()),
            response_endpoint_url: Some(return_url),
            description: Some("UPI Payment".to_string()),
            webhook_type: Some("PAYMENT".to_string()),
        };
        
        let cart_payload = TpslCartPayload {
            item: vec![TpslItemPayload {
                description: "UPI Payment".to_string(),
                provider_identifier: "UPI".to_string(),
                surcharge_or_discount_amount: "0".to_string(),
                amount: amount.clone(),
                com_amt: "0".to_string(),
                sku: "UPI_001".to_string(),
                reference: transaction_id,
                identifier: "item_001".to_string(),
            }],
            reference: transaction_id,
            identifier: "cart_001".to_string(),
            description: Some("UPI Payment Transaction".to_string()),
        };
        
        let payment_payload = TpslPaymentPayload {
            method: TpslMethodPayload {
                token: "UPI".to_string(),
                method_type: constants::DEFAULT_PAYMENT_METHOD.to_string(),
                code: "UPI".to_string(),
            },
            instrument: TpslInstrumentPayload {
                identifier: vpa.clone().unwrap_or_else(|| "default_vpa".to_string()),
                token: None,
                alias: vpa,
                provider: Some("UPI".to_string()),
                instrument_type: Some("VPA".to_string()),
                action: Some("COLLECT".to_string()),
                processor: None,
                issuer: None,
                acquirer: None,
                authentication: None,
            },
            instruction: None,
        };
        
        let transaction_payload = TpslTransactionPayload {
            identifier: transaction_id,
            amount: amount.clone(),
            currency: currency.clone(),
            txn_type: constants::TXN_TYPE_PAYMENT.to_string(),
            sub_type: constants::UPI_COLLECT_TYPE.to_string(),
            request_type: constants::DEFAULT_REQUEST_TYPE.to_string(),
            description: Some("UPI Payment Transaction".to_string()),
            date_time: "2024-01-01 00:00:00".to_string(),
            token: None,
            security_token: None,
            reference: transaction_id,
            device_identifier: None, // TODO: implement IP address extraction
            sms_sending: Some("N".to_string()),
            forced_3ds_call: Some("N".to_string()),
            is_registration: Some("N".to_string()),
            merchant_initiated: Some("N".to_string()),
            tenure_id: None,
        };
        
        let consumer_payload = TpslConsumerPayload {
            identifier: customer_id_string.to_string(),
            email_id: email.map(|e| e.expose().clone()),
            mobile_number: phone.map(|p| p.expose().clone()),
            account_no: None,
            account_type: None,
            account_holder_name: None,
            aadhar_no: None,
            vpa,
        };
        
        let flags = TpslFlagsType {
            account_no: false,
            mobile_number: true,
            email_id: true,
            card_details: false,
            mandate_details: false,
        };
        
        Ok(Self {
            merchant: merchant_payload,
            cart: cart_payload,
            payment: payment_payload,
            transaction: transaction_payload,
            consumer: consumer_payload,
            merchant_input_flags: Some(flags),
        })
    }
}

impl TryFrom<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for TpslPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let merchant_id = get_merchant_id(&item.connector_auth_type)?;
        let transaction_id = item.request.connector_transaction_id.get_connector_transaction_id().unwrap_or_else(|_| "default_transaction_id".to_string());
        
        let customer_id = item.resource_common_data.get_customer_id()?;
        let customer_id_string = customer_id.get_string_repr();
        
        Ok(Self {
            merchant: TpslMerchantDataType {
                identifier: merchant_id,
            },
            payment: TpslPaymentSyncType {
                instruction: None,
            },
            transaction: TpslTransactionSyncType {
                identifier: transaction_id,
                amount: None,
                currency: None,
                txn_type: None,
                sub_type: None,
                request_type: constants::RESPONSE_TYPE_SYNC.to_string(),
                date_time: "2024-01-01 00:00:00".to_string(),
                token: "sync_token".to_string(),
                device_identifier: None,
            },
            consumer: TpslConsumerDataType {
                identifier: customer_id_string.to_string(),
            },
        })
    }
}

impl TryFrom<TpslPaymentsResponse> for PaymentsResponseData
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(response: TpslPaymentsResponse) -> Result<Self, Self::Error> {
        let status = match response.status.to_uppercase().as_str() {
            "SUCCESS" | "OK" => AttemptStatus::Charged,
            "PENDING" | "PROCESSING" => AttemptStatus::Pending,
            "FAILED" | "ERROR" => AttemptStatus::Failure,
            "CANCELLED" => AttemptStatus::Voided,
            _ => AttemptStatus::Pending,
        };
        
        let (amount, currency, transaction_id, error_message) = match response.response {
            TpslResponseData::DecryptedResponse(decrypted) => {
                let amount = MinorUnit::new(
                    (decrypted.payment_method.payment_transaction.amount.parse::<f64>()
                        .unwrap_or(0.0) * 100.0) as i64);
                let currency = constants::DEFAULT_CURRENCY.to_string();
                let transaction_id = decrypted.merchant_transaction_identifier
                    .unwrap_or_else(|| "unknown".to_string());
                let error_message = if decrypted.payment_method.payment_transaction.status_code == "000" {
                    None
                } else {
                    Some(decrypted.payment_method.payment_transaction.error_message)
                };
                (Some(amount), Some(currency), Some(transaction_id), error_message)
            },
            TpslResponseData::UpiResponse(upi) => {
                let amount = MinorUnit::new(
                    (upi.payment_method.payment_transaction.amount.parse::<f64>()
                        .unwrap_or(0.0) * 100.0) as i64);
                let currency = constants::DEFAULT_CURRENCY.to_string();
                let transaction_id = upi.merchant_transaction_identifier;
                let error_message = if upi.payment_method.payment_transaction.status_code == "000" {
                    None
                } else {
                    upi.payment_method.payment_transaction.error_message
                };
                (Some(amount), Some(currency), Some(transaction_id), error_message)
            },
            TpslResponseData::ErrorResponse(error) => {
                (None, None, None, Some(error.error_message))
            },
            TpslResponseData::AuthResponse(_) => {
                (None, None, None, Some("Authentication response received".to_string()))
            },
        };
        
        Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId("unknown".to_string()),
            redirection_data: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            mandate_reference: None,
            status_code: 200,
        })
    }
}

impl TryFrom<TpslPaymentsSyncResponse> for PaymentsResponseData
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(response: TpslPaymentsSyncResponse) -> Result<Self, Self::Error> {
        let status = match response.transaction_state.to_uppercase().as_str() {
            "SUCCESS" | "COMPLETED" => AttemptStatus::Charged,
            "PENDING" | "PROCESSING" | "INITIATED" => AttemptStatus::Pending,
            "FAILED" | "ERROR" | "DECLINED" => AttemptStatus::Failure,
            "CANCELLED" | "ABORTED" => AttemptStatus::Voided,
            _ => AttemptStatus::Pending,
        };
        
        let amount = MinorUnit::new(
            (response.payment_method.payment_transaction.amount.parse::<f64>()
                .unwrap_or(0.0) * 100.0) as i64);
        
        let currency = constants::DEFAULT_CURRENCY.to_string();
        let transaction_id = response.merchant_transaction_identifier.clone();
        
        let error_message = if response.payment_method.payment_transaction.status_code == "000" {
            None
        } else {
            response.payment_method.payment_transaction.error_message
        };
        
        Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(transaction_id),
            redirection_data: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            mandate_reference: None,
            status_code: 200,
        })
    }
}

// Helper functions

fn get_merchant_id(auth_type: &ConnectorAuthType) -> CustomResult<String, ConnectorError> {
    match auth_type {
        ConnectorAuthType::SignatureKey { api_key, .. } => {
            Ok(api_key.clone().expose().to_string())
        },
        ConnectorAuthType::HeaderKey { api_key, .. } => {
            Ok(api_key.clone().expose().to_string())
        },
        ConnectorAuthType::BodyKey { api_key, .. } => {
            Ok(api_key.clone().expose().to_string())
        },
        _ => Err(ConnectorError::RequestEncodingFailed)?,
    }
}

fn _extract_upi_vpa<T>(_payment_method_data: &T) -> CustomResult<Option<String>, ConnectorError>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    // This would need to be implemented based on the actual PaymentMethodDataTypes structure
    // For now, return None as placeholder
    Ok(None)
}

pub fn get_content_type() -> &'static str {
    "application/json"
}

pub fn get_error_response_v2(
    response: &Response,
) -> CustomResult<ErrorResponse, ConnectorError> {
    Ok(ErrorResponse {
        status_code: response.status_code,
        code: "UNKNOWN".to_string(),
        message: "Unknown error occurred".to_string(),
        reason: None,
        status_message: None,
    })
}

#[derive(Debug, Default)]
pub struct ErrorResponse {
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub reason: Option<String>,
    pub status_message: Option<String>,
}