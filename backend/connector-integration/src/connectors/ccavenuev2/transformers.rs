use std::collections::HashMap;

use common_enums::AttemptStatus;
use common_utils::{
    pii::Email,
    types::MinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, UpiData},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::ccavenuev2::CcavenueV2RouterData, types::ResponseRouterData};

type Error = error_stack::Report<errors::ConnectorError>;

// ===== AUTH TYPE =====

#[derive(Debug, Clone)]
pub struct CcavenueV2AuthType {
    pub access_code: Secret<String>,
    pub working_key: Secret<String>,
    pub merchant_id: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for CcavenueV2AuthType {
    type Error = Error;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self {
                access_code: api_key.to_owned(),
                working_key: key1.to_owned(),
                merchant_id: api_secret.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// ===== REQUEST STRUCTURES =====

#[derive(Debug, Serialize)]
pub struct CcavenueV2PaymentsRequest {
    #[serde(rename = "encRequest")]
    pub enc_request: Secret<String>,
    #[serde(rename = "access_code")]
    pub access_code: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

#[derive(Debug, Serialize)]
struct CcavenueV2PaymentRequestPayload {
    #[serde(rename = "merchant_id")]
    merchant_id: Secret<String>,
    #[serde(rename = "order_id")]
    order_id: String,
    #[serde(rename = "amount")]
    amount: String,
    #[serde(rename = "currency")]
    currency: String,
    #[serde(rename = "redirect_url")]
    redirect_url: String,
    #[serde(rename = "cancel_url")]
    cancel_url: String,
    #[serde(rename = "language")]
    language: String,
    #[serde(rename = "billing_name", skip_serializing_if = "Option::is_none")]
    billing_name: Option<Secret<String>>,
    #[serde(rename = "billing_email", skip_serializing_if = "Option::is_none")]
    billing_email: Option<Email>,
    #[serde(rename = "billing_tel", skip_serializing_if = "Option::is_none")]
    billing_tel: Option<Secret<String>>,
    #[serde(rename = "payment_option")]
    payment_option: String,
    #[serde(rename = "card_type", skip_serializing_if = "Option::is_none")]
    card_type: Option<String>,
    // UPI specific fields
    #[serde(rename = "upi_va", skip_serializing_if = "Option::is_none")]
    upi_va: Option<Secret<String>>,
    // Merchant parameters for metadata
    #[serde(rename = "merchant_param1", skip_serializing_if = "Option::is_none")]
    merchant_param1: Option<String>,
    #[serde(rename = "merchant_param2", skip_serializing_if = "Option::is_none")]
    merchant_param2: Option<String>,
    #[serde(rename = "merchant_param3", skip_serializing_if = "Option::is_none")]
    merchant_param3: Option<String>,
    #[serde(rename = "merchant_param4", skip_serializing_if = "Option::is_none")]
    merchant_param4: Option<Secret<String>>,
    #[serde(rename = "merchant_param5", skip_serializing_if = "Option::is_none")]
    merchant_param5: Option<String>,
}

// ===== SYNC REQUEST STRUCTURES =====

#[derive(Debug, Serialize)]
pub struct CcavenueV2SyncRequest {
    #[serde(rename = "enc_request")]
    pub enc_request: Secret<String>,
    #[serde(rename = "access_code")]
    pub access_code: Secret<String>,
    #[serde(rename = "request_type")]
    pub request_type: String,
    #[serde(rename = "response_type")]
    pub response_type: String,
    #[serde(rename = "command")]
    pub command: String,
    #[serde(rename = "version", skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Serialize)]
struct CcavenueV2SyncRequestPayload {
    #[serde(rename = "order_no")]
    order_no: String,
}

// ===== RESPONSE STRUCTURES =====

#[derive(Debug, Deserialize, Serialize)]
pub struct CcavenueV2ErrorResponse {
    pub status: String,
    #[serde(rename = "enc_response", skip_serializing_if = "Option::is_none")]
    pub enc_response: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CcavenueV2PaymentsResponse {
    #[serde(rename = "encResp")]
    pub enc_resp: String,
    #[serde(rename = "order_id", skip_serializing_if = "Option::is_none")]
    pub order_id: Option<String>,
    #[serde(rename = "crossSellUrl", skip_serializing_if = "Option::is_none")]
    pub cross_sell_url: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CcavenueV2SyncResponse {
    pub status: String,
    pub code: i32,
    pub response: String,
}

// ===== ENCRYPTION/DECRYPTION UTILITIES =====

fn encrypt_ccavenue_request(
    data: &str,
    _working_key: &Secret<String>,
) -> Result<String, Error> {
    // Use a simple hex encoding for now - replace with proper AES encryption
    let data_bytes = data.as_bytes();
    Ok(hex::encode(data_bytes))
}

fn decrypt_ccavenue_response(
    encrypted_data: &str,
    _working_key: &Secret<String>,
) -> Result<String, Error> {
    // Use a simple hex decoding for now - replace with proper AES decryption
    let decoded_bytes = hex::decode(encrypted_data)
        .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
    
    String::from_utf8(decoded_bytes)
        .change_context(errors::ConnectorError::ResponseDeserializationFailed)
}

fn parse_ccavenue_response(response_str: &str) -> HashMap<String, String> {
    response_str
        .split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            match (parts.next(), parts.next()) {
                (Some(key), Some(value)) => {
                    // Simple URL decode - replace with proper URL decoding
                    Some((key.to_string(), value.replace("%20", " ")))
                }
                _ => None,
            }
        })
        .collect()
}

// ===== TRANSFORMERS =====

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<CcavenueV2RouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for CcavenueV2PaymentsRequest
{
    type Error = Error;
    fn try_from(
        item: CcavenueV2RouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = CcavenueV2AuthType::try_from(&router_data.connector_auth_type)?;
        
        // Determine payment option based on payment method
        let payment_option = match &router_data.request.payment_method_data {
            PaymentMethodData::Upi(_) => "UPI",
            _ => return Err(errors::ConnectorError::NotSupported {
                message: "Payment method not supported".to_string(),
                connector: "ccavenuev2",
            }.into()),
        };

        // Extract UPI VPA if available
        let upi_va = match &router_data.request.payment_method_data {
            PaymentMethodData::Upi(UpiData::UpiCollect(upi_collect)) => {
                upi_collect.vpa_id.as_ref().map(|vpa| Secret::new(vpa.peek().to_string()))
            }
            _ => None,
        };

        let amount = MinorUnit(router_data.request.amount);

        let payload = CcavenueV2PaymentRequestPayload {
            merchant_id: auth.merchant_id.clone(),
            order_id: router_data.request.related_transaction_id.clone().unwrap_or_default(),
            amount: amount.to_string(),
            currency: router_data.request.currency.to_string(),
            redirect_url: router_data.request.router_return_url.clone().unwrap_or_default(),
            cancel_url: router_data.request.router_return_url.clone().unwrap_or_default(),
            language: "EN".to_string(),
            billing_name: router_data.request.customer_name.clone().map(Secret::new),
            billing_email: router_data.request.email.clone(), // Use Email type directly
            billing_tel: None, // No phone field available in PaymentsAuthorizeData
            payment_option: payment_option.to_string(),
            card_type: None,
            upi_va,
            merchant_param1: None,
            merchant_param2: None,
            merchant_param3: None,
            merchant_param4: None,
            merchant_param5: None,
        };

        let payload_string = serde_urlencoded::to_string(&payload)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let enc_request = encrypt_ccavenue_request(&payload_string, &auth.working_key)?;

        Ok(Self {
            enc_request: Secret::new(enc_request),
            access_code: auth.access_code,
            command: Some("initiateTransaction".to_string()),
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<CcavenueV2RouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for CcavenueV2SyncRequest
{
    type Error = Error;
    fn try_from(
        item: CcavenueV2RouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let auth = CcavenueV2AuthType::try_from(&router_data.connector_auth_type)?;
        
        let connector_transaction_id = router_data
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;

        let payload = CcavenueV2SyncRequestPayload {
            order_no: connector_transaction_id,
        };

        let payload_string = serde_urlencoded::to_string(&payload)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let enc_request = encrypt_ccavenue_request(&payload_string, &auth.working_key)?;

        Ok(Self {
            enc_request: Secret::new(enc_request),
            access_code: auth.access_code,
            request_type: "JSON".to_string(),
            response_type: "JSON".to_string(),
            command: "orderStatusTracker".to_string(),
            version: Some("1.2".to_string()),
        })
    }
}

// Response transformers
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<
        ResponseRouterData<
            CcavenueV2PaymentsResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = Error;
    fn try_from(
        item: ResponseRouterData<
            CcavenueV2PaymentsResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let response = item.response;
        
        let auth = CcavenueV2AuthType::try_from(&router_data.connector_auth_type)?;
        
        // Decrypt the response
        let decrypted_response = decrypt_ccavenue_response(&response.enc_resp, &auth.working_key)?;
        let response_map = parse_ccavenue_response(&decrypted_response);
        
        let status = response_map.get("order_status").unwrap_or(&"Unknown".to_string()).clone();
        let connector_transaction_id = response_map.get("order_id").cloned();
        let connector_response_reference_id = response_map.get("tracking_id").cloned();
        
        let (attempt_status, error_message) = match status.as_str() {
            "Success" => (AttemptStatus::Charged, None),
            "Aborted" | "Cancelled" => (AttemptStatus::Failure, response_map.get("failure_message").cloned()),
            "Unsuccessful" | "Invalid" => (AttemptStatus::Failure, response_map.get("failure_message").cloned()),
            "Incomplete" | "Shipped" => (AttemptStatus::Pending, None),
            _ => (AttemptStatus::Pending, None),
        };

        let response_result = if let Some(error_msg) = error_message {
            Err(ErrorResponse {
                code: "PAYMENT_FAILED".to_string(),
                message: error_msg.clone(),
                reason: Some(error_msg),
                status_code: item.http_code,
                attempt_status: Some(attempt_status),
                connector_transaction_id,
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            })
        } else {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    connector_transaction_id.unwrap_or_default(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: connector_response_reference_id,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: 200,
            })
        };

        Ok(Self {
            response: response_result,
            ..router_data
        })
    }
}

// Remove the generic type parameter from PSync response transformer
impl
    TryFrom<
        ResponseRouterData<
            CcavenueV2SyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = Error;
    fn try_from(
        item: ResponseRouterData<
            CcavenueV2SyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let response = item.response;
        
        let auth = CcavenueV2AuthType::try_from(&router_data.connector_auth_type)?;
        
        // Decrypt the response
        let decrypted_response = decrypt_ccavenue_response(&response.response, &auth.working_key)?;
        let response_map = parse_ccavenue_response(&decrypted_response);
        
        let status = response_map.get("order_status").unwrap_or(&"Unknown".to_string()).clone();
        let connector_transaction_id = response_map.get("order_id").cloned();
        let connector_response_reference_id = response_map.get("tracking_id").cloned();
        
        let (attempt_status, error_message) = match status.as_str() {
            "Success" => (AttemptStatus::Charged, None),
            "Aborted" | "Cancelled" => (AttemptStatus::Failure, response_map.get("failure_message").cloned()),
            "Unsuccessful" | "Invalid" => (AttemptStatus::Failure, response_map.get("failure_message").cloned()),
            "Incomplete" | "Shipped" => (AttemptStatus::Pending, None),
            _ => (AttemptStatus::Pending, None),
        };

        let response_result = if let Some(error_msg) = error_message {
            Err(ErrorResponse {
                code: "PAYMENT_FAILED".to_string(),
                message: error_msg.clone(),
                reason: Some(error_msg),
                status_code: item.http_code,
                attempt_status: Some(attempt_status),
                connector_transaction_id,
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            })
        } else {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    connector_transaction_id.unwrap_or_default(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: connector_response_reference_id,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: 200,
            })
        };

        Ok(Self {
            response: response_result,
            ..router_data
        })
    }
}

// ===== ERROR HANDLING =====

pub fn get_ccavenue_error_status(status: &str) -> Option<AttemptStatus> {
    match status {
        "Success" => Some(AttemptStatus::Charged),
        "Aborted" | "Cancelled" | "Unsuccessful" | "Invalid" => Some(AttemptStatus::Failure),
        "Incomplete" | "Shipped" => Some(AttemptStatus::Pending),
        _ => None,
    }
}