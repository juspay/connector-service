use common_utils::{
    errors::CustomResult, request::Method,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsSyncData, PaymentsResponseData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::{PaymentMethodDataTypes, DefaultPCIHolder},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use hyperswitch_masking::{ExposeInterface, Secret};
use chrono;
use serde::{Deserialize, Serialize};

use crate::types::ResponseRouterData;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAuth {
    pub merchant_code: Option<Secret<String>>,
    pub merchant_key: Option<Secret<String>>,
    pub salt_key: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for TpslAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1, api_secret: _ } => Ok(Self {
                merchant_code: Some(api_key.clone()),
                merchant_key: Some(key1.clone()),
                salt_key: None,
            }),
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                merchant_code: Some(api_key.clone()),
                merchant_key: Some(key1.clone()),
                salt_key: None,
            }),
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                merchant_code: Some(api_key.clone()),
                merchant_key: None,
                salt_key: None,
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslMerchantPayload {
    pub identifier: String,
    pub description: String,
    pub response_endpoint_url: String,
    pub webhook_endpoint_url: String,
    pub webhook_type: String,
    pub response_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslConsumerPayload {
    pub identifier: String,
    pub email_id: String,
    pub mobile_number: String,
    pub account_no: String,
    pub account_type: String,
    pub account_holder_name: String,
    pub aadhar_no: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslTxnPayload {
    pub identifier: String,
    pub amount: String,
    pub currency: String,
    pub request_type: String,
    pub transaction_type: String,
    pub description: String,
    pub date_time: String,
    pub device_identifier: String,
    pub token: Option<String>,
    pub security_token: Option<String>,
    pub is_registration: String,
    pub forced_3ds_call: String,
    pub sms_sending: String,
    pub merchant_initiated: String,
    pub tenure_id: Option<String>,
    pub sub_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslMethodPayload {
    pub token: String,
    pub r#type: String,
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslInstrumentPayload {
    pub identifier: String,
    pub token: Option<String>,
    pub alias: Option<String>,
    pub r#type: String,
    pub action: String,
    pub provider: String,
    pub processor: Option<String>,
    pub issuer: Option<String>,
    pub acquirer: Option<String>,
    pub sub_type: Option<String>,
    pub authentication: Option<TpslAuthenticationPayload>,
    pub i_ban: Option<String>,
    pub i_fsc: Option<String>,
    pub b_i_c: Option<String>,
    pub m_i_c_r: Option<String>,
    pub verification_code: Option<String>,
    pub issuance: Option<TpslExpiryPayload>,
    pub expiry: Option<TpslExpiryPayload>,
    pub holder: Option<TpslHolderPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAuthenticationPayload {
    pub token: Option<String>,
    pub r#type: Option<String>,
    pub sub_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslExpiryPayload {
    pub year: Option<String>,
    pub month: Option<String>,
    pub date_time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslHolderPayload {
    pub name: String,
    pub address: Option<TpslAddressPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAddressPayload {
    pub street: String,
    pub city: String,
    pub state: String,
    pub country: String,
    pub zip_code: String,
    pub county: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslInstructionPayload {
    pub identifier: String,
    pub reference: String,
    pub r#type: String,
    pub description: String,
    pub action: String,
    pub amount: String,
    pub frequency: Option<String>,
    pub occurrence: Option<String>,
    pub start_date_time: Option<String>,
    pub end_date_time: Option<String>,
    pub validity: Option<String>,
    pub limit: Option<String>,
    pub debit_day: Option<String>,
    pub debit_flag: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentPayload {
    pub method: TpslMethodPayload,
    pub instrument: TpslInstrumentPayload,
    pub instruction: Option<TpslInstructionPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslItemPayload {
    pub identifier: String,
    pub reference: String,
    pub s_k_u: String,
    pub description: String,
    pub amount: String,
    pub com_amt: String,
    pub provider_identifier: String,
    pub surcharge_or_discount_amount: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslCartPayload {
    pub identifier: String,
    pub reference: String,
    pub description: String,
    pub item: Vec<TpslItemPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsRequest {
    pub merchant: TpslMerchantPayload,
    pub consumer: TpslConsumerPayload,
    pub transaction: TpslTxnPayload,
    pub payment: TpslPaymentPayload,
    pub cart: TpslCartPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslMerchantDataType {
    pub identifier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslConsumerDataType {
    pub identifier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentUPISyncType {
    pub instruction: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslTransactionUPITxnType {
    pub device_identifier: String,
    pub r#type: Option<String>,
    pub sub_type: Option<String>,
    pub amount: String,
    pub currency: String,
    pub date_time: String,
    pub request_type: String,
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsSyncRequest {
    pub merchant: TpslMerchantDataType,
    pub payment: TpslPaymentUPISyncType,
    pub transaction: TpslTransactionUPITxnType,
    pub consumer: TpslConsumerDataType,
}

// Response types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsResponse {
    pub code: i32,
    pub status: String,
    pub response: TpslResponseData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum TpslResponseData {
    TpslUPISuccessTxnResponse(TpslUPITxnResponse),
    TpslAuthS2sResponse(TpslAuthResponse),
    TpslDecryptedResponse(TpslDecryptedResponse),
    TpslUPISyncResponse(TpslUPISyncResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPITxnResponse {
    pub merchant_code: String,
    pub merchant_transaction_identifier: String,
    pub merchant_transaction_request_type: String,
    pub response_type: String,
    pub transaction_state: String,
    pub merchant_additional_details: Option<serde_json::Value>,
    pub payment_method: TpslUPIPaymentPayload,
    pub error: Option<serde_json::Value>,
    pub merchant_response_string: Option<serde_json::Value>,
    pub pdf_download_url: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAuthResponse {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslDecryptedResponse {
    pub merchant_code: String,
    pub merchant_transaction_identifier: Option<String>,
    pub merchant_transaction_request_type: String,
    pub response_type: String,
    pub transaction_state: String,
    pub merchant_additional_details: Option<String>,
    pub payment_method: TpslPaymentMethodPayload,
    pub error: Option<serde_json::Value>,
    pub identifier: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentMethodPayload {
    pub token: String,
    pub instrument_alias_name: Option<String>,
    pub instrument_token: Option<serde_json::Value>,
    pub bank_selection_code: String,
    pub a_c_s: Option<TpslAcsPayload>,
    pub o_t_p: Option<serde_json::Value>,
    pub payment_transaction: TpslPaymentTransactionPayload,
    pub authentication: Option<serde_json::Value>,
    pub error: TpslPaymentMethodErrorPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAcsPayload {
    pub bank_acs_form_name: String,
    pub bank_acs_http_method: serde_json::Value,
    pub bank_acs_params: Option<serde_json::Value>,
    pub bank_acs_url: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentTransactionPayload {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentMethodErrorPayload {
    pub code: String,
    pub desc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPIPaymentPayload {
    pub token: Option<String>,
    pub instrument_alias_name: String,
    pub instrument_token: String,
    pub bank_selection_code: String,
    pub a_c_s: TpslAcsPayload,
    pub o_t_p: Option<serde_json::Value>,
    pub payment_transaction: TpslPaymentTxnPayload,
    pub authentication: Option<serde_json::Value>,
    pub error: TpslPaymentMethodErrorPayload,
    pub payment_mode: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentTxnPayload {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPISyncResponse {
    pub merchant_code: String,
    pub merchant_transaction_identifier: String,
    pub merchant_transaction_request_type: String,
    pub response_type: String,
    pub transaction_state: String,
    pub payment_method: TpslUPIPaymentPayload,
    pub error: Option<serde_json::Value>,
    pub merchant_response_string: Option<serde_json::Value>,
    pub status_code: Option<String>,
    pub status_message: Option<String>,
    pub identifier: Option<String>,
    pub bank_reference_identifier: Option<String>,
    pub merchant_additional_details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslErrorResponse {
    pub error_code: String,
    pub error_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TpslPaymentsSyncResponse {
    Success(TpslUPISyncResponse),
    Error(TpslErrorResponse),
}

// CORRECT: Use proper types for TryFrom implementations expected by macro framework
impl<T: PaymentMethodDataTypes> TryFrom<crate::connectors::tpsl::TPSLRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for TpslPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: crate::connectors::tpsl::TPSLRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = TpslAuth::try_from(&item.router_data.connector_auth_type)?;
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let return_url = item.router_data.request.get_router_return_url()?;
        
        // CORRECT: Use proper amount framework
        let amount = item.amount.get_amount_as_string();

        let merchant_code = auth.merchant_code
            .ok_or(errors::ConnectorError::FailedToObtainAuthType)?
            .expose()
            .clone();

        let merchant = TpslMerchantPayload {
            identifier: merchant_code.clone(),
            description: "Payment Transaction".to_string(),
            response_endpoint_url: return_url.clone(),
            webhook_endpoint_url: return_url.clone(),
            webhook_type: "HTTP_POST".to_string(),
            response_type: "URL".to_string(),
        };

        let consumer = TpslConsumerPayload {
            identifier: customer_id.get_string_repr().to_string(),
            email_id: item.router_data.request.email
                .clone()
                .map(|e| e.expose().expose().to_string())
                .unwrap_or_else(|| format!("{}@example.com", customer_id.get_string_repr())),
            mobile_number: "9999999999".to_string(),
            account_no: customer_id.get_string_repr().to_string(),
            account_type: "SAVINGS".to_string(),
            account_holder_name: item.router_data.request.customer_name
                .clone()
                .unwrap_or_else(|| "Customer".to_string()),
            aadhar_no: None,
        };

        let transaction = TpslTxnPayload {
            identifier: item.router_data.resource_common_data.connector_request_reference_id.clone(),
            amount: amount.to_string(),
            currency: item.router_data.request.currency.to_string(),
            request_type: "SALE".to_string(),
            transaction_type: "SALE".to_string(),
            description: "UPI Payment".to_string(),
            date_time: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            device_identifier: item.router_data.request.get_ip_address_as_optional()
                .map(|ip| ip.expose())
                .unwrap_or_else(|| "127.0.0.1".to_string()),
            token: None,
            security_token: None,
            is_registration: "N".to_string(),
            forced_3ds_call: "N".to_string(),
            sms_sending: "Y".to_string(),
            merchant_initiated: "N".to_string(),
            tenure_id: None,
            sub_type: Some("UPI".to_string()),
        };

        let method = TpslMethodPayload {
            token: "UPI".to_string(),
            r#type: "UPI".to_string(),
            code: "UPI".to_string(),
        };

        let instrument = TpslInstrumentPayload {
            identifier: "UPI".to_string(),
            token: None,
            alias: None,
            r#type: "UPI".to_string(),
            action: "SALE".to_string(),
            provider: "UPI".to_string(),
            processor: None,
            issuer: None,
            acquirer: None,
            sub_type: Some("UPI".to_string()),
            authentication: None,
            i_ban: None,
            i_fsc: None,
            b_i_c: None,
            m_i_c_r: None,
            verification_code: None,
            issuance: None,
            expiry: None,
            holder: None,
        };

        let payment = TpslPaymentPayload {
            method,
            instrument,
            instruction: None,
        };

        let cart = TpslCartPayload {
            identifier: format!("CART_{}", customer_id.get_string_repr()),
            reference: item.router_data.resource_common_data.connector_request_reference_id.clone(),
            description: "UPI Payment Cart".to_string(),
            item: vec![TpslItemPayload {
                identifier: "ITEM_1".to_string(),
                reference: item.router_data.resource_common_data.connector_request_reference_id.clone(),
                s_k_u: "UPI_ITEM".to_string(),
                description: "UPI Payment Item".to_string(),
                amount: amount.to_string(),
                com_amt: "0".to_string(),
                provider_identifier: "UPI".to_string(),
                surcharge_or_discount_amount: "0".to_string(),
            }],
        };

        Ok(Self {
            merchant,
            consumer,
            transaction,
            payment,
            cart,
        })
    }
}

impl TryFrom<crate::connectors::tpsl::TPSLRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, DefaultPCIHolder>>
    for TpslPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: crate::connectors::tpsl::TPSLRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, DefaultPCIHolder>,
    ) -> Result<Self, Self::Error> {
        let auth = TpslAuth::try_from(&item.router_data.connector_auth_type)?;
        let merchant_code = auth.merchant_code
            .ok_or(errors::ConnectorError::FailedToObtainAuthType)?
            .expose()
            .clone();

        let merchant = TpslMerchantDataType {
            identifier: merchant_code,
        };

        let consumer = TpslConsumerDataType {
            identifier: item.router_data.resource_common_data.get_customer_id()?.get_string_repr().to_string(),
        };

        let payment = TpslPaymentUPISyncType {
            instruction: None,
        };

        let transaction = TpslTransactionUPITxnType {
            device_identifier: "127.0.0.1".to_string(),
            r#type: Some("UPI".to_string()),
            sub_type: Some("UPI".to_string()),
            amount: item.amount.get_amount_as_string(),
            currency: item.router_data.request.currency.to_string(),
            date_time: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            request_type: "STATUS".to_string(),
            token: item.router_data.request.connector_transaction_id
                .get_connector_transaction_id()
                .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?
                .to_string(),
        };

        Ok(Self {
            merchant,
            payment,
            transaction,
            consumer,
        })
    }
}

impl<F> TryFrom<ResponseRouterData<TpslPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<()>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TpslPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response_data) = match response.response {
            TpslResponseData::TpslUPISuccessTxnResponse(upi_response) => {
                let merchant_transaction_identifier = upi_response.merchant_transaction_identifier.clone();
                let network_txn_id = upi_response.payment_method.payment_transaction.identifier.clone().unwrap_or_default();
                let redirection_data = get_redirect_form_data(upi_response)?;
                (
                    common_enums::AttemptStatus::AuthenticationPending,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            router_data
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                        ),
                        redirection_data: Some(Box::new(redirection_data)),
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: Some(network_txn_id),
                        connector_response_reference_id: Some(merchant_transaction_identifier),
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            TpslResponseData::TpslAuthS2sResponse(_) => {
                (
                    common_enums::AttemptStatus::AuthenticationPending,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            router_data
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            TpslResponseData::TpslDecryptedResponse(decrypted_response) => {
                let status = match decrypted_response.transaction_state.as_str() {
                    "SUCCESS" => common_enums::AttemptStatus::Charged,
                    "PENDING" => common_enums::AttemptStatus::Pending,
                    "FAILURE" => common_enums::AttemptStatus::Failure,
                    _ => common_enums::AttemptStatus::Pending,
                };

                (
                    status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            router_data
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: decrypted_response.payment_method.payment_transaction.identifier,
                        connector_response_reference_id: decrypted_response.merchant_transaction_identifier,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            _ => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: "TPSL_ERROR".to_string(),
                    status_code: http_code,
                    message: "Unknown response type".to_string(),
                    reason: Some("Unknown response type".to_string()),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: response_data,
            ..router_data
        })
    }
}

impl<F> TryFrom<ResponseRouterData<TpslPaymentsSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TpslPaymentsSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response_data) = match response {
            TpslPaymentsSyncResponse::Success(sync_response) => {
                let status = match sync_response.transaction_state.as_str() {
                    "SUCCESS" => common_enums::AttemptStatus::Charged,
                    "PENDING" => common_enums::AttemptStatus::Pending,
                    "FAILURE" => common_enums::AttemptStatus::Failure,
                    "PROCESSING" => common_enums::AttemptStatus::Authorizing,
                    _ => common_enums::AttemptStatus::Pending,
                };

                (
                    status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            router_data
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: sync_response.payment_method.payment_transaction.identifier,
                        connector_response_reference_id: Some(sync_response.merchant_transaction_identifier),
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            TpslPaymentsSyncResponse::Error(error_response) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_response.error_code,
                    status_code: http_code,
                    message: error_response.error_message.clone(),
                    reason: Some(error_response.error_message),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: response_data,
            ..router_data
        })
    }
}

fn get_redirect_form_data(
    upi_response: TpslUPITxnResponse,
) -> CustomResult<RedirectForm, errors::ConnectorError> {
    // For UPI payments, typically we return a redirect to the UPI app or a payment URL
    // This would be extracted from the payment_method or merchant_additional_details
    let redirect_url = upi_response.merchant_additional_details
        .and_then(|details| {
            if let Ok(url_str) = serde_json::from_value::<String>(details) {
                Some(url_str)
            } else {
                None
            }
        })
        .unwrap_or_else(|| "https://upi.app/pay".to_string());

    Ok(RedirectForm::Form {
        endpoint: redirect_url,
        method: Method::Get,
        form_fields: std::collections::HashMap::new(),
    })
}