use std::collections::HashMap;

use common_utils::{
    errors::CustomResult, ext_traits::ValueExt, request::Method, types::StringMinorUnit,
    Email,
};
use common_enums;
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};
use chrono;

use crate::types::ResponseRouterData;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAuth {
    pub merchant_code: Option<Secret<String>>,
    pub api_key: Option<Secret<String>>,
    pub secret_key: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for TpslAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, .. } => {
                let auth_data: Self = api_key
                    .to_owned()
                    .parse_value("TpslAuth")
                    .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
                Ok(auth_data)
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslMerchantPayload {
    pub identifier: String,
    pub description: String,
    pub webhook_endpoint_url: String,
    pub response_type: String,
    pub response_endpoint_url: String,
    pub webhook_type: String,
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
    pub date_time: String,
    pub description: String,
    pub request_type: String,
    pub token: Option<String>,
    pub security_token: Option<String>,
    pub device_identifier: String,
    pub sms_sending: String,
    pub forced_3ds_call: String,
    pub r#type: String,
    pub is_registration: String,
    pub sub_type: String,
    pub merchant_initiated: String,
    pub tenure_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentPayload {
    pub method: TpslMethodPayload,
    pub instrument: TpslInstrumentPayload,
    pub instruction: TpslInstructionPayload,
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
    pub processor: String,
    pub issuer: String,
    pub acquirer: String,
    pub sub_type: String,
    pub i_fsc: Option<String>,
    pub b_ic: Option<String>,
    pub m_icr: Option<String>,
    pub i_ban: Option<String>,
    pub verification_code: Option<String>,
    pub authentication: Option<TpslAuthenticationPayload>,
    pub holder: Option<TpslHolderPayload>,
    pub expiry: Option<TpslExpiryPayload>,
    pub issuance: Option<TpslExpiryPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslInstructionPayload {
    pub identifier: String,
    pub reference: String,
    pub amount: String,
    pub currency: String,
    pub description: String,
    pub action: String,
    pub r#type: String,
    pub occurrence: String,
    pub frequency: String,
    pub limit: String,
    pub start_date_time: String,
    pub end_date_time: String,
    pub validity: String,
    pub debit_day: String,
    pub debit_flag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAuthenticationPayload {
    pub token: String,
    pub r#type: String,
    pub sub_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslHolderPayload {
    pub name: String,
    pub address: TpslAddressPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAddressPayload {
    pub street: String,
    pub city: String,
    pub state: String,
    pub country: String,
    pub zip_code: Secret<String>,
    pub county: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslExpiryPayload {
    pub month: String,
    pub year: String,
    pub date_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslCartPayload {
    pub identifier: String,
    pub description: String,
    pub reference: String,
    pub item: Vec<TpslItemPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslItemPayload {
    pub identifier: String,
    pub reference: String,
    pub description: String,
    pub amount: String,
    pub com_amt: String,
    pub s_k_u: String,
    pub provider_identifier: String,
    pub surcharge_or_discount_amount: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsRequest {
    pub merchant: TpslMerchantPayload,
    pub cart: TpslCartPayload,
    pub payment: TpslPaymentPayload,
    pub transaction: TpslTxnPayload,
    pub consumer: TpslConsumerPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsSyncRequest {
    pub merchant: TpslMerchantDataType,
    pub payment: TpslPaymentSyncDataType,
    pub transaction: TpslTransactionSyncDataType,
    pub consumer: TpslConsumerDataType,
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
pub struct TpslPaymentSyncDataType {
    pub instruction: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslTransactionSyncDataType {
    pub identifier: String,
    pub amount: String,
    pub currency: String,
    pub date_time: String,
    pub request_type: String,
    pub token: String,
    pub device_identifier: String,
    pub r#type: Option<String>,
    pub sub_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsResponse {
    pub code: i32,
    pub status: String,
    pub response: TpslResponseData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub enum TpslResponseData {
    AuthS2sResponse(TpslAuthResponse),
    AuthErrorOrDecryptedResponse(TpslDecryptedResponse),
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
pub struct TpslPaymentsSyncResponse {
    pub merchant_code: String,
    pub merchant_transaction_identifier: String,
    pub merchant_transaction_request_type: String,
    pub response_type: String,
    pub transaction_state: String,
    pub payment_method: TpslPaymentMethodPayload,
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

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for TpslPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = TpslAuth::try_from(&item.connector_auth_type)?;
        let merchant_code = auth.merchant_code
            .ok_or(errors::ConnectorError::FailedToObtainAuthType)?
            .expose();

        let customer_id = item.resource_common_data.get_customer_id()?;
        let return_url = item.request.get_router_return_url()?;
        let amount = item.request.minor_amount.to_string();
        let currency = item.request.currency.to_string();
        let transaction_id = item.resource_common_data.connector_request_reference_id.clone();
        let email = item.request.email.clone().map(|e| e.to_string()).unwrap_or_default();
        let phone = item.request.phone.clone().map(|p| p.to_string()).unwrap_or_default();

        let date_time = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        Ok(Self {
            merchant: TpslMerchantPayload {
                identifier: merchant_code,
                description: format!("Payment for transaction {}", transaction_id),
                webhook_endpoint_url: return_url.clone(),
                response_type: "S2S".to_string(),
                response_endpoint_url: return_url.clone(),
                webhook_type: "POST".to_string(),
            },
            cart: TpslCartPayload {
                identifier: format!("cart_{}", transaction_id),
                description: "Payment cart".to_string(),
                reference: transaction_id.clone(),
                item: vec![TpslItemPayload {
                    identifier: "item_1".to_string(),
                    reference: transaction_id.clone(),
                    description: "Payment item".to_string(),
                    amount: amount.clone(),
                    com_amt: "0".to_string(),
                    s_k_u: "SKU_001".to_string(),
                    provider_identifier: merchant_code.clone(),
                    surcharge_or_discount_amount: "0".to_string(),
                }],
            },
            payment: TpslPaymentPayload {
                method: TpslMethodPayload {
                    token: "UPI".to_string(),
                    r#type: "UPI".to_string(),
                    code: "UPI".to_string(),
                },
                instrument: TpslInstrumentPayload {
                    identifier: "UPI_INSTRUMENT".to_string(),
                    token: None,
                    alias: None,
                    r#type: "UPI".to_string(),
                    action: "PAY".to_string(),
                    provider: "UPI".to_string(),
                    processor: "UPI".to_string(),
                    issuer: "UPI".to_string(),
                    acquirer: "UPI".to_string(),
                    sub_type: "COLLECT".to_string(),
                    i_fsc: None,
                    b_ic: None,
                    m_icr: None,
                    i_ban: None,
                    verification_code: None,
                    authentication: Some(TpslAuthenticationPayload {
                        token: "UPI_AUTH".to_string(),
                        r#type: "UPI".to_string(),
                        sub_type: "COLLECT".to_string(),
                    }),
                    holder: None,
                    expiry: None,
                    issuance: None,
                },
                instruction: TpslInstructionPayload {
                    identifier: format!("instruction_{}", transaction_id),
                    reference: transaction_id.clone(),
                    amount: amount.clone(),
                    currency: currency.clone(),
                    description: "UPI payment instruction".to_string(),
                    action: "PAY".to_string(),
                    r#type: "PAYMENT".to_string(),
                    occurrence: "ONCE".to_string(),
                    frequency: "ONCE".to_string(),
                    limit: amount.clone(),
                    start_date_time: date_time.clone(),
                    end_date_time: date_time.clone(),
                    validity: "VALID".to_string(),
                    debit_day: "0".to_string(),
                    debit_flag: "N".to_string(),
                },
            },
            transaction: TpslTxnPayload {
                identifier: transaction_id.clone(),
                amount,
                currency,
                date_time: date_time.clone(),
                description: "UPI transaction".to_string(),
                request_type: "SALE".to_string(),
                token: None,
                security_token: None,
                device_identifier: item.request.get_ip_address_as_optional()
                    .map(|ip| ip.expose())
                    .unwrap_or_else(|| "127.0.0.1".to_string()),
                sms_sending: "Y".to_string(),
                forced_3ds_call: "N".to_string(),
                r#type: "SALE".to_string(),
                is_registration: "N".to_string(),
                sub_type: "UPI".to_string(),
                merchant_initiated: "N".to_string(),
                tenure_id: None,
            },
            consumer: TpslConsumerPayload {
                identifier: customer_id.to_string(),
                email_id: email,
                mobile_number: phone,
                account_no: customer_id.to_string(),
                account_type: "SAVINGS".to_string(),
                account_holder_name: customer_id.to_string(),
                aadhar_no: None,
            },
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for TpslPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = TpslAuth::try_from(&item.connector_auth_type)?;
        let merchant_code = auth.merchant_code
            .ok_or(errors::ConnectorError::FailedToObtainAuthType)?
            .expose();

        let transaction_id = item.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        let amount = item.request.minor_amount.to_string();
        let currency = item.request.currency.to_string();
        let date_time = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        Ok(Self {
            merchant: TpslMerchantDataType {
                identifier: merchant_code,
            },
            payment: TpslPaymentSyncDataType {
                instruction: None,
            },
            transaction: TpslTransactionSyncDataType {
                identifier: transaction_id,
                amount,
                currency,
                date_time,
                request_type: "VERIFY".to_string(),
                token: "SYNC_TOKEN".to_string(),
                device_identifier: item.request.get_ip_address_as_optional()
                    .map(|ip| ip.expose())
                    .unwrap_or_else(|| "127.0.0.1".to_string()),
                r#type: Some("VERIFY".to_string()),
                sub_type: Some("UPI".to_string()),
            },
            consumer: TpslConsumerDataType {
                identifier: "CONSUMER_ID".to_string(),
            },
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<(TpslPaymentsResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, u16)>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: (TpslPaymentsResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, u16),
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response_data) = match response.response {
            TpslResponseData::AuthS2sResponse(auth_response) => {
                (
                    common_enums::AttemptStatus::AuthenticationPending,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            router_data
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                        ),
                        redirection_data: Some(Box::new(RedirectForm::Form {
                            endpoint: format!("https://www.tpsl-india.in/PaymentGateway/redirect?token={}", auth_response.token),
                            method: Method::Get,
                            form_fields: std::collections::HashMap::new(),
                        })),
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: Some(auth_response.token),
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            TpslResponseData::AuthErrorOrDecryptedResponse(decrypted_response) => {
                let attempt_status = match decrypted_response.transaction_state.as_str() {
                    "SUCCESS" => common_enums::AttemptStatus::Charged,
                    "FAILURE" => common_enums::AttemptStatus::Failure,
                    "PENDING" => common_enums::AttemptStatus::Pending,
                    _ => common_enums::AttemptStatus::AuthenticationPending,
                };

                (
                    attempt_status,
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
                        network_txn_id: decrypted_response.identifier,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
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

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<TpslPaymentsSyncResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
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

        let attempt_status = match response.transaction_state.as_str() {
            "SUCCESS" => common_enums::AttemptStatus::Charged,
            "FAILURE" => common_enums::AttemptStatus::Failure,
            "PENDING" => common_enums::AttemptStatus::Pending,
            "PROCESSING" => common_enums::AttemptStatus::Processing,
            _ => common_enums::AttemptStatus::AuthenticationPending,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status: attempt_status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    response.merchant_transaction_identifier,
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: response.identifier,
                connector_response_reference_id: response.bank_reference_identifier,
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TpslErrorResponseWrapper {
    ErrorResponse(TpslErrorResponse),
    GenericError(serde_json::Value),
}

impl From<TpslErrorResponseWrapper> for ErrorResponse {
    fn from(error: TpslErrorResponseWrapper) -> Self {
        match error {
            TpslErrorResponseWrapper::ErrorResponse(err) => Self {
                status_code: 400,
                code: err.error_code,
                message: err.error_message.clone(),
                reason: Some(err.error_message),
                attempt_status: None,
                connector_transaction_id: None,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            },
            TpslErrorResponseWrapper::GenericError(err) => Self {
                status_code: 400,
                code: "GENERIC_ERROR".to_string(),
                message: format!("{:?}", err),
                reason: Some(format!("{:?}", err)),
                attempt_status: None,
                connector_transaction_id: None,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            },
        }
    }
}