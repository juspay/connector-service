use common_utils::{
    ext_traits::ValueExt, types::StringMinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use crate::types::ResponseRouterData;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPITxnRequest {
    pub merchant: TpslMerchantPayload,
    pub cart: TpslUPITokenCart,
    pub payment: TpslPaymentIntentPayload,
    pub transaction: TpslTransactionPayload,
    pub consumer: TpslConsumerIntentPayload,
    pub merchant_input_flags: TpslFlagsType,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslMerchantPayload {
    pub webhook_endpoint_url: String,
    pub response_type: String,
    pub response_endpoint_url: String,
    pub description: String,
    pub identifier: String,
    pub webhook_type: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPITokenCart {
    pub item: Vec<TpslUPIItem>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPIItem {
    pub amount: String,
    pub com_amt: String,
    pub s_k_u: String,
    pub reference: String,
    pub identifier: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentIntentPayload {
    pub method: TpslMethodUPIPayload,
    pub instrument: TpslUPIInstrumentPayload,
    pub instruction: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslMethodUPIPayload {
    pub token: String,
    pub r#type: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPIInstrumentPayload {
    pub expiry: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslTransactionPayload {
    pub device_identifier: String,
    pub sms_sending: String,
    pub amount: String,
    pub forced3_d_s_call: String,
    pub r#type: String,
    pub description: String,
    pub currency: String,
    pub is_registration: String,
    pub identifier: String,
    pub date_time: String,
    pub token: String,
    pub security_token: String,
    pub sub_type: String,
    pub request_type: String,
    pub reference: String,
    pub merchant_initiated: String,
    pub tenure_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslConsumerIntentPayload {
    pub mobile_number: String,
    pub email_i_d: String,
    pub identifier: String,
    pub account_no: String,
    pub account_type: String,
    pub account_holder_name: String,
    pub vpa: String,
    pub aadhar_no: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslFlagsType {
    pub account_no: bool,
    pub mobile_number: bool,
    pub email_i_d: bool,
    pub card_details: bool,
    pub mandate_details: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsSyncRequest {
    pub merchant: TpslMerchantDataType,
    pub payment: TpslPaymentUPISyncType,
    pub transaction: TpslTransactionUPITxnType,
    pub consumer: TpslConsumerDataType,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslMerchantDataType {
    pub identifier: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentUPISyncType {
    pub instruction: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslConsumerDataType {
    pub identifier: String,
}

// Response types
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TpslPaymentsResponse {
    Success(TpslUPITxnResponse),
    Error(TpslErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
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

#[derive(Debug, Deserialize, Serialize)]
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAcsPayload {
    pub bank_acs_form_name: String,
    pub bank_acs_http_method: serde_json::Value,
    pub bank_acs_params: Option<serde_json::Value>,
    pub bank_acs_url: serde_json::Value,
}

#[derive(Debug, Deserialize, Serialize)]
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentMethodErrorPayload {
    pub code: String,
    pub desc: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslErrorResponse {
    pub error_code: String,
    pub error_message: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsSyncResponse {
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
    pub merchant_additional_details: Option<serde_json::Value>,
}

// Auth types
#[derive(Default, Debug, Deserialize)]
pub struct TpslAuthType {
    pub merchant_code: Secret<String>,
    pub merchant_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for TpslAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1, api_secret: _ } => Ok(Self {
                merchant_code: api_key.clone(),
                merchant_key: key1.clone(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Request conversion implementations
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for TpslUPITxnRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = TpslAuthType::try_from(&item.connector_auth_type)?;
        let amount = "1000".to_string(); // Fixed amount for now - will be properly implemented later

        let return_url = item.request.get_router_return_url().unwrap_or_else(|_| "https://example.com".to_string());
        let customer_id = item.resource_common_data.get_customer_id().unwrap_or_else(|_| "customer_123".to_string());
        let email = item.request.email.clone();
        let mobile_number = item.request.phone.clone();

        Ok(Self {
            merchant: TpslMerchantPayload {
                webhook_endpoint_url: return_url.clone(),
                response_type: "URL".to_string(),
                response_endpoint_url: return_url.clone(),
                description: "UPI Payment".to_string(),
                identifier: auth.merchant_code.peek().to_string(),
                webhook_type: "HTTP".to_string(),
            },
            cart: TpslUPITokenCart {
                item: vec![TpslUPIItem {
                    amount: amount.clone(),
                    com_amt: "0".to_string(),
                    s_k_u: "UPI".to_string(),
                    reference: item
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                    identifier: "1".to_string(),
                }],
                description: Some("UPI Payment".to_string()),
            },
            payment: TpslPaymentIntentPayload {
                method: TpslMethodUPIPayload {
                    token: "UPI".to_string(),
                    r#type: "UPI".to_string(),
                },
                instrument: TpslUPIInstrumentPayload { expiry: None },
                instruction: None,
            },
            transaction: TpslTransactionPayload {
                device_identifier: "WEB".to_string(),
                sms_sending: "N".to_string(),
                amount,
                forced3_d_s_call: "N".to_string(),
                r#type: "SALE".to_string(),
                description: "UPI Payment".to_string(),
                currency: item.request.currency.to_string(),
                is_registration: "N".to_string(),
                identifier: item
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
                date_time: "2025-01-20 12:00:00".to_string(),
                token: auth.merchant_key.peek().to_string(),
                security_token: auth.merchant_key.peek().to_string(),
                sub_type: "SALE".to_string(),
                request_type: "TXN".to_string(),
                reference: item
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
                merchant_initiated: "N".to_string(),
                tenure_id: "".to_string(),
            },
            consumer: TpslConsumerIntentPayload {
                mobile_number: mobile_number
                    .map(|p| p.number().to_string())
                    .unwrap_or_else(|| "".to_string()),
                email_i_d: email.map(|e| e.to_string()).unwrap_or_else(|| "".to_string()),
                identifier: customer_id.get_string_repr(),
                account_no: "".to_string(),
                account_type: "".to_string(),
                account_holder_name: "".to_string(),
                vpa: "".to_string(), // Will be populated from payment method data
                aadhar_no: "".to_string(),
            },
            merchant_input_flags: TpslFlagsType {
                account_no: false,
                mobile_number: true,
                email_i_d: true,
                card_details: false,
                mandate_details: false,
            },
        })
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for TpslPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = TpslAuthType::try_from(&item.connector_auth_type)?;
        let amount = "1000".to_string(); // Fixed amount for now - will be properly implemented later

        Ok(Self {
            merchant: TpslMerchantDataType {
                identifier: auth.merchant_code.peek().to_string(),
            },
            payment: TpslPaymentUPISyncType { instruction: None },
            transaction: TpslTransactionUPITxnType {
                device_identifier: "WEB".to_string(),
                r#type: Some("SALE".to_string()),
                sub_type: Some("SALE".to_string()),
                amount,
                currency: item.request.currency.to_string(),
                date_time: "2025-01-20 12:00:00".to_string(),
                request_type: "STATUS".to_string(),
                token: auth.merchant_key.peek().to_string(),
            },
            consumer: TpslConsumerDataType {
                identifier: item
                    .resource_common_data
                    .get_customer_id()
                    .unwrap_or_else(|_| "customer_123".to_string()),
            },
        })
    }
}

// Response conversion implementations
impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<ResponseRouterData<TpslPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
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

        let (status, response) = match response {
            TpslPaymentsResponse::Error(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.error_code,
                    status_code: http_code,
                    message: error_data.error_message.clone(),
                    reason: Some(error_data.error_message),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            TpslPaymentsResponse::Success(response_data) => {
                let status = match response_data.transaction_state.as_str() {
                    "SUCCESS" | "SUCCESSFUL" => common_enums::AttemptStatus::Charged,
                    "PENDING" | "PROCESSING" => common_enums::AttemptStatus::AuthenticationPending,
                    "FAILED" => common_enums::AttemptStatus::Failure,
                    _ => common_enums::AttemptStatus::AuthenticationPending,
                };

                (
                    status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            response_data.merchant_transaction_identifier.clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: Some(serde_json::to_value(&response_data).unwrap_or_default()),
                        network_txn_id: response_data.payment_method.payment_transaction.identifier.clone(),
                        connector_response_reference_id: Some(
                            response_data.merchant_transaction_identifier.clone(),
                        ),
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
            response,
            ..router_data
        })
    }
}

impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<ResponseRouterData<TpslPaymentsSyncResponse, Self>>
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

        let status = match response.transaction_state.as_str() {
            "SUCCESS" | "SUCCESSFUL" => common_enums::AttemptStatus::Charged,
            "PENDING" | "PROCESSING" => common_enums::AttemptStatus::AuthenticationPending,
            "FAILED" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::AuthenticationPending,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    response.merchant_transaction_identifier.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: Some(serde_json::to_value(response).unwrap_or_default()),
                network_txn_id: response.payment_method.payment_transaction.identifier.clone(),
                connector_response_reference_id: Some(response.merchant_transaction_identifier),
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}