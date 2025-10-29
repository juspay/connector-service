use std::collections::HashMap;

use common_utils::{
    errors::CustomResult, ext_traits::ValueExt, id_type, request::Method, types::StringMinorUnit,
    Email,
};
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

use crate::{connectors::tpsl::TPSLRouterData, types::ResponseRouterData};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAuth {
    pub merchant_code: Option<Secret<String>>,
    pub merchant_key: Option<Secret<String>>,
    pub checksum_key: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for TpslAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1 } => Ok(Self {
                merchant_code: Some(Secret::new(api_key.clone())),
                merchant_key: key1.clone().map(Secret::new),
                checksum_key: None,
            }),
            ConnectorAuthType::MultiAccountKey { api_key, key1, key2 } => Ok(Self {
                merchant_code: Some(Secret::new(api_key.clone())),
                merchant_key: key1.clone().map(Secret::new),
                checksum_key: key2.clone().map(Secret::new),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsRequest {
    pub merchant: TpslMerchantPayload,
    pub cart: TpslCartPayload,
    pub payment: TpslPaymentPayload,
    pub transaction: TpslTransactionPayload,
    pub consumer: TpslConsumerPayload,
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
pub struct TpslCartPayload {
    pub item: Vec<TpslItemPayload>,
    pub reference: String,
    pub identifier: String,
    pub description: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslItemPayload {
    pub description: String,
    pub provider_identifier: String,
    pub surcharge_or_discount_amount: String,
    pub amount: String,
    pub com_amt: String,
    pub s_k_u: String,
    pub reference: String,
    pub identifier: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentPayload {
    pub method: TpslMethodPayload,
    pub instrument: TpslInstrumentPayload,
    pub instruction: TpslInstructionPayload,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslMethodPayload {
    pub token: String,
    pub r#type: String,
    pub code: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslInstrumentPayload {
    pub identifier: String,
    pub token: Option<String>,
    pub alias: Option<String>,
    pub r#type: String,
    pub action: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslInstructionPayload {
    pub amount: String,
    pub currency: String,
    pub identifier: String,
    pub reference: String,
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
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslConsumerPayload {
    pub mobile_number: Option<String>,
    pub email_id: Option<Email>,
    pub identifier: String,
    pub account_no: Option<String>,
    pub account_type: Option<String>,
    pub account_holder_name: Option<String>,
    pub vpa: Option<String>,
    pub aadhar_no: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsSyncRequest {
    pub merchant: TpslMerchantDataType,
    pub payment: TpslPaymentSyncType,
    pub transaction: TpslTransactionSyncType,
    pub consumer: TpslConsumerDataType,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslMerchantDataType {
    pub identifier: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentSyncType {
    pub instruction: serde_json::Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslTransactionSyncType {
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

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
> TryFrom<TpslRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for TpslPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: TpslRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = TpslAuth::try_from(&item.router_data.connector_auth_type)?;
        let merchant_code = auth.merchant_code.ok_or(ConnectorError::FailedToObtainAuthType)?;
        
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let return_url = item.router_data.request.get_router_return_url()?;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let transaction_id = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        let currency = item.router_data.request.currency.to_string();
        let email = item.router_data.request.email.clone();
        let phone = item.router_data.request.phone.clone();

        // Extract VPA for UPI payments
        let vpa = item
            .router_data
            .request
            .payment_method_data
            .as_ref()
            .and_then(|pm| pm.get_upi())
            .and_then(|upi| upi.vpa.clone());

        match item.router_data.resource_common_data.payment_method {
            common_enums::PaymentMethod::Upi => Ok(Self {
                merchant: TpslMerchantPayload {
                    webhook_endpoint_url: return_url.clone(),
                    response_type: "URL".to_string(),
                    response_endpoint_url: return_url.clone(),
                    description: "UPI Payment".to_string(),
                    identifier: merchant_code.expose().clone(),
                    webhook_type: "HTTP_POST".to_string(),
                },
                cart: TpslCartPayload {
                    item: vec![TpslItemPayload {
                        description: "UPI Payment".to_string(),
                        provider_identifier: "UPI".to_string(),
                        surcharge_or_discount_amount: "0".to_string(),
                        amount: amount.clone(),
                        com_amt: "0".to_string(),
                        s_k_u: transaction_id.clone(),
                        reference: transaction_id.clone(),
                        identifier: transaction_id.clone(),
                    }],
                    reference: transaction_id.clone(),
                    identifier: transaction_id.clone(),
                    description: "UPI Payment".to_string(),
                },
                payment: TpslPaymentPayload {
                    method: TpslMethodPayload {
                        token: "UPI".to_string(),
                        r#type: "UPI".to_string(),
                        code: "UPI_INTENT".to_string(),
                    },
                    instrument: TpslInstrumentPayload {
                        identifier: vpa.unwrap_or_default(),
                        token: None,
                        alias: None,
                        r#type: "UPI".to_string(),
                        action: "PAY".to_string(),
                    },
                    instruction: TpslInstructionPayload {
                        amount: amount.clone(),
                        currency: currency.clone(),
                        identifier: transaction_id.clone(),
                        reference: transaction_id.clone(),
                    },
                },
                transaction: TpslTransactionPayload {
                    device_identifier: "WEB".to_string(),
                    sms_sending: "N".to_string(),
                    amount: amount.clone(),
                    forced3_d_s_call: "N".to_string(),
                    r#type: "SALE".to_string(),
                    description: "UPI Payment".to_string(),
                    currency: currency.clone(),
                    is_registration: "N".to_string(),
                    identifier: transaction_id.clone(),
                    date_time: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    token: transaction_id.clone(),
                    security_token: merchant_code.expose().clone(),
                    sub_type: "SALE".to_string(),
                    request_type: "SALE".to_string(),
                    reference: transaction_id.clone(),
                    merchant_initiated: "N".to_string(),
                },
                consumer: TpslConsumerPayload {
                    mobile_number: phone.map(|p| p.number.to_string()),
                    email_id: email,
                    identifier: customer_id.to_string(),
                    account_no: None,
                    account_type: None,
                    account_holder_name: None,
                    vpa,
                    aadhar_no: None,
                },
            }),
            _ => Err(errors::ConnectorError::NotImplemented("Payment method".to_string()).into()),
        }
    }
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
> TryFrom<TpslRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for TpslPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: TpslRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = TpslAuth::try_from(&item.router_data.connector_auth_type)?;
        let merchant_code = auth.merchant_code.ok_or(ConnectorError::FailedToObtainAuthType)?;
        
        let transaction_id = item
            .router_data
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| ConnectorError::RequestEncodingFailed)?;

        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let currency = item.router_data.request.currency.to_string();

        Ok(Self {
            merchant: TpslMerchantDataType {
                identifier: merchant_code.expose().clone(),
            },
            payment: TpslPaymentSyncType {
                instruction: serde_json::json!({}),
            },
            transaction: TpslTransactionSyncType {
                device_identifier: "WEB".to_string(),
                r#type: Some("SALE".to_string()),
                sub_type: Some("SALE".to_string()),
                amount,
                currency,
                date_time: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                request_type: "STATUS".to_string(),
                token: transaction_id,
            },
            consumer: TpslConsumerDataType {
                identifier: "SYNC".to_string(),
            },
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsResponse {
    pub code: i32,
    pub status: String,
    pub response: TpslResponseData,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TpslResponseData {
    Success(TpslSuccessResponse),
    Error(TpslErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslSuccessResponse {
    pub merchant_code: String,
    pub merchant_transaction_identifier: String,
    pub merchant_transaction_request_type: String,
    pub response_type: String,
    pub transaction_state: Option<String>,
    pub payment_method: TpslPaymentMethodResponse,
    pub error: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentMethodResponse {
    pub token: Option<String>,
    pub instrument_alias_name: String,
    pub instrument_token: String,
    pub bank_selection_code: String,
    pub a_c_s: Option<TpslAcsResponse>,
    pub o_t_p: Option<serde_json::Value>,
    pub payment_transaction: TpslPaymentTransactionResponse,
    pub authentication: Option<serde_json::Value>,
    pub error: TpslPaymentMethodError,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAcsResponse {
    pub bank_acs_form_name: String,
    pub bank_acs_http_method: serde_json::Value,
    pub bank_acs_params: Option<serde_json::Value>,
    pub bank_acs_url: serde_json::Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentTransactionResponse {
    pub amount: String,
    pub balance_amount: Option<String>,
    pub bank_reference_identifier: Option<String>,
    pub date_time: Option<String>,
    pub error_message: String,
    pub identifier: Option<String>,
    pub refund_identifier: String,
    pub status_code: String,
    pub status_message: String,
    pub instruction: Option<serde_json::Value>,
    pub reference: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentMethodError {
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
    pub payment_method: TpslPaymentMethodResponse,
    pub error: Option<serde_json::Value>,
    pub status_code: Option<String>,
    pub status_message: Option<String>,
    pub identifier: Option<String>,
    pub bank_reference_identifier: Option<String>,
}

impl From<TpslPaymentsResponse> for common_enums::AttemptStatus {
    fn from(response: TpslPaymentsResponse) -> Self {
        match response.status.to_uppercase().as_str() {
            "SUCCESS" | "COMPLETED" => Self::Charged,
            "PENDING" | "PROCESSING" => Self::AuthenticationPending,
            "FAILURE" | "FAILED" => Self::Failure,
            "INITIATED" => Self::Started,
            _ => Self::AuthenticationPending,
        }
    }
}

impl From<TpslPaymentsSyncResponse> for common_enums::AttemptStatus {
    fn from(response: TpslPaymentsSyncResponse) -> Self {
        match response.transaction_state.to_uppercase().as_str() {
            "SUCCESS" | "COMPLETED" => Self::Charged,
            "PENDING" | "PROCESSING" => Self::AuthenticationPending,
            "FAILURE" | "FAILED" => Self::Failure,
            "INITIATED" => Self::Started,
            _ => Self::AuthenticationPending,
        }
    }
}

impl<
    F,
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
> TryFrom<ResponseRouterData<TpslPaymentsResponse, F>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TpslPaymentsResponse, F>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response_data) = match response.response {
            TpslResponseData::Success(success_data) => {
                let status = common_enums::AttemptStatus::from(response.clone());
                
                // Check if we need to redirect for UPI
                let redirection_data = if let Some(acs) = success_data.payment_method.a_c_s {
                    if let Ok(acs_url) = serde_json::from_value::<String>(acs.bank_acs_url) {
                        Some(Box::new(RedirectForm::Form {
                            endpoint: acs_url,
                            method: Method::Post,
                            form_fields: HashMap::new(),
                        }))
                    } else {
                        None
                    }
                } else {
                    None
                };

                (
                    status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            success_data.merchant_transaction_identifier,
                        ),
                        redirection_data,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: success_data.payment_method.payment_transaction.bank_reference_identifier,
                        connector_response_reference_id: Some(success_data.payment_method.payment_transaction.reference),
                        incremental_authorization_allowed: None,
                        status_code: Some(http_code),
                    }),
                )
            }
            TpslResponseData::Error(error_data) => (
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

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
> TryFrom<ResponseRouterData<TpslPaymentsSyncResponse, PSync>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TpslPaymentsSyncResponse, PSync>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let status = common_enums::AttemptStatus::from(response.clone());
        let amount_received = response.payment_method.payment_transaction.amount.parse::<f64>()
            .ok()
            .map(|amt| common_utils::types::MinorUnit::from_major_unit_as_i64(amt));

        let response_data = Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(
                response.merchant_transaction_identifier,
            ),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: response.payment_method.payment_transaction.bank_reference_identifier,
            connector_response_reference_id: Some(response.payment_method.payment_transaction.reference),
            incremental_authorization_allowed: None,
            status_code: Some(http_code),
        });

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                amount_received,
                ..router_data.resource_common_data
            },
            response: response_data,
            ..router_data
        })
    }
}