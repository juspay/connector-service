use common_utils::{
    errors::CustomResult, request::Method,
};
use hyperswitch_masking::PeekInterface;
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use crate::{connectors::tpsl::TPSLRouterData, types::ResponseRouterData};

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsRequest {
    pub merchant: TpslMerchantPayload,
    pub cart: TpslCartPayload,
    pub payment: TpslPaymentPayload,
    pub transaction: TpslTransactionPayload,
    pub consumer: TpslConsumerPayload,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TpslMerchantPayload {
    pub webhook_endpoint_url: String,
    pub response_type: String,
    pub response_endpoint_url: String,
    pub description: String,
    pub identifier: String,
    pub webhook_type: String,
}

#[derive(Debug, Serialize, Default)]
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

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentPayload {
    pub method: TpslMethodPayload,
    pub instrument: TpslInstrumentPayload,
    pub instruction: TpslInstructionPayload,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TpslMethodPayload {
    pub token: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub code: String,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TpslInstrumentPayload {
    pub expiry: Option<TpslExpiryPayload>,
    pub provider: String,
    pub i_f_s_c: Option<String>,
    pub holder: Option<TpslHolderPayload>,
    pub b_i_c: Option<String>,
    #[serde(rename = "type")]
    pub instrument_type: String,
    pub action: String,
    pub m_i_c_r: Option<String>,
    pub verification_code: Option<String>,
    pub i_b_a_n: Option<String>,
    pub processor: String,
    pub issuance: Option<TpslExpiryPayload>,
    pub alias: String,
    pub identifier: String,
    pub token: String,
    pub authentication: Option<TpslAuthenticationPayload>,
    pub sub_type: String,
    pub issuer: String,
    pub acquirer: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslExpiryPayload {
    pub year: String,
    pub month: String,
    pub date_time: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslHolderPayload {
    pub name: String,
    pub address: TpslAddressPayload,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAddressPayload {
    pub country: String,
    pub street: String,
    pub state: String,
    pub city: String,
    pub zip_code: Secret<String>,
    pub county: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAuthenticationPayload {
    pub token: String,
    #[serde(rename = "type")]
    pub auth_type: String,
    pub sub_type: String,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TpslInstructionPayload {
    pub occurrence: String,
    pub amount: String,
    pub frequency: String,
    #[serde(rename = "type")]
    pub instruction_type: String,
    pub description: String,
    pub action: String,
    pub limit: String,
    pub end_date_time: String,
    pub debit_day: String,
    pub debit_flag: String,
    pub identifier: String,
    pub reference: String,
    pub start_date_time: String,
    pub validity: String,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TpslTransactionPayload {
    pub device_identifier: String,
    pub sms_sending: String,
    pub amount: String,
    pub forced3_d_s_call: String,
    #[serde(rename = "type")]
    pub transaction_type: String,
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

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TpslConsumerPayload {
    pub mobile_number: String,
    pub email_i_d: String,
    pub identifier: String,
    pub account_no: String,
    pub account_type: String,
    pub account_holder_name: String,
    pub aadhar_no: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsSyncRequest {
    pub merchant: TpslMerchantDataType,
    pub payment: TpslPaymentDataType,
    pub transaction: TpslTransactionDataType,
    pub consumer: TpslConsumerDataType,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslMerchantDataType {
    pub identifier: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentDataType {
    pub instruction: TpslInstructionDataType,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslInstructionDataType {
    pub amount: Option<String>,
    pub end_date_time: Option<String>,
    pub identifier: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslTransactionDataType {
    pub device_identifier: String,
    #[serde(rename = "type")]
    pub transaction_type: String,
    pub currency: String,
    pub identifier: String,
    pub date_time: String,
    pub sub_type: String,
    pub request_type: String,
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
    Success(TpslAuthCaptureTxnResponse),
    Error(TpslErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAuthCaptureTxnResponse {
    pub code: i32,
    pub status: String,
    pub response: TpslAuthCaptureResponse,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TpslAuthCaptureResponse {
    AuthResponse(TpslAuthResponse),
    DecryptedResponse(TpslDecryptedResponse),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslAuthResponse(pub String);

#[derive(Debug, Deserialize, Serialize)]
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

#[derive(Debug, Deserialize, Serialize)]
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
    pub payment_method: TpslPaymentMethodPayload,
    pub error: Option<serde_json::Value>,
    pub merchant_response_string: Option<serde_json::Value>,
    pub status_code: Option<String>,
    pub status_message: Option<String>,
    pub identifier: Option<String>,
    pub bank_reference_identifier: Option<String>,
    pub merchant_additional_details: Option<String>,
}

// Authentication types
#[derive(Debug, Deserialize)]
pub struct TpslAuthType {
    pub merchant_code: Secret<String>,
    pub merchant_key: Secret<String>,
    pub merchant_salt: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for TpslAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, .. } => {
                let auth_data: TpslAuthType = serde_json::from_str(api_key.peek())
                    .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
                Ok(auth_data)
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

impl std::str::FromStr for TpslAuthType {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<TPSLRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for TpslPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: TPSLRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
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

        let auth_type = TpslAuthType::try_from(&item.router_data.connector_auth_type)?;

        Ok(Self {
            merchant: TpslMerchantPayload {
                webhook_endpoint_url: return_url.clone(),
                response_type: "URL".to_string(),
                response_endpoint_url: return_url.clone(),
                description: "Payment Transaction".to_string(),
                identifier: auth_type.merchant_code.peek().to_string(),
                webhook_type: "HTTP".to_string(),
            },
            cart: TpslCartPayload {
                item: vec![TpslItemPayload {
                    description: "Payment".to_string(),
                    provider_identifier: "UPI".to_string(),
                    surcharge_or_discount_amount: "0".to_string(),
                    amount: amount.to_string(),
                    com_amt: "0".to_string(),
                    s_k_u: "PAYMENT".to_string(),
                    reference: item.router_data.resource_common_data.connector_request_reference_id.clone(),
                    identifier: "PAYMENT_001".to_string(),
                }],
                reference: item.router_data.resource_common_data.connector_request_reference_id.clone(),
                identifier: "CART_001".to_string(),
                description: "Payment Cart".to_string(),
            },
            payment: TpslPaymentPayload {
                method: TpslMethodPayload {
                    token: "UPI".to_string(),
                    method_type: "UPI".to_string(),
                    code: "UPI".to_string(),
                },
                instrument: TpslInstrumentPayload {
                    expiry: None,
                    provider: "UPI".to_string(),
                    i_f_s_c: None,
                    holder: None,
                    b_i_c: None,
                    instrument_type: "UPI".to_string(),
                    action: "PAY".to_string(),
                    m_i_c_r: None,
                    verification_code: None,
                    i_b_a_n: None,
                    processor: "UPI".to_string(),
                    issuance: None,
                    alias: "UPI_ALIAS".to_string(),
                    identifier: "UPI_INSTRUMENT".to_string(),
                    token: "UPI_TOKEN".to_string(),
                    authentication: None,
                    sub_type: "COLLECT".to_string(),
                    issuer: "UPI_ISSUER".to_string(),
                    acquirer: "UPI_ACQUIRER".to_string(),
                },
                instruction: TpslInstructionPayload {
                    occurrence: "ONCE".to_string(),
                    amount: amount.to_string(),
                    frequency: "ONCE".to_string(),
                    instruction_type: "PAYMENT".to_string(),
                    description: "Payment Instruction".to_string(),
                    action: "PAY".to_string(),
                    limit: amount.to_string(),
                    end_date_time: "".to_string(),
                    debit_day: "".to_string(),
                    debit_flag: "N".to_string(),
                    identifier: "INSTRUCTION_001".to_string(),
                    reference: item.router_data.resource_common_data.connector_request_reference_id.clone(),
                    start_date_time: "".to_string(),
                    validity: "".to_string(),
                },
            },
            transaction: TpslTransactionPayload {
                device_identifier: "WEB".to_string(),
                sms_sending: "N".to_string(),
                amount: amount.to_string(),
                forced3_d_s_call: "N".to_string(),
                transaction_type: "SALE".to_string(),
                description: "Payment Transaction".to_string(),
                currency: item.router_data.request.currency.to_string(),
                is_registration: "N".to_string(),
                identifier: item.router_data.resource_common_data.connector_request_reference_id.clone(),
                date_time: "2025-01-01 00:00:00".to_string(),
                token: "TXN_TOKEN".to_string(),
                security_token: auth_type.merchant_key.peek().to_string(),
                sub_type: "SALE".to_string(),
                request_type: "SALE".to_string(),
                reference: item.router_data.resource_common_data.connector_request_reference_id.clone(),
                merchant_initiated: "N".to_string(),
                tenure_id: "".to_string(),
            },
            consumer: TpslConsumerPayload {
                mobile_number: "9999999999".to_string(),
                email_i_d: item.router_data.request.email.as_ref().map(|_| "test@example.com".to_string()).unwrap_or_else(|| "test@example.com".to_string()),
                identifier: customer_id.get_string_repr().to_string(),
                account_no: "".to_string(),
                account_type: "".to_string(),
                account_holder_name: "".to_string(),
                aadhar_no: "".to_string(),
            },
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<TPSLRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for TpslPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: TPSLRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth_type = TpslAuthType::try_from(&item.router_data.connector_auth_type)?;

        Ok(Self {
            merchant: TpslMerchantDataType {
                identifier: auth_type.merchant_code.peek().to_string(),
            },
            payment: TpslPaymentDataType {
                instruction: TpslInstructionDataType {
                    amount: None,
                    end_date_time: None,
                    identifier: None,
                },
            },
            transaction: TpslTransactionDataType {
                device_identifier: "WEB".to_string(),
                transaction_type: "SALE".to_string(),
                currency: item.router_data.request.currency.to_string(),
                identifier: item.router_data.resource_common_data.connector_request_reference_id.clone(),
                date_time: "2025-01-01 00:00:00".to_string(),
                sub_type: "SALE".to_string(),
                request_type: "STATUS".to_string(),
            },
            consumer: TpslConsumerDataType {
                identifier: item.router_data.resource_common_data.get_customer_id()?.get_string_repr().to_string(),
            },
        })
    }
}

impl<F, T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<TpslPaymentsResponse, Self>>
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
            TpslPaymentsResponse::Success(success_response) => {
                let redirection_data = get_redirect_form_data(&success_response)?;
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
                        network_txn_id: None,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            TpslPaymentsResponse::Error(error_response) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_response.error_code,
                    status_code: item.http_code,
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
            response,
            ..router_data
        })
    }
}

impl<F> TryFrom<ResponseRouterData<TpslPaymentsSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TpslPaymentsSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let status = match response.transaction_state.as_str() {
            "SUCCESS" | "SUCCESSFUL" => common_enums::AttemptStatus::Charged,
            "PENDING" | "PROCESSING" => common_enums::AttemptStatus::Pending,
            "FAILED" | "FAILURE" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Pending,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    response.merchant_transaction_identifier,
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: response.bank_reference_identifier,
                connector_response_reference_id: Some(response.identifier.unwrap_or_default()),
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

fn get_redirect_form_data(
    response: &TpslAuthCaptureTxnResponse,
) -> CustomResult<RedirectForm, errors::ConnectorError> {
    match &response.response {
        TpslAuthCaptureResponse::AuthResponse(auth_url) => Ok(RedirectForm::Form {
            endpoint: auth_url.0.clone(),
            method: Method::Get,
            form_fields: Default::default(),
        }),
        TpslAuthCaptureResponse::DecryptedResponse(_) => {
            // For UPI collect, we might need to return different redirect data
            Ok(RedirectForm::Form {
                endpoint: "https://api.tpsl-india.in/upi/collect".to_string(),
                method: Method::Post,
                form_fields: Default::default(),
            })
        }
    }
}