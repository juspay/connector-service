use std::collections::HashMap;

use common_utils::{
    errors::CustomResult,
    ext_traits::ValueExt,
    request::Method,
    types::StringMinorUnit,
};
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

use crate::types::ResponseRouterData;

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsRequest {
    pub merchant: TpslMerchantPayload,
    pub cart: TpslCartPayload,
    pub payment: TpslPaymentPayload,
    pub transaction: TpslTransactionPayload,
    pub consumer: TpslConsumerPayload,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslMerchantPayload {
    pub webhook_endpoint_url: String,
    pub response_type: String,
    pub response_endpoint_url: String,
    pub description: String,
    pub identifier: String,
    pub webhook_type: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslCartPayload {
    pub item: Vec<TpslItemPayload>,
    pub reference: String,
    pub identifier: String,
    pub description: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslItemPayload {
    pub description: String,
    pub provider_identifier: String,
    pub surcharge_or_discount_amount: String,
    pub amount: StringMinorUnit,
    pub com_amt: String,
    pub s_k_u: String,
    pub reference: String,
    pub identifier: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentPayload {
    pub method: TpslMethodPayload,
    pub instrument: TpslInstrumentPayload,
    pub instruction: TpslInstructionPayload,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslMethodPayload {
    pub token: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub code: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslInstrumentPayload {
    pub expiry: TpslExpiryPayload,
    pub provider: String,
    pub i_f_s_c: String,
    pub holder: TpslHolderPayload,
    pub b_i_c: String,
    #[serde(rename = "type")]
    pub instrument_type: String,
    pub action: String,
    pub m_i_c_r: String,
    pub verification_code: String,
    pub i_b_a_n: String,
    pub processor: String,
    pub issuance: TpslExpiryPayload,
    pub alias: String,
    pub identifier: String,
    pub token: String,
    pub authentication: TpslAuthenticationPayload,
    pub sub_type: String,
    pub issuer: String,
    pub acquirer: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslExpiryPayload {
    pub year: String,
    pub month: String,
    pub date_time: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslHolderPayload {
    pub name: String,
    pub address: TpslAddressPayload,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAddressPayload {
    pub country: String,
    pub street: String,
    pub state: String,
    pub city: String,
    pub zip_code: Secret<String>,
    pub county: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAuthenticationPayload {
    pub token: String,
    #[serde(rename = "type")]
    pub auth_type: String,
    pub sub_type: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslInstructionPayload {
    pub occurrence: String,
    pub amount: StringMinorUnit,
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

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslTransactionPayload {
    pub device_identifier: String,
    pub sms_sending: String,
    pub amount: StringMinorUnit,
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

#[derive(Default, Debug, Serialize)]
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

#[derive(Default, Debug, Serialize)]
pub struct TpslPaymentsSyncRequest {
    pub merchant: TpslMerchantDataType,
    pub payment: TpslPaymentDataType,
    pub transaction: TpslTransactionDataType,
    pub consumer: TpslConsumerDataType,
}

#[derive(Default, Debug, Serialize)]
pub struct TpslMerchantDataType {
    pub identifier: String,
}

#[derive(Default, Debug, Serialize)]
pub struct TpslPaymentDataType {
    pub instruction: TpslInstructionDataType,
}

#[derive(Default, Debug, Serialize)]
pub struct TpslInstructionDataType {
    pub amount: Option<String>,
    pub end_date_time: Option<String>,
    pub identifier: Option<String>,
}

#[derive(Default, Debug, Serialize)]
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

#[derive(Default, Debug, Serialize)]
pub struct TpslConsumerDataType {
    pub identifier: String,
}

#[derive(Default, Debug, Deserialize)]
pub struct TpslAuthType {
    pub auths: HashMap<common_enums::Currency, TpslAuth>,
}

#[derive(Default, Debug, Deserialize)]
pub struct TpslAuth {
    pub merchant_id: Secret<String>,
    pub api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for TpslAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::CurrencyAuthKey { auth_key_map } => {
                let transformed_auths = auth_key_map
                    .iter()
                    .map(|(currency, identity_auth_key)| {
                        let tpsl_auth = identity_auth_key
                            .to_owned()
                            .parse_value::<TpslAuth>("TpslAuth")
                            .change_context(errors::ConnectorError::InvalidDataFormat {
                                field_name: "auth_key_map",
                            })?;

                        Ok((currency.to_owned(), tpsl_auth))
                    })
                    .collect::<Result<_, Self::Error>>()?;

                Ok(Self {
                    auths: transformed_auths,
                })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

impl TryFrom<(&ConnectorAuthType, &common_enums::Currency)> for TpslAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(value: (&ConnectorAuthType, &common_enums::Currency)) -> Result<Self, Self::Error> {
        let (auth_type, currency) = value;

        if let ConnectorAuthType::CurrencyAuthKey { auth_key_map } = auth_type {
            if let Some(identity_auth_key) = auth_key_map.get(currency) {
                let tpsl_auth: Self = identity_auth_key
                    .to_owned()
                    .parse_value("TpslAuth")
                    .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
                Ok(tpsl_auth)
            } else {
                Err(errors::ConnectorError::CurrencyNotSupported {
                    message: currency.to_string(),
                    connector: "TPSL",
                }
                .into())
            }
        } else {
            Err(errors::ConnectorError::FailedToObtainAuthType.into())
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TpslPaymentStatus {
    #[default]
    Pending,
    Success,
    Failure,
    Processing,
}

impl From<TpslPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: TpslPaymentStatus) -> Self {
        match item {
            TpslPaymentStatus::Success => Self::Charged,
            TpslPaymentStatus::Failure => Self::Failure,
            TpslPaymentStatus::Pending => Self::AuthenticationPending,
            TpslPaymentStatus::Processing => Self::Authorizing,
        }
    }
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct TpslErrors {
    pub message: String,
    pub path: String,
    #[serde(rename = "type")]
    pub error_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TpslPaymentsResponse {
    TpslError(TpslErrorResponse),
    TpslData(TpslPaymentsResponseData),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsResponseData {
    pub code: i32,
    pub status: String,
    pub response: TpslAuthCaptureResponse,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TpslAuthCaptureResponse {
    AuthResponse(TpslAuthS2sResponse),
    DecryptedResponse(TpslDecryptedResponse),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslAuthS2sResponse {
    pub token: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslDecryptedResponse {
    pub merchant_code: String,
    pub merchant_transaction_identifier: Option<String>,
    pub merchant_transaction_request_type: String,
    pub response_type: String,
    pub transaction_state: String,
    pub merchant_additional_details: Option<serde_json::Value>,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsSyncResponse {
    pub txn_status: String,
    pub txn_msg: Option<String>,
    pub txn_err_msg: String,
    pub clnt_txn_ref: String,
    pub tpsl_bank_cd: Option<String>,
    pub tpsl_txn_id: Option<String>,
    pub txn_amt: Option<String>,
    pub clnt_rqst_meta: Option<String>,
    pub tpsl_txn_time: Option<String>,
    pub tpsl_rfnd_id: Option<String>,
    pub bal_amt: Option<String>,
    pub rqst_token: Option<String>,
    pub token: Option<String>,
    pub card_id: Option<String>,
    #[serde(rename = "BankTransactionID")]
    pub bank_transaction_id: Option<String>,
    pub alias_name: Option<String>,
    pub mandate_reg_no: Option<String>,
    pub hash: Option<String>,
    #[serde(rename = "REFUND_DETAILS")]
    pub refund_details: Option<String>,
    pub tpsl_err_msg: Option<String>,
    pub vpa_name: Option<String>,
    pub auth: Option<String>,
    #[serde(rename = "MandateId")]
    pub mandate_id: Option<String>,
    #[serde(rename = "VPA")]
    pub vpa: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslErrorResponse {
    pub error_code: String,
    pub error_message: String,
    pub errors: Option<Vec<TpslErrors>>,
}

fn get_redirect_form_data(
    _payment_method_type: common_enums::PaymentMethodType,
    _response_data: TpslPaymentsResponseData,
) -> CustomResult<RedirectForm, errors::ConnectorError> {
    Ok(RedirectForm::Form {
        endpoint: "https://www.tpsl-india.in/PaymentGateway/merchant2.pg".to_string(),
        method: Method::Post,
        form_fields: Default::default(),
    })
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
>
    TryFrom<
        super::TPSLRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for TpslPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: super::TPSLRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let return_url = item.router_data.request.get_router_return_url()?;
        let auth_type = TpslAuth::try_from((
            &item.router_data.connector_auth_type,
            &item.router_data.request.currency,
        ))?;
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            merchant: TpslMerchantPayload {
                webhook_endpoint_url: return_url.clone(),
                response_type: "URL".to_string(),
                response_endpoint_url: return_url.clone(),
                description: "UPI Payment".to_string(),
                identifier: auth_type.merchant_id.peek_mut().to_string(),
                webhook_type: "HTTP".to_string(),
            },
            cart: TpslCartPayload {
                item: vec![TpslItemPayload {
                    description: "UPI Transaction".to_string(),
                    provider_identifier: "UPI".to_string(),
                    surcharge_or_discount_amount: "0".to_string(),
                    amount: amount.clone(),
                    com_amt: "0".to_string(),
                    s_k_u: "UPI".to_string(),
                    reference: item
                        .router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                    identifier: "UPI_ITEM".to_string(),
                }],
                reference: item
                    .router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
                identifier: "UPI_CART".to_string(),
                description: "UPI Payment Cart".to_string(),
            },
            payment: TpslPaymentPayload {
                method: TpslMethodPayload {
                    token: "UPI".to_string(),
                    method_type: "UPI".to_string(),
                    code: "UPI".to_string(),
                },
                instrument: TpslInstrumentPayload {
                    expiry: TpslExpiryPayload {
                        year: "2024".to_string(),
                        month: "12".to_string(),
                        date_time: chrono::Utc::now().to_rfc3339(),
                    },
                    provider: "UPI".to_string(),
                    i_f_s_c: "".to_string(),
                    holder: TpslHolderPayload {
                        name: customer_id.get_string_repr(),
                        address: TpslAddressPayload {
                            country: "IN".to_string(),
                            street: "".to_string(),
                            state: "".to_string(),
                            city: "".to_string(),
                            zip_code: Secret::new("".to_string()),
                            county: "".to_string(),
                        },
                    },
                    b_i_c: "".to_string(),
                    instrument_type: "UPI".to_string(),
                    action: "PAY".to_string(),
                    m_i_c_r: "".to_string(),
                    verification_code: "".to_string(),
                    i_b_a_n: "".to_string(),
                    processor: "UPI".to_string(),
                    issuance: TpslExpiryPayload {
                        year: "2024".to_string(),
                        month: "12".to_string(),
                        date_time: chrono::Utc::now().to_rfc3339(),
                    },
                    alias: "UPI_ALIAS".to_string(),
                    identifier: "UPI_INSTRUMENT".to_string(),
                    token: "UPI_TOKEN".to_string(),
                    authentication: TpslAuthenticationPayload {
                        token: "UPI_AUTH".to_string(),
                        auth_type: "UPI".to_string(),
                        sub_type: "COLLECT".to_string(),
                    },
                    sub_type: "COLLECT".to_string(),
                    issuer: "UPI".to_string(),
                    acquirer: "UPI".to_string(),
                },
                instruction: TpslInstructionPayload {
                    occurrence: "SINGLE".to_string(),
                    amount: amount.clone(),
                    frequency: "ONCE".to_string(),
                    instruction_type: "PAYMENT".to_string(),
                    description: "UPI Payment".to_string(),
                    action: "DEBIT".to_string(),
                    limit: amount.clone(),
                    end_date_time: chrono::Utc::now().to_rfc3339(),
                    debit_day: "1".to_string(),
                    debit_flag: "Y".to_string(),
                    identifier: "UPI_INSTRUCTION".to_string(),
                    reference: item
                        .router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                    start_date_time: chrono::Utc::now().to_rfc3339(),
                    validity: "VALID".to_string(),
                },
            },
            transaction: TpslTransactionPayload {
                device_identifier: item
                    .router_data
                    .request
                    .get_ip_address_as_optional()
                    .map(|ip| ip.expose())
                    .unwrap_or_else(|| "127.0.0.1".to_string()),
                sms_sending: "N".to_string(),
                amount,
                forced3_d_s_call: "N".to_string(),
                transaction_type: "SALE".to_string(),
                description: "UPI Transaction".to_string(),
                currency: item.router_data.request.currency.to_string(),
                is_registration: "N".to_string(),
                identifier: item
                    .router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
                date_time: chrono::Utc::now().to_rfc3339(),
                token: "TXN_TOKEN".to_string(),
                security_token: auth_type.api_key.peek_mut().to_string(),
                sub_type: "SALE".to_string(),
                request_type: "TXN".to_string(),
                reference: item
                    .router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
                merchant_initiated: "Y".to_string(),
                tenure_id: "".to_string(),
            },
            consumer: TpslConsumerPayload {
                mobile_number: item
                    .router_data
                    .request
                    .browser_info
                    .as_ref()
                    .and_then(|info| info.mobile_number.clone())
                    .unwrap_or_else(|| "9999999999".to_string()),
                email_i_d: item
                    .router_data
                    .request
                    .email
                    .clone()
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "test@example.com".to_string()),
                identifier: customer_id.get_string_repr(),
                account_no: "".to_string(),
                account_type: "SAVINGS".to_string(),
                account_holder_name: customer_id.get_string_repr(),
                aadhar_no: "".to_string(),
            },
        })
    }
}

impl<F, T> TryFrom<ResponseRouterData<TpslPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T>, PaymentsResponseData>
where
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
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
            TpslPaymentsResponse::TpslError(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.error_code.to_string(),
                    status_code: item.http_code,
                    message: error_data.error_message.clone(),
                    reason: Some(error_data.error_message),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            TpslPaymentsResponse::TpslData(response_data) => {
                let payment_method_type = router_data
                    .request
                    .payment_method_type
                    .ok_or(errors::ConnectorError::MissingPaymentMethodType)?;
                let redirection_data = get_redirect_form_data(payment_method_type, response_data)?;
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
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
>
    TryFrom<
        super::TPSLRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for TpslPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: super::TPSLRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth_type = TpslAuth::try_from((
            &item.router_data.connector_auth_type,
            &item.router_data.request.currency,
        ))?;

        Ok(Self {
            merchant: TpslMerchantDataType {
                identifier: auth_type.merchant_id.peek_mut().to_string(),
            },
            payment: TpslPaymentDataType {
                instruction: TpslInstructionDataType {
                    amount: Some(
                        item.connector
                            .amount_converter
                            .convert(
                                item.router_data.request.minor_amount,
                                item.router_data.request.currency,
                            )
                            .change_context(ConnectorError::RequestEncodingFailed)?
                            .get_amount_as_string(),
                    ),
                    end_date_time: Some(chrono::Utc::now().to_rfc3339()),
                    identifier: Some(
                        item.router_data
                            .resource_common_data
                            .connector_request_reference_id
                            .clone(),
                    ),
                },
            },
            transaction: TpslTransactionDataType {
                device_identifier: item
                    .router_data
                    .request
                    .get_ip_address_as_optional()
                    .map(|ip| ip.expose())
                    .unwrap_or_else(|| "127.0.0.1".to_string()),
                transaction_type: "SALE".to_string(),
                currency: item.router_data.request.currency.to_string(),
                identifier: item
                    .router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
                date_time: chrono::Utc::now().to_rfc3339(),
                sub_type: "SALE".to_string(),
                request_type: "STATUS".to_string(),
            },
            consumer: TpslConsumerDataType {
                identifier: item
                    .router_data
                    .resource_common_data
                    .get_customer_id()?
                    .get_string_repr(),
            },
        })
    }
}

impl<F> TryFrom<ResponseRouterData<TpslPaymentsSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, domain_types::connector_types::PaymentsSyncData, PaymentsResponseData>
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

        let status = match response.txn_status.as_str() {
            "SUCCESS" | "SUCCESSFUL" => common_enums::AttemptStatus::Charged,
            "PENDING" => common_enums::AttemptStatus::Authorizing,
            "FAILURE" | "FAILED" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Pending,
        };

        let amount_received = response.txn_amt.as_ref().and_then(|amt| {
            amt.parse::<f64>()
                .ok()
                .map(|amt_f64| (amt_f64 * 100.0) as i64)
                .map(common_utils::types::MinorUnit::new)
        });

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.clnt_txn_ref),
                redirection_data: None,
                mandate_reference: response.mandate_reg_no.map(|mr| {
                    Box::new(domain_types::connector_types::MandateReference { 
                        connector_mandate_id: Some(mr),
                        payment_method_id: None,
                    })
                }),
                connector_metadata: None,
                network_txn_id: response.tpsl_txn_id,
                connector_response_reference_id: response.tpsl_txn_id,
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}