use std::collections::HashMap;

use common_utils::{
    ext_traits::ValueExt, request::Method,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Maskable, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::tpsl::TpslRouterData, types::ResponseRouterData};

// TPSL Authentication Types
#[derive(Default, Debug, Deserialize)]
pub struct TpslAuthType {
    pub auths: HashMap<common_enums::Currency, TpslAuth>,
}

#[derive(Default, Debug, Deserialize)]
pub struct TpslAuth {
    pub merchant_code: Option<Secret<String>>,
    pub merchant_key: Option<Secret<String>>,
    pub salt_key: Option<Secret<String>>,
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

// Request Types for UPI Transaction
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsRequest {
    pub merchant: TpslMerchantPayload,
    pub cart: TpslCartPayload,
    pub payment: TpslPaymentPayload,
    pub transaction: TpslTransactionPayload,
    pub consumer: TpslConsumerPayload,
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
pub struct TpslCartPayload {
    pub item: Vec<TpslItemPayload>,
    pub reference: String,
    pub identifier: String,
    pub description: Option<String>,
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
    pub instruction: serde_json::Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslMethodPayload {
    pub token: String,
    pub r#type: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslInstrumentPayload {
    pub expiry: serde_json::Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslTransactionPayload {
    pub amount: String,
    pub r#type: String,
    pub currency: String,
    pub identifier: String,
    pub sub_type: String,
    pub request_type: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslConsumerPayload {
    pub mobile_number: String,
    pub email_id: String,
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
    pub email_id: bool,
    pub card_details: bool,
    pub mandate_details: bool,
}

// Sync Request Types
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsSyncRequest {
    pub merchant: TpslMerchantDataType,
    pub payment: TpslPaymentSyncType,
    pub transaction: TpslTransactionSyncType,
    pub consumer: TpslConsumerDataType,
}

#[derive(Debug, Serialize)]
pub struct TpslMerchantDataType {
    pub identifier: String,
}

#[derive(Debug, Serialize)]
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
pub struct TpslConsumerDataType {
    pub identifier: String,
}

// Response Types
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
    pub merchant_additional_details: serde_json::Value,
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

// Status mapping
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TpslTransactionStatus {
    #[default]
    Pending,
    Success,
    Failure,
    Processing,
}

impl From<TpslTransactionStatus> for common_enums::AttemptStatus {
    fn from(item: TpslTransactionStatus) -> Self {
        match item {
            TpslTransactionStatus::Success => Self::Charged,
            TpslTransactionStatus::Failure => Self::Failure,
            TpslTransactionStatus::Processing => Self::AuthenticationPending,
            TpslTransactionStatus::Pending => Self::Pending,
        }
    }
}

// Helper functions
fn get_merchant_auth(
    connector_auth_type: &ConnectorAuthType,
    currency: common_enums::Currency,
) -> error_stack::Result<TpslAuth, errors::ConnectorError> {
    TpslAuth::try_from((connector_auth_type, &currency))
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> TryFrom<
    TpslRouterData<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        T,
    >,
> for TpslPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: TpslRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let return_url = item.router_data.request.get_router_return_url()?;
        let auth = get_merchant_auth(
            &item.router_data.connector_auth_type,
            item.router_data.request.currency,
        )?;
        
        let merchant_code = auth.merchant_code.ok_or(errors::ConnectorError::FailedToObtainAuthType)?;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let email = item.router_data.request.email.clone().unwrap_or_default();
        // For UPI payments, we need to extract VPA from payment method data
        let vpa = match &item.router_data.request.payment_method_data {
            domain_types::payment_method_data::PaymentMethodData::Upi(upi_data) => {
                "test_vpa@upi".to_string() // Placeholder VPA
            }
            _ => return Err(errors::ConnectorError::MissingRequiredField { field_name: "vpa" }.into()),
        };

        Ok(Self {
            merchant: TpslMerchantPayload {
                webhook_endpoint_url: return_url.clone(),
                response_type: "URL".to_string(),
                response_endpoint_url: return_url.clone(),
                description: "UPI Payment".to_string(),
                identifier: merchant_code.peek().clone(),
                webhook_type: "HTTP".to_string(),
            },
            cart: TpslCartPayload {
                item: vec![TpslItemPayload {
                    description: "UPI Payment".to_string(),
                    provider_identifier: "UPI".to_string(),
                    surcharge_or_discount_amount: "0".to_string(),
                    amount: amount.to_string(),
                    com_amt: "0".to_string(),
                    s_k_u: "UPI".to_string(),
                    reference: item.router_data.resource_common_data.connector_request_reference_id.clone(),
                    identifier: "UPI_ITEM".to_string(),
                }],
                reference: item.router_data.resource_common_data.connector_request_reference_id.clone(),
                identifier: "UPI_CART".to_string(),
                description: Some("UPI Payment Cart".to_string()),
            },
            payment: TpslPaymentPayload {
                method: TpslMethodPayload {
                    token: "UPI".to_string(),
                    r#type: "UPI".to_string(),
                },
                instrument: TpslInstrumentPayload {
                    expiry: serde_json::Value::Null,
                },
                instruction: serde_json::Value::Null,
            },
            transaction: TpslTransactionPayload {
                amount,
                r#type: "SALE".to_string(),
                currency: item.router_data.request.currency.to_string(),
                identifier: item.router_data.resource_common_data.connector_request_reference_id.clone(),
                sub_type: "UPI".to_string(),
                request_type: "TXN".to_string(),
            },
            consumer: TpslConsumerPayload {
                mobile_number: phone.number.to_string(),
                email_id: email.expose().clone(),
                identifier: customer_id.get_string_repr().to_string(),
                account_no: "".to_string(),
                account_type: "".to_string(),
                account_holder_name: "".to_string(),
                vpa: vpa.to_string(),
                aadhar_no: "".to_string(),
            },
            merchant_input_flags: TpslFlagsType {
                account_no: false,
                mobile_number: true,
                email_id: true,
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
> TryFrom<
    TpslRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
> for TpslPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: TpslRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = get_merchant_auth(
            &item.router_data.connector_auth_type,
            item.router_data.request.currency,
        )?;
        
        let merchant_code = auth.merchant_code.ok_or(errors::ConnectorError::FailedToObtainAuthType)?;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            merchant: TpslMerchantDataType {
                identifier: merchant_code.peek().clone(),
            },
            payment: TpslPaymentSyncType {
                instruction: serde_json::Value::Null,
            },
            transaction: TpslTransactionSyncType {
                device_identifier: "WEB".to_string(),
                r#type: Some("SALE".to_string()),
                sub_type: Some("UPI".to_string()),
                amount,
                currency: item.router_data.request.currency.to_string(),
                date_time: "2025-01-01 00:00:00".to_string(),
                request_type: "STATUS".to_string(),
                token: item.router_data.request.connector_transaction_id.get_connector_transaction_id()
                    .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?,
            },
            consumer: TpslConsumerDataType {
                identifier: "".to_string(),
            },
        })
    }
}

// Response transformations
// Simplified response handling for Authorize flow
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> 
TryFrom<crate::types::ResponseRouterData<TpslPaymentsResponse, TpslRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>>
for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: crate::types::ResponseRouterData<TpslPaymentsResponse, TpslRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>,
    ) -> Result<Self, Self::Error> {
        let crate::types::ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        
        let (status, response) = match response {
            TpslPaymentsResponse::Success(_response_data) => {
                (
                    common_enums::AttemptStatus::AuthenticationPending,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(
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
            TpslPaymentsResponse::Error(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.error_code,
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
> TryFrom<TpslPaymentsSyncResponse> for PaymentsResponseData {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(response: TpslPaymentsSyncResponse) -> Result<Self, Self::Error> {
        let status = match response.transaction_state.as_str() {
            "SUCCESS" => common_enums::AttemptStatus::Charged,
            "FAILURE" => common_enums::AttemptStatus::Failure,
            "PENDING" => common_enums::AttemptStatus::Pending,
            _ => common_enums::AttemptStatus::AuthenticationPending,
        };

        Ok(PaymentsResponseData::TransactionResponse {
            resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(response.merchant_transaction_identifier),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: response.payment_method.payment_transaction.bank_reference_identifier,
            connector_response_reference_id: Some(response.merchant_transaction_identifier),
            incremental_authorization_allowed: None,
            status_code: response.status_code
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(200),
        })
    }
}