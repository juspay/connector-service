use std::collections::HashMap;

use common_utils::{
    errors::CustomResult,
    ext_traits::ValueExt,
    request::Method,
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
    pub get_transaction_token: TpslTransactionMessage,
}

#[derive(Default, Debug, Serialize)]
pub struct TpslTransactionMessage {
    pub msg: String,
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

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
>
    TryFrom<
        TpslRouterData<
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
        item: TpslRouterData<
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
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Create transaction message based on UPI payment method
        let transaction_msg = match item.router_data.resource_common_data.payment_method {
            common_enums::PaymentMethod::Upi => {
                let vpa = item.router_data
                    .request
                    .payment_method_data
                    .as_ref()
                    .and_then(|pm| pm.get_upi_data())
                    .and_then(|upi| upi.vpa.clone())
                    .unwrap_or_else(|| "".to_string());
                
                format!(
                    r#"{{
                        "merchant": {{
                            "identifier": "{}"
                        }},
                        "cart": {{
                            "item": [{{
                                "amount": "{}",
                                "comAmt": "0",
                                "sKU": "UPI",
                                "reference": "{}",
                                "identifier": "UPI_{}"
                            }}],
                            "description": "UPI Payment"
                        }},
                        "payment": {{
                            "method": {{
                                "token": "UPI",
                                "type": "UPI",
                                "code": "UPI"
                            }},
                            "instrument": {{
                                "expiry": null
                            }},
                            "instruction": null
                        }},
                        "transaction": {{
                            "amount": "{}",
                            "type": "SALE",
                            "currency": "{}",
                            "identifier": "{}",
                            "dateTime": "{}",
                            "subType": "DEBIT",
                            "requestType": "TXN"
                        }},
                        "consumer": {{
                            "mobileNumber": "{}",
                            "emailID": "{}",
                            "identifier": "{}",
                            "accountNo": "",
                            "accountType": "",
                            "accountHolderName": "",
                            "vpa": "{}",
                            "aadharNo": ""
                        }},
                        "merchantInputFlags": {{
                            "accountNo": false,
                            "mobileNumber": true,
                            "emailID": true,
                            "cardDetails": false,
                            "mandateDetails": false
                        }}
                    }}"#,
                    get_merchant_id(&item.router_data.connector_auth_type)?,
                    amount,
                    item.router_data.resource_common_data.connector_request_reference_id,
                    customer_id,
                    amount,
                    item.router_data.request.currency.to_string(),
                    item.router_data.resource_common_data.connector_request_reference_id,
                    "2024-01-01 00:00:00".to_string(), // TODO: Use proper timestamp
                    item.router_data.request.get_phone_number().unwrap_or_else(|| "".to_string()),
                    item.router_data.request.email.as_ref().map(|e| e.to_string()).unwrap_or_else(|| "".to_string()),
                    customer_id,
                    vpa
                )
            },
            _ => return Err(errors::ConnectorError::NotImplemented(
                "Payment method not supported by TPSL".to_string()
            ).into()),
        };

        Ok(Self {
            get_transaction_token: TpslTransactionMessage {
                msg: transaction_msg,
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
>
    TryFrom<
        TpslRouterData<
            RouterDataV2<
                PSync,
                PaymentFlowData,
                PaymentsSyncData,
                PaymentsResponseData,
            >,
            T,
        >,
    > for TpslPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: TpslRouterData<
            RouterDataV2<
                PSync,
                PaymentFlowData,
                PaymentsSyncData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let connector_transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .change_context(ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            merchant: TpslMerchantDataType {
                identifier: get_merchant_id(&item.router_data.connector_auth_type)?,
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
                identifier: connector_transaction_id.to_string(),
                date_time: "2024-01-01 00:00:00".to_string(), // TODO: Use proper timestamp
                sub_type: "DEBIT".to_string(),
                request_type: "STATUS".to_string(),
            },
            consumer: TpslConsumerDataType {
                identifier: item.router_data.resource_common_data.get_customer_id()?,
            },
        })
    }
}

#[derive(Default, Debug, Deserialize)]
pub struct TpslAuthType {
    pub auths: HashMap<common_enums::Currency, TpslAuth>,
}

#[derive(Default, Debug, Deserialize)]
pub struct TpslAuth {
    pub api_key: Option<Secret<String>>,
    pub merchant_id: Option<String>,
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

impl TryFrom<&ConnectorAuthType> for TpslAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, .. } => Ok(Self {
                api_key: Some(api_key.clone()),
                merchant_id: None,
            }),
            ConnectorAuthType::CurrencyAuthKey { auth_key_map } => {
                // Use the first available currency auth for now
                if let Some((_, identity_auth_key)) = auth_key_map.iter().next() {
                    let tpsl_auth: Self = identity_auth_key
                        .to_owned()
                        .parse_value("TpslAuth")
                        .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
                    Ok(tpsl_auth)
                } else {
                    Err(errors::ConnectorError::FailedToObtainAuthType.into())
                }
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TpslPaymentStatus {
    Success,
    Pending,
    Failure,
    #[default]
    Processing,
}

impl From<TpslPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: TpslPaymentStatus) -> Self {
        match item {
            TpslPaymentStatus::Success => Self::Charged,
            TpslPaymentStatus::Pending => Self::AuthenticationPending,
            TpslPaymentStatus::Failure => Self::Failure,
            TpslPaymentStatus::Processing => Self::Pending,
        }
    }
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct TpslErrors {
    pub message: String,
    pub code: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TpslPaymentsResponse {
    TpslError(TpslErrorResponse),
    TpslData(TpslTransactionResponse),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslTransactionResponse {
    #[serde(rename = "getTransactionTokenReturn")]
    pub get_transaction_token_return: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsSyncResponse {
    pub merchant_code: String,
    pub merchant_transaction_identifier: String,
    pub merchant_transaction_request_type: String,
    pub response_type: String,
    pub transaction_state: Option<String>,
    pub payment_method: TpslPaymentMethodPayload,
    pub error: Option<serde_json::Value>,
    pub status_code: Option<String>,
    pub status_message: Option<String>,
    pub identifier: Option<String>,
    pub bank_reference_identifier: Option<String>,
    pub error_message: Option<String>,
    pub desc: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslPaymentMethodPayload {
    pub token: String,
    pub instrument_alias_name: String,
    pub instrument_token: String,
    pub bank_selection_code: String,
    pub payment_transaction: TpslPaymentTransactionPayload,
    pub error: TpslPaymentMethodErrorPayload,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslPaymentTransactionPayload {
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
    pub reference: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslPaymentMethodErrorPayload {
    pub code: String,
    pub desc: String,
}

fn get_redirect_form_data(
    response_data: TpslTransactionResponse,
) -> CustomResult<RedirectForm, errors::ConnectorError> {
    // TPSL typically returns a token or redirect URL for UPI payments
    Ok(RedirectForm::Form {
        endpoint: response_data.get_transaction_token_return,
        method: Method::Post,
        form_fields: Default::default(),
    })
}

impl<
    F,
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize
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
                let redirection_data = get_redirect_form_data(response_data)?;
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
> TryFrom<TpslPaymentsSyncResponse> for PaymentsResponseData {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(response: TpslPaymentsSyncResponse) -> Result<Self, Self::Error> {
        let status = response
            .transaction_state
            .as_ref()
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|| "processing".to_string());

        let attempt_status = match status.as_str() {
            "success" | "completed" => common_enums::AttemptStatus::Charged,
            "pending" | "processing" => common_enums::AttemptStatus::Pending,
            "failed" | "failure" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Pending,
        };

        Ok(Self::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(
                response.merchant_transaction_identifier,
            ),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: response.bank_reference_identifier,
            connector_response_reference_id: response.identifier,
            incremental_authorization_allowed: None,
            status_code: response
                .status_code
                .and_then(|s| s.parse().ok())
                .unwrap_or(200),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslErrorResponse {
    pub error_code: String,
    pub error_message: String,
    pub errors: Option<Vec<TpslErrors>>,
}

// Stub types for unsupported flows
#[derive(Debug, Clone, Serialize)]
pub struct TpslVoidRequest;
#[derive(Debug, Clone)]
pub struct TpslVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslCaptureRequest;
#[derive(Debug, Clone)]
pub struct TpslCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslRefundRequest;
#[derive(Debug, Clone)]
pub struct TpslRefundResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslRefundSyncRequest;
#[derive(Debug, Clone)]
pub struct TpslRefundSyncResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct TpslCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslSessionTokenRequest;
#[derive(Debug, Clone)]
pub struct TpslSessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslSetupMandateRequest;
#[derive(Debug, Clone)]
pub struct TpslSetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct TpslRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslAcceptDisputeRequest;
#[derive(Debug, Clone)]
pub struct TpslAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct TpslDefendDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct TpslSubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct TpslSubmitEvidenceResponse;

fn get_merchant_id(
    connector_auth_type: &ConnectorAuthType,
) -> Result<String, errors::ConnectorError> {
    match TpslAuth::try_from(connector_auth_type) {
        Ok(tpsl_auth) => {
            if let Some(merchant_id) = tpsl_auth.merchant_id {
                Ok(merchant_id)
            } else {
                // Fallback to a default merchant ID or extract from API key
                Err(errors::ConnectorError::FailedToObtainAuthType)
            }
        }
        Err(_) => Err(errors::ConnectorError::FailedToObtainAuthType),
    }
}