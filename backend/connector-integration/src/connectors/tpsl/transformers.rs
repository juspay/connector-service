use std::collections::HashMap;

use common_utils::{
    errors::CustomResult,
    ext_traits::ValueExt,
    id_type,
    request::Method,
    types::StringMinorUnit,
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

use crate::{types::ResponseRouterData};

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsRequest {
    #[serde(rename = "getTransactionToken")]
    pub get_transaction_token: TpslTransactionMessage,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslTransactionMessage {
    pub msg: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TpslPaymentsResponse {
    TpslTransactionResponse(TpslTransactionResponse),
    TpslErrorResponse(TpslErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslTransactionResponse {
    #[serde(rename = "getTransactionTokenReturn")]
    pub get_transaction_token_return: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslErrorResponse {
    #[serde(rename = "_ErrorCode")]
    pub error_code: String,
    #[serde(rename = "_ErrorMessage")]
    pub error_message: String,
}

// PSync request and response types
#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsSyncRequest {
    pub merchant: TpslMerchantDataType,
    pub payment: TpslPaymentDataType,
    pub transaction: TpslTransactionDataType,
    pub consumer: TpslConsumerDataType,
}

#[derive(Debug, Serialize, Default)]
pub struct TpslMerchantDataType {
    pub identifier: String,
}

#[derive(Debug, Serialize, Default)]
pub struct TpslPaymentDataType {
    pub instruction: TpslInstructionDataType,
}

#[derive(Debug, Serialize, Default)]
pub struct TpslInstructionDataType {
    pub amount: Option<String>,
    pub end_date_time: Option<String>,
    pub identifier: Option<String>,
}

#[derive(Debug, Serialize, Default)]
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

#[derive(Debug, Serialize, Default)]
pub struct TpslConsumerDataType {
    pub identifier: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TpslPaymentsSyncResponse {
    TpslDecodedRedirectionResponse(TpslDecodedRedirectionResponse),
    TpslErrorResponse(TpslErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslDecodedRedirectionResponse {
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
    #[serde(rename = "_BankTransactionID")]
    pub bank_transaction_id: Option<String>,
    pub alias_name: Option<String>,
    pub mandate_reg_no: Option<String>,
    pub hash: Option<String>,
    #[serde(rename = "_REFUND_DETAILS")]
    pub refund_details: Option<String>,
    pub tpsl_err_msg: Option<String>,
    pub vpa_name: Option<String>,
    pub auth: Option<String>,
    #[serde(rename = "_MandateId")]
    pub mandate_id: Option<String>,
    #[serde(rename = "_VPA")]
    pub vpa: Option<String>,
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

// Authentication types
#[derive(Default, Debug, Deserialize)]
pub struct TpslAuth {
    pub api_key: Secret<String>,
    pub merchant_code: String,
}

impl TryFrom<&ConnectorAuthType> for TpslAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, .. } => Ok(Self {
                api_key: api_key.to_owned(),
                merchant_code: "".to_string(), // Will be extracted from config
            }),
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
            TpslPaymentStatus::Pending => Self::Pending,
            TpslPaymentStatus::Failure => Self::Failure,
            TpslPaymentStatus::Processing => Self::AuthenticationPending,
        }
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
        &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    > for TpslPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
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
        match item.router_data.resource_common_data.payment_method {
            common_enums::PaymentMethod::Upi => {
                let transaction_message = format!(
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
                                "identifier": "UPI_ITEM_1"
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
                            "deviceIdentifier": "WEB",
                            "amount": "{}",
                            "type": "SALE",
                            "currency": "{}",
                            "identifier": "{}",
                            "dateTime": "{}",
                            "subType": "UPI",
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
                    customer_id.get_string_repr(),
                    amount,
                    item.router_data.resource_common_data.connector_request_reference_id,
                    amount,
                    item.router_data.request.currency.to_string(),
                    item.router_data.resource_common_data.connector_request_reference_id,
                    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S"),
                    item.router_data.request.browser_info.as_ref().and_then(|info| info.mobile_number.clone()).unwrap_or_default(),
                    item.router_data.request.email.as_ref().map(|e| e.to_string()).unwrap_or_default(),
                    customer_id.get_string_repr(),
                    item.router_data.request.payment_method_data.as_ref()
                        .and_then(|pm| pm.upi.as_ref())
                        .and_then(|upi| upi.vpa.clone())
                        .unwrap_or_default()
                );

                Ok(Self {
                    get_transaction_token: TpslTransactionMessage {
                        msg: transaction_message,
                    },
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                "Payment method".to_string(),
            )
            .into()),
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
            TpslPaymentsResponse::TpslTransactionResponse(response_data) => {
                // For UPI payments, we typically get a token that needs to be used for redirection
                let redirection_data = RedirectForm::Form {
                    endpoint: format!(
                        "https://www.tpsl-india.in/PaymentGateway/merchant2.pg/{}",
                        response_data.get_transaction_token_return
                    ),
                    method: Method::Post,
                    form_fields: Default::default(),
                };

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
                        network_txn_id: Some(response_data.get_transaction_token_return),
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            TpslPaymentsResponse::TpslErrorResponse(error_data) => (
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

// PSync implementation
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
>
    TryFrom<
        &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    > for TpslPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let transaction_id = item.router_data.request.connector_transaction_id.get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            merchant: TpslMerchantDataType {
                identifier: customer_id.get_string_repr(),
            },
            payment: TpslPaymentDataType {
                instruction: TpslInstructionDataType {
                    amount: None,
                    end_date_time: None,
                    identifier: Some(transaction_id),
                },
            },
            transaction: TpslTransactionDataType {
                device_identifier: "WEB".to_string(),
                transaction_type: "SALE".to_string(),
                currency: item.router_data.request.currency.to_string(),
                identifier: transaction_id,
                date_time: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                sub_type: "UPI".to_string(),
                request_type: "TXN".to_string(),
            },
            consumer: TpslConsumerDataType {
                identifier: customer_id.get_string_repr(),
            },
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
        + Serialize
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
        let (status, response) = match response {
            TpslPaymentsSyncResponse::TpslDecodedRedirectionResponse(response_data) => {
                let status = match response_data.txn_status.as_str() {
                    "SUCCESS" | "SUCCESSFUL" => common_enums::AttemptStatus::Charged,
                    "PENDING" => common_enums::AttemptStatus::Pending,
                    "FAILURE" | "FAILED" => common_enums::AttemptStatus::Failure,
                    _ => common_enums::AttemptStatus::AuthenticationPending,
                };

                let amount_received = response_data.txn_amt.as_ref()
                    .and_then(|amt| amt.parse::<f64>().ok())
                    .map(|amt| common_utils::types::MinorUnit::from_major_unit_as_i64(amt));

                (
                    status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            response_data.clnt_txn_ref.clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: response_data.tpsl_txn_id.clone(),
                        connector_response_reference_id: response_data.tpsl_txn_id.clone(),
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                        amount_received,
                    }),
                )
            }
            TpslPaymentsSyncResponse::TpslErrorResponse(error_data) => (
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