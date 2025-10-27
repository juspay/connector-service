use std::collections::HashMap;

use common_utils::{
    errors::CustomResult, ext_traits::ValueExt, id_type, request::Method, types::StringMinorUnit,
    Email,
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsResponseData, ResponseId},
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

use crate::{connectors::easebuzz::EaseBuzzRouterData, types::RequestResponseRouterData};

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsRequest {
    txnid: String,
    amount: StringMinorUnit,
    email: Option<Email>,
    phone: Option<String>,
    firstname: Option<Secret<String>>,
    lastname: Option<Secret<String>>,
    surl: String,
    furl: String,
    productinfo: String,
    udf1: Option<String>,
    udf2: Option<String>,
    udf3: Option<String>,
    udf4: Option<String>,
    udf5: Option<String>,
    udf6: Option<String>,
    udf7: Option<String>,
    udf8: Option<String>,
    udf9: Option<String>,
    udf10: Option<String>,
    address1: Option<String>,
    address2: Option<String>,
    city: Option<String>,
    state: Option<String>,
    country: Option<String>,
    zipcode: Option<String>,
    pg: Option<String>,
    customer_unique_id: Option<String>,
    split_payments: Option<String>,
    sub_merchant_id: Option<String>,
    customer_name: Option<String>,
    card_type: Option<String>,
    card_number: Option<Secret<String>>,
    card_name: Option<Secret<String>>,
    card_cvv: Option<Secret<String>>,
    card_exp_month: Option<String>,
    card_exp_year: Option<String>,
    bankcode: Option<String>,
    vpa: Option<String>,
    mandate_type: Option<String>,
    mandate_max_amount: Option<String>,
    mandate_start_date: Option<String>,
    mandate_end_date: Option<String>,
    mandate_frequency: Option<String>,
    mandate_rule_id: Option<String>,
    mandate_reg_ref_id: Option<String>,
    tr: Option<String>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSyncRequest {
    txnid: String,
    amount: StringMinorUnit,
    email: Option<Email>,
    phone: Option<String>,
    key: String,
    hash: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzRefundSyncRequest {
    key: String,
    easebuzz_id: String,
    hash: String,
    merchant_refund_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzAuth {
    pub api_key: Option<Secret<String>>,
    pub salt: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for EaseBuzzAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, api_secret } => Ok(Self {
                api_key: Some(api_key.clone()),
                salt: Some(api_secret.clone()),
            }),
            ConnectorAuthType::Key { api_key } => Ok(Self {
                api_key: Some(api_key.clone()),
                salt: None,
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EaseBuzzPaymentStatus {
    Success,
    Pending,
    Failure,
    #[default]
    Unknown,
}

impl From<EaseBuzzPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: EaseBuzzPaymentStatus) -> Self {
        match item {
            EaseBuzzPaymentStatus::Success => Self::Charged,
            EaseBuzzPaymentStatus::Pending => Self::AuthenticationPending,
            EaseBuzzPaymentStatus::Failure => Self::Failure,
            EaseBuzzPaymentStatus::Unknown => Self::Pending,
        }
    }
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct EaseBuzzErrors {
    pub message: String,
    pub path: String,
    #[serde(rename = "type")]
    pub event_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EaseBuzzPaymentsResponse {
    EaseBuzzError(EaseBuzzErrorResponse),
    EaseBuzzData(EaseBuzzPaymentsResponseData),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsResponseData {
    pub status: i32,
    pub error_desc: Option<String>,
    pub data: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSyncResponse {
    pub status: bool,
    pub msg: EaseBuzzTxnSyncMessageType,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EaseBuzzTxnSyncMessageType {
    Success(EaseBuzzSeamlessTxnResponse),
    Error(String),
    ErrorType(EaseBuzzTxnsyncErrorType),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzSeamlessTxnResponse {
    pub txnid: String,
    pub amount: String,
    pub status: String,
    pub error_desc: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzTxnsyncErrorType {
    pub error: String,
    pub error_desc: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzRefundSyncResponse {
    pub code: i32,
    pub status: String,
    pub response: EaseBuzzRefundSyncResponseData,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EaseBuzzRefundSyncResponseData {
    Success(EaseBuzzRefundSyncSuccessResponse),
    Failure(EaseBuzzRefundSyncFailureResponse),
    ValidationError(EaseBuzzRefundSyncValidationErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzRefundSyncSuccessResponse {
    pub txnid: String,
    pub easebuzz_id: String,
    pub net_amount_debit: String,
    pub amount: String,
    pub refunds: Option<Vec<RefundSyncType>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefundSyncType {
    pub refund_id: String,
    pub refund_status: String,
    pub merchant_refund_id: String,
    pub merchant_refund_date: String,
    pub refund_settled_date: Option<serde_json::Value>,
    pub refund_amount: String,
    pub arn_number: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzRefundSyncFailureResponse {
    pub status: String,
    pub message: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzRefundSyncValidationErrorResponse {
    pub validation_errors: Option<serde_json::Value>,
    pub status: bool,
    pub error_code: Option<String>,
    pub error_desc: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EaseBuzzErrorResponse {
    pub status: i32,
    pub error_code: String,
    pub error_desc: String,
}

// Stub types for unsupported flows
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzVoidRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzCaptureRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzRefundRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzRefundResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzSessionTokenRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzSessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzSetupMandateRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzSetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzAcceptDisputeRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzDefendDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzSubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct EaseBuzzSubmitEvidenceResponse;

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        EaseBuzzRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for EaseBuzzPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: EaseBuzzRouterData<
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
        let url = item.router_data.request.get_router_return_url()?;
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        match item.router_data.resource_common_data.payment_method {
            common_enums::PaymentMethod::Upi => {
                let vpa = item
                    .router_data
                    .request
                    .payment_method_data
                    .as_ref()
                    .and_then(|pm| pm.get_upi_data())
                    .and_then(|upi| upi.vpa.clone());

                Ok(Self {
                    txnid: item
                        .router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                    amount,
                    email: item.router_data.request.email.clone(),
                    phone: item.router_data.request.get_phone_number().map(|p| p.to_string()),
                    firstname: None,
                    lastname: None,
                    surl: url.to_owned(),
                    furl: url,
                    productinfo: "UPI Payment".to_string(),
                    udf1: None,
                    udf2: None,
                    udf3: None,
                    udf4: None,
                    udf5: None,
                    udf6: None,
                    udf7: None,
                    udf8: None,
                    udf9: None,
                    udf10: None,
                    address1: None,
                    address2: None,
                    city: None,
                    state: None,
                    country: None,
                    zipcode: None,
                    pg: Some("UPI".to_string()),
                    customer_unique_id: Some(customer_id.to_string()),
                    split_payments: None,
                    sub_merchant_id: None,
                    customer_name: None,
                    card_type: None,
                    card_number: None,
                    card_name: None,
                    card_cvv: None,
                    card_exp_month: None,
                    card_exp_year: None,
                    bankcode: None,
                    vpa,
                    mandate_type: None,
                    mandate_max_amount: None,
                    mandate_start_date: None,
                    mandate_end_date: None,
                    mandate_frequency: None,
                    mandate_rule_id: None,
                    mandate_reg_ref_id: None,
                    tr: None,
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                "Payment methods other than UPI are not supported".to_string(),
            )
            .into()),
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
        EaseBuzzRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for EaseBuzzPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: EaseBuzzRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let auth_type = EaseBuzzAuth::try_from(&item.router_data.connector_auth_type)?;
        let key = auth_type
            .api_key
            .ok_or(errors::ConnectorError::FailedToObtainAuthType)?
            .peek()
            .to_string();
        let salt = auth_type
            .salt
            .ok_or(errors::ConnectorError::FailedToObtainAuthType)?
            .peek()
            .to_string();

        // Generate hash - this is a simplified version, actual implementation should follow EaseBuzz hash generation logic
        let hash_string = format!(
            "{}|{}|{}|{}|{}|{}",
            key,
            item.router_data.request.connector_transaction_id.get_connector_transaction_id()
                .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?,
            amount.get_amount_as_string(),
            item.router_data.request.email.as_ref().map(|e| e.to_string()).unwrap_or_default(),
            item.router_data.request.get_phone_number().map(|p| p.to_string()).unwrap_or_default(),
            salt
        );
        let hash = format!("{:x}", md5::compute(hash_string));

        Ok(Self {
            txnid: item
                .router_data
                .request
                .connector_transaction_id
                .get_connector_transaction_id()
                .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?,
            amount,
            email: item.router_data.request.email.clone(),
            phone: item.router_data.request.get_phone_number().map(|p| p.to_string()),
            key,
            hash,
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
        EaseBuzzRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for EaseBuzzRefundSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: EaseBuzzRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth_type = EaseBuzzAuth::try_from(&item.router_data.connector_auth_type)?;
        let key = auth_type
            .api_key
            .ok_or(errors::ConnectorError::FailedToObtainAuthType)?
            .peek()
            .to_string();
        let salt = auth_type
            .salt
            .ok_or(errors::ConnectorError::FailedToObtainAuthType)?
            .peek()
            .to_string();

        let easebuzz_id = item
            .router_data
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;
        let merchant_refund_id = item
            .router_data
            .request
            .refund_id
            .get_string_repr()
            .to_string();

        // Generate hash - simplified version
        let hash_string = format!(
            "{}|{}|{}|{}",
            key,
            easebuzz_id,
            merchant_refund_id,
            salt
        );
        let hash = format!("{:x}", md5::compute(hash_string));

        Ok(Self {
            key,
            easebuzz_id,
            hash,
            merchant_refund_id,
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
    > TryFrom<ResponseRouterData<EaseBuzzPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<EaseBuzzPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        let (status, response) = match response {
            EaseBuzzPaymentsResponse::EaseBuzzError(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.error_code.to_string(),
                    status_code: item.http_code,
                    message: error_data.error_desc.clone(),
                    reason: Some(error_data.error_desc),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            EaseBuzzPaymentsResponse::EaseBuzzData(response_data) => {
                if response_data.status == 1 {
                    // Success - redirect to payment URL
                    let redirection_data = RedirectForm::Form {
                        endpoint: response_data.data,
                        method: Method::Get,
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
                            network_txn_id: None,
                            connector_response_reference_id: None,
                            incremental_authorization_allowed: None,
                            status_code: http_code,
                        }),
                    )
                } else {
                    // Error
                    (
                        common_enums::AttemptStatus::Failure,
                        Err(ErrorResponse {
                            code: response_data.status.to_string(),
                            status_code: item.http_code,
                            message: response_data.error_desc.clone().unwrap_or_default(),
                            reason: response_data.error_desc,
                            attempt_status: None,
                            connector_transaction_id: None,
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: None,
                        }),
                    )
                }
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
            + Serialize
            + Serialize,
    > TryFrom<ResponseRouterData<EaseBuzzPaymentsSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<EaseBuzzPaymentsSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        let (status, response) = match response.msg {
            EaseBuzzTxnSyncMessageType::Success(txn_response) => {
                let attempt_status = match txn_response.status.as_str() {
                    "success" => common_enums::AttemptStatus::Charged,
                    "pending" => common_enums::AttemptStatus::Pending,
                    "failure" => common_enums::AttemptStatus::Failure,
                    _ => common_enums::AttemptStatus::Pending,
                };
                (
                    attempt_status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(txn_response.txnid),
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
            EaseBuzzTxnSyncMessageType::Error(error_msg) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: "SYNC_ERROR".to_string(),
                    status_code: item.http_code,
                    message: error_msg.clone(),
                    reason: Some(error_msg),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            EaseBuzzTxnSyncMessageType::ErrorType(error_type) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_type.error,
                    status_code: item.http_code,
                    message: error_type.error_desc.clone(),
                    reason: Some(error_type.error_desc),
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
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize
            + Serialize,
    > TryFrom<ResponseRouterData<EaseBuzzRefundSyncResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<EaseBuzzRefundSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        let (status, response) = match response.response {
            EaseBuzzRefundSyncResponseData::Success(success_response) => {
                let refund_status = success_response
                    .refunds
                    .as_ref()
                    .and_then(|refunds| refunds.first())
                    .map(|r| match r.refund_status.as_str() {
                        "success" => common_enums::RefundStatus::Success,
                        "pending" => common_enums::RefundStatus::Pending,
                        "failure" => common_enums::RefundStatus::Failure,
                        _ => common_enums::RefundStatus::Pending,
                    })
                    .unwrap_or(common_enums::RefundStatus::Pending);

                (
                    common_enums::RefundStatus::Success,
                    Ok(RefundsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(success_response.txnid),
                        refund_status,
                        connector_response_reference_id: Some(success_response.easebuzz_id),
                        connector_metadata: None,
                        amount_received: Some(
                            common_utils::types::MinorUnit::from_major_unit_as_i64(
                                success_response.amount.parse().unwrap_or(0.0),
                            ),
                        ),
                        network_txn_id: None,
                        status_code: http_code,
                    }),
                )
            }
            EaseBuzzRefundSyncResponseData::Failure(failure_response) => (
                common_enums::RefundStatus::Failure,
                Err(ErrorResponse {
                    code: failure_response.status,
                    status_code: item.http_code,
                    message: failure_response.message.clone(),
                    reason: Some(failure_response.message),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            EaseBuzzRefundSyncResponseData::ValidationError(validation_error) => (
                common_enums::RefundStatus::Failure,
                Err(ErrorResponse {
                    code: validation_error.error_code.unwrap_or_default(),
                    status_code: item.http_code,
                    message: validation_error.error_desc.clone().unwrap_or_default(),
                    reason: validation_error.error_desc,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
        };

        Ok(Self {
            resource_common_data: RefundFlowData {
                status,
                ..router_data.resource_common_data
            },
            response,
            ..router_data
        })
    }
}