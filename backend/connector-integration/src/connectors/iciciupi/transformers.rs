use std::collections::HashMap;

use common_utils::{
    errors::CustomResult, ext_traits::ValueExt, request::Method, types::StringMinorUnit,
    Email,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId},
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

use crate::{connectors::iciciupi::IciciUpiRouterData, types::ResponseRouterData};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiAuth {
    pub api_key: Secret<String>,
    pub aggregator_id: Secret<String>,
    pub merchant_id: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for IciciUpiAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, .. } => {
                let auth_data: IciciUpiAuth = api_key
                    .parse_value("IciciUpiAuth")
                    .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
                Ok(auth_data)
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiPaymentsRequest {
    pub payer_va: String,
    pub amount: StringMinorUnit,
    pub note: Option<String>,
    pub collect_by_date: Option<String>,
    pub merchant_id: String,
    pub merchant_name: Option<String>,
    pub sub_merchant_id: Option<String>,
    pub sub_merchant_name: Option<String>,
    pub terminal_id: Option<String>,
    pub merchant_tran_id: String,
    pub bill_number: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiPaymentsSyncRequest {
    pub merchant_id: String,
    pub sub_merchant_id: Option<String>,
    pub terminal_id: Option<String>,
    pub transaction_type: Option<String>,
    pub merchant_tran_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiRefundRequest {
    pub merchant_id: String,
    pub sub_merchant_id: Option<String>,
    pub terminal_id: Option<String>,
    pub original_bank_rrn: String,
    pub merchant_tran_id: String,
    pub original_merchant_tran_id: String,
    pub refund_amount: StringMinorUnit,
    pub payee_va: String,
    pub note: Option<String>,
    pub online_refund: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiVerifyVpaRequest {
    pub profile_id: String,
    pub virtual_address: String,
    pub channel_code: String,
    pub device_id: String,
    pub mobile: String,
    pub seq_no: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiMandateRequest {
    pub request_id: String,
    pub service: String,
    pub encrypted_key: String,
    pub oaep_hashing_algorithm: String,
    pub iv: String,
    pub encrypted_data: String,
    pub client_info: String,
    pub optional_param: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiMandatePayload {
    pub merchant_id: String,
    pub sub_merchant_id: Option<String>,
    pub terminal_id: Option<String>,
    pub merchant_name: String,
    pub sub_merchant_name: Option<String>,
    pub payer_va: String,
    pub amount: StringMinorUnit,
    pub note: Option<String>,
    pub collect_by_date: Option<String>,
    pub merchant_tran_id: String,
    pub bill_number: Option<String>,
    pub validity_start_date: Option<String>,
    pub validity_end_date: Option<String>,
    pub amount_limit: Option<String>,
    pub remark: Option<String>,
    pub request_type: String,
    pub frequency: Option<String>,
    pub auto_execute: Option<String>,
    pub debit_day: Option<String>,
    pub debit_rule: Option<String>,
    pub revokable: Option<String>,
    pub blockfund: Option<String>,
    pub purpose: Option<String>,
    pub umn: Option<String>,
    pub validate_payer_acc_flag: Option<String>,
    pub payer_account: Option<String>,
    pub payer_ifsc: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiExecuteMandatePayload {
    pub merchant_id: String,
    pub sub_merchant_id: Option<String>,
    pub terminal_id: Option<String>,
    pub merchant_name: String,
    pub sub_merchant_name: Option<String>,
    pub amount: StringMinorUnit,
    pub merchant_tran_id: String,
    pub bill_number: Option<String>,
    pub remark: Option<String>,
    pub retry_count: Option<String>,
    pub mandate_seq_no: Option<String>,
    pub umn: String,
    pub purpose: Option<String>,
}

// Response types
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiPaymentsResponse {
    pub act_code: Option<String>,
    pub merchant_id: Option<String>,
    pub sub_merchant_id: Option<String>,
    pub terminal_id: Option<String>,
    pub amount: Option<StringMinorUnit>,
    pub success: bool,
    pub message: String,
    pub merchant_tran_id: Option<String>,
    pub bank_rrn: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiPaymentsSyncResponse {
    pub act_code: Option<String>,
    pub merchant_id: Option<String>,
    pub sub_merchant_id: Option<String>,
    pub terminal_id: Option<String>,
    pub amount: Option<StringMinorUnit>,
    pub success: bool,
    pub message: String,
    pub merchant_tran_id: Option<String>,
    pub bank_rrn: Option<String>,
    pub status: Option<String>,
    pub response_code: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiRefundResponse {
    pub merchant_id: Option<String>,
    pub sub_merchant_id: Option<String>,
    pub terminal_id: Option<String>,
    pub success: bool,
    pub response: Option<String>,
    pub status: String,
    pub message: String,
    pub merchant_tran_id: String,
    pub original_bank_rrn: Option<String>,
    pub resp_code_description: Option<String>,
    pub act_code: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiVerifyVpaResponse {
    pub success: bool,
    pub response: String,
    pub message: String,
    pub bank_rrn: String,
    pub upi_tranlog_id: String,
    pub user_profile: String,
    pub seq_no: String,
    pub mobile_app_data: IciciUpiMobileAppData,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum IciciUpiMobileAppData {
    String(String),
    Object(serde_json::Value),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiMandateResponse {
    pub response: String,
    pub merchant_id: Option<String>,
    pub sub_merchant_id: Option<String>,
    pub terminal_id: Option<String>,
    pub amount: Option<StringMinorUnit>,
    pub success: bool,
    pub message: String,
    pub merchant_tran_id: Option<String>,
    pub bank_rrn: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiErrorResponse {
    pub error_code: String,
    pub error_message: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum IciciUpiPaymentsResponseEnum {
    Success(IciciUpiPaymentsResponse),
    Error(IciciUpiErrorResponse),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum IciciUpiPaymentsSyncResponseEnum {
    Success(IciciUpiPaymentsSyncResponse),
    Error(IciciUpiErrorResponse),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum IciciUpiRefundResponseEnum {
    Success(IciciUpiRefundResponse),
    Error(IciciUpiErrorResponse),
}

// Request transformers
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> TryFrom<IciciUpiRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for IciciUpiPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: IciciUpiRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = IciciUpiAuth::try_from(&item.router_data.connector_auth_type)?;
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Extract UPI virtual address from payment method data
        let payer_va = item
            .router_data
            .request
            .payment_method_data
            .as_ref()
            .and_then(|pm| pm.upi.as_ref())
            .and_then(|upi| upi.vpa.clone())
            .ok_or(ConnectorError::MissingRequiredField {
                field_name: "payer_va",
            })?;

        Ok(Self {
            payer_va,
            amount,
            note: item.router_data.request.description.clone(),
            collect_by_date: None, // Can be configured based on requirements
            merchant_id: auth.merchant_id.expose().clone(),
            merchant_name: None, // Can be extracted from merchant config
            sub_merchant_id: None,
            sub_merchant_name: None,
            terminal_id: None,
            merchant_tran_id: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            bill_number: None,
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
> TryFrom<IciciUpiRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for IciciUpiPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: IciciUpiRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = IciciUpiAuth::try_from(&item.router_data.connector_auth_type)?;

        Ok(Self {
            merchant_id: auth.merchant_id.expose().clone(),
            sub_merchant_id: None,
            terminal_id: None,
            transaction_type: None,
            merchant_tran_id: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
        })
    }
}

// Response transformers
impl<
    F,
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize
        + Serialize,
> TryFrom<ResponseRouterData<IciciUpiPaymentsResponseEnum, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<IciciUpiPaymentsResponseEnum, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            IciciUpiPaymentsResponseEnum::Success(response_data) => {
                let attempt_status = if response_data.success {
                    common_enums::AttemptStatus::Charged
                } else {
                    common_enums::AttemptStatus::Failure
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
                        network_txn_id: response_data.bank_rrn.clone(),
                        connector_response_reference_id: response_data.merchant_tran_id.clone(),
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            IciciUpiPaymentsResponseEnum::Error(error_data) => (
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
    F,
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize
        + Serialize,
> TryFrom<ResponseRouterData<IciciUpiPaymentsSyncResponseEnum, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<IciciUpiPaymentsSyncResponseEnum, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            IciciUpiPaymentsSyncResponseEnum::Success(response_data) => {
                let attempt_status = if response_data.success {
                    common_enums::AttemptStatus::Charged
                } else {
                    match response_data.status.as_deref() {
                        Some("PENDING") => common_enums::AttemptStatus::Pending,
                        Some("AUTHENTICATION_PENDING") => common_enums::AttemptStatus::AuthenticationPending,
                        _ => common_enums::AttemptStatus::Failure,
                    }
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
                        network_txn_id: response_data.bank_rrn.clone(),
                        connector_response_reference_id: response_data.merchant_tran_id.clone(),
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            IciciUpiPaymentsSyncResponseEnum::Error(error_data) => (
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

// Helper functions
pub fn get_base_url(is_test_mode: bool) -> &'static str {
    if is_test_mode {
        crate::connectors::iciciupi::constants::endpoints::STAGING_BASE_URL
    } else {
        crate::connectors::iciciupi::constants::endpoints::PRODUCTION_BASE_URL
    }
}

pub fn get_collect_pay_endpoint(merchant_id: &str) -> String {
    format!(
        "{}{}",
        crate::connectors::iciciupi::constants::endpoints::COLLECT_PAY_V2,
        merchant_id
    )
}

pub fn get_transaction_status_endpoint(merchant_id: &str) -> String {
    format!(
        "{}{}",
        crate::connectors::iciciupi::constants::endpoints::TRANSACTION_STATUS,
        merchant_id
    )
}

pub fn get_refund_endpoint(merchant_id: &str) -> String {
    format!(
        "{}{}",
        crate::connectors::iciciupi::constants::endpoints::REFUND,
        merchant_id
    )
}