use std::collections::HashMap;

use cards::CardNumber;
use common_utils::{
    ext_traits::OptionExt,
    pii,
    request::Method,
    types::{MinorUnit, StringMinorUnit},
};
use domain_types::{
    connector_flow::{self, Authorize, PSync, RSync, RepeatPayment, SetupMandate, Void, Capture},
    connector_types::{
        MandateReference, MandateReferenceId, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData,
        ResponseId, SetupMandateRequestData,
    },
    errors::{self, ConnectorError},
    payment_method_data::{
        PaymentMethodData, PaymentMethodDataTypes, RawCardNumber,
        WalletData as WalletDataPaymentMethod,
    },
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret, PeekInterface};
use serde::{Deserialize, Serialize};
use strum::Display;

use common_enums::enums;
use common_utils::types::FloatMajorUnit;
use hyperswitch_masking as masking;

use crate::{
    connectors::forte::ForteRouterData,
    types::ResponseRouterData,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FortePaymentsRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    pub amount: FloatMajorUnit,
    pub currency: String,
    pub payment_method_data: T,
}

// TryFrom implementation for FortePaymentsRequest
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
    > for FortePaymentsRequest<T>
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
        Ok(Self {
            amount: utils::to_currency_base_unit(item.request.amount, item.request.currency)?,
            currency: item.request.currency.to_string(),
            payment_method_data: item.request.payment_method_data,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FortePaymentsResponse {
    pub transaction_id: String,
    pub status: String,
    pub response: ForteResponseDetails,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForteResponseDetails {
    pub response_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FortePaymentsSyncResponse {
    pub transaction_id: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForteCancelResponse {
    pub transaction_id: String,
    pub response: ForteResponseDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForteRefundRequest {
    pub amount: FloatMajorUnit,
    pub transaction_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundResponse {
    pub refund_id: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundSyncResponse {
    pub refund_id: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForteCaptureRequest {
    pub amount: FloatMajorUnit,
    pub transaction_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForteCaptureResponse {
    pub transaction_id: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForteCancelRequest {
    pub transaction_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForteSyncRequest {
    pub transaction_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForteRefundSyncRequest {
    pub refund_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForteAuthType {
    pub api_key: masking::Secret<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForteErrorResponse {
    pub error: ForteError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForteError {
    pub code: String,
    pub message: String,
    pub reason: Option<String>,
}

impl TryFrom<&ConnectorAuthType> for ForteAuthType {
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(domain_types::errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

impl<T> TryFrom<ResponseRouterData<FortePaymentsResponse, T>>
    for domain_types::connector_types::PaymentsResponseData
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FortePaymentsResponse, T>,
    ) -> Result<Self, Self::Error> {
        let response_code = item.response.response.response_code;
        let _action = item.response.action;
        let transaction_id = &item.response.transaction_id;

        let _status = status_from_string(item.response.status);

        Ok(Self::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(transaction_id.to_string()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(transaction_id.to_string()),
            incremental_authorization_allowed: None,
            status_code: response_code.parse().unwrap_or(200),
        })
    }
}

impl<T> TryFrom<ResponseRouterData<FortePaymentsSyncResponse, T>>
    for domain_types::connector_types::PaymentsResponseData
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FortePaymentsSyncResponse, T>,
    ) -> Result<Self, Self::Error> {
        let transaction_id = &item.response.transaction_id;

        Ok(Self::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(transaction_id.to_string()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(transaction_id.to_string()),
            incremental_authorization_allowed: None,
            status_code: 200,
        })
    }
}

impl<T> TryFrom<ResponseRouterData<ForteCancelResponse, T>>
    for domain_types::connector_types::PaymentsResponseData
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<ForteCancelResponse, T>,
    ) -> Result<Self, Self::Error> {
        let transaction_id = &item.response.transaction_id;

        Ok(Self::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(transaction_id.to_string()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(transaction_id.to_string()),
            incremental_authorization_allowed: None,
            status_code: 200,
        })
    }
}

impl<T> TryFrom<ResponseRouterData<ForteCaptureResponse, T>>
    for domain_types::connector_types::PaymentsResponseData
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<ForteCaptureResponse, T>,
    ) -> Result<Self, Self::Error> {
        let transaction_id = &item.response.transaction_id;

        Ok(Self::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(transaction_id.to_string()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(transaction_id.to_string()),
            incremental_authorization_allowed: None,
            status_code: 200,
        })
    }
}

impl<T> TryFrom<ResponseRouterData<RefundResponse, T>>
    for domain_types::connector_types::RefundsResponseData
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<RefundResponse, T>,
    ) -> Result<Self, Self::Error> {
        let refund_id = &item.response.refund_id;

        Ok(Self {
            connector_refund_id: refund_id.to_string(),
            refund_status: enums::RefundStatus::Success,
            status_code: item.http_code,
        })
    }
}

impl<T> TryFrom<ResponseRouterData<RefundSyncResponse, T>>
    for domain_types::connector_types::RefundsResponseData
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<RefundSyncResponse, T>,
    ) -> Result<Self, Self::Error> {
        let refund_id = &item.response.refund_id;

        Ok(Self {
            connector_refund_id: refund_id.to_string(),
            refund_status: enums::RefundStatus::Success,
            status_code: item.http_code,
        })
    }
}

// Custom implementation for String to AttemptStatus conversion
pub fn status_from_string(status: String) -> enums::AttemptStatus {
    match status.as_str() {
        "completed" | "success" => enums::AttemptStatus::Charged,
        "pending" => enums::AttemptStatus::Pending,
        "failed" => enums::AttemptStatus::Failure,
        "cancelled" => enums::AttemptStatus::Voided,
        _ => enums::AttemptStatus::Pending,
    }
}