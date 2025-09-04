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

use crate::{connectors::forte::ForteRouterData, types::ResponseRouterData};
use common_enums;

#[derive(Debug, Serialize)]
pub struct ForteAuthType {
    pub api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for ForteAuthType {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct FortePaymentsRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    pub amount: i64,
    pub currency: String,
    pub payment_method: FortePaymentMethod<T>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FortePaymentMethod<T: PaymentMethodDataTypes> {
    pub card: Option<ForteCard<T>>,
}

#[derive(Debug, Serialize)]
pub struct ForteCard<T: PaymentMethodDataTypes> {
    pub number: RawCardNumber<T>,
    pub exp_month: Secret<String>,
    pub exp_year: Secret<String>,
    pub cvc: Secret<String>,
    pub name: Option<Secret<String>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FortePaymentsResponse {
    pub id: String,
    pub status: String,
    pub amount: i64,
    pub currency: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForteErrorResponse {
    pub error: ForteError,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForteError {
    pub code: Option<String>,
    pub message: Option<String>,
    pub details: Option<String>,
}

// Authorize flow implementation
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        ForteRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for FortePaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ForteRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let payment_method = match &item.router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => FortePaymentMethod {
                card: Some(ForteCard {
                    number: card.card_number.clone(),
                    exp_month: card.card_exp_month.clone(),
                    exp_year: card.card_exp_year.clone(),
                    cvc: card.card_cvc.clone(),
                    name: card.card_holder_name.clone(),
                }),
            },
            _ => Err(ConnectorError::NotImplemented("Payment method not supported".to_string()))?,
        };

        Ok(Self {
            amount: item.router_data.request.amount,
            currency: item.router_data.request.currency.to_string(),
            payment_method,
            description: item.router_data.resource_common_data.description.clone(),
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
        ResponseRouterData<
            FortePaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            FortePaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.status.as_str() {
            "succeeded" => common_enums::AttemptStatus::Charged,
            "pending" => common_enums::AttemptStatus::Pending,
            "failed" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Pending,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,

                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// PSync flow implementations
#[derive(Debug, Serialize)]
pub struct ForteSyncRequest {
    pub transaction_id: String,
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
        ForteRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for ForteSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ForteRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            transaction_id: item.router_data.request.get_connector_transaction_id()?,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForteSyncResponse {
    pub id: String,
    pub status: String,
    pub amount: i64,
    pub currency: String,
}

impl<F> TryFrom<ResponseRouterData<ForteSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<ForteSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.status.as_str() {
            "succeeded" => common_enums::AttemptStatus::Charged,
            "pending" => common_enums::AttemptStatus::Pending,
            "failed" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Pending,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,

                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// Refund flow implementations
#[derive(Debug, Serialize)]
pub struct ForteRefundRequest {
    pub transaction_id: String,
    pub amount: i64,
    pub reason: Option<String>,
}

impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        ForteRouterData<RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for ForteRefundRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ForteRouterData<
            RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            transaction_id: item.router_data.request.connector_transaction_id.clone(),
            amount: item.router_data.request.refund_amount,
            reason: item.router_data.request.reason.clone(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForteRefundResponse {
    pub id: String,
    pub status: String,
    pub amount: i64,
}

impl<F> TryFrom<ResponseRouterData<ForteRefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<ForteRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.status.as_str() {
            "succeeded" => common_enums::RefundStatus::Success,
            "pending" => common_enums::RefundStatus::Pending,
            "failed" => common_enums::RefundStatus::Failure,
            _ => common_enums::RefundStatus::Pending,
        };

        Ok(Self {
            resource_common_data: RefundFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id,
                refund_status: status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// RSync flow implementations
#[derive(Debug, Serialize)]
pub struct ForteRSyncRequest {
    pub refund_id: String,
}

impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        ForteRouterData<RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>, T>,
    > for ForteRSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ForteRouterData<
            RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            refund_id: item.router_data.request.connector_refund_id.clone(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForteRSyncResponse {
    pub id: String,
    pub status: String,
    pub amount: i64,
}

impl<F> TryFrom<ResponseRouterData<ForteRSyncResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<ForteRSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.status.as_str() {
            "succeeded" => common_enums::RefundStatus::Success,
            "pending" => common_enums::RefundStatus::Pending,
            "failed" => common_enums::RefundStatus::Failure,
            _ => common_enums::RefundStatus::Pending,
        };

        Ok(Self {
            resource_common_data: RefundFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id,
                refund_status: status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// Capture flow implementations
#[derive(Debug, Serialize)]
pub struct ForteCaptureRequest {
    pub transaction_id: String,
    pub amount: i64,
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
        ForteRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for ForteCaptureRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ForteRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            transaction_id: item.router_data.request.get_connector_transaction_id()?,
            amount: item.router_data.request.amount_to_capture,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForteCaptureResponse {
    pub id: String,
    pub status: String,
    pub amount: i64,
}

impl<F, T> TryFrom<ResponseRouterData<ForteCaptureResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<ForteCaptureResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.status.as_str() {
            "succeeded" => common_enums::AttemptStatus::Charged,
            "pending" => common_enums::AttemptStatus::Pending,
            "failed" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Pending,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,

                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// Void flow implementations
#[derive(Debug, Serialize)]
pub struct ForteVoidRequest {
    pub transaction_id: String,
    pub reason: Option<String>,
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
        ForteRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for ForteVoidRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ForteRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            transaction_id: item.router_data.request.connector_transaction_id.clone(),
            reason: item.router_data.request.cancellation_reason.clone(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForteVoidResponse {
    pub id: String,
    pub status: String,
}

impl<F, T> TryFrom<ResponseRouterData<ForteVoidResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(item: ResponseRouterData<ForteVoidResponse, Self>) -> Result<Self, Self::Error> {
        let status = match item.response.status.as_str() {
            "succeeded" => common_enums::AttemptStatus::Voided,
            "pending" => common_enums::AttemptStatus::Pending,
            "failed" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Pending,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,

                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}