use crate::types::ResponseRouterData;
use common_enums::{AttemptStatus, RefundStatus};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundsData, RefundsResponseData,
        ResponseId,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct WorldpayAuthType {
    pub api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for WorldpayAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorldpayErrorResponse {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum WorldpayPaymentStatus {
    Authorized,
    Captured,
    Refunded,
    Cancelled,
    Pending,
    Failed,
    Declined,
    Processing,
    Succeeded,
    Error,
}

impl From<WorldpayPaymentStatus> for AttemptStatus {
    fn from(status: WorldpayPaymentStatus) -> Self {
        match status {
            WorldpayPaymentStatus::Authorized => AttemptStatus::Authorized,
            WorldpayPaymentStatus::Captured => AttemptStatus::Charged,
            WorldpayPaymentStatus::Refunded => AttemptStatus::Charged,
            WorldpayPaymentStatus::Cancelled => AttemptStatus::Voided,
            WorldpayPaymentStatus::Pending | WorldpayPaymentStatus::Processing => {
                AttemptStatus::Pending
            }
            WorldpayPaymentStatus::Failed | WorldpayPaymentStatus::Declined => AttemptStatus::Failure,
            WorldpayPaymentStatus::Succeeded => AttemptStatus::Charged,
            WorldpayPaymentStatus::Error => AttemptStatus::Failure,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct WorldpayPaymentsRequest {
    pub amount: i64,
    pub currency: String,
    pub reference: String,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    > for WorldpayPaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: item.request.minor_amount.get_amount_as_i64(),
            currency: item.request.currency.to_string(),
            reference: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayPaymentsResponse {
    pub id: String,
    pub status: WorldpayPaymentStatus,
    pub amount: i64,
    pub currency: String,
    pub reference: Option<String>,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            WorldpayPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            WorldpayPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let status: AttemptStatus = item.response.status.into();

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.reference,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

#[derive(Debug, Serialize)]
pub struct WorldpayCaptureRequest {
    pub amount: i64,
    pub currency: String,
    pub reference: String,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    > for WorldpayCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: item.request.minor_amount_to_capture.get_amount_as_i64(),
            currency: item.request.currency.to_string(),
            reference: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayCaptureResponse {
    pub id: String,
    pub status: WorldpayPaymentStatus,
    pub amount: i64,
    pub currency: String,
    pub reference: Option<String>,
}

impl<F>
    TryFrom<
        ResponseRouterData<
            WorldpayCaptureResponse,
            RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            WorldpayCaptureResponse,
            RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status: AttemptStatus = item.response.status.into();
        let amount_captured = if status == AttemptStatus::Charged {
            Some(item.response.amount)
        } else {
            None
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.reference,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                amount_captured,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

#[derive(Debug, Serialize)]
pub struct WorldpayRefundRequest {
    pub amount: i64,
    pub currency: String,
    pub reference: String,
}

impl<F, T: PaymentMethodDataTypes>
    TryFrom<&RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>>
    for WorldpayRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: item.request.minor_refund_amount.get_amount_as_i64(),
            currency: item.request.currency.to_string(),
            reference: item.request.refund_id.clone(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayRefundResponse {
    pub id: String,
    pub status: WorldpayPaymentStatus,
    pub amount: i64,
    pub currency: String,
    pub reference: Option<String>,
}

impl<F>
    TryFrom<
        ResponseRouterData<
            WorldpayRefundResponse,
            RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            WorldpayRefundResponse,
            RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let refund_status = match item.response.status {
            WorldpayPaymentStatus::Succeeded | WorldpayPaymentStatus::Refunded => {
                RefundStatus::Success
            }
            WorldpayPaymentStatus::Pending | WorldpayPaymentStatus::Processing => {
                RefundStatus::Pending
            }
            _ => RefundStatus::Failure,
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id,
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

#[derive(Debug, Serialize)]
pub struct WorldpayVoidRequest {
    pub reference: String,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    > for WorldpayVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            reference: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayVoidResponse {
    pub id: String,
    pub status: WorldpayPaymentStatus,
    pub reference: Option<String>,
}

impl<F>
    TryFrom<
        ResponseRouterData<
            WorldpayVoidResponse,
            RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            WorldpayVoidResponse,
            RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status: AttemptStatus = item.response.status.into();

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.reference,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayPSyncResponse {
    pub id: String,
    pub status: WorldpayPaymentStatus,
    pub amount: i64,
    pub currency: String,
    pub reference: Option<String>,
}

impl<F>
    TryFrom<
        ResponseRouterData<
            WorldpayPSyncResponse,
            RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            WorldpayPSyncResponse,
            RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status: AttemptStatus = item.response.status.into();

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.reference,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}
