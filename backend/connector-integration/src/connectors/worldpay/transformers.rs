use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    errors::CustomResult,
    types::MinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, Capture, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundsData, RefundsResponseData,
        ResponseId,
    },
    errors::ConnectorError,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    utils,
};
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{
    connectors::worldpay::WorldpayRouterData,
    types::ResponseRouterData,
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayCard<T: PaymentMethodDataTypes> {
    pub card_number: RawCardNumber<T>,
    pub card_expiry_date: Secret<String>,
    pub card_holder_name: Option<Secret<String>>,
    pub cvc: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayAuthorizeRequest<T: PaymentMethodDataTypes> {
    pub token: Option<String>,
    pub card: Option<WorldpayCard<T>>,
    pub amount: MinorUnit,
    pub currency: common_enums::Currency,
    pub order_description: Option<String>,
    pub customer_order_code: String,
    pub settlement_reference: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayCaptureRequest {
    pub amount: MinorUnit,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayRefundRequest {
    pub amount: MinorUnit,
    pub reference: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayVoidRequest {
    pub reference: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayAuthorizeResponse {
    pub payment_id: String,
    pub status: WorldpayPaymentStatus,
    pub amount: MinorUnit,
    pub currency: common_enums::Currency,
    pub description: Option<String>,
    pub reference: Option<String>,
}

pub type WorldpayPSyncResponse = WorldpayAuthorizeResponse;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayCaptureResponse {
    pub settlement_id: String,
    pub status: WorldpayPaymentStatus,
    pub amount: MinorUnit,
    pub currency: common_enums::Currency,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayRefundResponse {
    pub refund_id: String,
    pub status: WorldpayRefundStatus,
    pub amount: MinorUnit,
    pub currency: common_enums::Currency,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayVoidResponse {
    pub cancellation_id: String,
    pub status: WorldpayPaymentStatus,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorldpayPaymentStatus {
    Success,
    Authorized,
    Failed,
    Cancelled,
    Refunded,
    Settled,
    Pending,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorldpayRefundStatus {
    Success,
    Failed,
    Pending,
}

impl From<WorldpayPaymentStatus> for common_enums::AttemptStatus {
    fn from(status: WorldpayPaymentStatus) -> Self {
        match status {
            WorldpayPaymentStatus::Success => Self::Charged,
            WorldpayPaymentStatus::Authorized => Self::Authorized,
            WorldpayPaymentStatus::Failed => Self::Failure,
            WorldpayPaymentStatus::Cancelled => Self::Voided,
            WorldpayPaymentStatus::Refunded => Self::Charged,
            WorldpayPaymentStatus::Settled => Self::Charged,
            WorldpayPaymentStatus::Pending => Self::Pending,
        }
    }
}

impl From<WorldpayRefundStatus> for common_enums::RefundStatus {
    fn from(status: WorldpayRefundStatus) -> Self {
        match status {
            WorldpayRefundStatus::Success => Self::Success,
            WorldpayRefundStatus::Failed => Self::Failure,
            WorldpayRefundStatus::Pending => Self::Pending,
        }
    }
}

pub struct WorldpayAuthType {
    pub username: Secret<String>,
    pub password: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for WorldpayAuthType {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        if let ConnectorAuthType::BodyKey { api_key, key1 } = auth_type {
            Ok(Self {
                username: api_key.to_owned(),
                password: key1.to_owned(),
            })
        } else {
            Err(ConnectorError::FailedToObtainAuthType.into())
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        WorldpayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for WorldpayAuthorizeRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: WorldpayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let card_data = match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(ccard) => {
                let expiry_date = format!(
                    "{}-{}",
                    ccard.card_exp_year.expose(),
                    ccard.card_exp_month.expose()
                );
                Ok(WorldpayCard {
                    card_number: ccard.card_number.clone(),
                    card_expiry_date: Secret::new(expiry_date),
                    card_holder_name: ccard.card_holder_name.clone(),
                    cvc: ccard.card_cvc.clone(),
                })
            }
            _ => Err(ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("worldpay"),
            )),
        }?;

        Ok(Self {
            token: None,
            card: Some(card_data),
            amount: item.router_data.request.minor_amount,
            currency: item.router_data.request.currency,
            order_description: item.router_data.request.order_category.clone(),
            customer_order_code: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            settlement_reference: None,
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        WorldpayRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for WorldpayCaptureRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: WorldpayRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: item.router_data.request.minor_amount_to_capture.to_owned(),
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        WorldpayRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for WorldpayRefundRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: WorldpayRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: item.router_data.request.minor_refund_amount.to_owned(),
            reference: item.router_data.request.refund_id.clone(),
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        WorldpayRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for WorldpayVoidRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: WorldpayRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            reference: item.router_data.request.connector_transaction_id.clone(),
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<WorldpayAuthorizeResponse, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<WorldpayAuthorizeResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = common_enums::AttemptStatus::from(item.response.status.clone());

        if status == common_enums::AttemptStatus::Failure {
            let error_response = ErrorResponse {
                status_code: item.http_code,
                code: NO_ERROR_CODE.to_string(),
                message: NO_ERROR_MESSAGE.to_string(),
                reason: Some("Payment failed".to_string()),
                attempt_status: None,
                connector_transaction_id: Some(item.response.payment_id.clone()),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            };

            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..item.router_data.resource_common_data
                },
                response: Err(error_response),
                ..item.router_data
            });
        }

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(item.response.payment_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: item.response.reference.clone(),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(payments_response_data),
            ..item.router_data
        })
    }
}

impl<F> TryFrom<ResponseRouterData<WorldpayPSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<WorldpayPSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = common_enums::AttemptStatus::from(item.response.status.clone());

        let error_response = if status == common_enums::AttemptStatus::Failure {
            Some(ErrorResponse {
                status_code: item.http_code,
                code: NO_ERROR_CODE.to_string(),
                message: NO_ERROR_MESSAGE.to_string(),
                reason: Some("Payment failed".to_string()),
                attempt_status: None,
                connector_transaction_id: Some(item.response.payment_id.clone()),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            })
        } else {
            None
        };

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(item.response.payment_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: item.response.reference.clone(),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: error_response.map_or_else(|| Ok(payments_response_data), Err),
            ..item.router_data
        })
    }
}

impl<F> TryFrom<ResponseRouterData<WorldpayCaptureResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<WorldpayCaptureResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = common_enums::AttemptStatus::from(item.response.status.clone());

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(item.response.settlement_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(payments_response_data),
            ..item.router_data
        })
    }
}

impl<F> TryFrom<ResponseRouterData<WorldpayVoidResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<WorldpayVoidResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = common_enums::AttemptStatus::from(item.response.status.clone());

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(item.response.cancellation_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(payments_response_data),
            ..item.router_data
        })
    }
}

impl<F> TryFrom<ResponseRouterData<WorldpayRefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<WorldpayRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let refund_status = common_enums::RefundStatus::from(item.response.status.clone());

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.refund_id.clone(),
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayErrorResponse {
    pub error_name: String,
    pub message: String,
    pub code: String,
}
