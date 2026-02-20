use crate::types::ResponseRouterData;
use common_enums::{AttemptStatus, RefundStatus};
use domain_types::{
    connector_flow::{Authorize, Capture, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData,
        PaymentsSyncData, PaymentVoidData, RefundFlowData, RefundsData, RefundsResponseData,
        ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
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

// =============================================================================
// AUTHORIZE FLOW
// =============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayAuthorizeRequest {
    pub transaction_reference: String,
    pub merchant: WorldpayMerchant,
    pub narrative: WorldpayNarrative,
    pub value: WorldpayValue,
    #[serde(rename = "paymentMethod")]
    pub payment_method: WorldpayPaymentMethod,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayMerchant {
    pub entity: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayNarrative {
    pub line1: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayValue {
    pub currency: String,
    pub amount: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayPaymentMethod {
    #[serde(rename = "type")]
    pub payment_method_type: String,
    pub card: Option<WorldpayCard>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayCard {
    pub number: Secret<String>,
    pub expiry_month: Secret<String>,
    pub expiry_year: Secret<String>,
    pub cvv: Secret<String>,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    > for WorldpayAuthorizeRequest
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
        let card = match &item.request.payment_method_data {
            PaymentMethodData::Card(card) => Ok(card),
            _ => Err(error_stack::report!(
                errors::ConnectorError::NotImplemented("Payment method not supported".to_string())
            )),
        }?;

        Ok(Self {
            transaction_reference: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            merchant: WorldpayMerchant {
                entity: "default".to_string(),
            },
            narrative: WorldpayNarrative {
                line1: item
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            },
            value: WorldpayValue {
                currency: item.request.currency.to_string(),
                amount: item.request.minor_amount.get_amount_as_i64(),
            },
            payment_method: WorldpayPaymentMethod {
                payment_method_type: "card".to_string(),
                card: Some(WorldpayCard {
                    number: Secret::new(card.card_number.peek().to_string()),
                    expiry_month: card.card_exp_month.clone(),
                    expiry_year: card.card_exp_year.clone(),
                    cvv: card.card_cvc.clone(),
                }),
            },
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayAuthorizeResponse {
    pub payment_id: String,
    pub status: String,
    pub transaction_reference: Option<String>,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            WorldpayAuthorizeResponse,
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
            WorldpayAuthorizeResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.status.as_str() {
            "authorized" => AttemptStatus::Authorized,
            "captured" => AttemptStatus::Charged,
            "refused" => AttemptStatus::Failure,
            "cancelled" => AttemptStatus::Voided,
            "pending" => AttemptStatus::Pending,
            _ => AttemptStatus::Pending,
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.payment_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.transaction_reference,
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

// =============================================================================
// PSYNC FLOW
// =============================================================================

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayPSyncResponse {
    pub payment_id: String,
    pub status: String,
    pub transaction_reference: Option<String>,
    pub value: Option<WorldpayValue>,
}

impl<F> TryFrom<ResponseRouterData<WorldpayPSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
where
    F: Clone,
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<WorldpayPSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.status.as_str() {
            "authorized" => AttemptStatus::Authorized,
            "captured" => AttemptStatus::Charged,
            "refused" => AttemptStatus::Failure,
            "cancelled" => AttemptStatus::Voided,
            "pending" => AttemptStatus::Pending,
            _ => AttemptStatus::Pending,
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.payment_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.transaction_reference,
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

// =============================================================================
// CAPTURE FLOW
// =============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayCaptureRequest {
    pub value: WorldpayValue,
}

impl TryFrom<&RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>
    for WorldpayCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            value: WorldpayValue {
                currency: item.request.currency.to_string(),
                amount: item.request.minor_amount_to_capture.get_amount_as_i64(),
            },
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayCaptureResponse {
    pub capture_id: String,
    pub status: String,
}

impl TryFrom<ResponseRouterData<WorldpayCaptureResponse, Self>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<WorldpayCaptureResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.status.as_str() {
            "captured" => AttemptStatus::Charged,
            "pending" => AttemptStatus::Pending,
            "failed" => AttemptStatus::CaptureFailed,
            _ => AttemptStatus::Pending,
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.capture_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
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

// =============================================================================
// REFUND FLOW
// =============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayRefundRequest {
    pub value: WorldpayValue,
}

impl TryFrom<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>
    for WorldpayRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            value: WorldpayValue {
                currency: item.request.currency.to_string(),
                amount: item.request.minor_refund_amount.get_amount_as_i64(),
            },
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayRefundResponse {
    pub refund_id: String,
    pub status: String,
}

impl TryFrom<ResponseRouterData<WorldpayRefundResponse, Self>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<WorldpayRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.status.as_str() {
            "refunded" => RefundStatus::Success,
            "pending" => RefundStatus::Pending,
            "failed" => RefundStatus::Failure,
            _ => RefundStatus::Pending,
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.refund_id,
                refund_status: status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// =============================================================================
// VOID FLOW
// =============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayVoidRequest {
    pub reason: Option<String>,
}

impl TryFrom<&RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>
    for WorldpayVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            reason: item.request.cancellation_reason.clone(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayVoidResponse {
    pub cancellation_id: String,
    pub status: String,
}

impl TryFrom<ResponseRouterData<WorldpayVoidResponse, Self>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<WorldpayVoidResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.status.as_str() {
            "cancelled" => AttemptStatus::Voided,
            "pending" => AttemptStatus::VoidInitiated,
            _ => AttemptStatus::VoidInitiated,
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.cancellation_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
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
