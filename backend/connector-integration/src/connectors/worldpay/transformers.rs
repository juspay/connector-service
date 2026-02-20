use crate::types::ResponseRouterData;
use common_enums::{AttemptStatus, RefundStatus};
use common_utils::types::MinorUnit;
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundsData, RefundsResponseData,
        ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
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

// ============================================================================
// PAYMENT METHOD TYPES
// ============================================================================

#[derive(Debug, Serialize)]
pub struct WorldpayCardPaymentMethod {
    #[serde(rename = "type")]
    pub payment_method_type: String,
    pub name: String,
    pub number: String,
    #[serde(rename = "expiryMonth")]
    pub expiry_month: String,
    #[serde(rename = "expiryYear")]
    pub expiry_year: String,
    pub cvv: String,
}

// ============================================================================
// AUTHORIZE FLOW
// ============================================================================

#[derive(Debug, Serialize)]
pub struct WorldpayPaymentRequest {
    pub amount: MinorUnit,
    pub currency: String,
    pub reference: String,
    #[serde(rename = "paymentMethod")]
    pub payment_method: WorldpayCardPaymentMethod,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    > for WorldpayPaymentRequest
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
        let payment_method_data = match &item.request.payment_method_data {
            PaymentMethodData::Card(card) => {
                let card_holder_name = card
                    .card_holder_name
                    .as_ref()
                    .map(|name| name.clone().expose())
                    .unwrap_or_default();

                WorldpayCardPaymentMethod {
                    payment_method_type: "card".to_string(),
                    name: card_holder_name,
                    number: card.card_number.clone().expose(),
                    expiry_month: card.card_exp_month.clone().expose(),
                    expiry_year: card.card_exp_year.clone().expose(),
                    cvv: card.card_cvc.clone().expose(),
                }
            }
            _ => {
                return Err(error_stack::report!(
                    errors::ConnectorError::NotImplemented(
                        "Only card payments are supported for Worldpay".to_string()
                    )
                ))
            }
        };

        Ok(Self {
            amount: item.request.minor_amount,
            currency: item.request.currency.to_string(),
            reference: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            payment_method: payment_method_data,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayPaymentResponse {
    pub id: String,
    pub status: String,
    pub amount: Option<MinorUnit>,
    pub currency: Option<String>,
    pub reference: Option<String>,
}

fn get_attempt_status(status: &str, capture_method: Option<common_enums::CaptureMethod>) -> AttemptStatus {
    match status.to_lowercase().as_str() {
        "success" | "authorized" => {
            if capture_method == Some(common_enums::CaptureMethod::Automatic)
                || capture_method.is_none()
            {
                AttemptStatus::Charged
            } else {
                AttemptStatus::Authorized
            }
        }
        "pending" | "processing" => AttemptStatus::Pending,
        "failed" | "error" | "declined" => AttemptStatus::Failure,
        "cancelled" | "canceled" | "voided" => AttemptStatus::Voided,
        "captured" => AttemptStatus::Charged,
        "refunded" => AttemptStatus::Charged,
        _ => AttemptStatus::Pending,
    }
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            WorldpayPaymentResponse,
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
            WorldpayPaymentResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let status = get_attempt_status(&item.response.status, item.router_data.request.capture_method);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.reference.clone(),
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

// ============================================================================
// CAPTURE FLOW
// ============================================================================

#[derive(Debug, Serialize)]
pub struct WorldpayCaptureRequest {
    pub amount: MinorUnit,
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
            amount: item.request.minor_amount_to_capture,
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
    pub status: String,
    pub amount: Option<MinorUnit>,
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
        let status = match item.response.status.to_lowercase().as_str() {
            "success" | "captured" => AttemptStatus::Charged,
            "pending" | "processing" => AttemptStatus::Pending,
            "failed" => AttemptStatus::CaptureFailed,
            _ => AttemptStatus::Pending,
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.reference.clone(),
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

// ============================================================================
// VOID FLOW
// ============================================================================

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
            reference: item.request.connector_transaction_id.clone(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayVoidResponse {
    pub id: String,
    pub status: String,
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
        let status = match item.response.status.to_lowercase().as_str() {
            "success" | "cancelled" | "canceled" | "voided" => AttemptStatus::Voided,
            "pending" => AttemptStatus::Pending,
            "failed" => AttemptStatus::VoidFailed,
            _ => AttemptStatus::Pending,
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.reference.clone(),
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

// ============================================================================
// REFUND FLOW
// ============================================================================

#[derive(Debug, Serialize)]
pub struct WorldpayRefundRequest {
    pub amount: MinorUnit,
    pub reference: String,
}

impl<F>
    TryFrom<
        &RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
    > for WorldpayRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: item.request.minor_refund_amount,
            reference: item.request.refund_id.clone(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayRefundResponse {
    pub id: String,
    pub status: String,
    pub reference: Option<String>,
}

fn get_refund_status(status: &str) -> RefundStatus {
    match status.to_lowercase().as_str() {
        "success" | "refunded" => RefundStatus::Success,
        "pending" | "processing" => RefundStatus::Pending,
        "failed" => RefundStatus::Failure,
        _ => RefundStatus::Pending,
    }
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
        let refund_status = get_refund_status(&item.response.status);

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.clone(),
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// ============================================================================
// PSYNC FLOW
// ============================================================================

pub type WorldpayPSyncResponse = WorldpayPaymentResponse;

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
        let status = get_attempt_status(&item.response.status, None);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.reference.clone(),
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

// ============================================================================
// RSYNC FLOW
// ============================================================================

pub type WorldpayRSyncResponse = WorldpayRefundResponse;

impl<F>
    TryFrom<
        ResponseRouterData<
            WorldpayRSyncResponse,
            RouterDataV2<F, RefundFlowData, domain_types::connector_types::RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<F, RefundFlowData, domain_types::connector_types::RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            WorldpayRSyncResponse,
            RouterDataV2<F, RefundFlowData, domain_types::connector_types::RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let refund_status = get_refund_status(&item.response.status);

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.clone(),
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}
