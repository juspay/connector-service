use crate::types::ResponseRouterData;
use common_enums::{AttemptStatus, Currency, RefundStatus};
use common_utils::types::MinorUnit;
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

// Import the connector's RouterData wrapper type created by the macro
use super::Shift4RouterData;

#[derive(Debug, Clone)]
pub struct Shift4AuthType {
    pub api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for Shift4AuthType {
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
pub struct Shift4ErrorResponse {
    pub error: ApiErrorResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    pub code: Option<String>,
    pub message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Shift4PaymentsRequest<T: PaymentMethodDataTypes> {
    pub amount: MinorUnit,
    pub currency: Currency,
    pub captured: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(flatten)]
    pub payment_method: Shift4PaymentMethod<T>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Shift4PaymentMethod<T: PaymentMethodDataTypes> {
    Card(Shift4CardPayment<T>),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Shift4CardPayment<T: PaymentMethodDataTypes> {
    pub card: Shift4CardData<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Shift4CardData<T: PaymentMethodDataTypes> {
    pub number: RawCardNumber<T>,
    pub exp_month: Secret<String>,
    pub exp_year: Secret<String>,
    pub cardholder_name: Secret<String>,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    > for Shift4PaymentsRequest<T>
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
        let card_data = match &item.request.payment_method_data {
            PaymentMethodData::Card(card) => card,
            _ => {
                return Err(error_stack::report!(errors::ConnectorError::NotSupported {
                    message: "Payment method not supported".to_string(),
                    connector: "Shift4",
                }))
            }
        };

        let captured = item
            .request
            .is_auto_capture()
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        // Get cardholder name from address/billing info if available
        let cardholder_name = item
            .resource_common_data
            .address
            .get_payment_method_billing()
            .and_then(|billing| billing.get_optional_full_name())
            .or_else(|| {
                item.request
                    .customer_name
                    .as_ref()
                    .map(|name| Secret::new(name.clone()))
            })
            .unwrap_or_else(|| Secret::new("".to_string()));

        Ok(Self {
            amount: item.request.minor_amount,
            currency: item.request.currency,
            captured,
            description: item.resource_common_data.description.clone(),
            metadata: item.request.metadata.clone(),
            payment_method: Shift4PaymentMethod::Card(Shift4CardPayment {
                card: Shift4CardData {
                    number: card_data.card_number.clone(),
                    exp_month: card_data.card_exp_month.clone(),
                    exp_year: card_data.card_exp_year.clone(),
                    cardholder_name,
                },
            }),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Shift4PaymentsResponse {
    pub id: String,
    pub currency: Currency,
    pub amount: MinorUnit,
    pub status: Shift4PaymentStatus,
    pub captured: bool,
    pub refunded: bool,
    pub flow: Option<FlowResponse>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowResponse {
    pub next_action: Option<NextAction>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NextAction {
    Redirect,
    Wait,
    None,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Shift4PaymentStatus {
    Successful,
    Pending,
    Failed,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            Shift4PaymentsResponse,
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
            Shift4PaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        // Match Hyperswitch status mapping logic exactly
        let status = match item.response.status {
            Shift4PaymentStatus::Successful => {
                if item.response.captured {
                    AttemptStatus::Charged
                } else {
                    AttemptStatus::Authorized
                }
            }
            Shift4PaymentStatus::Failed => AttemptStatus::Failure,
            Shift4PaymentStatus::Pending => {
                match item
                    .response
                    .flow
                    .as_ref()
                    .and_then(|flow| flow.next_action.as_ref())
                {
                    Some(NextAction::Redirect) => AttemptStatus::AuthenticationPending,
                    Some(NextAction::Wait) | Some(NextAction::None) | None => {
                        AttemptStatus::Pending
                    }
                }
            }
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.id),
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

// PSync response transformation - reuses Shift4PaymentsResponse and status mapping logic
impl
    TryFrom<
        ResponseRouterData<
            Shift4PaymentsResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            Shift4PaymentsResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Match Hyperswitch status mapping logic exactly
        let status = match item.response.status {
            Shift4PaymentStatus::Successful => {
                if item.response.captured {
                    AttemptStatus::Charged
                } else {
                    AttemptStatus::Authorized
                }
            }
            Shift4PaymentStatus::Failed => AttemptStatus::Failure,
            Shift4PaymentStatus::Pending => {
                match item
                    .response
                    .flow
                    .as_ref()
                    .and_then(|flow| flow.next_action.as_ref())
                {
                    Some(NextAction::Redirect) => AttemptStatus::AuthenticationPending,
                    Some(NextAction::Wait) | Some(NextAction::None) | None => {
                        AttemptStatus::Pending
                    }
                }
            }
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.id),
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

// Capture response transformation - reuses Shift4PaymentsResponse
impl
    TryFrom<
        ResponseRouterData<
            Shift4PaymentsResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            Shift4PaymentsResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Match Hyperswitch status mapping logic exactly
        let status = match item.response.status {
            Shift4PaymentStatus::Successful => {
                if item.response.captured {
                    AttemptStatus::Charged
                } else {
                    AttemptStatus::Authorized
                }
            }
            Shift4PaymentStatus::Failed => AttemptStatus::Failure,
            Shift4PaymentStatus::Pending => {
                match item
                    .response
                    .flow
                    .as_ref()
                    .and_then(|flow| flow.next_action.as_ref())
                {
                    Some(NextAction::Redirect) => AttemptStatus::AuthenticationPending,
                    Some(NextAction::Wait) | Some(NextAction::None) | None => {
                        AttemptStatus::Pending
                    }
                }
            }
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.id),
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

// ===== REFUND FLOW STRUCTURES =====

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Shift4RefundRequest {
    pub charge_id: String,
    pub amount: MinorUnit,
}

impl TryFrom<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>
    for Shift4RefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            charge_id: item.request.connector_transaction_id.clone(),
            amount: item.request.minor_refund_amount,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Shift4RefundResponse {
    pub id: String,
    pub amount: MinorUnit,
    pub currency: Currency,
    pub charge: String,
    pub status: Shift4RefundStatus,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Shift4RefundStatus {
    Successful,
    Failed,
    Processing,
}

impl
    TryFrom<
        ResponseRouterData<
            Shift4RefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            Shift4RefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // CRITICAL: Explicitly check the status field from the response
        // Do NOT assume success based solely on HTTP 200 response
        let refund_status = match item.response.status {
            Shift4RefundStatus::Successful => RefundStatus::Success,
            Shift4RefundStatus::Failed => RefundStatus::Failure,
            Shift4RefundStatus::Processing => RefundStatus::Pending,
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

// RSync (Refund Sync) response transformation - reuses Shift4RefundResponse
impl
    TryFrom<
        ResponseRouterData<
            Shift4RefundResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            Shift4RefundResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // CRITICAL: Explicitly check the status field from the response
        // Do NOT assume success based solely on HTTP 200 response
        let refund_status = match item.response.status {
            Shift4RefundStatus::Successful => RefundStatus::Success,
            Shift4RefundStatus::Failed => RefundStatus::Failure,
            Shift4RefundStatus::Processing => RefundStatus::Pending,
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

// ===== SYNC REQUEST STRUCTURES =====
// Sync operations (GET requests) typically don't send a body, but we need these for the macro

#[derive(Debug, Serialize, Default)]
pub struct Shift4PSyncRequest {}

#[derive(Debug, Serialize, Default)]
pub struct Shift4RSyncRequest {}

// ===== MACRO-COMPATIBLE TRYFROM IMPLEMENTATIONS =====
// The macro creates a Shift4RouterData wrapper type. We need TryFrom implementations
// that work with this wrapper.

// PSync Request - converts from Shift4RouterData to empty request struct
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        Shift4RouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for Shift4PSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: Shift4RouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self::default())
    }
}

// RSync Request - converts from Shift4RouterData to empty request struct
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        Shift4RouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for Shift4RSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: Shift4RouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self::default())
    }
}

// Authorize Request - delegates to existing implementation
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        Shift4RouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for Shift4PaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: Shift4RouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        // Delegate to the existing TryFrom<&RouterDataV2> implementation
        Self::try_from(&item.router_data)
    }
}

// Capture Request - we need a separate request type
#[derive(Debug, Serialize)]
pub struct Shift4CaptureRequest {
    // Shift4 capture is done via POST to /charges/{id}/capture with no body
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        Shift4RouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for Shift4CaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: Shift4RouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {})
    }
}

// Refund Request - delegates to existing implementation
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        Shift4RouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for Shift4RefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: Shift4RouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        // Delegate to the existing TryFrom<&RouterDataV2> implementation
        Self::try_from(&item.router_data)
    }
}
