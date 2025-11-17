use super::BillwerkRouterData;
use crate::types::ResponseRouterData;

pub type RefundsResponseRouterData<F, T> =
    ResponseRouterData<T, RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>>;

use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    types::MinorUnit,
};

use domain_types::{
    connector_flow::{Authorize, Capture, PSync, PaymentMethodToken, RSync, Void},
    connector_types::{
        PaymentFlowData, PaymentMethodTokenResponse, PaymentMethodTokenizationData,
        PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        ResponseId,
    },
    errors::{self, ConnectorError},
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct BillwerkAuthType {
    pub api_key: Secret<String>,
    pub public_api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for BillwerkAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                api_key: api_key.to_owned(),
                public_api_key: key1.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillwerkErrorResponse {
    pub code: Option<i32>,
    pub error: String,
    pub message: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BillwerkTokenRequest<T: PaymentMethodDataTypes> {
    pub number: Secret<String>,
    pub month: Secret<String>,
    pub year: Secret<String>,
    pub cvv: Secret<String>,
    pub pkey: Secret<String>,
    pub recurring: Option<bool>,
    #[serde(skip)]
    pub _phantom_data: std::marker::PhantomData<T>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BillwerkTokenResponse {
    pub id: Secret<String>,
    pub recurring: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct BillwerkPaymentsRequest<T: PaymentMethodDataTypes> {
    pub amount: i64,
    pub currency: String,
    pub reference: String,
    #[serde(skip)]
    pub _phantom_data: std::marker::PhantomData<T>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BillwerkSource {
    #[serde(rename = "type")]
    pub source_type: Option<String>,
    pub fingerprint: Option<String>,
    pub provider: Option<String>,
    pub frictionless: Option<bool>,
    pub card_type: Option<String>,
    pub transaction_card_type: Option<String>,
    pub exp_date: Option<String>,
    pub masked_card: Option<String>,
    pub card_country: Option<String>,
    pub acquirer_reference: Option<String>,
    pub text_on_statement: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BillwerkOrderLine {
    pub id: Option<String>,
    pub ordertext: Option<String>,
    pub amount: Option<i64>,
    pub vat: Option<f64>,
    pub quantity: Option<i64>,
    pub origin: Option<String>,
    pub timestamp: Option<String>,
    pub amount_vat: Option<i64>,
    pub amount_ex_vat: Option<i64>,
    pub unit_amount: Option<i64>,
    pub unit_amount_vat: Option<i64>,
    pub unit_amount_ex_vat: Option<i64>,
    pub amount_defined_incl_vat: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BillwerkPaymentState {
    Created,
    Authorized,
    Pending,
    Settled,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BillwerkPaymentsResponse {
    state: BillwerkPaymentState,
    handle: String,
    error: Option<String>,
    error_state: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BillwerkVoidRequest {}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        BillwerkRouterData<
            RouterDataV2<
                PaymentMethodToken,
                PaymentFlowData,
                PaymentMethodTokenizationData<T>,
                PaymentMethodTokenResponse,
            >,
            T,
        >,
    > for BillwerkTokenRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: BillwerkRouterData<
            RouterDataV2<
                PaymentMethodToken,
                PaymentFlowData,
                PaymentMethodTokenizationData<T>,
                PaymentMethodTokenResponse,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        match &item.router_data.request.payment_method_data {
            PaymentMethodData::Card(ref card_data) => {
                let auth = BillwerkAuthType::try_from(&item.router_data.connector_auth_type)?;

                let card_number_str = format!("{:?}", card_data.card_number.0);
                let card_number = card_number_str
                    .chars()
                    .filter(|c| c.is_ascii_digit())
                    .collect::<String>();

                Ok(Self {
                    number: Secret::new(card_number),
                    month: card_data.card_exp_month.clone(),
                    year: card_data.card_exp_year.clone(),
                    cvv: card_data.card_cvc.clone(),
                    pkey: auth.public_api_key,
                    recurring: Some(false),
                    _phantom_data: std::marker::PhantomData,
                })
            }
            _ => Err(errors::ConnectorError::NotSupported {
                message: "Payment method not supported for tokenization".to_string(),
                connector: "Billwerk",
            }
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
            + serde::Serialize,
    >
    TryFrom<
        BillwerkRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for BillwerkPaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: BillwerkRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: item.router_data.request.minor_amount.get_amount_as_i64(),
            currency: item.router_data.request.currency.to_string(),
            reference: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            _phantom_data: std::marker::PhantomData,
        })
    }
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            BillwerkTokenResponse,
            RouterDataV2<
                PaymentMethodToken,
                PaymentFlowData,
                PaymentMethodTokenizationData<T>,
                PaymentMethodTokenResponse,
            >,
        >,
    >
    for RouterDataV2<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            BillwerkTokenResponse,
            RouterDataV2<
                PaymentMethodToken,
                PaymentFlowData,
                PaymentMethodTokenizationData<T>,
                PaymentMethodTokenResponse,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(PaymentMethodTokenResponse {
                token: item.response.id.expose(),
            }),
            ..item.router_data
        })
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        BillwerkRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for BillwerkPaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: BillwerkRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: 0,
            currency: String::new(),
            reference: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            _phantom_data: std::marker::PhantomData,
        })
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        BillwerkRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for BillwerkPaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: BillwerkRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: item.router_data.request.amount_to_capture,
            currency: item.router_data.request.currency.to_string(),
            reference: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            _phantom_data: std::marker::PhantomData,
        })
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        BillwerkRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for BillwerkVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: BillwerkRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {})
    }
}

impl<F, T> TryFrom<ResponseRouterData<BillwerkPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<BillwerkPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        let error_response = if response.error.is_some() || response.error_state.is_some() {
            Some(ErrorResponse {
                code: response
                    .error_state
                    .clone()
                    .unwrap_or(NO_ERROR_CODE.to_string()),
                message: response
                    .error
                    .clone()
                    .unwrap_or(NO_ERROR_MESSAGE.to_string()),
                reason: response.error,
                status_code: http_code,
                attempt_status: None,
                connector_transaction_id: Some(response.handle.clone()),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            })
        } else {
            None
        };
        let payments_response = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.handle.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(response.handle),
            incremental_authorization_allowed: None,
            status_code: http_code,
        };
        Ok(Self {
            response: error_response.map_or_else(|| Ok(payments_response), Err),
            ..router_data
        })
    }
}

impl From<BillwerkPaymentState> for common_enums::AttemptStatus {
    fn from(item: BillwerkPaymentState) -> Self {
        match item {
            BillwerkPaymentState::Created | BillwerkPaymentState::Pending => Self::Pending,
            BillwerkPaymentState::Authorized => Self::Authorized,
            BillwerkPaymentState::Settled => Self::Charged,
            BillwerkPaymentState::Failed => Self::Failure,
            BillwerkPaymentState::Cancelled => Self::Voided,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct BillwerkCaptureRequest {
    amount: MinorUnit,
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
        BillwerkRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for BillwerkCaptureRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: BillwerkRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: item.router_data.request.minor_amount_to_capture,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RefundState {
    Refunded,
    Failed,
    Processing,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefundResponse {
    id: String,
    state: RefundState,
}

#[derive(Debug, Serialize)]
pub struct BillwerkRefundRequest {
    pub invoice: String,
    pub amount: MinorUnit,
    pub text: Option<String>,
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
        BillwerkRouterData<RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for BillwerkRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: BillwerkRouterData<
            RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: item.router_data.request.minor_refund_amount,
            invoice: item.router_data.request.connector_transaction_id.clone(),
            text: item.router_data.request.reason.clone(),
        })
    }
}

impl From<RefundState> for common_enums::RefundStatus {
    fn from(item: RefundState) -> Self {
        match item {
            RefundState::Refunded => Self::Success,
            RefundState::Failed => Self::Failure,
            RefundState::Processing => Self::Pending,
        }
    }
}

impl<F> TryFrom<RefundsResponseRouterData<F, RefundResponse>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: RefundsResponseRouterData<F, RefundResponse>) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.to_string(),
                refund_status: common_enums::RefundStatus::from(item.response.state),
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

#[derive(Debug, Serialize)]
pub struct BillwerkRSyncRequest {}

pub type BillwerkRSyncResponse = RefundResponse;

pub type BillwerkRefundResponse = RefundResponse;

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        BillwerkRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for BillwerkRSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: BillwerkRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {})
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        BillwerkRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for BillwerkRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: BillwerkRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: MinorUnit::new(0),
            invoice: item.router_data.request.connector_refund_id.clone(),
            text: None,
        })
    }
}

impl
    TryFrom<
        ResponseRouterData<
            RefundResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            RefundResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.to_string(),
                refund_status: common_enums::RefundStatus::from(item.response.state),
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}
