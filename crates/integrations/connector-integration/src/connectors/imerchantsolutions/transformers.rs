use crate::types::ResponseRouterData;
use common_enums::{AttemptStatus, RefundStatus};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, SetupMandate, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsCaptureData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        ResponseId, SetupMandateRequestData, SetupMandateResponseData,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_data::ConnectorSpecificConfig,
    router_data_v2::RouterDataV2,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

// =============================================================================
// AUTH TYPE
// =============================================================================
#[derive(Debug, Clone)]
pub struct ImerchantsolutionsAuthType {
    pub api_key: Secret<String>,
    pub api_secret: Secret<String>,
    pub merchant_id: Secret<String>,
}

impl TryFrom<&ConnectorSpecificConfig> for ImerchantsolutionsAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorSpecificConfig) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorSpecificConfig::Imerchantsolutions {
                api_key,
                api_secret,
                merchant_id,
                ..
            } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: api_secret.to_owned(),
                merchant_id: merchant_id.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

// =============================================================================
// ERROR RESPONSE
// =============================================================================
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImerchantsolutionsErrorResponse {
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub error_description: Option<String>,
}

// =============================================================================
// AUTHORIZE FLOW
// =============================================================================
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImerchantsolutionsAuthorizeRequest {
    pub amount: i64,
    pub currency: String,
    pub payment_method: ImerchantsolutionsPaymentMethod,
    pub merchant_reference: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImerchantsolutionsPaymentMethod {
    #[serde(rename = "type")]
    pub payment_method_type: String,
    pub card: ImerchantsolutionsCardDetails,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImerchantsolutionsCardDetails {
    pub number: Secret<String>,
    pub expiry_month: Secret<String>,
    pub expiry_year: Secret<String>,
    pub cvc: Secret<String>,
    pub holder_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImerchantsolutionsAuthorizeResponse {
    pub id: String,
    pub status: String,
    pub amount: i64,
    pub currency: String,
    pub merchant_reference: String,
}

impl<T> TryFrom<&ImerchantsolutionsRouterData<RouterDataV2<Authorize, PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for ImerchantsolutionsAuthorizeRequest
where
    T: Clone,
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        data: &ImerchantsolutionsRouterData<RouterDataV2<Authorize, PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let auth_data = data.router_data.request.payment_method_data.clone();
        let card_data = match auth_data {
            PaymentMethodDataTypes::Card(card) => card,
            _ => Err(errors::ConnectorError::NotImplemented("Only card payments are supported".to_string()))?,
        };

        Ok(Self {
            amount: data.router_data.request.amount,
            currency: data.router_data.request.currency.to_string(),
            payment_method: ImerchantsolutionsPaymentMethod {
                payment_method_type: "card".to_string(),
                card: ImerchantsolutionsCardDetails {
                    number: card_data.card_number,
                    expiry_month: card_data.card_exp_month,
                    expiry_year: card_data.card_exp_year,
                    cvc: card_data.card_cvc,
                    holder_name: card_data.card_holder_name,
                },
            },
            merchant_reference: data.router_data.attempt_id.clone(),
            description: data.router_data.description.clone(),
        })
    }
}

impl<T> TryFrom<ResponseRouterData<Authorize, ImerchantsolutionsAuthorizeResponse, PaymentsResponseData>>
    for ResponseRouterData<Authorize, PaymentsResponseData>
where
    T: Clone,
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        data: ResponseRouterData<Authorize, ImerchantsolutionsAuthorizeResponse, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let status = match data.response.status.as_str() {
            "authorized" => AttemptStatus::Authorized,
            "pending" => AttemptStatus::Pending,
            "failed" => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        Ok(Self {
            response: PaymentsResponseData {
                connector_transaction_id: Some(data.response.id),
                mandate_reference: None,
                status,
                amount: Some(data.response.amount),
                ..Default::default()
            },
            data: data.data,
        })
    }
}

// =============================================================================
// CAPTURE FLOW
// =============================================================================
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImerchantsolutionsCaptureRequest {
    pub amount: Option<i64>,
    pub final_capture: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImerchantsolutionsCaptureResponse {
    pub id: String,
    pub status: String,
    pub amount: i64,
}

impl<T> TryFrom<&ImerchantsolutionsRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>>
    for ImerchantsolutionsCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        data: &ImerchantsolutionsRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: data.router_data.request.amount_to_capture,
            final_capture: true,
        })
    }
}

impl<T> TryFrom<ResponseRouterData<Capture, ImerchantsolutionsCaptureResponse, PaymentsResponseData>>
    for ResponseRouterData<Capture, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        data: ResponseRouterData<Capture, ImerchantsolutionsCaptureResponse, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let status = match data.response.status.as_str() {
            "captured" => AttemptStatus::Charged,
            "pending" => AttemptStatus::Pending,
            "failed" => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        Ok(Self {
            response: PaymentsResponseData {
                connector_transaction_id: Some(data.response.id),
                status,
                amount: Some(data.response.amount),
                ..Default::default()
            },
            data: data.data,
        })
    }
}

// =============================================================================
// VOID FLOW
// =============================================================================
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImerchantsolutionsVoidRequest {
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImerchantsolutionsVoidResponse {
    pub id: String,
    pub status: String,
}

impl<T> TryFrom<&RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>
    for ImerchantsolutionsVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        data: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            reason: data.request.cancellation_reason.clone(),
        })
    }
}

impl<T> TryFrom<ResponseRouterData<Void, ImerchantsolutionsVoidResponse, PaymentsResponseData>>
    for ResponseRouterData<Void, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        data: ResponseRouterData<Void, ImerchantsolutionsVoidResponse, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let status = match data.response.status.as_str() {
            "voided" => AttemptStatus::Voided,
            "pending" => AttemptStatus::Pending,
            "failed" => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        Ok(Self {
            response: PaymentsResponseData {
                connector_transaction_id: Some(data.response.id),
                status,
                ..Default::default()
            },
            data: data.data,
        })
    }
}

// =============================================================================
// REFUND FLOW
// =============================================================================
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImerchantsolutionsRefundRequest {
    pub amount: i64,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImerchantsolutionsRefundResponse {
    pub id: String,
    pub status: String,
    pub amount: i64,
}

impl<T> TryFrom<&ImerchantsolutionsRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>>
    for ImerchantsolutionsRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        data: &ImerchantsolutionsRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: data.router_data.request.refund_amount,
            reason: data.router_data.request.reason.clone(),
        })
    }
}

impl<T> TryFrom<ResponseRouterData<Refund, ImerchantsolutionsRefundResponse, RefundsResponseData>>
    for ResponseRouterData<Refund, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        data: ResponseRouterData<Refund, ImerchantsolutionsRefundResponse, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let status = match data.response.status.as_str() {
            "refunded" => RefundStatus::Success,
            "pending" => RefundStatus::Pending,
            "failed" => RefundStatus::Failure,
            _ => RefundStatus::Pending,
        };

        Ok(Self {
            response: RefundsResponseData {
                connector_refund_id: Some(data.response.id),
                refund_status: status,
                amount: Some(data.response.amount),
                ..Default::default()
            },
            data: data.data,
        })
    }
}

// =============================================================================
// PAYMENT SYNC FLOW
// =============================================================================
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImerchantsolutionsPSyncResponse {
    pub id: String,
    pub status: String,
    pub amount: i64,
    pub currency: String,
    pub captured_amount: Option<i64>,
    pub refunded_amount: Option<i64>,
}

impl<T> TryFrom<ResponseRouterData<PSync, ImerchantsolutionsPSyncResponse, PaymentsResponseData>>
    for ResponseRouterData<PSync, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        data: ResponseRouterData<PSync, ImerchantsolutionsPSyncResponse, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let status = match data.response.status.as_str() {
            "authorized" => AttemptStatus::Authorized,
            "captured" => AttemptStatus::Charged,
            "voided" => AttemptStatus::Voided,
            "pending" => AttemptStatus::Pending,
            "failed" => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        Ok(Self {
            response: PaymentsResponseData {
                connector_transaction_id: Some(data.response.id),
                status,
                amount: Some(data.response.amount),
                captured_amount: data.response.captured_amount,
                refunded_amount: data.response.refunded_amount,
                ..Default::default()
            },
            data: data.data,
        })
    }
}

// =============================================================================
// REFUND SYNC FLOW
// =============================================================================
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImerchantsolutionsRSyncResponse {
    pub id: String,
    pub status: String,
    pub amount: i64,
    pub payment_id: String,
}

impl<T> TryFrom<ResponseRouterData<RSync, ImerchantsolutionsRSyncResponse, RefundsResponseData>>
    for ResponseRouterData<RSync, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        data: ResponseRouterData<RSync, ImerchantsolutionsRSyncResponse, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let status = match data.response.status.as_str() {
            "refunded" => RefundStatus::Success,
            "pending" => RefundStatus::Pending,
            "failed" => RefundStatus::Failure,
            _ => RefundStatus::Pending,
        };

        Ok(Self {
            response: RefundsResponseData {
                connector_refund_id: Some(data.response.id),
                refund_status: status,
                amount: Some(data.response.amount),
                ..Default::default()
            },
            data: data.data,
        })
    }
}

// =============================================================================
// SETUP MANDATE FLOW
// =============================================================================
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImerchantsolutionsSetupMandateRequest {
    pub payment_method: ImerchantsolutionsPaymentMethod,
    pub merchant_reference: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImerchantsolutionsSetupMandateResponse {
    pub id: String,
    pub status: String,
    pub mandate_reference: String,
}

impl<T> TryFrom<&ImerchantsolutionsRouterData<RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, SetupMandateResponseData>>>
    for ImerchantsolutionsSetupMandateRequest
where
    T: Clone,
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        data: &ImerchantsolutionsRouterData<RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, SetupMandateResponseData>>,
    ) -> Result<Self, Self::Error> {
        let auth_data = data.router_data.request.payment_method_data.clone();
        let card_data = match auth_data {
            PaymentMethodDataTypes::Card(card) => card,
            _ => Err(errors::ConnectorError::NotImplemented("Only card payments are supported".to_string()))?,
        };

        Ok(Self {
            payment_method: ImerchantsolutionsPaymentMethod {
                payment_method_type: "card".to_string(),
                card: ImerchantsolutionsCardDetails {
                    number: card_data.card_number,
                    expiry_month: card_data.card_exp_month,
                    expiry_year: card_data.card_exp_year,
                    cvc: card_data.card_cvc,
                    holder_name: card_data.card_holder_name,
                },
            },
            merchant_reference: data.router_data.attempt_id.clone(),
        })
    }
}

impl<T> TryFrom<ResponseRouterData<SetupMandate, ImerchantsolutionsSetupMandateResponse, SetupMandateResponseData>>
    for ResponseRouterData<SetupMandate, SetupMandateResponseData>
where
    T: Clone,
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        data: ResponseRouterData<SetupMandate, ImerchantsolutionsSetupMandateResponse, SetupMandateResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: SetupMandateResponseData {
                mandate_reference: Some(data.response.mandate_reference),
                connector_mandate_id: Some(data.response.id),
                payment_method_id: None,
            },
            data: data.data,
        })
    }
}

// =============================================================================
// ROUTER DATA HELPER
// =============================================================================
pub struct ImerchantsolutionsRouterData<RouterData> {
    pub router_data: RouterData,
}

impl<T, T2> TryFrom<(&Imerchantsolutions<T>, &RouterDataV2<Authorize, PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T2>, PaymentsResponseData>)>
    for ImerchantsolutionsRouterData<RouterDataV2<Authorize, PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T2>, PaymentsResponseData>>
where
    T2: Clone,
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        (_connector, router_data): (&Imerchantsolutions<T>, &RouterDataV2<Authorize, PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T2>, PaymentsResponseData>),
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            router_data: router_data.clone(),
        })
    }
}

impl<T> TryFrom<(&Imerchantsolutions<T>, &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>)>
    for ImerchantsolutionsRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        (_connector, router_data): (&Imerchantsolutions<T>, &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>),
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            router_data: router_data.clone(),
        })
    }
}

impl<T> TryFrom<(&Imerchantsolutions<T>, &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>)>
    for ImerchantsolutionsRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        (_connector, router_data): (&Imerchantsolutions<T>, &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>),
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            router_data: router_data.clone(),
        })
    }
}

impl<T, T2> TryFrom<(&Imerchantsolutions<T>, &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, SetupMandateResponseData>)>
    for ImerchantsolutionsRouterData<RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, SetupMandateResponseData>>
where
    T2: Clone,
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        (_connector, router_data): (&Imerchantsolutions<T>, &RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, SetupMandateResponseData>),
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            router_data: router_data.clone(),
        })
    }
}
