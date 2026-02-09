use common_utils::{
    consts::NO_ERROR_CODE,
    ext_traits::ValueExt,
    types::{FloatMajorUnit, FloatMajorUnitForConnector},
};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors::ConnectorError,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    utils::{self, ForeignTryFrom},
};
use error_stack::{report, ResultExt};
use hyperswitch_masking::{ExposeInterface, Mask, Maskable, Secret};
use serde::{Deserialize, Serialize};
use crate::types::ResponseRouterData;

#[derive(Debug, Clone)]
pub struct FiservEMEAAuthType {
    pub api_key: Secret<String>,
    pub api_secret: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for FiservEMEAAuthType {
    type Error = ConnectorError;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::Signature { api_key, api_secret } => Ok(Self {
                api_key: api_key.clone(),
                api_secret: api_secret.clone(),
            }),
            _ => Err(report!(ConnectorError::FailedToObtainAuthType)),
        }
    }
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TransactionAmount {
    pub total: String,
    pub currency: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ExpiryDate {
    pub month: String,
    pub year: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PaymentCard {
    pub number: Maskable<String>,
    pub security_code: Maskable<String>,
    pub expiry_date: ExpiryDate,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PaymentMethod {
    pub payment_card: PaymentCard,
}

#[derive(Debug, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct BillingDetails {}

#[derive(Debug, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct ShippingDetails {}

#[derive(Debug, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    pub order_id: Option<String>,
    pub billing: Option<BillingDetails>,
    pub shipping: Option<ShippingDetails>,
}

#[derive(Debug, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationRequest {}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FiservEMEAPaymentsRequest<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize> {
    pub request_type: String,
    pub transaction_amount: TransactionAmount,
    pub payment_method: PaymentMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<Order>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication_request: Option<AuthenticationRequest>,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    ForeignTryFrom<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for FiservEMEAPaymentsRequest<T>
{
    type Error = ConnectorError;

    fn foreign_try_from(
        item: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let request_type = match item.request.capture_method {
            Some(domain_types::router_request_types::CaptureMethod::Automatic) => {
                "PaymentCardSaleTransaction".to_string()
            }
            Some(domain_types::router_request_types::CaptureMethod::Manual) => {
                "PaymentCardPreAuthTransaction".to_string()
            }
            None => "PaymentCardSaleTransaction".to_string(),
        };

        let payment_method_data = item
            .request
            .payment_method_data
            .clone()
            .ok_or(utils::missing_field_err("payment_method_data"))?;

        let card = match payment_method_data {
            PaymentMethodData::Card(card) => card,
            _ => {
                return Err(report!(utils::not_implemented_error(
                    "Only card payments are supported for FiservEMEA",
                )))
            }
        };

        let card_number = card.card_number.peek().to_string();
        let card_cvc = card.card_cvc.peek().to_string();

        let expiry_month = card
            .card_exp_month
            .map(|m| format!("{:02}", m))
            .unwrap_or_else(|| "".to_string());
        let expiry_year = card
            .card_exp_year
            .map(|y| format!("{:02}", y % 100))
            .unwrap_or_else(|| "".to_string());

        let amount = item.request.amount.to_string();
        let currency = item.request.currency.to_string();

        Ok(Self {
            request_type,
            transaction_amount: TransactionAmount {
                total: amount,
                currency,
            },
            payment_method: PaymentMethod {
                payment_card: PaymentCard {
                    number: card_number.into_masked(),
                    security_code: card_cvc.into_masked(),
                    expiry_date: ExpiryDate {
                        month: expiry_month,
                        year: expiry_year,
                    },
                },
            },
            order: item.request.order_id.map(|order_id| Order {
                order_id: Some(order_id),
                ..Default::default()
            }),
            authentication_request: None,
        })
    }
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FiservEMEACaptureRequest {
    pub request_type: String,
    pub transaction_amount: TransactionAmount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<Order>,
}

impl ForeignTryFrom<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>
    for FiservEMEACaptureRequest
{
    type Error = ConnectorError;

    fn foreign_try_from(
        item: RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let amount = item.request.amount.to_string();
        let currency = item.request.currency.to_string();

        Ok(Self {
            request_type: "PostAuthTransaction".to_string(),
            transaction_amount: TransactionAmount {
                total: amount,
                currency,
            },
            order: None,
        })
    }
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FiservEMEARefundRequest {
    pub request_type: String,
    pub transaction_amount: TransactionAmount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comments: Option<String>,
}

impl ForeignTryFrom<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>
    for FiservEMEARefundRequest
{
    type Error = ConnectorError;

    fn foreign_try_from(
        item: RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let amount = item.request.refund_amount.to_string();
        let currency = item.request.refund_currency.to_string();

        Ok(Self {
            request_type: "ReturnTransaction".to_string(),
            transaction_amount: TransactionAmount {
                total: amount,
                currency,
            },
            comments: item.request.reason.clone(),
        })
    }
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FiservEMEAVoidRequest {
    pub request_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comments: Option<String>,
}

impl ForeignTryFrom<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>
    for FiservEMEAVoidRequest
{
    type Error = ConnectorError;

    fn foreign_try_from(
        item: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            request_type: "VoidTransaction".to_string(),
            comments: item.request.reason.clone(),
        })
    }
}

#[derive(Debug, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct FiservEMEASyncRequest {}

impl ForeignTryFrom<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for FiservEMEASyncRequest
{
    type Error = ConnectorError;

    fn foreign_try_from(
        _item: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {})
    }
}

impl ForeignTryFrom<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>
    for FiservEMEASyncRequest
{
    type Error = ConnectorError;

    fn foreign_try_from(
        _item: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {})
    }
}

impl TryFrom<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for FiservEMEASyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        _item: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {})
    }
}

impl TryFrom<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>
    for FiservEMEASyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        _item: RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {})
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ApprovedAmount {
    pub total: Option<String>,
    pub currency: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Processor {
    pub response_code: Option<String>,
    pub response_message: Option<String>,
    pub approval_code: Option<String>,
    pub network_response_code: Option<String>,
    pub avs_response_code: Option<String>,
    pub cvv_response_code: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PaymentMethodDetails {
    pub card: Option<CardDetails>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CardDetails {
    pub bin: Option<String>,
    pub last_four: Option<String>,
    pub card_type: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ErrorDetail {
    pub field: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Error {
    pub code: Option<String>,
    pub message: Option<String>,
    pub details: Option<Vec<ErrorDetail>>,
    pub decline_reason_code: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FiservEMEAPaymentsResponse {
    pub client_request_id: String,
    pub api_trace_id: String,
    pub ipg_transaction_id: String,
    pub order_id: Option<String>,
    pub transaction_type: String,
    pub transaction_result: String,
    pub transaction_state: String,
    pub approval_code: Option<String>,
    pub scheme_response_code: Option<String>,
    pub error_message: Option<String>,
    pub approved_amount: Option<ApprovedAmount>,
    pub processor: Option<Processor>,
    pub payment_method_details: Option<PaymentMethodDetails>,
    pub error: Option<Error>,
}

pub type FiservEMEACaptureResponse = FiservEMEAPaymentsResponse;
pub type FiservEMEARefundResponse = FiservEMEAPaymentsResponse;
pub type FiservEMEAVoidResponse = FiservEMEAPaymentsResponse;

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FiservEMEAPSyncResponse {
    pub client_request_id: String,
    pub api_trace_id: String,
    pub ipg_transaction_id: String,
    pub order_id: Option<String>,
    pub transaction_type: String,
    pub transaction_result: String,
    pub transaction_state: String,
    pub approval_code: Option<String>,
    pub scheme_response_code: Option<String>,
    pub error_message: Option<String>,
    pub approved_amount: Option<ApprovedAmount>,
    pub processor: Option<Processor>,
    pub payment_method_details: Option<PaymentMethodDetails>,
    pub error: Option<Error>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FiservEMEARefundSyncResponse {
    pub client_request_id: String,
    pub api_trace_id: String,
    pub ipg_transaction_id: String,
    pub order_id: Option<String>,
    pub transaction_type: String,
    pub transaction_result: String,
    pub transaction_state: String,
    pub approval_code: Option<String>,
    pub scheme_response_code: Option<String>,
    pub error_message: Option<String>,
    pub approved_amount: Option<ApprovedAmount>,
    pub processor: Option<Processor>,
    pub payment_method_details: Option<PaymentMethodDetails>,
    pub error: Option<Error>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FiservEMEAErrorResponse {
    pub client_request_id: String,
    pub api_trace_id: String,
    pub response_type: String,
    pub error: Error,
}

impl<T, F, Req, Res> ForeignTryFrom<RouterDataV2<T, F, Req, Res>> for FiservEMEAPaymentsResponse
where
    T: Clone,
    F: Clone,
    Req: Clone,
    Res: Clone,
{
    type Error = ConnectorError;

    fn foreign_try_from(
        _item: RouterDataV2<T, F, Req, Res>,
    ) -> Result<Self, Self::Error> {
        Err(report!(utils::not_implemented_error(
            "ForeignTryFrom for FiservEMEAPaymentsResponse is not implemented",
        )))
    }
}

fn get_transaction_status(transaction_result: &str, transaction_state: &str) -> common_enums::AttemptStatus {
    match transaction_result.to_uppercase().as_str() {
        "APPROVED" => common_enums::AttemptStatus::PaymentSuccess,
        "DECLINED" | "FAILED" | "FRAUD" => common_enums::AttemptStatus::PaymentFailure,
        "WAITING" | "PARTIAL" => common_enums::AttemptStatus::Pending,
        _ => match transaction_state.to_uppercase().as_str() {
            "AUTHORIZED" | "CAPTURED" => common_enums::AttemptStatus::PaymentSuccess,
            "DECLINED" | "VOIDED" => common_enums::AttemptStatus::PaymentFailure,
            "SETTLED" => common_enums::AttemptStatus::PaymentSuccess,
            _ => common_enums::AttemptStatus::Pending,
        },
    }
}

impl<T, F>
    utils::ForeignFrom<
        (
            FiservEMEAPaymentsResponse,
            RouterDataV2<T, F, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
    > for PaymentsResponseData
where
    T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize,
    F: Clone,
{
    fn foreign_from(
        item: (
            FiservEMEAPaymentsResponse,
            RouterDataV2<T, F, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
    ) -> Self {
        let (response, req) = item;
        let status = get_transaction_status(&response.transaction_result, &response.transaction_state);

        let error_code = response
            .error
            .as_ref()
            .and_then(|e| e.code.clone())
            .or_else(|| response.error_message.clone())
            .unwrap_or_else(|| NO_ERROR_CODE.to_string());

        let error_message = response
            .error
            .as_ref()
            .and_then(|e| e.message.clone())
            .or_else(|| response.error_message.clone())
            .unwrap_or_else(|| "".to_string());

        let capture_method = match response.transaction_type.to_uppercase().as_str() {
            "SALE" => Some(domain_types::router_request_types::CaptureMethod::Automatic),
            "PREAUTH" => Some(domain_types::router_request_types::CaptureMethod::Manual),
            _ => None,
        };

        let connector_transaction_id = Some(response.ipg_transaction_id.clone());

        let amount = response
            .approved_amount
            .as_ref()
            .and_then(|a| a.total.clone())
            .and_then(|s| s.parse::<i64>().ok());

        let currency = response
            .approved_amount
            .as_ref()
            .and_then(|a| a.currency.clone());

        let processor_response_code = response
            .processor
            .as_ref()
            .and_then(|p| p.response_code.clone());

        let processor_response_message = response
            .processor
            .as_ref()
            .and_then(|p| p.response_message.clone());

        let authorization_code = response.approval_code.clone();

        let network_response_code = response.scheme_response_code.clone();

        let card_last_four = response
            .payment_method_details
            .as_ref()
            .and_then(|pmd| p.card.as_ref())
            .and_then(|c| c.last_four.clone());

        let card_bin = response
            .payment_method_details
            .as_ref()
            .and_then(|pmd| p.card.as_ref())
            .and_then(|c| c.bin.clone());

        let card_brand = response
            .payment_method_details
            .as_ref()
            .and_then(|pmd| p.card.as_ref())
            .and_then(|c| c.card_type.clone());

        let card_metadata = if card_last_four.is_some() || card_bin.is_some() {
            Some(common_utils::types::CardMetadata {
                card_last_four,
                card_bin,
                card_brand,
            })
        } else {
            None
        };

        Self {
            status,
            error_code: Some(error_code),
            error_message: Some(error_message),
            capture_method,
            connector_transaction_id,
            amount,
            currency,
            processor_response_code,
            processor_response_message,
            authorization_code,
            network_response_code,
            card_metadata,
            ..Default::default()
        }
    }
}

impl<F> utils::ForeignFrom<(FiservEMEAPaymentsResponse, RouterDataV2<Capture, F, PaymentsCaptureData, PaymentsResponseData>)>
    for PaymentsResponseData
{
    fn foreign_from(
        item: (FiservEMEAPaymentsResponse, RouterDataV2<Capture, F, PaymentsCaptureData, PaymentsResponseData>),
    ) -> Self {
        let (response, _req) = item;
        let status = get_transaction_status(&response.transaction_result, &response.transaction_state);

        let error_code = response
            .error
            .as_ref()
            .and_then(|e| e.code.clone())
            .or_else(|| response.error_message.clone())
            .unwrap_or_else(|| NO_ERROR_CODE.to_string());

        let error_message = response
            .error
            .as_ref()
            .and_then(|e| e.message.clone())
            .or_else(|| response.error_message.clone())
            .unwrap_or_else(|| "".to_string());

        let connector_transaction_id = Some(response.ipg_transaction_id.clone());

        let amount = response
            .approved_amount
            .as_ref()
            .and_then(|a| a.total.clone())
            .and_then(|s| s.parse::<i64>().ok());

        let currency = response
            .approved_amount
            .as_ref()
            .and_then(|a| a.currency.clone());

        let processor_response_code = response
            .processor
            .as_ref()
            .and_then(|p| p.response_code.clone());

        let processor_response_message = response
            .processor
            .as_ref()
            .and_then(|p| p.response_message.clone());

        let authorization_code = response.approval_code.clone();

        Self {
            status,
            error_code: Some(error_code),
            error_message: Some(error_message),
            connector_transaction_id,
            amount,
            currency,
            processor_response_code,
            processor_response_message,
            authorization_code,
            ..Default::default()
        }
    }
}

impl<F> utils::ForeignFrom<(FiservEMEAPaymentsResponse, RouterDataV2<Void, F, PaymentVoidData, PaymentsResponseData>)>
    for PaymentsResponseData
{
    fn foreign_from(
        item: (FiservEMEAPaymentsResponse, RouterDataV2<Void, F, PaymentVoidData, PaymentsResponseData>),
    ) -> Self {
        let (response, _req) = item;
        let status = get_transaction_status(&response.transaction_result, &response.transaction_state);

        let error_code = response
            .error
            .as_ref()
            .and_then(|e| e.code.clone())
            .or_else(|| response.error_message.clone())
            .unwrap_or_else(|| NO_ERROR_CODE.to_string());

        let error_message = response
            .error
            .as_ref()
            .and_then(|e| e.message.clone())
            .or_else(|| response.error_message.clone())
            .unwrap_or_else(|| "".to_string());

        let connector_transaction_id = Some(response.ipg_transaction_id.clone());

        Self {
            status,
            error_code: Some(error_code),
            error_message: Some(error_message),
            connector_transaction_id,
            ..Default::default()
        }
    }
}

impl<F> utils::ForeignFrom<(FiservEMEAPaymentsResponse, RouterDataV2<Refund, F, RefundsData, RefundsResponseData>)>
    for RefundsResponseData
{
    fn foreign_from(
        item: (FiservEMEAPaymentsResponse, RouterDataV2<Refund, F, RefundsData, RefundsResponseData>),
    ) -> Self {
        let (response, _req) = item;
        let status = get_transaction_status(&response.transaction_result, &response.transaction_state);

        let error_code = response
            .error
            .as_ref()
            .and_then(|e| e.code.clone())
            .or_else(|| response.error_message.clone())
            .unwrap_or_else(|| NO_ERROR_CODE.to_string());

        let error_message = response
            .error
            .as_ref()
            .and_then(|e| e.message.clone())
            .or_else(|| response.error_message.clone())
            .unwrap_or_else(|| "".to_string());

        let connector_transaction_id = Some(response.ipg_transaction_id.clone());

        let amount = response
            .approved_amount
            .as_ref()
            .and_then(|a| a.total.clone())
            .and_then(|s| s.parse::<i64>().ok());

        let currency = response
            .approved_amount
            .as_ref()
            .and_then(|a| a.currency.clone());

        Self {
            status,
            error_code: Some(error_code),
            error_message: Some(error_message),
            connector_transaction_id,
            amount,
            currency,
            ..Default::default()
        }
    }
}

impl<F> utils::ForeignFrom<(FiservEMEAPaymentsResponse, RouterDataV2<PSync, F, PaymentsSyncData, PaymentsResponseData>)>
    for PaymentsResponseData
{
    fn foreign_from(
        item: (FiservEMEAPaymentsResponse, RouterDataV2<PSync, F, PaymentsSyncData, PaymentsResponseData>),
    ) -> Self {
        let (response, _req) = item;
        let status = get_transaction_status(&response.transaction_result, &response.transaction_state);

        let error_code = response
            .error
            .as_ref()
            .and_then(|e| e.code.clone())
            .or_else(|| response.error_message.clone())
            .unwrap_or_else(|| NO_ERROR_CODE.to_string());

        let error_message = response
            .error
            .as_ref()
            .and_then(|e| e.message.clone())
            .or_else(|| response.error_message.clone())
            .unwrap_or_else(|| "".to_string());

        let connector_transaction_id = Some(response.ipg_transaction_id.clone());

        let amount = response
            .approved_amount
            .as_ref()
            .and_then(|a| a.total.clone())
            .and_then(|s| s.parse::<i64>().ok());

        let currency = response
            .approved_amount
            .as_ref()
            .and_then(|a| a.currency.clone());

        let processor_response_code = response
            .processor
            .as_ref()
            .and_then(|p| p.response_code.clone());

        let processor_response_message = response
            .processor
            .as_ref()
            .and_then(|p| p.response_message.clone());

        let authorization_code = response.approval_code.clone();

        Self {
            status,
            error_code: Some(error_code),
            error_message: Some(error_message),
            connector_transaction_id,
            amount,
            currency,
            processor_response_code,
            processor_response_message,
            authorization_code,
            ..Default::default()
        }
    }
}

impl<F> utils::ForeignFrom<(FiservEMEAPaymentsResponse, RouterDataV2<RSync, F, RefundSyncData, RefundsResponseData>)>
    for RefundsResponseData
{
    fn foreign_from(
        item: (FiservEMEAPaymentsResponse, RouterDataV2<RSync, F, RefundSyncData, RefundsResponseData>),
    ) -> Self {
        let (response, _req) = item;
        let status = get_transaction_status(&response.transaction_result, &response.transaction_state);

        let error_code = response
            .error
            .as_ref()
            .and_then(|e| e.code.clone())
            .or_else(|| response.error_message.clone())
            .unwrap_or_else(|| NO_ERROR_CODE.to_string());

        let error_message = response
            .error
            .as_ref()
            .and_then(|e| e.message.clone())
            .or_else(|| response.error_message.clone())
            .unwrap_or_else(|| "".to_string());

        let connector_transaction_id = Some(response.ipg_transaction_id.clone());

        let amount = response
            .approved_amount
            .as_ref()
            .and_then(|a| a.total.clone())
            .and_then(|s| s.parse::<i64>().ok());

        let currency = response
            .approved_amount
            .as_ref()
            .and_then(|a| a.currency.clone());

        Self {
            status,
            error_code: Some(error_code),
            error_message: Some(error_message),
            connector_transaction_id,
            amount,
            currency,
            ..Default::default()
        }
    }
}

impl<F> TryFrom<ResponseRouterData<FiservEMEAPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<F>, PaymentsResponseData>
where
    F: Clone,
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservEMEAPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let response_payload =
            PaymentsResponseData::foreign_from((response, router_data.clone()));

        let mut router_data_out = router_data;
        router_data_out.response = Ok(response_payload);
        router_data_out.resource_common_data.status = response_payload.status;

        Ok(router_data_out)
    }
}

impl<F> TryFrom<ResponseRouterData<FiservEMEACaptureResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
where
    F: Clone,
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservEMEACaptureResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let response_payload =
            PaymentsResponseData::foreign_from((response, router_data.clone()));

        let mut router_data_out = router_data;
        router_data_out.response = Ok(response_payload);
        router_data_out.resource_common_data.status = response_payload.status;

        Ok(router_data_out)
    }
}

impl<F> TryFrom<ResponseRouterData<FiservEMEAVoidResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
where
    F: Clone,
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservEMEAVoidResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let response_payload =
            PaymentsResponseData::foreign_from((response, router_data.clone()));

        let mut router_data_out = router_data;
        router_data_out.response = Ok(response_payload);
        router_data_out.resource_common_data.status = response_payload.status;

        Ok(router_data_out)
    }
}

impl<F> TryFrom<ResponseRouterData<FiservEMEARefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
where
    F: Clone,
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservEMEARefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let response_payload =
            RefundsResponseData::foreign_from((response, router_data.clone()));

        let mut router_data_out = router_data;
        router_data_out.response = Ok(response_payload);
        router_data_out.resource_common_data.status = response_payload.status;

        Ok(router_data_out)
    }
}

impl<F> TryFrom<ResponseRouterData<FiservEMEAPSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
where
    F: Clone,
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservEMEAPSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let response_payload =
            PaymentsResponseData::foreign_from((response, router_data.clone()));

        let mut router_data_out = router_data;
        router_data_out.response = Ok(response_payload);
        router_data_out.resource_common_data.status = response_payload.status;

        Ok(router_data_out)
    }
}

impl<F> TryFrom<ResponseRouterData<FiservEMEARefundSyncResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
where
    F: Clone,
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservEMEARefundSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let response_payload =
            RefundsResponseData::foreign_from((response, router_data.clone()));

        let mut router_data_out = router_data;
        router_data_out.response = Ok(response_payload);
        router_data_out.resource_common_data.status = response_payload.status;

        Ok(router_data_out)
    }
}

impl<F, Req, Res> TryFrom<ResponseRouterData<FiservEMEAPSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, Req, Res>
where
    F: Clone,
    Req: Clone,
    Res: Clone,
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservEMEAPSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let response_payload =
            PaymentsResponseData::foreign_from((response, router_data.clone()));

        let mut router_data_out = router_data;
        router_data_out.response = Ok(response_payload);
        router_data_out.resource_common_data.status = response_payload.status;

        Ok(router_data_out)
    }
}

impl<F, Req, Res> TryFrom<ResponseRouterData<FiservEMEARefundSyncResponse, Self>>
    for RouterDataV2<F, RefundFlowData, Req, Res>
where
    F: Clone,
    Req: Clone,
    Res: Clone,
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservEMEARefundSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let response_payload =
            RefundsResponseData::foreign_from((response, router_data.clone()));

        let mut router_data_out = router_data;
        router_data_out.response = Ok(response_payload);
        router_data_out.resource_common_data.status = response_payload.status;

        Ok(router_data_out)
    }
}

impl<F, Req, Res> TryFrom<ResponseRouterData<FiservEMEAErrorResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, Req, Res>
where
    F: Clone,
    Req: Clone,
    Res: Clone,
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservEMEAErrorResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let error_code = response
            .error
            .code
            .clone()
            .unwrap_or_else(|| NO_ERROR_CODE.to_string());

        let error_message = response
            .error
            .message
            .clone()
            .unwrap_or_else(|| "".to_string());

        let mut router_data_out = router_data;
        router_data_out.response = Err(ErrorResponse {
            code: error_code,
            message: error_message,
            reason: None,
            status_code: http_code,
            attempt_status: None,
        });

        Ok(router_data_out)
    }
}

impl<F, Req, Res> TryFrom<ResponseRouterData<FiservEMEAErrorResponse, Self>>
    for RouterDataV2<F, RefundFlowData, Req, Res>
where
    F: Clone,
    Req: Clone,
    Res: Clone,
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservEMEAErrorResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let error_code = response
            .error
            .code
            .clone()
            .unwrap_or_else(|| NO_ERROR_CODE.to_string());

        let error_message = response
            .error
            .message
            .clone()
            .unwrap_or_else(|| "".to_string());

        let mut router_data_out = router_data;
        router_data_out.response = Err(ErrorResponse {
            code: error_code,
            message: error_message,
            reason: None,
            status_code: http_code,
            attempt_status: None,
        });

        Ok(router_data_out)
    }
}