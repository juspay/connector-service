use domain_types::{
    connector_flow::{Authorize, Capture},
    connector_types::{
        MandateReference, PaymentFlowData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
};

use hyperswitch_common_utils::{request::Method, types::FloatMajorUnit};

use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
    router_data::{ConnectorAuthType, ErrorResponse}, // Added for XenditErrorResponse
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};

use std::collections::HashMap;

use hyperswitch_interfaces::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    errors::{self, ConnectorError},
};

use hyperswitch_common_enums::Currency;

use hyperswitch_cards::CardNumber;

use serde::{Deserialize, Serialize};

use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};

type Error = error_stack::Report<hyperswitch_interfaces::errors::ConnectorError>;

pub trait ForeignTryFrom<F>: Sized {
    type Error;

    fn foreign_try_from(from: F) -> Result<Self, Self::Error>;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChannelProperties {
    pub success_return_url: Option<String>,
    pub failure_return_url: Option<String>,
    pub skip_three_d_secure: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CardInformation {
    pub card_number: CardNumber,
    pub expiry_month: Secret<String>,
    pub expiry_year: Secret<String>,
    pub cvv: Secret<String>,
    // pub cardholder_name: Secret<String>,
    // pub cardholder_email: pii::Email,
    // pub cardholder_phone_number: Secret<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CardInfo {
    pub channel_properties: ChannelProperties,
    pub card_information: CardInformation,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransactionType {
    OneTimeUse,
    MultipleUse,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum PaymentMethodType {
    CARD,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum PaymentMethod {
    Card(CardPaymentRequest),
}
#[derive(Serialize, Deserialize, Debug)]
pub struct CardPaymentRequest {
    #[serde(rename = "type")]
    pub payment_type: PaymentMethodType,
    pub card: CardInfo,
    pub reusability: TransactionType,
    pub reference_id: Secret<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaymentStatus {
    Pending,
    RequiresAction,
    Failed,
    Succeeded,
    AwaitingCapture,
    Verified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum MethodType {
    Get,
    Post,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub method: MethodType,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentMethodInfo {
    pub id: Secret<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct XenditPaymentResponse {
    pub id: String,
    pub status: PaymentStatus,
    pub actions: Option<Vec<Action>>,
    pub payment_method: PaymentMethodInfo,
    pub failure_code: Option<String>,
    pub reference_id: Secret<String>,
    pub amount: Option<FloatMajorUnit>,
    pub currency: Currency,
}

pub struct XenditAuthType {
    pub(super) api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for XenditAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

pub struct XenditRouterData<T> {
    pub amount: FloatMajorUnit, // The type of amount that a connector accepts, for example, String, i64, f64, etc.
    pub router_data: T,
}

impl<T> From<(FloatMajorUnit, T)> for XenditRouterData<T> {
    fn from((amount, item): (FloatMajorUnit, T)) -> Self {
        Self {
            amount,
            router_data: item,
        }
    }
}

// Basic Request Structure from Hyperswitch Xendit
#[derive(Serialize, Deserialize, Debug)]
pub struct XenditPaymentsRequest {
    pub amount: FloatMajorUnit,
    pub currency: hyperswitch_common_enums::Currency,
    pub capture_method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method: Option<PaymentMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method_id: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_properties: Option<ChannelProperties>,
}

#[derive(Debug, Clone, Serialize)]
pub enum XenditPaymentMethodType {
    #[serde(rename = "CARD")]
    Card,
    // ... other types like EWALLET, DIRECT_DEBIT etc.
}

#[derive(Debug, Clone, Serialize)]
pub struct XenditLineItem {
    pub name: String,
    pub quantity: i32,
    pub price: i64,
    pub category: Option<String>,
    pub url: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum XenditResponse {
    Payment(XenditPaymentResponse),
    Webhook(XenditWebhookEvent),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct XenditWebhookEvent {
    pub event: XenditEventType,
    pub data: EventDetails,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum XenditEventType {
    #[serde(rename = "payment.succeeded")]
    PaymentSucceeded,
    #[serde(rename = "payment.awaiting_capture")]
    PaymentAwaitingCapture,
    #[serde(rename = "payment.failed")]
    PaymentFailed,
    #[serde(rename = "capture.succeeded")]
    CaptureSucceeded,
    #[serde(rename = "capture.failed")]
    CaptureFailed,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EventDetails {
    pub id: String,
    pub payment_request_id: Option<String>,
    pub amount: FloatMajorUnit,
    pub currency: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct XenditPaymentActions {
    #[serde(rename = "desktop_web_checkout_url")]
    pub desktop_redirect_url: Option<String>,
    #[serde(rename = "mobile_web_checkout_url")]
    pub mobile_redirect_url: Option<String>,
    #[serde(rename = "mobile_deeplink_checkout_url")]
    pub mobile_deeplink_url: Option<String>,
    // QR code URL if applicable
    #[serde(rename = "qr_checkout_string")]
    pub qr_code_url: Option<String>,
}

// Xendit Error Response Structure (from Hyperswitch xendit.rs)
#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct XenditErrorResponse {
    pub error_code: Option<String>,
    pub message: Option<String>,
    pub reason: Option<String>, // This might not be standard, check Xendit docs
                                // Xendit might have more structured errors, e.g. a list of errors
                                // errors: Option<Vec<XenditErrorDetail>>
}

fn is_auto_capture(data: &PaymentsAuthorizeData) -> Result<bool, ConnectorError> {
    match data.capture_method {
        Some(hyperswitch_common_enums::CaptureMethod::Automatic) | None => Ok(true),
        Some(hyperswitch_common_enums::CaptureMethod::Manual) => Ok(false),
        Some(_) => Err(ConnectorError::CaptureMethodNotSupported),
    }
}

fn is_auto_capture_psync(data: &PaymentsSyncData) -> Result<bool, ConnectorError> {
    match data.capture_method {
        Some(hyperswitch_common_enums::CaptureMethod::Automatic) | None => Ok(true),
        Some(hyperswitch_common_enums::CaptureMethod::Manual) => Ok(false),
        Some(_) => Err(ConnectorError::CaptureMethodNotSupported),
    }
}

fn map_payment_response_to_attempt_status(
    response: XenditPaymentResponse,
    is_auto_capture: bool,
) -> hyperswitch_common_enums::AttemptStatus {
    match response.status {
        PaymentStatus::Failed => hyperswitch_common_enums::AttemptStatus::Failure,
        PaymentStatus::Succeeded | PaymentStatus::Verified => {
            if is_auto_capture {
                hyperswitch_common_enums::AttemptStatus::Charged
            } else {
                hyperswitch_common_enums::AttemptStatus::Authorized
            }
        }
        PaymentStatus::Pending => hyperswitch_common_enums::AttemptStatus::Pending,
        PaymentStatus::RequiresAction => {
            hyperswitch_common_enums::AttemptStatus::AuthenticationPending
        }
        PaymentStatus::AwaitingCapture => hyperswitch_common_enums::AttemptStatus::Authorized,
    }
}

// Transformer for Request: RouterData -> XenditPaymentsRequest
impl
    TryFrom<(
        &XenditRouterData<
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    )> for XenditPaymentsRequest
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;
    fn try_from(
        value: (
            &XenditRouterData<
                &RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData,
                    PaymentsResponseData,
                >,
            >,
        ),
    ) -> Result<Self, Self::Error> {
        let (item,) = value;
        let card_data = match &item.router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => Ok(card),
            _ => Err(ConnectorError::RequestEncodingFailed),
        }?;
        let capture_method = match is_auto_capture(&item.router_data.request)? {
            true => "AUTOMATIC".to_string(),
            false => "MANUAL".to_string(),
        };

        let currency = item.router_data.request.currency;
        let amount = item.amount;

        let payment_method = Some(PaymentMethod::Card(CardPaymentRequest {
            payment_type: PaymentMethodType::CARD,
            reference_id: Secret::new(item.router_data.connector_request_reference_id.clone()),
            card: CardInfo {
                channel_properties: ChannelProperties {
                    success_return_url: item.router_data.request.router_return_url.clone(),
                    failure_return_url: item.router_data.request.router_return_url.clone(),
                    skip_three_d_secure: !item.router_data.request.enrolled_for_3ds,
                },
                card_information: CardInformation {
                    card_number: card_data.card_number.clone(),
                    expiry_month: card_data.card_exp_month.clone(),
                    expiry_year: card_data.card_exp_year.clone(),
                    cvv: card_data.card_cvc.clone(),
                    // cardholder_name_not_found
                    // cardholder_name: Secret::new("Test User".to_string()),
                    // cardholder_email: pii::Email::try_from("test@example.com".to_string())
                    // .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?,
                    // cardholder_phone_number: Secret::new("+1234567890".to_string()),
                },
            },
            reusability: TransactionType::OneTimeUse,
        }));
        let payment_method_id = None;
        let channel_properties = None;
        Ok(XenditPaymentsRequest {
            amount,
            currency,
            capture_method,
            payment_method,
            payment_method_id,
            channel_properties,
        })
    }
}

impl<F>
    ForeignTryFrom<(
        XenditPaymentResponse,
        RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        u16,
    )> for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
{
    type Error = Error;
    fn foreign_try_from(
        (response, item, http_code): (
            XenditPaymentResponse,
            RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
            u16,
        ),
    ) -> Result<Self, Self::Error> {
        let status = map_payment_response_to_attempt_status(
            response.clone(),
            is_auto_capture(&item.request)?,
        );

        let response = if status == hyperswitch_common_enums::AttemptStatus::Failure {
            Err(ErrorResponse {
                code: response
                    .failure_code
                    .clone()
                    .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                message: response
                    .failure_code
                    .clone()
                    .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                reason: Some(
                    response
                        .failure_code
                        .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                ),
                attempt_status: None,
                connector_transaction_id: Some(response.id.clone()),
                status_code: http_code,
                // network_advice_code: None,
                // network_decline_code: None,
                // network_error_message: None,
            })
        } else {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.id.clone()),
                redirection_data: match response.actions {
                    Some(actions) if !actions.is_empty() => {
                        actions.first().map_or(Box::new(None), |single_action| {
                            Box::new(Some(RedirectForm::Form {
                                endpoint: single_action.url.clone(),
                                method: match single_action.method {
                                    MethodType::Get => Method::Get,
                                    MethodType::Post => Method::Post,
                                },
                                form_fields: HashMap::new(),
                            }))
                        })
                    }
                    _ => Box::new(None),
                },
                mandate_reference: match is_mandate_payment(&item.request) {
                    true => Box::new(Some(MandateReference {
                        connector_mandate_id: Some(response.payment_method.id.expose()),
                        payment_method_id: None,
                    })),
                    false => Box::new(None),
                },
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(response.reference_id.peek().to_string()),
                incremental_authorization_allowed: None,
                raw_connector_response: None,
            })
        };

        Ok(Self {
            response,
            resource_common_data: PaymentFlowData {
                status,
                ..item.resource_common_data
            },
            ..item
        })
    }
}

impl<F>
    ForeignTryFrom<(
        XenditResponse,
        RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        u16,
    )> for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = Error;
    fn foreign_try_from(
        (response, item, http_code): (
            XenditResponse,
            RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            u16,
        ),
    ) -> Result<Self, Self::Error> {
        match response {
            XenditResponse::Payment(payment_response) => {
                let status = map_payment_response_to_attempt_status(
                    payment_response.clone(),
                    is_auto_capture_psync(&item.request)?,
                );
                let response = if status == hyperswitch_common_enums::AttemptStatus::Failure {
                    Err(ErrorResponse {
                        code: payment_response
                            .failure_code
                            .clone()
                            .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                        message: payment_response
                            .failure_code
                            .clone()
                            .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                        reason: Some(
                            payment_response
                                .failure_code
                                .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                        ),
                        attempt_status: None,
                        connector_transaction_id: Some(payment_response.id.clone()),
                        status_code: http_code,
                        //network_advice_code: None,
                        // network_decline_code: None,
                        //network_error_message: None,
                    })
                } else {
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::NoResponseId,
                        redirection_data: Box::new(None),
                        mandate_reference: Box::new(None),
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        raw_connector_response: None,
                        // charges: None,
                    })
                };
                Ok(Self {
                    response,
                    resource_common_data: PaymentFlowData {
                        status,
                        ..item.resource_common_data
                    },
                    ..item
                })
            }
            XenditResponse::Webhook(webhook_event) => {
                let status = match webhook_event.event {
                    XenditEventType::PaymentSucceeded | XenditEventType::CaptureSucceeded => {
                        hyperswitch_common_enums::AttemptStatus::Charged
                    }
                    XenditEventType::PaymentAwaitingCapture => {
                        hyperswitch_common_enums::AttemptStatus::Authorized
                    }
                    XenditEventType::PaymentFailed | XenditEventType::CaptureFailed => {
                        hyperswitch_common_enums::AttemptStatus::Failure
                    }
                };
                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status,
                        ..item.resource_common_data
                    },
                    ..item
                })
            }
        }
    }
}

impl
    TryFrom<
        XenditRouterData<
            &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for XenditPaymentsCaptureRequest
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;
    fn try_from(
        item: XenditRouterData<
            &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            capture_amount: item.amount,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct XenditPaymentsCaptureRequest {
    pub capture_amount: FloatMajorUnit,
}

impl<F>
    ForeignTryFrom<(
        XenditPaymentResponse,
        RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        u16,
    )> for RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn foreign_try_from(
        (response, item, http_code): (
            XenditPaymentResponse,
            RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            u16,
        ),
    ) -> Result<Self, Self::Error> {
        let status = map_payment_response_to_attempt_status(response.clone(), true);
        let response = if status == hyperswitch_common_enums::AttemptStatus::Failure {
            Err(ErrorResponse {
                code: response
                    .failure_code
                    .clone()
                    .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                message: response
                    .failure_code
                    .clone()
                    .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                reason: Some(
                    response
                        .failure_code
                        .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                ),
                attempt_status: None,
                connector_transaction_id: None,
                status_code: http_code,
                // network_advice_code: None,
                // network_decline_code: None,
                // network_error_message: None,
            })
        } else {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::NoResponseId,
                redirection_data: Box::new(None),
                mandate_reference: Box::new(None),
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(response.reference_id.peek().to_string()),
                incremental_authorization_allowed: None,
                raw_connector_response: None,
                //charges: None,
            })
        };
        Ok(Self {
            response,
            resource_common_data: PaymentFlowData {
                status,
                ..item.resource_common_data
            },
            ..item
        })
    }
}

#[derive(Default, Debug, Serialize)]
pub struct XenditRefundRequest {
    pub amount: FloatMajorUnit,
    pub payment_request_id: String,
    pub reason: String,
}

impl<F>
    TryFrom<&XenditRouterData<&RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>>>
    for XenditRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &XenditRouterData<&RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: item.amount.to_owned(),
            payment_request_id: item.router_data.request.connector_transaction_id.clone(),
            reason: "REQUESTED_BY_CUSTOMER".to_string(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundResponse {
    pub id: String,
    pub status: RefundStatus,
    pub amount: FloatMajorUnit,
    pub currency: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RefundStatus {
    RequiresAction,
    Succeeded,
    Failed,
    Pending,
    Cancelled,
}

impl<F>
    ForeignTryFrom<(
        RefundResponse,
        RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
        u16,
    )> for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn foreign_try_from(
        (response, item, _http_code): (
            RefundResponse,
            RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
            u16,
        ),
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: response.id,
                refund_status: hyperswitch_common_enums::RefundStatus::from(response.status),
                raw_connector_response: None,
            }),
            ..item
        })
    }
}

impl From<RefundStatus> for hyperswitch_common_enums::RefundStatus {
    fn from(item: RefundStatus) -> Self {
        match item {
            RefundStatus::Succeeded => Self::Success,
            RefundStatus::Failed | RefundStatus::Cancelled => Self::Failure,
            RefundStatus::Pending | RefundStatus::RequiresAction => Self::Pending,
        }
    }
}

impl<F>
    ForeignTryFrom<(
        RefundResponse,
        RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>,
        u16,
    )> for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn foreign_try_from(
        (response, item, _http_code): (
            RefundResponse,
            RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>,
            u16,
        ),
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: response.id,
                refund_status: hyperswitch_common_enums::RefundStatus::from(response.status),
                raw_connector_response: None,
            }),
            ..item
        })
    }
}

fn is_mandate_payment(item: &PaymentsAuthorizeData) -> bool {
    (item.setup_future_usage == Some(hyperswitch_common_enums::enums::FutureUsage::OffSession))
        || item
            .mandate_id
            .as_ref()
            .and_then(|mandate_ids| mandate_ids.mandate_reference_id.as_ref())
            .is_some()
}
