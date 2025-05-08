use std::collections::HashMap;

use error_stack::ResultExt;
use hyperswitch_api_models::enums::{self, AttemptStatus, CardNetwork};

use hyperswitch_cards::CardNumber;
use hyperswitch_common_enums::RefundStatus;
use hyperswitch_common_utils::{
    ext_traits::ByteSliceExt, pii::Email, request::Method, types::MinorUnit,
};

use domain_types::{
    connector_flow::{Authorize, Capture, CreateOrder, RSync, Refund},
    connector_types::{
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsResponseData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
};
use hyperswitch_domain_models::{
    payment_method_data::{Card, PaymentMethodData},
    router_data::{ConnectorAuthType, RouterData},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use hyperswitch_interfaces::errors;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub enum Currency {
    #[default]
    USD,
    EUR,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Amount {
    pub currency: enums::Currency,
    pub value: MinorUnit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CardBrand {
    Visa,
}

#[derive(Debug, PartialEq)]
pub enum ConnectorError {
    ParsingFailed,
    NotImplemented,
    FailedToObtainAuthType,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RazorpayCard {
    number: CardNumber,
    expiry_month: Secret<String>,
    expiry_year: Secret<String>,
    cvc: Option<Secret<String>>,
    holder_name: Option<Secret<String>>,
    brand: Option<CardNetwork>,
    network_payment_reference: Option<Secret<String>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "lowercase")]
pub enum RazorpayPaymentMethod {
    #[serde(rename = "scheme")]
    RazorpayCard(Box<RazorpayCard>),
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub enum AuthType {
    #[default]
    PreAuth,
}

#[serde_with::skip_serializing_none]
#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Address {
    city: String,
    country: enums::CountryAlpha2,
    house_number_or_name: Secret<String>,
    postal_code: Secret<String>,
    state_or_province: Option<Secret<String>>,
    street: Option<Secret<String>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum PaymentMethod {
    RazorpayPaymentMethod(Box<RazorpayPaymentMethod>),
}

#[serde_with::skip_serializing_none]
#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CardDetails {
    pub number: CardNumber,
    pub name: Option<String>,
    pub expiry_month: Option<Secret<String>>,
    pub expiry_year: Secret<String>,
    pub cvv: Option<Secret<String>>,
}

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationChannel {
    #[default]
    Browser,
    App,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AuthenticationDetails {
    pub authentication_channel: AuthenticationChannel,
}

#[serde_with::skip_serializing_none]
#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct BrowserInfo {
    pub java_enabled: Option<bool>,
    pub javascript_enabled: Option<bool>,
    pub timezone_offset: Option<i32>,
    pub color_depth: Option<i32>,
    pub screen_width: Option<i32>,
    pub screen_height: Option<i32>,
    pub language: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RazorpayPaymentRequest {
    pub amount: MinorUnit,
    pub currency: String,
    pub contact: Secret<String>,
    pub email: Email,
    pub order_id: String,
    pub method: PaymentMethodType,
    pub card: PaymentMethodSpecificData,
    pub authentication: Option<AuthenticationDetails>,
    pub browser: Option<BrowserInfo>,
    pub ip: String,
    pub referer: String,
    pub user_agent: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged, rename_all = "snake_case")]
pub enum PaymentMethodSpecificData {
    Card(CardDetails),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PaymentMethodType {
    Card,
    Wallet,
    Upi,
    Emi,
    Netbanking,
}

#[derive(Debug, Serialize)]
pub struct RazorpayRouterData<T> {
    pub amount: MinorUnit,
    pub router_data: T,
}

impl<T> TryFrom<(MinorUnit, T)> for RazorpayRouterData<T> {
    type Error = hyperswitch_interfaces::errors::ConnectorError;
    fn try_from((amount, item): (MinorUnit, T)) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            router_data: item,
        })
    }
}

pub struct RazorpayAuthType {
    pub(super) key_id: Secret<String>,
    pub(super) secret_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for RazorpayAuthType {
    type Error = hyperswitch_interfaces::errors::ConnectorError;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                key_id: api_key.to_owned(),
                secret_key: key1.to_owned(),
            }),
            _ => Err(hyperswitch_interfaces::errors::ConnectorError::FailedToObtainAuthType),
        }
    }
}

impl TryFrom<(&Card, Option<Secret<String>>)> for RazorpayPaymentMethod {
    type Error = ConnectorError;
    fn try_from(
        (card, card_holder_name): (&Card, Option<Secret<String>>),
    ) -> Result<Self, Self::Error> {
        let razorpay_card = RazorpayCard {
            number: card.card_number.clone(),
            expiry_month: card.card_exp_month.clone(),
            expiry_year: card.card_exp_year.clone(),
            cvc: Some(card.card_cvc.clone()),
            holder_name: card_holder_name,
            brand: card.card_network.clone(),
            network_payment_reference: None,
        };
        Ok(RazorpayPaymentMethod::RazorpayCard(Box::new(razorpay_card)))
    }
}

fn extract_payment_method_and_data(
    payment_method_data: &PaymentMethodData,
    customer_name: Option<String>,
) -> Result<
    (PaymentMethodType, PaymentMethodSpecificData),
    hyperswitch_interfaces::errors::ConnectorError,
> {
    match payment_method_data {
        PaymentMethodData::Card(card_data) => {
            let card_holder_name = customer_name.clone();

            let card = PaymentMethodSpecificData::Card(CardDetails {
                number: card_data.card_number.clone(),
                name: card_holder_name,
                expiry_month: Some(card_data.card_exp_month.clone()),
                expiry_year: card_data.card_exp_year.clone(),
                cvv: Some(card_data.card_cvc.clone()),
            });

            Ok((PaymentMethodType::Card, card))
        }
        PaymentMethodData::CardRedirect(_)
        | PaymentMethodData::Wallet(_)
        | PaymentMethodData::PayLater(_)
        | PaymentMethodData::BankRedirect(_)
        | PaymentMethodData::BankDebit(_)
        | PaymentMethodData::BankTransfer(_)
        | PaymentMethodData::Crypto(_)
        | PaymentMethodData::MandatePayment
        | PaymentMethodData::Reward
        | PaymentMethodData::RealTimePayment(_)
        | PaymentMethodData::Upi(_)
        | PaymentMethodData::Voucher(_)
        | PaymentMethodData::GiftCard(_)
        | PaymentMethodData::CardToken(_)
        | PaymentMethodData::OpenBanking(_) => Err(
            hyperswitch_interfaces::errors::ConnectorError::NotImplemented(
                "Only Card payment method is supported for Razorpay".to_string(),
            ),
        ),
    }
}

impl
    TryFrom<(
        &RazorpayRouterData<
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
        &Card,
    )> for RazorpayPaymentRequest
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn try_from(
        value: (
            &RazorpayRouterData<
                &RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData,
                    PaymentsResponseData,
                >,
            >,
            &Card,
        ),
    ) -> Result<Self, Self::Error> {
        let (item, _card_data) = value;
        let amount = item.amount;
        let currency = item.router_data.request.currency.to_string();

        let billing = item
            .router_data
            .resource_common_data
            .address
            .get_payment_billing();

        let contact = billing
            .and_then(|billing| billing.phone.as_ref())
            .and_then(|phone| phone.number.clone())
            .ok_or(
                hyperswitch_interfaces::errors::ConnectorError::MissingRequiredField {
                    field_name: "contact",
                },
            )?;

        let email = item.router_data.request.email.clone().ok_or(
            hyperswitch_interfaces::errors::ConnectorError::MissingRequiredField {
                field_name: "email",
            },
        )?;

        let order_id = item.router_data.reference_id.clone().ok_or(
            hyperswitch_interfaces::errors::ConnectorError::MissingRequiredField {
                field_name: "order_id",
            },
        )?;

        let (method, card) = extract_payment_method_and_data(
            &item.router_data.request.payment_method_data,
            item.router_data.request.customer_name.clone(),
        )?;

        let browser_info_opt = item.router_data.request.browser_info.as_ref();

        let authentication_channel = match browser_info_opt {
            Some(_) => AuthenticationChannel::Browser,
            None => AuthenticationChannel::App,
        };

        let authentication = Some(AuthenticationDetails {
            authentication_channel,
        });

        let browser = browser_info_opt.map(|info| BrowserInfo {
            java_enabled: info.java_enabled,
            javascript_enabled: info.java_script_enabled,
            timezone_offset: info.time_zone,
            color_depth: info.color_depth.map(|v| v as i32),
            screen_width: info.screen_width.map(|v| v as i32),
            screen_height: info.screen_height.map(|v| v as i32),
            language: info.language.clone(),
        });

        let ip = browser_info_opt
            .and_then(|info| info.ip_address)
            .map(|ip| ip.to_string())
            .unwrap_or_default();

        let user_agent = browser_info_opt
            .and_then(|info| info.user_agent.clone())
            .unwrap_or_default();

        let referer = browser_info_opt
            .and_then(|info| info.accept_header.clone())
            .unwrap_or_default();

        Ok(RazorpayPaymentRequest {
            amount,
            currency,
            contact,
            email,
            order_id,
            method,
            card,
            authentication,
            browser,
            ip,
            referer,
            user_agent,
        })
    }
}

impl
    TryFrom<
        &RazorpayRouterData<
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for RazorpayPaymentRequest
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn try_from(
        item: &RazorpayRouterData<
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        match &item.router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => RazorpayPaymentRequest::try_from((item, card)),
            _ => Err(
                hyperswitch_interfaces::errors::ConnectorError::NotImplemented(
                    "Only card payments are supported".into(),
                ),
            ),
        }
    }
}

pub struct ResponseRouterData<Flow, R, Request, Response> {
    pub response: R,
    pub data: RouterData<Flow, Request, Response>,
    pub http_code: u16,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RazorpayPaymentResponse {
    pub razorpay_payment_id: String,
    pub next: Option<Vec<NextAction>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NextAction {
    pub action: String,
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged, rename_all = "snake_case")]
pub enum RazorpayResponse {
    PaymentResponse(Box<RazorpayPaymentResponse>),
    PsyncResponse(Box<RazorpayPsyncResponse>),
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RazorpayPsyncResponse {
    pub id: String,
    pub entity: String,
    pub amount: i64,
    pub base_amount: i64,
    pub currency: String,
    pub base_currency: String,
    pub status: RazorpayStatus,
    pub method: PaymentMethodType,
    pub order_id: Option<String>,
    pub invoice_id: Option<String>,
    pub description: Option<String>,
    pub international: bool,
    pub refund_status: Option<String>,
    pub amount_refunded: i64,
    pub captured: bool,
    pub email: String,
    pub contact: String,
    pub fee: Option<i64>,
    pub tax: Option<i64>,
    pub error_code: Option<String>,
    pub error_description: Option<String>,
    pub error_source: Option<String>,
    pub error_step: Option<String>,
    pub error_reason: Option<String>,
    pub notes: Option<HashMap<String, String>>,
    pub created_at: i64,
    pub card_id: Option<String>,
    pub card: Option<SyncCardDetails>,
    pub upi: Option<SyncUPIDetails>,
    pub acquirer_data: Option<AcquirerData>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RazorpayRefundResponse {
    pub id: String,
    pub status: RazorpayRefundStatus,
    pub receipt: Option<String>,
    pub amount: i64,
    pub currency: String,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RazorpayRefundRequest {
    pub amount: MinorUnit,
}

impl ForeignTryFrom<RazorpayRefundStatus> for hyperswitch_common_enums::RefundStatus {
    type Error = hyperswitch_interfaces::errors::ConnectorError;
    fn foreign_try_from(item: RazorpayRefundStatus) -> Result<Self, Self::Error> {
        match item {
            RazorpayRefundStatus::Failed => Ok(Self::Failure),
            RazorpayRefundStatus::Pending | RazorpayRefundStatus::Created => Ok(Self::Pending),
            RazorpayRefundStatus::Processed => Ok(Self::Success),
        }
    }
}

impl
    TryFrom<
        &RazorpayRouterData<
            &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RazorpayRefundRequest
{
    type Error = errors::ConnectorError;
    fn try_from(
        item: &RazorpayRouterData<
            &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: item.amount,
        })
    }
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SyncCardDetails {
    pub id: String,
    pub entity: String,
    pub name: String,
    pub last4: String,
    pub network: String,
    pub r#type: String,
    pub issuer: Option<String>,
    pub emi: bool,
    pub sub_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SyncUPIDetails {
    pub payer_account_type: String,
    pub vpa: String,
    pub flow: String,
    pub bank: String,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AcquirerData {
    pub auth_code: Option<String>,
    pub rrn: Option<String>,
    pub authentication_reference_number: Option<String>,
    pub bank_transaction_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RazorpayStatus {
    Created,
    Authorized,
    Captured,
    Refunded,
    Failed,
}

#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMethod {
    #[default]
    Automatic,
    Manual,
    ManualMultiple,
    Scheduled,
    SequentialAutomatic,
}

pub trait ForeignTryFrom<F>: Sized {
    type Error;

    fn foreign_try_from(from: F) -> Result<Self, Self::Error>;
}

fn get_authorization_razorpay_payment_status_from_action(
    is_manual_capture: bool,
    has_next_action: bool,
) -> AttemptStatus {
    if has_next_action {
        AttemptStatus::AuthenticationPending
    } else if is_manual_capture {
        AttemptStatus::Authorized
    } else {
        AttemptStatus::Charged
    }
}

fn get_psync_razorpay_payment_status(
    is_manual_capture: bool,
    razorpay_status: RazorpayStatus,
) -> AttemptStatus {
    match razorpay_status {
        RazorpayStatus::Created => AttemptStatus::Pending,
        RazorpayStatus::Authorized => {
            if is_manual_capture {
                AttemptStatus::Authorized
            } else {
                AttemptStatus::Charged
            }
        }
        RazorpayStatus::Captured => AttemptStatus::Charged,
        RazorpayStatus::Refunded => AttemptStatus::AutoRefunded,
        RazorpayStatus::Failed => AttemptStatus::Failure,
    }
}

impl
    ForeignTryFrom<(
        RazorpayRefundResponse,
        RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    )> for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn foreign_try_from(
        (response, data): (
            RazorpayRefundResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        ),
    ) -> Result<Self, Self::Error> {
        let status = hyperswitch_common_enums::RefundStatus::foreign_try_from(response.status)?;

        let refunds_response_data = RefundsResponseData {
            connector_refund_id: response.id,
            refund_status: status,
        };

        Ok(Self {
            resource_common_data: RefundFlowData {
                status,
                ..data.resource_common_data
            },
            response: Ok(refunds_response_data),
            ..data
        })
    }
}

impl
    ForeignTryFrom<(
        RazorpayRefundResponse,
        RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    )> for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn foreign_try_from(
        (response, data): (
            RazorpayRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        ),
    ) -> Result<Self, Self::Error> {
        let status = hyperswitch_common_enums::RefundStatus::foreign_try_from(response.status)?;

        let refunds_response_data = RefundsResponseData {
            connector_refund_id: response.id,
            refund_status: status,
        };

        Ok(Self {
            resource_common_data: RefundFlowData {
                status,
                ..data.resource_common_data
            },
            response: Ok(refunds_response_data),
            ..data
        })
    }
}

impl<F, Req>
    ForeignTryFrom<(
        RazorpayResponse,
        RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
        u16,
        Option<hyperswitch_api_models::enums::CaptureMethod>,
        bool,
        Option<hyperswitch_api_models::enums::PaymentMethodType>,
    )> for RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn foreign_try_from(
        (response, data, _http_code, _capture_method, _is_multiple_capture_psync_flow, _pmt): (
            RazorpayResponse,
            RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
            u16,
            Option<hyperswitch_api_models::enums::CaptureMethod>,
            bool,
            Option<hyperswitch_api_models::enums::PaymentMethodType>,
        ),
    ) -> Result<Self, Self::Error> {
        let is_manual_capture = false;

        match response {
            RazorpayResponse::PaymentResponse(payment_response) => {
                let status =
                    get_authorization_razorpay_payment_status_from_action(is_manual_capture, true);
                let redirect_url = payment_response
                    .next
                    .as_ref()
                    .and_then(|next_actions| next_actions.first())
                    .map(|action| action.url.clone())
                    .ok_or_else(|| {
                        hyperswitch_interfaces::errors::ConnectorError::MissingRequiredField {
                            field_name: "next.url",
                        }
                    })?;

                let form_fields = HashMap::new();

                let payment_response_data = PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(
                        payment_response.razorpay_payment_id.clone(),
                    ),
                    redirection_data: Box::new(Some(RedirectForm::Form {
                        endpoint: redirect_url,
                        method: Method::Get,
                        form_fields,
                    })),
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                };
                let error = None;

                Ok(Self {
                    response: error.map_or_else(|| Ok(payment_response_data), Err),
                    resource_common_data: PaymentFlowData {
                        status,
                        ..data.resource_common_data
                    },
                    ..data
                })
            }
            RazorpayResponse::PsyncResponse(psync_response) => {
                let status =
                    get_psync_razorpay_payment_status(is_manual_capture, psync_response.status);
                let psync_response_data = PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(psync_response.id),
                    redirection_data: Box::new(None),
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                };
                let error = None;

                Ok(Self {
                    response: error.map_or_else(|| Ok(psync_response_data), Err),
                    resource_common_data: PaymentFlowData {
                        status,
                        ..data.resource_common_data
                    },
                    ..data
                })
            }
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RazorpayErrorResponse {
    pub error: RazorpayError,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RazorpayError {
    pub code: String,
    pub description: String,
    pub source: String,
    pub step: String,
    pub reason: String,
    pub metadata: Option<Metadata>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Metadata {
    pub order_id: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RazorpayOrderRequest {
    pub amount: MinorUnit,
    pub currency: String,
    pub receipt: String,
    pub partial_payment: Option<bool>,
    pub first_payment_min_amount: Option<MinorUnit>,
    pub notes: Option<RazorpayNotes>,
}

impl
    TryFrom<
        &RazorpayRouterData<
            &RouterDataV2<
                CreateOrder,
                PaymentFlowData,
                PaymentCreateOrderData,
                PaymentCreateOrderResponse,
            >,
        >,
    > for RazorpayOrderRequest
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn try_from(
        item: &RazorpayRouterData<
            &RouterDataV2<
                CreateOrder,
                PaymentFlowData,
                PaymentCreateOrderData,
                PaymentCreateOrderResponse,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let request_data = &item.router_data.request;

        Ok(RazorpayOrderRequest {
            amount: item.amount,
            currency: request_data.currency.to_string(),
            receipt: uuid::Uuid::new_v4().to_string(),
            partial_payment: None,
            first_payment_min_amount: None,
            notes: None,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum RazorpayNotes {
    Map(HashMap<String, String>),
    EmptyVec(Vec<()>),
}
#[serde_with::skip_serializing_none]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RazorpayOrderResponse {
    pub id: String,
    pub entity: String,
    pub amount: MinorUnit,
    pub amount_paid: MinorUnit,
    pub amount_due: MinorUnit,
    pub currency: String,
    pub receipt: String,
    pub status: String,
    pub attempts: u32,
    pub notes: Option<RazorpayNotes>,
    pub offer_id: Option<String>,
    pub created_at: u64,
}

impl
    ForeignTryFrom<(
        RazorpayOrderResponse,
        RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
        u16,
        bool,
    )>
    for RouterDataV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    >
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn foreign_try_from(
        (response, data, _status_code, _): (
            RazorpayOrderResponse,
            RouterDataV2<
                CreateOrder,
                PaymentFlowData,
                PaymentCreateOrderData,
                PaymentCreateOrderResponse,
            >,
            u16,
            bool,
        ),
    ) -> Result<Self, Self::Error> {
        let order_response = PaymentCreateOrderResponse {
            order_id: response.id,
        };

        Ok(Self {
            response: Ok(order_response),
            ..data
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RazorpayWebhook {
    pub account_id: String,
    pub contains: Vec<String>,
    pub entity: String,
    pub event: String,
    pub payload: Payload,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Payload {
    pub payment: Option<PaymentWrapper>,
    pub refund: Option<RefundWrapper>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct PaymentWrapper {
    pub entity: PaymentEntity,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RefundWrapper {
    pub entity: RefundEntity,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct PaymentEntity {
    pub id: String,
    pub entity: RazorpayEntity,
    pub amount: i64,
    pub currency: String,
    pub status: RazorpayPaymentStatus,
    pub order_id: String,
    pub invoice_id: Option<String>,
    pub international: bool,
    pub method: String,
    pub amount_refunded: i64,
    pub refund_status: Option<String>,
    pub captured: bool,
    pub description: Option<String>,
    pub card_id: Option<String>,
    pub bank: Option<String>,
    pub wallet: Option<String>,
    pub vpa: Option<String>,
    pub email: Option<String>,
    pub contact: Option<String>,
    pub notes: Vec<String>,
    pub fee: Option<i64>,
    pub tax: Option<i64>,
    pub error_code: Option<String>,
    pub error_description: Option<String>,
    pub error_reason: Option<String>,
    pub error_source: Option<String>,
    pub error_step: Option<String>,
    pub acquirer_data: Option<AcquirerData>,
    pub card: Option<RazorpayWebhookCard>,
    pub token_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RefundEntity {
    pub id: String,
    pub entity: RazorpayEntity,
    pub amount: i64,
    pub currency: String,
    pub payment_id: String,
    pub status: RazorpayRefundStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RazorpayEntity {
    Payment,
    Refund,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RazorpayPaymentStatus {
    Authorized,
    Captured,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RazorpayRefundStatus {
    Created,
    Processed,
    Failed,
    Pending,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RazorpayWebhookCard {
    pub id: String,
    pub entity: String,
    pub name: String,
    pub last4: String,
    pub network: String,
    #[serde(rename = "type")]
    pub card_type: String,
    pub sub_type: String,
    pub issuer: Option<String>,
    pub international: bool,
    pub iin: String,
    pub emi: bool,
}

pub fn get_webhook_object_from_body(
    body: Vec<u8>,
) -> Result<Payload, error_stack::Report<errors::ConnectorError>> {
    let webhook: RazorpayWebhook = body
        .parse_struct("RazorpayWebhook")
        .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)?;
    Ok(webhook.payload)
}

pub(crate) fn get_razorpay_payment_webhook_status(
    entity: RazorpayEntity,
    status: RazorpayPaymentStatus,
) -> Result<AttemptStatus, errors::ConnectorError> {
    match entity {
        RazorpayEntity::Payment => match status {
            RazorpayPaymentStatus::Authorized => Ok(AttemptStatus::Authorized),
            RazorpayPaymentStatus::Captured => Ok(AttemptStatus::Charged),
            RazorpayPaymentStatus::Failed => Ok(AttemptStatus::AuthorizationFailed),
        },
        RazorpayEntity::Refund => Err(errors::ConnectorError::RequestEncodingFailed),
    }
}

pub(crate) fn get_razorpay_refund_webhook_status(
    entity: RazorpayEntity,
    status: RazorpayRefundStatus,
) -> Result<RefundStatus, errors::ConnectorError> {
    match entity {
        RazorpayEntity::Refund => match status {
            RazorpayRefundStatus::Processed => Ok(RefundStatus::Success),
            RazorpayRefundStatus::Created | RazorpayRefundStatus::Pending => {
                Ok(RefundStatus::Pending)
            }
            RazorpayRefundStatus::Failed => Ok(RefundStatus::Failure),
        },
        RazorpayEntity::Payment => Err(errors::ConnectorError::RequestEncodingFailed),
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RazorpayCaptureRequest {
    pub amount: MinorUnit,
    pub currency: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RazorpayCaptureResponse {
    pub id: String,
    pub entity: RazorpayEntity,
    pub amount: i64,
    pub currency: String,
    pub status: RazorpayPaymentStatus,
    pub order_id: String,
    pub invoice_id: Option<String>,
    pub international: bool,
    pub method: String,
    pub amount_refunded: i64,
    pub refund_status: Option<String>,
    pub captured: bool,
    pub description: Option<String>,
    pub card_id: Option<String>,
    pub bank: Option<String>,
    pub wallet: Option<String>,
    pub vpa: Option<String>,
    pub email: Option<String>,
    pub contact: Option<String>,
    pub customer_id: Option<String>,
    pub token_id: Option<String>,
    pub notes: Vec<String>,
    pub fee: Option<i64>,
    pub tax: Option<i64>,
    pub error_code: Option<String>,
    pub error_description: Option<String>,
    pub error_reason: Option<String>,
    pub error_source: Option<String>,
    pub error_step: Option<String>,
    pub acquirer_data: Option<AcquirerData>,
}

impl
    TryFrom<
        &RazorpayRouterData<
            &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RazorpayCaptureRequest
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn try_from(
        item: &RazorpayRouterData<
            &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let request_data = &item.router_data.request;

        Ok(RazorpayCaptureRequest {
            amount: item.amount,
            currency: request_data.currency.to_string(),
        })
    }
}

impl<F, Req>
    ForeignTryFrom<(
        RazorpayCaptureResponse,
        RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
    )> for RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;
    fn foreign_try_from(
        (response, data): (
            RazorpayCaptureResponse,
            RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
        ),
    ) -> Result<Self, Self::Error> {
        let status = match response.status {
            RazorpayPaymentStatus::Captured => AttemptStatus::Charged,
            RazorpayPaymentStatus::Authorized => AttemptStatus::Authorized,
            RazorpayPaymentStatus::Failed => AttemptStatus::Failure,
        };
        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.id),
                redirection_data: Box::new(None),
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(response.order_id),
                incremental_authorization_allowed: None,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..data.resource_common_data
            },
            ..data
        })
    }
}
