use std::collections::HashMap;

use error_stack::ResultExt;
use hyperswitch_api_models::enums::{self, AttemptStatus, CardNetwork};

use hyperswitch_cards::CardNumber;
use hyperswitch_common_enums::RefundStatus;
use hyperswitch_common_utils::{
    ext_traits::ByteSliceExt,
    pii::{Email, UpiVpaMaskingStrategy},
    request::Method,
    types::MinorUnit,
};

pub struct PayUAuthType {
    pub(super) key_id: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for PayUAuthType {
    type Error = hyperswitch_interfaces::errors::ConnectorError;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                key_id: api_key.to_owned(),
            }),
            _ => Err(hyperswitch_interfaces::errors::ConnectorError::FailedToObtainAuthType),
        }
    }
}

use domain_types::{
    connector_flow::{Authorize, Capture, CreateOrder, RSync, Refund},
    connector_types::{
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsResponseData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
};
use hyperswitch_domain_models::{
    payment_method_data::{Card, PaymentMethodData, UpiData},
    router_data::{ConnectorAuthType, RouterData},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use hyperswitch_interfaces::errors;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

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

#[serde_with::skip_serializing_none]
#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UpiDetails {
    flow: UpiAction,
    vpa: Option<Secret<String, UpiVpaMaskingStrategy>>,
}

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum UpiAction {
    #[default]
    Collect,
    Intent,
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentMethodSpecificData {
    Upi(UpiDetails),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PaymentMethodType {
    Upi,
}

#[derive(Debug, Serialize)]
pub struct PayURouterData<T> {
    pub amount: MinorUnit,
    pub router_data: T,
}

impl<T> TryFrom<(MinorUnit, T)> for PayURouterData<T> {
    type Error = hyperswitch_interfaces::errors::ConnectorError;
    fn try_from((amount, item): (MinorUnit, T)) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            router_data: item,
        })
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PayUErrorResponse {
    pub error: PayUError,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PayUError {
    pub code: String,
    pub description: String,
    pub source: String,
    pub step: String,
    pub reason: String,
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
        PaymentMethodData::Upi(upi_data) => {
            let upi = match upi_data {
                UpiData::UpiCollect(upi_collect_data) => {
                    PaymentMethodSpecificData::Upi(UpiDetails {
                        flow: UpiAction::Collect,
                        vpa: upi_collect_data.vpa_id.clone(),
                    })
                }
                UpiData::UpiIntent(_) => PaymentMethodSpecificData::Upi(UpiDetails {
                    flow: UpiAction::Intent,
                    vpa: None,
                }),
            };

            Ok((PaymentMethodType::Upi, upi))
        }
        PaymentMethodData::CardRedirect(_)
        | PaymentMethodData::Card(_)
        | PaymentMethodData::Wallet(_)
        | PaymentMethodData::PayLater(_)
        | PaymentMethodData::BankRedirect(_)
        | PaymentMethodData::BankDebit(_)
        | PaymentMethodData::BankTransfer(_)
        | PaymentMethodData::Crypto(_)
        | PaymentMethodData::MandatePayment
        | PaymentMethodData::Reward
        | PaymentMethodData::RealTimePayment(_)
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
    pub base_amount: Option<i64>,
    pub currency: String,
    pub base_currency: Option<String>,
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
pub struct RazorpayRefundRequest {
    pub amount: MinorUnit,
}

impl
    TryFrom<
        &PayURouterData<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>,
    > for RazorpayRefundRequest
{
    type Error = errors::ConnectorError;
    fn try_from(
        item: &PayURouterData<
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
    pub payer_account_type: Option<String>,
    pub vpa: String,
    pub flow: Option<String>,
    pub bank: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AcquirerData {
    pub auth_code: Option<String>,
    pub rrn: Option<String>,
    pub authentication_reference_number: Option<String>,
    pub bank_transaction_id: Option<String>,
    pub upi_transaction_id: Option<String>,
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
                    mandate_reference: Box::new(None),
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
                    mandate_reference: Box::new(None),
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
pub struct PayUOrderRequest {
    pub amount: MinorUnit,
    pub currency: String,
    pub receipt: String,
    pub partial_payment: Option<bool>,
    pub first_payment_min_amount: Option<MinorUnit>,
    pub notes: Option<RazorpayNotes>,
}

impl
    TryFrom<
        &PayURouterData<
            &RouterDataV2<
                CreateOrder,
                PaymentFlowData,
                PaymentCreateOrderData,
                PaymentCreateOrderResponse,
            >,
        >,
    > for PayUOrderRequest
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn try_from(
        item: &PayURouterData<
            &RouterDataV2<
                CreateOrder,
                PaymentFlowData,
                PaymentCreateOrderData,
                PaymentCreateOrderResponse,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let request_data = &item.router_data.request;

        Ok(PayUOrderRequest {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayUPaymentRequest {
    // Core payment fields
    pub amount: i64, // Amount in smallest currency unit (paise for INR)
    pub pg: String,
    // pub intent_url: String,
    pub currency: String,
    pub order_id: Option<String>,
    pub email: Option<hyperswitch_common_utils::pii::Email>,
    pub contact: Option<String>,
    // Phone number
    pub key: String,
    pub txnid: String,
    pub productinfo: String,
    pub firstname: String,
    pub lastname: Option<String>,
    pub phone: String,
    pub surl: String,
    pub furl: Option<String>,
    pub hash: String,
    // pub salt: String,
    pub upiAppName: String,
    pub bankcode: String,
    pub txn_s2s_flow: i64,
    pub s2s_client_ip: String,
    pub s2s_device_info: String,

    // Customer details
    // pub customer: Option<PayUCustomer>,

    // Payment method specific
    // pub method: String, // card, netbanking, wallet, upi, etc.
    // pub card: Option<PayUCard>,
    // pub bank: Option<String>,   // For netbanking
    // pub wallet: Option<String>, // For wallet payments
    // pub vpa: Option<Secret<String, UpiVpaMaskingStrategy>>, // For UPI payments
    // pub upi: Option<PayUUpi>,

    // Billing address

    // Additional fields
    pub description: Option<String>,
    pub callback_url: Option<String>,
    pub cancel_url: Option<String>,

    // Recurring/Mandate related
    pub recurring: Option<bool>,
    pub save: Option<bool>,
    pub token: Option<String>,

    // 3DS and authentication
    pub auth_type: Option<String>,

    // Additional charges
    pub fee: Option<i64>,
    pub tax: Option<i64>,
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub zipcode: Option<String>,
    pub udf1: Option<String>,
    pub udf2: Option<String>,
    pub udf3: Option<String>,
    pub udf4: Option<String>,
    pub udf5: Option<String>,

    // Metadata

    // UDF fields (User Defined Fields)

    // Device and session info
    // pub device: Option<PayUDeviceInfo>,

    // Split payment
    // pub transfers: Option<Vec<PayUTransfer>>,

    // Offer related
    pub offer_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayUCustomer {
    pub id: Option<String>,
    pub name: Option<String>,
    pub email: Option<hyperswitch_common_utils::pii::Email>,
    pub contact: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayUCard {
    pub number: Option<String>,
    pub expiry_month: Option<String>,
    pub expiry_year: Option<String>,
    pub cvv: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayUUpi {
    pub vpa: Option<Secret<String, UpiVpaMaskingStrategy>>,
    pub flow: Option<String>, // collect, intent
    pub app: Option<String>,  // UPI app name
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayUAddress {
    pub line1: Option<String>,
    pub line2: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayUDeviceInfo {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub platform: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayUTransfer {
    pub account: String,
    pub amount: i64,
    pub currency: String,
    pub notes: Option<HashMap<String, String>>,
}

impl
    TryFrom<
        &PayURouterData<
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for PayUPaymentRequest
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn try_from(
        item: &PayURouterData<
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // key
        // - txnid
        // - productinfo
        // - firstname
        // - lastname
        // - phone
        // - surl
        // - furl
        // - hash
        let request_data = &item.router_data.request;
        let txnid = item.router_data.request.txnid.clone();
        let productinfo = &item.router_data.request.productinfo;

        let key = "DhAndB".to_string();
        let salt = "helow".to_string();
        let furl = item
            .router_data
            .request
            .furl
            .clone()
            .unwrap_or("lol".to_string());
        let surl = item.router_data.request.surl.clone();

        // Convert currency
        let currency = request_data.currency.to_string();

        // Convert amount - Payu expects amount in smallest currency unit
        let amount = item.amount.get_amount_as_i64();

        // Get billing address
        let billing = item
            .router_data
            .resource_common_data
            .address
            .get_payment_billing();

        // Determine payment method from payment_method_data
        // let (method, card, bank, wallet, vpa, upi) = match &request_data.payment_method_data {
        //     hyperswitch_domain_models::payment_method_data::PaymentMethodData::Wallet(
        //         wallet_data,
        //     ) => {
        //         let wallet_name = match wallet_data {
        //             hyperswitch_domain_models::payment_method_data::WalletData::PaypalRedirect(
        //                 _,
        //             ) => "paypal",
        //             hyperswitch_domain_models::payment_method_data::WalletData::GooglePay(_) => {
        //                 "googlepay"
        //             }
        //             hyperswitch_domain_models::payment_method_data::WalletData::ApplePay(_) => {
        //                 "applepay"
        //             }
        //             _ => "wallet",
        //         };
        //         (
        //             "wallet".to_string(),
        //             None,
        //             None,
        //             Some(wallet_name.to_string()),
        //             None,
        //             None,
        //         )
        //     }
        //     hyperswitch_domain_models::payment_method_data::PaymentMethodData::PayLater(_) => {
        //         ("paylater".to_string(), None, None, None, None, None)
        //     }
        //     hyperswitch_domain_models::payment_method_data::PaymentMethodData::BankRedirect(
        //         bank_data,
        //     ) => {
        //         let bank_name = match bank_data {
        //             hyperswitch_domain_models::payment_method_data::BankRedirectData::Eps {
        //                 ..
        //             } => Some("eps".to_string()),
        //             hyperswitch_domain_models::payment_method_data::BankRedirectData::Giropay {
        //                 ..
        //             } => Some("giropay".to_string()),
        //             hyperswitch_domain_models::payment_method_data::BankRedirectData::Ideal {
        //                 ..
        //             } => Some("ideal".to_string()),
        //             hyperswitch_domain_models::payment_method_data::BankRedirectData::Sofort {
        //                 ..
        //             } => Some("sofort".to_string()),
        //             _ => None,
        //         };
        //         ("netbanking".to_string(), None, bank_name, None, None, None)
        //     }
        //     hyperswitch_domain_models::payment_method_data::PaymentMethodData::Upi(upi_data) => {
        //         let vpa_value = match upi_data {
        //             hyperswitch_domain_models::payment_method_data::UpiData::UpiCollect(
        //                 collect_data,
        //             ) => collect_data.vpa_id.clone(),
        //             hyperswitch_domain_models::payment_method_data::UpiData::UpiIntent(_) => None,
        //         };

        //         let upi_info = PayUUpi {
        //             vpa: vpa_value.clone(),
        //             flow: match upi_data {
        //                 hyperswitch_domain_models::payment_method_data::UpiData::UpiCollect(_) => {
        //                     Some("collect".to_string())
        //                 }
        //                 hyperswitch_domain_models::payment_method_data::UpiData::UpiIntent(_) => {
        //                     Some("intent".to_string())
        //                 }
        //             },
        //             app: None, // This would come from request_data if available
        //         };

        //         (
        //             "upi".to_string(),
        //             None,
        //             None,
        //             None,
        //             vpa_value.clone(),
        //             Some(upi_info),
        //         )
        //     }
        //     _ => {
        //         return Err(
        //             hyperswitch_interfaces::errors::ConnectorError::NotImplemented(
        //                 "Payment method not supported for Payu".to_string(),
        //             ),
        //         );
        //     }
        // };

        // Get contact from billing address
        let contact = billing
            .and_then(|billing| billing.phone.as_ref())
            .and_then(|phone| phone.number.clone())
            .map(|phone| phone.peek().to_string())
            .unwrap_or_else(|| "".to_string());

        // Build customer info
        let customer = if request_data.customer_name.is_some() || request_data.email.is_some() {
            Some(PayUCustomer {
                id: None, // Customer ID would come from request if available
                name: request_data.customer_name.clone(),
                email: request_data.email.clone(),
                contact: if contact.is_empty() {
                    None
                } else {
                    Some(contact.clone())
                },
            })
        } else {
            None
        };
        // Generate hash for PayU
        // PayU hash format: sha512(key|txnid|amount|productinfo|firstname|email|udf1|udf2|udf3|udf4|udf5||||||SALT)
        let binding = "".to_string();
        let email_str = request_data
            .email
            .as_ref()
            .map(|e| e.peek())
            .unwrap_or(&binding);
        let firstname = request_data.customer_name.as_deref().unwrap_or("Customer");
        let hash_string = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}||||||{}",
            key,
            txnid,
            amount,
            productinfo,
            firstname,
            email_str,
            "udf1_value".to_string(),
            "udf2_value".to_string(),
            "udf3_value".to_string(),
            "udf4_value".to_string(),
            "udf5_value".to_string(),
            "grocEwXFSWzydVuE7Gs8JqQd8y57alko".to_string()
        );

        let hash = {
            let mut hasher = Sha512::new();
            hasher.update(hash_string.as_bytes());
            let result = hasher.finalize();
            format!("{:x}", result)
        };
        // Build billing address

        // Build device info from browser info if available
        let device = request_data
            .browser_info
            .as_ref()
            .map(|browser_info| PayUDeviceInfo {
                ip: browser_info.ip_address.map(|ip| ip.to_string()),
                user_agent: browser_info.user_agent.clone(),
                platform: None,
            });

        // Build notes from metadata if available
        let notes = request_data.metadata.as_ref().and_then(|meta| {
            if let serde_json::Value::Object(map) = meta {
                let mut notes_map = HashMap::new();
                for (key, value) in map {
                    if let serde_json::Value::String(s) = value {
                        notes_map.insert(key.clone(), s.clone());
                    }
                }
                if !notes_map.is_empty() {
                    Some(notes_map)
                } else {
                    None
                }
            } else {
                None
            }
        });

        // Convert metadata
        let metadata = request_data.metadata.as_ref().map(|meta| {
            let mut meta_map = HashMap::new();
            meta_map.insert("original_metadata".to_string(), meta.clone());
            meta_map
        });

        Ok(PayUPaymentRequest {
            pg: "UPI".to_string(),
            s2s_client_ip:"103.159.11.202".to_string(),
            s2s_device_info:"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3".to_string(),
            upiAppName: "phonepe".to_string(),
            bankcode: "PPINTENT".to_string(),
            txn_s2s_flow: 2,
            // intent_url : "upi://pay?pa=receiver@upi&pn=Receiver+Name&mc=0000&tid=txn123456&tr=order987654&tn=Test+Payment&am=2.00&cu=INR&url=https://your.site".to_string(),

            amount,
            currency,
            order_id: item.router_data.reference_id.clone(),
            email: request_data.email.clone(),
            contact: if contact.is_empty() {
            None
            } else {
            Some(contact.clone())
            },
            key: "DhAndB".to_string(),
            txnid,
            productinfo: productinfo.to_string(),
            firstname: request_data
            .customer_name
            .clone()
            .unwrap_or_else(|| "Customer".to_string()),
            lastname: None,
            phone: contact,
            surl,
            furl: Some(furl.to_string()),
            hash, // Hash needs to be calculated based on PayU requirements
            // salt,

            // customer,
            // method,
            // card,
            // bank,
            // wallet,
            // vpa,
            // upi,
            // billing_address: None,
            description: Some("Payment".to_string()), // Default description
            // notes,
            callback_url: request_data.router_return_url.clone(),
            cancel_url: None, // This would need to be set based on requirements
            recurring: None,
            save: request_data.setup_future_usage.map(|usage| match usage {
            hyperswitch_common_enums::FutureUsage::OffSession => true,
            hyperswitch_common_enums::FutureUsage::OnSession => false,
            }),
            token: None,
            auth_type: None,
            fee: None,
            tax: None,
            // metadata,
            // udf: None,
            // device,
            // transfers: None,
            offer_id: None,
            address1: Some("123 Main St".to_string()),
            address2: Some("Apt 4B".to_string()),
            city: Some("New York".to_string()),
            state: Some("NY".to_string()),
            country: Some("US".to_string()),
            zipcode: Some("10001".to_string()),
            udf1: Some("udf1_value".to_string()),
            udf2: Some("udf2_value".to_string()),
            udf3: Some("udf3_value".to_string()),
            udf4: Some("udf4_value".to_string()),
            udf5: Some("udf5_value".to_string()),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SdkParams {
    UpiPayParam(serde_json::Value),
    FlowWiseParams(UpiFlowWiseSdkParams),
    UpiInAppParam(UpiInAppSdkParams),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UpiFlowWiseSdkParams {
    CommonIntentParams(CommonSdkParams),
    GooglePayParams(GooglePaySdkParams),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CommonSdkParams {
    pub merchant_vpa: String,
    pub merchant_name: Option<String>,
    pub amount: String,
    pub customer_first_name: Option<String>,
    pub customer_last_name: Option<String>,
    pub tr: Option<String>,
    pub currency: Option<String>,
    pub mam: Option<String>,
    pub tn: Option<String>,
    pub tid: Option<String>,
    pub tr_prefix: Option<String>,
    pub mcc: Option<String>,
    pub pg_intent_url: Option<String>,
    pub mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GooglePaySdkParams {
    pub api_version: i32,
    pub api_version_minor: i32,
    pub allowed_payment_methods: Vec<GooglePayAllowedPaymentMethods>,
    pub transaction_info: GooglePayTransactionInfo,
    pub pg_intent_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GooglePayAllowedPaymentMethods {
    #[serde(rename = "type")]
    pub payment_type: String,
    pub parameters: AllowedPaymentParameters,
    pub tokenization_specification: TokenizationSpecification,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowedPaymentParameters {
    pub payee_vpa: Option<String>,
    pub payee_name: Option<String>,
    pub reference_url: Option<String>,
    pub mcc: Option<String>,
    pub transaction_reference_id: Option<String>,
    pub transaction_id: Option<String>,
    pub allowed_card_networks: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GooglePayTransactionInfo {
    pub currency_code: Option<String>,
    pub total_price: String,
    pub total_price_status: String,
    pub transaction_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenizationSpecification {
    #[serde(rename = "type")]
    pub token_type: String,
    pub gateway: Option<String>,
    pub gateway_merchant_id: Option<String>,
    pub gateway_transaction_id: Option<String>,
    pub parameters: Option<GatewayParametersType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayParametersType {
    pub gateway: Option<String>,
    pub gateway_merchant_id: Option<String>,
    pub gateway_transaction_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UpiInAppSdkParams {
    pub merchant_vpa: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PayUPaymentResponse {
    pub status: String,
    pub message: String,
    pub transaction_id: Option<String>,
    pub order_id: Option<String>,
    pub payment_url: Option<String>,
    pub sdk_params: Option<SdkParams>,
    pub next_action: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PayUResponse {
    PaymentResponse(Box<PayUPaymentResponse>),
    ErrorResponse(Box<PayUErrorResponse>),
}

impl<F, Req>
    ForeignTryFrom<(
        PayUResponse,
        RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
        u16,
    )> for RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>
{
    type Error = hyperswitch_interfaces::errors::ConnectorError;

    fn foreign_try_from(
        (response, data, _http_code): (
            PayUResponse,
            RouterDataV2<F, PaymentFlowData, Req, PaymentsResponseData>,
            u16,
        ),
    ) -> Result<Self, Self::Error> {
        match response {
            PayUResponse::PaymentResponse(payment_response) => {
                let status = if payment_response.payment_url.is_some() {
                    AttemptStatus::AuthenticationPending
                } else {
                    AttemptStatus::Pending
                };

                let redirect_form = payment_response.payment_url.map(|url| RedirectForm::Form {
                    endpoint: url,
                    method: Method::Get,
                    form_fields: HashMap::new(),
                });

                let payment_response_data = PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(
                        payment_response.transaction_id.unwrap_or_default(),
                    ),
                    redirection_data: Box::new(redirect_form),
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: payment_response.order_id,
                    incremental_authorization_allowed: None,
                    mandate_reference: Box::new(None),
                };

                Ok(Self {
                    response: Ok(payment_response_data),
                    resource_common_data: PaymentFlowData {
                        status,
                        ..data.resource_common_data
                    },
                    ..data
                })
            }
            PayUResponse::ErrorResponse(error_response) => {
                Err(hyperswitch_interfaces::errors::ConnectorError::ResponseHandlingFailed)
            }
        }
    }
}
