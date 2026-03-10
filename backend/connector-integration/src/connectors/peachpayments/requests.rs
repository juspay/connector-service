use common_enums::Currency;
use domain_types::payment_method_data::{PaymentMethodDataTypes, RawCardNumber};
use hyperswitch_masking::Secret;
use serde::Serialize;
use std::fmt::Debug;

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum PaymentMethod {
    #[serde(rename = "ecommerce_card_payment_only")]
    EcommerceCardPaymentOnly,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub enum DccMode {
    #[serde(rename = "noDcc")]
    NoDcc,
    #[serde(rename = "optInDcc")]
    OptInDcc,
    #[serde(rename = "optOutDcc")]
    OptOutDcc,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum MerchantType {
    Standard,
    Sub,
    Iso,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum CardNetworkLowercase {
    Visa,
    Mastercard,
    #[serde(rename = "amex")]
    Amex,
    #[serde(rename = "discover")]
    Discover,
    #[serde(rename = "jcb")]
    Jcb,
    #[serde(rename = "diners")]
    Diners,
    #[serde(rename = "cartes_bancaires")]
    CartesBancaires,
    #[serde(rename = "unionpay")]
    UnionPay,
    #[serde(rename = "interac")]
    Interac,
    #[serde(rename = "rupay")]
    RuPay,
    #[serde(rename = "maestro")]
    Maestro,
    #[serde(rename = "star")]
    Star,
    #[serde(rename = "pulse")]
    Pulse,
    #[serde(rename = "accel")]
    Accel,
    #[serde(rename = "nyce")]
    Nyce,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreAuthIncExtCaptureFlow {
    #[serde(rename = "dccMode")]
    pub dcc_mode: DccMode,
    #[serde(rename = "txnRefNr")]
    pub txn_ref_nr: String,
}

#[derive(Debug, Serialize)]
pub struct PosData {
    pub referral: String,
}

#[derive(Debug, Serialize, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum CofType {
    Adhoc,
    Recurring,
    Instalment,
}

#[derive(Debug, Serialize, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum CofSource {
    Cit,
    Mit,
}

#[derive(Debug, Serialize, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum CofMode {
    Initial,
    Subsequent,
}

#[derive(Debug, Serialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CardOnFileData {
    #[serde(rename = "type")]
    pub _type: CofType,
    pub source: CofSource,
    pub mode: CofMode,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeachpaymentsAmount {
    pub amount: String,
    pub currency_code: Currency,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_amount: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PeachpaymentsCaptureRequest {
    pub amount: PeachpaymentsAmount,
}

#[derive(Debug, Serialize)]
pub struct PeachpaymentsVoidRequest {
    pub amount: PeachpaymentsAmount,
}

#[derive(Debug, Serialize)]
pub struct PeachpaymentsRefundRequest {
    #[serde(rename = "referenceId")]
    pub reference_id: String,
    #[serde(rename = "ecommerceCardPaymentOnlyTransactionData")]
    pub card_data: PeachpaymentsRefundTransactionData,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pos_data: Option<PosData>,
}

#[derive(Debug, Serialize)]
pub struct PeachpaymentsRefundTransactionData {
    pub amount: PeachpaymentsAmount,
}

#[derive(Debug, Serialize)]
pub struct PeachpaymentsAuthorizeRequest<T: PaymentMethodDataTypes> {
    #[serde(rename = "chargeMethod")]
    pub charge_method: String,
    #[serde(rename = "referenceId")]
    pub reference_id: String,
    #[serde(rename = "ecommerceCardPaymentOnlyTransactionData")]
    pub card_data: PeachpaymentsCardData<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pos_data: Option<serde_json::Value>,
    #[serde(rename = "sendDateTime")]
    pub send_date_time: String,
    #[serde(skip)]
    pub(crate) _phantom: std::marker::PhantomData<T>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum PeachpaymentsCardData<T: PaymentMethodDataTypes> {
    Card(PeachpaymentsCard<T>),
    NetworkToken(PeachpaymentsNetworkToken<T>),
}

#[derive(Debug, Serialize)]
pub struct PeachpaymentsCard<T: PaymentMethodDataTypes> {
    pub card: PeachpaymentsCardDetails<T>,
}

#[derive(Debug, Serialize)]
pub struct PeachpaymentsCardDetails<T: PaymentMethodDataTypes> {
    pub pan: RawCardNumber<T>,
    pub cvv: Secret<String>,
    pub cardholder_name: Option<Secret<String>>,
    pub expiry_year: Option<Secret<String>>,
    pub expiry_month: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eci: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PeachpaymentsNetworkToken<T: PaymentMethodDataTypes> {
    #[serde(rename = "paymentMethod")]
    pub payment_method: String,
    pub routing: PeachpaymentsRoutingInfo,
    #[serde(rename = "networkToken")]
    pub network_token: PeachpaymentsNetworkTokenDetails,
    pub cof_data: PeachpaymentsCofData,
    #[serde(skip)]
    pub(crate) _phantom: std::marker::PhantomData<T>,
}

#[derive(Debug, Serialize)]
pub struct PeachpaymentsRoutingInfo {
    #[serde(rename = "merchantPaymentMethodRouteId")]
    pub merchant_payment_method_route_id: Secret<String>,
}

#[derive(Debug, Serialize)]
pub struct PeachpaymentsNetworkTokenDetails {
    pub token: Secret<String>,
    pub expiry_year: Secret<String>,
    pub expiry_month: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptogram: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eci: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct PeachpaymentsCofData {
    #[serde(rename = "type")]
    pub cof_type: CofType,
    pub source: CofSource,
    pub mode: CofMode,
}

#[derive(Debug, Serialize)]
pub struct PeachpaymentsMerchantInformation {
    #[serde(rename = "clientMerchantReferenceId")]
    pub client_merchant_reference_id: Secret<String>,
}
