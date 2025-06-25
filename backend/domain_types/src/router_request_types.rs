use common_enums::{CaptureMethod, Currency};
use common_utils::{pii, types::SemanticVersion, MinorUnit};
use hyperswitch_masking::Secret;
use serde::Serialize;

use crate::payment_method_data::PaymentMethodData;

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BrowserInformation {
    pub color_depth: Option<u8>,
    pub java_enabled: Option<bool>,
    pub java_script_enabled: Option<bool>,
    pub language: Option<String>,
    pub screen_height: Option<u32>,
    pub screen_width: Option<u32>,
    pub time_zone: Option<i32>,
    pub ip_address: Option<std::net::IpAddr>,
    pub accept_header: Option<String>,
    pub user_agent: Option<String>,
    pub os_type: Option<String>,
    pub os_version: Option<String>,
    pub device_model: Option<String>,
    pub accept_language: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub enum SyncRequestType {
    MultipleCaptureSync(Vec<String>),
    #[default]
    SinglePaymentSync,
}

#[derive(Debug, Default, Clone)]
pub struct PaymentsCancelData {
    pub amount: Option<i64>,
    pub currency: Option<Currency>,
    pub connector_transaction_id: String,
    pub cancellation_reason: Option<String>,
    pub connector_meta: Option<serde_json::Value>,
    pub browser_info: Option<BrowserInformation>,
    pub metadata: Option<serde_json::Value>,
    // This metadata is used to store the metadata shared during the payment intent request.

    // minor amount data for amount framework
    pub minor_amount: Option<MinorUnit>,
    pub webhook_url: Option<String>,
    pub capture_method: Option<CaptureMethod>,
}

#[derive(Debug, Clone)]
pub struct AuthenticationData {
    pub eci: Option<String>,
    pub cavv: Secret<String>,
    pub threeds_server_transaction_id: Option<String>,
    pub message_version: Option<SemanticVersion>,
    pub ds_trans_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ConnectorCustomerData {
    pub description: Option<String>,
    pub email: Option<pii::Email>,
    pub phone: Option<Secret<String>>,
    pub name: Option<Secret<String>>,
    pub preprocessing_id: Option<String>,
    pub payment_method_data: Option<PaymentMethodData>,
    // pub split_payments: Option<SplitPaymentsRequest>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AuthoriseIntegrityObject {
    /// Authorise amount
    pub amount: MinorUnit,
    /// Authorise currency
    pub currency: common_enums::Currency,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CreateOrderIntegrityObject {
    /// Authorise amount
    pub amount: MinorUnit,
    /// Authorise currency
    pub currency: common_enums::Currency,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SetupMandateIntegrityObject {
    /// Authorise amount
    pub amount: Option<MinorUnit>,
    /// Authorise currency
    pub currency: common_enums::Currency,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PaymentSynIntegrityObject {
    /// Authorise amount
    pub amount: MinorUnit,
    /// Authorise currency
    pub currency: common_enums::Currency,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PaymentVoidIntegrityObject {
    pub connector_transaction_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RefundIntegrityObject {
    pub refund_amount: MinorUnit,
    pub currency: common_enums::Currency,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CaptureIntegrityObject {
    pub amount_to_capture: MinorUnit,
    pub currency: common_enums::Currency,
}
