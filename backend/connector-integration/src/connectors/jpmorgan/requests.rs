use common_utils::types::MinorUnit;
use domain_types::payment_method_data::{PaymentMethodDataTypes, RawCardNumber};
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct JpmorganTokenRequest {
    pub grant_type: String,
    pub scope: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganPaymentsRequest<T: PaymentMethodDataTypes> {
    pub capture_method: CapMethod,
    pub amount: MinorUnit,
    pub currency: common_enums::Currency,
    pub merchant: JpmorganMerchant,
    pub payment_method_type: JpmorganPaymentMethodType<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganPaymentMethodType<T: PaymentMethodDataTypes> {
    pub card: JpmorganCard<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganCard<T: PaymentMethodDataTypes> {
    pub account_number: RawCardNumber<T>,
    pub expiry: Expiry,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Expiry {
    pub month: Secret<i32>,
    pub year: Secret<i32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganMerchant {
    pub merchant_software: JpmorganMerchantSoftware,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganMerchantSoftware {
    pub company_name: Secret<String>,
    pub product_name: Secret<String>,
}

#[derive(Debug, Default, Copy, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum CapMethod {
    #[default]
    Now,
    Delayed,
    Manual,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganCaptureRequest {
    pub capture_method: Option<CapMethod>,
    pub amount: MinorUnit,
    pub currency: Option<common_enums::Currency>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganVoidRequest {
    /// As per the docs, this is not a required field
    /// Since we always pass `true` in `isVoid` only during the void call, it makes more sense to have it required field
    pub is_void: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganRefundRequest {
    pub merchant: JpmorganMerchantRefund,
    pub amount: MinorUnit,
    pub currency: common_enums::Currency,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganMerchantRefund {
    pub merchant_software: JpmorganMerchantSoftware,
}
