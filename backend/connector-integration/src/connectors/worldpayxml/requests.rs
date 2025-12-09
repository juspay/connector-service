use hyperswitch_masking::Secret;
use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename = "paymentService")]
pub struct WorldpayxmlPaymentsRequest {
    #[serde(rename = "@version")]
    pub version: String,
    #[serde(rename = "@merchantCode")]
    pub merchant_code: Secret<String>,
    pub submit: WorldpayxmlSubmit,
}

#[derive(Debug, Serialize)]
pub struct WorldpayxmlSubmit {
    pub order: WorldpayxmlOrder,
}

#[derive(Debug, Serialize)]
pub struct WorldpayxmlOrder {
    #[serde(rename = "@orderCode")]
    pub order_code: String,
    #[serde(rename = "@captureDelay", skip_serializing_if = "Option::is_none")]
    pub capture_delay: Option<String>,
    pub description: String,
    pub amount: WorldpayxmlAmount,
    #[serde(rename = "paymentDetails")]
    pub payment_details: WorldpayxmlPaymentDetails,
    pub shopper: WorldpayxmlShopper,
    #[serde(rename = "billingAddress", skip_serializing_if = "Option::is_none")]
    pub billing_address: Option<WorldpayxmlBillingAddress>,
}

#[derive(Debug, Serialize)]
pub struct WorldpayxmlAmount {
    #[serde(rename = "@value")]
    pub value: String,
    #[serde(rename = "@currencyCode")]
    pub currency_code: String,
    #[serde(rename = "@exponent")]
    pub exponent: String,
}

#[derive(Debug, Serialize)]
pub struct WorldpayxmlPaymentDetails {
    #[serde(rename = "@action")]
    pub action: String,
    #[serde(rename = "$value")]
    pub payment_method: WorldpayxmlPaymentMethod,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
pub enum WorldpayxmlPaymentMethod {
    #[serde(rename = "CARD-SSL")]
    CardSsl(WorldpayxmlCard),
    #[serde(rename = "VISA-SSL")]
    VisaSsl(WorldpayxmlCard),
    #[serde(rename = "ECMC-SSL")]
    EcmcSsl(WorldpayxmlCard),
    #[serde(rename = "PAYWITHGOOGLE-SSL")]
    PaywithgoogleSsl(WorldpayxmlGooglePay),
}

#[derive(Debug, Serialize)]
pub struct WorldpayxmlCard {
    #[serde(rename = "cardNumber")]
    pub card_number: Secret<String>,
    #[serde(rename = "expiryDate")]
    pub expiry_date: WorldpayxmlExpiryDate,
    #[serde(rename = "cardHolderName", skip_serializing_if = "Option::is_none")]
    pub card_holder_name: Option<Secret<String>>,
    #[serde(rename = "cvc")]
    pub cvc: Secret<String>,
}

#[derive(Debug, Serialize)]
pub struct WorldpayxmlExpiryDate {
    pub date: WorldpayxmlDate,
}

#[derive(Debug, Serialize)]
pub struct WorldpayxmlDate {
    #[serde(rename = "@month")]
    pub month: Secret<String>,
    #[serde(rename = "@year")]
    pub year: Secret<String>,
}

#[derive(Debug, Serialize)]
pub struct WorldpayxmlGooglePay {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub signature: String,
    #[serde(rename = "signedMessage")]
    pub signed_message: String,
}

#[derive(Debug, Serialize)]
pub struct WorldpayxmlShopper {
    #[serde(rename = "shopperEmailAddress", skip_serializing_if = "Option::is_none")]
    pub shopper_email_address: Option<common_utils::Email>,
}

#[derive(Debug, Serialize)]
pub struct WorldpayxmlBillingAddress {
    pub address: WorldpayxmlAddress,
}

#[derive(Debug, Serialize)]
pub struct WorldpayxmlAddress {
    #[serde(rename = "firstName", skip_serializing_if = "Option::is_none")]
    pub first_name: Option<Secret<String>>,
    #[serde(rename = "lastName", skip_serializing_if = "Option::is_none")]
    pub last_name: Option<Secret<String>>,
    #[serde(rename = "address1", skip_serializing_if = "Option::is_none")]
    pub address1: Option<Secret<String>>,
    #[serde(rename = "postalCode", skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<Secret<String>>,
    #[serde(rename = "city", skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(rename = "countryCode", skip_serializing_if = "Option::is_none")]
    pub country_code: Option<common_enums::CountryAlpha2>,
}

#[derive(Debug, Serialize)]
#[serde(rename = "paymentService")]
pub struct WorldpayxmlCaptureRequest {
    #[serde(rename = "@version")]
    pub version: String,
    #[serde(rename = "@merchantCode")]
    pub merchant_code: Secret<String>,
    pub modify: WorldpayxmlModify,
}

#[derive(Debug, Serialize)]
pub struct WorldpayxmlModify {
    #[serde(rename = "orderModification")]
    pub order_modification: WorldpayxmlOrderModification,
}

#[derive(Debug, Serialize)]
pub struct WorldpayxmlOrderModification {
    #[serde(rename = "@orderCode")]
    pub order_code: String,
    pub capture: WorldpayxmlCapture,
}

#[derive(Debug, Serialize)]
pub struct WorldpayxmlCapture {
    pub amount: WorldpayxmlAmount,
}

#[derive(Debug, Serialize)]
#[serde(rename = "paymentService")]
pub struct WorldpayxmlVoidRequest {
    #[serde(rename = "@version")]
    pub version: String,
    #[serde(rename = "@merchantCode")]
    pub merchant_code: Secret<String>,
    pub modify: WorldpayxmlVoidModify,
}

#[derive(Debug, Serialize)]
pub struct WorldpayxmlVoidModify {
    #[serde(rename = "orderModification")]
    pub order_modification: WorldpayxmlVoidOrderModification,
}

#[derive(Debug, Serialize)]
pub struct WorldpayxmlVoidOrderModification {
    #[serde(rename = "@orderCode")]
    pub order_code: String,
    pub cancel: WorldpayxmlCancel,
}

#[derive(Debug, Serialize)]
pub struct WorldpayxmlCancel {
    // Empty struct - generates <cancel/> element
}

#[derive(Debug, Serialize)]
#[serde(rename = "paymentService")]
pub struct WorldpayxmlRefundRequest {
    #[serde(rename = "@version")]
    pub version: String,
    #[serde(rename = "@merchantCode")]
    pub merchant_code: Secret<String>,
    pub modify: WorldpayxmlRefundModify,
}

#[derive(Debug, Serialize)]
pub struct WorldpayxmlRefundModify {
    #[serde(rename = "orderModification")]
    pub order_modification: WorldpayxmlRefundOrderModification,
}

#[derive(Debug, Serialize)]
pub struct WorldpayxmlRefundOrderModification {
    #[serde(rename = "@orderCode")]
    pub order_code: String,
    pub refund: WorldpayxmlRefund,
}

#[derive(Debug, Serialize)]
pub struct WorldpayxmlRefund {
    pub amount: WorldpayxmlAmount,
}

#[derive(Debug, Serialize)]
#[serde(rename = "paymentService")]
pub struct WorldpayxmlPSyncRequest {
    #[serde(rename = "@version")]
    pub version: String,
    #[serde(rename = "@merchantCode")]
    pub merchant_code: Secret<String>,
    pub inquiry: WorldpayxmlInquiry,
}

#[derive(Debug, Serialize)]
pub struct WorldpayxmlInquiry {
    #[serde(rename = "orderInquiry")]
    pub order_inquiry: WorldpayxmlOrderInquiry,
}

#[derive(Debug, Serialize)]
pub struct WorldpayxmlOrderInquiry {
    #[serde(rename = "@orderCode")]
    pub order_code: String,
}

// Type alias for RSync - reuses PSync request structure
pub type WorldpayxmlRSyncRequest = WorldpayxmlPSyncRequest;
