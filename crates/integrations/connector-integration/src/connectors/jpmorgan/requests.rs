use common_utils::types::MinorUnit;
use domain_types::payment_method_data::{PaymentMethodDataTypes, RawCardNumber};
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

/// Client Authentication Token request — obtains an OAuth2 access token
/// for client-side SDK initialization via JP Morgan's token endpoint.
/// Uses form-urlencoded format matching the ServerAuthenticationToken flow.
#[derive(Debug, Clone, Serialize)]
pub struct JpmorganClientAuthRequest {
    pub grant_type: String,
    pub scope: String,
}

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_holder: Option<JpmorganAccountHolder>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_descriptor: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganPaymentMethodType<T: PaymentMethodDataTypes> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<JpmorganCard<T>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ach: Option<JpmorganAch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub googlepay: Option<JpmorganGooglePay>,
    /// Token obtained from client-side SDK (CardToken flow)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganCard<T: PaymentMethodDataTypes> {
    pub account_number: RawCardNumber<T>,
    pub expiry: Expiry,
}

/// ACH Bank Debit payment method structure for JPMorgan
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganAch {
    pub account_number: Secret<String>,
    pub financial_institution_routing_number: Secret<String>,
    pub account_type: JpmorganAchAccountType,
}

/// ACH Account Holder structure
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganAccountHolder {
    pub first_name: Secret<String>,
    pub last_name: Secret<String>,
}

/// ACH Account Type enum
#[derive(Debug, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum JpmorganAchAccountType {
    Checking,
    Savings,
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
    pub soft_merchant: JpmorganSoftMerchant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganMerchantSoftware {
    pub company_name: Secret<String>,
    pub product_name: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganSoftMerchant {
    pub merchant_purchase_description: Secret<String>,
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
    pub capture_method: CapMethod,
    pub amount: MinorUnit,
    pub currency: common_enums::Currency,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganVoidRequest {
    // As per the docs, this is not a required field
    // Since we always pass `true` in `isVoid` only during the void call, it makes more sense to have it required field
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

/// JPMorgan initiator type for stored credentials / MIT
#[derive(Debug, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum JpmorganInitiatorType {
    Cardholder,
    Merchant,
}

/// JPMorgan account on file status
#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JpmorganAccountOnFile {
    ToBeStored,
    Stored,
}

/// JPMorgan recurring sequence
#[derive(Debug, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum JpmorganRecurringSequence {
    First,
    Subsequent,
}

/// JPMorgan recurring object for MIT transactions
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganRecurring {
    pub recurring_sequence: JpmorganRecurringSequence,
    pub agreement_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_variable_amount: Option<bool>,
}

/// JPMorgan card for MIT. `account_number` and `expiry` are absent in
/// `MandatePayment` flows where only the network transaction ID is available.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganMitCard<T: PaymentMethodDataTypes> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_number: Option<RawCardNumber<T>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<Expiry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_network_transaction_id: Option<String>,
}

/// JPMorgan payment method type for MIT (with optional network transaction ID)
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganMitPaymentMethodType<T: PaymentMethodDataTypes> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<JpmorganMitCard<T>>,
}

/// SetupMandate request (initial CIT with credential storage)
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganSetupMandateRequest<T: PaymentMethodDataTypes> {
    pub capture_method: CapMethod,
    pub amount: MinorUnit,
    pub currency: common_enums::Currency,
    pub merchant: JpmorganMerchant,
    pub payment_method_type: JpmorganMitPaymentMethodType<T>,
    pub recurring: JpmorganRecurring,
    pub initiator_type: JpmorganInitiatorType,
    pub account_on_file: JpmorganAccountOnFile,
    pub is_amount_final: bool,
}

/// RepeatPayment request (subsequent MIT)
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganRepeatPaymentRequest<T: PaymentMethodDataTypes> {
    pub capture_method: CapMethod,
    pub amount: MinorUnit,
    pub currency: common_enums::Currency,
    pub merchant: JpmorganMerchant,
    pub payment_method_type: JpmorganMitPaymentMethodType<T>,
    pub recurring: JpmorganRecurring,
    pub initiator_type: JpmorganInitiatorType,
    pub account_on_file: JpmorganAccountOnFile,
    pub is_amount_final: bool,
}

// ---- Google Pay (encrypted) request structs ----

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganGooglePay {
    /// Latitude/longitude string required by JPMorgan (e.g. "0,0" when unavailable)
    pub lat_long: String,
    pub encrypted_payment_bundle: JpmorganEncryptedPaymentBundle,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganEncryptedPaymentBundle {
    /// The full signedMessage JSON string from Google Pay (contains encryptedMessage, ephemeralPublicKey, tag)
    pub encrypted_payload: Secret<String>,
    pub encrypted_payment_header: JpmorganEncryptedPaymentHeader,
    /// Maps from intermediateSigningKey.signatures[0] (ECv2) or signature (ECv1) in the Google token
    pub signature: Secret<String>,
    /// e.g. "ECv1" or "ECv2"
    pub protocol_version: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganEncryptedPaymentHeader {
    /// The ephemeralPublicKey extracted from the Google Pay signedMessage
    pub ephemeral_public_key: Secret<String>,
}

/// Helper structs for deserializing the Google Pay token string
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GooglePayToken {
    pub protocol_version: String,
    pub signature: Secret<String>,
    #[serde(default)]
    pub intermediate_signing_key: Option<GooglePayIntermediateSigningKey>,
    pub signed_message: Secret<String>,
}

#[derive(Debug, Deserialize)]
pub struct GooglePayIntermediateSigningKey {
    pub signatures: Vec<Secret<String>>,
}

/// The parsed signedMessage JSON inside the Google Pay token
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GooglePaySignedMessage {
    pub ephemeral_public_key: Secret<String>,
}
