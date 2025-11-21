use domain_types::payment_method_data::{PaymentMethodDataTypes, RawCardNumber};
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

// ===== TRANSACTION TYPES =====
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum TransactionType {
    #[serde(rename = "0")]
    Authorization,
    #[serde(rename = "1")]
    Preauthorization,
    #[serde(rename = "2")]
    Confirmation,
    #[serde(rename = "3")]
    Refund,
    #[serde(rename = "7")]
    SeparatePreauth,
    #[serde(rename = "8")]
    SeparateConfirm,
    #[serde(rename = "9")]
    Cancellation,
}

// ===== EMV 3DS STRUCTURES =====

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreeDSInfo {
    #[serde(rename = "CardData")]
    CardData,
    #[serde(rename = "CardConfiguration")]
    CardConfiguration,
    #[serde(rename = "AuthenticationData")]
    AuthenticationData,
    #[serde(rename = "ChallengeRequest")]
    ChallengeRequest,
    #[serde(rename = "ChallengeResponse")]
    ChallengeResponse,
}

// PreAuthenticate request - CardData flow
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmvThreeDsCardData {
    pub three_d_s_info: ThreeDSInfo,
}

// Authorize request - AuthenticationData flow
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmvThreeDsAuthData {
    pub three_d_s_info: ThreeDSInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_accept_header: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_java_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_java_script_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_color_depth: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_screen_height: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_screen_width: Option<String>,
    #[serde(rename = "browserTZ", skip_serializing_if = "Option::is_none")]
    pub browser_tz: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub three_d_s_server_trans_i_d: Option<String>,
    #[serde(rename = "notificationURL", skip_serializing_if = "Option::is_none")]
    pub notification_url: Option<String>,
    #[serde(rename = "threeDSCompInd", skip_serializing_if = "Option::is_none")]
    pub three_ds_comp_ind: Option<String>,
}

// PostAuthenticate request - ChallengeResponse flow
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmvThreeDsChallengeResponse {
    pub three_d_s_info: ThreeDSInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cres: Option<String>,
}

// ===== MERCHANT PARAMETERS =====

// PreAuthenticate merchant parameters (iniciaPeticion)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedsysPreAuthMerchantParams {
    #[serde(rename = "DS_MERCHANT_ORDER")]
    pub ds_merchant_order: String,
    #[serde(rename = "DS_MERCHANT_MERCHANTCODE")]
    pub ds_merchant_merchantcode: String,
    #[serde(rename = "DS_MERCHANT_TERMINAL")]
    pub ds_merchant_terminal: String,
    #[serde(rename = "DS_MERCHANT_CURRENCY")]
    pub ds_merchant_currency: String,
    #[serde(rename = "DS_MERCHANT_TRANSACTIONTYPE")]
    pub ds_merchant_transactiontype: String,
    #[serde(rename = "DS_MERCHANT_AMOUNT")]
    pub ds_merchant_amount: String,
    #[serde(rename = "DS_MERCHANT_PAN")]
    pub ds_merchant_pan: Secret<String>,
    #[serde(rename = "DS_MERCHANT_EMV3DS", skip_serializing_if = "Option::is_none")]
    pub ds_merchant_emv3ds: Option<EmvThreeDsCardData>,
}

// Authorize merchant parameters (trataPeticion - payment)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedsysAuthorizeMerchantParams<T: PaymentMethodDataTypes> {
    #[serde(rename = "DS_MERCHANT_AMOUNT")]
    pub ds_merchant_amount: String,
    #[serde(rename = "DS_MERCHANT_CURRENCY")]
    pub ds_merchant_currency: String,
    #[serde(rename = "DS_MERCHANT_ORDER")]
    pub ds_merchant_order: String,
    #[serde(rename = "DS_MERCHANT_MERCHANTCODE")]
    pub ds_merchant_merchantcode: String,
    #[serde(rename = "DS_MERCHANT_TERMINAL")]
    pub ds_merchant_terminal: String,
    #[serde(rename = "DS_MERCHANT_TRANSACTIONTYPE")]
    pub ds_merchant_transactiontype: String,
    #[serde(rename = "DS_MERCHANT_PAN")]
    pub ds_merchant_pan: RawCardNumber<T>,
    #[serde(rename = "DS_MERCHANT_EXPIRYDATE")]
    pub ds_merchant_expirydate: Secret<String>,
    #[serde(rename = "DS_MERCHANT_CVV2", skip_serializing_if = "Option::is_none")]
    pub ds_merchant_cvv2: Option<Secret<String>>,
    #[serde(rename = "DS_MERCHANT_EMV3DS")]
    pub ds_merchant_emv3ds: EmvThreeDsAuthData,
    #[serde(
        rename = "DS_MERCHANT_MERCHANTURL",
        skip_serializing_if = "Option::is_none"
    )]
    pub ds_merchant_merchanturl: Option<String>,
    #[serde(
        rename = "DS_MERCHANT_PRODUCTDESCRIPTION",
        skip_serializing_if = "Option::is_none"
    )]
    pub ds_merchant_productdescription: Option<String>,
    #[serde(
        rename = "DS_MERCHANT_TITULAR",
        skip_serializing_if = "Option::is_none"
    )]
    pub ds_merchant_titular: Option<Secret<String>>,
}

// PostAuthenticate merchant parameters (trataPeticion - challenge completion)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedsysPostAuthMerchantParams<T: PaymentMethodDataTypes> {
    #[serde(rename = "DS_MERCHANT_ORDER")]
    pub ds_merchant_order: String,
    #[serde(rename = "DS_MERCHANT_MERCHANTCODE")]
    pub ds_merchant_merchantcode: String,
    #[serde(rename = "DS_MERCHANT_TERMINAL")]
    pub ds_merchant_terminal: String,
    #[serde(rename = "DS_MERCHANT_CURRENCY")]
    pub ds_merchant_currency: String,
    #[serde(rename = "DS_MERCHANT_TRANSACTIONTYPE")]
    pub ds_merchant_transactiontype: String,
    #[serde(rename = "DS_MERCHANT_AMOUNT")]
    pub ds_merchant_amount: String,
    #[serde(rename = "DS_MERCHANT_PAN")]
    pub ds_merchant_pan: RawCardNumber<T>,
    #[serde(rename = "DS_MERCHANT_EXPIRYDATE")]
    pub ds_merchant_expirydate: Secret<String>,
    #[serde(rename = "DS_MERCHANT_CVV2", skip_serializing_if = "Option::is_none")]
    pub ds_merchant_cvv2: Option<Secret<String>>,
    #[serde(rename = "DS_MERCHANT_EMV3DS")]
    pub ds_merchant_emv3ds: EmvThreeDsChallengeResponse,
}

// Capture/Void/Refund merchant parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedsysOperationMerchantParams {
    #[serde(rename = "DS_MERCHANT_AMOUNT")]
    pub ds_merchant_amount: String,
    #[serde(rename = "DS_MERCHANT_CURRENCY")]
    pub ds_merchant_currency: String,
    #[serde(rename = "DS_MERCHANT_ORDER")]
    pub ds_merchant_order: String,
    #[serde(rename = "DS_MERCHANT_MERCHANTCODE")]
    pub ds_merchant_merchantcode: String,
    #[serde(rename = "DS_MERCHANT_TERMINAL")]
    pub ds_merchant_terminal: String,
    #[serde(rename = "DS_MERCHANT_TRANSACTIONTYPE")]
    pub ds_merchant_transactiontype: String,
}

// ===== REQUEST WRAPPER =====

// Common wrapper for all REST requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedsysTransaction {
    #[serde(rename = "Ds_SignatureVersion")]
    pub ds_signature_version: String,
    #[serde(rename = "Ds_MerchantParameters")]
    pub ds_merchant_parameters: Secret<String>,
    #[serde(rename = "Ds_Signature")]
    pub ds_signature: Secret<String>,
}

// ===== SOAP REQUEST STRUCTURES =====

// Placeholder for future SOAP implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedsysSoapSyncParams {
    #[serde(rename = "DS_MERCHANT_MERCHANTCODE")]
    pub ds_merchant_merchantcode: String,
    #[serde(rename = "DS_MERCHANT_TERMINAL")]
    pub ds_merchant_terminal: String,
    #[serde(rename = "DS_MERCHANT_ORDER")]
    pub ds_merchant_order: String,
    #[serde(rename = "DS_MERCHANT_MERCHANTSIGNATURE")]
    pub ds_merchant_merchantsignature: String,
    #[serde(rename = "DS_MERCHANT_SIGNATUREVERSION")]
    pub ds_merchant_signatureversion: String,
}
