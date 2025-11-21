use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use super::requests::ThreeDSInfo;

// ===== EMV 3DS RESPONSE STRUCTURES =====

// PreAuthenticate response - CardConfiguration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmvThreeDsCardConfiguration {
    pub three_d_s_info: ThreeDSInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub three_d_s_server_trans_i_d: Option<String>,
    #[serde(rename = "threeDSMethodURL", skip_serializing_if = "Option::is_none")]
    pub three_ds_method_url: Option<String>,
}

// Authorize response - ChallengeRequest (when challenge required)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmvThreeDsChallengeRequest {
    pub three_d_s_info: ThreeDSInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    #[serde(rename = "acsURL", skip_serializing_if = "Option::is_none")]
    pub acs_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creq: Option<String>,
}

// ===== MERCHANT PARAMETERS RESPONSE =====

// PreAuthenticate response parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedsysPreAuthResponseParams {
    #[serde(rename = "Ds_Order")]
    pub ds_order: String,
    #[serde(rename = "Ds_MerchantCode")]
    pub ds_merchant_code: String,
    #[serde(rename = "Ds_Terminal")]
    pub ds_terminal: String,
    #[serde(rename = "Ds_TransactionType")]
    pub ds_transaction_type: String,
    #[serde(rename = "Ds_Card_PSD2", skip_serializing_if = "Option::is_none")]
    pub ds_card_psd2: Option<String>,
    #[serde(rename = "Ds_Excep_SCA", skip_serializing_if = "Option::is_none")]
    pub ds_excep_sca: Option<String>,
    #[serde(rename = "Ds_EMV3DS", skip_serializing_if = "Option::is_none")]
    pub ds_emv3ds: Option<EmvThreeDsCardConfiguration>,
}

// Authorize/PostAuthenticate response parameters (payment result)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedsysPaymentResponseParams {
    #[serde(rename = "Ds_Date", skip_serializing_if = "Option::is_none")]
    pub ds_date: Option<String>,
    #[serde(rename = "Ds_Hour", skip_serializing_if = "Option::is_none")]
    pub ds_hour: Option<String>,
    #[serde(rename = "Ds_Amount")]
    pub ds_amount: String,
    #[serde(rename = "Ds_Currency")]
    pub ds_currency: String,
    #[serde(rename = "Ds_Order")]
    pub ds_order: String,
    #[serde(rename = "Ds_MerchantCode")]
    pub ds_merchant_code: String,
    #[serde(rename = "Ds_Terminal")]
    pub ds_terminal: String,
    #[serde(rename = "Ds_Response")]
    pub ds_response: String,
    #[serde(
        rename = "Ds_AuthorisationCode",
        skip_serializing_if = "Option::is_none"
    )]
    pub ds_authorisation_code: Option<String>,
    #[serde(rename = "Ds_TransactionType")]
    pub ds_transaction_type: String,
    #[serde(rename = "Ds_SecurePayment", skip_serializing_if = "Option::is_none")]
    pub ds_secure_payment: Option<String>,
    #[serde(rename = "Ds_Card_Number", skip_serializing_if = "Option::is_none")]
    pub ds_card_number: Option<Secret<String>>,
    #[serde(rename = "Ds_Card_Type", skip_serializing_if = "Option::is_none")]
    pub ds_card_type: Option<String>,
    #[serde(rename = "Ds_Card_Brand", skip_serializing_if = "Option::is_none")]
    pub ds_card_brand: Option<String>,
    #[serde(rename = "Ds_EMV3DS", skip_serializing_if = "Option::is_none")]
    pub ds_emv3ds: Option<EmvThreeDsChallengeRequest>,
}

// Capture/Void/Refund response parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedsysOperationResponseParams {
    #[serde(rename = "Ds_Date", skip_serializing_if = "Option::is_none")]
    pub ds_date: Option<String>,
    #[serde(rename = "Ds_Hour", skip_serializing_if = "Option::is_none")]
    pub ds_hour: Option<String>,
    #[serde(rename = "Ds_Amount")]
    pub ds_amount: String,
    #[serde(rename = "Ds_Currency")]
    pub ds_currency: String,
    #[serde(rename = "Ds_Order")]
    pub ds_order: String,
    #[serde(rename = "Ds_MerchantCode")]
    pub ds_merchant_code: String,
    #[serde(rename = "Ds_Terminal")]
    pub ds_terminal: String,
    #[serde(rename = "Ds_Response")]
    pub ds_response: String,
    #[serde(
        rename = "Ds_AuthorisationCode",
        skip_serializing_if = "Option::is_none"
    )]
    pub ds_authorisation_code: Option<String>,
    #[serde(rename = "Ds_TransactionType")]
    pub ds_transaction_type: String,
}

// ===== RESPONSE WRAPPER =====

// Common wrapper for all REST responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedsysTransactionResponse {
    #[serde(rename = "Ds_SignatureVersion")]
    pub ds_signature_version: String,
    #[serde(rename = "Ds_MerchantParameters")]
    pub ds_merchant_parameters: Secret<String>,
    #[serde(rename = "Ds_Signature")]
    pub ds_signature: Secret<String>,
}

// ===== ERROR RESPONSE =====

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedsysErrorParams {
    #[serde(rename = "Ds_Order", skip_serializing_if = "Option::is_none")]
    pub ds_order: Option<String>,
    #[serde(rename = "Ds_MerchantCode", skip_serializing_if = "Option::is_none")]
    pub ds_merchant_code: Option<String>,
    #[serde(rename = "Ds_Terminal", skip_serializing_if = "Option::is_none")]
    pub ds_terminal: Option<String>,
    #[serde(rename = "Ds_Response")]
    pub ds_response: String,
    #[serde(rename = "Ds_ErrorCode", skip_serializing_if = "Option::is_none")]
    pub ds_error_code: Option<String>,
    #[serde(rename = "Ds_TransactionType", skip_serializing_if = "Option::is_none")]
    pub ds_transaction_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedsysErrorResponse {
    #[serde(rename = "Ds_SignatureVersion")]
    pub ds_signature_version: String,
    #[serde(rename = "Ds_MerchantParameters")]
    pub ds_merchant_parameters: Secret<String>,
    #[serde(rename = "Ds_Signature")]
    pub ds_signature: Secret<String>,
}

// ===== SOAP RESPONSE STRUCTURES =====

// Placeholder for future SOAP implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedsysSoapOperationData {
    #[serde(rename = "Ds_Amount")]
    pub ds_amount: String,
    #[serde(rename = "Ds_Currency")]
    pub ds_currency: String,
    #[serde(rename = "Ds_Order")]
    pub ds_order: String,
    #[serde(rename = "Ds_Signature")]
    pub ds_signature: String,
    #[serde(rename = "Ds_MerchantCode")]
    pub ds_merchant_code: String,
    #[serde(rename = "Ds_Terminal")]
    pub ds_terminal: String,
    #[serde(rename = "Ds_Response")]
    pub ds_response: String,
    #[serde(
        rename = "Ds_AuthorisationCode",
        skip_serializing_if = "Option::is_none"
    )]
    pub ds_authorisation_code: Option<String>,
    #[serde(rename = "Ds_TransactionType")]
    pub ds_transaction_type: String,
    #[serde(rename = "Ds_SecurePayment", skip_serializing_if = "Option::is_none")]
    pub ds_secure_payment: Option<String>,
    #[serde(rename = "Ds_Language", skip_serializing_if = "Option::is_none")]
    pub ds_language: Option<String>,
    #[serde(rename = "Ds_Card_Number", skip_serializing_if = "Option::is_none")]
    pub ds_card_number: Option<Secret<String>>,
}

// Type aliases for different flow responses
pub type RedsysPreAuthenticateResponse = RedsysTransactionResponse;
pub type RedsysAuthorizeResponse = RedsysTransactionResponse;
pub type RedsysPostAuthenticateResponse = RedsysTransactionResponse;
pub type RedsysPSyncResponse = RedsysTransactionResponse;
pub type RedsysCaptureResponse = RedsysTransactionResponse;
pub type RedsysVoidResponse = RedsysTransactionResponse;
pub type RedsysRefundResponse = RedsysTransactionResponse;
pub type RedsysRSyncResponse = RedsysTransactionResponse;
