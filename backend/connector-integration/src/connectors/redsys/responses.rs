// Redsys Response Structures
//
// This file contains all response parameter structures and enums for Redsys flows.

use serde::{Deserialize, Serialize};

// ============================================================================
// RESPONSE PARAMETER STRUCTS
// ============================================================================

/// Authenticate response parameters
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct RedsysAuthenticateResponseParams {
    pub ds_order: String,
    pub ds_merchant_code: String,
    pub ds_terminal: String,
    pub ds_transaction_type: String,
    #[serde(rename = "Ds_Card_PSD2")]
    pub ds_card_psd2: Option<String>, // "Y" or "N"
    pub ds_excep_sca: Option<String>,
    #[serde(rename = "Ds_EMV3DS")]
    pub ds_emv3ds: Option<RedsysEmv3DSResponse>,
}

/// PostAuthenticate response parameters
/// Also used for Authorize, Capture, Void responses
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct RedsysPostAuthenticateResponseParams {
    pub ds_amount: Option<String>,
    pub ds_currency: Option<String>,
    pub ds_order: String,
    pub ds_merchant_code: String,
    pub ds_terminal: String,
    pub ds_transaction_type: String,
    pub ds_response: String, // Response code (0000-0099 = success, 9999 = challenge needed)
    pub ds_authorisation_code: Option<String>,
    pub ds_date: Option<String>,
    pub ds_hour: Option<String>,
    pub ds_secure_payment: Option<String>, // "0", "1", "2"
    pub ds_card_number: Option<String>,    // Masked card number
    #[serde(rename = "Ds_EMV3DS")]
    pub ds_emv3ds: Option<RedsysEmv3DSResponse>,
}

/// Type aliases for different flow responses that use the same structure
pub type RedsysAuthorizeResponseParams = RedsysPostAuthenticateResponseParams;
pub type RedysCaptureResponseParams = RedsysPostAuthenticateResponseParams;
pub type RedsysVoidResponseParams = RedsysPostAuthenticateResponseParams;
pub type RedsysRefundResponseParams = RedsysPostAuthenticateResponseParams;
pub type RedysPSyncResponseParams = RedsysPostAuthenticateResponseParams;
pub type RedsysRSyncResponseParams = RedsysPostAuthenticateResponseParams;

// ============================================================================
// EMV 3DS RESPONSE DATA
// ============================================================================

/// EMV 3DS response data embedded in payment responses
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RedsysEmv3DSResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "threeDSServerTransID")]
    pub three_ds_server_trans_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub three_ds_info: Option<String>, // "CardConfiguration", "ChallengeRequest", etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "threeDSMethodURL")]
    pub three_ds_method_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "acsURL")]
    pub acs_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creq: Option<String>, // Challenge request
}

// ============================================================================
// MAIN RESPONSE WRAPPER
// ============================================================================

/// Main response wrapper - all Redsys REST responses follow this structure
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct RedsysTransactionResponse {
    pub ds_signature_version: String,
    pub ds_merchant_parameters: String, // Base64-encoded JSON
    pub ds_signature: String,           // Base64-encoded HMAC-SHA256
}

// ============================================================================
// ERROR RESPONSE
// ============================================================================

/// Error response structure
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RedsysErrorResponse {
    #[serde(rename = "errorCode")]
    pub error_code: String,
}

// ============================================================================
// UNIFIED RESPONSE ENUM
// ============================================================================

/// Response enum to handle different response types
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum RedsysResponse {
    Success(RedsysTransactionResponse),
    Error(RedsysErrorResponse),
}

// ============================================================================
// TYPE ALIASES FOR MACRO SUPPORT
// ============================================================================
// The create_all_prerequisites! macro requires unique type names for each flow

pub type RedsysAuthenticateResponse = RedsysResponse;
pub type RedsysPostAuthenticateResponse = RedsysResponse;
pub type RedsysAuthorizeResponse = RedsysResponse;
pub type RedysPSyncResponse = RedsysResponse;
pub type RedysCaptureResponse = RedsysResponse;
pub type RedsysVoidResponse = RedsysResponse;
pub type RedsysRefundResponse = RedsysResponse;
pub type RedsysRSyncResponse = RedsysResponse;
