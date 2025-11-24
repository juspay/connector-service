// Redsys Request Structures
//
// This file contains all request parameter structures and enums for Redsys flows.

use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

// ============================================================================
// REQUEST PARAMETER STRUCTS
// ============================================================================

/// Authenticate request parameters (iniciaPeticionREST)
/// Used for 3DS Method Invocation
#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct RedsysAuthenticateRequestParams {
    pub ds_merchant_order: String,
    pub ds_merchant_merchantcode: String,
    pub ds_merchant_terminal: String,
    pub ds_merchant_currency: String,
    pub ds_merchant_transactiontype: String, // "0" = payment, "1" = preauth
    pub ds_merchant_amount: String,
    pub ds_merchant_pan: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ds_merchant_emv3ds: Option<RedsysEmv3DSRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ds_merchant_excep_sca: Option<String>, // "Y" to query exemptions
}

/// PostAuthenticate request parameters (trataPeticionREST)
/// Used for authorization after 3DS Method completes
#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct RedsysPostAuthenticateRequestParams {
    pub ds_merchant_amount: String,
    pub ds_merchant_currency: String,
    pub ds_merchant_order: String,
    pub ds_merchant_merchantcode: String,
    pub ds_merchant_terminal: String,
    pub ds_merchant_transactiontype: String,
    pub ds_merchant_pan: String,
    pub ds_merchant_expirydate: String, // YYMM
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ds_merchant_cvv2: Option<String>,
    pub ds_merchant_emv3ds: RedsysEmv3DSRequest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ds_merchant_merchanturl: Option<String>, // Webhook URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ds_merchant_productdescription: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ds_merchant_titular: Option<String>, // Cardholder name
}

/// Authorize request parameters (trataPeticionREST with cres)
/// Used for final authorization after 3DS challenge
#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct RedsysAuthorizeRequestParams {
    pub ds_merchant_order: String,
    pub ds_merchant_merchantcode: String,
    pub ds_merchant_terminal: String,
    pub ds_merchant_currency: String,
    pub ds_merchant_transactiontype: String,
    pub ds_merchant_amount: String,
    pub ds_merchant_pan: String,
    pub ds_merchant_expirydate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ds_merchant_cvv2: Option<String>,
    pub ds_merchant_emv3ds: RedsysEmv3DSRequest,
}

/// Capture request parameters
#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct RedysCaptureRequestParams {
    pub ds_merchant_amount: String,
    pub ds_merchant_currency: String,
    pub ds_merchant_order: String,
    pub ds_merchant_merchantcode: String,
    pub ds_merchant_terminal: String,
    pub ds_merchant_transactiontype: String, // "2" = capture
}

/// Void request parameters
#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct RedsysVoidRequestParams {
    pub ds_merchant_amount: String,
    pub ds_merchant_currency: String,
    pub ds_merchant_order: String,
    pub ds_merchant_merchantcode: String,
    pub ds_merchant_terminal: String,
    pub ds_merchant_transactiontype: String, // "9" = cancellation
}

/// Refund request parameters
#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct RedsysRefundRequestParams {
    pub ds_merchant_amount: String,
    pub ds_merchant_currency: String,
    pub ds_merchant_order: String,
    pub ds_merchant_merchantcode: String,
    pub ds_merchant_terminal: String,
    pub ds_merchant_transactiontype: String, // "3" = refund
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ds_merchant_authorisationcode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ds_merchant_transactiondate: Option<String>, // yyyy-mm-dd
}

/// PSync request (SOAP-based query)
#[derive(Debug, Serialize)]
pub struct RedysPSyncRequest {
    pub order: String,
}

/// RSync request (SOAP-based refund query)
#[derive(Debug, Serialize)]
pub struct RedsysRSyncRequest {
    pub order: String,
}

// ============================================================================
// EMV 3DS DATA STRUCTURES
// ============================================================================

/// EMV 3DS request data embedded in payment requests
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RedsysEmv3DSRequest {
    pub three_ds_info: String, // "CardData", "AuthenticationData", or "ChallengeResponse"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_accept_header: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_java_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_javascript_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_color_depth: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_screen_height: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_screen_width: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "browserTZ")]
    pub browser_tz: Option<String>, // Timezone offset in minutes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "threeDSServerTransID")]
    pub three_ds_server_trans_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "notificationURL")]
    pub notification_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub three_ds_comp_ind: Option<String>, // "Y" or "N"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cres: Option<String>, // Challenge response for final authorization
}

// ============================================================================
// MAIN REQUEST WRAPPER
// ============================================================================

/// Main request wrapper - all Redsys REST requests follow this structure
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedsysTransaction {
    pub ds_signature_version: String,
    pub ds_merchant_parameters: String, // Base64-encoded JSON
    pub ds_signature: String,           // Base64-encoded HMAC-SHA256
}

// ============================================================================
// TYPE ALIASES FOR MACRO SUPPORT
// ============================================================================
// The create_all_prerequisites! macro requires unique type names for each flow

pub type RedsysAuthenticateRequest = RedsysTransaction;
pub type RedsysPostAuthenticateRequest = RedsysTransaction;
pub type RedsysAuthorizeRequest = RedsysTransaction;
pub type RedysCaptureRequest = RedsysTransaction;
pub type RedsysVoidRequest = RedsysTransaction;
pub type RedsysRefundRequest = RedsysTransaction;

// ============================================================================
// AUTHENTICATION STRUCTURE
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedsysAuthType {
    pub merchant_id: Secret<String>, // FUC code (api_key)
    pub terminal_id: Secret<String>, // Terminal number (key1)
    pub sha256_pwd: Secret<String>,  // SHA256 password (api_secret)
}
