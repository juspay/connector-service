use common_utils::StringMinorUnit;
use domain_types::router_response_types;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use super::{requests::RedsysThreeDsInfo, transformers::RedsysTransaction};

pub type RedsysPreAuthenticateResponse = RedsysResponse;
pub type RedsysAuthenticateResponse = RedsysResponse;
pub type RedsysAuthorizeResponse = RedsysResponse;
pub type RedsysCaptureResponse = RedsysResponse;
pub type RedsysVoidResponse = RedsysResponse;
pub type RedsysRefundResponse = RedsysResponse;

/// Main response enum that handles both success and error responses
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RedsysResponse {
    RedsysResponse(RedsysTransaction),
    RedsysErrorResponse(RedsysErrorResponse),
}

/// Payment response containing order details and 3DS data
#[derive(Debug, Serialize, Deserialize)]
pub struct RedsysPaymentsResponse {
    #[serde(rename = "Ds_Order")]
    pub ds_order: String,
    #[serde(rename = "Ds_EMV3DS")]
    pub ds_emv3ds: Option<RedsysEmv3DSResponseData>,
    #[serde(rename = "Ds_Card_PSD2")]
    pub ds_card_psd2: Option<CardPSD2>,
    #[serde(rename = "Ds_Response")]
    pub ds_response: Option<DsResponse>,
    #[serde(rename = "Ds_Response_Description")]
    pub ds_response_description: Option<String>,
    #[serde(rename = "Ds_AuthorisationCode")]
    pub ds_authorisation_code: Option<Secret<String>>,
}

/// PSD2 compliance indicator
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CardPSD2 {
    Y,
    N,
}

/// EMV 3DS response data from authentication
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedsysEmv3DSResponseData {
    pub protocol_version: String,
    pub three_d_s_server_trans_i_d: Option<String>,
    pub three_d_s_info: Option<RedsysThreeDsInfo>,
    pub three_d_s_method_u_r_l: Option<String>,
    pub acs_u_r_l: Option<String>,
    pub creq: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RedsysThreedsChallengeResponse {
    pub cres: String,
}

/// Result type for pre-authenticate response building
pub struct PreAuthenticateResponseData {
    pub redirection_data: Option<Box<router_response_types::RedirectForm>>,
    pub connector_meta_data: Option<Secret<serde_json::Value>>,
    pub response_ref_id: Option<String>,
    pub authentication_data: Option<domain_types::router_request_types::AuthenticationData>,
}

/// Response code from Redsys (4-digit code)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DsResponse(pub String);

/// Response for operation requests (capture, void, refund)
#[derive(Debug, Serialize, Deserialize)]
pub struct RedsysOperationsResponse {
    #[serde(rename = "Ds_Order")]
    pub ds_order: String,
    #[serde(rename = "Ds_Response")]
    pub ds_response: DsResponse,
    #[serde(rename = "Ds_AuthorisationCode")]
    pub ds_authorisation_code: Option<String>,
}

/// Error response structure from Redsys
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RedsysErrorResponse {
    pub error_code: String,
    pub error_code_description: String,
}

/// The final RedsysSyncResponse structure used by transformers
#[derive(Debug, Serialize, Deserialize)]
pub struct RedsysSyncResponse {
    pub body: RedsysSyncResponseBody,
}

/// SOAP body containing the actual response
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct RedsysSyncResponseBody {
    pub consultaoperacionesresponse: ConsultaOperacionesResponse,
}

/// Consulta operaciones response wrapper
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct ConsultaOperacionesResponse {
    #[serde(rename = "@xmlns:p259", default)]
    pub xmlns_p259: String,
    pub consultaoperacionesreturn: ConsultaOperacionesReturn,
}

/// Return data from consulta operaciones
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct ConsultaOperacionesReturn {
    pub messages: MessagesResponseData,
}

/// Messages wrapper in sync response
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct MessagesResponseData {
    pub version: VersionResponseData,
    pub signature: Option<String>,
}

/// Version wrapper containing message data
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct VersionResponseData {
    #[serde(rename = "@ds_version")]
    pub ds_version: String,
    pub message: MessageResponseType,
}

// The response will contain either a sync transaction data or error data.
// Since the XML parser does not support enums for this case, we use Option to handle both scenarios.
// If both are present or both are absent, an error is thrown.
#[derive(Debug, Serialize, Deserialize)]
pub struct MessageResponseType {
    pub response: Option<Vec<RedsysSyncResponseData>>,
    pub errormsg: Option<SyncErrorCode>,
}

/// Error code from sync response
#[derive(Debug, Serialize, Deserialize)]
pub struct SyncErrorCode {
    pub ds_errorcode: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DsState {
    /// Requested
    S,
    /// Authorizing
    P,
    /// Authenticating
    A,
    /// Completed
    F,
    /// No response / Technical Error
    T,
    /// Transfer, direct debit, or PayPal in progress
    E,
    /// Direct debit downloaded.
    D,
    /// Online transfer
    L,
    /// Redirected to a wallet
    W,
    /// Redirected to Iupay
    O,
}

/// Sync response transaction data
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RedsysSyncResponseData {
    pub ds_merchantcode: Option<String>,
    pub ds_terminal: Option<String>,
    pub ds_order: String,
    pub ds_transactiontype: String,
    pub ds_date: Option<String>,
    pub ds_hour: Option<String>,
    pub ds_amount: Option<StringMinorUnit>,
    // Redsys uses numeric ISO 4217 currency codes (e.g., "978" for EUR)
    // not 3-letter codes, so we use String here
    pub ds_currency: Option<String>,
    pub ds_securepayment: Option<String>,
    pub ds_state: Option<DsState>,
    pub ds_response: Option<DsResponse>,
    pub ds_authorisationcode: Option<String>,
}
