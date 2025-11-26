use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use super::{requests::RedsysThreeDsInfo, transformers::RedsysTransaction};

pub type RedsysPreAuthenticateResponse = RedsysResponse;
pub type RedsysAuthenticateResponse = RedsysResponse;
pub type RedsysPostAuthenticateResponse = RedsysResponse;
pub type RedsysCaptureResponse = RedsysResponse;
pub type RedsysVoidResponse = RedsysResponse;
pub type RedsysRefundResponse = RedsysResponse;

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RedsysResponse {
    RedsysResponse(RedsysTransaction),
    RedsysErrorResponse(RedsysErrorResponse),
}

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
    #[serde(rename = "Ds_AuthorisationCode")]
    pub ds_authorisation_code: Option<Secret<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CardPSD2 {
    Y,
    N,
}

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
pub struct DsResponse(pub String);

#[derive(Debug, Serialize, Deserialize)]
pub struct RedsysOperationsResponse {
    #[serde(rename = "Ds_Order")]
    pub ds_order: String,
    #[serde(rename = "Ds_Response")]
    pub ds_response: DsResponse,
    #[serde(rename = "Ds_AuthorisationCode")]
    pub ds_authorisation_code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RedsysErrorResponse {
    pub error_code: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "soapenv:envelope")]
pub struct RedsysSyncResponse {
    #[serde(rename = "@xmlns:soapenv")]
    pub xmlns_soapenv: String,
    #[serde(rename = "@xmlns:soapenc")]
    pub xmlns_soapenc: String,
    #[serde(rename = "@xmlns:xsd")]
    pub xmlns_xsd: String,
    #[serde(rename = "@xmlns:xsi")]
    pub xmlns_xsi: String,
    #[serde(rename = "header")]
    pub header: Option<SoapHeader>,
    #[serde(rename = "body")]
    pub body: RedsysSyncResponseBody,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SoapHeader {}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct RedsysSyncResponseBody {
    pub consultaoperacionesresponse: ConsultaOperacionesResponse,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct ConsultaOperacionesResponse {
    #[serde(rename = "@xmlns:p259")]
    pub xmlns_p259: String,
    pub consultaoperacionesreturn: ConsultaOperacionesReturn,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct ConsultaOperacionesReturn {
    pub messages: MessagesResponseData,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct MessagesResponseData {
    pub version: VersionResponseData,
}

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
    pub response: Option<RedsysSyncResponseData>,
    pub errormsg: Option<SyncErrorCode>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncErrorCode {
    pub ds_errorcode: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RedsysSyncResponseData {
    pub ds_order: String,
    pub ds_transactiontype: String,
    pub ds_amount: Option<String>,
    pub ds_currency: Option<String>,
    pub ds_securepayment: Option<String>,
    pub ds_state: Option<String>,
    pub ds_response: Option<DsResponse>,
}
