use common_utils::{pii, StringMinorUnit};
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

pub type RedsysPreAuthenticateRequest = super::transformers::RedsysTransaction;
pub type RedsysAuthenticateRequest = super::transformers::RedsysTransaction;
pub type RedsysPostAuthenticateRequest = super::transformers::RedsysTransaction;
pub type RedsysCaptureRequest = super::transformers::RedsysTransaction;
pub type RedsysVoidRequest = super::transformers::RedsysTransaction;
pub type RedsysRefundRequest = super::transformers::RedsysTransaction;

#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct RedsysPaymentRequest {
    pub ds_merchant_amount: StringMinorUnit,
    pub ds_merchant_currency: String,
    pub ds_merchant_emv3ds: Option<RedsysEmvThreeDsRequestData>,
    pub ds_merchant_expirydate: Secret<String>,
    pub ds_merchant_merchantcode: Secret<String>,
    pub ds_merchant_order: String,
    pub ds_merchant_pan: cards::CardNumber,
    pub ds_merchant_terminal: Secret<String>,
    pub ds_merchant_transactiontype: RedsysTransactionType,
    pub ds_merchant_cvv2: Secret<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RedsysTransactionType {
    #[serde(rename = "0")]
    Payment,
    #[serde(rename = "1")]
    Preauthorization,
    #[serde(rename = "2")]
    Confirmation,
    #[serde(rename = "3")]
    Refund,
    #[serde(rename = "9")]
    Cancellation,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedsysEmvThreeDsRequestData {
    pub three_d_s_info: RedsysThreeDsInfo,
    pub protocol_version: Option<String>,
    pub browser_accept_header: Option<String>,
    pub browser_user_agent: Option<Secret<String>>,
    pub browser_java_enabled: Option<bool>,
    pub browser_javascript_enabled: Option<bool>,
    pub browser_language: Option<String>,
    pub browser_color_depth: Option<String>,
    pub browser_screen_height: Option<String>,
    pub browser_screen_width: Option<String>,
    pub browser_t_z: Option<String>,
    pub browser_i_p: Option<Secret<String, pii::IpAddress>>,
    pub three_d_s_server_trans_i_d: Option<String>,
    pub notification_u_r_l: Option<String>,
    pub three_d_s_comp_ind: Option<RedsysThreeDSCompInd>,
    pub cres: Option<String>,
    #[serde(flatten)]
    pub billing_data: Option<RedsysBillingData>,
    #[serde(flatten)]
    pub shipping_data: Option<RedsysShippingData>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedsysBillingData {
    pub bill_addr_city: Option<Secret<String>>,
    pub bill_addr_country: Option<String>,
    pub bill_addr_line1: Option<Secret<String>>,
    pub bill_addr_line2: Option<Secret<String>>,
    pub bill_addr_line3: Option<Secret<String>>,
    pub bill_addr_postal_code: Option<Secret<String>>,
    pub bill_addr_state: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedsysShippingData {
    pub ship_addr_city: Option<Secret<String>>,
    pub ship_addr_country: Option<String>,
    pub ship_addr_line1: Option<Secret<String>>,
    pub ship_addr_line2: Option<Secret<String>>,
    pub ship_addr_line3: Option<Secret<String>>,
    pub ship_addr_postal_code: Option<Secret<String>>,
    pub ship_addr_state: Option<Secret<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum RedsysThreeDsInfo {
    CardData,
    CardConfiguration,
    ChallengeRequest,
    ChallengeResponse,
    AuthenticationData,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RedsysThreeDSCompInd {
    Y,
    N,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RedsysThreeDsInvokeData {
    pub three_ds_method_url: String,
    pub three_ds_method_data: String,
    pub message_version: String,
    pub directory_server_id: String,
    pub three_ds_method_data_submission: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThreeDsInvokeExempt {
    pub three_d_s_server_trans_i_d: String,
    pub message_version: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct RedsysOperationRequest {
    pub ds_merchant_order: String,
    pub ds_merchant_merchantcode: Secret<String>,
    pub ds_merchant_terminal: Secret<String>,
    pub ds_merchant_currency: String,
    pub ds_merchant_transactiontype: RedsysTransactionType,
    pub ds_merchant_amount: StringMinorUnit,
}

#[derive(Debug, Serialize)]
pub struct Messages {
    #[serde(rename = "Version")]
    pub version: RedsysVersionData,
    #[serde(rename = "Signature")]
    pub signature: String,
    #[serde(rename = "SignatureVersion")]
    pub signature_version: String,
}

#[derive(Debug, Serialize)]
#[serde(rename = "Version")]
pub struct RedsysVersionData {
    #[serde(rename = "@Ds_Version")]
    pub ds_version: String,
    #[serde(rename = "Message")]
    pub message: Message,
}

#[derive(Debug, Serialize)]
pub struct Message {
    #[serde(rename = "Transaction")]
    pub transaction: RedsysSyncRequest,
}

#[derive(Debug, Serialize)]
#[serde(rename = "Transaction")]
pub struct RedsysSyncRequest {
    #[serde(rename = "Ds_MerchantCode")]
    pub ds_merchant_code: Secret<String>,
    #[serde(rename = "Ds_Terminal")]
    pub ds_terminal: Secret<String>,
    #[serde(rename = "Ds_Order")]
    pub ds_order: String,
    #[serde(rename = "Ds_TransactionType")]
    pub ds_transaction_type: String,
}

// Note: PSync and RSync use SOAP XML and are implemented manually in redsys.rs
// They don't use request type structs - the SOAP XML is built directly as Vec<u8>
