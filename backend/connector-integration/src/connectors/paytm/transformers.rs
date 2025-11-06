use std::{
    cmp,
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use aes::{Aes128, Aes192, Aes256};

// PayTM API Constants
pub mod constants {
    // PayTM API versions and identifiers
    pub const API_VERSION: &str = "v2";
    pub const CHANNEL_ID: &str = "WEB";

    // Request types
    pub const REQUEST_TYPE_PAYMENT: &str = "Payment";
    pub const REQUEST_TYPE_NATIVE: &str = "NATIVE";

    // UPI specific constants
    pub const PAYMENT_MODE_UPI: &str = "UPI";
    pub const UPI_CHANNEL_UPIPUSH: &str = "UPIPUSH";
    pub const PAYMENT_FLOW_NONE: &str = "NONE";
    pub const AUTH_MODE_DEBIT_PIN: &str = "DEBIT_PIN";
    pub const AUTH_MODE_OTP: &str = "otp";

    // Response codes
    pub const SUCCESS_CODE: &str = "0000";
    pub const DUPLICATE_CODE: &str = "0002";
    pub const QR_SUCCESS_CODE: &str = "QR_0001";

    // PSync specific constants
    pub const TXN_SUCCESS_CODE: &str = "01";
    pub const TXN_FAILURE_CODE: &str = "227";
    pub const WALLET_INSUFFICIENT_CODE: &str = "235";
    pub const INVALID_UPI_CODE: &str = "295";
    pub const NO_RECORD_FOUND_CODE: &str = "331";
    pub const INVALID_ORDER_ID_CODE: &str = "334";
    pub const INVALID_MID_CODE: &str = "335";
    pub const PENDING_CODE: &str = "400";
    pub const BANK_DECLINED_CODE: &str = "401";
    pub const PENDING_BANK_CONFIRM_CODE: &str = "402";
    pub const SERVER_DOWN_CODE: &str = "501";
    pub const TXN_FAILED_CODE: &str = "810";
    pub const ACCOUNT_BLOCKED_CODE: &str = "843";
    pub const MOBILE_CHANGED_CODE: &str = "820";
    pub const MANDATE_GAP_CODE: &str = "267";

    // Transaction types for PSync
    pub const TXN_TYPE_PREAUTH: &str = "PREAUTH";
    pub const TXN_TYPE_CAPTURE: &str = "CAPTURE";
    pub const TXN_TYPE_RELEASE: &str = "RELEASE";
    pub const TXN_TYPE_WITHDRAW: &str = "WITHDRAW";

    // Default values
    pub const DEFAULT_CUSTOMER_ID: &str = "guest";
    pub const DEFAULT_CALLBACK_URL: &str = "https://default-callback.com";

    // Error messages
    pub const ERROR_INVALID_VPA: &str = "Invalid UPI VPA format";
    pub const ERROR_SALT_GENERATION: &str = "Failed to generate random salt";
    pub const ERROR_AES_128_ENCRYPTION: &str = "AES-128 encryption failed";
    pub const ERROR_AES_192_ENCRYPTION: &str = "AES-192 encryption failed";
    pub const ERROR_AES_256_ENCRYPTION: &str = "AES-256 encryption failed";

    // HTTP constants
    pub const CONTENT_TYPE_JSON: &str = "application/json";
    pub const CONTENT_TYPE_HEADER: &str = "Content-Type";

    // AES encryption constants (from PayTM Haskell implementation)
    pub const PAYTM_IV: &[u8; 16] = b"@@@@&&&&####$$$$";
    pub const SALT_LENGTH: usize = 3;
    pub const AES_BUFFER_PADDING: usize = 16;
    pub const AES_128_KEY_LENGTH: usize = 16;
    pub const AES_192_KEY_LENGTH: usize = 24;
    pub const AES_256_KEY_LENGTH: usize = 32;
}
use base64::{engine::general_purpose, Engine};
use cbc::{
    cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit},
    Encryptor,
};
use common_enums::{AttemptStatus, Currency};
use common_utils::{
    errors::CustomResult,
    request::Method,
    types::{AmountConvertor, StringMajorUnit},
    Email,
};
use domain_types::{
    connector_flow::{Authorize, CreateSessionToken, PSync},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId,
        SessionTokenRequestData, SessionTokenResponseData,
    },
    errors,
    payment_method_data::{PaymentMethodData, UpiData},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
# use crate::masking::{PeekInterface, Secret};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use serde_json;
use url::Url;

use crate::{
    connectors::paytm::PaytmRouterData as MacroPaytmRouterData, types::ResponseRouterData,
};

#[derive(Debug, Clone)]
pub struct PaytmAuthType {
    pub merchant_id: Secret<String>,  // From api_key
    pub merchant_key: Secret<String>, // From key1
    pub website: Secret<String>,      // From api_secret
    pub channel_id: String,           // Hardcoded "WEB"
    pub client_id: Option<String>,    // None as specified
}

impl TryFrom<&ConnectorAuthType> for PaytmAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => {
                Ok(Self {
                    merchant_id: api_key.to_owned(), // merchant_id
                    merchant_key: key1.to_owned(),   // signing key
                    website: api_secret.to_owned(),  // website name
                    channel_id: constants::CHANNEL_ID.to_string(),
                    client_id: None, // None as specified
                })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub enum UpiFlowType {
    Intent,
    Collect,
}

pub fn determine_upi_flow<T: domain_types::payment_method_data::PaymentMethodDataTypes>(
    payment_method_data: &PaymentMethodData<T>,
) -> CustomResult<UpiFlowType, errors::ConnectorError> {
    match payment_method_data {
        PaymentMethodData::Upi(upi_data) => {
            match upi_data {
                UpiData::UpiCollect(collect_data) => {
                    // If VPA is provided, it's a collect flow
                    if collect_data.vpa_id.is_some() {
                        Ok(UpiFlowType::Collect)
                    } else {
                        // If no VPA provided, default to Intent
                        Ok(UpiFlowType::Intent)
                    }
                }
                UpiData::UpiIntent(_) | UpiData::UpiQr(_) => Ok(UpiFlowType::Intent),
            }
        }
        _ => {
            // Default to Intent for non-UPI specific payment methods
            Ok(UpiFlowType::Intent)
        }
    }
}

// Request structures for CreateSessionToken flow (Paytm initiate)

#[derive(Debug, Serialize)]
pub struct PaytmInitiateTxnRequest {
    pub head: PaytmRequestHeader,
    pub body: PaytmInitiateReqBody,
}

#[derive(Debug, Serialize)]
pub struct PaytmRequestHeader {
    #[serde(rename = "clientId")]
    pub client_id: Option<String>, // None
    pub version: String, // "v2"
    #[serde(rename = "requestTimestamp")]
    pub request_timestamp: String,
    #[serde(rename = "channelId")]
    pub channel_id: String, // "WEB"
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct PaytmInitiateReqBody {
    #[serde(rename = "requestType")]
    pub request_type: String, // "Payment"
    pub mid: String, // Merchant ID
    #[serde(rename = "orderId")]
    pub order_id: String, // Payment ID
    #[serde(rename = "websiteName")]
    pub website_name: String, // From api_secret
    #[serde(rename = "txnAmount")]
    pub txn_amount: PaytmAmount,
    #[serde(rename = "userInfo")]
    pub user_info: PaytmUserInfo,
    #[serde(rename = "enablePaymentMode")]
    pub enable_payment_mode: Vec<PaytmEnableMethod>,
    #[serde(rename = "callbackUrl")]
    pub callback_url: String,
}

#[derive(Debug, Serialize)]
pub struct PaytmAmount {
    pub value: StringMajorUnit, // Decimal amount (e.g., "10.50")
    pub currency: Currency,     // INR
}

#[derive(Debug, Serialize)]
pub struct PaytmUserInfo {
    #[serde(rename = "custId")]
    pub cust_id: String,
    pub mobile: Option<Secret<String>>,
    pub email: Option<Email>,
    #[serde(rename = "firstName")]
    pub first_name: Option<Secret<String>>,
    #[serde(rename = "lastName")]
    pub last_name: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
pub struct PaytmEnableMethod {
    pub mode: String,                  // "UPI"
    pub channels: Option<Vec<String>>, // ["UPIPUSH"] for Intent/Collect
}

// Response structures for CreateSessionToken flow

#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmInitiateTxnResponse {
    pub head: PaytmRespHead,
    pub body: PaytmResBodyTypes,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PaytmResBodyTypes {
    SuccessBody(PaytmRespBody),
    FailureBody(PaytmErrorBody),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmRespBody {
    #[serde(rename = "resultInfo")]
    pub result_info: PaytmResultInfo,
    #[serde(rename = "txnToken")]
    pub txn_token: String, // This will be stored as session_token
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmResultInfo {
    #[serde(rename = "resultStatus")]
    pub result_status: String,
    #[serde(rename = "resultCode")]
    pub result_code: String, // "0000" for success, "0002" for duplicate
    #[serde(rename = "resultMsg")]
    pub result_msg: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmRespHead {
    #[serde(rename = "responseTimestamp")]
    pub response_timestamp: Option<String>,
    pub version: String,
    #[serde(rename = "clientId")]
    pub client_id: Option<String>,
    pub signature: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmErrorBody {
    #[serde(rename = "resultInfo")]
    pub result_info: PaytmResultInfo,
}

// Error response structure
#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmErrorResponse {
    #[serde(rename = "errorCode")]
    pub error_code: Option<String>,
    #[serde(rename = "errorMessage")]
    pub error_message: Option<String>,
    #[serde(rename = "errorDescription")]
    pub error_description: Option<String>,
    #[serde(rename = "transactionId")]
    pub transaction_id: Option<String>,
}

// Transaction info structure used in multiple response types
// Supports both lowercase (txnId) and uppercase (TXNID) field name variants
#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmTxnInfo {
    #[serde(rename = "txnId", alias = "TXNID")]
    pub txn_id: Option<String>,
    #[serde(rename = "orderId", alias = "ORDERID")]
    pub order_id: Option<String>,
    #[serde(rename = "bankTxnId", alias = "BANKTXNID")]
    pub bank_txn_id: Option<String>,
    #[serde(alias = "STATUS")]
    pub status: Option<String>,
    #[serde(rename = "respCode", alias = "RESPCODE")]
    pub resp_code: Option<String>,
    #[serde(rename = "respMsg", alias = "RESPMSG")]
    pub resp_msg: Option<String>,
    // Additional callback-specific fields
    #[serde(alias = "CHECKSUMHASH")]
    pub checksum_hash: Option<String>,
    #[serde(alias = "CURRENCY")]
    pub currency: Option<Currency>,
    #[serde(alias = "GATEWAYNAME")]
    pub gateway_name: Option<String>,
    #[serde(alias = "MID")]
    pub mid: Option<String>,
    #[serde(alias = "PAYMENTMODE")]
    pub payment_mode: Option<String>,
    #[serde(alias = "TXNAMOUNT")]
    pub txn_amount: Option<StringMajorUnit>,
    #[serde(alias = "TXNDATE")]
    pub txn_date: Option<String>,
}

// Alternative error response structure for callback URL format
#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmCallbackErrorResponse {
    pub head: PaytmRespHead,
    pub body: PaytmCallbackErrorBody,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmCallbackErrorBody {
    #[serde(rename = "resultInfo")]
    pub result_info: PaytmResultInfo,
    #[serde(rename = "txnInfo")]
    pub txn_info: PaytmTxnInfo,
}

// Authorize flow request structures

// Enum to handle both UPI Intent and UPI Collect request types
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum PaytmAuthorizeRequest {
    Intent(PaytmProcessTxnRequest),
    Collect(PaytmNativeProcessTxnRequest),
}

#[derive(Debug, Serialize)]
pub struct PaytmProcessTxnRequest {
    pub head: PaytmProcessHeadTypes,
    pub body: PaytmProcessBodyTypes,
}

#[derive(Debug, Serialize)]
pub struct PaytmProcessHeadTypes {
    pub version: String, // "v2"
    #[serde(rename = "requestTimestamp")]
    pub request_timestamp: String,
    #[serde(rename = "channelId")]
    pub channel_id: String, // "WEB"
    #[serde(rename = "txnToken")]
    pub txn_token: String, // From CreateSessionToken
}

#[derive(Debug, Serialize)]
pub struct PaytmProcessBodyTypes {
    pub mid: String,
    #[serde(rename = "orderId")]
    pub order_id: String,
    #[serde(rename = "requestType")]
    pub request_type: String, // "Payment"
    #[serde(rename = "paymentMode")]
    pub payment_mode: String, // "UPI"
    #[serde(rename = "paymentFlow")]
    pub payment_flow: Option<String>, // "NONE"
}

// UPI Collect Native Process Request
#[derive(Debug, Serialize)]
pub struct PaytmNativeProcessTxnRequest {
    pub head: PaytmTxnTokenType,
    pub body: PaytmNativeProcessRequestBody,
}

#[derive(Debug, Serialize)]
pub struct PaytmTxnTokenType {
    #[serde(rename = "txnToken")]
    pub txn_token: String, // From CreateSessionToken
}

#[derive(Debug, Serialize)]
pub struct PaytmNativeProcessRequestBody {
    #[serde(rename = "requestType")]
    pub request_type: String, // "NATIVE"
    pub mid: String,
    #[serde(rename = "orderId")]
    pub order_id: String,
    #[serde(rename = "paymentMode")]
    pub payment_mode: String, // "UPI"
    #[serde(rename = "payerAccount")]
    pub payer_account: Option<String>, // UPI VPA for collect
    #[serde(rename = "channelCode")]
    pub channel_code: Option<String>, // Gateway code
    #[serde(rename = "channelId")]
    pub channel_id: String, // "WEB"
    #[serde(rename = "txnToken")]
    pub txn_token: String, // From CreateSessionToken
    #[serde(rename = "authMode")]
    pub auth_mode: Option<String>, // "DEBIT_PIN"
}

// Authorize flow response structures

#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmProcessTxnResponse {
    pub head: PaytmProcessHead,
    pub body: PaytmProcessRespBodyTypes,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmProcessHead {
    pub version: Option<String>,
    #[serde(rename = "responseTimestamp")]
    pub response_timestamp: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PaytmProcessRespBodyTypes {
    SuccessBody(Box<PaytmProcessSuccessResp>),
    FailureBody(PaytmProcessFailureResp),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmProcessSuccessResp {
    #[serde(rename = "resultInfo")]
    pub result_info: PaytmResultInfo,
    #[serde(rename = "deepLinkInfo", skip_serializing_if = "Option::is_none")]
    pub deep_link_info: Option<PaytmDeepLinkInfo>,
    #[serde(rename = "bankForm", skip_serializing_if = "Option::is_none")]
    pub bank_form: Option<serde_json::Value>,
    #[serde(rename = "upiDirectForm", skip_serializing_if = "Option::is_none")]
    pub upi_direct_form: Option<serde_json::Value>,
    #[serde(rename = "displayField", skip_serializing_if = "Option::is_none")]
    pub display_field: Option<serde_json::Value>,
    #[serde(rename = "riskContent", skip_serializing_if = "Option::is_none")]
    pub risk_content: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmDeepLinkInfo {
    #[serde(rename = "deepLink")]
    pub deep_link: String, // UPI intent URL
    #[serde(rename = "orderId")]
    pub order_id: String,
    #[serde(rename = "cashierRequestId")]
    pub cashier_request_id: String,
    #[serde(rename = "transId")]
    pub trans_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmProcessFailureResp {
    #[serde(rename = "resultInfo")]
    pub result_info: PaytmResultInfo,
}

// UPI Collect Native Process Response
#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmNativeProcessTxnResponse {
    pub head: PaytmProcessHead,
    pub body: PaytmNativeProcessRespBodyTypes,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PaytmNativeProcessRespBodyTypes {
    SuccessBody(PaytmNativeProcessSuccessResp),
    FailureBody(PaytmNativeProcessFailureResp),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmNativeProcessSuccessResp {
    #[serde(rename = "resultInfo")]
    pub result_info: PaytmResultInfo,
    #[serde(rename = "transId")]
    pub trans_id: String,
    #[serde(rename = "orderId")]
    pub order_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmNativeProcessFailureResp {
    #[serde(rename = "resultInfo")]
    pub result_info: PaytmResultInfo,
}

// Helper function for UPI VPA extraction
pub fn extract_upi_vpa<T: domain_types::payment_method_data::PaymentMethodDataTypes>(
    payment_method_data: &PaymentMethodData<T>,
) -> CustomResult<Option<String>, errors::ConnectorError> {
    match payment_method_data {
        PaymentMethodData::Upi(UpiData::UpiCollect(collect_data)) => {
            if let Some(vpa_id) = &collect_data.vpa_id {
                let vpa = vpa_id.peek().to_string();
                if vpa.contains('@') && vpa.len() > 3 {
                    Ok(Some(vpa))
                } else {
                    Err(errors::ConnectorError::RequestEncodingFailedWithReason(
                        constants::ERROR_INVALID_VPA.to_string(),
                    )
                    .into())
                }
            } else {
                Err(errors::ConnectorError::MissingRequiredField {
                    field_name: "vpa_id",
                }
                .into())
            }
        }
        _ => Ok(None),
    }
}

// Paytm signature generation algorithm implementation
// Following exact PayTM v2 algorithm from Haskell codebase
pub fn generate_paytm_signature(
    payload: &str,
    merchant_key: &str,
) -> CustomResult<String, errors::ConnectorError> {
    // Step 1: Generate random salt bytes using ring (same logic, different implementation)
    let rng = SystemRandom::new();
    let mut salt_bytes = [0u8; constants::SALT_LENGTH];
    rng.fill(&mut salt_bytes).map_err(|_| {
        errors::ConnectorError::RequestEncodingFailedWithReason(
            constants::ERROR_SALT_GENERATION.to_string(),
        )
    })?;

    // Step 2: Convert salt to Base64 (same logic)
    let salt_b64 = general_purpose::STANDARD.encode(salt_bytes);

    // Step 3: Create hash input: payload + "|" + base64_salt (same logic)
    let hash_input = format!("{payload}|{salt_b64}");

    // Step 4: SHA-256 hash using ring (same logic, different implementation)
    let hash_digest = digest::digest(&digest::SHA256, hash_input.as_bytes());
    let sha256_hash = hex::encode(hash_digest.as_ref());

    // Step 5: Create checksum: sha256_hash + base64_salt (same logic)
    let checksum = format!("{sha256_hash}{salt_b64}");

    // Step 6: AES encrypt checksum with merchant key (same logic)
    let signature = aes_encrypt(&checksum, merchant_key)?;

    Ok(signature)
}

// AES-CBC encryption implementation for PayTM v2
// This follows the exact PayTMv1 encrypt function used by PayTMv2:
// - Fixed IV: "@@@@&&&&####$$$$" (16 bytes) - exact value from Haskell code
// - Key length determines AES variant: 16→AES-128, 24→AES-192, other→AES-256
// - Mode: CBC with PKCS7 padding (16-byte blocks)
// - Output: Base64 encoded encrypted data
fn aes_encrypt(data: &str, key: &str) -> CustomResult<String, errors::ConnectorError> {
    // PayTM uses fixed IV as specified in PayTMv1 implementation
    let iv = get_paytm_iv();
    let key_bytes = key.as_bytes();
    let data_bytes = data.as_bytes();

    // Determine AES variant based on key length (following PayTMv1 Haskell implementation)
    match key_bytes.len() {
        constants::AES_128_KEY_LENGTH => {
            // AES-128-CBC with PKCS7 padding
            type Aes128CbcEnc = Encryptor<Aes128>;
            let mut key_array = [0u8; constants::AES_128_KEY_LENGTH];
            key_array.copy_from_slice(key_bytes);

            let encryptor = Aes128CbcEnc::new(&key_array.into(), &iv.into());

            // Encrypt with proper buffer management
            let mut buffer = Vec::with_capacity(data_bytes.len() + constants::AES_BUFFER_PADDING);
            buffer.extend_from_slice(data_bytes);
            buffer.resize(buffer.len() + constants::AES_BUFFER_PADDING, 0);

            let encrypted_len = encryptor
                .encrypt_padded_mut::<Pkcs7>(&mut buffer, data_bytes.len())
                .map_err(|_| {
                    errors::ConnectorError::RequestEncodingFailedWithReason(
                        constants::ERROR_AES_128_ENCRYPTION.to_string(),
                    )
                })?
                .len();

            buffer.truncate(encrypted_len);
            Ok(general_purpose::STANDARD.encode(&buffer))
        }
        constants::AES_192_KEY_LENGTH => {
            // AES-192-CBC with PKCS7 padding
            type Aes192CbcEnc = Encryptor<Aes192>;
            let mut key_array = [0u8; constants::AES_192_KEY_LENGTH];
            key_array.copy_from_slice(key_bytes);

            let encryptor = Aes192CbcEnc::new(&key_array.into(), &iv.into());

            let mut buffer = Vec::with_capacity(data_bytes.len() + constants::AES_BUFFER_PADDING);
            buffer.extend_from_slice(data_bytes);
            buffer.resize(buffer.len() + constants::AES_BUFFER_PADDING, 0);

            let encrypted_len = encryptor
                .encrypt_padded_mut::<Pkcs7>(&mut buffer, data_bytes.len())
                .map_err(|_| {
                    errors::ConnectorError::RequestEncodingFailedWithReason(
                        constants::ERROR_AES_192_ENCRYPTION.to_string(),
                    )
                })?
                .len();

            buffer.truncate(encrypted_len);
            Ok(general_purpose::STANDARD.encode(&buffer))
        }
        _ => {
            // Default to AES-256-CBC with PKCS7 padding (for any other key length)
            type Aes256CbcEnc = Encryptor<Aes256>;

            // For AES-256, we need exactly 32 bytes, so pad or truncate the key
            let mut aes256_key = [0u8; constants::AES_256_KEY_LENGTH];
            let copy_len = cmp::min(key_bytes.len(), constants::AES_256_KEY_LENGTH);
            aes256_key[..copy_len].copy_from_slice(&key_bytes[..copy_len]);

            let encryptor = Aes256CbcEnc::new(&aes256_key.into(), &iv.into());

            let mut buffer = Vec::with_capacity(data_bytes.len() + constants::AES_BUFFER_PADDING);
            buffer.extend_from_slice(data_bytes);
            buffer.resize(buffer.len() + constants::AES_BUFFER_PADDING, 0);

            let encrypted_len = encryptor
                .encrypt_padded_mut::<Pkcs7>(&mut buffer, data_bytes.len())
                .map_err(|_| {
                    errors::ConnectorError::RequestEncodingFailedWithReason(
                        constants::ERROR_AES_256_ENCRYPTION.to_string(),
                    )
                })?
                .len();

            buffer.truncate(encrypted_len);
            Ok(general_purpose::STANDARD.encode(&buffer))
        }
    }
}

// Fixed IV for Paytm AES encryption (from PayTM v2 Haskell implementation)
// IV value: "@@@@&&&&####$$$$" (16 characters) - exact value from Haskell codebase
fn get_paytm_iv() -> [u8; 16] {
    // This is the exact IV used by PayTM v2 as found in the Haskell codebase
    *constants::PAYTM_IV
}

pub fn create_paytm_header(
    request_body: &impl serde::Serialize,
    auth: &PaytmAuthType,
) -> CustomResult<PaytmRequestHeader, errors::ConnectorError> {
    let _payload = serde_json::to_string(request_body)
        .change_context(errors::ConnectorError::RequestEncodingFailed)?;
    let signature = generate_paytm_signature(&_payload, auth.merchant_key.peek())?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    Ok(PaytmRequestHeader {
        client_id: auth.client_id.clone(), // None
        version: constants::API_VERSION.to_string(),
        request_timestamp: timestamp,
        channel_id: auth.channel_id.clone(), // "WEB"
        signature,
    })
}

// Helper struct for RouterData transformation
#[derive(Debug, Clone)]
pub struct PaytmRouterData {
    pub amount: StringMajorUnit,
    pub currency: Currency,
    pub payment_id: String,
    pub customer_id: Option<String>,
    pub email: Option<Email>,
    pub phone: Option<Secret<String>>,
    pub first_name: Option<Secret<String>>,
    pub last_name: Option<Secret<String>>,
    pub return_url: Option<String>,
}

// Helper struct for Authorize flow RouterData transformation
#[derive(Debug, Clone)]
pub struct PaytmAuthorizeRouterData<T: domain_types::payment_method_data::PaymentMethodDataTypes> {
    pub amount: StringMajorUnit,
    pub currency: Currency,
    pub payment_id: String,
    pub session_token: String,
    pub payment_method_data: PaymentMethodData<T>,
    pub customer_id: Option<String>,
    pub email: Option<Email>,
    pub phone: Option<Secret<String>>,
    pub first_name: Option<Secret<String>>,
    pub last_name: Option<Secret<String>>,
    pub return_url: Option<String>,
}

// Request transformation for CreateSessionToken flow
impl PaytmRouterData {
    pub fn try_from_with_converter(
        item: &RouterDataV2<
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
        amount_converter: &dyn AmountConvertor<Output = StringMajorUnit>,
    ) -> Result<Self, error_stack::Report<errors::ConnectorError>> {
        let amount = amount_converter
            .convert(item.request.amount, item.request.currency)
            .change_context(errors::ConnectorError::AmountConversionFailed)?;
        let customer_id = item
            .resource_common_data
            .get_customer_id()
            .ok()
            .map(|id| id.get_string_repr().to_string());
        let email = item.resource_common_data.get_optional_billing_email();
        let phone = item
            .resource_common_data
            .get_optional_billing_phone_number();
        let first_name = item.resource_common_data.get_optional_billing_first_name();
        let last_name = item.resource_common_data.get_optional_billing_last_name();

        Ok(Self {
            amount,
            currency: item.request.currency,
            payment_id: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            customer_id,
            email,
            phone,
            first_name,
            last_name,
            return_url: item.resource_common_data.get_return_url(),
        })
    }
}

// Request body transformation for PayTM initiate transaction
impl PaytmInitiateTxnRequest {
    pub fn try_from_with_auth(
        item: &PaytmRouterData,
        auth: &PaytmAuthType,
    ) -> CustomResult<Self, errors::ConnectorError> {
        let body = PaytmInitiateReqBody {
            request_type: constants::REQUEST_TYPE_PAYMENT.to_string(),
            mid: auth.merchant_id.peek().to_string(),
            order_id: item.payment_id.clone(),
            website_name: auth.website.peek().to_string(),
            txn_amount: PaytmAmount {
                value: item.amount.clone(),
                currency: item.currency,
            },
            user_info: PaytmUserInfo {
                cust_id: item
                    .customer_id
                    .clone()
                    .unwrap_or_else(|| constants::DEFAULT_CUSTOMER_ID.to_string()),
                mobile: item.phone.clone(),
                email: item.email.clone(),
                first_name: item.first_name.clone(),
                last_name: item.last_name.clone(),
            },
            enable_payment_mode: vec![PaytmEnableMethod {
                mode: constants::PAYMENT_MODE_UPI.to_string(),
                channels: Some(vec![
                    constants::UPI_CHANNEL_UPIPUSH.to_string(),
                    constants::PAYMENT_MODE_UPI.to_string(),
                ]),
            }],
            callback_url: item
                .return_url
                .clone()
                .unwrap_or_else(|| constants::DEFAULT_CALLBACK_URL.to_string()),
        };

        // Create header with actual signature
        let head = create_paytm_header(&body, auth)?;

        Ok(Self { head, body })
    }
}

// Request transformation for Authorize flow
impl<T: domain_types::payment_method_data::PaymentMethodDataTypes> PaytmAuthorizeRouterData<T> {
    pub fn try_from_with_converter(
        item: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
        amount_converter: &dyn AmountConvertor<Output = StringMajorUnit>,
    ) -> Result<Self, error_stack::Report<errors::ConnectorError>> {
        let amount = amount_converter
            .convert(item.request.minor_amount, item.request.currency)
            .change_context(errors::ConnectorError::AmountConversionFailed)?;
        let customer_id = item
            .resource_common_data
            .get_customer_id()
            .ok()
            .map(|id| id.get_string_repr().to_string());
        let email = item.resource_common_data.get_optional_billing_email();
        let phone = item
            .resource_common_data
            .get_optional_billing_phone_number();
        let first_name = item.resource_common_data.get_optional_billing_first_name();
        let last_name = item.resource_common_data.get_optional_billing_last_name();

        // Extract session token from previous session token response
        let session_token = item.resource_common_data.get_session_token()?;

        Ok(Self {
            amount,
            currency: item.request.currency,
            payment_id: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            session_token,
            payment_method_data: item.request.payment_method_data.clone(),
            customer_id,
            email,
            phone,
            first_name,
            last_name,
            return_url: item.resource_common_data.get_return_url(),
        })
    }
}

// Request transformation for PayTM UPI Intent flow (ProcessTxnRequest)
impl PaytmProcessTxnRequest {
    pub fn try_from_with_auth<T: domain_types::payment_method_data::PaymentMethodDataTypes>(
        item: &PaytmAuthorizeRouterData<T>,
        auth: &PaytmAuthType,
    ) -> CustomResult<Self, errors::ConnectorError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();

        let head = PaytmProcessHeadTypes {
            version: constants::API_VERSION.to_string(),
            request_timestamp: timestamp,
            channel_id: auth.channel_id.clone(),
            txn_token: item.session_token.clone(),
        };

        let body = PaytmProcessBodyTypes {
            mid: auth.merchant_id.peek().to_string(),
            order_id: item.payment_id.clone(),
            request_type: constants::REQUEST_TYPE_PAYMENT.to_string(),
            payment_mode: format!("{}_{}", constants::PAYMENT_MODE_UPI, "INTENT"), // "UPI_INTENT" for intent
            payment_flow: Some(constants::PAYMENT_FLOW_NONE.to_string()),
        };

        Ok(Self { head, body })
    }
}

// Request transformation for PayTM UPI Collect flow (NativeProcessTxnRequest)
impl PaytmNativeProcessTxnRequest {
    pub fn try_from_with_auth<T: domain_types::payment_method_data::PaymentMethodDataTypes>(
        item: &PaytmAuthorizeRouterData<T>,
        auth: &PaytmAuthType,
    ) -> CustomResult<Self, errors::ConnectorError> {
        // Extract UPI VPA for collect flow
        let vpa = extract_upi_vpa(&item.payment_method_data)?.ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "vpa_id",
            },
        )?;

        let head = PaytmTxnTokenType {
            txn_token: item.session_token.clone(),
        };

        let body = PaytmNativeProcessRequestBody {
            request_type: constants::REQUEST_TYPE_NATIVE.to_string(),
            mid: auth.merchant_id.peek().to_string(),
            order_id: item.payment_id.clone(),
            payment_mode: constants::PAYMENT_MODE_UPI.to_string(),
            payer_account: Some(vpa),
            channel_code: Some("collect".to_string()), // Gateway code if needed
            channel_id: auth.channel_id.clone(),
            txn_token: item.session_token.clone(),
            auth_mode: None,
        };

        Ok(Self { head, body })
    }
}

// PSync (Payment Sync) flow request structures

#[derive(Debug, Serialize)]
pub struct PaytmTransactionStatusRequest {
    pub head: PaytmRequestHeader,
    pub body: PaytmTransactionStatusReqBody,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytmTransactionStatusReqBody {
    pub mid: String,      // Merchant ID
    pub order_id: String, // Order ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txn_type: Option<String>, // PREAUTH, CAPTURE, RELEASE, WITHDRAW
}

// PSync (Payment Sync) flow response structures

#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmTransactionStatusResponse {
    pub head: PaytmRespHead,
    pub body: PaytmTransactionStatusRespBodyTypes,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PaytmTransactionStatusRespBodyTypes {
    SuccessBody(Box<PaytmTransactionStatusRespBody>),
    FailureBody(PaytmErrorBody),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytmTransactionStatusRespBody {
    pub result_info: PaytmResultInfo,
    pub txn_id: Option<String>,
    pub bank_txn_id: Option<String>,
    pub order_id: Option<String>,
    pub txn_amount: Option<StringMajorUnit>,
    pub txn_type: Option<String>,
    pub gateway_name: Option<String>,
    pub mid: Option<String>,
    pub payment_mode: Option<String>,
    pub refund_amt: Option<String>,
    pub txn_date: Option<String>,
}

// Helper struct for PSync RouterData transformation
#[derive(Debug, Clone)]
pub struct PaytmSyncRouterData {
    pub payment_id: String,
    pub connector_transaction_id: Option<String>,
    pub txn_type: Option<String>,
}

// Request transformation for PSync flow
impl TryFrom<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for PaytmSyncRouterData
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Use connector transaction ID if available, otherwise fall back to payment ID
        let transaction_id = item
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .unwrap_or_else(|_| {
                item.resource_common_data
                    .connector_request_reference_id
                    .clone()
            });

        let connector_transaction_id = item
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_| {
                error_stack::Report::new(errors::ConnectorError::MissingConnectorTransactionID)
            })?;

        Ok(Self {
            payment_id: transaction_id,
            connector_transaction_id: Some(connector_transaction_id),
            txn_type: None,
        })
    }
}

// Request body transformation for PayTM transaction status
impl PaytmTransactionStatusRequest {
    pub fn try_from_with_auth(
        item: &PaytmSyncRouterData,
        auth: &PaytmAuthType,
    ) -> CustomResult<Self, errors::ConnectorError> {
        let body = PaytmTransactionStatusReqBody {
            mid: auth.merchant_id.peek().to_string(),
            order_id: item.payment_id.clone(),
            txn_type: item.txn_type.clone(),
        };

        // Create header with actual signature
        let head = create_paytm_header(&body, auth)?;

        Ok(Self { head, body })
    }
}

// Status mapping function for Paytm result codes
pub fn map_paytm_status_to_attempt_status(result_code: &str) -> AttemptStatus {
    match result_code {
        // Success
        "01" => AttemptStatus::Charged,                 // TXN_SUCCESS
        "0000" => AttemptStatus::AuthenticationPending, // Success - waiting for authentication

        // Pending cases
        "400" | "402" => AttemptStatus::Pending, // PENDING, PENDING_BANK_CONFIRM
        "331" => AttemptStatus::Pending,         // NO_RECORD_FOUND

        // Failure cases
        "227" | "235" | "295" | "334" | "335" | "401" | "501" | "810" | "843" | "820" | "267" => {
            AttemptStatus::Failure
        }

        // Default to failure for unknown codes (WILL NEVER HAPPEN)
        _ => AttemptStatus::Pending,
    }
}

// Additional response structures needed for compilation

// Session token error response structure
#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmSessionTokenErrorResponse {
    pub head: PaytmRespHead,
    pub body: PaytmSessionTokenErrorBody,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmSessionTokenErrorBody {
    #[serde(rename = "extraParamsMap")]
    pub extra_params_map: Option<serde_json::Value>, // This field must be present (even if null) to distinguish from other types
    #[serde(rename = "resultInfo")]
    pub result_info: PaytmResultInfo,
}

// Success transaction response structure (handles both callback and standard formats)
#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmSuccessTransactionResponse {
    pub head: PaytmRespHead,
    pub body: PaytmSuccessTransactionBody,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmSuccessTransactionBody {
    #[serde(rename = "resultInfo")]
    pub result_info: PaytmResultInfo,
    #[serde(rename = "txnInfo")]
    pub txn_info: PaytmTxnInfo,
    #[serde(rename = "callBackUrl")]
    pub callback_url: Option<String>,
}

// Bank form response structure
#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmBankFormResponse {
    pub head: PaytmRespHead,
    pub body: PaytmBankFormBody,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmBankFormBody {
    #[serde(rename = "resultInfo")]
    pub result_info: PaytmResultInfo,
    #[serde(rename = "bankForm")]
    pub bank_form: PaytmBankForm,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmBankForm {
    #[serde(rename = "redirectForm")]
    pub redirect_form: PaytmRedirectForm,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmRedirectForm {
    #[serde(rename = "actionUrl")]
    pub action_url: String,
    pub method: String,
    pub content: HashMap<String, String>,
}

// TryFrom implementations required by the macro framework
// The macro expects TryFrom implementations that work with its generated PaytmRouterData<RouterDataV2<...>>

// Since the macro generates PaytmRouterData<T> but our existing PaytmRouterData is not generic,
// we need to implement TryFrom for the exact RouterDataV2 types the macro expects

// PaytmInitiateTxnRequest TryFrom CreateSessionToken RouterData
// Using the macro-generated PaytmRouterData type from the paytm module
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        MacroPaytmRouterData<
            RouterDataV2<
                CreateSessionToken,
                PaymentFlowData,
                SessionTokenRequestData,
                SessionTokenResponseData,
            >,
            T,
        >,
    > for PaytmInitiateTxnRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: MacroPaytmRouterData<
            RouterDataV2<
                CreateSessionToken,
                PaymentFlowData,
                SessionTokenRequestData,
                SessionTokenResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = PaytmAuthType::try_from(&item.router_data.connector_auth_type)?;
        let intermediate_router_data = PaytmRouterData::try_from_with_converter(
            &item.router_data,
            item.connector.amount_converter,
        )?;
        PaytmInitiateTxnRequest::try_from_with_auth(&intermediate_router_data, &auth)
    }
}

// PaytmAuthorizeRequest TryFrom Authorize RouterData
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        MacroPaytmRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for PaytmAuthorizeRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: MacroPaytmRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = PaytmAuthType::try_from(&item.router_data.connector_auth_type)?;
        let intermediate_authorize_router_data = PaytmAuthorizeRouterData::try_from_with_converter(
            &item.router_data,
            item.connector.amount_converter,
        )?;

        // Determine the UPI flow type based on payment method data
        let upi_flow = determine_upi_flow(&item.router_data.request.payment_method_data)?;

        match upi_flow {
            UpiFlowType::Intent => {
                // UPI Intent flow - use PaytmProcessTxnRequest
                let intent_request = PaytmProcessTxnRequest::try_from_with_auth(
                    &intermediate_authorize_router_data,
                    &auth,
                )?;
                Ok(PaytmAuthorizeRequest::Intent(intent_request))
            }
            UpiFlowType::Collect => {
                // UPI Collect flow - use PaytmNativeProcessTxnRequest
                let collect_request = PaytmNativeProcessTxnRequest::try_from_with_auth(
                    &intermediate_authorize_router_data,
                    &auth,
                )?;
                Ok(PaytmAuthorizeRequest::Collect(collect_request))
            }
        }
    }
}

// PaytmTransactionStatusRequest TryFrom PSync RouterData
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        MacroPaytmRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for PaytmTransactionStatusRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: MacroPaytmRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = PaytmAuthType::try_from(&item.router_data.connector_auth_type)?;
        let intermediate_sync_router_data = PaytmSyncRouterData::try_from(&item.router_data)?;
        PaytmTransactionStatusRequest::try_from_with_auth(&intermediate_sync_router_data, &auth)
    }
}

// ResponseRouterData TryFrom implementations required by the macro framework

// CreateSessionToken response transformation
impl
    TryFrom<
        ResponseRouterData<
            PaytmInitiateTxnResponse,
            RouterDataV2<
                CreateSessionToken,
                PaymentFlowData,
                SessionTokenRequestData,
                SessionTokenResponseData,
            >,
        >,
    >
    for RouterDataV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            PaytmInitiateTxnResponse,
            RouterDataV2<
                CreateSessionToken,
                PaymentFlowData,
                SessionTokenRequestData,
                SessionTokenResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let mut router_data = item.router_data;

        // Handle both success and failure cases from the enum body
        let session_token = match &response.body {
            PaytmResBodyTypes::SuccessBody(success_body) => Some(success_body.txn_token.clone()),
            PaytmResBodyTypes::FailureBody(_failure_body) => None,
        };

        router_data.response = Ok(SessionTokenResponseData {
            session_token: session_token.unwrap_or_default(),
        });

        Ok(router_data)
    }
}

// Authorize response transformation
impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    >
    TryFrom<
        ResponseRouterData<
            PaytmProcessTxnResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            PaytmProcessTxnResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let mut router_data = item.router_data;

        // Handle both success and failure cases from the enum body
        let (redirection_data, resource_id, connector_txn_id) = match &response.body {
            PaytmProcessRespBodyTypes::SuccessBody(success_body) => {
                // Extract redirection URL if present
                let redirection_data = if let Some(deep_link_info) = &success_body.deep_link_info {
                    if !deep_link_info.deep_link.is_empty() {
                        // Check if it's a UPI deep link (starts with upi://) or regular URL
                        if deep_link_info.deep_link.starts_with("upi://") {
                            // For UPI deep links, use them as-is
                            Some(Box::new(RedirectForm::Uri {
                                uri: deep_link_info.deep_link.clone(),
                            }))
                        } else {
                            // For regular URLs, parse and convert
                            let url = Url::parse(&deep_link_info.deep_link).change_context(
                                errors::ConnectorError::ResponseDeserializationFailed,
                            )?;
                            Some(Box::new(RedirectForm::from((url, Method::Get))))
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Extract transaction IDs from deep_link_info or use fallback
                let (resource_id, connector_txn_id) =
                    if let Some(deep_link_info) = &success_body.deep_link_info {
                        let resource_id =
                            ResponseId::ConnectorTransactionId(deep_link_info.order_id.clone());
                        let connector_txn_id = Some(deep_link_info.trans_id.clone());
                        (resource_id, connector_txn_id)
                    } else {
                        // Fallback when deep_link_info is not present
                        let resource_id = ResponseId::ConnectorTransactionId(
                            router_data
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                        );
                        (resource_id, None)
                    };

                (redirection_data, resource_id, connector_txn_id)
            }
            PaytmProcessRespBodyTypes::FailureBody(_failure_body) => {
                let resource_id = ResponseId::ConnectorTransactionId(
                    router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                );
                (None, resource_id, None)
            }
        };
        // Get result code for status mapping
        let result_code = match &response.body {
            PaytmProcessRespBodyTypes::SuccessBody(success_body) => {
                &success_body.result_info.result_code
            }
            PaytmProcessRespBodyTypes::FailureBody(failure_body) => {
                &failure_body.result_info.result_code
            }
        };

        // Map status using the result code
        let attempt_status = map_paytm_status_to_attempt_status(result_code);
        router_data.resource_common_data.set_status(attempt_status);

        router_data.response = Ok(PaymentsResponseData::TransactionResponse {
            resource_id,
            redirection_data,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: connector_txn_id,
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        });

        Ok(router_data)
    }
}

// PSync response transformation
impl
    TryFrom<
        ResponseRouterData<
            PaytmTransactionStatusResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            PaytmTransactionStatusResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let mut router_data = item.router_data;

        // Handle both success and failure cases from the enum body
        let (resource_id, connector_txn_id) = match &response.body {
            PaytmTransactionStatusRespBodyTypes::SuccessBody(success_body) => {
                let order_id = success_body.order_id.clone().unwrap_or_else(|| {
                    router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone()
                });
                let resource_id = ResponseId::ConnectorTransactionId(order_id);
                let connector_txn_id = success_body.txn_id.clone();
                (resource_id, connector_txn_id)
            }
            PaytmTransactionStatusRespBodyTypes::FailureBody(_failure_body) => {
                let resource_id = ResponseId::ConnectorTransactionId(
                    router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                );
                (resource_id, None)
            }
        };

        // Get result code for status mapping
        let result_code = match &response.body {
            PaytmTransactionStatusRespBodyTypes::SuccessBody(success_body) => {
                &success_body.result_info.result_code
            }
            PaytmTransactionStatusRespBodyTypes::FailureBody(failure_body) => {
                &failure_body.result_info.result_code
            }
        };

        // Map status and set response accordingly
        let attempt_status = map_paytm_status_to_attempt_status(result_code);

        // Update the status using the new setter function
        router_data.resource_common_data.set_status(attempt_status);

        router_data.response = match attempt_status {
            AttemptStatus::Failure => Err(domain_types::router_data::ErrorResponse {
                code: result_code.clone(),
                message: match &response.body {
                    PaytmTransactionStatusRespBodyTypes::SuccessBody(body) => {
                        body.result_info.result_msg.clone()
                    }
                    PaytmTransactionStatusRespBodyTypes::FailureBody(body) => {
                        body.result_info.result_msg.clone()
                    }
                },
                reason: None,
                status_code: item.http_code,
                attempt_status: Some(attempt_status),
                connector_transaction_id: connector_txn_id.clone(),
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            }),
            _ => Ok(PaymentsResponseData::TransactionResponse {
                resource_id,
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: connector_txn_id,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
        };

        Ok(router_data)
    }
}
