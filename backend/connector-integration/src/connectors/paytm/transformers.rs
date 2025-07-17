use std::time::{SystemTime, UNIX_EPOCH};

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
    pub const AUTH_MODE_DEBIT_PIN: &str = "pin";
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
    pub const QR_SUCCESS_CODE: &str = "QR_0001";

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
    types::{AmountConvertor, MinorUnit, StringMajorUnit},
};
use domain_types::{
    connector_flow::PSync,
    connector_types::{PaymentFlowData, PaymentsResponseData, PaymentsSyncData},
    errors,
    payment_method_data::{PaymentMethodData, UpiData},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};

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
    // QrCode,
}

pub fn determine_upi_flow(
    payment_method_data: &PaymentMethodData,
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
                UpiData::UpiIntent(_) => Ok(UpiFlowType::Intent),
                // UpiData::UpiQr(_) => {
                //     Ok(UpiFlowType::QrCode)
                // }
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
#[serde(rename_all = "camelCase")]
pub struct PaytmRequestHeader {
    pub client_id: Option<String>, // None
    pub version: String,           // "v2"
    pub request_timestamp: String,
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
    pub value: String,    // Decimal amount (e.g., "10.50")
    pub currency: String, // "INR"
}

#[derive(Debug, Serialize)]
pub struct PaytmUserInfo {
    #[serde(rename = "custId")]
    pub cust_id: String,
    pub mobile: Option<String>,
    pub email: Option<String>,
    #[serde(rename = "firstName")]
    pub first_name: Option<String>,
    #[serde(rename = "lastName")]
    pub last_name: Option<String>,
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

// Authorize flow request structures

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
    SuccessBody(PaytmProcessSuccessResp),
    FailureBody(PaytmProcessFailureResp),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmProcessSuccessResp {
    #[serde(rename = "resultInfo")]
    pub result_info: PaytmResultInfo,
    #[serde(rename = "deepLinkInfo")]
    pub deep_link_info: PaytmDeepLinkInfo,
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
pub fn extract_upi_vpa(
    payment_method_data: &PaymentMethodData,
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
            let copy_len = std::cmp::min(key_bytes.len(), constants::AES_256_KEY_LENGTH);
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
    pub amount: i64,
    pub currency: Currency,
    pub payment_id: String,
    pub customer_id: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub return_url: Option<String>,
}

// Helper struct for Authorize flow RouterData transformation
#[derive(Debug, Clone)]
pub struct PaytmAuthorizeRouterData {
    pub amount: i64,
    pub currency: String,
    pub payment_id: String,
    pub session_token: String,
    pub payment_method_data: PaymentMethodData,
    pub customer_id: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub return_url: Option<String>,
}

// Request transformation for CreateSessionToken flow
impl
    TryFrom<
        &domain_types::router_data_v2::RouterDataV2<
            domain_types::connector_flow::CreateSessionToken,
            domain_types::connector_types::PaymentFlowData,
            domain_types::connector_types::SessionTokenRequestData,
            domain_types::connector_types::SessionTokenResponseData,
        >,
    > for PaytmRouterData
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &domain_types::router_data_v2::RouterDataV2<
            domain_types::connector_flow::CreateSessionToken,
            domain_types::connector_types::PaymentFlowData,
            domain_types::connector_types::SessionTokenRequestData,
            domain_types::connector_types::SessionTokenResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let amount_minor_units = item.request.amount.get_amount_as_i64();
        let customer_id = item
            .resource_common_data
            .get_customer_id()
            .ok()
            .map(|id| id.get_string_repr().to_string());
        let email = item
            .resource_common_data
            .get_optional_billing_email()
            .map(|e| e.peek().to_string());
        let phone = item
            .resource_common_data
            .get_optional_billing_phone_number()
            .map(|p| p.peek().to_string());
        let first_name = item
            .resource_common_data
            .get_optional_billing_first_name()
            .map(|name| name.peek().to_string());
        let last_name = item
            .resource_common_data
            .get_optional_billing_last_name()
            .map(|name| name.peek().to_string());

        Ok(Self {
            amount: amount_minor_units,
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
            return_url: item.resource_common_data.return_url.clone(),
        })
    }
}

// Request body transformation for PayTM initiate transaction
impl PaytmInitiateTxnRequest {
    pub fn try_from_with_auth(
        item: &PaytmRouterData,
        auth: &PaytmAuthType,
        amount_converter: &dyn AmountConvertor<Output = StringMajorUnit>,
    ) -> CustomResult<Self, errors::ConnectorError> {
        let amount_value = amount_converter
            .convert(MinorUnit::new(item.amount), item.currency)
            .change_context(errors::ConnectorError::AmountConversionFailed)?;
        let body = PaytmInitiateReqBody {
            request_type: constants::REQUEST_TYPE_PAYMENT.to_string(),
            mid: auth.merchant_id.peek().to_string(),
            order_id: item.payment_id.clone(),
            website_name: auth.website.peek().to_string(),
            txn_amount: PaytmAmount {
                value: amount_value.get_amount_as_string(),
                currency: item.currency.to_string(),
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
                channels: Some(vec![constants::UPI_CHANNEL_UPIPUSH.to_string()]),
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

// Note: Use PaytmInitiateTxnRequest::try_from_with_auth for production code
// This implementation is deprecated and should not be used

// Request transformation for Authorize flow
impl
    TryFrom<
        &domain_types::router_data_v2::RouterDataV2<
            domain_types::connector_flow::Authorize,
            domain_types::connector_types::PaymentFlowData,
            domain_types::connector_types::PaymentsAuthorizeData,
            domain_types::connector_types::PaymentsResponseData,
        >,
    > for PaytmAuthorizeRouterData
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &domain_types::router_data_v2::RouterDataV2<
            domain_types::connector_flow::Authorize,
            domain_types::connector_types::PaymentFlowData,
            domain_types::connector_types::PaymentsAuthorizeData,
            domain_types::connector_types::PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let amount_minor_units = item.request.amount;
        let customer_id = item
            .resource_common_data
            .get_customer_id()
            .ok()
            .map(|id| id.get_string_repr().to_string());
        let email = item
            .resource_common_data
            .get_optional_billing_email()
            .map(|e| e.peek().to_string());
        let phone = item
            .resource_common_data
            .get_optional_billing_phone_number()
            .map(|p| p.peek().to_string());
        let first_name = item
            .resource_common_data
            .get_optional_billing_first_name()
            .map(|name| name.peek().to_string());
        let last_name = item
            .resource_common_data
            .get_optional_billing_last_name()
            .map(|name| name.peek().to_string());
        // Extract session token from previous session token response
        let session_token = item
            .resource_common_data
            .get_session_token()
            .ok()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "session_token",
            })?
            .clone();

        Ok(Self {
            amount: amount_minor_units,
            currency: item.request.currency.to_string(),
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
            return_url: item.resource_common_data.return_url.clone(),
        })
    }
}

// Request transformation for PayTM UPI Intent flow (ProcessTxnRequest)
impl PaytmProcessTxnRequest {
    pub fn try_from_with_auth(
        item: &PaytmAuthorizeRouterData,
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
            payment_mode: "UPI_INTENT".to_string(), // UPI Intent flow
            payment_flow: Some(constants::PAYMENT_FLOW_NONE.to_string()),
        };

        Ok(Self { head, body })
    }
}

// Note: Use PaytmProcessTxnRequest::try_from_with_auth for production code
// This implementation is deprecated and should not be used

// Request transformation for PayTM UPI Collect flow (NativeProcessTxnRequest)
impl PaytmNativeProcessTxnRequest {
    pub fn try_from_with_auth(
        item: &PaytmAuthorizeRouterData,
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

// Note: Use PaytmNativeProcessTxnRequest::try_from_with_auth for production code
// This implementation is deprecated and should not be used

// UPI QR Code Flow Request/Response Structures

// #[derive(Debug, Serialize)]
// pub struct PaytmQRRequest {
//     pub head: PaytmRequestHeader,
//     pub body: PaytmQRRequestPayload,
// }

// #[derive(Debug, Serialize)]
// pub struct PaytmQRRequestPayload {
//     pub mid: String,                                    // Merchant ID
//     #[serde(rename = "businessType")]
//     pub business_type: String,                          // "UPI_QR_CODE"
//     #[serde(rename = "orderId")]
//     pub order_id: String,                               // Transaction reference
//     pub amount: String,                                 // Amount as string
//     #[serde(rename = "posId")]
//     pub pos_id: String,                                 // POS identifier
//     #[serde(rename = "imageRequired")]
//     pub image_required: Option<bool>,                   // QR image generation flag
// }

// impl PaytmQRRequest {
//     pub fn try_from_with_auth(
//         item: &PaytmAuthorizeRouterData,
//         auth: &PaytmAuthType,
//     ) -> CustomResult<Self, errors::ConnectorError> {
//         let unix_timestamp = SystemTime::now()
//             .duration_since(UNIX_EPOCH)
//             .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?
//             .as_secs()
//             .to_string();

//         let body = PaytmQRRequestPayload {
//             mid: auth.merchant_id.peek().clone(),
//             business_type: "UPI_QR_CODE".to_string(),
//             order_id: item.payment_id.clone(),
//             amount: item.amount.to_string(),
//             pos_id: format!("POS_{}", item.payment_id), // Generate POS ID from payment ID
//             image_required: Some(true), // Request QR image
//         };

//         let body_json = serde_json::to_string(&body)
//             .change_context(errors::ConnectorError::RequestEncodingFailed)?;

//         let signature = generate_paytm_signature(&body_json, auth.merchant_key.peek())?;

//         let head = PaytmRequestHeader {
//             client_id: None, // PayTM QR doesn't require client_id
//             version: constants::API_VERSION.to_string(),
//             request_timestamp: unix_timestamp,
//             channel_id: auth.channel_id.clone(),
//             signature,
//         };

//         Ok(Self { head, body })
//     }
// }

// #[derive(Debug, Deserialize, Serialize)]
// pub struct PaytmQRResponse {
//     pub head: PaytmRespHead,
//     pub body: PaytmQRRespBodyTypes,
// }

// #[derive(Debug, Deserialize, Serialize)]
// #[serde(untagged)]
// pub enum PaytmQRRespBodyTypes {
//     SuccessBody(PaytmQRResponsePayload),
//     FailureBody(PaytmQRErrorResponse),
// }

// #[derive(Debug, Deserialize, Serialize)]
// pub struct PaytmQRResponsePayload {
//     #[serde(rename = "qrCodeId")]
//     pub qr_code_id: String,                             // QR code identifier
//     #[serde(rename = "qrData")]
//     pub qr_data: String,                                // QR code data string
//     pub image: Option<String>,                          // Base64 encoded QR image
//     #[serde(rename = "resultInfo")]
//     pub result_info: PaytmResultInfo,               // Result information
// }

// #[derive(Debug, Deserialize, Serialize)]
// pub struct PaytmQRErrorResponse {
//     #[serde(rename = "resultInfo")]
//     pub result_info: PaytmResultInfo,
//     #[serde(rename = "errorCode")]
//     pub error_code: Option<String>,
//     #[serde(rename = "errorMessage")]
//     pub error_message: Option<String>,
// }

// // QR-specific success code constant
// impl PaytmQRResponsePayload {
//     pub fn is_successful(&self) -> bool {
//         self.result_info.result_code == constants::QR_SUCCESS_CODE
//     }
// }

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
    SuccessBody(PaytmTransactionStatusRespBody),
    FailureBody(PaytmErrorBody),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytmTransactionStatusRespBody {
    pub result_info: PaytmResultInfo,
    pub txn_id: Option<String>,
    pub bank_txn_id: Option<String>,
    pub order_id: Option<String>,
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
        Ok(Self {
            payment_id: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            connector_transaction_id: item
                .request
                .connector_transaction_id
                .get_connector_transaction_id()
                .ok(),
            txn_type: None, // Can be enhanced later to support specific transaction types
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
        constants::TXN_SUCCESS_CODE => AttemptStatus::Charged,

        // Failure cases
        constants::TXN_FAILURE_CODE
        | constants::WALLET_INSUFFICIENT_CODE
        | constants::INVALID_UPI_CODE
        | constants::BANK_DECLINED_CODE
        | constants::TXN_FAILED_CODE
        | constants::ACCOUNT_BLOCKED_CODE
        | constants::MOBILE_CHANGED_CODE
        | constants::MANDATE_GAP_CODE
        | constants::INVALID_ORDER_ID_CODE
        | constants::INVALID_MID_CODE
        | constants::SERVER_DOWN_CODE => AttemptStatus::Failure,

        // Pending cases
        constants::PENDING_CODE
        | constants::PENDING_BANK_CONFIRM_CODE
        | constants::NO_RECORD_FOUND_CODE => AttemptStatus::Pending,

        // Default to failure for unknown codes
        _ => AttemptStatus::Failure,
    }
}

// Response transformation implementations completed - all structs properly defined
use std::time::{SystemTime, UNIX_EPOCH};

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

    // Response codes
    pub const SUCCESS_CODE: &str = "0000";
    pub const DUPLICATE_CODE: &str = "0002";

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
use common_enums::Currency;
use common_utils::{
    errors::CustomResult,
    types::{AmountConvertor, MinorUnit, StringMajorUnit},
};
use domain_types::{
    errors,
    payment_method_data::{PaymentMethodData, UpiData},
    router_data::ConnectorAuthType,
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};

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

pub fn determine_upi_flow(
    payment_method_data: &PaymentMethodData,
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
                UpiData::UpiIntent(_) => Ok(UpiFlowType::Intent),
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
    pub value: String,    // Decimal amount (e.g., "10.50")
    pub currency: String, // "INR"
}

#[derive(Debug, Serialize)]
pub struct PaytmUserInfo {
    #[serde(rename = "custId")]
    pub cust_id: String,
    pub mobile: Option<String>,
    pub email: Option<String>,
    #[serde(rename = "firstName")]
    pub first_name: Option<String>,
    #[serde(rename = "lastName")]
    pub last_name: Option<String>,
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

// Authorize flow request structures

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
    SuccessBody(PaytmProcessSuccessResp),
    FailureBody(PaytmProcessFailureResp),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaytmProcessSuccessResp {
    #[serde(rename = "resultInfo")]
    pub result_info: PaytmResultInfo,
    #[serde(rename = "deepLinkInfo")]
    pub deep_link_info: PaytmDeepLinkInfo,
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
pub fn extract_upi_vpa(
    payment_method_data: &PaymentMethodData,
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
    let salt_b64 = general_purpose::STANDARD.encode(&salt_bytes);

    // Step 3: Create hash input: payload + "|" + base64_salt (same logic)
    let hash_input = format!("{}|{}", payload, salt_b64);

    // Step 4: SHA-256 hash using ring (same logic, different implementation)
    let hash_digest = digest::digest(&digest::SHA256, hash_input.as_bytes());
    let sha256_hash = hex::encode(hash_digest.as_ref());

    // Step 5: Create checksum: sha256_hash + base64_salt (same logic)
    let checksum = format!("{}{}", sha256_hash, salt_b64);

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
            let copy_len = std::cmp::min(key_bytes.len(), constants::AES_256_KEY_LENGTH);
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
    pub amount: i64,
    pub currency: Currency,
    pub payment_id: String,
    pub customer_id: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub return_url: Option<String>,
}

// Helper struct for Authorize flow RouterData transformation
#[derive(Debug, Clone)]
pub struct PaytmAuthorizeRouterData {
    pub amount: i64,
    pub currency: String,
    pub payment_id: String,
    pub session_token: String,
    pub payment_method_data: PaymentMethodData,
    pub customer_id: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub return_url: Option<String>,
}

// Request transformation for CreateSessionToken flow
impl
    TryFrom<
        &domain_types::router_data_v2::RouterDataV2<
            domain_types::connector_flow::CreateSessionToken,
            domain_types::connector_types::PaymentFlowData,
            domain_types::connector_types::SessionTokenRequestData,
            domain_types::connector_types::SessionTokenResponseData,
        >,
    > for PaytmRouterData
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &domain_types::router_data_v2::RouterDataV2<
            domain_types::connector_flow::CreateSessionToken,
            domain_types::connector_types::PaymentFlowData,
            domain_types::connector_types::SessionTokenRequestData,
            domain_types::connector_types::SessionTokenResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let amount_minor_units = item.request.amount.get_amount_as_i64();
        let customer_id = item
            .resource_common_data
            .get_customer_id()
            .ok()
            .map(|id| id.get_string_repr().to_string());
        let email = item
            .resource_common_data
            .get_optional_billing_email()
            .map(|e| e.peek().to_string());
        let phone = item
            .resource_common_data
            .get_optional_billing_phone_number()
            .map(|p| p.peek().to_string());
        let first_name = item
            .resource_common_data
            .get_optional_billing_first_name()
            .map(|name| name.peek().to_string());
        let last_name = item
            .resource_common_data
            .get_optional_billing_last_name()
            .map(|name| name.peek().to_string());

        Ok(Self {
            amount: amount_minor_units,
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
            return_url: item.resource_common_data.return_url.clone(),
        })
    }
}

// Request body transformation for PayTM initiate transaction
impl PaytmInitiateTxnRequest {
    pub fn try_from_with_auth(
        item: &PaytmRouterData,
        auth: &PaytmAuthType,
        amount_converter: &dyn AmountConvertor<Output = StringMajorUnit>,
    ) -> CustomResult<Self, errors::ConnectorError> {
        let amount_value = amount_converter
            .convert(MinorUnit::new(item.amount), item.currency.clone())
            .change_context(errors::ConnectorError::AmountConversionFailed)?;
        let body = PaytmInitiateReqBody {
            request_type: constants::REQUEST_TYPE_PAYMENT.to_string(),
            mid: auth.merchant_id.peek().to_string(),
            order_id: item.payment_id.clone(),
            website_name: auth.website.peek().to_string(),
            txn_amount: PaytmAmount {
                value: amount_value.get_amount_as_string(),
                currency: item.currency.to_string(),
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
                channels: Some(vec![constants::UPI_CHANNEL_UPIPUSH.to_string()]),
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

// Note: Use PaytmInitiateTxnRequest::try_from_with_auth for production code
// This implementation is deprecated and should not be used

// Request transformation for Authorize flow
impl
    TryFrom<
        &domain_types::router_data_v2::RouterDataV2<
            domain_types::connector_flow::Authorize,
            domain_types::connector_types::PaymentFlowData,
            domain_types::connector_types::PaymentsAuthorizeData,
            domain_types::connector_types::PaymentsResponseData,
        >,
    > for PaytmAuthorizeRouterData
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &domain_types::router_data_v2::RouterDataV2<
            domain_types::connector_flow::Authorize,
            domain_types::connector_types::PaymentFlowData,
            domain_types::connector_types::PaymentsAuthorizeData,
            domain_types::connector_types::PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let amount_minor_units = item.request.amount;
        let customer_id = item
            .resource_common_data
            .get_customer_id()
            .ok()
            .map(|id| id.get_string_repr().to_string());
        let email = item
            .resource_common_data
            .get_optional_billing_email()
            .map(|e| e.peek().to_string());
        let phone = item
            .resource_common_data
            .get_optional_billing_phone_number()
            .map(|p| p.peek().to_string());
        let first_name = item
            .resource_common_data
            .get_optional_billing_first_name()
            .map(|name| name.peek().to_string());
        let last_name = item
            .resource_common_data
            .get_optional_billing_last_name()
            .map(|name| name.peek().to_string());

        // Extract session token from previous session token response
        let session_token = item
            .request
            .session_token
            .as_ref()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "session_token",
            })?
            .clone();

        Ok(Self {
            amount: amount_minor_units,
            currency: item.request.currency.to_string(),
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
            return_url: item.resource_common_data.return_url.clone(),
        })
    }
}

// Request transformation for PayTM UPI Intent flow (ProcessTxnRequest)
impl PaytmProcessTxnRequest {
    pub fn try_from_with_auth(
        item: &PaytmAuthorizeRouterData,
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
            payment_mode: "UPI_INTENT".to_string(), // UPI Intent flow
            payment_flow: Some(constants::PAYMENT_FLOW_NONE.to_string()),
        };

        Ok(Self { head, body })
    }
}

// Note: Use PaytmProcessTxnRequest::try_from_with_auth for production code
// This implementation is deprecated and should not be used

// Request transformation for PayTM UPI Collect flow (NativeProcessTxnRequest)
impl PaytmNativeProcessTxnRequest {
    pub fn try_from_with_auth(
        item: &PaytmAuthorizeRouterData,
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

// Note: Use PaytmNativeProcessTxnRequest::try_from_with_auth for production code
// This implementation is deprecated and should not be used

// UPI QR Code Flow Request/Response Structures

// #[derive(Debug, Serialize)]
// pub struct PaytmQRRequest {
//     pub head: PaytmRequestHeader,
//     pub body: PaytmQRRequestPayload,
// }

// #[derive(Debug, Serialize)]
// pub struct PaytmQRRequestPayload {
//     pub mid: String,                                    // Merchant ID
//     #[serde(rename = "businessType")]
//     pub business_type: String,                          // "UPI_QR_CODE"
//     #[serde(rename = "orderId")]
//     pub order_id: String,                               // Transaction reference
//     pub amount: String,                                 // Amount as string
//     #[serde(rename = "posId")]
//     pub pos_id: String,                                 // POS identifier
//     #[serde(rename = "imageRequired")]
//     pub image_required: Option<bool>,                   // QR image generation flag
// }

// impl PaytmQRRequest {
//     pub fn try_from_with_auth(
//         item: &PaytmAuthorizeRouterData,
//         auth: &PaytmAuthType,
//     ) -> CustomResult<Self, errors::ConnectorError> {
//         let unix_timestamp = SystemTime::now()
//             .duration_since(UNIX_EPOCH)
//             .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?
//             .as_secs()
//             .to_string();

//         let body = PaytmQRRequestPayload {
//             mid: auth.merchant_id.peek().clone(),
//             business_type: "UPI_QR_CODE".to_string(),
//             order_id: item.payment_id.clone(),
//             amount: item.amount.to_string(),
//             pos_id: format!("POS_{}", item.payment_id), // Generate POS ID from payment ID
//             image_required: Some(true), // Request QR image
//         };

//         let body_json = serde_json::to_string(&body)
//             .change_context(errors::ConnectorError::RequestEncodingFailed)?;

//         let signature = generate_paytm_signature(&body_json, auth.merchant_key.peek())?;

//         let head = PaytmRequestHeader {
//             client_id: None, // PayTM QR doesn't require client_id
//             version: constants::API_VERSION.to_string(),
//             request_timestamp: unix_timestamp,
//             channel_id: auth.channel_id.clone(),
//             signature,
//         };

//         Ok(Self { head, body })
//     }
// }

// #[derive(Debug, Deserialize, Serialize)]
// pub struct PaytmQRResponse {
//     pub head: PaytmRespHead,
//     pub body: PaytmQRRespBodyTypes,
// }

// #[derive(Debug, Deserialize, Serialize)]
// #[serde(untagged)]
// pub enum PaytmQRRespBodyTypes {
//     SuccessBody(PaytmQRResponsePayload),
//     FailureBody(PaytmQRErrorResponse),
// }

// #[derive(Debug, Deserialize, Serialize)]
// pub struct PaytmQRResponsePayload {
//     #[serde(rename = "qrCodeId")]
//     pub qr_code_id: String,                             // QR code identifier
//     #[serde(rename = "qrData")]
//     pub qr_data: String,                                // QR code data string
//     pub image: Option<String>,                          // Base64 encoded QR image
//     #[serde(rename = "resultInfo")]
//     pub result_info: PaytmResultInfo,               // Result information
// }

// #[derive(Debug, Deserialize, Serialize)]
// pub struct PaytmQRErrorResponse {
//     #[serde(rename = "resultInfo")]
//     pub result_info: PaytmResultInfo,
//     #[serde(rename = "errorCode")]
//     pub error_code: Option<String>,
//     #[serde(rename = "errorMessage")]
//     pub error_message: Option<String>,
// }

// // QR-specific success code constant
// impl PaytmQRResponsePayload {
//     pub fn is_successful(&self) -> bool {
//         self.result_info.result_code == constants::QR_SUCCESS_CODE
//     }
// }

// Response transformation implementations completed - all structs properly defined
