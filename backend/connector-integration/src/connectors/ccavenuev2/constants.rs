use std::collections::HashMap;

use common_enums::Currency;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CcavenueV2Connector {
    pub base_url: String,
    pub auth: HashMap<Currency, CcavenueV2Auth>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CcavenueV2Auth {
    pub merchant_id: String,
    pub access_code: String,
    pub working_key: String,
}

/// Get the appropriate endpoint URL based on request type and test mode
/// This mirrors the Haskell getEndpointForReq function
pub fn get_endpoint_for_req(request_type: &str, is_test: bool) -> String {
    match (request_type, is_test) {
        ("CcAvenueTransactionRequest", true) => "https://test.ccavenue.com/transaction/transaction.do".to_string(),
        ("CcAvenueTransactionRequest", false) => "https://secure.ccavenue.com/transaction/transaction.do".to_string(),
        ("CcAvenueStatusRequest", true) => "https://apitest.ccavenue.com/apis/servlet/DoWebTrans".to_string(),
        ("CcAvenueStatusRequest", false) => "https://api.ccavenue.com/apis/servlet/DoWebTrans".to_string(),
        ("CcAvenueRefundStatusRequest", true) => "https://apitest.ccavenue.com/apis/servlet/DoWebTrans".to_string(),
        ("CcAvenueRefundStatusRequest", false) => "https://api.ccavenue.com/apis/servlet/DoWebTrans".to_string(),
        ("CcAvenueMultiCurrencyTransactionRequest", true) => "https://test.ccavenue.com/transaction/transaction.do".to_string(),
        ("CcAvenueMultiCurrencyTransactionRequest", false) => "https://secure.ccavenue.ae/transaction/transaction.do".to_string(),
        ("CcAvenueQueryAndRefundRequest", true) => "https://apitest.ccavenue.com/apis/servlet/DoWebTrans".to_string(),
        ("CcAvenueQueryAndRefundRequest", false) => "https://api.ccavenue.com/apis/servlet/DoWebTrans".to_string(),
        ("CcAvenueQueryAndRefundMultiCurrencyRequest", true) => "https://apitest.ccavenue.com/apis/servlet/DoWebTrans".to_string(),
        ("CcAvenueQueryAndRefundMultiCurrencyRequest", false) => "https://login.ccavenue.ae/apis/servlet/DoWebTrans".to_string(),
        ("CcAvenueVerifyVpaRequest", true) => "https://apitest.ccavenue.com/apis/servlet/DoWebTrans".to_string(),
        ("CcAvenueVerifyVpaRequest", false) => "https://api.ccavenue.com/apis/servlet/DoWebTrans".to_string(),
        ("CcAvenueSARCurrencyPayloadTransactionRequest", true) => "https://secure.ccavenue.sa/transaction/transaction.do?command=initiatePayloadTransaction".to_string(),
        ("CcAvenueSARCurrencyPayloadTransactionRequest", false) => "https://secure.ccavenue.sa/transaction/transaction.do?command=initiatePayloadTransaction".to_string(),
        ("CcAvenueSARCurrencyNotS2STransactionRequest", true) => "https://secure.ccavenue.sa/transaction/transaction.do?command=initiateTransaction".to_string(),
        ("CcAvenueSARCurrencyNotS2STransactionRequest", false) => "https://secure.ccavenue.sa/transaction/transaction.do?command=initiateTransaction".to_string(),
        ("CcAvenueSARCurrencyQueryAndRefundRequest", true) => "https://login.ccavenue.sa/apis/servlet/DoWebTrans".to_string(),
        ("CcAvenueSARCurrencyQueryAndRefundRequest", false) => "https://login.ccavenue.sa/apis/servlet/DoWebTrans".to_string(),
        ("CcavenueSiRequest", true) => "https://api.ccavenue.com/apis/servlet/DoWebTrans".to_string(),
        ("CcavenueSiRequest", false) => "https://api.ccavenue.com/apis/servlet/DoWebTrans".to_string(),
        ("CcAvenueDCEmiEligibilityCheck", true) => "https://apitest.ccavenue.com/apis/servlet/DoWebTrans".to_string(),
        ("CcAvenueDCEmiEligibilityCheck", false) => "https://api.ccavenue.com/apis/servlet/DoWebTrans".to_string(),
        _ => "".to_string(),
    }
}

/// Supported payment methods for CCAvenue V2
pub const SUPPORTED_PAYMENT_METHODS: &[&str] = &[
    "upi",
    "upi_qr",
    "upi_intent",
    "upi_collect",
];

/// Default currency for CCAvenue V2
pub const DEFAULT_CURRENCY: &str = "INR";

/// Command types for different operations
pub const COMMAND_INITIATE_TRANSACTION: &str = "initiateTransaction";
pub const COMMAND_ORDER_STATUS_TRACKER: &str = "orderStatusTracker";
pub const COMMAND_VERIFY_VPA: &str = "verifyVPA";

/// Request types
pub const REQUEST_TYPE_JSON: &str = "JSON";
pub const RESPONSE_TYPE_JSON: &str = "JSON";

/// API version
pub const API_VERSION: &str = "1.1";

/// Encryption algorithm (placeholder - should match CCAvenue's actual algorithm)
pub const ENCRYPTION_ALGORITHM: &str = "AES-256-CBC";

/// Default timeout for API requests in seconds
pub const DEFAULT_TIMEOUT_SECONDS: u64 = 30;

/// Maximum retry attempts for failed requests
pub const MAX_RETRY_ATTEMPTS: u32 = 3;

/// Headers
pub const HEADER_CONTENT_TYPE: &str = "Content-Type";
pub const HEADER_ACCEPT: &str = "Accept";
pub const HEADER_AUTHORIZATION: &str = "Authorization";

/// Content types
pub const CONTENT_TYPE_JSON: &str = "application/json";
pub const CONTENT_TYPE_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";

/// Error codes
pub const ERROR_CODE_INVALID_REQUEST: i32 = 1001;
pub const ERROR_CODE_AUTHENTICATION_FAILED: i32 = 1002;
pub const ERROR_CODE_INVALID_MERCHANT: i32 = 1003;
pub const ERROR_CODE_INVALID_ORDER: i32 = 1004;
pub const ERROR_CODE_INVALID_CURRENCY: i32 = 1005;
pub const ERROR_CODE_INVALID_AMOUNT: i32 = 1006;
pub const ERROR_CODE_TRANSACTION_FAILED: i32 = 1007;
pub const ERROR_CODE_ORDER_NOT_FOUND: i32 = 1008;
pub const ERROR_CODE_INVALID_ACCESS_CODE: i32 = 1009;
pub const ERROR_CODE_INVALID_WORKING_KEY: i32 = 1010;

/// Status codes from CCAvenue
pub const STATUS_SUCCESS: &str = "Success";
pub const STATUS_FAILURE: &str = "Failure";
pub const STATUS_PENDING: &str = "Pending";
pub const STATUS_ABORTED: &str = "Aborted";
pub const STATUS_INVALID: &str = "Invalid";

/// UPI specific constants
pub const UPI_INTENT_FLOW: &str = "upi_intent";
pub const UPI_COLLECT_FLOW: &str = "upi_collect";
pub const UPI_QR_FLOW: &str = "upi_qr";

/// Response field names
pub const FIELD_ENC_RESP: &str = "enc_resp";
pub const FIELD_ORDER_ID: &str = "order_id";
pub const FIELD_STATUS: &str = "status";
pub const FIELD_MESSAGE: &str = "message";
pub const FIELD_TRACKING_ID: &str = "tracking_id";
pub const FIELD_BANK_REF_NO: &str = "bank_ref_no";
pub const FIELD_ORDER_STATUS: &str = "order_status";
pub const FIELD_FAILURE_MESSAGE: &str = "failure_message";
pub const FIELD_PAYMENT_MODE: &str = "payment_mode";
pub const FIELD_CARD_NAME: &str = "card_name";
pub const FIELD_STATUS_CODE: &str = "status_code";
pub const FIELD_STATUS_MESSAGE: &str = "status_message";

/// Request field names
pub const FIELD_ENC_REQUEST: &str = "enc_request";
pub const FIELD_ACCESS_CODE: &str = "access_code";
pub const FIELD_COMMAND: &str = "command";
pub const FIELD_REQUEST_TYPE: &str = "request_type";
pub const FIELD_RESPONSE_TYPE: &str = "response_type";
pub const FIELD_VERSION: &str = "version";
pub const FIELD_ORDER_NO: &str = "order_no";
pub const FIELD_CURRENCY: &str = "currency";
pub const FIELD_AMOUNT: &str = "amount";
pub const FIELD_REDIRECT_URL: &str = "redirect_url";
pub const FIELD_CANCEL_URL: &str = "cancel_url";
pub const FIELD_MERCHANT_ID: &str = "merchant_id";
pub const FIELD_CUSTOMER_ID: &str = "customer_id";
pub const FIELD_CUSTOMER_EMAIL: &str = "customer_email";
pub const FIELD_CUSTOMER_PHONE: &str = "customer_phone";

/// Webhook related constants
pub const WEBHOOK_SIGNATURE_HEADER: &str = "X-CCAVENUE-SIGNATURE";
pub const WEBHOOK_TIMESTAMP_HEADER: &str = "X-CCAVENUE-TIMESTAMP";

/// Mandate related constants
pub const MANDATE_TYPE_UPI: &str = "upi";
pub const MANDATE_STATUS_ACTIVE: &str = "active";
pub const MANDATE_STATUS_REVOKED: &str = "revoked";
pub const MANDATE_STATUS_PAUSED: &str = "paused";

/// Refund related constants
pub const REFUND_STATUS_SUCCESS: &str = "SUCCESS";
pub const REFUND_STATUS_PENDING: &str = "PENDING";
pub const REFUND_STATUS_FAILURE: &str = "FAILURE";
pub const REFUND_STATUS_CANCELLED: &str = "CANCELLED";