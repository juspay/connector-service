// Billdesk API endpoints based on Haskell implementation
pub const SANDBOX_BASE_URL: &str = "https://uat.billdesk.com";
pub const LIVE_BASE_URL: &str = "https://www.billdesk.com";

// UPI specific endpoints
pub const UPI_INITIATE_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF007";
pub const AUTHORIZATION_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF002";
pub const STATUS_SYNC_ENDPOINT: &str = "/pgidsk/PGIQueryController";

// V2 API endpoints for newer flows
pub const V2_SANDBOX_BASE_URL: &str = "https://uat1.billdesk.com";
pub const V2_LIVE_BASE_URL: &str = "https://api.billdesk.com";
pub const V2_PAYMENT_BASE_PATH: &str = "/payments/ve1_2";
pub const V2_PGSI_BASE_PATH: &str = "/pgsi/ve1_2";

// V2 specific endpoints
pub const V2_CREATE_TXN_ENDPOINT: &str = "/transactions/create";
pub const V2_UPDATE_TXN_ENDPOINT: &str = "/transactions/update";
pub const V2_RETRIEVE_TXN_ENDPOINT: &str = "/transactions/get";
pub const V2_VERIFY_VPA_ENDPOINT: &str = "/upi/validatevpa";

// Helper functions to get complete URLs
pub fn get_authorize_endpoint(is_sandbox: bool) -> String {
    let base_url = if is_sandbox { SANDBOX_BASE_URL } else { LIVE_BASE_URL };
    format!("{}{}", base_url, UPI_INITIATE_ENDPOINT)
}

pub fn get_sync_endpoint(is_sandbox: bool) -> String {
    let base_url = if is_sandbox { SANDBOX_BASE_URL } else { LIVE_BASE_URL };
    format!("{}{}", base_url, STATUS_SYNC_ENDPOINT)
}

pub fn get_v2_payment_endpoint(endpoint: &str, is_sandbox: bool) -> String {
    let base_url = if is_sandbox { V2_SANDBOX_BASE_URL } else { V2_LIVE_BASE_URL };
    format!("{}{}{}", base_url, V2_PAYMENT_BASE_PATH, endpoint)
}

pub fn get_v2_pgsi_endpoint(endpoint: &str, is_sandbox: bool) -> String {
    let base_url = if is_sandbox { V2_SANDBOX_BASE_URL } else { V2_LIVE_BASE_URL };
    format!("{}{}{}", base_url, V2_PGSI_BASE_PATH, endpoint)
}

// API tags for different flows
pub fn get_api_tag(flow_name: &str) -> &'static str {
    match flow_name {
        "Authorize" => "billdesk_upi_authorize",
        "PSync" => "billdesk_payment_sync", 
        "RSync" => "billdesk_refund_sync",
        "Refund" => "billdesk_refund",
        "Capture" => "billdesk_capture",
        "Void" => "billdesk_void",
        "CreateOrder" => "billdesk_create_order",
        "SessionToken" => "billdesk_session_token",
        "SetupMandate" => "billdesk_setup_mandate",
        "RepeatPayment" => "billdesk_repeat_payment",
        _ => "billdesk_unknown",
    }
}

// Billdesk specific constants
pub const MERCHANT_ID_FIELD: &str = "mercid";
pub const CHECKSUM_FIELD: &str = "checksum";
pub const UPI_BANK_ID: &str = "UPI";
pub const UPI_TXN_TYPE: &str = "01";
pub const DIRECT_ITEM_CODE: &str = "DIRECT";

// Status codes mapping from Haskell implementation
pub const AUTH_STATUS_SUCCESS: &str = "0300";
pub const AUTH_STATUS_PENDING: &str = "0002";
pub const AUTH_STATUS_AUTHENTICATION_PENDING: &str = "0001";
pub const ERROR_STATUS_SUCCESS: &str = "0";

// Request types for different operations
pub const REQUEST_TYPE_STATUS_INQUIRY: &str = "0122";
pub const REQUEST_TYPE_REFUND: &str = "0400";
pub const REQUEST_TYPE_REFUND_STATUS: &str = "0420";

// Currency and amount constants
pub const DEFAULT_CURRENCY: &str = "INR";
pub const MINOR_UNIT_MULTIPLIER: i64 = 100;

// Timeout constants
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;
pub const LONG_TIMEOUT_SECS: u64 = 60;

// Headers
pub mod headers {
    pub const AUTHORIZATION: &str = "Authorization";
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const ACCEPT: &str = "Accept";
    pub const USER_AGENT: &str = "User-Agent";
    pub const BD_TIMESTAMP: &str = "BD-Timestamp";
    pub const BD_TRACEID: &str = "BD-Traceid";
}

// Error codes from Billdesk
pub mod error_codes {
    pub const INVALID_REQUEST: &str = "E001";
    pub const AUTHENTICATION_FAILED: &str = "E002";
    pub const INSUFFICIENT_FUNDS: &str = "E003";
    pub const TRANSACTION_DECLINED: &str = "E004";
    pub const INVALID_MERCHANT: &str = "E005";
    pub const SYSTEM_ERROR: &str = "E999";
}

// UPI specific constants
pub mod upi {
    pub const VPA_REGEX: &str = r"^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+$";
    pub const MAX_VPA_LENGTH: usize = 50;
    pub const MIN_VPA_LENGTH: usize = 3;
    pub const UPI_INTENT_TIMEOUT_MINS: u32 = 5;
    pub const UPI_COLLECT_TIMEOUT_MINS: u32 = 10;
}

// Test data for sandbox environment
pub mod test_data {
    pub const TEST_MERCHANT_ID: &str = "TESTMERCHANT";
    pub const TEST_CUSTOMER_ID: &str = "TESTCUSTOMER";
    pub const TEST_UPI_VPA: &str = "test@upi";
    pub const TEST_AMOUNT: &str = "100";
    pub const TEST_CURRENCY: &str = "INR";
}