// ================================================================================================
// EaseBuzz API Endpoints
// ================================================================================================

// Payment API Endpoints
pub const INITIATE_PAYMENT_ENDPOINT: &str = "/payment/initiateLink";
pub const SEAMLESS_PAYMENT_ENDPOINT: &str = "/initiate_seamless_payment/";
pub const TRANSACTION_SYNC_ENDPOINT: &str = "/transaction/v1/retrieve";

// Refund API Endpoints  
pub const REFUND_ENDPOINT: &str = "/transaction/v2/refund";
pub const REFUND_SYNC_ENDPOINT: &str = "/refund/v1/retrieve";

// UPI Specific Endpoints
pub const UPI_INTENT_ENDPOINT: &str = "/initiate_seamless_payment/";
pub const UPI_COLLECT_ENDPOINT: &str = "/initiate_seamless_payment/";

// Mandate/Recurring Payment Endpoints (for future implementation)
pub const GENERATE_ACCESS_KEY_ENDPOINT: &str = "/autocollect/v1/access-key/generate/";
pub const MANDATE_CREATION_ENDPOINT: &str = "/autocollect/v1/mandate/";
pub const MANDATE_RETRIEVE_ENDPOINT: &str = "/autocollect/v1/mandate/:txnId/";
pub const PRESENTMENT_REQUEST_ENDPOINT: &str = "/autocollect/v1/mandate/presentment/";
pub const DEBIT_REQUEST_RETRIEVE_ENDPOINT: &str = "/autocollect/v1/mandate/presentment/:txnId/";
pub const UPI_AUTOPAY_ENDPOINT: &str = "/autocollect/v1/mandate/process/";
pub const NOTIFICATION_REQUEST_ENDPOINT: &str = "/autocollect/v1/mandate/notify/";
pub const UPI_MANDATE_EXECUTE_ENDPOINT: &str = "/autocollect/v1/mandate/execute/";
pub const REVOKE_MANDATE_ENDPOINT: &str = "/autocollect/v1/mandate/:mandateId/status_update/";
pub const MANDATE_NOTIFICATION_SYNC_ENDPOINT: &str = "/autocollect/v1/mandate/notification/:notificationReqId/";

// EMI Endpoints (for future implementation)
pub const GET_EMI_OPTIONS_ENDPOINT: &str = "/v1/getEMIOptions";
pub const GET_EMI_PLANS_ENDPOINT: &str = "/emi/v1/retrieve";

// Settlement Endpoints (for future implementation)
pub const DELAYED_SETTLEMENT_ENDPOINT: &str = "/settlements/v1/ondemand/initiate/";
pub const DELAYED_SETTLEMENT_STATUS_ENDPOINT: &str = "/settlements/v1/ondemand/status/";

// Authorization Endpoints (for future implementation)
pub const AUTHORIZATION_REQUEST_ENDPOINT: &str = "/payment/v1/capture/direct";

// ================================================================================================
// Base URLs
// ================================================================================================

// Production URLs
pub const PRODUCTION_BASE_URL: &str = "https://pay.easebuzz.in";
pub const PRODUCTION_DASHBOARD_URL: &str = "https://dashboard.easebuzz.in";
pub const PRODUCTION_API_URL: &str = "https://api.easebuzz.in";

// Sandbox URLs  
pub const SANDBOX_BASE_URL: &str = "https://testpay.easebuzz.in";
pub const SANDBOX_DASHBOARD_URL: &str = "https://testdashboard.easebuzz.in";
pub const SANDBOX_API_URL: &str = "https://sandboxapi.easebuzz.in";

// ================================================================================================
// Payment Method Constants
// ================================================================================================

pub const UPI_PAYMENT_METHOD: &str = "UPI";
pub const CARD_PAYMENT_METHOD: &str = "CARD";
pub const NET_BANKING_PAYMENT_METHOD: &str = "NB";
pub const WALLET_PAYMENT_METHOD: &str = "WALLET";

// UPI Flow Types
pub const UPI_COLLECT_FLOW: &str = "COLLECT";
pub const UPI_INTENT_FLOW: &str = "INTENT";

// ================================================================================================
// Request/Response Constants
// ================================================================================================

// Default Values
pub const DEFAULT_PRODUCT_INFO: &str = "Payment";
pub const DEFAULT_AUTO_REDIRECT: &str = "1";
pub const DEFAULT_SMS_PERMISSION: &str = "1";

// Hash Algorithm
pub const HASH_ALGORITHM: &str = "SHA512";

// Status Values
pub const SUCCESS_STATUS: &str = "success";
pub const FAILURE_STATUS: &str = "failure";
pub const PENDING_STATUS: &str = "pending";

// Payment Modes
pub const UPI_PAYMENT_MODE: &str = "UPI";
pub const CARD_PAYMENT_MODE: &str = "CC";
pub const DEBIT_CARD_PAYMENT_MODE: &str = "DC";
pub const NET_BANKING_PAYMENT_MODE: &str = "NB";
pub const WALLET_PAYMENT_MODE: &str = "WALLET";

// ================================================================================================
// Error Constants
// ================================================================================================

pub const INVALID_HASH_ERROR: &str = "Invalid hash";
pub const INVALID_MERCHANT_ERROR: &str = "Invalid merchant";
pub const TRANSACTION_NOT_FOUND_ERROR: &str = "Transaction not found";
pub const INSUFFICIENT_BALANCE_ERROR: &str = "Insufficient balance";
pub const PAYMENT_DECLINED_ERROR: &str = "Payment declined";
pub const NETWORK_ERROR: &str = "Network error";

// ================================================================================================
// Timeout Constants
// ================================================================================================

pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;
pub const PAYMENT_TIMEOUT_SECS: u64 = 60;
pub const SYNC_TIMEOUT_SECS: u64 = 15;

// ================================================================================================
// Field Length Limits
// ================================================================================================

pub const MAX_TRANSACTION_ID_LENGTH: usize = 50;
pub const MAX_EMAIL_LENGTH: usize = 100;
pub const MAX_PHONE_LENGTH: usize = 15;
pub const MAX_NAME_LENGTH: usize = 100;
pub const MAX_PRODUCT_INFO_LENGTH: usize = 255;
pub const MAX_UPI_VPA_LENGTH: usize = 100;

// ================================================================================================
// Currency Constants
// ================================================================================================

pub const SUPPORTED_CURRENCY: &str = "INR";
pub const CURRENCY_MINOR_UNIT: u8 = 2; // INR has 2 decimal places (paise)

// ================================================================================================
// Regex Patterns
// ================================================================================================

pub const UPI_VPA_REGEX: &str = r"^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+$";
pub const PHONE_NUMBER_REGEX: &str = r"^[6-9]\d{9}$"; // Indian mobile number format
pub const EMAIL_REGEX: &str = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$";

// ================================================================================================
// HTTP Headers
// ================================================================================================

pub const CONTENT_TYPE_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
pub const CONTENT_TYPE_JSON: &str = "application/json";
pub const USER_AGENT: &str = "Hyperswitch-EaseBuzz-Connector/1.0";

// ================================================================================================
// Webhook Constants
// ================================================================================================

pub const WEBHOOK_SUCCESS_RESPONSE: &str = "OK";
pub const WEBHOOK_FAILURE_RESPONSE: &str = "FAIL";

// Webhook Event Types
pub const PAYMENT_SUCCESS_WEBHOOK: &str = "payment.success";
pub const PAYMENT_FAILURE_WEBHOOK: &str = "payment.failure";
pub const REFUND_SUCCESS_WEBHOOK: &str = "refund.success";
pub const REFUND_FAILURE_WEBHOOK: &str = "refund.failure";
pub const MANDATE_STATUS_UPDATE_WEBHOOK: &str = "mandate.status_update";
pub const PRESENTMENT_STATUS_UPDATE_WEBHOOK: &str = "presentment.status_update";
pub const NOTIFICATION_STATUS_UPDATE_WEBHOOK: &str = "notification.status_update";

// ================================================================================================
// Feature Flags
// ================================================================================================

pub const UPI_COLLECT_ENABLED: bool = true;
pub const UPI_INTENT_ENABLED: bool = true;
pub const REFUND_ENABLED: bool = true;
pub const WEBHOOK_ENABLED: bool = true;
pub const MANDATE_ENABLED: bool = false; // Future implementation
pub const EMI_ENABLED: bool = false; // Future implementation

// ================================================================================================
// Utility Functions
// ================================================================================================

/// Get the appropriate base URL based on environment
pub fn get_base_url(is_sandbox: bool) -> &'static str {
    if is_sandbox {
        SANDBOX_BASE_URL
    } else {
        PRODUCTION_BASE_URL
    }
}

/// Get the appropriate dashboard URL based on environment
pub fn get_dashboard_url(is_sandbox: bool) -> &'static str {
    if is_sandbox {
        SANDBOX_DASHBOARD_URL
    } else {
        PRODUCTION_DASHBOARD_URL
    }
}

/// Get the appropriate API URL based on environment
pub fn get_api_url(is_sandbox: bool) -> &'static str {
    if is_sandbox {
        SANDBOX_API_URL
    } else {
        PRODUCTION_API_URL
    }
}

/// Check if a payment method is supported
pub fn is_payment_method_supported(payment_method: &str) -> bool {
    matches!(payment_method, 
        UPI_PAYMENT_METHOD | 
        CARD_PAYMENT_METHOD | 
        NET_BANKING_PAYMENT_METHOD | 
        WALLET_PAYMENT_METHOD
    )
}

/// Check if UPI flow type is supported
pub fn is_upi_flow_supported(flow_type: &str) -> bool {
    matches!(flow_type, UPI_COLLECT_FLOW | UPI_INTENT_FLOW)
}

/// Validate UPI VPA format
pub fn is_valid_upi_vpa(vpa: &str) -> bool {
    use regex::Regex;
    let re = Regex::new(UPI_VPA_REGEX).unwrap();
    re.is_match(vpa)
}

/// Validate Indian phone number format
pub fn is_valid_indian_phone(phone: &str) -> bool {
    use regex::Regex;
    let re = Regex::new(PHONE_NUMBER_REGEX).unwrap();
    re.is_match(phone)
}

/// Get timeout for specific operation
pub fn get_timeout_for_operation(operation: &str) -> u64 {
    match operation {
        "payment" => PAYMENT_TIMEOUT_SECS,
        "sync" => SYNC_TIMEOUT_SECS,
        _ => DEFAULT_REQUEST_TIMEOUT_SECS,
    }
}

// ================================================================================================
// Environment-specific Endpoint Builders
// ================================================================================================

/// Build full endpoint URL for payments
pub fn build_payment_endpoint(base_url: &str, endpoint: &str) -> String {
    format!("{}{}", base_url, endpoint)
}

/// Build full endpoint URL for dashboard operations
pub fn build_dashboard_endpoint(dashboard_url: &str, endpoint: &str) -> String {
    format!("{}{}", dashboard_url, endpoint)
}

/// Build full endpoint URL for API operations
pub fn build_api_endpoint(api_url: &str, endpoint: &str) -> String {
    format!("{}{}", api_url, endpoint)
}

/// Build endpoint with path parameters
pub fn build_endpoint_with_params(base_url: &str, endpoint: &str, params: &[(&str, &str)]) -> String {
    let mut url = format!("{}{}", base_url, endpoint);
    for (placeholder, value) in params {
        url = url.replace(&format!(":{}", placeholder), value);
    }
    url
}