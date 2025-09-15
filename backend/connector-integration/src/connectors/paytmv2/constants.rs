// PayTMv2 API constants and endpoints

// Base URLs for different environments
pub const PAYTMV2_BASE_URL_STAGING: &str = "https://securegw-stage.paytm.in";
pub const PAYTMV2_BASE_URL_PRODUCTION: &str = "https://securegw.paytm.in";

// API endpoints
pub const PAYTMV2_AUTHORIZE_URL: &str = "/theia/api/v1/initiateTransaction";
pub const PAYTMV2_SYNC_URL: &str = "/theia/api/v1/transactionStatus";
pub const PAYTMV2_REFUND_URL: &str = "/refund/api/v1/refund";
pub const PAYTMV2_REFUND_SYNC_URL: &str = "/refund/api/v1/refundStatus";

// API versions
pub const PAYTMV2_API_VERSION: &str = "v1";

// Request headers
pub const PAYTMV2_HEADER_CONTENT_TYPE: &str = "application/json";
pub const PAYTMV2_HEADER_MID: &str = "x-mid";
pub const PAYTMV2_HEADER_CHECKSUM: &str = "x-checksum";
pub const PAYTMV2_HEADER_CLIENT_ID: &str = "x-client-id";
pub const PAYTMV2_HEADER_CLIENT_VERSION: &str = "x-client-version";
pub const PAYTMV2_HEADER_CLIENT_PLATFORM: &str = "x-client-platform";

// Default values
pub const PAYTMV2_DEFAULT_CLIENT_ID: &str = "C11";
pub const PAYTMV2_DEFAULT_CLIENT_VERSION: &str = "1.0";
pub const PAYTMV2_DEFAULT_CLIENT_PLATFORM: &str = "WEB";

// Status codes
pub const PAYTMV2_STATUS_SUCCESS: &str = "SUCCESS";
pub const PAYTMV2_STATUS_PENDING: &str = "PENDING";
pub const PAYTMV2_STATUS_FAILURE: &str = "FAILURE";
pub const PAYTMV2_STATUS_TXN_FAILURE: &str = "TXN_FAILURE";
pub const PAYTMV2_STATUS_OPEN: &str = "OPEN";

// Payment method types
pub const PAYTMV2_PAYMENT_METHOD_UPI: &str = "UPI";
pub const PAYTMV2_PAYMENT_METHOD_UPI_INTENT: &str = "UPI_INTENT";
pub const PAYTMV2_PAYMENT_METHOD_UPI_COLLECT: &str = "UPI_COLLECT";

// UPI flow types
pub const PAYTMV2_UPI_FLOW_INTENT: &str = "INTENT";
pub const PAYTMV2_UPI_FLOW_COLLECT: &str = "COLLECT";

// Error codes
pub const PAYTMV2_ERROR_INVALID_MID: &str = "1001";
pub const PAYTMV2_ERROR_INVALID_ORDER_ID: &str = "1002";
pub const PAYTMV2_ERROR_INVALID_TXN_AMOUNT: &str = "1003";
pub const PAYTMV2_ERROR_INVALID_CUST_ID: &str = "1004";
pub const PAYTMV2_ERROR_INVALID_PAYMENT_METHOD: &str = "1005";
pub const PAYTMV2_ERROR_AUTH_FAILED: &str = "2001";
pub const PAYTMV2_ERROR_INVALID_CHECKSUM: &str = "2002";
pub const PAYTMV2_ERROR_TXN_DECLINED: &str = "3001";
pub const PAYTMV2_ERROR_INSUFFICIENT_FUNDS: &str = "3002";
pub const PAYTMV2_ERROR_INVALID_UPI_ID: &str = "3003";
pub const PAYTMV2_ERROR_TIMEOUT: &str = "4001";
pub const PAYTMV2_ERROR_SERVER_ERROR: &str = "5001";

// Response codes
pub const PAYTMV2_RESPONSE_CODE_SUCCESS: &str = "01";
pub const PAYTMV2_RESPONSE_CODE_PENDING: &str = "02";
pub const PAYTMV2_RESPONSE_CODE_FAILURE: &str = "03";
pub const PAYTMV2_RESPONSE_CODE_INVALID: &str = "141";

// Currency codes (PayTM specific)
pub const PAYTMV2_CURRENCY_INR: &str = "INR";
pub const PAYTMV2_CURRENCY_USD: &str = "USD";

// Timeouts (in seconds)
pub const PAYTMV2_REQUEST_TIMEOUT: u64 = 30;
pub const PAYTMV2_CONNECTION_TIMEOUT: u64 = 10;

// Retry configuration
pub const PAYTMV2_MAX_RETRIES: u32 = 3;
pub const PAYTMV2_RETRY_DELAY_MS: u64 = 1000;

// Webhook configuration
pub const PAYTMV2_WEBHOOK_VERSION: &str = "v1";
pub const PAYTMV2_WEBHOOK_SIGNATURE_ALGORITHM: &str = "SHA256";

// Configuration keys
pub const PAYTMV2_CONFIG_MERCHANT_ID: &str = "merchant_id";
pub const PAYTMV2_CONFIG_MERCHANT_KEY: &str = "merchant_key";
pub const PAYTMV2_CONFIG_WEBSITE: &str = "website";
pub const PAYTMV2_CONFIG_INDUSTRY_TYPE: &str = "industry_type";
pub const PAYTMV2_CONFIG_CHANNEL_ID: &str = "channel_id";
pub const PAYTMV2_CONFIG_CALLBACK_URL: &str = "callback_url";

// Default configuration values
pub const PAYTMV2_DEFAULT_WEBSITE: &str = "WEBSTAGING";
pub const PAYTMV2_DEFAULT_INDUSTRY_TYPE: &str = "Retail";
pub const PAYTMV2_DEFAULT_CHANNEL_ID: &str = "WEB";

// Helper function to get base URL based on environment
pub fn get_base_url(is_production: bool) -> &'static str {
    if is_production {
        PAYTMV2_BASE_URL_PRODUCTION
    } else {
        PAYTMV2_BASE_URL_STAGING
    }
}

// Helper function to get full API URL
pub fn get_api_url(endpoint: &str, is_production: bool) -> String {
    format!("{}{}", get_base_url(is_production), endpoint)
}

// Helper function to get default headers
pub fn get_default_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (PAYTMV2_HEADER_CONTENT_TYPE, PAYTMV2_HEADER_CONTENT_TYPE),
        (PAYTMV2_HEADER_CLIENT_ID, PAYTMV2_DEFAULT_CLIENT_ID),
        (PAYTMV2_HEADER_CLIENT_VERSION, PAYTMV2_DEFAULT_CLIENT_VERSION),
        (PAYTMV2_HEADER_CLIENT_PLATFORM, PAYTMV2_DEFAULT_CLIENT_PLATFORM),
    ]
}