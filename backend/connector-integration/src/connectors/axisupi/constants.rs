pub const PROD_BASE_URL: &str = "https://upisdk.axisbank.co.in";
pub const SANDBOX_BASE_URL: &str = "https://upiuatv3.axisbank.co.in";

// API Endpoints
pub const COLLECT_ENDPOINT: &str = "/api/m1/merchants/transactions/webCollect";
pub const STATUS_ENDPOINT: &str = "/api/m1/merchants/transactions/status";
pub const REFUND_ENDPOINT: &str = "/api/m1/merchants/transactions/refund";
pub const REGISTER_INTENT_ENDPOINT: &str = "/api/m1/merchants/transactions/registerIntent";
pub const INSTANT_REFUND_ENDPOINT: &str = "/api/m1/merchants/transactions/onlineRefund";
pub const VALID_VPA_ENDPOINT: &str = "/api/m1/merchants/vpas/validity";
pub const ONLINE_REFUND_STATUS_ENDPOINT: &str = "/api/m1/merchants/transactions/onlineRefund/status";
pub const INTENT_STATUS_ENDPOINT: &str = "/api/m1/merchants/transactions/intent/status";

// Response Codes
pub const SUCCESS_CODE: &str = "00";
pub const PENDING_CODE: &str = "01";
pub const PROCESSING_CODE: &str = "02";

// Default Values
pub const DEFAULT_EXPIRY_MINUTES: &str = "30";
pub const DEFAULT_REMARKS: &str = "UPI Payment";

// HTTP Headers
pub const CONTENT_TYPE_JSON: &str = "application/json";
pub const AUTHORIZATION_HEADER: &str = "Authorization";

// UDF Parameters
pub const CUSTOMER_ID_KEY: &str = "_CustomerId";