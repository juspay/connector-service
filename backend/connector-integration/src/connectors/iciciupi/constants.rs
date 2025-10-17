// ICICI UPI API constants and endpoints

pub const STAGING_BASE_URL: &str = "https://apibankingonesandbox.icicibank.com/api";
pub const PRODUCTION_BASE_URL: &str = "https://apibankingone.icicibank.com/api";

// API Endpoints
pub const COLLECT_PAY_ENDPOINT: &str = "/MerchantAPI/UPI/v0/CollectPay2/:merchantId";
pub const COLLECT_PAY_ENDPOINT_V3: &str = "/MerchantAPI/UPI/v0/CollectPay3/:merchantId";
pub const TRANSACTION_STATUS_ENDPOINT: &str = "/MerchantAPI/UPI/v0/TransactionStatus/:merchantId";
pub const REFUND_ENDPOINT: &str = "/MerchantAPI/UPI/v0/Refund/:merchantId";
pub const VERIFY_VPA_ENDPOINT: &str = "/MerchantAPI/UPI/v0/VerifyVpa";
pub const MANDATE_CREATE_ENDPOINT: &str = "/MerchantAPI/UPI/v0/MandateCreate/:merchantId";
pub const MANDATE_UPDATE_ENDPOINT: &str = "/MerchantAPI/UPI/v0/MandateUpdate/:merchantId";
pub const MANDATE_EXECUTE_ENDPOINT: &str = "/MerchantAPI/UPI/v0/MandateExecute/:merchantId";
pub const NOTIFICATION_ENDPOINT: &str = "/MerchantAPI/UPI/v0/Notification/:merchantId";

// Headers
pub const CONTENT_TYPE: &str = "Content-Type";
pub const AUTHORIZATION: &str = "Authorization";
pub const ACCEPT: &str = "Accept";

// Content Types
pub const APPLICATION_JSON: &str = "application/json";
pub const TEXT_PLAIN: &str = "text/plain";

// Response Status Codes
pub const SUCCESS_STATUS: &str = "SUCCESS";
pub const PENDING_STATUS: &str = "PENDING";
pub const FAILURE_STATUS: &str = "FAILURE";

// Transaction Types
pub const COLLECT_PAY_TRANSACTION: &str = "COLLECT_PAY";
pub const REFUND_TRANSACTION: &str = "REFUND";
pub const MANDATE_TRANSACTION: &str = "MANDATE";

// Mandate Types
pub const ONE_TIME_MANDATE: &str = "ONE_TIME";
pub const RECURRING_MANDATE: &str = "RECURRING";