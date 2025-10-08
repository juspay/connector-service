// API endpoints for GooglePay connector
pub const UPI_TRANSACTION_PATH: &str = "/api/m1/transactions";
pub const WEBHOOK_PATH_PREFIX: &str = "/v2/pay/webhooks/";
pub const STATUS_PATH: &str = "/api/m1/status";
pub const REFUND_PATH: &str = "/api/m1/refunds";
pub const REFUND_SYNC_PATH: &str = "/api/m1/refund-sync";

// Headers
pub const CONTENT_TYPE: &str = "Content-Type";
pub const AUTHORIZATION: &str = "Authorization";
pub const X_API_VERSION: &str = "X-API-Version";

// Default values
pub const DEFAULT_EXPIRY: i32 = 900; // 15 minutes in seconds
pub const DEFAULT_PLATFORM: &str = "ANDROID_APP";
pub const DEFAULT_MOBILE_NUMBER: &str = "9999999999";
pub const DEFAULT_MERCHANT_ID: &str = "default_merchant";

// Transaction types
pub const TRANSACTION_TYPE_INTENT: &str = "INTENT";
pub const TRANSACTION_TYPE_COLLECT: &str = "COLLECT";

// Status mappings
pub const STATUS_SUCCESS: &str = "success";
pub const STATUS_CHARGED: &str = "charged";
pub const STATUS_COMPLETED: &str = "completed";
pub const STATUS_PENDING: &str = "pending";
pub const STATUS_PROCESSING: &str = "processing";
pub const STATUS_INITIATED: &str = "initiated";
pub const STATUS_FAILED: &str = "failed";
pub const STATUS_FAILURE: &str = "failure";
pub const STATUS_DECLINED: &str = "declined";
pub const STATUS_REFUNDED: &str = "refunded";

// API versions
pub const API_VERSION: &str = "v1";

// Error codes
pub const ERROR_CODE_INVALID_REQUEST: &str = "INVALID_REQUEST";
pub const ERROR_CODE_AUTHENTICATION_FAILED: &str = "AUTHENTICATION_FAILED";
pub const ERROR_CODE_TRANSACTION_NOT_FOUND: &str = "TRANSACTION_NOT_FOUND";
pub const ERROR_CODE_INSUFFICIENT_FUNDS: &str = "INSUFFICIENT_FUNDS";
pub const ERROR_CODE_INVALID_VPA: &str = "INVALID_VPA";