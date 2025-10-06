// API endpoints for GooglePay connector
pub const UPI_TRANSACTION_PATH: &str = "/api/m1/transactions";
pub const WEBHOOK_PATH_PREFIX: &str = "/v2/pay/webhooks/";

// Headers
pub const CONTENT_TYPE: &str = "Content-Type";
pub const AUTHORIZATION: &str = "Authorization";

// Default values
pub const DEFAULT_EXPIRY: i32 = 900; // 15 minutes in seconds
pub const DEFAULT_PLATFORM: &str = "ANDROID_APP";