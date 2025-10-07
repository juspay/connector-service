//! Constants for PhonePe connector

// ===== API ENDPOINTS =====
pub const API_PAY_ENDPOINT: &str = "/v3/debit";
pub const API_STATUS_ENDPOINT: &str = "/v3/transaction/:mid/:tid/status";
pub const API_V4_PAY_ENDPOINT: &str = "/v4/debit";
pub const API_V4_STATUS_ENDPOINT: &str = "/v4/transaction/:mid/:tid/status";

// ===== UPI INSTRUMENT TYPES =====
pub const UPI_INTENT: &str = "UPI_INTENT";
pub const UPI_COLLECT: &str = "UPI_COLLECT";
pub const UPI_QR: &str = "UPI_QR";

// ===== DEFAULT VALUES =====
pub const DEFAULT_KEY_INDEX: &str = "1";
pub const DEFAULT_DEVICE_OS: &str = "ANDROID";
pub const DEFAULT_IP: &str = "127.0.0.1";
pub const DEFAULT_USER_AGENT: &str = "Mozilla/5.0";

// ===== CHECKSUM =====
pub const CHECKSUM_SEPARATOR: &str = "###";

// ===== CONTENT TYPES =====
pub const APPLICATION_JSON: &str = "application/json";

// ===== BASE URLS =====
pub const PRODUCTION_BASE_URL: &str = "https://mercury-t2.phonepe.com";
pub const SANDBOX_BASE_URL: &str = "https://mercury-uat.phonepe.com";
pub const V2_PRODUCTION_BASE_URL: &str = "https://api.phonepe.com/apis/hermes";
pub const V2_SANDBOX_BASE_URL: &str = "https://api-preprod.phonepe.com/apis/pg-sandbox";