//! Constants for PhonePe connector

// ===== API ENDPOINTS =====
pub const API_PAY_ENDPOINT: &str = "pg/v1/pay";

// ===== UPI INSTRUMENT TYPES =====
pub const UPI_INTENT: &str = "UPI_INTENT";
pub const UPI_COLLECT: &str = "UPI_COLLECT";
pub const UPI_QR: &str = "UPI_QR";

// ===== DEFAULT VALUES =====
pub const DEFAULT_KEY_INDEX: &str = "1";
pub const DEFAULT_DEVICE_OS: &str = "Android";
pub const DEFAULT_IP: &str = "127.0.0.1";
pub const DEFAULT_USER_AGENT: &str = "Mozilla/5.0";

// ===== CHECKSUM =====
pub const CHECKSUM_SEPARATOR: &str = "###";

// ===== CONTENT TYPES =====
pub const APPLICATION_JSON: &str = "application/json";
