pub const API_VERSION: &str = "v1";
pub const PAYMENT_ENDPOINT: &str = "payment";
pub const PAYMENT_SYNC_ENDPOINT: &str = "payment/status";
pub const REFUND_ENDPOINT: &str = "refund";
pub const REFUND_SYNC_ENDPOINT: &str = "refund/status";
pub const CAPTURE_ENDPOINT: &str = "payment/capture";
pub const VOID_ENDPOINT: &str = "payment/void";

pub const SUCCESS_STATUS: &str = "SUCCESS";
pub const PENDING_STATUS: &str = "PENDING";
pub const FAILED_STATUS: &str = "FAILED";
pub const CANCELLED_STATUS: &str = "CANCELLED";

pub const CONTENT_TYPE: &str = "application/json";
pub const AUTHORIZATION_HEADER: &str = "Authorization";
pub const API_KEY_HEADER: &str = "X-API-Key";