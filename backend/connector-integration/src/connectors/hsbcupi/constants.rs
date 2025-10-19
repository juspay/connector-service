// API Endpoints
pub const API_COLLECT_ENDPOINT: &str = "/upi/api/v3/meCollect";
pub const API_INTENT_ENDPOINT: &str = "/upi/api/v3/registerIntent";
pub const API_STATUS_ENDPOINT: &str = "/upi/api/v3/meTransQuery";
pub const API_REFUND_ENDPOINT: &str = "/upi/api/v3/meRefund";

// Default values
pub const DEFAULT_EXPIRY_MINUTES: &str = "5";
pub const DEFAULT_CIRCLE_CODE: &str = "00";

// Status codes
pub const STATUS_SUCCESS: &str = "S";
pub const STATUS_PENDING: &str = "P";
pub const STATUS_FAILED: &str = "F";
pub const STATUS_INITIATED: &str = "I";

// Response codes
pub const RESPONSE_CODE_SUCCESS: &str = "00";
pub const RESPONSE_CODE_PENDING: &str = "01";
pub const RESPONSE_CODE_FAILED: &str = "02";
