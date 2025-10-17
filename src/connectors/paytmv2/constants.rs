// PayTMv2 API constants and endpoints

pub const PAYTMV2_BASE_URL: &str = "https://securegw.paytm.in";
pub const PAYTMV2_SANDBOX_BASE_URL: &str = "https://securegw-stage.paytm.in";

// API endpoints
pub const PAYTMV2_INITIATE_PAYMENT: &str = "/theia/api/v1/initiateTransaction";
pub const PAYTMV2_PROCESS_TRANSACTION: &str = "/theia/api/v1/processTransaction";
pub const PAYTMV2_CHECK_TRANSACTION_STATUS: &str = "/merchant-status/api/v1/getTransactionStatus";
pub const PAYTMV2_REFUND: &str = "/refund/api/v1/advanceRefund";
pub const PAYTMV2_REFUND_STATUS: &str = "/refund/api/v1/refundStatus";

// Payment modes
pub const PAYTMV2_UPI_INTENT: &str = "UPI_INTENT";
pub const PAYTMV2_UPI_COLLECT: &str = "UPI_COLLECT";
pub const PAYTMV2_UPI_QR: &str = "UPI_QR";

// Status codes
pub const PAYTMV2_STATUS_SUCCESS: &str = "SUCCESS";
pub const PAYTMV2_STATUS_PENDING: &str = "PENDING";
pub const PAYTMV2_STATUS_FAILURE: &str = "FAILURE";

// Channel IDs
pub const PAYTMV2_CHANNEL_WEB: &str = "WEB";
pub const PAYTMV2_CHANNEL_WAP: &str = "WAP";
pub const PAYTMV2_CHANNEL_APP: &str = "APP";

// Request types
pub const PAYTMV2_REQUEST_TYPE_PAYMENT: &str = "PAYMENT";
pub const PAYTMV2_REQUEST_TYPE_SUBSCRIBE: &str = "SUBSCRIBE";
pub const PAYTMV2_REQUEST_TYPE_RENEW: &str = "RENEW";
pub const PAYTMV2_REQUEST_TYPE_CANCEL: &str = "CANCEL";

// API versions
pub const PAYTMV2_API_VERSION: &str = "v1";

// Default values
pub const PAYTMV2_DEFAULT_WEBSITE: &str = "DEFAULT";
pub const PAYTMV2_DEFAULT_CALLBACK_URL: &str = "https://merchant.com/callback";

// Error codes
pub const PAYTMV2_ERROR_INVALID_REQUEST: &str = "400";
pub const PAYTMV2_ERROR_AUTH_FAILED: &str = "401";
pub const PAYTMV2_ERROR_FORBIDDEN: &str = "403";
pub const PAYTMV2_ERROR_NOT_FOUND: &str = "404";
pub const PAYTMV2_ERROR_RATE_LIMIT: &str = "429";
pub const PAYTMV2_ERROR_SERVER_ERROR: &str = "500";