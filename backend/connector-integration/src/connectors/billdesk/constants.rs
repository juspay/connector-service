pub const BILLDESK_UAT_BASE_URL: &str = "https://uat.billdesk.com";
pub const BILLDESK_PROD_BASE_URL: &str = "https://www.billdesk.com";

// API Endpoints
pub const BILLDESK_UPI_INITIATE_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF011";
pub const BILLDESK_AUTH_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF002";
pub const BILLDESK_STATUS_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF003";

// Request IDs for different operations
pub const BILLDESK_REQID_UPI_INITIATE: &str = "BDRDF011";
pub const BILLDESK_REQID_AUTH: &str = "BDRDF002";
pub const BILLDESK_REQID_STATUS: &str = "BDRDF003";

// Response status codes
pub const BILLDESK_STATUS_SUCCESS: &str = "0000";
pub const BILLDESK_STATUS_PENDING: &str = "0300";
pub const BILLDESK_STATUS_FAILURE: &str = "0001";

// Payment method types
pub const BILLDESK_PAYMENT_METHOD_UPI: &str = "UPI";
pub const BILLDESK_PAYMENT_METHOD_UPI_COLLECT: &str = "UPI_COLLECT";

// Error codes
pub const BILLDESK_ERROR_INVALID_REQUEST: &str = "1001";
pub const BILLDESK_ERROR_AUTH_FAILED: &str = "1002";
pub const BILLDESK_ERROR_INVALID_MERCHANT: &str = "1003";
pub const BILLDESK_ERROR_INVALID_AMOUNT: &str = "1004";
pub const BILLDESK_ERROR_TRANSACTION_NOT_FOUND: &str = "1005";