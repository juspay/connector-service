pub const BILLDESK_UAT_BASE_URL: &str = "https://uat.billdesk.com";
pub const BILLDESK_PROD_BASE_URL: &str = "https://www.billdesk.com";

// API Endpoints
pub const BILLDESK_AUTHORIZE_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF011";
pub const BILLDESK_STATUS_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF002";
pub const BILLDESK_REFUND_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF003";
pub const BILLDESK_REFUND_STATUS_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF004";

// Request IDs for different operations
pub const BILLDESK_UPI_INITIATE_REQID: &str = "BDRDF011";
pub const BILLDESK_STATUS_CHECK_REQID: &str = "BDRDF002";
pub const BILLDESK_REFUND_REQID: &str = "BDRDF003";
pub const BILLDESK_REFUND_STATUS_REQID: &str = "BDRDF004";

// Status codes
pub const BILLDESK_STATUS_SUCCESS: &str = "0300";
pub const BILLDESK_STATUS_SUCCESS_ALT: &str = "0399";
pub const BILLDESK_STATUS_FAILURE: &str = "0396";
pub const BILLDESK_STATUS_PENDING: &str = "0398";

// Payment methods
pub const BILLDESK_PAYMENT_METHOD_UPI: &str = "UPI";
pub const BILLDESK_PAYMENT_METHOD_NB: &str = "NB";
pub const BILLDESK_PAYMENT_METHOD_CARD: &str = "CARD";

// Request types
pub const BILLDESK_REQUEST_TYPE_STATUS: &str = "STATUS";
pub const BILLDESK_REQUEST_TYPE_REFUND: &str = "REFUND";
pub const BILLDESK_REQUEST_TYPE_REFUND_STATUS: &str = "REFUND_STATUS";

// Currency codes
pub const BILLDESK_CURRENCY_INR: &str = "356";
pub const BILLDESK_CURRENCY_USD: &str = "840";

// Error codes
pub const BILLDESK_ERROR_INVALID_REQUEST: &str = "INVALID_REQUEST";
pub const BILLDESK_ERROR_AUTHENTICATION_FAILED: &str = "AUTHENTICATION_FAILED";
pub const BILLDESK_ERROR_TRANSACTION_NOT_FOUND: &str = "TRANSACTION_NOT_FOUND";
pub const BILLDESK_ERROR_INSUFFICIENT_FUNDS: &str = "INSUFFICIENT_FUNDS";
pub const BILLDESK_ERROR_INVALID_MERCHANT: &str = "INVALID_MERCHANT";