pub const BILLDESK_UAT_BASE_URL: &str = "https://uat.billdesk.com/pgidsk/PGIDirectRequest";
pub const BILLDESK_PROD_BASE_URL: &str = "https://www.billdesk.com/pgidsk/PGIDirectRequest";

// Request IDs for different Billdesk operations
pub const BILLDESK_UPI_INITIATE_REQID: &str = "BDRDF011";
pub const BILLDESK_AUTH_REQID: &str = "BDRDF002";
pub const BILLDESK_STATUS_REQID: &str = "BDRDF003";
pub const BILLDESK_REFUND_REQID: &str = "BDRDF004";

// Payment status codes from Billdesk
pub const BILLDESK_STATUS_SUCCESS: &str = "0300";
pub const BILLDESK_STATUS_SUCCESS_ALT: &str = "0399";
pub const BILLDESK_STATUS_PENDING: &str = "0396";
pub const BILLDESK_STATUS_FAILURE: &str = "0398";

// Error codes
pub const BILLDESK_ERROR_INVALID_REQUEST: &str = "400";
pub const BILLDESK_ERROR_AUTH_FAILED: &str = "401";
pub const BILLDESK_ERROR_NOT_FOUND: &str = "404";
pub const BILLDESK_ERROR_SERVER_ERROR: &str = "500";

// Headers
pub const BILLDESK_CONTENT_TYPE: &str = "application/json";
pub const BILLDESK_AUTH_HEADER: &str = "Authorization";

// Currency codes
pub const BILLDESK_CURRENCY_INR: &str = "356";
pub const BILLDESK_CURRENCY_USD: &str = "840";

// Transaction types
pub const BILLDESK_TXN_TYPE_UPI: &str = "UPI";
pub const BILLDESK_TXN_TYPE_NB: &str = "NB";
pub const BILLDESK_TXN_TYPE_CARD: &str = "CARD";

// Item codes
pub const BILLDESK_ITEM_CODE_DIRECT: &str = "DIRECT";
pub const BILLDESK_ITEM_CODE_RECURRING: &str = "RECURRING";