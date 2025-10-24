pub mod api;

pub const BILLDESK: &str = "billdesk";

// API Request IDs
pub const REQID_INITIATE_UPI: &str = "BDRDF011";
pub const REQID_AUTHORIZE: &str = "BDRDF002";
pub const REQID_STATUS_CHECK: &str = "BDRDF002";

// Status codes from Billdesk
pub const STATUS_SUCCESS: &str = "0300";
pub const STATUS_SUCCESS_ALT: &str = "0399";
pub const STATUS_PENDING: &str = "0396";
pub const STATUS_FAILURE: &str = "0397";

// Error codes
pub const ERROR_INVALID_REQUEST: &str = "INVALID_REQUEST";
pub const ERROR_AUTHENTICATION_FAILED: &str = "AUTHENTICATION_FAILED";
pub const ERROR_INSUFFICIENT_FUNDS: &str = "INSUFFICIENT_FUNDS";
pub const ERROR_TRANSACTION_DECLINED: &str = "TRANSACTION_DECLINED";

// URLs
pub const UAT_BASE_URL: &str = "https://uat.billdesk.com/pgidsk/PGIDirectRequest";
pub const PROD_BASE_URL: &str = "https://www.billdesk.com/pgidsk/PGIDirectRequest";