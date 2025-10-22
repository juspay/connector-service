pub const BILLDESK_UAT_BASE_URL: &str = "https://uat.billdesk.com/pgidsk/PGIDirectRequest";
pub const BILLDESK_PROD_BASE_URL: &str = "https://www.billdesk.com/pgidsk/PGIDirectRequest";

// Request IDs for different Billdesk operations
pub const BILLDESK_UPI_INITIATE_REQID: &str = "BDRDF011";
pub const BILLDESK_AUTH_REQID: &str = "BDRDF002";
pub const BILLDESK_STATUS_REQID: &str = "BDRDF002";
pub const BILLDESK_REFUND_REQID: &str = "BDRDF003";
pub const BILLDESK_REFUND_STATUS_REQID: &str = "BDRDF004";

// Payment status codes from Billdesk
pub const BILLDESK_STATUS_SUCCESS: &str = "0300";
pub const BILLDESK_STATUS_SUCCESS_ALT: &str = "0000";
pub const BILLDESK_STATUS_PENDING: &str = "0301";
pub const BILLDESK_STATUS_FAILURE: &str = "0399";
pub const BILLDESK_STATUS_FAILURE_ALT: &str = "0398";

// Default values
pub const DEFAULT_CURRENCY: &str = "INR";
pub const DEFAULT_ITEM_CODE: &str = "DIRECT";
pub const DEFAULT_TXN_TYPE: &str = "UPI";

// Error messages
pub const ERROR_MISSING_PAYMENT_METHOD: &str = "Payment method type is required for Billdesk";
pub const ERROR_MISSING_AUTH_TYPE: &str = "Billdesk authentication type is not configured properly";
pub const ERROR_UNSUPPORTED_PAYMENT_METHOD: &str = "Billdesk only supports UPI payments";