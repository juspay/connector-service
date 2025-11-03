pub const BILLDESK_UAT_BASE_URL: &str = "https://uat.billdesk.com";
pub const BILLDESK_PROD_BASE_URL: &str = "https://www.billdesk.com";

pub const BILLDESK_AUTHORIZE_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF011";
pub const BILLDESK_AUTH_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF002";
pub const BILLDESK_STATUS_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF003";
pub const BILLDESK_REFUND_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF004";
pub const BILLDESK_REFUND_STATUS_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF005";

pub const BILLDESK_UPI_INITIATE_REQUEST_ID: &str = "BDRDF011";
pub const BILLDESK_NB_INITIATE_REQUEST_ID: &str = "BDRDF012";
pub const BILLDESK_CARD_INITIATE_REQUEST_ID: &str = "BDRDF013";
pub const BILLDESK_AUTH_REQUEST_ID: &str = "BDRDF002";
pub const BILLDESK_STATUS_REQUEST_ID: &str = "BDRDF003";
pub const BILLDESK_REFUND_REQUEST_ID: &str = "BDRDF004";
pub const BILLDESK_REFUND_STATUS_REQUEST_ID: &str = "BDRDF005";

// Payment status codes from Billdesk
pub const BILLDESK_STATUS_SUCCESS: &str = "0300";
pub const BILLDESK_STATUS_SUCCESS_MIGRATED: &str = "0399";
pub const BILLDESK_STATUS_FAILURE: &str = "0396";
pub const BILLDESK_STATUS_PENDING: &str = "0001";
pub const BILLDESK_STATUS_AUTH_PENDING: &str = "0002";
pub const BILLDESK_STATUS_INITIATED: &str = "0003";

// Error codes
pub const BILLDESK_ERROR_INVALID_REQUEST: &str = "1001";
pub const BILLDESK_ERROR_AUTH_FAILED: &str = "1002";
pub const BILLDESK_ERROR_INVALID_MERCHANT: &str = "1003";
pub const BILLDESK_ERROR_INVALID_AMOUNT: &str = "1004";
pub const BILLDESK_ERROR_INVALID_CURRENCY: &str = "1005";
pub const BILLDESK_ERROR_TRANSACTION_NOT_FOUND: &str = "1006";
pub const BILLDESK_ERROR_DUPLICATE_TRANSACTION: &str = "1007";
pub const BILLDESK_ERROR_TIMEOUT: &str = "1008";
pub const BILLDESK_ERROR_SYSTEM_ERROR: &str = "9999";