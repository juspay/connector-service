pub const BILLDESK_UAT_BASE_URL: &str = "https://uat.billdesk.com/pgidsk/PGIDirectRequest";
pub const BILLDESK_PROD_BASE_URL: &str = "https://www.billdesk.com/pgidsk/PGIDirectRequest";

// Request IDs for different Billdesk operations
pub const BILLDESK_REQID_AUTHORIZE: &str = "BDRDF002";
pub const BILLDESK_REQID_UPI_INITIATE: &str = "BDRDF011";
pub const BILLDESK_REQID_STATUS_CHECK: &str = "BDRDF002";
pub const BILLDESK_REQID_REFUND: &str = "BDRDF003";
pub const BILLDESK_REQID_REFUND_STATUS: &str = "BDRDF004";

// Billdesk response codes
pub const BILLDESK_SUCCESS_CODE: &str = "0300";
pub const BILLDESK_AUTH_PENDING_CODE: &str = "0396";
pub const BILLDESK_FAILURE_CODE: &str = "0397";
pub const BILLDESK_PENDING_CODE: &str = "0399";

// Payment method mappings
pub const BILLDESK_UPI_BANK_ID: &str = "UPI";
pub const BILLDESK_NET_BANKING_BANK_ID: &str = "NB";

// Default values
pub const DEFAULT_ITEM_CODE: &str = "DIRECT";
pub const DEFAULT_TXN_TYPE: &str = "PURCHASE";
pub const DEFAULT_REQUEST_TYPE: &str = "STATUSQUERY";