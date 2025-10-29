pub const BILLDESK_UAT_BASE_URL: &str = "https://uat.billdesk.com/pgidsk/PGIDirectRequest";
pub const BILLDESK_PROD_BASE_URL: &str = "https://www.billdesk.com/pgidsk/PGIDirectRequest";

// Request IDs for different Billdesk operations
pub const BILLDESK_UPI_INITIATE_REQID: &str = "BDRDF011";
pub const BILLDESK_NB_INITIATE_REQID: &str = "BDRDF002";
pub const BILLDESK_AUTH_REQID: &str = "BDRDF002";
pub const BILLDESK_STATUS_REQID: &str = "BDRDF002";
pub const BILLDESK_REFUND_REQID: &str = "BDRDF002";
pub const BILLDESK_REFUND_STATUS_REQID: &str = "BDRDF002";

// Billdesk response codes
pub const BILLDESK_SUCCESS_CODE: &str = "0300";
pub const BILLDESK_PARTIAL_SUCCESS_CODE: &str = "0399";
pub const BILLDESK_FAILURE_CODE: &str = "0396";
pub const BILLDESK_PENDING_CODE_1: &str = "0001";
pub const BILLDESK_PENDING_CODE_2: &str = "0002";

// Payment method mappings
pub const BILLDESK_UPI_TXN_TYPE: &str = "UPI";
pub const BILLDESK_NB_TXN_TYPE: &str = "NB";
pub const BILLDESK_DIRECT_TXN_TYPE: &str = "D";

// Item codes
pub const BILLDESK_UPI_ITEM_CODE: &str = "UPI";
pub const BILLDESK_NB_ITEM_CODE: &str = "NETBANKING";
pub const BILLDESK_DIRECT_ITEM_CODE: &str = "DIRECT";

// Default values
pub const BILLDESK_DEFAULT_BANK_ID: &str = "DEFAULT";
pub const BILLDESK_DEFAULT_ITEM_CODE: &str = "DIRECT";