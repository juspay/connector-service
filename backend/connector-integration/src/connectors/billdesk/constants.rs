pub const BILLDESK_UAT_BASE_URL: &str = "https://uat.billdesk.com/pgidsk/PGIDirectRequest";
pub const BILLDESK_PROD_BASE_URL: &str = "https://www.billdesk.com/pgidsk/PGIDirectRequest";

// Request IDs for different Billdesk operations - UPI focused
pub const BILLDESK_UPI_INITIATE_REQID: &str = "BDRDF011";
pub const BILLDESK_STATUS_REQID: &str = "BDRDF002";
pub const BILLDESK_REFUND_REQID: &str = "BDRDF002";
pub const BILLDESK_REFUND_STATUS_REQID: &str = "BDRDF002";

// Billdesk response codes
pub const BILLDESK_SUCCESS_CODE: &str = "0300";
pub const BILLDESK_PARTIAL_SUCCESS_CODE: &str = "0399";
pub const BILLDESK_FAILURE_CODE: &str = "0396";
pub const BILLDESK_PENDING_CODE_1: &str = "0001";
pub const BILLDESK_PENDING_CODE_2: &str = "0002";

// UPI Payment method mappings
pub const BILLDESK_UPI_TXN_TYPE: &str = "UPI";
pub const BILLDESK_DIRECT_TXN_TYPE: &str = "D";

// UPI Item codes
pub const BILLDESK_UPI_ITEM_CODE: &str = "UPI";
pub const BILLDESK_DIRECT_ITEM_CODE: &str = "DIRECT";