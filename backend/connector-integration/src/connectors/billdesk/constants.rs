pub const BILLDESK_UAT_BASE_URL: &str = "https://uat.billdesk.com/pgidsk/PGIDirectRequest";
pub const BILLDESK_PROD_BASE_URL: &str = "https://www.billdesk.com/pgidsk/PGIDirectRequest";

// Request IDs for different Billdesk operations
pub const BILLDESK_AUTHORIZE_REQID: &str = "BDRDF002";
pub const BILLDESK_UPI_INITIATE_REQID: &str = "BDRDF011";
pub const BILLDESK_STATUS_REQID: &str = "BDRDF003";
pub const BILLDESK_REFUND_REQID: &str = "BDRDF004";

// Status codes from Billdesk
pub const BILLDESK_STATUS_SUCCESS: &str = "0300";
pub const BILLDESK_STATUS_FAILURE: &str = "0399";
pub const BILLDESK_STATUS_PENDING: &str = "0001";

// Item codes for different payment methods
pub const BILLDESK_ITEM_CODE_UPI: &str = "UPI";
pub const BILLDESK_ITEM_CODE_NB: &str = "NB";
pub const BILLDESK_ITEM_CODE_CARD: &str = "CRD";

// Currency codes
pub const BILLDESK_CURRENCY_INR: &str = "356";
pub const BILLDESK_CURRENCY_USD: &str = "840";