pub const BILLDESK_UAT_BASE_URL: &str = "https://uat.billdesk.com";
pub const BILLDESK_PROD_BASE_URL: &str = "https://www.billdesk.com";

pub const BILLDESK_AUTHORIZE_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF011";
pub const BILLDESK_STATUS_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF002";
pub const BILLDESK_UPI_INITIATE_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF011";

// Billdesk status codes
pub const BILLDESK_STATUS_SUCCESS: &str = "0300";
pub const BILLDESK_STATUS_SUCCESS_ALT: &str = "0399";
pub const BILLDESK_STATUS_FAILURE: &str = "0396";
pub const BILLDESK_STATUS_FAILURE_ALT: &str = "0397";
pub const BILLDESK_STATUS_FAILURE_ALT2: &str = "0398";
pub const BILLDESK_STATUS_PENDING: &str = "0001";
pub const BILLDESK_STATUS_PENDING_ALT: &str = "0002";

// Payment method types
pub const BILLDESK_PAYMENT_TYPE_UPI: &str = "UPI";
pub const BILLDESK_ITEM_CODE_DIRECT: &str = "DIRECT";

// Request types
pub const BILLDESK_REQUEST_TYPE_STATUS: &str = "STATUS";