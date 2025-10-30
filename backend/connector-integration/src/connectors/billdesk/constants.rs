// Billdesk API constants and endpoints

pub const BILLDESK_UAT_BASE_URL: &str = "https://uat.billdesk.com";
pub const BILLDESK_PROD_BASE_URL: &str = "https://www.billdesk.com";

pub const BILLDESK_AUTH_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF002";
pub const BILLDESK_UPI_INITIATE_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF011";
pub const BILLDESK_STATUS_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF003";
pub const BILLDESK_REFUND_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF004";
pub const BILLDESK_REFUND_STATUS_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF005";

pub const BILLDESK_MANDATE_CREATE_ENDPOINT: &str = "/pgsi/mandates/v2";
pub const BILLDESK_MANDATE_RETRIEVE_ENDPOINT: &str = "/pgsi/mandates/v2";
pub const BILLDESK_MANDATE_REVOKE_ENDPOINT: &str = "/pgsi/mandates/v2";

pub const BILLDESK_VPA_VERIFY_ENDPOINT: &str = "/pgsi/vpa/v1/verify";

// Request IDs for different operations
pub const BILLDESK_REQID_AUTH: &str = "BDRDF002";
pub const BILLDESK_REQID_UPI_INITIATE: &str = "BDRDF011";
pub const BILLDESK_REQID_STATUS: &str = "BDRDF003";
pub const BILLDESK_REQID_REFUND: &str = "BDRDF004";
pub const BILLDESK_REQID_REFUND_STATUS: &str = "BDRDF005";

// Headers
pub const BILLDESK_CONTENT_TYPE: &str = "application/json";
pub const BILLDESK_ACCEPT: &str = "application/json";

// Response status codes
pub const BILLDESK_SUCCESS_STATUS: &str = "0300";
pub const BILLDESK_PENDING_STATUS: &str = "0002";
pub const BILLDESK_FAILURE_STATUS: &str = "0399";

// Transaction types
pub const BILLDESK_TXN_TYPE_UPI: &str = "UPI";
pub const BILLDESK_TXN_TYPE_NB: &str = "NB";
pub const BILLDESK_TXN_TYPE_CARD: &str = "CARD";

// Currency codes
pub const BILLDESK_CURRENCY_INR: &str = "356";

// Item codes
pub const BILLDESK_ITEM_CODE_DIRECT: &str = "DIRECT";

// Additional info fields
pub const BILLDESK_ADDITIONAL_INFO_1: &str = "UPI";
pub const BILLDESK_ADDITIONAL_INFO_2: &str = "COLLECT";