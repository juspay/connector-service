pub const BILLDESK_UAT_BASE_URL: &str = "https://uat.billdesk.com";
pub const BILLDESK_PROD_BASE_URL: &str = "https://www.billdesk.com";

pub const BILLDESK_AUTHORIZE_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF011";
pub const BILLDESK_STATUS_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF002";
pub const BILLDESK_UPI_INITIATE_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF011";

pub const BILLDESK_AUTH_SUCCESS_STATUS: &str = "0300";
pub const BILLDESK_AUTH_PENDING_STATUS: &str = "0001";
pub const BILLDESK_AUTH_FAILURE_STATUS: &str = "0396";

pub const BILLDESK_PAYMENT_METHOD_UPI: &str = "UPI";
pub const BILLDESK_CURRENCY_INR: &str = "INR";

pub const BILLDESK_RESPONSE_TYPE_SUCCESS: &str = "Success";
pub const BILLDESK_RESPONSE_TYPE_ERROR: &str = "Error";