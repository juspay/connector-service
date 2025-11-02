pub const BILLDESK_UAT_BASE_URL: &str = "https://uat.billdesk.com/pgidsk/PGIDirectRequest";
pub const BILLDESK_PROD_BASE_URL: &str = "https://www.billdesk.com/pgidsk/PGIDirectRequest";

pub const BILLDESK_AUTHORIZE_REQID: &str = "BDRDF002";
pub const BILLDESK_INITIATE_CARD_REQID: &str = "BDRDF011";
pub const BILLDESK_UPI_INITIATE_REQID: &str = "BDRDF011";
pub const BILLDESK_STATUS_REQID: &str = "BDRDF002";
pub const BILLDESK_REFUND_REQID: &str = "BDRDF003";

pub const BILLDESK_AUTH_STATUS_SUCCESS: &str = "0300";
pub const BILLDESK_AUTH_STATUS_PARTIAL: &str = "0399";
pub const BILLDESK_AUTH_STATUS_PENDING: &str = "0396";
pub const BILLDESK_AUTH_STATUS_FAILURE: &str = "0398";

pub const BILLDESK_PAYMENT_METHOD_UPI: &str = "UPI";
pub const BILLDESK_PAYMENT_METHOD_CARD: &str = "CARD";
pub const BILLDESK_PAYMENT_METHOD_NB: &str = "NB";

pub const BILLDESK_CURRENCY_INR: &str = "INR";
pub const BILLDESK_ITEM_CODE_DIRECT: &str = "DIRECT";

pub const BILLDESK_RESPONSE_TYPE_SUCCESS: &str = "Success";
pub const BILLDESK_RESPONSE_TYPE_ERROR: &str = "Error";