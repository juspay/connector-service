pub mod constants;

pub const BILLDESK_UAT_BASE_URL: &str = "https://uat.billdesk.com";
pub const BILLDESK_PROD_BASE_URL: &str = "https://www.billdesk.com";

// Billdesk request IDs for different operations
pub const BILLDESK_UPI_INITIATE_REQ_ID: &str = "BDRDF011";
pub const BILLDESK_AUTH_REQ_ID: &str = "BDRDF002";
pub const BILLDESK_STATUS_REQ_ID: &str = "BDRDF003";
pub const BILLDESK_REFUND_REQ_ID: &str = "BDRDF004";

// Billdesk response status codes
pub const BILLDESK_STATUS_SUCCESS: &str = "0300";
pub const BILLDESK_STATUS_PENDING: &str = "0396";
pub const BILLDESK_STATUS_FAILURE: &str = "0398";
pub const BILLDESK_STATUS_AUTH_PENDING: &str = "0399";

// Payment method types
pub const BILLDESK_PAYMENT_TYPE_UPI: &str = "UPI";
pub const BILLDESK_PAYMENT_TYPE_NB: &str = "NB";
pub const BILLDESK_PAYMENT_TYPE_CARD: &str = "CARD";

// Item codes
pub const BILLDESK_ITEM_CODE_DIRECT: &str = "DIRECT";
pub const BILLDESK_ITEM_CODE_RECURRING: &str = "RECURRING";

// Request types
pub const BILLDESK_REQUEST_TYPE_STATUS: &str = "STATUSQUERY";
pub const BILLDESK_REQUEST_TYPE_REFUND: &str = "REFUND";
pub const BILLDESK_REQUEST_TYPE_REFUND_STATUS: &str = "REFUNDSTATUS";