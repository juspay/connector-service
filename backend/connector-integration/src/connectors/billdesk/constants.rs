pub mod api;

pub const BILLDESK: &str = "billdesk";

// API Endpoints
pub mod endpoints {
    pub const AUTHORIZE_UAT: &str = "https://uat.billdesk.com/pgidsk/PGIDirectRequest?reqid=BDRDF011";
    pub const AUTHORIZE_PROD: &str = "https://www.billdesk.com/pgidsk/PGIDirectRequest?reqid=BDRDF011";
    pub const STATUS_UAT: &str = "https://uat.billdesk.com/pgidsk/PGIDirectRequest?reqid=BDRDF002";
    pub const STATUS_PROD: &str = "https://www.billdesk.com/pgidsk/PGIDirectRequest?reqid=BDRDF002";
    pub const REFUND_UAT: &str = "https://uat.billdesk.com/pgidsk/PGIDirectRequest?reqid=BDRDF003";
    pub const REFUND_PROD: &str = "https://www.billdesk.com/pgidsk/PGIDirectRequest?reqid=BDRDF003";
    pub const REFUND_STATUS_UAT: &str = "https://uat.billdesk.com/pgidsk/PGIDirectRequest?reqid=BDRDF004";
    pub const REFUND_STATUS_PROD: &str = "https://www.billdesk.com/pgidsk/PGIDirectRequest?reqid=BDRDF004";
}

// Request IDs for different operations
pub mod request_ids {
    pub const UPI_INITIATE: &str = "BDRDF011";
    pub const AUTHORIZATION: &str = "BDRDF002";
    pub const REFUND: &str = "BDRDF003";
    pub const REFUND_STATUS: &str = "BDRDF004";
    pub const NB_INITIATE: &str = "BDRDF005";
    pub const CARD_INITIATE: &str = "BDRDF006";
    pub const RECURRING: &str = "BDRDF007";
}

// Status mappings
pub mod status {
    pub const SUCCESS: &str = "0300";
    pub const PENDING: &str = "0399";
    pub const FAILURE: &str = "0398";
    pub const AUTH_PENDING: &str = "0397";
}

// Error codes
pub mod error_codes {
    pub const INVALID_REQUEST: &str = "4001";
    pub const INVALID_MERCHANT: &str = "4002";
    pub const INVALID_AMOUNT: &str = "4003";
    pub const INVALID_CURRENCY: &str = "4004";
    pub const INVALID_TXN_TYPE: &str = "4005";
    pub const INVALID_ITEM_CODE: &str = "4006";
    pub const INVALID_CUSTOMER_ID: &str = "4007";
    pub const INVALID_TXN_DATE: &str = "4008";
    pub const INVALID_CHECKSUM: &str = "4009";
    pub const DUPLICATE_TXN: &str = "4010";
    pub const TXN_NOT_FOUND: &str = "4011";
    pub const INSUFFICIENT_FUNDS: &str = "4012";
    pub const INVALID_UPI_HANDLE: &str = "4013";
    pub const UPI_TIMEOUT: &str = "4014";
    pub const UPI_DECLINED: &str = "4015";
}

// Transaction types
pub mod txn_types {
    pub const UPI: &str = "UPI";
    pub const NB: &str = "NB";
    pub const CARD: &str = "CARD";
    pub const RECURRING: &str = "RECURRING";
}

// Item codes
pub mod item_codes {
    pub const UPI: &str = "UPI";
    pub const NB: &str = "NB";
    pub const CARD: &str = "CARD";
    pub const RECURRING: &str = "RECURRING";
}

// Currency codes
pub mod currencies {
    pub const INR: &str = "356";
    pub const USD: &str = "840";
    pub const EUR: &str = "978";
    pub const GBP: &str = "826";
}

// Default values
pub mod defaults {
    pub const DEFAULT_TXN_TYPE: &str = "UPI";
    pub const DEFAULT_ITEM_CODE: &str = "UPI";
    pub const DEFAULT_CURRENCY: &str = "INR";
    pub const DEFAULT_TIMEOUT: u64 = 300; // 5 minutes
}