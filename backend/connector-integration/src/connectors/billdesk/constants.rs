pub mod constants {
    // Billdesk API endpoints
    pub const BILLDESK_UAT_BASE_URL: &str = "https://uat.billdesk.com/pgidsk/PGIDirectRequest";
    pub const BILLDESK_PROD_BASE_URL: &str = "https://www.billdesk.com/pgidsk/PGIDirectRequest";

    // Request IDs for different operations
    pub const BILLDESK_UPI_INITIATE_REQID: &str = "BDRDF011";
    pub const BILLDESK_AUTH_REQID: &str = "BDRDF002";
    pub const BILLDESK_STATUS_REQID: &str = "BDRDF002";
    pub const BILLDESK_REFUND_STATUS_REQID: &str = "REFUND_STATUS";

    // Payment status codes from Billdesk
    pub mod status_codes {
        pub const SUCCESS: &str = "0300";
        pub const SUCCESS_ALT: &str = "0399";
        pub const PENDING: &str = "0396";
        pub const FAILURE: &str = "0398";
        pub const AUTH_PENDING: &str = "0396";
    }

    // Transaction types
    pub mod txn_types {
        pub const UPI: &str = "UPI";
        pub const NB: &str = "NB";
        pub const CARD: &str = "CARD";
    }

    // Item codes
    pub mod item_codes {
        pub const DIRECT: &str = "DIRECT";
        pub const INTENT: &str = "INTENT";
    }

    // Error codes
    pub mod error_codes {
        pub const INVALID_REQUEST: &str = "1001";
        pub const INVALID_MERCHANT: &str = "1002";
        pub const INVALID_AMOUNT: &str = "1003";
        pub const INVALID_CURRENCY: &str = "1004";
        pub const TRANSACTION_NOT_FOUND: &str = "2001";
        pub const INVALID_CHECKSUM: &str = "3001";
    }

    // Currency codes
    pub mod currencies {
        pub const INR: &str = "356";
        pub const USD: &str = "840";
        pub const EUR: &str = "978";
    }

    // Default values
    pub mod defaults {
        pub const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        pub const DEFAULT_IP_ADDRESS: &str = "127.0.0.1";
        pub const DEFAULT_TIMEOUT: u64 = 30;
    }
}