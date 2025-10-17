pub mod api;

pub const ZAAKPAY: &str = "zaakpay";

// API endpoints
pub mod api {
    pub const TRANSACTION_API: &str = "/transaction/.do";
    pub const CHECK_API: &str = "/check.do";
    pub const UPDATE_API: &str = "/update.do";
}

// Response codes
pub mod response_codes {
    pub const SUCCESS: &str = "100";
    pub const PENDING: &str = "101";
    pub const FAILURE: &str = "102";
    pub const INVALID_REQUEST: &str = "103";
    pub const AUTHENTICATION_FAILED: &str = "104";
    pub const INVALID_CHECKSUM: &str = "105";
}

// Transaction modes
pub mod modes {
    pub const TEST: &str = "0";
    pub const LIVE: &str = "1";
}

// Payment modes
pub mod payment_modes {
    pub const UPI: &str = "upi";
    pub const NETBANKING: &str = "netbanking";
    pub const CARD: &str = "card";
}

// Default values
pub mod defaults {
    pub const DEFAULT_CURRENCY: &str = "INR";
    pub const DEFAULT_COUNTRY: &str = "IN";
    pub const DEFAULT_PHONE: &str = "0000000000";
    pub const DEFAULT_ADDRESS: &str = "Default Address";
    pub const DEFAULT_CITY: &str = "Default City";
    pub const DEFAULT_STATE: &str = "Default State";
    pub const DEFAULT_PINCODE: &str = "000000";
}