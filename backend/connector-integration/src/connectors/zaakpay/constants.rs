// ZaakPay API constants and endpoints

pub const ZAAKPAY_API_BASE_URL: &str = "https://api.zaakpay.com";
pub const ZAAKPAY_TRANSACTION_ENDPOINT: &str = "/transaction/.do";
pub const ZAAKPAY_CHECK_STATUS_ENDPOINT: &str = "/checkStatus/.do";

// Response codes
pub const ZAAKPAY_SUCCESS_CODE: &str = "100";
pub const ZAAKPAY_PENDING_CODE: &str = "101";
pub const ZAAKPAY_FAILURE_CODE: &str = "102";

// Payment modes
pub const ZAAKPAY_UPI_MODE: &str = "upi";
pub const ZAAKPAY_CARD_MODE: &str = "card";
pub const ZAAKPAY_NETBANKING_MODE: &str = "netbanking";

// Environment modes
pub const ZAAKPAY_LIVE_MODE: &str = "1";
pub const ZAAKPAY_TEST_MODE: &str = "0";