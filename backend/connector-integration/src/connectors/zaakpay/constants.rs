// ZaakPay API constants and endpoints

pub const ZAAKPAY_BASE_URL: &str = "https://zaakpay.com";
pub const ZAAKPAY_TEST_URL: &str = "https://zaakpay.com";

// API endpoints
pub const ZAAKPAY_TRANSACT_ENDPOINT: &str = "/transact";
pub const ZAAKPAY_CHECK_ENDPOINT: &str = "/check";
pub const ZAAKPAY_UPDATE_ENDPOINT: &str = "/update";

// Response codes
pub const ZAAKPAY_SUCCESS_CODE: &str = "100";
pub const ZAAKPAY_PENDING_CODE: &str = "101";
pub const ZAAKPAY_FAILURE_CODE: &str = "102";

// Payment modes
pub const ZAAKPAY_UPI_MODE: &str = "upi";
pub const ZAAKPAY_CARD_MODE: &str = "card";
pub const ZAAKPAY_NETBANKING_MODE: &str = "netbanking";

// Environment modes
pub const ZAAKPAY_LIVE_MODE: &str = "live";
pub const ZAAKPAY_TEST_MODE: &str = "test";

// Redirect flags
pub const ZAAKPAY_REDIRECT_TRUE: &str = "true";
pub const ZAAKPAY_REDIRECT_FALSE: &str = "false";

// Transaction statuses
pub const ZAAKPAY_TXN_SUCCESS: &str = "success";
pub const ZAAKPAY_TXN_PENDING: &str = "pending";
pub const ZAAKPAY_TXN_FAILURE: &str = "failure";

// Headers
pub const ZAAKPAY_AUTH_HEADER: &str = "Authorization";
pub const ZAAKPAY_SIGNATURE_HEADER: &str = "x-zaakpay-signature";
pub const ZAAKPAY_CONTENT_TYPE: &str = "application/json";