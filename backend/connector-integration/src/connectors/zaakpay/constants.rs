// ZaakPay API constants and configurations

pub const ZAAKPAY_API_BASE_URL: &str = "https://api.zaakpay.com";
pub const ZAAKPAY_TRANSACT_ENDPOINT: &str = "/transact";
pub const ZAAKPAY_CHECK_ENDPOINT: &str = "/check";
pub const ZAAKPAY_UPDATE_ENDPOINT: &str = "/update";

pub const ZAAKPAY_SUCCESS_RESPONSE_CODE: &str = "100";
pub const ZAAKPAY_PENDING_RESPONSE_CODE: &str = "001";
pub const ZAAKPAY_FAILURE_RESPONSE_CODE: &str = "000";

pub const ZAAKPAY_MODE_LIVE: &str = "LIVE";
pub const ZAAKPAY_MODE_TEST: &str = "TEST";

pub const ZAAKPAY_PAYMENT_MODE_UPI: &str = "UPI";
pub const ZAAKPAY_PAYMENT_MODE_NETBANKING: &str = "NB";
pub const ZAAKPAY_PAYMENT_MODE_CARD: &str = "CC";

pub const ZAAKPAY_DEFAULT_CURRENCY: &str = "INR";

pub const ZAAKPAY_CHECKSUM_ALGORITHM: &str = "SHA256";

// Headers
pub const ZAAKPAY_HEADER_CONTENT_TYPE: &str = "Content-Type";
pub const ZAAKPAY_HEADER_ACCEPT: &str = "Accept";
pub const ZAAKPAY_HEADER_USER_AGENT: &str = "User-Agent";

// Default values
pub const ZAAKPAY_DEFAULT_CONTENT_TYPE: &str = "application/json";
pub const ZAAKPAY_DEFAULT_ACCEPT: &str = "application/json";
pub const ZAAKPAY_DEFAULT_USER_AGENT: &str = "Hyperswitch-UCS/1.0";