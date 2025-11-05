// ZaakPay API constants and endpoints

pub const ZAAKPAY_BASE_URL: &str = "https://api.zaakpay.com";
pub const ZAAKPAY_TRANSACT_URL: &str = "/transact";
pub const ZAAKPAY_CHECK_URL: &str = "/check";
pub const ZAAKPAY_UPDATE_URL: &str = "/update";

pub const ZAAKPAY_SUCCESS_CODE: &str = "100";
pub const ZAAKPAY_PENDING_CODE: &str = "001";
pub const ZAAKPAY_FAILURE_CODE: &str = "000";

pub const ZAAKPAY_MODE_LIVE: &str = "LIVE";
pub const ZAAKPAY_MODE_TEST: &str = "TEST";

pub const ZAAKPAY_PAYMENT_MODE_UPI: &str = "UPI";
pub const ZAAKPAY_PAYMENT_MODE_NETBANKING: &str = "NB";
pub const ZAAKPAY_PAYMENT_MODE_CARD: &str = "CC";

pub const ZAAKPAY_RESPONSE_SUCCESS: &str = "1";
pub const ZAAKPAY_RESPONSE_FAILURE: &str = "0";

pub const ZAAKPAY_TXN_STATUS_SUCCESS: &str = "SUCCESS";
pub const ZAAKPAY_TXN_STATUS_PENDING: &str = "PENDING";
pub const ZAAKPAY_TXN_STATUS_FAILURE: &str = "FAILURE";
pub const ZAAKPAY_TXN_STATUS_REFUNDED: &str = "REFUNDED";
pub const ZAAKPAY_TXN_STATUS_PARTIAL_REFUNDED: &str = "PARTIAL_REFUNDED";