use common_utils::consts;

pub const ZAAKPAY_API_BASE_URL: &str = "https://api.zaakpay.com";

pub const ZAAKPAY_AUTHORIZE_URL: &str = "/transaction/.do";
pub const ZAAKPAY_STATUS_URL: &str = "/status.do";

pub const ZAAKPAY_MODE_TEST: &str = "0";
pub const ZAAKPAY_MODE_LIVE: &str = "1";

pub const ZAAKPAY_PAYMENT_MODE_UPI: &str = "upi";

pub const ZAAKPAY_RESPONSE_CODE_SUCCESS: &str = "200";
pub const ZAAKPAY_RESPONSE_CODE_PENDING: &str = "201";
pub const ZAAKPAY_RESPONSE_CODE_AUTH_FAILED: &str = "100";
pub const ZAAKPAY_RESPONSE_CODE_INVALID_REQUEST: &str = "101";
pub const ZAAKPAY_RESPONSE_CODE_SYSTEM_ERROR: &str = "102";
pub const ZAAKPAY_RESPONSE_CODE_INVALID_DATA: &str = "103";

pub const ZAAKPAY_TXN_STATUS_SUCCESS: &str = "success";
pub const ZAAKPAY_TXN_STATUS_PENDING: &str = "pending";
pub const ZAAKPAY_TXN_STATUS_FAILURE: &str = "failure";

pub const ZAAKPAY_CURRENCY_INR: &str = "INR";
pub const ZAAKPAY_COUNTRY_IN: &str = "IN";

pub const ZAAKPAY_DEFAULT_PINCODE: &str = "110001";
pub const ZAAKPAY_DEFAULT_PHONE: &str = "9999999999";