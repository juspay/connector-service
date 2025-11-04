pub const API_BASE_URL: &str = "https://api.zaakpay.com";
pub const TRANSACTION_AUTHORIZE_ENDPOINT: &str = "/transaction/authorize";
pub const TRANSACTION_CHECK_ENDPOINT: &str = "/transaction/check";
pub const TRANSACTION_UPDATE_ENDPOINT: &str = "/transaction/update";

pub const MODE_LIVE: &str = "1";
pub const MODE_TEST: &str = "0";

pub const RESPONSE_CODE_SUCCESS: &str = "100";
pub const RESPONSE_CODE_REDIRECT: &str = "101";
pub const RESPONSE_CODE_FAILURE: &str = "102";

pub const PAYMENT_MODE_UPI: &str = "upi";
pub const PAYMENT_MODE_NETBANKING: &str = "netbanking";
pub const PAYMENT_MODE_CARD: &str = "card";

pub const DEFAULT_COUNTRY: &str = "IN"; // Default to India for UPI payments