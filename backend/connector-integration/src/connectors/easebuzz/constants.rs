// API Constants for EaseBuzz Connector

pub const TEST_BASE_URL: &str = "https://testpay.easebuzz.in";
pub const PROD_BASE_URL: &str = "https://pay.easebuzz.in";

pub const INITIATE_PAYMENT_PATH: &str = "/payment/initiateLink";
pub const SEAMLESS_TRANSACTION_PATH: &str = "/transaction/v1/secure";
pub const TRANSACTION_SYNC_PATH: &str = "/transaction/v1/sync";
pub const REFUND_PATH: &str = "/transaction/v1/refund";
pub const REFUND_SYNC_PATH: &str = "/transaction/v1/refundStatus";

pub const CONTENT_TYPE: &str = "Content-Type";
pub const AUTHORIZATION: &str = "Authorization";
pub const ACCEPT: &str = "Accept";

pub const APPLICATION_JSON: &str = "application/json";
pub const APPLICATION_X_WWW_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";