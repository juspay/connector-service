// TPSL Connector Constants

pub const TPSL_TRANSACTION_URL: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_AUTH_CAPTURE_URL: &str = "/PaymentGateway/merchant2.pg";
pub const TPSL_SI_TRANSACTION_URL: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_UPI_TRANSACTION_URL: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_UPI_TOKEN_GENERATION_URL: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_REFUND_ARN_SYNC_URL: &str = "/PaymentGateway/services/TransactionDetailsNew";

pub const TPSL_PRODUCTION_BASE_URL: &str = "https://www.tpsl-india.in";
pub const TPSL_TEST_BASE_URL: &str = "https://www.tekprocess.co.in";

pub const TPSL_SUCCESS_STATUS: &str = "SUCCESS";
pub const TPSL_FAILURE_STATUS: &str = "FAILURE";
pub const TPSL_PENDING_STATUS: &str = "PENDING";

pub const TPSL_UPI_PAYMENT_METHOD: &str = "UPI";
pub const TPSL_COLLECT_TYPE: &str = "COLLECT";
pub const TPSL_INTENT_TYPE: &str = "INTENT";

pub mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const AUTHORIZATION: &str = "Authorization";
    pub const ACCEPT: &str = "Accept";
    pub const USER_AGENT: &str = "User-Agent";
}

pub mod content_types {
    pub const APPLICATION_JSON: &str = "application/json";
    pub const APPLICATION_XML: &str = "application/xml";
    pub const TEXT_XML: &str = "text/xml";
    pub const FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
}