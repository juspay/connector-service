// TPSL API constants and endpoints

pub const TPSL_TRANSACTION_URL: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_AUTH_CAPTURE_URL: &str = "/PaymentGateway/merchant2.pg";
pub const TPSL_SI_TRANSACTION_URL: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_UPI_TRANSACTION_URL: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_UPI_TOKEN_GENERATION_URL: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_REFUND_ARN_SYNC_URL: &str = "/PaymentGateway/services/TransactionDetailsNew";

pub const TPSL_PRODUCTION_BASE_URL: &str = "https://www.tpsl-india.in";
pub const TPSL_TEST_BASE_URL: &str = "https://www.tekprocess.co.in";

pub mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const AUTHORIZATION: &str = "Authorization";
}