// TPSL API endpoints based on Haskell implementation
pub const TPSL_TRANSACTION_ENDPOINT: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_AUTH_CAPTURE_ENDPOINT: &str = "/PaymentGateway/merchant2.pg/:merchantCode";
pub const TPSL_SI_TRANSACTION_ENDPOINT: &str = "/mobile/paynimoV2.req";
pub const TPSL_UPI_TRANSACTION_ENDPOINT: &str = "/api/PaynimoEncNew.jsp";
pub const TPSL_UPI_TOKEN_GENERATION_ENDPOINT: &str = "/api/paynimoV2.req";
pub const TPSL_REFUND_ARN_SYNC_ENDPOINT: &str = "/PaymentGateway/ARNPullAPI.jsp";

// Base URLs
pub const TPSL_PRODUCTION_BASE_URL: &str = "https://www.tpsl-india.in";
pub const TPSL_TEST_BASE_URL: &str = "https://www.tekprocess.co.in";
pub const TPSL_PAYNIMO_BASE_URL: &str = "https://www.paynimo.com";

// Headers
pub const CONTENT_TYPE: &str = "Content-Type";
pub const AUTHORIZATION: &str = "Authorization";