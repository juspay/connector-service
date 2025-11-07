pub const TPSL_PROD_BASE_URL: &str = "https://www.tpsl-india.in";
pub const TPSL_TEST_BASE_URL: &str = "https://www.tekprocess.co.in";

// Core transaction endpoints based on Haskell implementation
pub const TPSL_TRANSACTION_ENDPOINT: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_AUTH_CAPTURE_ENDPOINT: &str = "/PaymentGateway/merchant2.pg";
pub const TPSL_SI_TRANSACTION_ENDPOINT: &str = "/PaymentGateway/services/TransactionDetailsNew";

// UPI specific endpoints based on Haskell implementation
pub const TPSL_UPI_TRANSACTION_ENDPOINT: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_UPI_TOKEN_GENERATION_ENDPOINT: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_UPI_SYNC_ENDPOINT: &str = "/PaymentGateway/services/TransactionDetailsNew";

// Additional endpoints from Haskell implementation
pub const TPSL_REFUND_ARN_SYNC_ENDPOINT: &str = "/PaymentGateway/services/TransactionDetailsNew";

// UPI specific constants
pub const TPSL_UPI_INTENT_METHOD: &str = "UPI_INTENT";
pub const TPSL_UPI_COLLECT_METHOD: &str = "UPI_COLLECT";
pub const TPSL_UPI_PROVIDER: &str = "TECHPROCESS";

// Transaction types from Haskell implementation
pub const TPSL_TXN_TYPE_SALE: &str = "SALE";
pub const TPSL_TXN_TYPE_STATUS: &str = "STATUS";
pub const TPSL_REQUEST_TYPE_SALE: &str = "SALE";

// Response types from Haskell implementation
pub const TPSL_RESPONSE_TYPE_URL: &str = "URL";
pub const TPSL_RESPONSE_TYPE_JSON: &str = "JSON";