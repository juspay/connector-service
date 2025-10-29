pub const TPSL_BASE_URL_PROD: &str = "https://www.tpsl-india.in";
pub const TPSL_BASE_URL_TEST: &str = "https://www.tekprocess.co.in";

pub const TPSL_TRANSACTION_ENDPOINT: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_AUTH_CAPTURE_ENDPOINT: &str = "/PaymentGateway/merchant2.pg";
pub const TPSL_SI_TRANSACTION_ENDPOINT: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_UPI_TRANSACTION_ENDPOINT: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_UPI_TOKEN_GENERATION_ENDPOINT: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_REFUND_ARN_SYNC_ENDPOINT: &str = "/PaymentGateway/services/TransactionDetailsNew";

pub const TPSL_SUCCESS_STATUS: &str = "success";
pub const TPSL_PENDING_STATUS: &str = "pending";
pub const TPSL_FAILURE_STATUS: &str = "failure";
pub const TPSL_PROCESSING_STATUS: &str = "processing";

pub const TPSL_UPI_PAYMENT_METHOD: &str = "UPI";
pub const TPSL_SALE_TRANSACTION_TYPE: &str = "SALE";
pub const TPSL_DEBIT_SUBTYPE: &str = "DEBIT";
pub const TPSL_CREDIT_SUBTYPE: &str = "CREDIT";
pub const TPSL_TXN_REQUEST_TYPE: &str = "TXN";
pub const TPSL_STATUS_REQUEST_TYPE: &str = "STATUS";

pub const TPSL_DEVICE_IDENTIFIER_WEB: &str = "WEB";
pub const TPSL_DEVICE_IDENTIFIER_MOBILE: &str = "MOBILE";

pub const TPSL_RESPONSE_TYPE_TXN: &str = "TXN";
pub const TPSL_RESPONSE_TYPE_SYNC: &str = "SYNC";