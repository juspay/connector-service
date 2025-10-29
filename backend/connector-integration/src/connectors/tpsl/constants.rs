pub const TPSL_BASE_URL_PROD: &str = "https://www.tpsl-india.in/PaymentGateway";
pub const TPSL_BASE_URL_TEST: &str = "https://www.tekprocess.co.in/PaymentGateway";

pub const TPSL_TRANSACTION_ENDPOINT: &str = "/services/TransactionDetailsNew";
pub const TPSL_AUTH_CAPTURE_ENDPOINT: &str = "/merchant2.pg";
pub const TPSL_SI_TRANSACTION_ENDPOINT: &str = "/services/SITransactionDetailsNew";
pub const TPSL_UPI_TRANSACTION_ENDPOINT: &str = "/services/UPITransactionDetailsNew";
pub const TPSL_UPI_TOKEN_GENERATION_ENDPOINT: &str = "/services/UPITokenGeneration";
pub const TPSL_REFUND_ARN_SYNC_ENDPOINT: &str = "/services/RefundArnSync";

// SOAP namespace constants
pub const SOAP_ENV_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";
pub const SOAP_XSD_NS: &str = "http://www.w3.org/2001/XMLSchema";
pub const SOAP_XSI_NS: &str = "http://www.w3.org/2001/XMLSchema-instance";

// TPSL specific constants
pub const TPSL_MERCHANT_CODE_HEADER: &str = "merchantCode";
pub const TPSL_MERCHANT_KEY_HEADER: &str = "merchantKey";
pub const TPSL_CONTENT_TYPE: &str = "application/json";

// Payment method codes
pub const TPSL_UPI_CODE: &str = "UPI";
pub const TPSL_UPI_COLLECT_TYPE: &str = "COLLECT";
pub const TPSL_UPI_INTENT_TYPE: &str = "INTENT";

// Transaction types
pub const TPSL_TXN_TYPE: &str = "TXN";
pub const TPSL_STATUS_TYPE: &str = "STATUS";

// Response status mapping
pub const TPSL_STATUS_SUCCESS: &str = "SUCCESS";
pub const TPSL_STATUS_SUCCESSFUL: &str = "SUCCESSFUL";
pub const TPSL_STATUS_PENDING: &str = "PENDING";
pub const TPSL_STATUS_FAILURE: &str = "FAILURE";
pub const TPSL_STATUS_FAILED: &str = "FAILED";