// API Endpoints for TPSL connector
pub const TPSL_TRANSACTION_URL: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_AUTH_CAPTURE_URL: &str = "/PaymentGateway/merchant2.pg";
pub const TPSL_SI_TRANSACTION_URL: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_UPI_TRANSACTION_URL: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_UPI_TOKEN_GENERATION_URL: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_REFUND_ARN_SYNC_URL: &str = "/PaymentGateway/services/TransactionDetailsNew";

// Base URLs
pub const TPSL_PRODUCTION_BASE_URL: &str = "https://www.tpsl-india.in";
pub const TPSL_TEST_BASE_URL: &str = "https://www.tekprocess.co.in";

// Headers
pub const CONTENT_TYPE: &str = "Content-Type";
pub const AUTHORIZATION: &str = "Authorization";

// Content Types
pub const APPLICATION_JSON: &str = "application/json";
pub const APPLICATION_XML: &str = "application/xml";
pub const TEXT_XML: &str = "text/xml";

// Transaction Types
pub const TRANSACTION_TYPE_SALE: &str = "SALE";
pub const TRANSACTION_TYPE_AUTH: &str = "AUTH";
pub const TRANSACTION_TYPE_CAPTURE: &str = "CAPTURE";
pub const TRANSACTION_TYPE_REFUND: &str = "REFUND";
pub const TRANSACTION_TYPE_VOID: &str = "VOID";

// Payment Methods
pub const PAYMENT_METHOD_UPI: &str = "UPI";
pub const PAYMENT_METHOD_UPI_INTENT: &str = "UPI_INTENT";
pub const PAYMENT_METHOD_UPI_COLLECT: &str = "UPI_COLLECT";

// Status Mappings
pub const TPSL_STATUS_SUCCESS: &str = "SUCCESS";
pub const TPSL_STATUS_PENDING: &str = "PENDING";
pub const TPSL_STATUS_FAILURE: &str = "FAILURE";
pub const TPSL_STATUS_INITIATED: &str = "INITIATED";
pub const TPSL_STATUS_PROCESSING: &str = "PROCESSING";

// Error Codes
pub const TPSL_ERROR_INVALID_REQUEST: &str = "INVALID_REQUEST";
pub const TPSL_ERROR_AUTHENTICATION_FAILED: &str = "AUTHENTICATION_FAILED";
pub const TPSL_ERROR_INSUFFICIENT_FUNDS: &str = "INSUFFICIENT_FUNDS";
pub const TPSL_ERROR_TRANSACTION_DECLINED: &str = "TRANSACTION_DECLINED";
pub const TPSL_ERROR_TIMEOUT: &str = "TIMEOUT";
pub const TPSL_ERROR_INVALID_MERCHANT: &str = "INVALID_MERCHANT";

// Default Values
pub const DEFAULT_CURRENCY: &str = "INR";
pub const DEFAULT_COUNTRY: &str = "IN";