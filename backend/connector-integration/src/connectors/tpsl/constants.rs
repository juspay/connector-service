pub mod constants;

pub const TPSL_BASE_URL_PROD: &str = "https://www.tpsl-india.in";
pub const TPSL_BASE_URL_TEST: &str = "https://www.tekprocess.co.in";

pub const TPSL_TRANSACTION_ENDPOINT: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_AUTH_CAPTURE_ENDPOINT: &str = "/PaymentGateway/merchant2.pg";
pub const TPSL_SI_TRANSACTION_ENDPOINT: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_UPI_TRANSACTION_ENDPOINT: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_UPI_TOKEN_GENERATION_ENDPOINT: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_REFUND_ARN_SYNC_ENDPOINT: &str = "/PaymentGateway/services/TransactionDetailsNew";

// API Tags for different flows
pub const API_TAG_TRANSACTION: &str = "tpsl_transaction";
pub const API_TAG_AUTH_CAPTURE: &str = "tpsl_auth_capture";
pub const API_TAG_SI_TRANSACTION: &str = "tpsl_si_transaction";
pub const API_TAG_UPI_TRANSACTION: &str = "tpsl_upi_transaction";
pub const API_TAG_UPI_TOKEN_GENERATION: &str = "tpsl_upi_token_generation";
pub const API_TAG_REFUND_ARN_SYNC: &str = "tpsl_refund_arn_sync";

// Status mappings
pub const TPSL_STATUS_SUCCESS: &str = "SUCCESS";
pub const TPSL_STATUS_SUCCESSFUL: &str = "SUCCESSFUL";
pub const TPSL_STATUS_PENDING: &str = "PENDING";
pub const TPSL_STATUS_FAILURE: &str = "FAILURE";
pub const TPSL_STATUS_FAILED: &str = "FAILED";

// Error codes
pub const TPSL_ERROR_INVALID_REQUEST: &str = "INVALID_REQUEST";
pub const TPSL_ERROR_AUTHENTICATION_FAILED: &str = "AUTHENTICATION_FAILED";
pub const TPSL_ERROR_TRANSACTION_NOT_FOUND: &str = "TRANSACTION_NOT_FOUND";
pub const TPSL_ERROR_INSUFFICIENT_FUNDS: &str = "INSUFFICIENT_FUNDS";
pub const TPSL_ERROR_INVALID_MERCHANT: &str = "INVALID_MERCHANT";

// Payment method types
pub const TPSL_PAYMENT_METHOD_UPI: &str = "UPI";
pub const TPSL_PAYMENT_METHOD_CREDIT_CARD: &str = "CREDIT_CARD";
pub const TPSL_PAYMENT_METHOD_DEBIT_CARD: &str = "DEBIT_CARD";
pub const TPSL_PAYMENT_METHOD_NET_BANKING: &str = "NET_BANKING";
pub const TPSL_PAYMENT_METHOD_WALLET: &str = "WALLET";

// Transaction types
pub const TPSL_TRANSACTION_TYPE_SALE: &str = "SALE";
pub const TPSL_TRANSACTION_TYPE_AUTH: &str = "AUTH";
pub const TPSL_TRANSACTION_TYPE_CAPTURE: &str = "CAPTURE";
pub const TPSL_TRANSACTION_TYPE_REFUND: &str = "REFUND";
pub const TPSL_TRANSACTION_TYPE_VOID: &str = "VOID";

// Request types
pub const TPSL_REQUEST_TYPE_TXN: &str = "TXN";
pub const TPSL_REQUEST_TYPE_SYNC: &str = "SYNC";
pub const TPSL_REQUEST_TYPE_REFUND: &str = "REFUND";
pub const TPSL_REQUEST_TYPE_STATUS: &str = "STATUS";

// Sub types
pub const TPSL_SUB_TYPE_UPI: &str = "UPI";
pub const TPSL_SUB_TYPE_UPI_INTENT: &str = "UPI_INTENT";
pub const TPSL_SUB_TYPE_UPI_COLLECT: &str = "UPI_COLLECT";
pub const TPSL_SUB_TYPE_CARD: &str = "CARD";
pub const TPSL_SUB_TYPE_NB: &str = "NB";

// Device identifiers
pub const TPSL_DEVICE_WEB: &str = "WEB";
pub const TPSL_DEVICE_MOBILE: &str = "MOBILE";
pub const TPSL_DEVICE_APP: &str = "APP";

// Currency codes (commonly used)
pub const TPSL_CURRENCY_INR: &str = "INR";
pub const TPSL_CURRENCY_USD: &str = "USD";
pub const TPSL_CURRENCY_EUR: &str = "EUR";
pub const TPSL_CURRENCY_GBP: &str = "GBP";

// Default values
pub const TPSL_DEFAULT_DESCRIPTION: &str = "Payment Transaction";
pub const TPSL_DEFAULT_ITEM_IDENTIFIER: &str = "ITEM_1";
pub const TPSL_DEFAULT_ITEM_SKU: &str = "DEFAULT_SKU";