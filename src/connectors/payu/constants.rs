// Payu connector constants

pub const PAYU_API_VERSION: &str = "1";
pub const PAYU_DEFAULT_CURRENCY: &str = "INR";
pub const PAYU_COMMAND_UPI_COLLECT: &str = "upi_collect";
pub const PAYU_COMMAND_VERIFY_PAYMENT: &str = "verify_payment";
pub const PAYU_COMMAND_GET_REFUNDS: &str = "get_all_refunds_from_txn_ids";

// API endpoints
pub const PAYU_TEST_BASE_URL: &str = "https://test.payu.in";
pub const PAYU_PROD_BASE_URL: &str = "https://info.payu.in";
pub const PAYU_POST_SERVICE_PATH: &str = "/merchant/postservice.php?form=2";

// Status mappings
pub const PAYU_STATUS_SUCCESS: &str = "success";
pub const PAYU_STATUS_PENDING: &str = "pending";
pub const PAYU_STATUS_FAILURE: &str = "failure";
pub const PAYU_STATUS_SUCCESS_CODE: &str = "1";
pub const PAYU_STATUS_PENDING_CODE: &str = "0";
pub const PAYU_STATUS_FAILURE_CODE: &str = "-1";

// Error codes
pub const PAYU_ERROR_INVALID_REQUEST: &str = "INVALID_REQUEST";
pub const PAYU_ERROR_INVALID_HASH: &str = "INVALID_HASH";
pub const PAYU_ERROR_TRANSACTION_NOT_FOUND: &str = "TRANSACTION_NOT_FOUND";
pub const PAYU_ERROR_INSUFFICIENT_FUNDS: &str = "INSUFFICIENT_FUNDS";
pub const PAYU_ERROR_INVALID_VPA: &str = "INVALID_VPA";

// Default values
pub const PAYU_DEFAULT_PRODUCT_INFO: &str = "UPI Payment";
pub const PAYU_DEFAULT_TIMEOUT: u64 = 30; // seconds