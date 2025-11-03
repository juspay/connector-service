// Payu API constants and endpoints
// Based on Haskell Endpoints.hs implementation

pub const API_VERSION: &str = "2.0";

// Payu device info
pub const DEVICE_INFO: &str = "web";

// Payu UPI specific constants
pub const PRODUCT_INFO: &str = "Payment"; // Default product info
pub const UPI_PG: &str = "UPI"; // UPI payment gateway
pub const UPI_COLLECT_BANKCODE: &str = "UPI"; // UPI Collect bank code
pub const UPI_INTENT_BANKCODE: &str = "INTENT"; // UPI Intent bank code
pub const UPI_S2S_FLOW: &str = "2"; // S2S flow type for UPI

// Payu PSync specific constants
pub const COMMAND: &str = "verify_payment";

// Payu API endpoints based on Haskell Endpoints.hs
pub const TEST_PAYMENT_URL: &str = "https://test.payu.in/_payment";
pub const PROD_PAYMENT_URL: &str = "https://secure.payu.in/_payment";
pub const TEST_VERIFY_URL: &str = "https://test.payu.in/merchant/postservice.php?form=2";
pub const PROD_VERIFY_URL: &str = "https://info.payu.in/merchant/postservice.php?form=2";

// Payu hash algorithm
pub const HASH_ALGORITHM: &str = "sha512";

// Payu response status values
pub const STATUS_SUCCESS_INT: i32 = 1;
pub const STATUS_ERROR_INT: i32 = 0;
pub const STATUS_SUCCESS_STRING: &str = "success";
pub const STATUS_PENDING: &str = "pending";
pub const STATUS_FAILURE: &str = "failure";
pub const STATUS_FAILED: &str = "failed";
pub const STATUS_CANCEL: &str = "cancel";
pub const STATUS_CANCELLED: &str = "cancelled";

// Payu field mappings for UPI transactions
pub const FIELD_UPI_TXN_ID: &str = "field1"; // UPI transaction ID
pub const FIELD_BANK_REF_NUM: &str = "field2"; // Bank reference number
pub const FIELD_PAYMENT_SOURCE: &str = "field3"; // Payment source
pub const FIELD_ADDITIONAL: &str = "field9"; // Additional field

// Payu error codes
pub const ERROR_CODE_PREFIX: &str = "PAYU_";
pub const SYNC_ERROR_CODE: &str = "PAYU_SYNC_ERROR";
pub const TRANSACTION_NOT_FOUND: &str = "TRANSACTION_NOT_FOUND";
pub const UNKNOWN_ERROR: &str = "UNKNOWN_ERROR";