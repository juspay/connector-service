// Payu connector constants - Migrated from Haskell implementation

// API versions
pub const API_VERSION: &str = "2.0";

// Device info
pub const DEVICE_INFO: &str = "web";

// UPI specific constants
pub const PRODUCT_INFO: &str = "Payment"; // Default product info
pub const UPI_PG: &str = "UPI"; // UPI payment gateway
pub const UPI_COLLECT_BANKCODE: &str = "UPI"; // UPI Collect bank code
pub const UPI_INTENT_BANKCODE: &str = "INTENT"; // UPI Intent bank code
pub const UPI_S2S_FLOW: &str = "2"; // S2S flow type for UPI

// PSync specific constants
pub const COMMAND: &str = "verify_payment";

// API endpoints (from Haskell Endpoints.hs)
pub const TEST_BASE_URL: &str = "https://test.payu.in";
pub const PROD_BASE_URL: &str = "https://info.payu.in";
pub const SECURE_BASE_URL: &str = "https://secure.payu.in"; // For payment endpoint
pub const POST_SERVICE_PATH: &str = "/merchant/postservice.php?form=2";
pub const PAYMENT_PATH: &str = "/_payment"; // For UPI transactions

// Status mappings (from Haskell types)
pub const STATUS_SUCCESS: &str = "success";
pub const STATUS_PENDING: &str = "pending";
pub const STATUS_FAILURE: &str = "failure";
pub const STATUS_SUCCESS_CODE: i32 = 1;
pub const STATUS_PENDING_CODE: i32 = 0;
pub const STATUS_FAILURE_CODE: i32 = -1;

// Error codes (from Haskell implementation)
pub const ERROR_INVALID_REQUEST: &str = "INVALID_REQUEST";
pub const ERROR_INVALID_HASH: &str = "INVALID_HASH";
pub const ERROR_TRANSACTION_NOT_FOUND: &str = "TRANSACTION_NOT_FOUND";
pub const ERROR_INSUFFICIENT_FUNDS: &str = "INSUFFICIENT_FUNDS";
pub const ERROR_INVALID_VPA: &str = "INVALID_VPA";

// Command constants (from Haskell Endpoints.hs)
pub const COMMAND_UPI_COLLECT: &str = "upi_collect";
pub const COMMAND_VERIFY_PAYMENT: &str = "verify_payment";
pub const COMMAND_GET_REFUNDS: &str = "get_all_refunds_from_txn_ids";
pub const COMMAND_EXERCISE_MANDATE: &str = "exercise_mandate";
pub const COMMAND_CHECK_OFFER: &str = "check_offer";

// Default values
pub const DEFAULT_PRODUCT_INFO: &str = "Payment";
pub const DEFAULT_TIMEOUT: u64 = 30; // seconds

// Hash separator
pub const HASH_SEPARATOR: &str = "|";