// EaseBuzz API endpoints based on the Haskell implementation

// UPI Intent/Collect endpoints
pub const EASEBUZZ_UPI_INTENT_TEST_ENDPOINT: &str = "/initiate_seamless_payment/";
pub const EASEBUZZ_UPI_INTENT_PROD_ENDPOINT: &str = "/initiate_seamless_payment/";

// Transaction sync endpoints
pub const EASEBUZZ_TXN_SYNC_TEST_ENDPOINT: &str = "/transaction/v1/retrieve";
pub const EASEBUZZ_TXN_SYNC_PROD_ENDPOINT: &str = "/transaction/v1/retrieve";

// Refund endpoints
pub const EASEBUZZ_REFUND_TEST_ENDPOINT: &str = "/transaction/v2/refund";
pub const EASEBUZZ_REFUND_PROD_ENDPOINT: &str = "/transaction/v2/refund";

// Refund sync endpoints
pub const EASEBUZZ_REFUND_SYNC_TEST_ENDPOINT: &str = "/refund/v1/retrieve";
pub const EASEBUZZ_REFUND_SYNC_PROD_ENDPOINT: &str = "/refund/v1/retrieve";

// Base URLs (these will be configured in the connector config)
pub const EASEBUZZ_TEST_BASE_URL: &str = "https://testpay.easebuzz.in";
pub const EASEBUZZ_PROD_BASE_URL: &str = "https://pay.easebuzz.in";

// Dashboard URLs for sync operations
pub const EASEBUZZ_DASHBOARD_TEST_BASE_URL: &str = "https://testdashboard.easebuzz.in";
pub const EASEBUZZ_DASHBOARD_PROD_BASE_URL: &str = "https://dashboard.easebuzz.in";

// Payment method constants
pub const UPI_PAYMENT_METHOD: &str = "upi";
pub const UPI_INTENT_MODE: &str = "intent";
pub const UPI_COLLECT_MODE: &str = "collect";

// Hash algorithm constants
pub const HASH_ALGORITHM: &str = "sha512";

// Default values
pub const DEFAULT_PRODUCT_INFO: &str = "UPI Payment";
pub const DEFAULT_PHONE: &str = "9999999999";
pub const DEFAULT_FIRSTNAME: &str = "Customer";

// Status constants
pub const STATUS_SUCCESS: &str = "success";
pub const STATUS_FAILURE: &str = "failure";
pub const STATUS_PENDING: &str = "pending";

// Error codes
pub const ERROR_INVALID_HASH: &str = "INVALID_HASH";
pub const ERROR_INVALID_MERCHANT: &str = "INVALID_MERCHANT";
pub const ERROR_TRANSACTION_NOT_FOUND: &str = "TRANSACTION_NOT_FOUND";
pub const ERROR_INSUFFICIENT_BALANCE: &str = "INSUFFICIENT_BALANCE";
pub const ERROR_PAYMENT_FAILED: &str = "PAYMENT_FAILED";