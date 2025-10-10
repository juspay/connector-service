pub const BASE_URL: &str = "https://pay.easebuzz.in";

// Test environment URLs
pub const TEST_PAYMENT_INITIATE_URL: &str = "https://testpay.easebuzz.in/payment/initiateLink";
pub const TEST_TXN_SYNC_URL: &str = "https://testpay.easebuzz.in/transaction/v1/retrieve";
pub const TEST_REFUND_SYNC_URL: &str = "https://testpay.easebuzz.in/transaction/v1/refundSync";

// Production environment URLs
pub const PROD_PAYMENT_INITIATE_URL: &str = "https://pay.easebuzz.in/payment/initiateLink";
pub const PROD_TXN_SYNC_URL: &str = "https://pay.easebuzz.in/transaction/v1/retrieve";
pub const PROD_REFUND_SYNC_URL: &str = "https://pay.easebuzz.in/transaction/v1/refundSync";

// API endpoints
pub const PAYMENT_INITIATE_ENDPOINT: &str = "/payment/initiateLink";
pub const TXN_SYNC_ENDPOINT: &str = "/transaction/v1/retrieve";
pub const REFUND_SYNC_ENDPOINT: &str = "/transaction/v1/refundSync";

// Payment method types
pub const UPI_PAYMENT_SOURCE: &str = "upi";
pub const UPI_INTENT_PAYMENT_SOURCE: &str = "upi_intent";
pub const UPI_COLLECT_PAYMENT_SOURCE: &str = "upi_collect";

// Status mappings
pub const STATUS_SUCCESS: &str = "success";
pub const STATUS_FAILURE: &str = "failure";
pub const STATUS_PENDING: &str = "pending";
pub const STATUS_INITIATED: &str = "initiated";

// Response codes
pub const RESPONSE_CODE_SUCCESS: i32 = 1;
pub const RESPONSE_CODE_FAILURE: i32 = 0;
pub const RESPONSE_CODE_PENDING: i32 = 2;

// Hash algorithm
pub const HASH_ALGORITHM: &str = "sha512";

// Default values
pub const DEFAULT_PRODUCT_INFO: &str = "UPI Payment";
pub const DEFAULT_CURRENCY: &str = "INR";
pub const DEFAULT_PHONE: &str = "9999999999";

// UDF (User Defined Fields) mappings
pub const UDF_CURRENCY: &str = "udf1";
pub const UDF_PAYMENT_METHOD: &str = "udf2";
pub const UDF_MERCHANT_ORDER_ID: &str = "udf3";
pub const UDF_CUSTOMER_ID: &str = "udf4";
pub const UDF_DEVICE_ID: &str = "udf5";