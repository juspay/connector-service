// EaseBuzz Constants

pub const EASEBUZZ: &str = "easebuzz";

// API Endpoints
pub const EASEBUZZ_INITIATE_PAYMENT: &str = "/payment/initiateLink";
pub const EASEBUZZ_SEAMLESS_TRANSACTION: &str = "/payment/initiateLink";
pub const EASEBUZZ_TXN_SYNC: &str = "/payment/txnSync";
pub const EASEBUZZ_REFUND: &str = "/transaction/refund";
pub const EASEBUZZ_REFUND_SYNC: &str = "/transaction/refundSync";

// Base URLs
pub const EASEBUZZ_PRODUCTION_BASE_URL: &str = "https://pay.easebuzz.in";
pub const EASEBUZZ_TEST_BASE_URL: &str = "https://testpay.easebuzz.in";

// Payment Methods
pub const PAYMENT_SOURCE_UPI: &str = "upi";

// Status Codes
pub const STATUS_SUCCESS: i32 = 1;
pub const STATUS_FAILURE: i32 = 0;

// Response Status Values
pub const RESPONSE_STATUS_SUCCESS: &str = "success";
pub const RESPONSE_STATUS_FAILURE: &str = "failure";
pub const RESPONSE_STATUS_PENDING: &str = "pending";

// Hash Algorithm
pub const HASH_ALGORITHM: &str = "sha512";

// Default Values
pub const DEFAULT_PRODUCT_INFO: &str = "Payment";
pub const DEFAULT_FIRST_NAME: &str = "Customer";
pub const DEFAULT_USER_AGENT: &str = "Mozilla/5.0";
pub const DEFAULT_IP_ADDRESS: &str = "127.0.0.1";