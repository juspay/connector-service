pub const EASEBUZZ_BASE_URL: &str = "https://pay.easebuzz.in";
pub const EASEBUZZ_TEST_BASE_URL: &str = "https://testpay.easebuzz.in";

// API Endpoints
pub const EASEBUZZ_INITIATE_PAYMENT: &str = "/payment/initiateLink";
pub const EASEBUZZ_SEAMLESS_TRANSACTION: &str = "/payment/seamless";
pub const EASEBUZZ_TRANSACTION_SYNC: &str = "/transaction/status";
pub const EASEBUZZ_REFUND: &str = "/transaction/refund";
pub const EASEBUZZ_REFUND_SYNC: &str = "/transaction/refundStatus";

// Headers
pub const EASEBUZZ_AUTH_HEADER: &str = "Authorization";
pub const EASEBUZZ_CONTENT_TYPE: &str = "application/json";

// Payment Methods
pub const EASEBUZZ_UPI: &str = "UPI";
pub const EASEBUZZ_UPI_INTENT: &str = "UPI_INTENT";
pub const EASEBUZZ_UPI_COLLECT: &str = "UPI_COLLECT";

// Status Codes
pub const EASEBUZZ_STATUS_SUCCESS: i32 = 1;
pub const EASEBUZZ_STATUS_PENDING: i32 = 0;
pub const EASEBUZZ_STATUS_FAILURE: i32 = -1;

// Response Status
pub const EASEBUZZ_RESPONSE_SUCCESS: &str = "success";
pub const EASEBUZZ_RESPONSE_FAILURE: &str = "failure";
pub const EASEBUZZ_RESPONSE_PENDING: &str = "pending";