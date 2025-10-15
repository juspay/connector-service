// API endpoints for EaseBuzz connector
pub const EASEBUZZ_INITIATE_PAYMENT: &str = "/payment/initiateLink";
pub const EASEBUZZ_SEAMLESS_TRANSACTION: &str = "/payment/seamless";
pub const EASEBUZZ_TXN_SYNC: &str = "/transaction/sync";
pub const EASEBUZZ_REFUND: &str = "/transaction/refund";
pub const EASEBUZZ_REFUND_SYNC: &str = "/transaction/refundSync";
pub const EASEBUZZ_UPI_AUTOPAY: &str = "/upi/autopay";
pub const EASEBUZZ_UPI_MANDATE_EXECUTE: &str = "/upi/mandate/execute";
pub const EASEBUZZ_MANDATE_RETRIEVE: &str = "/mandate/retrieve";
pub const EASEBUZZ_MANDATE_CREATE: &str = "/mandate/create";
pub const EASEBUZZ_ACCESS_KEY: &str = "/auth/accessKey";

// Base URLs
pub const EASEBUZZ_PRODUCTION_BASE_URL: &str = "https://pay.easebuzz.in";
pub const EASEBUZZ_TEST_BASE_URL: &str = "https://testpay.easebuzz.in";

// Headers
pub const CONTENT_TYPE: &str = "Content-Type";
pub const AUTHORIZATION: &str = "Authorization";
pub const ACCEPT: &str = "Accept";

// Content types
pub const APPLICATION_JSON: &str = "application/json";
pub const APPLICATION_X_WWW_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";

// Response status codes
pub const STATUS_SUCCESS: i32 = 1;
pub const STATUS_PENDING: i32 = 0;
pub const STATUS_FAILURE: i32 = -1;

// Payment modes
pub const PAYMENT_MODE_UPI: &str = "UPI";
pub const PAYMENT_MODE_UPI_INTENT: &str = "UPI_INTENT";
pub const PAYMENT_MODE_UPI_COLLECT: &str = "UPI_COLLECT";
pub const PAYMENT_MODE_UPI_QR: &str = "UPI_QR";

// Transaction types
pub const TXN_TYPE_SALE: &str = "SALE";
pub const TXN_TYPE_AUTH: &str = "AUTH";
pub const TXN_TYPE_CAPTURE: &str = "CAPTURE";

// Mandate types
pub const MANDATE_TYPE_EMANDATE: &str = "EMANDATE";
pub const MANDATE_TYPE_UPI_AUTOPAY: &str = "UPI_AUTOPAY";