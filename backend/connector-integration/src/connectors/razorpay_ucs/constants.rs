// API Endpoints for Razorpay UCS UPI flows
pub const UPI_PAYMENT_CREATE_ENDPOINT: &str = "v1/payments/create/upi";
pub const PAYMENT_SYNC_ENDPOINT: &str = "v1/payments";
pub const ORDER_CREATE_ENDPOINT: &str = "v1/orders";
pub const REFUND_CREATE_ENDPOINT: &str = "v1/payments/{}/refund";
pub const REFUND_SYNC_ENDPOINT: &str = "v1/refunds";

// Payment method constants
pub const UPI_COLLECT_METHOD: &str = "upi";
pub const UPI_INTENT_METHOD: &str = "upi";

// Status constants based on Razorpay API documentation
pub const STATUS_CREATED: &str = "created";
pub const STATUS_AUTHORIZED: &str = "authorized";
pub const STATUS_CAPTURED: &str = "captured";
pub const STATUS_REFUNDED: &str = "refunded";
pub const STATUS_FAILED: &str = "failed";
pub const STATUS_CANCELLED: &str = "cancelled";

// Error codes from Razorpay API
pub const ERROR_CODE_GATEWAY: &str = "GATEWAY_ERROR";
pub const ERROR_CODE_BAD_REQUEST: &str = "BAD_REQUEST_ERROR";
pub const ERROR_CODE_AUTHENTICATION: &str = "AUTHENTICATION_ERROR";
pub const ERROR_CODE_AUTHORIZATION: &str = "AUTHORIZATION_ERROR";
pub const ERROR_CODE_SERVER: &str = "SERVER_ERROR";

// UPI specific constants
pub const UPI_VPA_SEPARATOR: char = '@';
pub const MIN_VPA_LENGTH: usize = 3;

// Request timeouts (in seconds)
pub const PAYMENT_REQUEST_TIMEOUT: u64 = 30;
pub const SYNC_REQUEST_TIMEOUT: u64 = 15;

// Currency conversion constants
pub const PAISA_TO_RUPEE_CONVERSION: i64 = 100;

// API Tag constants for different flows
pub const API_TAG_PAYMENT_CREATE: &str = "GW_INIT_INTENT";
pub const API_TAG_PAYMENT_SYNC: &str = "GW_SYNC_PAYMENT";
pub const API_TAG_ORDER_CREATE: &str = "GW_CREATE_ORDER";
pub const API_TAG_REFUND_CREATE: &str = "GW_REFUND";
pub const API_TAG_REFUND_SYNC: &str = "GW_SYNC_REFUND";

// Headers
pub const HEADER_CONTENT_TYPE: &str = "Content-Type";
pub const HEADER_AUTHORIZATION: &str = "Authorization";
pub const HEADER_USER_AGENT: &str = "User-Agent";

// Content types
pub const CONTENT_TYPE_JSON: &str = "application/json";
pub const CONTENT_TYPE_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";

// Razorpay specific prefixes
pub const PAYMENT_ID_PREFIX: &str = "pay_";
pub const ORDER_ID_PREFIX: &str = "order_";
pub const REFUND_ID_PREFIX: &str = "rfnd_";
pub const CUSTOMER_ID_PREFIX: &str = "cust_";

// UPI flow constants based on Haskell implementation
pub const UPI_COLLECT_FLOW: &str = "collect";
pub const UPI_INTENT_FLOW: &str = "intent";

// Default values
pub const DEFAULT_DESCRIPTION: &str = "Payment via Hyperswitch";
pub const DEFAULT_CURRENCY: &str = "INR";

// Webhook constants
pub const WEBHOOK_EVENT_PAYMENT_CAPTURED: &str = "payment.captured";
pub const WEBHOOK_EVENT_PAYMENT_FAILED: &str = "payment.failed";
pub const WEBHOOK_EVENT_REFUND_PROCESSED: &str = "refund.processed";
pub const WEBHOOK_SIGNATURE_HEADER: &str = "x-razorpay-signature";

// Retry constants
pub const MAX_RETRIES: u32 = 3;
pub const RETRY_DELAY_MS: u64 = 1000;

// Amount validation constants
pub const MIN_PAYMENT_AMOUNT: i64 = 100; // 1 INR in paisa
pub const MAX_PAYMENT_AMOUNT: i64 = 50000000; // 5 lakh INR in paisa

// UPI validation constants
pub const VALID_UPI_HANDLES: &[&str] = &[
    "paytm", "googlepay", "phonepe", "bhim", "upi", "okaxis", "okhdfcbank", 
    "okicici", "oksbi", "ybl", "ibl", "apl", "axl"
];

// Error messages
pub const ERROR_INVALID_VPA: &str = "Invalid UPI VPA format";
pub const ERROR_UNSUPPORTED_PAYMENT_METHOD: &str = "Payment method not supported for UPI";
pub const ERROR_INVALID_AMOUNT: &str = "Invalid payment amount";
pub const ERROR_MISSING_REQUIRED_FIELD: &str = "Missing required field";

// Response field names (for JSON parsing)
pub const FIELD_ID: &str = "id";
pub const FIELD_ENTITY: &str = "entity";
pub const FIELD_AMOUNT: &str = "amount";
pub const FIELD_CURRENCY: &str = "currency";
pub const FIELD_STATUS: &str = "status";
pub const FIELD_ORDER_ID: &str = "order_id";
pub const FIELD_METHOD: &str = "method";
pub const FIELD_VPA: &str = "vpa";
pub const FIELD_ERROR_CODE: &str = "error_code";
pub const FIELD_ERROR_DESCRIPTION: &str = "error_description";
pub const FIELD_ERROR_REASON: &str = "error_reason";
pub const FIELD_ERROR_SOURCE: &str = "error_source";
pub const FIELD_ERROR_STEP: &str = "error_step";
pub const FIELD_CREATED_AT: &str = "created_at";

// Notes field names for UPI transactions
pub const NOTE_TRANSACTION_ID: &str = "transaction_id";
pub const NOTE_PAYMENT_ID: &str = "payment_id";
pub const NOTE_UPI_MODE: &str = "upi_mode";
pub const NOTE_VPA_ID: &str = "vpa_id";

// Environment constants
#[cfg(feature = "sandbox")]
pub const DEFAULT_BASE_URL: &str = "https://api.razorpay.com/";

#[cfg(not(feature = "sandbox"))]
pub const DEFAULT_BASE_URL: &str = "https://api.razorpay.com/";

// Test mode identifiers
pub const TEST_MODE_IDENTIFIER: &str = "test_";
pub const LIVE_MODE_IDENTIFIER: &str = "live_";