// API Endpoints based on Haskell implementation
pub const TRANSACTION_ENDPOINT: &str = "/transaction/transaction.do";
pub const STATUS_ENDPOINT: &str = "/apis/servlet/DoWebTrans";
pub const REFUND_ENDPOINT: &str = "/apis/servlet/DoWebTrans";
pub const REFUND_STATUS_ENDPOINT: &str = "/apis/servlet/DoWebTrans";
pub const VERIFY_VPA_ENDPOINT: &str = "/apis/servlet/DoWebTrans";

// Commands for different operations
pub const COMMAND_INITIATE_TRANSACTION: &str = "initiateTransaction";
pub const COMMAND_ORDER_STATUS_TRACKER: &str = "orderStatusTracker";
pub const COMMAND_REFUND: &str = "refund";
pub const COMMAND_REFUND_STATUS: &str = "refundStatusTracker";
pub const COMMAND_VERIFY_VPA: &str = "verifyVPA";

// Request/Response types
pub const REQUEST_TYPE_JSON: &str = "JSON";
pub const RESPONSE_TYPE_JSON: &str = "JSON";

// API Version
pub const API_VERSION: &str = "1.2";

// Payment options
pub const PAYMENT_OPTION_UPI: &str = "UPI";
pub const PAYMENT_OPTION_NETBANKING: &str = "NB";
pub const PAYMENT_OPTION_CREDIT_CARD: &str = "OPTCRDC";
pub const PAYMENT_OPTION_DEBIT_CARD: &str = "OPTDBCRD";

// UPI specific constants
pub const UPI_INTENT_TYPE: &str = "INTENT";
pub const UPI_COLLECT_TYPE: &str = "COLLECT";

// Order status values
pub const ORDER_STATUS_SUCCESS: &str = "Success";
pub const ORDER_STATUS_ABORTED: &str = "Aborted";
pub const ORDER_STATUS_CANCELLED: &str = "Cancelled";
pub const ORDER_STATUS_UNSUCCESSFUL: &str = "Unsuccessful";
pub const ORDER_STATUS_INVALID: &str = "Invalid";
pub const ORDER_STATUS_INCOMPLETE: &str = "Incomplete";
pub const ORDER_STATUS_SHIPPED: &str = "Shipped";

// Language codes
pub const LANGUAGE_ENGLISH: &str = "EN";
pub const LANGUAGE_HINDI: &str = "HI";

// Currency codes supported
pub const CURRENCY_INR: &str = "INR";
pub const CURRENCY_USD: &str = "USD";
pub const CURRENCY_EUR: &str = "EUR";
pub const CURRENCY_GBP: &str = "GBP";
pub const CURRENCY_AED: &str = "AED";
pub const CURRENCY_SAR: &str = "SAR";

// Error codes
pub const ERROR_CODE_INVALID_REQUEST: &str = "E001";
pub const ERROR_CODE_AUTHENTICATION_FAILED: &str = "E002";
pub const ERROR_CODE_TRANSACTION_FAILED: &str = "E003";
pub const ERROR_CODE_INSUFFICIENT_FUNDS: &str = "E004";
pub const ERROR_CODE_INVALID_VPA: &str = "E005";
pub const ERROR_CODE_TRANSACTION_TIMEOUT: &str = "E006";

// Encryption constants
pub const AES_BLOCK_SIZE: usize = 16;
pub const AES_KEY_SIZE: usize = 32;

// Webhook event types
pub const WEBHOOK_EVENT_PAYMENT_SUCCESS: &str = "payment.success";
pub const WEBHOOK_EVENT_PAYMENT_FAILED: &str = "payment.failed";
pub const WEBHOOK_EVENT_PAYMENT_PENDING: &str = "payment.pending";
pub const WEBHOOK_EVENT_REFUND_SUCCESS: &str = "refund.success";
pub const WEBHOOK_EVENT_REFUND_FAILED: &str = "refund.failed";

// HTTP headers
pub const HEADER_CONTENT_TYPE: &str = "Content-Type";
pub const HEADER_ACCEPT: &str = "Accept";
pub const HEADER_USER_AGENT: &str = "User-Agent";

// Content types
pub const CONTENT_TYPE_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
pub const CONTENT_TYPE_JSON: &str = "application/json";

// Timeout values (in seconds)
pub const DEFAULT_TIMEOUT: u64 = 30;
pub const PAYMENT_TIMEOUT: u64 = 300; // 5 minutes
pub const STATUS_CHECK_TIMEOUT: u64 = 60;

// Retry configuration
pub const MAX_RETRIES: u8 = 3;
pub const RETRY_DELAY_MS: u64 = 1000;

// Validation constants
pub const MIN_AMOUNT: f64 = 1.0;
pub const MAX_AMOUNT: f64 = 1000000.0;
pub const MAX_ORDER_ID_LENGTH: usize = 50;
pub const MAX_MERCHANT_PARAM_LENGTH: usize = 255;

// UPI VPA validation regex pattern
pub const UPI_VPA_REGEX: &str = r"^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+$";

// Test environment indicators
pub const TEST_MERCHANT_ID_PREFIX: &str = "TEST";
pub const SANDBOX_INDICATOR: &str = "test";

// Split payment constants (for marketplace scenarios)
pub const SPLIT_TDR_CHARGE_TYPE_PERCENTAGE: &str = "percentage";
pub const SPLIT_TDR_CHARGE_TYPE_FIXED: &str = "fixed";
pub const MAX_SPLIT_ACCOUNTS: usize = 10;

// EMI related constants
pub const EMI_TENURE_3_MONTHS: &str = "3";
pub const EMI_TENURE_6_MONTHS: &str = "6";
pub const EMI_TENURE_9_MONTHS: &str = "9";
pub const EMI_TENURE_12_MONTHS: &str = "12";
pub const EMI_TENURE_18_MONTHS: &str = "18";
pub const EMI_TENURE_24_MONTHS: &str = "24";

// Device context constants
pub const DEVICE_OS_ANDROID: &str = "ANDROID";
pub const DEVICE_OS_IOS: &str = "IOS";
pub const DEVICE_OS_WINDOWS: &str = "WINDOWS";
pub const DEVICE_OS_WEB: &str = "WEB";

// Card type constants
pub const CARD_TYPE_CREDIT: &str = "CRDC";
pub const CARD_TYPE_DEBIT: &str = "DBCRD";

// Bank codes for net banking (commonly used ones)
pub const BANK_CODE_SBI: &str = "SBI";
pub const BANK_CODE_HDFC: &str = "HDFC";
pub const BANK_CODE_ICICI: &str = "ICICI";
pub const BANK_CODE_AXIS: &str = "AXIS";
pub const BANK_CODE_KOTAK: &str = "KOTAK";
pub const BANK_CODE_YES: &str = "YES";

// Recurring payment constants
pub const RECURRING_TYPE_INITIAL: &str = "INITIAL";
pub const RECURRING_TYPE_SUBSEQUENT: &str = "SUBSEQUENT";
pub const RECURRING_FREQUENCY_DAILY: &str = "DAILY";
pub const RECURRING_FREQUENCY_WEEKLY: &str = "WEEKLY";
pub const RECURRING_FREQUENCY_MONTHLY: &str = "MONTHLY";
pub const RECURRING_FREQUENCY_YEARLY: &str = "YEARLY";