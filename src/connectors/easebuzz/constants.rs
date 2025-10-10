use std::collections::HashMap;

// EaseBuzz API endpoints
pub const EASEBUZZ_INITIATE_PAYMENT_PROD: &str = "https://pay.easebuzz.in/payment/initiateLink";
pub const EASEBUZZ_INITIATE_PAYMENT_TEST: &str = "https://testpay.easebuzz.in/payment/initiateLink";

pub const EASEBUZZ_SEAMLESS_TRANSACTION_PROD: &str = "https://pay.easebuzz.in/transaction/v1/retrieve";
pub const EASEBUZZ_SEAMLESS_TRANSACTION_TEST: &str = "https://testpay.easebuzz.in/transaction/v1/retrieve";

pub const EASEBUZZ_TXN_SYNC_PROD: &str = "https://pay.easebuzz.in/transaction/v1/sync";
pub const EASEBUZZ_TXN_SYNC_TEST: &str = "https://testpay.easebuzz.in/transaction/v1/sync";

pub const EASEBUZZ_REFUND_PROD: &str = "https://pay.easebuzz.in/transaction/v1/refund";
pub const EASEBUZZ_REFUND_TEST: &str = "https://testpay.easebuzz.in/transaction/v1/refund";

pub const EASEBUZZ_REFUND_SYNC_PROD: &str = "https://pay.easebuzz.in/transaction/v1/refundSync";
pub const EASEBUZZ_REFUND_SYNC_TEST: &str = "https://testpay.easebuzz.in/transaction/v1/refundSync";

// EaseBuzz status mappings
pub const EASEBUZZ_STATUS_SUCCESS: &str = "success";
pub const EASEBUZZ_STATUS_PENDING: &str = "pending";
pub const EASEBUZZ_STATUS_FAILURE: &str = "failure";
pub const EASEBUZZ_STATUS_INITIATED: &str = "initiated";

// EaseBuzz payment modes
pub const EASEBUZZ_MODE_UPI: &str = "UPI";
pub const EASEBUZZ_MODE_UPI_COLLECT: &str = "UPI_COLLECT";
pub const EASEBUZZ_MODE_UPI_INTENT: &str = "UPI_INTENT";

// EaseBuzz error codes
pub const EASEBUZZ_ERROR_INVALID_HASH: &str = "E1001";
pub const EASEBUZZ_ERROR_INVALID_TRANSACTION: &str = "E1002";
pub const EASEBUZZ_ERROR_INSUFFICIENT_FUNDS: &str = "E1003";
pub const EASEBUZZ_ERROR_TRANSACTION_DECLINED: &str = "E1004";
pub const EASEBUZZ_ERROR_TIMEOUT: &str = "E1005";

// EaseBuzz hash sequence for different operations
pub const EASEBUZZ_HASH_SEQUENCE_PAYMENT: &str = "key|txnid|amount|productinfo|firstname|email|udf1|udf2|udf3|udf4|udf5|udf6|udf7|udf8|udf9|udf10|salt";
pub const EASEBUZZ_HASH_SEQUENCE_REFUND: &str = "key|txnid|refund_amount|refund_refno|salt";
pub const EASEBUZZ_HASH_SEQUENCE_SYNC: &str = "key|txnid|amount|email|phone|salt";

// EaseBuzz UDF (User Defined Fields) mappings
pub const EASEBUZZ_UDF_CURRENCY: usize = 1;
pub const EASEBUZZ_UDF_PAYMENT_METHOD: usize = 2;
pub const EASEBUZZ_UDF_CUSTOMER_ID: usize = 3;
pub const EASEBUZZ_UDF_MERCHANT_ORDER_ID: usize = 4;
pub const EASEBUZZ_UDF_ROUTER_RETURN_URL: usize = 5;

// EaseBuzz API version
pub const EASEBUZZ_API_VERSION: &str = "v1";

// EaseBuzz timeout configurations (in seconds)
pub const EASEBUZZ_REQUEST_TIMEOUT: u64 = 30;
pub const EASEBUZZ_SYNC_TIMEOUT: u64 = 60;
pub const EASEBUZZ_REFUND_TIMEOUT: u64 = 45;

// EaseBuzz retry configurations
pub const EASEBUZZ_MAX_RETRIES: u32 = 3;
pub const EASEBUZZ_RETRY_DELAY_MS: u64 = 1000;

// EaseBuzz webhook configurations
pub const EASEBUZZ_WEBHOOK_TIMEOUT: u64 = 10;
pub const EASEBUZZ_WEBHOOK_RETRY_COUNT: u32 = 3;

// EaseBuzz currency support (major currencies supported)
pub const EASEBUZZ_SUPPORTED_CURRENCIES: &[&str] = &[
    "INR", "USD", "EUR", "GBP", "AUD", "CAD", "SGD", "HKD", "JPY", "CNY"
];

// EaseBuzz minimum and maximum amounts (in INR)
pub const EASEBUZZ_MIN_AMOUNT_INR: u64 = 100; // ₹1.00
pub const EASEBUZZ_MAX_AMOUNT_INR: u64 = 10000000; // ₹100,000.00

// EaseBuzz UPI specific configurations
pub const EASEBUZZ_UPI_INTENT_TIMEOUT: u64 = 300; // 5 minutes
pub const EASEBUZZ_UPI_COLLECT_TIMEOUT: u64 = 600; // 10 minutes

// EaseBuzz response codes
pub const EASEBUZZ_RESPONSE_CODE_SUCCESS: i32 = 1;
pub const EASEBUZZ_RESPONSE_CODE_PENDING: i32 = 2;
pub const EASEBUZZ_RESPONSE_CODE_FAILURE: i32 = 0;

// EaseBuzz payment source mappings
pub const EASEBUZZ_PAYMENT_SOURCE_UPI: &str = "upi";
pub const EASEBUZZ_PAYMENT_SOURCE_UPI_COLLECT: &str = "upi_collect";
pub const EASEBUZZ_PAYMENT_SOURCE_UPI_INTENT: &str = "upi_intent";

// EaseBuzz VPA (Virtual Payment Address) validation
pub const EASEBUZZ_VPA_REGEX: &str = r"^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+$";
pub const EASEBUZZ_VPA_MAX_LENGTH: usize = 50;

// EaseBuzz phone number validation
pub const EASEBUZZ_PHONE_REGEX: &str = r"^[6-9]\d{9}$";
pub const EASEBUZZ_PHONE_MAX_LENGTH: usize = 10;

// EaseBuzz email validation
pub const EASEBUZZ_EMAIL_REGEX: &str = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$";
pub const EASEBUZZ_EMAIL_MAX_LENGTH: usize = 100;

// EaseBuzz transaction ID validation
pub const EASEBUZZ_TXN_ID_MAX_LENGTH: usize = 50;
pub const EASEBUZZ_TXN_ID_MIN_LENGTH: usize = 8;

// EaseBuzz refund ID validation
pub const EASEBUZZ_REFUND_ID_MAX_LENGTH: usize = 50;
pub const EASEBUZZ_REFUND_ID_MIN_LENGTH: usize = 8;

// EaseBuzz product info validation
pub const EASEBUZZ_PRODUCT_INFO_MAX_LENGTH: usize = 100;
pub const EASEBUZZ_PRODUCT_INFO_MIN_LENGTH: usize = 3;

// EaseBuzz first name validation
pub const EASEBUZZ_FIRST_NAME_MAX_LENGTH: usize = 50;
pub const EASEBUZZ_FIRST_NAME_MIN_LENGTH: usize = 2;

// EaseBuzz hash validation
pub const EASEBUZZ_HASH_LENGTH: usize = 128; // SHA512 hash length in hex

// EaseBuzz API rate limits
pub const EASEBUZZ_RATE_LIMIT_REQUESTS_PER_MINUTE: u32 = 100;
pub const EASEBUZZ_RATE_LIMIT_REQUESTS_PER_HOUR: u32 = 1000;

// EaseBuzz settlement configurations
pub const EASEBUZZ_SETTLEMENT_CYCLE_DAYS: u32 = 2; // T+2 settlement
pub const EASEBUZZ_SETTLEMENT_CUTOFF_TIME: &str = "23:59:59";

// EaseBuzz chargeback configurations
pub const EASEBUZZ_CHARGEBACK_WINDOW_DAYS: u32 = 45;
pub const EASEBUZZ_DISPUTE_RESOLUTION_DAYS: u32 = 30;

// EaseBuzz compliance configurations
pub const EASEBUZZ_PCI_COMPLIANCE_LEVEL: &str = "Level 1";
pub const EASEBUZZ_DATA_RETENTION_DAYS: u32 = 365;

// EaseBuzz feature flags
pub const EASEBUZZ_FEATURE_UPI_INTENT: bool = true;
pub const EASEBUZZ_FEATURE_UPI_COLLECT: bool = true;
pub const EASEBUZZ_FEATURE_REFUND: bool = true;
pub const EASEBUZZ_FEATURE_SYNC: bool = true;
pub const EASEBUZZ_FEATURE_WEBHOOK: bool = true;

// EaseBuzz environment configurations
pub const EASEBUZZ_ENVIRONMENT: &str = "production"; // or "test"
pub const EASEBUZZ_LOG_LEVEL: &str = "info";

// EaseBuzz security configurations
pub const EASEBUZZ_ENCRYPTION_ALGORITHM: &str = "SHA512";
pub const EASEBUZZ_HASH_SALT_LENGTH: usize = 32;

// EaseBuzz monitoring configurations
pub const EASEBUZZ_METRICS_ENABLED: bool = true;
pub const EASEBUZZ_HEALTH_CHECK_INTERVAL: u64 = 60; // seconds

// EaseBuzz integration configurations
pub const EASEBUZZ_API_VERSION_HEADER: &str = "X-API-Version";
pub const EASEBUZZ_CLIENT_VERSION_HEADER: &str = "X-Client-Version";
pub const EASEBUZZ_REQUEST_ID_HEADER: &str = "X-Request-ID";

// EaseBuzz error messages
pub const EASEBUZZ_ERROR_MSG_INVALID_REQUEST: &str = "Invalid request parameters";
pub const EASEBUZZ_ERROR_MSG_INVALID_HASH: &str = "Invalid hash provided";
pub const EASEBUZZ_ERROR_MSG_TRANSACTION_NOT_FOUND: &str = "Transaction not found";
pub const EASEBUZZ_ERROR_MSG_INSUFFICIENT_BALANCE: &str = "Insufficient balance";
pub const EASEBUZZ_ERROR_MSG_TRANSACTION_DECLINED: &str = "Transaction declined by bank";
pub const EASEBUZZ_ERROR_MSG_TIMEOUT: &str = "Transaction timeout";
pub const EASEBUZZ_ERROR_MSG_INVALID_UPI_ID: &str = "Invalid UPI ID";
pub const EASEBUZZ_ERROR_MSG_UPI_NOT_SUPPORTED: &str = "UPI not supported for this transaction";

// EaseBuzz success messages
pub const EASEBUZZ_SUCCESS_MSG_PAYMENT_INITIATED: &str = "Payment initiated successfully";
pub const EASEBUZZ_SUCCESS_MSG_PAYMENT_COMPLETED: &str = "Payment completed successfully";
pub const EASEBUZZ_SUCCESS_MSG_REFUND_INITIATED: &str = "Refund initiated successfully";
pub const EASEBUZZ_SUCCESS_MSG_REFUND_COMPLETED: &str = "Refund completed successfully";

// EaseBuzz status descriptions
pub fn get_status_description(status: &str) -> &'static str {
    match status {
        EASEBUZZ_STATUS_SUCCESS => "Transaction completed successfully",
        EASEBUZZ_STATUS_PENDING => "Transaction is pending confirmation",
        EASEBUZZ_STATUS_FAILURE => "Transaction failed",
        EASEBUZZ_STATUS_INITIATED => "Transaction has been initiated",
        _ => "Unknown status",
    }
}

// EaseBuzz error code descriptions
pub fn get_error_description(error_code: &str) -> &'static str {
    match error_code {
        EASEBUZZ_ERROR_INVALID_HASH => "The provided hash is invalid",
        EASEBUZZ_ERROR_INVALID_TRANSACTION => "Invalid transaction details",
        EASEBUZZ_ERROR_INSUFFICIENT_FUNDS => "Insufficient funds in the account",
        EASEBUZZ_ERROR_TRANSACTION_DECLINED => "Transaction declined by the bank",
        EASEBUZZ_ERROR_TIMEOUT => "Transaction timed out",
        _ => "Unknown error occurred",
    }
}

// EaseBuzz payment method descriptions
pub fn get_payment_method_description(payment_source: &str) -> &'static str {
    match payment_source {
        EASEBUZZ_PAYMENT_SOURCE_UPI => "Unified Payments Interface",
        EASEBUZZ_PAYMENT_SOURCE_UPI_COLLECT => "UPI Collect Request",
        EASEBUZZ_PAYMENT_SOURCE_UPI_INTENT => "UPI Intent Flow",
        _ => "Unknown payment method",
    }
}