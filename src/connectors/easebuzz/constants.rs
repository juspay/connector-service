// EaseBuzz Constants and Endpoints

use std::collections::HashMap;

pub const EASEBUZZ_API_VERSION: &str = "v1";

pub const EASEBUZZ_INITIATE_PAYMENT: &str = "/payment/initiateLink";
pub const EASEBUZZ_SEAMLESS_TRANSACTION: &str = "/payment/initiateTransaction";
pub const EASEBUZZ_TXN_SYNC: &str = "/payment/transactionStatus";
pub const EASEBUZZ_REFUND: &str = "/transaction/refund";
pub const EASEBUZZ_REFUND_SYNC: &str = "/transaction/refundStatus";

// UPI specific endpoints
pub const EASEBUZZ_UPI_INTENT: &str = "/payment/upiIntent";
pub const EASEBUZZ_UPI_COLLECT: &str = "/payment/upiCollect";

// Test endpoints
pub const EASEBUZZ_TEST_BASE_URL: &str = "https://testpay.easebuzz.in";
pub const EASEBUZZ_PROD_BASE_URL: &str = "https://pay.easebuzz.in";

// Status mappings
pub const EASEBUZZ_STATUS_SUCCESS: &str = "success";
pub const EASEBUZZ_STATUS_PENDING: &str = "pending";
pub const EASEBUZZ_STATUS_FAILURE: &str = "failure";
pub const EASEBUZZ_STATUS_INITIATED: &str = "initiated";

// Error codes
pub const EASEBUZZ_ERROR_INVALID_REQUEST: &str = "INVALID_REQUEST";
pub const EASEBUZZ_ERROR_AUTHENTICATION_FAILED: &str = "AUTHENTICATION_FAILED";
pub const EASEBUZZ_ERROR_TRANSACTION_NOT_FOUND: &str = "TRANSACTION_NOT_FOUND";
pub const EASEBUZZ_ERROR_INSUFFICIENT_FUNDS: &str = "INSUFFICIENT_FUNDS";
pub const EASEBUZZ_ERROR_INVALID_MERCHANT: &str = "INVALID_MERCHANT";

// Hash algorithm
pub const EASEBUZZ_HASH_ALGORITHM: &str = "sha512";

// Default values
pub const EASEBUZZ_DEFAULT_CURRENCY: &str = "INR";
pub const EASEBUZZ_DEFAULT_TIMEOUT: u64 = 30;

// UPI specific constants
pub const EASEBUZZ_UPI_INTENT_TIMEOUT: u64 = 300; // 5 minutes
pub const EASEBUZZ_UPI_COLLECT_TIMEOUT: u64 = 600; // 10 minutes

// Response field mappings
pub static EASEBUZZ_STATUS_MAPPINGS: HashMap<&'static str, common_enums::AttemptStatus> = {
    let mut map = HashMap::new();
    map.insert(EASEBUZZ_STATUS_SUCCESS, common_enums::AttemptStatus::Charged);
    map.insert(EASEBUZZ_STATUS_PENDING, common_enums::AttemptStatus::Pending);
    map.insert(EASEBUZZ_STATUS_FAILURE, common_enums::AttemptStatus::Failure);
    map.insert(EASEBUZZ_STATUS_INITIATED, common_enums::AttemptStatus::Pending);
    map
};

pub static EASEBUZZ_REFUND_STATUS_MAPPINGS: HashMap<&'static str, common_enums::RefundStatus> = {
    let mut map = HashMap::new();
    map.insert("success", common_enums::RefundStatus::Success);
    map.insert("pending", common_enums::RefundStatus::Pending);
    map.insert("failure", common_enums::RefundStatus::Failure);
    map.insert("processed", common_enums::RefundStatus::Success);
    map
};

// Payment method type mappings
pub static EASEBUZZ_PAYMENT_METHOD_MAPPINGS: HashMap<&'static str, common_enums::PaymentMethodType> = {
    let mut map = HashMap::new();
    map.insert("upi", common_enums::PaymentMethodType::Upi);
    map.insert("upi_collect", common_enums::PaymentMethodType::UpiCollect);
    map.insert("upi_intent", common_enums::PaymentMethodType::UpiIntent);
    map
};