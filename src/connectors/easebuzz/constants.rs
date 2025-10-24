use std::collections::HashMap;

use common_enums::{Currency, PaymentMethodType};

// API Endpoints for EaseBuzz
pub const EASEBUZZ_BASE_URL: &str = "https://pay.easebuzz.in";
pub const EASEBUZZ_TEST_BASE_URL: &str = "https://testpay.easebuzz.in";

// API Paths
pub const EASEBUZZ_INITIATE_PAYMENT_PATH: &str = "/payment/initiateLink";
pub const EASEBUZZ_SEAMLESS_TRANSACTION_PATH: &str = "/payment/initiate";
pub const EASEBUZZ_TXN_SYNC_PATH: &str = "/transaction/status";
pub const EASEBUZZ_REFUND_PATH: &str = "/transaction/refund";
pub const EASEBUZZ_REFUND_SYNC_PATH: &str = "/transaction/refundStatus";

// Default values
pub const DEFAULT_PRODUCT_INFO: &str = "Payment";
pub const DEFAULT_FIRST_NAME: &str = "Customer";

// Supported currencies
pub const SUPPORTED_CURRENCIES: &[Currency] = &[Currency::Inr];

// Supported payment methods
pub const SUPPORTED_PAYMENT_METHODS: &[PaymentMethodType] = &[PaymentMethodType::Upi];

// Hash algorithm
pub const HASH_ALGORITHM: &str = "sha512";

// Response status codes
pub const RESPONSE_STATUS_SUCCESS: i32 = 1;
pub const RESPONSE_STATUS_FAILURE: i32 = 0;

// API timeouts (in seconds)
pub const API_TIMEOUT_SECONDS: u64 = 30;

// Maximum retry attempts
pub const MAX_RETRY_ATTEMPTS: u32 = 3;

// Error codes
pub const ERROR_CODE_INVALID_HASH: &str = "E001";
pub const ERROR_CODE_INVALID_TRANSACTION: &str = "E002";
pub const ERROR_CODE_INSUFFICIENT_FUNDS: &str = "E003";
pub const ERROR_CODE_TRANSACTION_DECLINED: &str = "E004";
pub const ERROR_CODE_INVALID_MERCHANT: &str = "E005";

// Error messages
pub const ERROR_MSG_INVALID_HASH: &str = "Invalid hash";
pub const ERROR_MSG_INVALID_TRANSACTION: &str = "Invalid transaction";
pub const ERROR_MSG_INSUFFICIENT_FUNDS: &str = "Insufficient funds";
pub const ERROR_MSG_TRANSACTION_DECLINED: &str = "Transaction declined";
pub const ERROR_MSG_INVALID_MERCHANT: &str = "Invalid merchant";

// UPI specific constants
pub const UPI_PAYMENT_SOURCE: &str = "upi";
pub const UPI_INTENT_FLOW: &str = "intent";
pub const UPI_COLLECT_FLOW: &str = "collect";

// Webhook constants
pub const WEBHOOK_SIGNATURE_HEADER: &str = "X-Easebuzz-Signature";
pub const WEBHOOK_TIMEOUT_SECONDS: u64 = 10;

// Request headers
pub const CONTENT_TYPE_FORM: &str = "application/x-www-form-urlencoded";
pub const CONTENT_TYPE_JSON: &str = "application/json";
pub const USER_AGENT: &str = "hyperswitch-ucs/1.0";

// Field limits
pub const MAX_TRANSACTION_ID_LENGTH: usize = 64;
pub const MAX_VPA_LENGTH: usize = 255;
pub const MAX_EMAIL_LENGTH: usize = 255;
pub const MAX_PHONE_LENGTH: usize = 20;
pub const MAX_REASON_LENGTH: usize = 255;

// Amount limits (in INR)
pub const MIN_TRANSACTION_AMOUNT: i64 = 100; // ₹1.00
pub const MAX_TRANSACTION_AMOUNT: i64 = 10000000; // ₹100,000.00
pub const MIN_REFUND_AMOUNT: i64 = 100; // ₹1.00
pub const MAX_REFUND_AMOUNT: i64 = 10000000; // ₹100,000.00

// Status mappings
use common_enums::AttemptStatus;

pub fn map_easebuzz_status_to_attempt_status(status: i32) -> AttemptStatus {
    match status {
        RESPONSE_STATUS_SUCCESS => AttemptStatus::AuthorizationSuccessful,
        RESPONSE_STATUS_FAILURE => AttemptStatus::AuthorizationFailed,
        _ => AttemptStatus::Pending,
    }
}

pub fn map_easebuzz_refund_status_to_attempt_status(status: &str) -> AttemptStatus {
    match status.to_lowercase().as_str() {
        "success" => AttemptStatus::AuthorizationSuccessful,
        "pending" => AttemptStatus::Pending,
        "failure" | "failed" => AttemptStatus::AuthorizationFailed,
        _ => AttemptStatus::Pending,
    }
}

// Error types
use domain_types::errors::ConnectorError;

// Error mapping
pub fn map_easebuzz_error_to_connector_error(error_code: &str, error_message: &str) -> ConnectorError {
    match error_code {
        ERROR_CODE_INVALID_HASH => ConnectorError::AuthenticationFailed,
        ERROR_CODE_INVALID_TRANSACTION => ConnectorError::TransactionNotFound,
        ERROR_CODE_INSUFFICIENT_FUNDS => ConnectorError::InsufficientBalance,
        ERROR_CODE_TRANSACTION_DECLINED => ConnectorError::PaymentDeclined,
        ERROR_CODE_INVALID_MERCHANT => ConnectorError::AuthenticationFailed,
        _ => ConnectorError::UnknownErrorResponse {
            code: error_code.to_string(),
            message: error_message.to_string(),
            status_code: None,
            reason: None,
        },
    }
}

// Validation functions
pub fn validate_transaction_id(txn_id: &str) -> Result<(), ConnectorError> {
    if txn_id.is_empty() {
        return Err(ConnectorError::MissingRequiredField {
            field_name: "transaction_id".to_string(),
        });
    }
    
    if txn_id.len() > MAX_TRANSACTION_ID_LENGTH {
        return Err(ConnectorError::InvalidRequestData {
            message: format!("Transaction ID exceeds maximum length of {}", MAX_TRANSACTION_ID_LENGTH),
        });
    }
    
    Ok(())
}

pub fn validate_vpa(vpa: &str) -> Result<(), ConnectorError> {
    if vpa.is_empty() {
        return Err(ConnectorError::MissingRequiredField {
            field_name: "vpa".to_string(),
        });
    }
    
    if vpa.len() > MAX_VPA_LENGTH {
        return Err(ConnectorError::InvalidRequestData {
            message: format!("VPA exceeds maximum length of {}", MAX_VPA_LENGTH),
        });
    }
    
    // Basic VPA format validation (should contain @)
    if !vpa.contains('@') {
        return Err(ConnectorError::InvalidRequestData {
            message: "Invalid VPA format".to_string(),
        });
    }
    
    Ok(())
}

pub fn validate_amount(amount: i64) -> Result<(), ConnectorError> {
    if amount < MIN_TRANSACTION_AMOUNT {
        return Err(ConnectorError::InvalidRequestData {
            message: format!("Amount must be at least ₹{}", MIN_TRANSACTION_AMOUNT / 100),
        });
    }
    
    if amount > MAX_TRANSACTION_AMOUNT {
        return Err(ConnectorError::InvalidRequestData {
            message: format!("Amount cannot exceed ₹{}", MAX_TRANSACTION_AMOUNT / 100),
        });
    }
    
    Ok(())
}

pub fn validate_refund_amount(amount: i64) -> Result<(), ConnectorError> {
    if amount < MIN_REFUND_AMOUNT {
        return Err(ConnectorError::InvalidRequestData {
            message: format!("Refund amount must be at least ₹{}", MIN_REFUND_AMOUNT / 100),
        });
    }
    
    if amount > MAX_REFUND_AMOUNT {
        return Err(ConnectorError::InvalidRequestData {
            message: format!("Refund amount cannot exceed ₹{}", MAX_REFUND_AMOUNT / 100),
        });
    }
    
    Ok(())
}

// URL construction helpers
pub fn get_base_url(test_mode: bool) -> &'static str {
    if test_mode {
        EASEBUZZ_TEST_BASE_URL
    } else {
        EASEBUZZ_BASE_URL
    }
}

pub fn get_initiate_payment_url(test_mode: bool) -> String {
    format!("{}{}", get_base_url(test_mode), EASEBUZZ_INITIATE_PAYMENT_PATH)
}

pub fn get_seamless_transaction_url(test_mode: bool) -> String {
    format!("{}{}", get_base_url(test_mode), EASEBUZZ_SEAMLESS_TRANSACTION_PATH)
}

pub fn get_txn_sync_url(test_mode: bool) -> String {
    format!("{}{}", get_base_url(test_mode), EASEBUZZ_TXN_SYNC_PATH)
}

pub fn get_refund_url(test_mode: bool) -> String {
    format!("{}{}", get_base_url(test_mode), EASEBUZZ_REFUND_PATH)
}

pub fn get_refund_sync_url(test_mode: bool) -> String {
    format!("{}{}", get_base_url(test_mode), EASEBUZZ_REFUND_SYNC_PATH)
}