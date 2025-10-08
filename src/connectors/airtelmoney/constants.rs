// AirtelMoney Constants and Endpoints

use std::collections::HashMap;

pub fn get_base_url() -> &'static str {
    "https://ecom.airtelbank.com"
}

pub fn get_test_base_url() -> &'static str {
    "https://apptest.airtelbank.com"
}

pub fn get_status_base_url() -> &'static str {
    "https://ecom.airtelbank.com"
}

pub fn get_status_test_base_url() -> &'static str {
    "https://apbuat.airtelbank.com:5050"
}

// API Endpoints mapping based on Haskell implementation
pub fn get_endpoint_for_request(request_type: &str, is_test: bool) -> String {
    match (request_type, is_test) {
        ("OtpGenerateRequest", true) => {
            format!("{}/apbnative/partners/:merchantId/customers/:customerId/authRequest", get_test_base_url())
        }
        ("OtpGenerateRequest", false) => {
            format!("{}/apbnative/partners/:merchantId/customers/:customerId/authRequest", get_base_url())
        }
        ("OtpVerificationRequest", true) => {
            format!("{}/apbnative/partners/:merchantId/customers/:customerId/authToken", get_test_base_url())
        }
        ("OtpVerificationRequest", false) => {
            format!("{}/apbnative/partners/:merchantId/customers/:customerId/authToken", get_base_url())
        }
        ("FetchCustomerRequest", true) => {
            format!("{}/apbnative/p1/customers/:customerId/profile", get_test_base_url())
        }
        ("FetchCustomerRequest", false) => {
            format!("{}/apbnative/p1/customers/:customerId/profile", get_base_url())
        }
        ("DelinkWalletRequest", true) => {
            format!("{}/apbnative/partners/:merchantId/customers/:customerId/delink", get_test_base_url())
        }
        ("DelinkWalletRequest", false) => {
            format!("{}/apbnative/partners/:merchantId/customers/:customerId/delink", get_base_url())
        }
        ("DirectDebitRequest", true) => {
            format!("{}/apbnative/p1/customers/:customerId/account/debit", get_test_base_url())
        }
        ("DirectDebitRequest", false) => {
            format!("{}/apbnative/p1/customers/:customerId/account/debit", get_base_url())
        }
        ("APBStatusRequest", true) => {
            format!("{}/bank/ecom/v2/inquiry", get_status_test_base_url())
        }
        ("APBStatusRequest", false) => {
            format!("{}/ecom/v2/inquiry", get_status_base_url())
        }
        ("RefundRequest", true) => {
            format!("{}/ecom/v2/reversal", get_status_test_base_url())
        }
        ("RefundRequest", false) => {
            format!("{}/ecom/v2/reversal", get_status_base_url())
        }
        ("TransactionRequest", true) => {
            format!("{}/ecom/v2/initiatePayment?", get_status_test_base_url())
        }
        ("TransactionRequest", false) => {
            format!("{}/ecom/v2/initiatePayment?", get_status_base_url())
        }
        _ => String::new(),
    }
}

// Headers
pub const CONTENT_TYPE_JSON: &str = "application/json";
pub const ACCEPT_JSON: &str = "application/json";

// Status codes
pub const STATUS_SUCCESS: i32 = 200;
pub const STATUS_PENDING: i32 = 202;
pub const STATUS_ERROR: i32 = 400;

// Response status text
pub const STATUS_TEXT_SUCCESS: &str = "SUCCESS";
pub const STATUS_TEXT_PENDING: &str = "PENDING";
pub const STATUS_TEXT_FAILED: &str = "FAILED";
pub const STATUS_TEXT_ERROR: &str = "ERROR";

// Default values
pub const DEFAULT_VERSION: &str = "1.0";
pub const DEFAULT_CHANNEL: &str = "APP";
pub const DEFAULT_END_CHANNEL: &str = "WEB";

// Hash algorithms
pub const HASH_ALGORITHM: &str = "SHA256";