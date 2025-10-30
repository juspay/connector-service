use std::collections::HashMap;

pub const BASE_URL_PROD: &str = "https://www.tpsl-india.in/PaymentGateway";
pub const BASE_URL_TEST: &str = "https://www.tekprocess.co.in/PaymentGateway";

pub const TRANSACTION_DETAILS_ENDPOINT: &str = "/services/TransactionDetailsNew";
pub const AUTH_CAPTURE_ENDPOINT: &str = "/merchant2.pg";
pub const UPI_TRANSACTION_ENDPOINT: &str = "/services/UPITransaction";
pub const UPI_TOKEN_GENERATION_ENDPOINT: &str = "/services/UPITokenGeneration";
pub const SI_TRANSACTION_ENDPOINT: &str = "/services/SITransaction";
pub const REFUND_ARN_SYNC_ENDPOINT: &str = "/services/RefundArnSync";

pub fn get_base_url() -> &'static str {
    BASE_URL_PROD
}

pub fn get_endpoint(flow: &str, test_mode: bool) -> String {
    let base_url = if test_mode { BASE_URL_TEST } else { BASE_URL_PROD };
    
    match flow {
        "transaction" => format!("{}{}", base_url, TRANSACTION_DETAILS_ENDPOINT),
        "auth_capture" => format!("{}{}", base_url, AUTH_CAPTURE_ENDPOINT),
        "upi_transaction" => format!("{}{}", base_url, UPI_TRANSACTION_ENDPOINT),
        "upi_token_generation" => format!("{}{}", base_url, UPI_TOKEN_GENERATION_ENDPOINT),
        "si_transaction" => format!("{}{}", base_url, SI_TRANSACTION_ENDPOINT),
        "refund_arn_sync" => format!("{}{}", base_url, REFUND_ARN_SYNC_ENDPOINT),
        _ => base_url.to_string(),
    }
}

use std::sync::LazyLock;

pub static ERROR_RESPONSE_MAPPING: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
    std::collections::HashMap::from([
        ("000".to_string(), "Success".to_string()),
        ("001".to_string(), "Invalid Request".to_string()),
        ("002".to_string(), "Authentication Failed".to_string()),
        ("003".to_string(), "Transaction Failed".to_string()),
        ("004".to_string(), "Invalid Merchant".to_string()),
        ("005".to_string(), "Invalid Amount".to_string()),
        ("006".to_string(), "Invalid Currency".to_string()),
        ("007".to_string(), "Invalid Payment Method".to_string()),
        ("008".to_string(), "Bank Timeout".to_string()),
        ("009".to_string(), "Bank Declined".to_string()),
        ("010".to_string(), "Insufficient Funds".to_string()),
        ("011".to_string(), "Invalid Card".to_string()),
        ("012".to_string(), "Expired Card".to_string()),
        ("013".to_string(), "Invalid UPI ID".to_string()),
        ("014".to_string(), "UPI Timeout".to_string()),
        ("015".to_string(), "UPI Declined".to_string()),
        ("016".to_string(), "Mandate Failed".to_string()),
        ("017".to_string(), "Invalid Mandate".to_string()),
        ("018".to_string(), "Refund Failed".to_string()),
        ("019".to_string(), "Invalid Refund".to_string()),
        ("020".to_string(), "Duplicate Transaction".to_string()),
        ("021".to_string(), "System Error".to_string()),
        ("022".to_string(), "Network Error".to_string()),
        ("023".to_string(), "Invalid Customer".to_string()),
        ("024".to_string(), "Invalid Order".to_string()),
        ("025".to_string(), "Invalid Signature".to_string()),
        ("026".to_string(), "Invalid Token".to_string()),
        ("027".to_string(), "Token Expired".to_string()),
        ("028".to_string(), "Invalid Response".to_string()),
        ("029".to_string(), "Processing Error".to_string()),
        ("030".to_string(), "Service Unavailable".to_string()),
    ])
});

pub const DEFAULT_CURRENCY: &str = "INR";
pub const DEFAULT_PAYMENT_METHOD: &str = "UPI";
pub const DEFAULT_REQUEST_TYPE: &str = "TXN";
pub const DEFAULT_SUB_TYPE: &str = "COLLECT";

// UPI specific constants
pub const UPI_INTENT_TYPE: &str = "INTENT";
pub const UPI_COLLECT_TYPE: &str = "COLLECT";
pub const UPI_QR_TYPE: &str = "QR";

// Status mappings
pub const STATUS_SUCCESS: &str = "SUCCESS";
pub const STATUS_PENDING: &str = "PENDING";
pub const STATUS_FAILED: &str = "FAILED";
pub const STATUS_CANCELLED: &str = "CANCELLED";
pub const STATUS_TIMEOUT: &str = "TIMEOUT";

// Transaction types
pub const TXN_TYPE_PAYMENT: &str = "PAYMENT";
pub const TXN_TYPE_MANDATE_REG: &str = "MANDATE_REG";
pub const TXN_TYPE_MANDATE_EXEC: &str = "MANDATE_EXEC";
pub const TXN_TYPE_REFUND: &str = "REFUND";

// Response types
pub const RESPONSE_TYPE_SYNC: &str = "SYNC";
pub const RESPONSE_TYPE_ASYNC: &str = "ASYNC";
pub const RESPONSE_TYPE_REDIRECT: &str = "REDIRECT";