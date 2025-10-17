pub const PAYU_BASE_URL: &str = "https://info.payu.in";
pub const PAYU_TEST_BASE_URL: &str = "https://test.payu.in";

pub const PAYU_AUTHORIZE_ENDPOINT: &str = "/merchant/postservice.php?form=2";
pub const PAYU_SYNC_ENDPOINT: &str = "/merchant/postservice.php?form=2";
pub const PAYU_REFUND_SYNC_ENDPOINT: &str = "/merchant/postservice.php?form=2";

pub const PAYU_COMMAND_AUTHORIZE: &str = "create_transaction";
pub const PAYU_COMMAND_VERIFY_PAYMENT: &str = "verify_payment";
pub const PAYU_COMMAND_GET_REFUNDS: &str = "get_all_refunds_from_txn_id";

pub const PAYU_STATUS_SUCCESS: &str = "success";
pub const PAYU_STATUS_FAILURE: &str = "failure";
pub const PAYU_STATUS_PENDING: &str = "pending";

pub const PAYU_MODE_UPI: &str = "UPI";
pub const PAYU_MODE_UPI_COLLECT: &str = "UPI";
pub const PAYU_MODE_UPI_INTENT: &str = "UPI_INTENT";
pub const PAYU_MODE_NET_BANKING: &str = "NB";

pub const PAYU_ERROR_CODE_INVALID_CREDENTIALS: &str = "E001";
pub const PAYU_ERROR_CODE_INVALID_TRANSACTION: &str = "E002";
pub const PAYU_ERROR_CODE_INSUFFICIENT_FUNDS: &str = "E003";
pub const PAYU_ERROR_CODE_INVALID_VPA: &str = "E004";

pub fn get_payu_endpoint(command: &str, is_test_mode: bool) -> String {
    let base_url = if is_test_mode {
        PAYU_TEST_BASE_URL
    } else {
        PAYU_BASE_URL
    };
    
    format!("{}{}", base_url, PAYU_AUTHORIZE_ENDPOINT)
}

pub fn get_payment_method_code(payment_method_type: &str) -> &'static str {
    match payment_method_type {
        "upi_collect" => PAYU_MODE_UPI_COLLECT,
        "upi_intent" => PAYU_MODE_UPI_INTENT,
        _ => PAYU_MODE_NET_BANKING,
    }
}

pub fn map_payu_status_to_attempt_status(status: &str) -> &'static str {
    match status {
        PAYU_STATUS_SUCCESS => "charged",
        PAYU_STATUS_FAILURE => "failure",
        PAYU_STATUS_PENDING => "pending",
        _ => "authentication_pending",
    }
}

pub fn map_payu_status_to_refund_status(status: &str) -> &'static str {
    match status {
        PAYU_STATUS_SUCCESS => "success",
        PAYU_STATUS_FAILURE => "failure",
        PAYU_STATUS_PENDING => "pending",
        _ => "pending",
    }
}

pub fn get_error_description(error_code: &str) -> &'static str {
    match error_code {
        PAYU_ERROR_CODE_INVALID_CREDENTIALS => "Invalid credentials provided",
        PAYU_ERROR_CODE_INVALID_TRANSACTION => "Invalid transaction details",
        PAYU_ERROR_CODE_INSUFFICIENT_FUNDS => "Insufficient funds in account",
        PAYU_ERROR_CODE_INVALID_VPA => "Invalid VPA address",
        _ => "Unknown error occurred",
    }
}