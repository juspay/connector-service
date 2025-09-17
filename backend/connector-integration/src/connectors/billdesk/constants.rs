/// Billdesk API Constants and Endpoints
/// Based on the Haskell Endpoints.hs file

// ===== BILLDESK BASE URLS =====
pub const UAT_DOMAIN: &str = "https://uat1.billdesk.com";
pub const PROD_DOMAIN: &str = "https://api.billdesk.com";

pub const UAT_PAYMENT_BASE_URL: &str = "https://uat1.billdesk.com/u2/payments/ve1_2";
pub const UAT_PGSI_BASE_URL: &str = "https://uat1.billdesk.com/u2/pgsi/ve1_2";

pub const PROD_PAYMENT_BASE_URL: &str = "https://api.billdesk.com/payments/ve1_2";
pub const PROD_PGSI_BASE_URL: &str = "https://api.billdesk.com/pgsi/ve1_2";

// ===== UPI ENDPOINTS =====
pub const UPI_INITIATE_ENDPOINT: &str = "/transactions/create";
pub const UPI_STATUS_ENDPOINT: &str = "/transactions/get";

// ===== LEGACY ENDPOINTS (from Haskell) =====
pub const LEGACY_UPI_INITIATE_UAT: &str = "https://uat.billdesk.com/pgidsk/PGIDirectRequest?reqid=BDRDF007";
pub const LEGACY_UPI_INITIATE_PROD: &str = "https://www.billdesk.com/pgidsk/PGIDirectRequest?reqid=BDRDF007";

// ===== UPI INSTRUMENT TYPES =====
pub const UPI_INTENT: &str = "UPI_INTENT";
pub const UPI_COLLECT: &str = "UPI_COLLECT";
pub const UPI_QR: &str = "UPI_QR";

// ===== PAYMENT METHOD TYPES =====
pub const PAYMENT_METHOD_UPI: &str = "UPI";

// ===== STATUS CODES =====
pub const SUCCESS_STATUS: &str = "0300";
pub const PENDING_STATUS: &str = "0002";
pub const FAILED_STATUS: &str = "0002";

// ===== CURRENCY CODES =====
pub const CURRENCY_INR: &str = "INR";

/// Get the appropriate endpoint based on flow type and environment
pub fn get_endpoint_for_flow(flow_type: &str, is_sandbox: bool) -> &'static str {
    match flow_type {
        "initiate_upi" => {
            if is_sandbox {
                LEGACY_UPI_INITIATE_UAT
            } else {
                LEGACY_UPI_INITIATE_PROD
            }
        }
        "upi_status" => UPI_STATUS_ENDPOINT,
        _ => "/",
    }
}

/// Get the payment base URL based on environment
pub fn get_payment_base_url(is_sandbox: bool) -> &'static str {
    if is_sandbox {
        UAT_PAYMENT_BASE_URL
    } else {
        PROD_PAYMENT_BASE_URL
    }
}

/// Get the PGSI base URL based on environment  
pub fn get_pgsi_base_url(is_sandbox: bool) -> &'static str {
    if is_sandbox {
        UAT_PGSI_BASE_URL
    } else {
        PROD_PGSI_BASE_URL
    }
}

// ===== TRANSACTION TYPES =====
pub const TXN_TYPE_PURCHASE: &str = "01";
pub const TXN_TYPE_REFUND: &str = "04";

// ===== BANK CODES =====
pub const BANK_ID_UPI: &str = "UPI";

// ===== REQUEST IDS (from Haskell) =====
pub const REQ_ID_UPI_INITIATE: &str = "BDRDF007";
pub const REQ_ID_AUTHORIZATION: &str = "BDRDF002";
pub const REQ_ID_STATUS: &str = "BDST001";

// ===== ERROR CODES =====
pub const ERROR_INVALID_REQUEST: &str = "E001";
pub const ERROR_AUTHENTICATION_FAILED: &str = "E002";
pub const ERROR_TRANSACTION_FAILED: &str = "E003";