// ZaakPay API Constants

pub const CONNECTOR_NAME: &str = "zaakpay";

// API Endpoints
pub const TRANSACT_ENDPOINT: &str = "/api/paymentTransact/V8";
pub const CHECK_ENDPOINT: &str = "/api/checkTxn/V8";
pub const UPDATE_ENDPOINT: &str = "/api/updateTxn/V8";

// API Response Codes
pub const SUCCESS_CODE: &str = "100";
pub const PENDING_CODE: &str = "101";
pub const FAILED_CODE: &str = "102";
pub const CANCELLED_CODE: &str = "103";

// Payment Modes
pub const UPI_MODE: &str = "UPI";
pub const CARD_MODE: &str = "CARD";
pub const NETBANKING_MODE: &str = "NETBANKING";

// Transaction Status
pub const TXN_SUCCESS: &str = "SUCCESS";
pub const TXN_PENDING: &str = "PENDING";
pub const TXN_FAILED: &str = "FAILED";
pub const TXN_CANCELLED: &str = "CANCELLED";

// Checksum Algorithm
pub const CHECKSUM_ALGORITHM: &str = "SHA256";

// Default Values
pub const DEFAULT_CURRENCY: &str = "INR";
pub const DEFAULT_VERSION: &str = "8";
pub const DEFAULT_MODE: &str = "LIVE";
pub const SANDBOX_MODE: &str = "SANDBOX";
