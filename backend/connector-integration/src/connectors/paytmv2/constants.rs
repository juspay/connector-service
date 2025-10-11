pub mod api;

pub const PAYTMV2: &str = "paytmv2";

// API Endpoints
pub const INITIATE_TRANSACTION: &str = "/theia/api/v1/initiateTransaction";
pub const PROCESS_TRANSACTION: &str = "/theia/api/v1/processTransaction";
pub const TRANSACTION_STATUS: &str = "/theia/api/v1/transactionStatus";
pub const VALIDATE_VPA: &str = "/theia/api/v1/validateVpa";
pub const MANDATE_INIT: &str = "/subscription/api/v1/mandate/initiate";
pub const MANDATE_STATUS: &str = "/subscription/api/v1/mandate/status";

// Headers
pub const CONTENT_TYPE: &str = "Content-Type";
pub const CLIENT_ID: &str = "client-id";
pub const VERSION: &str = "version";
pub const REQUEST_TIMESTAMP: &str = "request-timestamp";
pub const CHANNEL_ID: &str = "channel-id";
pub const SIGNATURE: &str = "signature";
pub const MID: &str = "mid";

// Default values
pub const DEFAULT_VERSION: &str = "v1";
pub const DEFAULT_CHANNEL_ID: &str = "WEB";
pub const DEFAULT_REQUEST_TYPE: &str = "PAYMENT";

// Payment modes
pub const PAYMENT_MODE_UPI: &str = "UPI";
pub const PAYMENT_MODE_UPI_COLLECT: &str = "UPI_COLLECT";
pub const PAYMENT_MODE_UPI_INTENT: &str = "UPI_INTENT";
pub const PAYMENT_MODE_UPI_QR: &str = "UPI_QR";

// Status codes
pub const STATUS_SUCCESS: &str = "SUCCESS";
pub const STATUS_PENDING: &str = "PENDING";
pub const STATUS_FAILURE: &str = "FAILURE";
pub const STATUS_TXN_SUCCESS: &str = "TXN_SUCCESS";
pub const STATUS_TXN_FAILURE: &str = "TXN_FAILURE";
pub const STATUS_TXN_PENDING: &str = "TXN_PENDING";

// Response codes
pub const RESP_CODE_SUCCESS: &str = "01";
pub const RESP_CODE_PENDING: &str = "01";
pub const RESP_CODE_FAILURE: &str = "01";