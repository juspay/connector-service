pub mod constants {
    // API Endpoints
    pub const BILLDESK_UAT_BASE_URL: &str = "https://uat.billdesk.com/pgidsk/PGIDirectRequest";
    pub const BILLDESK_PROD_BASE_URL: &str = "https://www.billdesk.com/pgidsk/PGIDirectRequest";

    // Request IDs for different operations
    pub const BILLDESK_UPI_INITIATE_REQ_ID: &str = "BDRDF011";
    pub const BILLDESK_AUTH_REQ_ID: &str = "BDRDF002";
    pub const BILLDESK_STATUS_REQ_ID: &str = "BDRDF003";
    pub const BILLDESK_REFUND_REQ_ID: &str = "BDRDF004";

    // Transaction Types
    pub const BILLDESK_TXN_TYPE_UPI: &str = "UPI";
    pub const BILLDESK_TXN_TYPE_NB: &str = "NB";
    pub const BILLDESK_TXN_TYPE_CARD: &str = "CARD";

    // Item Codes
    pub const BILLDESK_ITEM_CODE_DIRECT: &str = "DIRECT";
    pub const BILLDESK_ITEM_CODE_COLLECT: &str = "COLLECT";

    // Authentication Status Codes
    pub const BILLDESK_AUTH_SUCCESS: &str = "0300";
    pub const BILLDESK_AUTH_SUCCESS_VARIANT: &str = "0399";
    pub const BILLDESK_AUTH_PENDING: &str = "0396";
    pub const BILLDESK_AUTH_FAILURE: &str = "0397";

    // Error Codes
    pub const BILLDESK_ERROR_INVALID_REQUEST: &str = "400";
    pub const BILLDESK_ERROR_AUTH_FAILED: &str = "401";
    pub const BILLDESK_ERROR_NOT_FOUND: &str = "404";
    pub const BILLDESK_ERROR_SERVER_ERROR: &str = "500";

    // Currency Codes
    pub const BILLDESK_CURRENCY_INR: &str = "356";
    pub const BILLDESK_CURRENCY_USD: &str = "840";

    // Default Values
    pub const BILLDESK_DEFAULT_ITEM_CODE: &str = "DIRECT";
    pub const BILLDESK_DEFAULT_TXN_TYPE: &str = "UPI";
    pub const BILLDESK_DEFAULT_CURRENCY: &str = "356"; // INR

    // Headers
    pub const BILLDESK_CONTENT_TYPE: &str = "application/json";
    pub const BILLDESK_AUTH_HEADER: &str = "Authorization";

    // Response Fields
    pub const BILLDESK_RESPONSE_SUCCESS_STATUS: &str = "Success";
    pub const BILLDESK_RESPONSE_FAILURE_STATUS: &str = "Failure";
    pub const BILLDESK_RESPONSE_PENDING_STATUS: &str = "Pending";

    // Checksum Algorithm
    pub const BILLDESK_CHECKSUM_ALGORITHM: &str = "SHA256";
    pub const BILLDESK_CHECKSUM_SEPARATOR: &str = "|";

    // Timeout Values (in seconds)
    pub const BILLDESK_REQUEST_TIMEOUT: u64 = 30;
    pub const BILLDESK_SYNC_TIMEOUT: u64 = 60;

    // Retry Configuration
    pub const BILLDESK_MAX_RETRIES: u32 = 3;
    pub const BILLDESK_RETRY_DELAY_MS: u64 = 1000;

    // Webhook Configuration
    pub const BILLDESK_WEBHOOK_SIGNATURE_HEADER: &str = "X-Billdesk-Signature";
    pub const BILLDESK_WEBHOOK_TIMESTAMP_HEADER: &str = "X-Billdesk-Timestamp";
}