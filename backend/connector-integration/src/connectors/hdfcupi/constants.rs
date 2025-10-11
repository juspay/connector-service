pub const API_VERSION: &str = "1.0";

// HDFC UPI API Endpoints
pub const COLLECT_ENDPOINT: &str = "/upi/meTransCollectSvc";
pub const STATUS_QUERY_ENDPOINT: &str = "/upi/transactionStatusQuery";
pub const REFUND_ENDPOINT: &str = "/upi/refundReqSvc";
pub const VERIFY_VPA_ENDPOINT: &str = "/upi/vpaVerifySvc";

// Base URLs
pub const PROD_BASE_URL: &str = "https://upi.hdfcbank.com";
pub const SANDBOX_BASE_URL: &str = "https://upitest.hdfcbank.com";

// Response Status Codes
pub const STATUS_SUCCESS: &str = "success";
pub const STATUS_PENDING: &str = "pending";
pub const STATUS_FAILURE: &str = "failure";

// HTTP Headers
pub const HEADER_CONTENT_TYPE: &str = "Content-Type";
pub const HEADER_AUTHORIZATION: &str = "Authorization";

// Content Types
pub const CONTENT_TYPE_JSON: &str = "application/json";