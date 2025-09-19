pub(crate) const CONTENT_TYPE: &str = "Content-Type";

// ZaakPay API endpoints
pub(crate) const TRANSACTION_API: &str = "/transact";  // For transaction initiation
pub(crate) const CHECK_TRANSACTION_API: &str = "/check";  // For transaction status check
pub(crate) const REFUND_STATUS_API: &str = "/refundStatus";  // For refund status check

// ZaakPay response codes and statuses
pub(crate) const SUCCESS_CODE: &str = "100";
pub(crate) const PENDING_CODE: &str = "200";
pub(crate) const FAILURE_CODE: &str = "300";

// Payment modes supported by ZaakPay (UPI focused)
pub(crate) const PAYMENT_MODE_UPI: &str = "upi";
pub(crate) const PAYMENT_MODE_UPI_INTENT: &str = "upi_intent";
pub(crate) const PAYMENT_MODE_UPI_COLLECT: &str = "upi_collect";

// Response status mappings
pub(crate) const STATUS_SUCCESS: &str = "success";
pub(crate) const STATUS_PENDING: &str = "pending";
pub(crate) const STATUS_FAILED: &str = "failed";
pub(crate) const STATUS_CANCELLED: &str = "cancelled";

// Error messages
pub(crate) const ERROR_INVALID_REQUEST: &str = "Invalid request parameters";
pub(crate) const ERROR_AUTHENTICATION_FAILED: &str = "Authentication failed";
pub(crate) const ERROR_TRANSACTION_NOT_FOUND: &str = "Transaction not found";
pub(crate) const ERROR_INVALID_CHECKSUM: &str = "Invalid checksum";