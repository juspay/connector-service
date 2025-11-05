pub const BASE_URL: &str = "https://pay.easebuzz.in";

pub const PAYMENT_INITIATE: &str = "/payment/initiateLink";
pub const SEAMLESS_TRANSACTION: &str = "/transaction/v1/retrieve";
pub const TRANSACTION_SYNC: &str = "/transaction/v1/sync";
pub const REFUND: &str = "/transaction/v1/refund";
pub const REFUND_SYNC: &str = "/transaction/v1/refund/sync";
pub const SUBMIT_OTP: &str = "/transaction/v1/submitOtp";
pub const RESEND_OTP: &str = "/transaction/v1/resendOtp";
pub const UPI_AUTOPAY: &str = "/mandate/v1/upi/autopay";
pub const UPI_MANDATE_EXECUTE: &str = "/mandate/v1/upi/execute";
pub const REVOKE_MANDATE: &str = "/mandate/v1/revoke";

pub const TEST_BASE_URL: &str = "https://testpay.easebuzz.in";

pub const AUTHORIZATION_HEADER: &str = "Authorization";
pub const CONTENT_TYPE_HEADER: &str = "Content-Type";
pub const CONTENT_TYPE_FORM: &str = "application/x-www-form-urlencoded";
pub const CONTENT_TYPE_JSON: &str = "application/json";

pub const SUCCESS_STATUS: &str = "success";
pub const FAILURE_STATUS: &str = "failure";
pub const PENDING_STATUS: &str = "pending";

pub const UPI_INTENT: &str = "upi_intent";
pub const UPI_COLLECT: &str = "upi_collect";
pub const UPI_QR: &str = "upi_qr";