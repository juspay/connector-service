pub const BASE_URL_TEST: &str = "https://testpay.easebuzz.in";
pub const BASE_URL_PRODUCTION: &str = "https://pay.easebuzz.in";

pub const ENDPOINT_SEAMLESS_TRANSACTION: &str = "/payment/initiateLink";
pub const ENDPOINT_TXN_SYNC: &str = "/transaction/sync";
pub const ENDPOINT_REFUND_SYNC: &str = "/transaction/refund/sync";

pub const STATUS_SUCCESS: &str = "success";
pub const STATUS_PENDING: &str = "pending";
pub const STATUS_FAILURE: &str = "failure";
pub const STATUS_USER_ABORTED: &str = "user_aborted";

pub const UPI_INTENT: &str = "upi";
pub const UPI_COLLECT: &str = "upi_collect";

pub const HASH_ALGORITHM: &str = "sha512";