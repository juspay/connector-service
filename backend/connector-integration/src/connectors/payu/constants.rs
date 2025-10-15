// Payu API constants and endpoints

// Payu API versions
pub const API_VERSION: &str = "2.0";

// Payu device info
pub const DEVICE_INFO: &str = "web";

// Payu UPI specific constants
pub const PRODUCT_INFO: &str = "Payment"; // Default product info
pub const UPI_PG: &str = "UPI"; // UPI payment gateway
pub const UPI_COLLECT_BANKCODE: &str = "UPI"; // UPI Collect bank code
pub const UPI_INTENT_BANKCODE: &str = "INTENT"; // UPI Intent bank code
pub const UPI_S2S_FLOW: &str = "2"; // S2S flow type for UPI

// Payu PSync specific constants
pub const COMMAND: &str = "verify_payment";

// Payu API endpoints
pub const TEST_BASE_URL: &str = "https://test.payu.in";
pub const PROD_BASE_URL: &str = "https://secure.payu.in";

// API endpoint paths
pub const PAYMENT_ENDPOINT: &str = "/_payment";
pub const VERIFY_ENDPOINT: &str = "/merchant/postservice.php?form=2";