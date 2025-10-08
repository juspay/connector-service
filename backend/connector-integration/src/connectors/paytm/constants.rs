// Paytm connector constants

// API constants
pub const API_VERSION: &str = "v2";
pub const CHANNEL_ID: &str = "WEB";
pub const REQUEST_TYPE_PAYMENT: &str = "Payment";
pub const REQUEST_TYPE_NATIVE: &str = "NATIVE";
pub const PAYMENT_MODE_UPI: &str = "UPI";
pub const UPI_CHANNEL_UPIPUSH: &str = "UPIPUSH";
pub const PAYMENT_FLOW_NONE: &str = "NONE";

// Default values
pub const DEFAULT_CUSTOMER_ID: &str = "CUST_001";
pub const DEFAULT_CALLBACK_URL: &str = "https://example.com/callback";

// HTTP headers
pub const CONTENT_TYPE_HEADER: &str = "Content-Type";
pub const CONTENT_TYPE_JSON: &str = "application/json";

// AES encryption constants
pub const AES_128_KEY_LENGTH: usize = 16;
pub const AES_192_KEY_LENGTH: usize = 24;
pub const AES_256_KEY_LENGTH: usize = 32;
pub const AES_BUFFER_PADDING: usize = 16;
pub const SALT_LENGTH: usize = 32;

// Fixed IV for Paytm AES encryption (exact value from PayTM v2 Haskell implementation)
pub const PAYTM_IV: &[u8; 16] = b"@@@@&&&&####$$$$";

// Error messages
pub const ERROR_SALT_GENERATION: &str = "Failed to generate salt for signature";
pub const ERROR_AES_128_ENCRYPTION: &str = "Failed to encrypt with AES-128-CBC";
pub const ERROR_AES_192_ENCRYPTION: &str = "Failed to encrypt with AES-192-CBC";
pub const ERROR_AES_256_ENCRYPTION: &str = "Failed to encrypt with AES-256-CBC";
pub const ERROR_INVALID_VPA: &str = "Invalid UPI VPA format";