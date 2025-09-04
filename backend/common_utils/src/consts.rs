//! Consolidated constants for the connector service

// =============================================================================
// ID Generation and Length Constants
// =============================================================================

pub const ID_LENGTH: usize = 20;

/// Characters to use for generating NanoID
pub(crate) const ALPHABETS: [char; 62] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
    'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B',
    'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
    'V', 'W', 'X', 'Y', 'Z',
];

/// Max Length for MerchantReferenceId
pub const MAX_ALLOWED_MERCHANT_REFERENCE_ID_LENGTH: u8 = 64;
/// Minimum allowed length for MerchantReferenceId
pub const MIN_REQUIRED_MERCHANT_REFERENCE_ID_LENGTH: u8 = 1;
/// Length of a cell identifier in a distributed system
pub const CELL_IDENTIFIER_LENGTH: u8 = 5;
/// Minimum length required for a global id
pub const MAX_GLOBAL_ID_LENGTH: u8 = 64;
/// Maximum length allowed for a global id
pub const MIN_GLOBAL_ID_LENGTH: u8 = 32;

// =============================================================================
// HTTP Headers
// =============================================================================

/// Header key for tenant identification
pub const X_TENANT_ID: &str = "x-tenant-id";
/// Header key for request ID
pub const X_REQUEST_ID: &str = "x-request-id";
/// Header key for connector identification
pub const X_CONNECTOR: &str = "x-connector";
/// Header key for merchant identification
pub const X_MERCHANT_ID: &str = "x-merchant-id";
/// Header key for reference identification
pub const X_REFERENCE_ID: &str = "x-reference-id";

// =============================================================================
// Authentication Headers (Internal)
// =============================================================================

/// Authentication header
pub const X_AUTH: &str = "x-auth";
/// API key header for authentication
pub const X_API_KEY: &str = "x-api-key";
/// API key header variant
pub const X_KEY1: &str = "x-key1";
/// API key header variant
pub const X_KEY2: &str = "x-key2";
/// API secret header
pub const X_API_SECRET: &str = "x-api-secret";
/// Auth Key Map header
pub const X_AUTH_KEY_MAP: &str = "x-auth-key-map";
/// PROXY header
pub const X_VAULT_PROXY_URL: &str = "x-vault-proxy-url";
/// Certificate path header
pub const X_VAULT_CERT: &str = "x-ca-certificate";

/// Header key for lineage metadata fields
pub const X_LINEAGE_IDS: &str = "x-lineage-ids";

/// Prefix for lineage fields in additional_fields
pub const LINEAGE_FIELD_PREFIX: &str = "lineage_";

// =============================================================================
// Error Messages and Codes
// =============================================================================

/// No error message string const
pub const NO_ERROR_MESSAGE: &str = "No error message";
/// No error code string const
pub const NO_ERROR_CODE: &str = "No error code";
/// A string constant representing a redacted or masked value
pub const REDACTED: &str = "Redacted";
pub const UNSUPPORTED_ERROR_MESSAGE: &str = "Unsupported response type";

// =============================================================================
// Card Validation Constants
// =============================================================================

/// Minimum limit of a card number will not be less than 8 by ISO standards
pub const MIN_CARD_NUMBER_LENGTH: usize = 8;
/// Maximum limit of a card number will not exceed 19 by ISO standards
pub const MAX_CARD_NUMBER_LENGTH: usize = 19;

// =============================================================================
// Log Field Names
// =============================================================================

/// Log field for message content
pub const LOG_MESSAGE: &str = "message";
/// Log field for hostname
pub const LOG_HOSTNAME: &str = "hostname";
/// Log field for process ID
pub const LOG_PID: &str = "pid";
/// Log field for log level
pub const LOG_LEVEL: &str = "level";
/// Log field for target
pub const LOG_TARGET: &str = "target";
/// Log field for service name
pub const LOG_SERVICE: &str = "service";
/// Log field for line number
pub const LOG_LINE: &str = "line";
/// Log field for file name
pub const LOG_FILE: &str = "file";
/// Log field for function name
pub const LOG_FN: &str = "fn";
/// Log field for full name
pub const LOG_FULL_NAME: &str = "full_name";
/// Log field for timestamp
pub const LOG_TIME: &str = "time";

/// Constant variable for name
pub const NAME: &str = "UCS";
/// Constant variable for payment service name
pub const PAYMENT_SERVICE_NAME: &str = "payment_service";

pub const CONST_DEVELOPMENT: &str = "development";
pub const CONST_PRODUCTION: &str = "production";

// =============================================================================
// Environment and Configuration
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Env {
    Development,
    Release,
}

impl Env {
    pub const fn current_env() -> Self {
        if cfg!(debug_assertions) {
            Self::Development
        } else {
            Self::Release
        }
    }

    pub const fn config_path(self) -> &'static str {
        match self {
            Self::Development => "development.toml",
            Self::Release => "production.toml",
        }
    }
}

impl std::fmt::Display for Env {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Development => write!(f, "development"),
            Self::Release => write!(f, "release"),
        }
    }
}
