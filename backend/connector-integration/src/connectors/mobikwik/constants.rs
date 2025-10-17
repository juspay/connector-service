// Mobikwik API endpoints and constants

pub const MOBIKWIK_API_VERSION: &str = "2.0";
pub const MOBIKWIK_MERCHANT_NAME: &str = "Hyperswitch";

// Test environment endpoints
pub const MOBIKWIK_TEST_BASE_URL: &str = "https://test.mobikwik.com";

// Production environment endpoints  
pub const MOBIKWIK_PROD_BASE_URL: &str = "https://walletapi.mobikwik.com";

// API endpoints
pub const CHECK_EXISTING_USER_URL: &str = "/checkuser";
pub const OTP_GENERATION_URL: &str = "/otpgeneration";
pub const TOKEN_GENERATE_URL: &str = "/tokengenerate";
pub const TOKEN_REGENERATION_URL: &str = "/tokenregeneration";
pub const CREATE_USER_URL: &str = "/createuser";
pub const CHECK_BALANCE_URL: &str = "/checkbalance";
pub const ADD_MONEY_URL: &str = "/addmoney";
pub const REDIRECT_DEBIT_URL: &str = "/redirect";
pub const DEBIT_WALLET_URL: &str = "/debitwallet";
pub const CHECK_STATUS_URL: &str = "/checkstatus";
pub const WALLET_REFUND_URL: &str = "/walletrefund";
pub const REFUND_SYNC_URL: &str = "/refundstatus";

// Status codes
pub const STATUS_SUCCESS: &str = "0";
pub const STATUS_FAILURE: &str = "1";
pub const STATUS_PENDING: &str = "2";
pub const STATUS_PROCESSING: &str = "3";

// Message codes
pub const MSG_CHECK_USER: &str = "CU";
pub const MSG_GENERATE_OTP: &str = "GO";
pub const MSG_GENERATE_TOKEN: &str = "GT";
pub const MSG_REGENERATE_TOKEN: &str = "RT";
pub const MSG_CREATE_USER: &str = "CU";
pub const MSG_CHECK_BALANCE: &str = "CB";
pub const MSG_ADD_MONEY: &str = "AM";
pub const MSG_REDIRECT_DEBIT: &str = "RD";
pub const MSG_DEBIT_WALLET: &str = "DW";
pub const MSG_CHECK_STATUS: &str = "CS";
pub const MSG_WALLET_REFUND: &str = "WR";
pub const MSG_REFUND_SYNC: &str = "RS";

// Token types
pub const TOKEN_TYPE_LOGIN: &str = "login";
pub const TOKEN_TYPE_TRANSACTION: &str = "transaction";

// Transaction types
pub const TXN_TYPE_DEBIT: &str = "debit";
pub const TXN_TYPE_CREDIT: &str = "credit";

// Default values
pub const DEFAULT_VERSION: &str = "2.0";
pub const DEFAULT_SHOW_MOBILE: &str = "true";
pub const DEFAULT_COMMENT: &str = "Payment via Hyperswitch";

// Error messages
pub const ERROR_MISSING_PAYMENT_METHOD: &str = "Payment method type is required for Mobikwik";
pub const ERROR_MISSING_AUTH: &str = "Mobikwik authentication credentials are missing";
pub const ERROR_INVALID_CHECKSUM: &str = "Invalid checksum in Mobikwik response";
pub const ERROR_UNSUPPORTED_PAYMENT_METHOD: &str = "Unsupported payment method for Mobikwik";