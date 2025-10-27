pub const API_VERSION: &str = "v1";
pub const DEFAULT_PAYMENT_METHOD: &str = "UPI";
pub const DEFAULT_PRODUCT_INFO: &str = "Payment";

// EaseBuzz API endpoints
pub mod endpoints {
    pub const TEST_BASE_URL: &str = "https://testpay.easebuzz.in";
    pub const PROD_BASE_URL: &str = "https://pay.easebuzz.in";

    pub mod payments {
        pub const INITIATE: &str = "/payment/initiateLink";
        pub const SEAMLESS: &str = "/payment/seamless";
        pub const SYNC: &str = "/transaction/v1/sync";
    }

    pub mod refunds {
        pub const REFUND: &str = "/transaction/v1/refund";
        pub const REFUND_SYNC: &str = "/transaction/v1/refund/sync";
    }

    pub mod mandates {
        pub const CREATE: &str = "/mandate/create";
        pub const RETRIEVE: &str = "/mandate/retrieve";
        pub const EXECUTE: &str = "/mandate/execute";
        pub const REVOKE: &str = "/mandate/revoke";
    }

    pub mod upi {
        pub const AUTOPAY: &str = "/upi/autopay";
        pub const AUTOPAY_INTENT: &str = "/upi/autopay/intent";
        pub const MANDATE_EXECUTE: &str = "/upi/mandate/execute";
    }

    pub mod notifications {
        pub const SEND: &str = "/notification/send";
        pub const SYNC: &str = "/notification/sync";
    }

    pub mod settlements {
        pub const CREATE: &str = "/settlement/create";
        pub const STATUS: &str = "/settlement/status";
    }

    pub mod plans {
        pub const GET: &str = "/plans/get";
        pub const EMI_OPTIONS: &str = "/emi/options";
    }
}

// Response status codes
pub mod status_codes {
    pub const SUCCESS: i32 = 1;
    pub const FAILURE: i32 = 0;
    pub const PENDING: i32 = 2;
}

// Payment status values
pub mod payment_status {
    pub const SUCCESS: &str = "success";
    pub const FAILURE: &str = "failure";
    pub const PENDING: &str = "pending";
    pub const USER_ABANDONED: &str = "user_abandoned";
}

// Refund status values
pub mod refund_status {
    pub const SUCCESS: &str = "success";
    pub const FAILURE: &str = "failure";
    pub const PENDING: &str = "pending";
    pub const PROCESSING: &str = "processing";
}

// Mandate types
pub mod mandate_types {
    pub const EMI: &str = "EMI";
    pub const SUBSCRIPTION: &str = "SUBSCRIPTION";
    pub const ONE_TIME: &str = "ONE_TIME";
}

// Error codes
pub mod error_codes {
    pub const INVALID_REQUEST: &str = "E001";
    pub const INVALID_AUTH: &str = "E002";
    pub const INVALID_TRANSACTION: &str = "E003";
    pub const INVALID_AMOUNT: &str = "E004";
    pub const INVALID_MERCHANT: &str = "E005";
    pub const TRANSACTION_FAILED: &str = "E006";
    pub const TRANSACTION_PENDING: &str = "E007";
    pub const INVALID_HASH: &str = "E008";
    pub const DUPLICATE_TRANSACTION: &str = "E009";
    pub const INVALID_VPA: &str = "E010";
}

// Hash generation constants
pub mod hash {
    pub const HASH_ALGORITHM: &str = "md5";
    pub const HASH_SEPARATOR: &str = "|";
}

// UPI related constants
pub mod upi {
    pub const PAYMENT_MODE: &str = "UPI";
    pub const INTENT_FLOW: &str = "INTENT";
    pub const COLLECT_FLOW: &str = "COLLECT";
    pub const AUTOPAY_FLOW: &str = "AUTOPAY";
}

// Default values
pub mod defaults {
    pub const CURRENCY: &str = "INR";
    pub const LANGUAGE: &str = "en";
    pub const TIMEOUT: u64 = 300; // 5 minutes
}