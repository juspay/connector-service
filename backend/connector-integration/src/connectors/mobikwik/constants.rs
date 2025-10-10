pub(crate) mod endpoints {
    // Mobikwik API endpoints
    pub const CHECK_EXISTING_USER_URL: &str = "/checkexistinguser";
    pub const OTP_GENERATION_URL: &str = "/otpgeneration";
    pub const TOKEN_GENERATE_URL: &str = "/tokengenerate";
    pub const TOKEN_REGENERATION_URL: &str = "/tokenregeneration";
    pub const CREATE_USER_URL: &str = "/createuser";
    pub const CHECK_BALANCE_URL: &str = "/checkbalance";
    pub const ADD_MONEY_DEBIT_URL: &str = "/addmoneydebit";
    pub const REDIRECT_DEBIT_URL: &str = "/redirectdebit";
    pub const DEBIT_BALANCE_URL: &str = "/debitbalance";
    pub const CHECK_STATUS_URL: &str = "/checkstatus";
    pub const REFUND_URL: &str = "/walletrefund";
    pub const REFUND_SYNC_URL: &str = "/refundstatus";

    // Base URLs
    pub const TEST_BASE_URL: &str = "https://test.mobikwik.com";
    pub const PROD_BASE_URL: &str = "https://walletapi.mobikwik.com";
}

pub(crate) mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const ACCEPT: &str = "Accept";
}

pub(crate) mod api_versions {
    pub const API_VERSION: &str = "2.0";
}

pub(crate) mod message_codes {
    pub const CHECK_EXISTING_USER: &str = "301";
    pub const OTP_GENERATION: &str = "302";
    pub const TOKEN_GENERATE: &str = "303";
    pub const TOKEN_REGENERATION: &str = "304";
    pub const CREATE_USER: &str = "305";
    pub const CHECK_BALANCE: &str = "306";
    pub const ADD_MONEY_DEBIT: &str = "307";
    pub const REDIRECT_DEBIT: &str = "308";
    pub const DEBIT_BALANCE: &str = "309";
    pub const CHECK_STATUS: &str = "310";
    pub const REFUND: &str = "311";
    pub const REFUND_SYNC: &str = "312";
}

pub(crate) mod token_types {
    pub const ACCESS_TOKEN: &str = "access";
    pub const REGENERATE_TOKEN: &str = "regenerate";
}

pub(crate) mod transaction_types {
    pub const DEBIT: &str = "debit";
    pub const CREDIT: &str = "credit";
}