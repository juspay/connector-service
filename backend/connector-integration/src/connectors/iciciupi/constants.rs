pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
    pub(crate) const X_API_KEY: &str = "X-API-Key";
    pub(crate) const AGGREGATOR_ID: &str = "AggregatorId";
    pub(crate) const MERCHANT_ID: &str = "MerchantId";
}

pub mod api_version {
    pub const V0: &str = "v0";
}

pub mod endpoints {
    // Base URLs
    pub const STAGING_BASE_URL: &str = "https://apibankingonesandbox.icicibank.com/api";
    pub const PRODUCTION_BASE_URL: &str = "https://apibankingone.icicibank.com/api";

    // Collect Pay endpoints
    pub const COLLECT_PAY_V2: &str = "/MerchantAPI/UPI/v0/CollectPay2/:merchantId";
    pub const COLLECT_PAY_V3: &str = "/MerchantAPI/UPI/v0/CollectPay3/:merchantId";

    // Transaction Status endpoints
    pub const TRANSACTION_STATUS: &str = "/MerchantAPI/UPI/v0/TransactionStatus/:merchantId";
    pub const TRANSACTION_STATUS_BY_CRITERIA: &str = "/MerchantAPI/UPI/v0/TransactionStatusByCriteria/:merchantId";

    // Refund endpoints
    pub const REFUND: &str = "/MerchantAPI/UPI/v0/Refund/:merchantId";

    // Verify VPA endpoint
    pub const VERIFY_VPA: &str = "/MerchantAPI/UPI/v0/VerifyVPA";

    // Mandate endpoints
    pub const MANDATE_CREATE: &str = "/MerchantAPI/UPI/v0/CreateMandate/:merchantId";
    pub const MANDATE_UPDATE: &str = "/MerchantAPI/UPI/v0/UpdateMandate/:merchantId";
    pub const MANDATE_REVOKE: &str = "/MerchantAPI/UPI/v0/RevokeMandate/:merchantId";
    pub const MANDATE_EXECUTE: &str = "/MerchantAPI/UPI/v0/ExecuteMandate/:merchantId";
    pub const MANDATE_NOTIFICATION: &str = "/MerchantAPI/UPI/v0/MandateNotification/:merchantId";

    // Intent endpoint
    pub const INTENT: &str = "/MerchantAPI/UPI/v0/Intent/:merchantId";
}

pub mod status_codes {
    pub const SUCCESS: &str = "00";
    pub const PENDING: &str = "01";
    pub const FAILURE: &str = "99";
    pub const AUTHENTICATION_PENDING: &str = "02";
    pub const TRANSACTION_NOT_FOUND: &str = "03";
}

pub mod response_types {
    pub const SUCCESS: bool = true;
    pub const FAILURE: bool = false;
}