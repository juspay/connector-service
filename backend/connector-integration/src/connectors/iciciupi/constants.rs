pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

pub mod api_endpoints {
    // Base URLs from Haskell Endpoints.hs
    pub const STAGING_BASE_URL: &str = "https://apibankingonesandbox.icicibank.com/api";
    pub const PRODUCTION_BASE_URL: &str = "https://apibankingone.icicibank.com/api";

    // API endpoints from Haskell Endpoints.hs
    pub const COLLECT_PAY: &str = "/MerchantAPI/UPI/v0/CollectPay2/:merchantId";
    pub const TRANSACTION_STATUS: &str = "/MerchantAPI/UPI/v0/TransactionStatus3/:merchantId";
    pub const CALLBACK_STATUS: &str = "/MerchantAPI/UPI/v0/CallbackStatus2/:merchantId";
    pub const REFUND: &str = "/MerchantAPI/UPI/v0/Refund/:merchantId";
    pub const VERIFY_VPA: &str = "/v1/upi2/ValidateAddress";
    pub const CREATE_MANDATE: &str = "/MerchantAPI/UPI2/v1/CreateMandate";
    pub const EXECUTE_MANDATE: &str = "/MerchantAPI/UPI2/v1/ExecuteMandate";
    pub const MANDATE_STATUS: &str = "/MerchantAPI/UPI2/v1/TransactionStatus";
    pub const MANDATE_NOTIFICATION: &str = "/MerchantAPI/UPI2/v1/MandateNotification";
    pub const MANDATE_UPDATE: &str = "/MerchantAPI/UPI2/v1/CreateMandate";
    pub const MANDATE_STATUS_BY_CRITERIA: &str = "/MerchantAPI/UPI2/v1/TransactionStatusByCriteria";
}

pub mod flow_names {
    pub const AUTHORIZE: &str = "Authorize";
    pub const PSYNC: &str = "PSync";
    pub const RSYNC: &str = "RSync";
}