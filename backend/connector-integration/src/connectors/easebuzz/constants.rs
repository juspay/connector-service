pub mod api;

pub const EASEBUZZ: &str = "easebuzz";

// API Endpoints
pub mod endpoints {
    pub const INITIATE_PAYMENT: &str = "/payment/initiateLink";
    pub const SEAMLESS_TRANSACTION: &str = "/payment/transaction";
    pub const TRANSACTION_SYNC: &str = "/transaction/sync";
    pub const REFUND: &str = "/transaction/refund";
    pub const REFUND_SYNC: &str = "/transaction/refundSync";
    pub const EMI_OPTIONS: &str = "/emi/getOptions";
    pub const PLANS: &str = "/plans/getPlans";
    pub const DELAYED_SETTLEMENT: &str = "/settlement/create";
    pub const DELAYED_SETTLEMENT_STATUS: &str = "/settlement/status";
    pub const AUTHZ_REQUEST: &str = "/auth/authorize";
    pub const ACCESS_KEY: &str = "/auth/accessKey";
    pub const MANDATE_CREATION: &str = "/mandate/create";
    pub const MANDATE_RETRIEVE: &str = "/mandate/retrieve";
    pub const PRESENTMENT_REQUEST_INITIATE: &str = "/mandate/debitRequest";
    pub const DEBIT_REQUEST_RETRIEVE: &str = "/mandate/debitRequestRetrieve";
    pub const UPI_AUTOPAY: &str = "/upi/autopay";
    pub const NOTIFICATION_REQUEST: &str = "/notification/send";
    pub const UPI_MANDATE_EXECUTE: &str = "/upi/mandateExecute";
    pub const REVOKE_MANDATE: &str = "/mandate/revoke";
    pub const MANDATE_NOTIFICATION_SYNC: &str = "/notification/sync";
}

// Base URLs
pub mod base_urls {
    pub const PRODUCTION: &str = "https://pay.easebuzz.in";
    pub const TEST: &str = "https://testpay.easebuzz.in";
}

// Headers
pub mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const ACCEPT: &str = "Accept";
    pub const AUTHORIZATION: &str = "Authorization";
}

// Content Types
pub mod content_types {
    pub const APPLICATION_JSON: &str = "application/json";
    pub const APPLICATION_X_WWW_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
}