pub mod api;

pub struct EaseBuzzConstants;

impl EaseBuzzConstants {
    pub const BASE_URL_PROD: &'static str = "https://pay.easebuzz.in";
    pub const BASE_URL_TEST: &'static str = "https://testpay.easebuzz.in";

    // API Endpoints
    pub const INITIATE_PAYMENT: &'static str = "/payment/initiateLink";
    pub const SEAMLESS_TRANSACTION: &'static str = "/transaction";
    pub const TRANSACTION_SYNC: &'static str = "/transaction/sync";
    pub const REFUND: &'static str = "/transaction/refund";
    pub const REFUND_SYNC: &'static str = "/transaction/refund/sync";
    pub const UPI_AUTOPAY: &'static str = "/upi/autopay";
    pub const UPI_MANDATE_EXECUTE: &'static str = "/upi/mandate/execute";
    pub const MANDATE_RETRIEVE: &'static str = "/mandate/retrieve";
    pub const MANDATE_CREATE: &'static str = "/mandate/create";
    pub const NOTIFICATION_REQUEST: &'static str = "/notification/request";
    pub const NOTIFICATION_SYNC: &'static str = "/notification/sync";
    pub const REVOKE_MANDATE: &'static str = "/mandate/revoke";
}

pub mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const AUTHORIZATION: &str = "Authorization";
    pub const ACCEPT: &str = "Accept";
    pub const USER_AGENT: &str = "User-Agent";
}