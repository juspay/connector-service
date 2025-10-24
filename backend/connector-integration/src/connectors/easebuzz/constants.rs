pub mod api;

pub struct EasebuzzUrls;

impl EasebuzzUrls {
    pub const TEST_BASE_URL: &'static str = "https://testpay.easebuzz.in";
    pub const PROD_BASE_URL: &'static str = "https://pay.easebuzz.in";
}

pub struct EasebuzzApi;

impl EasebuzzApi {
    pub const INITIATE_PAYMENT: &'static str = "/payment/initiateLink";
    pub const SEAMLESS_TRANSACTION: &'static str = "/payment/transaction";
    pub const TRANSACTION_SYNC: &'static str = "/transaction/sync";
    pub const REFUND: &'static str = "/transaction/refund";
    pub const REFUND_SYNC: &'static str = "/transaction/refundSync";
    pub const UPI_AUTOPAY: &'static str = "/upi/autopay";
    pub const UPI_MANDATE_EXECUTE: &'static str = "/upi/mandate/execute";
    pub const MANDATE_RETRIEVE: &'static str = "/mandate/retrieve";
    pub const NOTIFICATION: &'static str = "/notification/send";
    pub const NOTIFICATION_SYNC: &'static str = "/notification/sync";
}

pub struct EasebuzzHeaders;

impl EasebuzzHeaders {
    pub const CONTENT_TYPE: &'static str = "Content-Type";
    pub const AUTHORIZATION: &'static str = "Authorization";
    pub const ACCEPT: &'static str = "Accept";
}