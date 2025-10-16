pub mod api {
    pub const INITIATE_PAYMENT: &str = "/payment/initiateLink";
    pub const SEAMLESS_TRANSACTION: &str = "/payment/transaction";
    pub const TRANSACTION_SYNC: &str = "/transaction/sync";
    pub const REFUND: &str = "/transaction/refund";
    pub const REFUND_SYNC: &str = "/transaction/refundSync";
    pub const UPI_AUTOPAY: &str = "/upi/autopay";
    pub const UPI_MANDATE_EXECUTE: &str = "/upi/mandate/execute";
    pub const MANDATE_RETRIEVE: &str = "/mandate/retrieve";
    pub const DEBIT_REQUEST_RETRIEVE: &str = "/debit/request/retrieve";
    pub const NOTIFICATION_REQUEST: &str = "/notification/request";
    pub const NOTIFICATION_SYNC: &str = "/notification/sync";
    pub const REVOKE_MANDATE: &str = "/mandate/revoke";
}

pub mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const AUTHORIZATION: &str = "Authorization";
    pub const ACCEPT: &str = "Accept";
}

pub mod test_urls {
    pub const BASE_URL: &str = "https://testpay.easebuzz.in";
}

pub mod prod_urls {
    pub const BASE_URL: &str = "https://pay.easebuzz.in";
}