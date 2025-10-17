pub mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const AUTHORIZATION: &str = "Authorization";
}

pub mod api_endpoints {
    pub const INITIATE_PAYMENT: &str = "/payment/initiateLink";
    pub const SEAMLESS_TRANSACTION: &str = "/payment/seamless";
    pub const TRANSACTION_SYNC: &str = "/transaction/sync";
    pub const REFUND: &str = "/transaction/refund";
    pub const REFUND_SYNC: &str = "/transaction/refundSync";
    pub const UPI_AUTOPAY: &str = "/upi/autopay";
    pub const UPI_MANDATE_EXECUTE: &str = "/upi/mandate/execute";
    pub const MANDATE_RETRIEVE: &str = "/mandate/retrieve";
    pub const PRESENTMENT_REQUEST_INITIATE: &str = "/presentment/initiate";
    pub const DEBIT_REQUEST_RETRIEVE: &str = "/debit/retrieve";
    pub const NOTIFICATION_REQUEST: &str = "/notification/request";
    pub const MANDATE_NOTIFICATION_SYNC: &str = "/mandate/notification/sync";
    pub const REVOKE_MANDATE: &str = "/mandate/revoke";
}

pub mod base_urls {
    pub const PRODUCTION: &str = "https://pay.easebuzz.in";
    pub const TEST: &str = "https://testpay.easebuzz.in";
}

pub mod payment_modes {
    pub const UPI: &str = "UPI";
    pub const UPI_INTENT: &str = "UPI_INTENT";
    pub const UPI_COLLECT: &str = "UPI_COLLECT";
    pub const UPI_QR: &str = "UPI_QR";
}

pub mod response_status {
    pub const SUCCESS: &str = "success";
    pub const FAILURE: &str = "failure";
    pub const PENDING: &str = "pending";
    pub const USER_PENDING: &str = "user_pending";
}

pub mod transaction_status {
    pub const SUCCESS: i32 = 1;
    pub const FAILURE: i32 = 0;
    pub const PENDING: i32 = 2;
}