pub mod headers;

pub const API_BASE_URL: &str = "https://api.razorpay.com/v1";

pub mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const AUTHORIZATION: &str = "Authorization";
}

pub mod api_tags {
    pub const AUTHORIZE: &str = "authorize";
    pub const PSYNC: &str = "psync";
    pub const RSYNC: &str = "rsync";
}

pub mod endpoints {
    pub const PAYMENTS: &str = "/payments";
    pub const PAYMENTS_CAPTURE: &str = "/payments/{payment_id}/capture";
    pub const ORDERS: &str = "/orders";
    pub const REFUNDS: &str = "/refunds";
    pub const PAYMENT_SYNC: &str = "/payments/{payment_id}";
    pub const REFUND_SYNC: &str = "/refunds/{refund_id}";
}