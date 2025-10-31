pub mod api;

pub static DEFAULT_BASE_URL: &str = "https://api.zaakpay.com";

pub mod api {
    pub mod transactions {
        pub const AUTHORIZE: &str = "/transact";
        pub const SYNC: &str = "/check";
        pub const REFUND: &str = "/update";
    }
}

pub mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const AUTHORIZATION: &str = "Authorization";
}

pub mod payment_modes {
    pub const UPI: &str = "upi";
    pub const NETBANKING: &str = "netbanking";
    pub const CARD: &str = "card";
}

pub mod response_codes {
    pub const SUCCESS: &str = "100";
    pub const PENDING: &str = "101";
    pub const FAILURE: &str = "102";
    pub const INVALID_REQUEST: &str = "103";
    pub const AUTHENTICATION_FAILED: &str = "104";
}

pub mod checksum {
    pub const ALGORITHM: &str = "SHA256";
}