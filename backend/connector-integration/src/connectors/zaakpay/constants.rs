pub(crate) mod api {
    pub const TRANSACTION_API: &str = "/transaction/v1";
    pub const CHECK_API: &str = "/check/v1";
    pub const UPDATE_API: &str = "/update/v1";
}

pub(crate) mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const AUTHORIZATION: &str = "Authorization";
}

pub(crate) mod payment_modes {
    pub const UPI: &str = "upi";
    pub const NETBANKING: &str = "netbanking";
    pub const CARD: &str = "card";
}

pub(crate) mod response_codes {
    pub const SUCCESS: &str = "000";
    pub const PENDING: &str = "001";
    pub const FAILURE: &str = "002";
}

pub(crate) mod transaction_status {
    pub const SUCCESS: &str = "success";
    pub const PENDING: &str = "pending";
    pub const FAILURE: &str = "failure";
    pub const REFUNDED: &str = "refunded";
    pub const PARTIALLY_REFUNDED: &str = "partially_refunded";
}