pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

pub(crate) mod api {
    // Base URLs
    pub(crate) const TEST_BASE_URL: &str = "https://testpay.easebuzz.in";
    pub(crate) const PROD_BASE_URL: &str = "https://pay.easebuzz.in";

    // Payment endpoints
    pub(crate) const INITIATE_PAYMENT: &str = "/payment/initiateLink";
    pub(crate) const SEAMLESS_TRANSACTION: &str = "/transaction/create";
    pub(crate) const TRANSACTION_SYNC: &str = "/transaction/v1/sync";

    // UPI endpoints
    pub(crate) const UPI_AUTOPAY: &str = "/upi/autopay";
    pub(crate) const UPI_MANDATE_EXECUTE: &str = "/upi/mandate/execute";

    // Refund endpoints
    pub(crate) const REFUND: &str = "/transaction/refund";
    pub(crate) const REFUND_SYNC: &str = "/transaction/refund/v1/sync";

    // Mandate endpoints
    pub(crate) const MANDATE_CREATE: &str = "/mandate/create";
    pub(crate) const MANDATE_RETRIEVE: &str = "/mandate/retrieve";
    pub(crate) const MANDATE_REVOKE: &str = "/mandate/revoke";

    // Settlement endpoints
    pub(crate) const DELAYED_SETTLEMENT: &str = "/settlement/delayed";
    pub(crate) const DELAYED_SETTLEMENT_STATUS: &str = "/settlement/delayed/status";

    // EMI endpoints
    pub(crate) const GET_EMI_OPTIONS: &str = "/emi/options";
    pub(crate) const GET_PLANS: &str = "/plans";

    // Notification endpoints
    pub(crate) const NOTIFICATION_REQUEST: &str = "/notification/request";
    pub(crate) const NOTIFICATION_SYNC: &str = "/notification/sync";
}

pub(crate) mod payment_status {
    pub(crate) const SUCCESS: &str = "success";
    pub(crate) const PENDING: &str = "pending";
    pub(crate) const FAILURE: &str = "failure";
    pub(crate) const USER_DROPPED: &str = "user_dropped";
}

pub(crate) mod transaction_types {
    pub(crate) const UPI_INTENT: &str = "upi_intent";
    pub(crate) const UPI_COLLECT: &str = "upi_collect";
    pub(crate) const UPI_QR: &str = "upi_qr";
}