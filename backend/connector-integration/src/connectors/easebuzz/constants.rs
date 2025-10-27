pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

pub(crate) mod api {
    // Base URLs
    pub(crate) const PROD_BASE_URL: &str = "https://pay.easebuzz.in";
    pub(crate) const TEST_BASE_URL: &str = "https://testpay.easebuzz.in";

    // Payment endpoints
    pub(crate) const INITIATE_PAYMENT: &str = "/payment/initiateLink";
    pub(crate) const SEAMLESS_TRANSACTION: &str = "/payment/transaction";
    pub(crate) const TRANSACTION_SYNC: &str = "/payment/transaction/status";

    // UPI specific endpoints
    pub(crate) const UPI_INTENT: &str = "/payment/upi/intent";
    pub(crate) const UPI_AUTOPAY: &str = "/payment/upi/autopay";
    pub(crate) const UPI_MANDATE_EXECUTE: &str = "/payment/upi/mandate/execute";

    // OTP endpoints
    pub(crate) const SUBMIT_OTP: &str = "/payment/otp/submit";
    pub(crate) const RESEND_OTP: &str = "/payment/otp/resend";

    // Refund endpoints
    pub(crate) const REFUND: &str = "/payment/refund";
    pub(crate) const REFUND_SYNC: &str = "/payment/refund/status";

    // Mandate endpoints
    pub(crate) const MANDATE_CREATE: &str = "/mandate/create";
    pub(crate) const MANDATE_RETRIEVE: &str = "/mandate/retrieve";
    pub(crate) const MANDATE_REVOKE: &str = "/mandate/revoke";

    // Settlement endpoints
    pub(crate) const DELAYED_SETTLEMENT: &str = "/settlement/delayed";
    pub(crate) const SETTLEMENT_STATUS: &str = "/settlement/status";

    // EMI endpoints
    pub(crate) const EMI_OPTIONS: &str = "/payment/emi/options";
    pub(crate) const EMI_PLANS: &str = "/payment/emi/plans";

    // Notification endpoints
    pub(crate) const NOTIFICATION_REQUEST: &str = "/notification/request";
    pub(crate) const NOTIFICATION_SYNC: &str = "/notification/status";
}

pub(crate) mod payment_methods {
    pub(crate) const UPI: &str = "upi";
    pub(crate) const UPI_INTENT: &str = "upi_intent";
    pub(crate) const UPI_COLLECT: &str = "upi_collect";
    pub(crate) const UPI_QR: &str = "upi_qr";
}

pub(crate) mod status {
    pub(crate) const SUCCESS: &str = "success";
    pub(crate) const PENDING: &str = "pending";
    pub(crate) const FAILURE: &str = "failure";
    pub(crate) const USER_PENDING: &str = "user_pending";
}

pub(crate) mod transaction_types {
    pub(crate) const UPI_INTENT: &str = "UPI_INTENT";
    pub(crate) const UPI_COLLECT: &str = "UPI_COLLECT";
    pub(crate) const UPI_QR: &str = "UPI_QR";
}