pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

pub(crate) mod api {
    pub(crate) const INITIATE_PAYMENT: &str = "/payment/initiateLink";
    pub(crate) const SEAMLESS_TRANSACTION: &str = "/payment/initiateTransaction";
    pub(crate) const TRANSACTION_SYNC: &str = "/payment/txnSync";
    pub(crate) const REFUND: &str = "/transaction/refund";
    pub(crate) const REFUND_SYNC: &str = "/transaction/refundSync";
    pub(crate) const SUBMIT_OTP: &str = "/auth/submitOtp";
    pub(crate) const RESEND_OTP: &str = "/auth/resendOtp";
    pub(crate) const GET_EMI_OPTIONS: &str = "/emi/getEMIOptions";
    pub(crate) const GET_PLANS: &str = "/plans/getPlans";
    pub(crate) const DELAYED_SETTLEMENT: &str = "/settlement/create";
    pub(crate) const DELAYED_SETTLEMENT_STATUS: &str = "/settlement/status";
    pub(crate) const AUTHZ_REQUEST: &str = "/auth/authorize";
    pub(crate) const GENERATE_ACCESS_KEY: &str = "/auth/accessKey";
    pub(crate) const MANDATE_CREATION: &str = "/mandate/create";
    pub(crate) const MANDATE_RETRIEVE: &str = "/mandate/retrieve";
    pub(crate) const PRESENTMENT_REQUEST_INITIATE: &str = "/mandate/presentment";
    pub(crate) const DEBIT_REQUEST_RETRIEVE: &str = "/mandate/debitRequest";
    pub(crate) const UPI_AUTOPAY: &str = "/upi/autopay";
    pub(crate) const NOTIFICATION_REQ: &str = "/notification/send";
    pub(crate) const UPI_MANDATE_EXECUTE: &str = "/upi/mandateExecute";
    pub(crate) const REVOKE_MANDATE: &str = "/mandate/revoke";
    pub(crate) const MANDATE_NOTIFICATION_SYNC: &str = "/notification/sync";
}

pub(crate) mod base_url {
    pub(crate) const PRODUCTION: &str = "https://pay.easebuzz.in";
    pub(crate) const TEST: &str = "https://testpay.easebuzz.in";
}