pub const EASEBUZZ_TEST_BASE_URL: &str = "https://testpay.easebuzz.in";
pub const EASEBUZZ_PRODUCTION_BASE_URL: &str = "https://pay.easebuzz.in";

// API Endpoints
pub const EASEBUZZ_INITIATE_PAYMENT: &str = "/payment/initiateLink";
pub const EASEBUZZ_SEAMLESS_TRANSACTION: &str = "/payment/seamless";
pub const EASEBUZZ_TXN_SYNC: &str = "/payment/txnSync";
pub const EASEBUZZ_REFUND: &str = "/transaction/refund";
pub const EASEBUZZ_REFUND_SYNC: &str = "/transaction/refundSync";
pub const EASEBUZZ_SUBMIT_OTP: &str = "/auth/submitOtp";
pub const EASEBUZZ_RESEND_OTP: &str = "/auth/resendOtp";
pub const EASEBUZZ_GET_EMI_OPTIONS: &str = "/emi/getEMIOptions";
pub const EASEBUZZ_GET_PLANS: &str = "/emi/getPlans";
pub const EASEBUZZ_DELAYED_SETTLEMENT: &str = "/settlement/create";
pub const EASEBUZZ_DELAYED_SETTLEMENT_STATUS: &str = "/settlement/status";
pub const EASEBUZZ_AUTHZ_REQUEST: &str = "/auth/authorize";
pub const EASEBUZZ_GENERATE_ACCESS_KEY: &str = "/auth/accessKey";
pub const EASEBUZZ_MANDATE_CREATION: &str = "/mandate/create";
pub const EASEBUZZ_MANDATE_RETRIEVE: &str = "/mandate/retrieve";
pub const EASEBUZZ_PRESENTMENT_REQUEST_INITIATE: &str = "/mandate/presentment";
pub const EASEBUZZ_DEBIT_REQUEST_RETRIEVE: &str = "/mandate/debitRetrieve";
pub const EASEBUZZ_UPI_AUTOPAY: &str = "/upi/autopay";
pub const EASEBUZZ_NOTIFICATION_REQ: &str = "/notification/send";
pub const EASEBUZZ_UPI_MANDATE_EXECUTE: &str = "/upi/mandateExecute";
pub const EASEBUZZ_REVOKE_MANDATE: &str = "/mandate/revoke";
pub const EASEBUZZ_MANDATE_NOTIFICATION_SYNC_REQ: &str = "/notification/sync";