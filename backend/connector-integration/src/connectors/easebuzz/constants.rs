// API constants for EaseBuzz connector

pub const EASEBUZZ_INITIATE_PAYMENT: &str = "/payment/initiateLink";
pub const EASEBUZZ_SEAMLESS_TRANSACTION: &str = "/payment/transaction";
pub const EASEBUZZ_TXN_SYNC: &str = "/transaction/sync";
pub const EASEBUZZ_REFUND: &str = "/transaction/refund";
pub const EASEBUZZ_REFUND_SYNC: &str = "/transaction/refundSync";
pub const EASEBUZZ_GET_EMI_OPTIONS: &str = "/emi/getOptions";
pub const EASEBUZZ_GET_PLANS: &str = "/plans/get";
pub const EASEBUZZ_DELAYED_SETTLEMENT: &str = "/settlement/create";
pub const EASEBUZZ_DELAYED_SETTLEMENT_STATUS: &str = "/settlement/status";
pub const EASEBUZZ_AUTHZ_REQUEST: &str = "/auth/authorize";
pub const EASEBUZZ_GENERATE_ACCESS_KEY: &str = "/auth/accessKey";
pub const EASEBUZZ_MANDATE_CREATION: &str = "/mandate/create";
pub const EASEBUZZ_MANDATE_RETRIEVE: &str = "/mandate/retrieve";
pub const EASEBUZZ_PRESENTMENT_REQUEST_INITIATE: &str = "/mandate/debit";
pub const EASEBUZZ_DEBIT_REQUEST_RETRIEVE: &str = "/mandate/debitStatus";
pub const EASEBUZZ_UPI_AUTOPAY: &str = "/upi/autopay";
pub const EASEBUZZ_NOTIFICATION_REQ: &str = "/notification/send";
pub const EASEBUZZ_UPI_MANDATE_EXECUTE: &str = "/upi/execute";
pub const EASEBUZZ_REVOKE_MANDATE: &str = "/mandate/revoke";
pub const EASEBUZZ_MANDATE_NOTIFICATION_SYNC: &str = "/notification/sync";

pub const EASEBUZZ_TEST_BASE_URL: &str = "https://testpay.easebuzz.in";
pub const EASEBUZZ_PROD_BASE_URL: &str = "https://pay.easebuzz.in";

pub const EASEBUZZ_API_VERSION: &str = "v1";