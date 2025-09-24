pub struct EaseBuzzUrls;

impl EaseBuzzUrls {
    // Test URLs
    pub const TEST_BASE_URL: &str = "https://testpay.easebuzz.in";
    pub const TEST_DASHBOARD_URL: &str = "https://testdashboard.easebuzz.in";
    pub const TEST_API_BASE_URL: &str = "https://sandboxapi.easebuzz.in";

    // Production URLs  
    pub const PROD_BASE_URL: &str = "https://pay.easebuzz.in";
    pub const PROD_DASHBOARD_URL: &str = "https://dashboard.easebuzz.in";
    pub const PROD_API_BASE_URL: &str = "https://api.easebuzz.in";

    // Payment Endpoints
    pub const INITIATE_PAYMENT: &str = "/payment/initiateLink";
    pub const SEAMLESS_TRANSACTION: &str = "/initiate_seamless_payment/";
    pub const TRANSACTION_SYNC: &str = "/transaction/v1/retrieve";
    pub const REFUND: &str = "/transaction/v2/refund";
    pub const REFUND_SYNC: &str = "/refund/v1/retrieve";

    // EMI & Plans
    pub const GET_EMI_OPTIONS: &str = "/v1/getEMIOptions";
    pub const GET_PLANS: &str = "/emi/v1/retrieve";

    // Settlement Endpoints
    pub const DELAYED_SETTLEMENT: &str = "/settlements/v1/ondemand/initiate/";
    pub const DELAYED_SETTLEMENT_STATUS: &str = "/settlements/v1/ondemand/status/";

    // Auth & Capture
    pub const AUTHZ_REQUEST: &str = "/payment/v1/capture/direct";

    // Mandate Management Endpoints (Autocollect API)
    pub const GENERATE_ACCESS_KEY: &str = "/autocollect/v1/access-key/generate/";
    pub const MANDATE_CREATION: &str = "/autocollect/v1/mandate/";
    pub const MANDATE_RETRIEVE: &str = "/autocollect/v1/mandate/:txnId/";
    pub const PRESENTMENT_REQUEST_INITIATE: &str = "/autocollect/v1/mandate/presentment/";
    pub const DEBIT_REQUEST_RETRIEVE: &str = "/autocollect/v1/mandate/presentment/:txnId/";
    pub const UPI_AUTOPAY: &str = "/autocollect/v1/mandate/process/";
    pub const NOTIFICATION_REQUEST: &str = "/autocollect/v1/mandate/notify/";
    pub const UPI_MANDATE_EXECUTE: &str = "/autocollect/v1/mandate/execute/";
    pub const REVOKE_MANDATE: &str = "/autocollect/v1/mandate/:mandateId/status_update/";
    pub const MANDATE_NOTIFICATION_SYNC: &str = "/autocollect/v1/mandate/notification/:notificationReqId/";
}