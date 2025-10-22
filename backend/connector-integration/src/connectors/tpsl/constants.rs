pub mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const AUTHORIZATION: &str = "Authorization";
}

pub mod api_endpoints {
    pub const TRANSACTION_DETAILS_NEW: &str = "/PaymentGateway/services/TransactionDetailsNew";
    pub const AUTH_CAPTURE: &str = "/PaymentGateway/merchant2.pg";
    pub const SI_TRANSACTION: &str = "/PaymentGateway/services/SITransaction";
    pub const UPI_TRANSACTION: &str = "/PaymentGateway/services/UPITransaction";
    pub const UPI_TOKEN_GENERATION: &str = "/PaymentGateway/services/UPITokenGeneration";
    pub const REFUND_ARN_SYNC: &str = "/PaymentGateway/services/RefundArnSync";
}

pub mod base_urls {
    pub const PRODUCTION: &str = "https://www.tpsl-india.in";
    pub const TEST: &str = "https://www.tekprocess.co.in";
}

pub mod payment_methods {
    pub const UPI: &str = "UPI";
    pub const UPI_COLLECT: &str = "UPI_COLLECT";
    pub const UPI_INTENT: &str = "UPI_INTENT";
}

pub mod transaction_types {
    pub const AUTHORIZE: &str = "AUTHORIZE";
    pub const CAPTURE: &str = "CAPTURE";
    pub const SALE: &str = "SALE";
    pub const VERIFY: &str = "VERIFY";
    pub const SCHEDULE: &str = "SCHEDULE";
}

pub mod response_types {
    pub const REDIRECT: &str = "REDIRECT";
    pub const S2S: &str = "S2S";
    pub const ERROR: &str = "ERROR";
}

pub mod status_codes {
    pub const SUCCESS: &str = "SUCCESS";
    pub const FAILURE: &str = "FAILURE";
    pub const PENDING: &str = "PENDING";
    pub const PROCESSING: &str = "PROCESSING";
}