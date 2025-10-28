pub mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const AUTHORIZATION: &str = "Authorization";
}

pub mod api_endpoints {
    // Base URLs for test and production
    pub const TEST_BASE_URL: &str = "https://www.tekprocess.co.in";
    pub const PROD_BASE_URL: &str = "https://www.tpsl-india.in";
    
    // Transaction endpoints
    pub const TRANSACTION_DETAILS: &str = "/PaymentGateway/services/TransactionDetailsNew";
    pub const AUTH_CAPTURE: &str = "/PaymentGateway/merchant2.pg";
    pub const SI_TRANSACTION: &str = "/PaymentGateway/services/TransactionDetailsNew";
    pub const UPI_TRANSACTION: &str = "/PaymentGateway/services/TransactionDetailsNew";
    pub const UPI_TOKEN_GENERATION: &str = "/PaymentGateway/services/TransactionDetailsNew";
    pub const REFUND_ARN_SYNC: &str = "/PaymentGateway/services/TransactionDetailsNew";
}

pub mod payment_methods {
    pub const UPI: &str = "UPI";
    pub const UPI_INTENT: &str = "UPI_INTENT";
    pub const UPI_COLLECT: &str = "UPI_COLLECT";
}

pub mod transaction_types {
    pub const AUTHORIZE: &str = "AUTHORIZE";
    pub const CAPTURE: &str = "CAPTURE";
    pub const REFUND: &str = "REFUND";
    pub const SYNC: &str = "SYNC";
    pub const MANDATE_REGISTRATION: &str = "MANDATE_REGISTRATION";
    pub const MANDATE_EXECUTION: &str = "MANDATE_EXECUTION";
}

pub mod response_codes {
    pub const SUCCESS: &str = "SUCCESS";
    pub const PENDING: &str = "PENDING";
    pub const FAILURE: &str = "FAILURE";
    pub const AUTHENTICATION_PENDING: &str = "AUTHENTICATION_PENDING";
}

pub mod error_codes {
    pub const INVALID_REQUEST: &str = "INVALID_REQUEST";
    pub const AUTHENTICATION_FAILED: &str = "AUTHENTICATION_FAILED";
    pub const TRANSACTION_FAILED: &str = "TRANSACTION_FAILED";
    pub const INVALID_MERCHANT: &str = "INVALID_MERCHANT";
    pub const INVALID_CURRENCY: &str = "INVALID_CURRENCY";
}