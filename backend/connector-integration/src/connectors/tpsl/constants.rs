pub mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const AUTHORIZATION: &str = "Authorization";
}

pub mod api_tags {
    pub const TRANSACTION: &str = "transaction";
    pub const AUTH_CAPTURE: &str = "auth_capture";
    pub const SI_TRANSACTION: &str = "si_transaction";
    pub const UPI_TRANSACTION: &str = "upi_transaction";
    pub const UPI_TOKEN_GENERATION: &str = "upi_token_generation";
    pub const REFUND_ARN_SYNC: &str = "refund_arn_sync";
}

pub mod endpoints {
    pub const TRANSACTION_DETAILS_NEW: &str = "/PaymentGateway/services/TransactionDetailsNew";
    pub const MERCHANT2_PG: &str = "/PaymentGateway/merchant2.pg";
    pub const UPI_TRANSACTION: &str = "/PaymentGateway/upiTransaction";
    pub const UPI_TOKEN_GENERATION: &str = "/PaymentGateway/upiTokenGeneration";
    pub const REFUND_ARN_SYNC: &str = "/PaymentGateway/refundArnSync";
}

pub mod base_urls {
    pub const PRODUCTION: &str = "https://www.tpsl-india.in";
    pub const TEST: &str = "https://www.tekprocess.co.in";
}

pub mod payment_methods {
    pub const UPI: &str = "UPI";
    pub const UPI_INTENT: &str = "UPI_INTENT";
    pub const UPI_COLLECT: &str = "UPI_COLLECT";
}

pub mod transaction_types {
    pub const SALE: &str = "SALE";
    pub const AUTHORIZE: &str = "AUTHORIZE";
    pub const CAPTURE: &str = "CAPTURE";
    pub const REFUND: &str = "REFUND";
    pub const STATUS: &str = "STATUS";
}

pub mod response_types {
    pub const REDIRECT: &str = "REDIRECT";
    pub const S2S: &str = "S2S";
    pub const ERROR: &str = "ERROR";
}

pub mod currencies {
    pub const INR: &str = "INR";
    pub const USD: &str = "USD";
}

pub mod status_codes {
    pub const SUCCESS: &str = "SUCCESS";
    pub const PENDING: &str = "PENDING";
    pub const FAILURE: &str = "FAILURE";
    pub const PROCESSING: &str = "PROCESSING";
    pub const AUTHENTICATION_PENDING: &str = "AUTHENTICATION_PENDING";
}