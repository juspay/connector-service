pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

pub(crate) mod api_tags {
    pub(crate) const TRANSACTION: &str = "transaction";
    pub(crate) const AUTH_CAPTURE: &str = "auth_capture";
    pub(crate) const SI_TRANSACTION: &str = "si_transaction";
    pub(crate) const UPI_TRANSACTION: &str = "upi_transaction";
    pub(crate) const UPI_TOKEN_GENERATION: &str = "upi_token_generation";
    pub(crate) const REFUND_ARN_SYNC: &str = "refund_arn_sync";
}

pub(crate) mod endpoints {
    pub(crate) const TRANSACTION_DETAILS_NEW: &str = "/PaymentGateway/services/TransactionDetailsNew";
    pub(crate) const MERCHANT2_PG: &str = "/PaymentGateway/merchant2.pg";
    pub(crate) const UPI_TOKEN_GENERATION: &str = "/PaymentGateway/services/UPITokenGeneration";
    pub(crate) const UPI_TRANSACTION: &str = "/PaymentGateway/services/UPITransaction";
    pub(crate) const REFUND_ARN_SYNC: &str = "/PaymentGateway/services/RefundArnSync";
}

pub(crate) mod base_urls {
    pub(crate) const PRODUCTION: &str = "https://www.tpsl-india.in";
    pub(crate) const TEST: &str = "https://www.tekprocess.co.in";
}

pub(crate) mod payment_methods {
    pub(crate) const UPI: &str = "UPI";
    pub(crate) const UPI_INTENT: &str = "UPI_INTENT";
    pub(crate) const UPI_COLLECT: &str = "UPI_COLLECT";
}

pub(crate) mod transaction_types {
    pub(crate) const SALE: &str = "SALE";
    pub(crate) const AUTHORIZE: &str = "AUTHORIZE";
    pub(crate) const CAPTURE: &str = "CAPTURE";
    pub(crate) const REFUND: &str = "REFUND";
    pub(crate) const STATUS: &str = "STATUS";
}

pub(crate) mod response_types {
    pub(crate) const REDIRECT: &str = "REDIRECT";
    pub(crate) const S2S: &str = "S2S";
    pub(crate) const ERROR: &str = "ERROR";
}

pub(crate) mod status_codes {
    pub(crate) const SUCCESS: &str = "SUCCESS";
    pub(crate) const PENDING: &str = "PENDING";
    pub(crate) const FAILURE: &str = "FAILURE";
    pub(crate) const PROCESSING: &str = "PROCESSING";
    pub(crate) const AUTHENTICATION_PENDING: &str = "AUTHENTICATION_PENDING";
}