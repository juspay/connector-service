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
    pub(crate) const AUTH_CAPTURE: &str = "/PaymentGateway/merchant2.pg/:merchantCode";
    pub(crate) const SI_TRANSACTION: &str = "/PaymentGateway/services/SITransaction";
    pub(crate) const UPI_TRANSACTION: &str = "/PaymentGateway/services/UPITransaction";
    pub(crate) const UPI_TOKEN_GENERATION: &str = "/PaymentGateway/services/UPITokenGeneration";
    pub(crate) const REFUND_ARN_SYNC: &str = "/PaymentGateway/services/RefundArnSync";
}

pub(crate) mod base_urls {
    pub(crate) const PRODUCTION: &str = "https://www.tpsl-india.in";
    pub(crate) const TEST: &str = "https://www.tekprocess.co.in";
}