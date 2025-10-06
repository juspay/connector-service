pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

pub(crate) mod api {
    pub(crate) const COLLECT_ENDPOINT: &str = "/upi/meTransCollectSvc";
    pub(crate) const STATUS_ENDPOINT: &str = "/upi/transactionStatusQuery";
    pub(crate) const REFUND_ENDPOINT: &str = "/upi/refundReqSvc";
    pub(crate) const VERIFY_VPA_ENDPOINT: &str = "/upi/checkMeVirtualAddress";
}

pub(crate) mod base_urls {
    pub(crate) const PROD: &str = "https://upi.hdfcbank.com";
    pub(crate) const SANDBOX: &str = "https://upitest.hdfcbank.com";
}