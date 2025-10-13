pub(crate) mod headers {
    pub(crate) const CONTENT_TYPE: &str = "Content-Type";
    pub(crate) const AUTHORIZATION: &str = "Authorization";
}

pub(crate) mod api_endpoints {
    pub(crate) const COLLECT: &str = "/upi/api/v3/meCollect";
    pub(crate) const INTENT: &str = "/upi/api/v3/registerIntent";
    pub(crate) const STATUS: &str = "/upi/api/v3/meTransQuery";
    pub(crate) const REFUND: &str = "/upi/api/v3/refund";
}

pub(crate) mod base_urls {
    pub(crate) const PROD: &str = "https://upi-api.hsbc.co.in";
    pub(crate) const SANDBOX: &str = "https://upiapi-sit.hsbc.co.in";
}