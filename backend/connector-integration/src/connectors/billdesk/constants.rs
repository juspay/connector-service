pub mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const AUTHORIZATION: &str = "Authorization";
}

pub mod api_tags {
    pub const AUTHORIZE: &str = "BilldeskInitiateUPIRequest";
    pub const PSYNC: &str = "BilldeskOnlineStatusRequest";
    pub const RSYNC: &str = "BilldeskRefundStatusRequestV2";
}

pub mod endpoints {
    // UAT endpoints
    pub const UAT_BASE_URL: &str = "https://uat.billdesk.com";
    pub const UAT_AUTHORIZE_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF011";
    pub const UAT_PSYNC_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF002";
    pub const UAT_RSYNC_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF004";

    // Production endpoints
    pub const PROD_BASE_URL: &str = "https://www.billdesk.com";
    pub const PROD_AUTHORIZE_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF011";
    pub const PROD_PSYNC_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF002";
    pub const PROD_RSYNC_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF004";
}

pub mod request_types {
    pub const AUTHORIZE: &str = "BilldeskInitiateUPIRequest";
    pub const PSYNC: &str = "BilldeskOnlineStatusRequest";
    pub const RSYNC: &str = "BilldeskRefundStatusRequestV2";
}

pub mod response_types {
    pub const AUTHORIZE: &str = "BilldeskUPIInitiateResponse";
    pub const PSYNC: &str = "BilldeskOnlineStatusResponse";
    pub const RSYNC: &str = "BilldeskOnlineRefundStatusResponseV2";
}