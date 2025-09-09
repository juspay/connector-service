pub mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const AUTHORIZATION: &str = "Authorization";
}

pub mod endpoints {
    pub const UAT_BASE_URL: &str = "https://uat.billdesk.com";
    pub const PROD_BASE_URL: &str = "https://www.billdesk.com";
    
    // UPI Initiation endpoints
    pub const UPI_INITIATE_UAT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF007";
    pub const UPI_INITIATE_PROD: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF007";
    
    // Status sync endpoints
    pub const STATUS_SYNC_UAT: &str = "/pgidsk/PGIQueryController";
    pub const STATUS_SYNC_PROD: &str = "/pgidsk/PGIQueryController";
}

pub mod request_types {
    pub const UPI_INITIATE: &str = "BilldeskInitiateUPIRequest";
    pub const STATUS_SYNC: &str = "BilldeskOnlineStatusRequest";
}