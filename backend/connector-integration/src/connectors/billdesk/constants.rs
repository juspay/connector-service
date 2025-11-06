pub mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const AUTHORIZATION: &str = "Authorization";
}

pub mod api_tags {
    // Based on Haskell implementation flow functions
    pub const AUTHORIZE: &str = "BilldeskInitiateUPIRequest";
    pub const PSYNC: &str = "BilldeskOnlineStatusRequest";
    pub const RSYNC: &str = "BilldeskRefundStatusRequestV2";
}

pub mod endpoints {
    // UAT endpoints - Based on Haskell Endpoints.hs
    pub const UAT_BASE_URL: &str = "https://uat.billdesk.com";
    pub const UAT_AUTHORIZE_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF011";
    pub const UAT_PSYNC_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF002";
    pub const UAT_RSYNC_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF004";

    // Production endpoints - Based on Haskell Endpoints.hs
    pub const PROD_BASE_URL: &str = "https://www.billdesk.com";
    pub const PROD_AUTHORIZE_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF011";
    pub const PROD_PSYNC_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF002";
    pub const PROD_RSYNC_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF004";
}

pub mod request_types {
    // Based on Haskell data types
    pub const AUTHORIZE: &str = "BilldeskInitiateUPIRequest";
    pub const PSYNC: &str = "BilldeskOnlineStatusRequest";
    pub const RSYNC: &str = "BilldeskRefundStatusRequestV2";
}

pub mod response_types {
    // Based on Haskell data types
    pub const AUTHORIZE: &str = "BilldeskUPIInitiateResponse";
    pub const PSYNC: &str = "BilldeskOnlineStatusResponse";
    pub const RSYNC: &str = "BilldeskOnlineRefundStatusResponseV2";
}

pub mod checksum {
    // Checksum calculation constants
    pub const CHECKSUM_SEPARATOR: &str = "|";
    pub const CHECKSUM_PREFIX: &str = "checksum_";
}

pub mod payment_methods {
    // Supported payment methods
    pub const UPI: &str = "UPI";
}

pub mod status_codes {
    // Billdesk status codes based on Haskell implementation
    pub const SUCCESS: &str = "Success";
    pub const FAILURE: &str = "Failure";
    pub const PENDING: &str = "Pending";
    pub const PROCESSING: &str = "Processing";
}

pub mod error_codes {
    // Common error codes
    pub const INVALID_REQUEST: &str = "INVALID_REQUEST";
    pub const AUTHENTICATION_FAILED: &str = "AUTHENTICATION_FAILED";
    pub const TRANSACTION_NOT_FOUND: &str = "TRANSACTION_NOT_FOUND";
    pub const INVALID_MERCHANT: &str = "INVALID_MERCHANT";
}