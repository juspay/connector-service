pub mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const AUTHORIZATION: &str = "Authorization";
}

pub mod endpoints {
    pub const UAT_BASE_URL: &str = "https://uat1.billdesk.com";
    pub const PROD_BASE_URL: &str = "https://api.billdesk.com";
    pub const UAT_PAYMENT_V1_2: &str = "https://uat1.billdesk.com/u2/payments/ve1_2";
    pub const PROD_PAYMENT_V1_2: &str = "https://api.billdesk.com/payments/ve1_2";
    
    // Endpoints for different flows
    pub const AUTHORIZE_UPI: &str = "/payments/upi/initiate";
    pub const PSYNC: &str = "/transactions/get";
    pub const VPA_VERIFY: &str = "/upi/validatevpa";
    
    // UAT endpoints
    pub const UAT_AUTHORIZE_UPI_V1: &str = "https://uat.billdesk.com/pgidsk/PGIDirectRequest?reqid=BDRDF007";
    pub const PROD_AUTHORIZE_UPI_V1: &str = "https://www.billdesk.com/pgidsk/PGIDirectRequest?reqid=BDRDF007";
    pub const UAT_PAYMENT_STATUS: &str = "https://uat.billdesk.com/pgidsk/PGIQueryController";
    pub const PROD_PAYMENT_STATUS: &str = "https://www.billdesk.com/pgidsk/PGIQueryController";
}

pub mod request_ids {
    pub const UPI_INITIATE: &str = "BDRDF007";
    pub const NB_INITIATE: &str = "BDRDF003";
    pub const CARD_INITIATE_V1: &str = "BDRDF001";
    pub const CARD_INITIATE_V2: &str = "BDRDF011";
    pub const AUTHORIZATION: &str = "BDRDF002";
    pub const REFUND: &str = "BDRDF004";
}