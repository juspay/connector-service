pub mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const CLIENT_ID: &str = "client-id";
    pub const VERSION: &str = "version";
    pub const REQUEST_TIMESTAMP: &str = "request-timestamp";
    pub const CHANNEL_ID: &str = "channel-id";
    pub const SIGNATURE: &str = "signature";
    pub const TOKEN_TYPE: &str = "token-type";
    pub const TOKEN: &str = "token";
}

pub mod api_endpoints {
    pub const INITIATE_TRANSACTION: &str = "/theia/api/v2/initiateTransaction";
    pub const PROCESS_TRANSACTION: &str = "/theia/api/v2/processTransaction";
    pub const TRANSACTION_STATUS: &str = "/v3/order/status";
    pub const VALIDATE_VPA: &str = "/theia/api/v1/vpa/validate";
    pub const SUBSCRIPTION_INIT: &str = "/subscription/api/v1/init";
    pub const SUBSCRIPTION_RENEW: &str = "/subscription/api/v1/renew";
    pub const SUBSCRIPTION_CANCEL: &str = "/subscription/api/v1/cancel";
    pub const SUBSCRIPTION_STATUS: &str = "/subscription/api/v1/fetch";
    pub const PRE_NOTIFY: &str = "/subscription/api/v1/preNotify";
    pub const PRE_NOTIFY_STATUS: &str = "/subscription/api/v1/preNotifyStatus";
}

pub mod payment_modes {
    pub const UPI: &str = "UPI";
    pub const UPI_COLLECT: &str = "UPI_COLLECT";
    pub const UPI_INTENT: &str = "UPI_INTENT";
    pub const PAYTM_WALLET: &str = "PAYTM_WALLET";
}

pub mod request_types {
    pub const SUBSCRIPTION: &str = "SUBSCRIPTION";
    pub const RENEW_SUBSCRIPTION: &str = "RENEW_SUBSCRIPTION";
    pub const TRANSACTION: &str = "TRANSACTION";
    pub const VPA_VALIDATE: &str = "VPA_VALIDATE";
}

pub mod response_codes {
    pub const SUCCESS: &str = "01";
    pub const PENDING: &str = "02";
    pub const FAILURE: &str = "03";
    pub const TXN_SUCCESS: &str = "TXN_SUCCESS";
    pub const TXN_FAILURE: &str = "TXN_FAILURE";
    pub const TXN_PENDING: &str = "TXN_PENDING";
}

pub mod status_codes {
    pub const SUCCESS: &str = "SUCCESS";
    pub const PENDING: &str = "PENDING";
    pub const FAILURE: &str = "FAILURE";
    pub const ACTIVE: &str = "ACTIVE";
    pub const EXPIRED: &str = "EXPIRED";
    pub const REVOKED: &str = "REVOKED";
    pub const AUTHORIZED: &str = "AUTHORIZED";
    pub const CAPTURED: &str = "CAPTURED";
}