pub mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const AUTHORIZATION: &str = "Authorization";
    pub const X_API_KEY: &str = "X-API-KEY";
    pub const X_MERCHANT_ID: &str = "X-MERCHANT-ID";
}

pub mod api_endpoints {
    // Payment endpoints
    pub const INITIATE_PAYMENT: &str = "/payment/initiateLink";
    pub const SEAMLESS_TRANSACTION: &str = "/payment/transaction";
    pub const TRANSACTION_SYNC: &str = "/payment/txnSync";
    
    // UPI endpoints
    pub const UPI_INTENT: &str = "/payment/upiIntent";
    pub const UPI_AUTOPAY: &str = "/payment/upiAutopay";
    pub const UPI_MANDATE_EXECUTE: &str = "/payment/upiMandateExecute";
    
    // OTP endpoints
    pub const SUBMIT_OTP: &str = "/payment/submitOtp";
    pub const RESEND_OTP: &str = "/payment/resendOtp";
    
    // Refund endpoints
    pub const REFUND: &str = "/payment/refund";
    pub const REFUND_SYNC: &str = "/payment/refundSync";
    
    // Mandate endpoints
    pub const MANDATE_CREATE: &str = "/mandate/create";
    pub const MANDATE_RETRIEVE: &str = "/mandate/retrieve";
    pub const MANDATE_REVOKE: &str = "/mandate/revoke";
    
    // Settlement endpoints
    pub const DELAYED_SETTLEMENT: &str = "/settlement/delayed";
    pub const SETTLEMENT_STATUS: &str = "/settlement/status";
    
    // EMI endpoints
    pub const EMI_OPTIONS: &str = "/emi/options";
    pub const EMI_PLANS: &str = "/emi/plans";
    
    // Notification endpoints
    pub const NOTIFICATION_REQUEST: &str = "/notification/request";
    pub const NOTIFICATION_SYNC: &str = "/notification/sync";
    
    // Access key endpoint
    pub const ACCESS_KEY: &str = "/auth/accessKey";
}

pub mod payment_modes {
    pub const UPI: &str = "UPI";
    pub const UPI_INTENT: &str = "UPI_INTENT";
    pub const UPI_COLLECT: &str = "UPI_COLLECT";
    pub const UPI_QR: &str = "UPI_QR";
}

pub mod transaction_types {
    pub const PAYMENT: &str = "payment";
    pub const REFUND: &str = "refund";
    pub const MANDATE: &str = "mandate";
}

pub mod status_codes {
    pub const SUCCESS: i32 = 1;
    pub const PENDING: i32 = 0;
    pub const FAILURE: i32 = -1;
}

pub mod error_codes {
    pub const INVALID_REQUEST: &str = "INVALID_REQUEST";
    pub const AUTHENTICATION_FAILED: &str = "AUTHENTICATION_FAILED";
    pub const TRANSACTION_NOT_FOUND: &str = "TRANSACTION_NOT_FOUND";
    pub const INSUFFICIENT_BALANCE: &str = "INSUFFICIENT_BALANCE";
    pub const INVALID_MERCHANT: &str = "INVALID_MERCHANT";
}