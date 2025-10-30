pub mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const AUTHORIZATION: &str = "Authorization";
}

pub mod api_urls {
    pub const TEST_BASE_URL: &str = "https://testpay.easebuzz.in";
    pub const PROD_BASE_URL: &str = "https://pay.easebuzz.in";
    
    // Payment endpoints - based on Haskell implementation
    pub const INITIATE_PAYMENT: &str = "/payment/initiateLink";
    pub const SEAMLESS_TRANSACTION: &str = "/transaction/v1/redirect";
    pub const TRANSACTION_SYNC: &str = "/transaction/v1/sync";
    
    // UPI endpoints - UPI focused as per requirements
    pub const UPI_INTENT: &str = "/upi/intent";
    pub const UPI_AUTOPAY: &str = "/upi/autopay";
    pub const UPI_MANDATE_EXECUTE: &str = "/upi/mandate/execute";
    
    // OTP endpoints
    pub const SUBMIT_OTP: &str = "/auth/submitOtp";
    pub const RESEND_OTP: &str = "/auth/resendOtp";
    
    // Refund endpoints
    pub const REFUND: &str = "/transaction/v1/refund";
    pub const REFUND_SYNC: &str = "/transaction/v1/refundStatus";
    
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
}

pub mod payment_methods {
    pub const UPI: &str = "upi";
    pub const UPI_INTENT: &str = "upi_intent";
    pub const UPI_COLLECT: &str = "upi_collect";
    pub const UPI_QR: &str = "upi_qr";
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
    pub const INVALID_AUTH: &str = "INVALID_AUTH";
    pub const TRANSACTION_NOT_FOUND: &str = "TRANSACTION_NOT_FOUND";
    pub const INSUFFICIENT_BALANCE: &str = "INSUFFICIENT_BALANCE";
    pub const INVALID_UPI_HANDLE: &str = "INVALID_UPI_HANDLE";
    pub const MANDATE_NOT_FOUND: &str = "MANDATE_NOT_FOUND";
    pub const MANDATE_ALREADY_EXISTS: &str = "MANDATE_ALREADY_EXISTS";
}