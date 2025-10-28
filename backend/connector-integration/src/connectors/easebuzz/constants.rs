pub mod constants {
    pub const API_VERSION: &str = "v1";
    
    pub mod endpoints {
        pub const INITIATE_PAYMENT: &str = "/payment/initiateLink";
        pub const TRANSACTION_SYNC: &str = "/payment/txnSync";
        pub const SEAMLESS_TRANSACTION: &str = "/payment/seamless";
        pub const SUBMIT_OTP: &str = "/payment/submitOtp";
        pub const RESEND_OTP: &str = "/payment/resendOtp";
        pub const REFUND: &str = "/payment/refund";
        pub const REFUND_SYNC: &str = "/payment/refundSync";
        pub const UPI_AUTOPAY: &str = "/payment/upiAutopay";
        pub const UPI_MANDATE_EXECUTE: &str = "/payment/upiMandateExecute";
        pub const MANDATE_RETRIEVE: &str = "/payment/mandateRetrieve";
        pub const MANDATE_CREATE: &str = "/payment/mandateCreate";
        pub const NOTIFICATION_REQUEST: &str = "/payment/notificationRequest";
        pub const NOTIFICATION_SYNC: &str = "/payment/notificationSync";
        pub const REVOKE_MANDATE: &str = "/payment/revokeMandate";
        pub const GET_EMI_OPTIONS: &str = "/payment/getEmiOptions";
        pub const GET_PLANS: &str = "/payment/getPlans";
        pub const DELAYED_SETTLEMENT: &str = "/payment/delayedSettlement";
        pub const DELAYED_SETTLEMENT_STATUS: &str = "/payment/delayedSettlementStatus";
    }
    
    pub mod headers {
        pub const CONTENT_TYPE: &str = "Content-Type";
        pub const AUTHORIZATION: &str = "Authorization";
        pub const ACCEPT: &str = "Accept";
        pub const USER_AGENT: &str = "User-Agent";
    }
    
    pub mod payment_methods {
        pub const UPI: &str = "UPI";
        pub const UPI_COLLECT: &str = "UPI_COLLECT";
        pub const UPI_INTENT: &str = "UPI_INTENT";
        pub const CREDIT_CARD: &str = "CC";
        pub const DEBIT_CARD: &str = "DC";
        pub const NET_BANKING: &str = "NB";
        pub const WALLET: &str = "WL";
        pub const EMI: &str = "EMI";
    }
    
    pub mod status_codes {
        pub const SUCCESS: i32 = 1;
        pub const FAILURE: i32 = 0;
        pub const PENDING: i32 = 2;
    }
    
    pub mod transaction_status {
        pub const SUCCESS: &str = "success";
        pub const FAILURE: &str = "failure";
        pub const FAILED: &str = "failed";
        pub const PENDING: &str = "pending";
        pub const USER_ABORTED: &str = "user_aborted";
        pub const INITIATED: &str = "initiated";
    }

    pub mod base_urls {
        pub const PRODUCTION: &str = "https://pay.easebuzz.in";
        pub const TEST: &str = "https://testpay.easebuzz.in";
    }

    pub mod auth {
        pub const BASIC_AUTH_PREFIX: &str = "Basic";
    }

    pub mod defaults {
        pub const PRODUCT_INFO: &str = "Payment";
        pub const DEFAULT_IP_ADDRESS: &str = "127.0.0.1";
        pub const DEFAULT_USER_AGENT: &str = "Mozilla/5.0";
        pub const DEFAULT_CURRENCY: &str = "INR";
        pub const DEFAULT_AMOUNT: i64 = 1000; // 10.00 INR in minor units
    }
}