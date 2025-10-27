pub mod api;

pub const BILLDESK: &str = "billdesk";

// API Endpoints
pub mod endpoints {
    pub const UAT_BASE_URL: &str = "https://uat.billdesk.com/pgidsk/PGIDirectRequest";
    pub const PROD_BASE_URL: &str = "https://www.billdesk.com/pgidsk/PGIDirectRequest";
    
    // Request IDs for different operations
    pub const UPI_INITIATE_REQ_ID: &str = "BDRDF011";
    pub const AUTH_REQ_ID: &str = "BDRDF002";
    pub const STATUS_REQ_ID: &str = "BDRDF003";
    pub const REFUND_REQ_ID: &str = "BDRDF004";
}

// Response Status Codes
pub mod status_codes {
    pub const SUCCESS: &str = "0300";
    pub const SUCCESS_ALT: &str = "0399";
    pub const PENDING: &str = "0396";
    pub const FAILURE: &str = "0397";
    pub const FAILURE_ALT: &str = "0398";
}

// Error Codes
pub mod error_codes {
    pub const INVALID_REQUEST: &str = "400";
    pub const AUTHENTICATION_FAILED: &str = "401";
    pub const NOT_FOUND: &str = "404";
    pub const SERVER_ERROR: &str = "500";
}

// Currency Mappings
pub mod currencies {
    use common_enums::Currency;
    
    pub fn is_supported(currency: Currency) -> bool {
        matches!(
            currency,
            Currency::INR | // Indian Rupee (primary)
            Currency::USD | // US Dollar
            Currency::EUR | // Euro
            Currency::GBP | // British Pound
            Currency::AED | // UAE Dirham
            Currency::SAR   // Saudi Riyal
        )
    }
}

// Payment Method Mappings
pub mod payment_methods {
    use common_enums::PaymentMethodType;
    
    pub fn is_supported(payment_method: PaymentMethodType) -> bool {
        matches!(
            payment_method,
            PaymentMethodType::Upi | PaymentMethodType::UpiCollect
        )
    }
}

// Default Values
pub mod defaults {
    pub const DEFAULT_CURRENCY: &str = "INR";
    pub const DEFAULT_ITEM_CODE: &str = "UPI";
    pub const DEFAULT_TXN_TYPE: &str = "UPICOLLECT";
    pub const DEFAULT_REQUEST_TYPE: &str = "STATUSQUERY";
}