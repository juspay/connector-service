pub mod api;

pub const BILLDESK: &str = "billdesk";

// API Endpoints
pub mod endpoints {
    pub const AUTHORIZE: &str = "/pgidsk/PGIDirectRequest";
    pub const SYNC: &str = "/pgidsk/PGIDirectRequest";
    pub const REFUND: &str = "/pgidsk/PGIDirectRequest";
}

// Request IDs for different operations
pub mod request_ids {
    pub const UPI_INITIATE: &str = "BDRDF011";
    pub const AUTHORIZE: &str = "BDRDF002";
    pub const STATUS_CHECK: &str = "BDRDF003";
    pub const REFUND: &str = "BDRDF004";
}

// Response Status Codes
pub mod status_codes {
    pub const SUCCESS: &str = "0300";
    pub const SUCCESS_VARIANTS: &str = "0399";
    pub const PENDING: &str = "0001";
    pub const AUTHENTICATION_PENDING: &str = "0002";
    pub const FAILURE: &str = "0396";
    pub const INVALID_REQUEST: &str = "0003";
}

// Error Codes
pub mod error_codes {
    pub const INVALID_MERCHANT: &str = "1001";
    pub const INVALID_TRANSACTION: &str = "1002";
    pub const INVALID_AMOUNT: &str = "1003";
    pub const INVALID_CURRENCY: &str = "1004";
    pub const INVALID_CHECKSUM: &str = "1005";
    pub const TRANSACTION_NOT_FOUND: &str = "1006";
    pub const DUPLICATE_TRANSACTION: &str = "1007";
}

// Currency Mappings
pub mod currency_mappings {
    use common_enums::Currency;
    
    pub fn to_billdesk_currency(currency: Currency) -> &'static str {
        match currency {
            Currency::INR => "356",
            Currency::USD => "840",
            Currency::EUR => "978",
            Currency::GBP => "826",
            Currency::JPY => "392",
            Currency::AUD => "036",
            Currency::CAD => "124",
            Currency::CHF => "756",
            Currency::CNY => "156",
            Currency::SEK => "752",
            Currency::NZD => "554",
            Currency::MXN => "484",
            Currency::SGD => "702",
            Currency::HKD => "344",
            Currency::NOK => "578",
            Currency::KRW => "410",
            Currency::TRY => "949",
            Currency::RUB => "643",
            Currency::BRL => "986",
            Currency::ZAR => "710",
            _ => "000", // Default/Unknown
        }
    }
}

// Payment Method Mappings
pub mod payment_method_mappings {
    use common_enums::PaymentMethodType;
    
    pub fn to_billdesk_payment_method(payment_method: PaymentMethodType) -> &'static str {
        match payment_method {
            PaymentMethodType::Upi => "UPI",
            PaymentMethodType::Credit => "CC",
            PaymentMethodType::Debit => "DC",
            PaymentMethodType::NetBanking => "NB",
            PaymentMethodType::Wallet => "WL",
            PaymentMethodType::Card => "CD",
            _ => "OT", // Other
        }
    }
}

// Transaction Type Mappings
pub mod transaction_types {
    pub const SALE: &str = "SALE";
    pub const AUTH: &str = "AUTH";
    pub const CAPTURE: &str = "CAPTURE";
    pub const REFUND: &str = "REFUND";
    pub const VOID: &str = "VOID";
    pub const STATUS: &str = "STATUS";
}

// Default Values
pub mod defaults {
    pub const DEFAULT_CURRENCY: &str = "356"; // INR
    pub const DEFAULT_COUNTRY: &str = "356"; // India
    pub const DEFAULT_LANGUAGE: &str = "en";
    pub const DEFAULT_TIMEOUT: u64 = 30; // seconds
}

// Validation Rules
pub mod validation {
    pub const MIN_AMOUNT: i64 = 100; // 1.00 INR in minor units
    pub const MAX_AMOUNT: i64 = 10000000; // 100000.00 INR in minor units
    pub const MAX_VPA_LENGTH: usize = 50;
    pub const MAX_MERCHANT_ID_LENGTH: usize = 50;
    pub const MAX_TRANSACTION_ID_LENGTH: usize = 50;
}

// Headers
pub mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const AUTHORIZATION: &str = "Authorization";
    pub const X_API_VERSION: &str = "X-API-Version";
    pub const X_REQUEST_ID: &str = "X-Request-ID";
}

// Content Types
pub mod content_types {
    pub const JSON: &str = "application/json";
    pub const FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
}

// HTTP Methods
pub mod http_methods {
    pub const GET: &str = "GET";
    pub const POST: &str = "POST";
    pub const PUT: &str = "PUT";
    pub const DELETE: &str = "DELETE";
}

// Environment URLs
pub mod environments {
    pub const PRODUCTION_BASE_URL: &str = "https://www.billdesk.com";
    pub const SANDBOX_BASE_URL: &str = "https://uat.billdesk.com";
}

// Webhook Event Types
pub mod webhook_events {
    pub const PAYMENT_SUCCESS: &str = "PAYMENT_SUCCESS";
    pub const PAYMENT_FAILURE: &str = "PAYMENT_FAILURE";
    pub const PAYMENT_PENDING: &str = "PAYMENT_PENDING";
    pub const REFUND_SUCCESS: &str = "REFUND_SUCCESS";
    pub const REFUND_FAILURE: &str = "REFUND_FAILURE";
}