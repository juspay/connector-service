// PayZapp API Endpoints
pub const PAYZAPP_AUTH_PROD_URL: &str = "https://app.wibmo.com/payment/merchant/init";
pub const PAYZAPP_AUTH_TEST_URL: &str = "https://app.pc.enstage-sas.com/payment/merchant/init";

pub const PAYZAPP_CHARGE_PROD_URL: &str = "https://api.wibmo.com/v2/in/txn/iap/wpay/charge";
pub const PAYZAPP_CHARGE_TEST_URL: &str = "https://api.pc.enstage-sas.com/v2/in/txn/iap/wpay/charge";

pub const PAYZAPP_SYNC_PROD_URL: &str = "https://api.wibmo.com/v2/in/txn/iap/wpay/enquiry";
pub const PAYZAPP_SYNC_TEST_URL: &str = "https://api.pc.enstage-sas.com/v2/in/txn/iap/wpay/enquiry";

pub const PAYZAPP_REFUND_PROD_URL: &str = "https://api.wibmo.com/v2/in/txn/iap/void";
pub const PAYZAPP_REFUND_TEST_URL: &str = "https://api.pc.enstage-sas.com/v2/in/txn/iap/void";

// PayZapp Response Codes
pub const PAYZAPP_SUCCESS_CODE: &str = "00";
pub const PAYZAPP_ALT_SUCCESS_CODE: &str = "0";
pub const PAYZAPP_CHARGE_SUCCESS_CODE: &str = "01";
pub const PAYZAPP_ALT_CHARGE_SUCCESS_CODE: &str = "1";

// PayZapp Transaction Types
pub const PAYZAPP_TXN_TYPE_PAY: &str = "PAY";
pub const PAYZAPP_TXN_TYPE_ENQ: &str = "ENQ";
pub const PAYZAPP_TXN_TYPE_VOID: &str = "VOID";

// PayZapp Payment Types
pub const PAYZAPP_UPI_PAYMENT_TYPE: &str = "UPI";

// PayZapp Default Values
pub const PAYZAPP_DEFAULT_COUNTRY_CODE: &str = "IN";
pub const PAYZAPP_DEFAULT_MERCHANT_NAME: &str = "PayZapp Merchant";
pub const PAYZAPP_DEFAULT_TXN_DESC: &str = "Payment Transaction";