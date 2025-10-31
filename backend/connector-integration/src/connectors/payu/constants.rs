use common_enums::Currency;

// Payu API endpoints
pub const BASE_URL_TEST: &str = "https://test.payu.in";
pub const BASE_URL_PRODUCTION: &str = "https://secure.payu.in";

// Payu API paths
pub const PAYMENT_PATH: &str = "_payment";
pub const VERIFY_PAYMENT_PATH: &str = "merchant/postservice.php?form=2";

// Payu API versions and constants
pub const API_VERSION: &str = "2.0";
pub const DEVICE_INFO: &str = "web";

// Payu UPI specific constants
pub const PRODUCT_INFO: &str = "Payment";
pub const UPI_PG: &str = "UPI";
pub const UPI_COLLECT_BANKCODE: &str = "UPI";
pub const UPI_INTENT_BANKCODE: &str = "INTENT";
pub const UPI_S2S_FLOW: &str = "2";

// Payu PSync specific constants
pub const COMMAND_VERIFY_PAYMENT: &str = "verify_payment";

// Payu status mappings
pub const PAYU_STATUS_SUCCESS_INT: i32 = 1;
pub const PAYU_STATUS_ERROR_INT: i32 = 0;
pub const PAYU_STATUS_SUCCESS_STRING: &str = "success";
pub const PAYU_STATUS_PENDING: &str = "pending";
pub const PAYU_STATUS_FAILURE: &str = "failure";
pub const PAYU_STATUS_FAILED: &str = "failed";
pub const PAYU_STATUS_CANCEL: &str = "cancel";
pub const PAYU_STATUS_CANCELLED: &str = "cancelled";

// Payu hash field order (based on Haskell implementation)
// key|txnid|amount|productinfo|firstname|email|udf1|udf2|udf3|udf4|udf5|udf6|udf7|udf8|udf9|udf10|salt
pub const HASH_FIELD_COUNT: usize = 17;

// Payu verify hash field order
// key|command|var1|salt
pub const VERIFY_HASH_FIELD_COUNT: usize = 4;

// Payu error codes
pub const PAYU_ERROR_CODE_PREFIX: &str = "PAYU_";
pub const TRANSACTION_NOT_FOUND_ERROR: &str = "TRANSACTION_NOT_FOUND";
pub const SYNC_ERROR: &str = "PAYU_SYNC_ERROR";

// Payu response field mappings
pub const FIELD_MIHPAYID: &str = "mihpayid";
pub const FIELD_TXNID: &str = "txnid";
pub const FIELD_AMOUNT: &str = "amount";
pub const FIELD_STATUS: &str = "status";
pub const FIELD_FIRSTNAME: &str = "firstname";
pub const FIELD_LASTNAME: &str = "lastname";
pub const FIELD_EMAIL: &str = "email";
pub const FIELD_PHONE: &str = "phone";
pub const FIELD_PRODUCTINFO: &str = "productinfo";
pub const FIELD_HASH: &str = "hash";
pub const FIELD_FIELD1: &str = "field1"; // UPI transaction ID
pub const FIELD_FIELD2: &str = "field2"; // Bank reference number
pub const FIELD_FIELD3: &str = "field3"; // Payment source
pub const FIELD_FIELD9: &str = "field9"; // Additional field
pub const FIELD_ERROR_CODE: &str = "error_code";
pub const FIELD_ERROR_MESSAGE: &str = "error_message";
pub const FIELD_PAYMENT_SOURCE: &str = "payment_source";
pub const FIELD_BANK_REF_NUM: &str = "bank_ref_num";
pub const FIELD_UPI_VA: &str = "upi_va";
pub const FIELD_CARDNUM: &str = "cardnum";
pub const FIELD_ISSUING_BANK: &str = "issuing_bank";
pub const FIELD_ADDEDON: &str = "addedon";

// Payu UPI app name mappings (based on Haskell implementation)
pub const UPI_APP_PHONEPE: &str = "phonepe";
pub const UPI_APP_GOOGLEPAY: &str = "googlepay";
pub const UPI_APP_BHIM: &str = "bhim";
pub const UPI_APP_PAYTM: &str = "paytm";
pub const UPI_APP_CRED: &str = "cred";
pub const UPI_APP_AMAZONPAY: &str = "amazonpay";
pub const UPI_APP_WHATSAPP: &str = "whatsapp";
pub const UPI_APP_GENERIC_INTENT: &str = "genericintent";

// Payu bank code mappings (from internal metadata)
pub const BANK_CODE_JP_PHONEPE: &str = "JP_PHONEPE";
pub const BANK_CODE_JP_GOOGLEPAY: &str = "JP_GOOGLEPAY";
pub const BANK_CODE_JP_BHIM: &str = "JP_BHIM";
pub const BANK_CODE_JP_PAYTM: &str = "JP_PAYTM";
pub const BANK_CODE_JP_CRED: &str = "JP_CRED";
pub const BANK_CODE_JP_AMAZONPAY: &str = "JP_AMAZONPAY";
pub const BANK_CODE_JP_WHATSAPP: &str = "JP_WHATSAPP";

// Payu payment source mappings
pub const PAYMENT_SOURCE_CAPTURED: &str = "captured";
pub const PAYMENT_SOURCE_AUTH: &str = "auth";

// Payu supported currencies (based on PayU documentation)
pub const SUPPORTED_CURRENCIES: &[Currency] = &[
    Currency::INR, // Primary currency for PayU India
    // Add other supported currencies as needed
];

// Payu default values
pub const DEFAULT_FIRST_NAME: &str = "Customer";
pub const DEFAULT_PRODUCT_INFO: &str = "Payment";

// Payu request headers
pub const CONTENT_TYPE_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
pub const CONTENT_TYPE_JSON: &str = "application/json";
pub const ACCEPT_JSON: &str = "application/json";

// Payu timeout values (in seconds)
pub const DEFAULT_TIMEOUT: u64 = 30;
pub const UPI_POLL_INTERVAL: u64 = 5;
pub const UPI_PUSH_EXPIRY: u64 = 300; // 5 minutes

// Payu metadata field names (based on Haskell implementation)
pub const METADATA_UDF1: &str = "udf1";
pub const METADATA_UDF2: &str = "udf2";
pub const METADATA_UDF3: &str = "udf3";
pub const METADATA_UDF4: &str = "udf4";
pub const METADATA_UDF5: &str = "udf5";
pub const METADATA_UDF6: &str = "udf6";
pub const METADATA_UDF7: &str = "udf7";
pub const METADATA_UDF8: &str = "udf8";
pub const METADATA_UDF9: &str = "udf9";
pub const METADATA_UDF10: &str = "udf10";

// Payu response aliases (for backward compatibility)
pub const RESPONSE_ALIAS_REFERENCE_ID: &str = "referenceId";
pub const RESPONSE_ALIAS_RETURN_URL: &str = "returnUrl";
pub const RESPONSE_ALIAS_MERCHANT_NAME: &str = "merchantName";
pub const RESPONSE_ALIAS_MERCHANT_VPA: &str = "merchantVpa";
pub const RESPONSE_ALIAS_TXN_ID: &str = "txnId";
pub const RESPONSE_ALIAS_INTENT_URI_DATA: &str = "intentURIData";
pub const RESPONSE_ALIAS_UPI_PUSH_DISABLED: &str = "upiPushDisabled";
pub const RESPONSE_ALIAS_PUSH_SERVICE_URL: &str = "pushServiceUrl";
pub const RESPONSE_ALIAS_ENCODED_PAYU_ID: &str = "encodedPayuId";
pub const RESPONSE_ALIAS_VPA_REGEX: &str = "vpaRegex";
pub const RESPONSE_ALIAS_UPI_SERVICE_POLL_INTERVAL: &str = "upiServicePollInterval";
pub const RESPONSE_ALIAS_SDK_UPI_PUSH_EXPIRY: &str = "sdkUpiPushExpiry";
pub const RESPONSE_ALIAS_SDK_UPI_VERIFICATION_INTERVAL: &str = "sdkUpiVerificationInterval";
pub const RESPONSE_ALIAS_DISABLE_INTENT_SEAMLESS_FAILURE: &str = "disableIntentSeamlessFailure";
pub const RESPONSE_ALIAS_INTENT_SDK_COMBINE_VERIFY_AND_PAY_BUTTON: &str = "intentSdkCombineVerifyAndPayButton";
pub const RESPONSE_ALIAS_FIELD3: &str = "field3";