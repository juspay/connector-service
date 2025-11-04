pub const API_BASE_URL_PROD: &str = "https://pay.easebuzz.in";
pub const API_BASE_URL_TEST: &str = "https://testpay.easebuzz.in";

pub const ENDPOINT_INITIATE_PAYMENT: &str = "/payment/initiateLink";
pub const ENDPOINT_TRANSACTION_SYNC: &str = "/transaction/v1/retrieve";
pub const ENDPOINT_SEAMLESS_TRANSACTION: &str = "/payment/seamless";
pub const ENDPOINT_SUBMIT_OTP: &str = "/auth/submitOtp";
pub const ENDPOINT_RESEND_OTP: &str = "/auth/resendOtp";
pub const ENDPOINT_REFUND: &str = "/transaction/refund";
pub const ENDPOINT_REFUND_SYNC: &str = "/transaction/refundStatus";
pub const ENDPOINT_EMI_OPTIONS: &str = "/emi/getEMIOptions";
pub const ENDPOINT_EMI_PLANS: &str = "/emi/getPlans";
pub const ENDPOINT_DELAYED_SETTLEMENT: &str = "/settlement/create";
pub const ENDPOINT_DELAYED_SETTLEMENT_STATUS: &str = "/settlement/status";
pub const ENDPOINT_AUTHZ_REQUEST: &str = "/auth/authorize";
pub const ENDPOINT_ACCESS_KEY: &str = "/auth/accessKey";
pub const ENDPOINT_MANDATE_CREATE: &str = "/mandate/create";
pub const ENDPOINT_MANDATE_RETRIEVE: &str = "/mandate/retrieve";
pub const ENDPOINT_PRESENTMENT_INITIATE: &str = "/mandate/presentment/initiate";
pub const ENDPOINT_DEBIT_REQUEST_RETRIEVE: &str = "/mandate/debit/retrieve";
pub const ENDPOINT_UPI_AUTOPAY: &str = "/upi/autopay";
pub const ENDPOINT_NOTIFICATION_REQUEST: &str = "/notification/send";
pub const ENDPOINT_UPI_MANDATE_EXECUTE: &str = "/upi/mandate/execute";
pub const ENDPOINT_REVOKE_MANDATE: &str = "/mandate/revoke";
pub const ENDPOINT_MANDATE_NOTIFICATION_SYNC: &str = "/mandate/notification/sync";

pub const HEADER_CONTENT_TYPE: &str = "Content-Type";
pub const HEADER_AUTHORIZATION: &str = "Authorization";
pub const HEADER_X_EASEBUZZ_SIGNATURE: &str = "x-easebuzz-signature";

pub const CONTENT_TYPE_JSON: &str = "application/json";
pub const CONTENT_TYPE_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";

pub const PAYMENT_METHOD_UPI: &str = "UPI";
pub const PAYMENT_MODE_UPI_INTENT: &str = "UPI_INTENT";
pub const PAYMENT_MODE_UPI_COLLECT: &str = "UPI_COLLECT";
pub const PAYMENT_MODE_UPI_QR: &str = "UPI_QR";

pub const STATUS_SUCCESS: i32 = 1;
pub const STATUS_PENDING: i32 = 0;
pub const STATUS_FAILURE: i32 = -1;

pub const TRANSACTION_STATUS_SUCCESS: &str = "success";
pub const TRANSACTION_STATUS_PENDING: &str = "pending";
pub const TRANSACTION_STATUS_FAILURE: &str = "failure";
pub const TRANSACTION_STATUS_USER_ABANDONED: &str = "user_abandoned";

pub const MANDATE_STATUS_ACTIVE: &str = "ACTIVE";
pub const MANDATE_STATUS_PAUSED: &str = "PAUSED";
pub const MANDATE_STATUS_REVOKED: &str = "REVOKED";
pub const MANDATE_STATUS_EXPIRED: &str = "EXPIRED";

pub const REFUND_STATUS_SUCCESS: &str = "success";
pub const REFUND_STATUS_PENDING: &str = "pending";
pub const REFUND_STATUS_FAILURE: &str = "failure";

pub const WEBHOOK_EVENT_PAYMENT_SUCCESS: &str = "payment.success";
pub const WEBHOOK_EVENT_PAYMENT_FAILURE: &str = "payment.failure";
pub const WEBHOOK_EVENT_REFUND_SUCCESS: &str = "refund.success";
pub const WEBHOOK_EVENT_REFUND_FAILURE: &str = "refund.failure";
pub const WEBHOOK_EVENT_MANDATE_STATUS_UPDATE: &str = "mandate.status_update";
pub const WEBHOOK_EVENT_PRESENTMENT_STATUS_UPDATE: &str = "presentment.status_update";
pub const WEBHOOK_EVENT_NOTIFICATION_STATUS_UPDATE: &str = "notification.status_update";

pub const ERROR_CODE_INVALID_REQUEST: &str = "E001";
pub const ERROR_CODE_INVALID_HASH: &str = "E002";
pub const ERROR_CODE_TRANSACTION_NOT_FOUND: &str = "E003";
pub const ERROR_CODE_INSUFFICIENT_BALANCE: &str = "E004";
pub const ERROR_CODE_INVALID_MERCHANT: &str = "E005";
pub const ERROR_CODE_INVALID_CURRENCY: &str = "E006";
pub const ERROR_CODE_INVALID_AMOUNT: &str = "E007";
pub const ERROR_CODE_DUPLICATE_TRANSACTION: &str = "E008";
pub const ERROR_CODE_TRANSACTION_TIMEOUT: &str = "E009";
pub const ERROR_CODE_BANK_DECLINED: &str = "E010";
pub const ERROR_CODE_INVALID_UPI_HANDLE: &str = "E011";
pub const ERROR_CODE_UPI_NOT_SUPPORTED: &str = "E012";
pub const ERROR_CODE_INVALID_OTP: &str = "E013";
pub const ERROR_CODE_OTP_EXPIRED: &str = "E014";
pub const ERROR_CODE_OTP_LIMIT_EXCEEDED: &str = "E015";
pub const ERROR_CODE_MANDATE_NOT_FOUND: &str = "E016";
pub const ERROR_CODE_MANDATE_ALREADY_EXISTS: &str = "E017";
pub const ERROR_CODE_INVALID_MANDATE: &str = "E018";
pub const ERROR_CODE_REFUND_NOT_ALLOWED: &str = "E019";
pub const ERROR_CODE_REFUND_LIMIT_EXCEEDED: &str = "E020";
pub const ERROR_CODE_INVALID_REFUND_AMOUNT: &str = "E021";

pub const DEFAULT_PRODUCT_INFO: &str = "Payment";
pub const DEFAULT_UDF_PREFIX: &str = "udf";

pub const HASH_ALGORITHM_SHA512: &str = "sha512";

pub const MAX_AMOUNT_LIMIT: i64 = 10000000; // 1 lakh in minor units
pub const MIN_AMOUNT_LIMIT: i64 = 100; // 1 rupee in minor units

pub const OTP_MAX_ATTEMPTS: i32 = 3;
pub const OTP_RESEND_COOLDOWN_SECONDS: i32 = 30;

pub const WEBHOOK_SIGNATURE_VALIDATION_WINDOW_SECONDS: i64 = 300; // 5 minutes

pub const MANDATE_MIN_AMOUNT: i64 = 1000; // 10 rupees in minor units
pub const MANDATE_MAX_AMOUNT: i64 = 100000000; // 10 lakhs in minor units

pub const REFUND_MIN_AMOUNT: i64 = 100; // 1 rupee in minor units
pub const REFUND_MAX_AMOUNT: i64 = 10000000; // 1 lakh in minor units

pub const SETTLEMENT_MIN_AMOUNT: i64 = 1000; // 10 rupees in minor units
pub const SETTLEMENT_MAX_AMOUNT: i64 = 100000000; // 10 lakhs in minor units

pub const NOTIFICATION_MIN_AMOUNT: i64 = 100; // 1 rupee in minor units
pub const NOTIFICATION_MAX_AMOUNT: i64 = 10000000; // 1 lakh in minor units

pub const UPI_INTENT_TIMEOUT_SECONDS: i64 = 300; // 5 minutes
pub const UPI_COLLECT_TIMEOUT_SECONDS: i64 = 600; // 10 minutes
pub const UPI_QR_TIMEOUT_SECONDS: i64 = 1800; // 30 minutes

pub const TRANSACTION_SYNC_RETRY_COUNT: i32 = 3;
pub const TRANSACTION_SYNC_RETRY_DELAY_SECONDS: i64 = 5;

pub const REFUND_SYNC_RETRY_COUNT: i32 = 3;
pub const REFUND_SYNC_RETRY_DELAY_SECONDS: i64 = 5;

pub const MANDATE_SYNC_RETRY_COUNT: i32 = 3;
pub const MANDATE_SYNC_RETRY_DELAY_SECONDS: i64 = 5;

pub const NOTIFICATION_SYNC_RETRY_COUNT: i32 = 3;
pub const NOTIFICATION_SYNC_RETRY_DELAY_SECONDS: i64 = 5;

pub const SETTLEMENT_SYNC_RETRY_COUNT: i32 = 3;
pub const SETTLEMENT_SYNC_RETRY_DELAY_SECONDS: i64 = 10;

pub const API_TIMEOUT_SECONDS: i64 = 30;
pub const API_RETRY_COUNT: i32 = 3;
pub const API_RETRY_DELAY_SECONDS: i64 = 2;

pub const RATE_LIMIT_REQUESTS_PER_MINUTE: i32 = 100;
pub const RATE_LIMIT_BURST_SIZE: i32 = 20;

pub const CACHE_TTL_SECONDS: i64 = 300; // 5 minutes
pub const CACHE_MAX_SIZE: usize = 1000;

pub const LOG_LEVEL_DEBUG: &str = "debug";
pub const LOG_LEVEL_INFO: &str = "info";
pub const LOG_LEVEL_WARN: &str = "warn";
pub const LOG_LEVEL_ERROR: &str = "error";

pub const METRIC_PREFIX: &str = "easebuzz_";
pub const METRIC_REQUEST_COUNT: &str = "request_count";
pub const METRIC_REQUEST_DURATION: &str = "request_duration";
pub const METRIC_ERROR_COUNT: &str = "error_count";
pub const METRIC_SUCCESS_RATE: &str = "success_rate";

pub const CONFIG_KEY_API_KEY: &str = "api_key";
pub const CONFIG_KEY_SALT: &str = "salt";
pub const CONFIG_KEY_MERCHANT_ID: &str = "merchant_id";
pub const CONFIG_KEY_WEBHOOK_SECRET: &str = "webhook_secret";
pub const CONFIG_KEY_TEST_MODE: &str = "test_mode";
pub const CONFIG_KEY_TIMEOUT_SECONDS: &str = "timeout_seconds";
pub const CONFIG_KEY_RETRY_COUNT: &str = "retry_count";
pub const CONFIG_KEY_RETRY_DELAY_SECONDS: &str = "retry_delay_seconds";

pub const ENV_EASEBUZZ_API_KEY: &str = "EASEBUZZ_API_KEY";
pub const ENV_EASEBUZZ_SALT: &str = "EASEBUZZ_SALT";
pub const ENV_EASEBUZZ_MERCHANT_ID: &str = "EASEBUZZ_MERCHANT_ID";
pub const ENV_EASEBUZZ_WEBHOOK_SECRET: &str = "EASEBUZZ_WEBHOOK_SECRET";
pub const ENV_EASEBUZZ_TEST_MODE: &str = "EASEBUZZ_TEST_MODE";

pub const VERSION: &str = "1.0.0";
pub const BUILD_DATE: &str = "2024-01-01";
pub const GIT_COMMIT: &str = "unknown";

pub const SUPPORTED_CURRENCIES: &[&str] = &["INR"];
pub const SUPPORTED_COUNTRIES: &[&str] = &["IN"];

pub const UPI_SUPPORTED_APPS: &[&str] = &[
    "google_pay",
    "phone_pe",
    "paytm",
    "bhim_upi",
    "amazon_pay",
    "mobikwik",
    "freecharge",
    "airtel_money",
    "jio_money",
    "yono",
    "sbi_yono",
    "hdfc_payzapp",
    "icici_pockets",
    "axis_pay",
    "kotak_811",
    "pnb_one",
    "bob_world",
    "canara_bank_upi",
    "union_bank_upi",
    "bank_of_baroda_upi",
    "bank_of_india_upi",
    "central_bank_upi",
    "indian_bank_upi",
    "indian_overseas_bank_upi",
    "punjab_national_bank_upi",
    "ucobank_upi",
    "unionbank_upi",
    "vijaya_bank_upi",
    "corporation_bank_upi",
    "andhra_bank_upi",
    "bank_of_maharashtra_upi",
    "dena_bank_upi",
    "idbi_bank_upi",
    "oriental_bank_upi",
    "punjab_sind_bank_upi",
    "syndicate_bank_upi",
    "ucobank_upi",
    "united_bank_upi",
    "vijaya_bank_upi",
    "yes_bank_upi",
    "idfc_first_bank_upi",
    "bandhan_bank_upi",
    "dbs_bank_upi",
    "hsbc_bank_upi",
    "standard_chartered_upi",
    "citibank_upi",
    "rbl_bank_upi",
    "karnataka_bank_upi",
    "federal_bank_upi",
    "south_indian_bank_upi",
    "tamilnad_mercantile_bank_upi",
    "karur_vysya_bank_upi",
    "lakshmi_vilas_bank_upi",
    "nainital_bank_upi",
    "jammu_kashmir_bank_upi",
    "dhanalakshmi_bank_upi",
    "janata_sahakari_bank_upi",
    "saraswat_bank_upi",
    "cosmos_bank_upi",
    "rupee_cooperative_bank_upi",
    "apna_sahakari_bank_upi",
    "punjab_maharashtra_cooperative_bank_upi",
    "shamrao_vithal_cooperative_bank_upi",
    "bharat_cooperative_bank_upi",
    "abhyudaya_cooperative_bank_upi",
    "gurgaon_gramin_bank_upi",
    "prathama_up_gramin_bank_upi",
    "sarva_up_gramin_bank_upi",
    "uttar_bihar_gramin_bank_upi",
    "madhya_bihar_gramin_bank_upi",
    "uttar_ganga_kshetriya_gramin_bank_upi",
    "kashi_gomti_samyut_gramin_bank_upi",
    "prathama_up_gramin_bank_upi",
    "pallavan_grama_bank_upi",
    "tamilnad_mercantile_bank_upi",
    "karnataka_vikas_grameena_bank_upi",
    "pragathi_krishna_gramin_bank_upi",
    "andhra_pradesh_grameena_vikas_bank_upi",
    "chaitanya_godavari_grameena_bank_upi",
    "telangana_grameena_bank_upi",
    "maharashtra_grameena_bank_upi",
    "saurashtra_grameena_bank_upi",
    "baroda_gujarat_gramin_bank_upi",
    "dena_gujarat_gramin_bank_upi",
    "saurashtra_kutch_gramin_bank_upi",
    "narmada_jhabua_gramin_bank_upi",
    "madhya_bharat_gramin_bank_upi",
    "rajasthan_marudhara_gramin_bank_upi",
    "pandyan_grama_bank_upi",
    "kerala_gramin_bank_upi",
    "karnataka_gramin_bank_upi",
    "andhra_pradesh_gramin_bank_upi",
    "bihar_gramin_bank_upi",
    "up_gramin_bank_upi",
    "uttarakhand_gramin_bank_upi",
    "himachal_pradesh_gramin_bank_upi",
    "jammu_kashmir_gramin_bank_upi",
    "punjab_gramin_bank_upi",
    "haryana_gramin_bank_upi",
    "rajasthan_gramin_bank_upi",
    "madhya_pradesh_gramin_bank_upi",
    "chhattisgarh_gramin_bank_upi",
    "odisha_gramin_bank_upi",
    "west_bengal_gramin_bank_upi",
    "assam_gramin_bank_upi",
    "meghalaya_gramin_bank_upi",
    "tripura_gramin_bank_upi",
    "mizoram_gramin_bank_upi",
    "nagaland_gramin_bank_upi",
    "arunachal_pradesh_gramin_bank_upi",
    "sikkim_gramin_bank_upi",
    "goa_gramin_bank_upi",
    "dadra_nagar_haveli_gramin_bank_upi",
    "daman_diu_gramin_bank_upi",
    "lakshadweep_gramin_bank_upi",
    "andaman_nicobar_gramin_bank_upi",
    "pondicherry_gramin_bank_upi",
    "chandigarh_gramin_bank_upi",
    "delhi_gramin_bank_upi",
    "jammu_gramin_bank_upi",
    "ladakh_gramin_bank_upi",
    "lakshadweep_gramin_bank_upi",
];