pub const UAT_DOMAIN: &str = "https://uat.billdesk.com";
pub const PROD_DOMAIN: &str = "https://www.billdesk.com";

// UPI Payment Endpoints (from Haskell Endpoints.hs)
pub const UPI_INITIATE_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF007";
pub const STATUS_CHECK_ENDPOINT: &str = "/pgidsk/PGIQueryController";
pub const REFUND_ENDPOINT: &str = "/pgidsk/PGIRefundController";
pub const REFUND_STATUS_ENDPOINT: &str = "/pgidsk/PGIRefundQueryController";

// V2 API Endpoints (from Haskell Endpoints.hs)
pub const UAT_V2_DOMAIN: &str = "https://uat1.billdesk.com";
pub const PROD_V2_DOMAIN: &str = "https://api.billdesk.com";

pub const UAT_PAYMENT_BASE_URL: &str = "https://uat1.billdesk.com/u2/payments/ve1_2";
pub const PROD_PAYMENT_BASE_URL: &str = "https://api.billdesk.com/payments/ve1_2";

pub const UAT_PGSI_BASE_URL: &str = "https://uat1.billdesk.com/u2/pgsi/ve1_2";
pub const PROD_PGSI_BASE_URL: &str = "https://api.billdesk.com/pgsi/ve1_2";

// V2 Endpoints
pub const CREATE_TXN_ENDPOINT: &str = "/transactions/create";
pub const UPDATE_TXN_ENDPOINT: &str = "/transactions/update";
pub const RETRIEVE_TXN_ENDPOINT: &str = "/transactions/get";
pub const REFUND_V2_ENDPOINT: &str = "/refunds/create";
pub const RETRIEVE_REFUND_ENDPOINT: &str = "/refunds/get";
pub const VERIFY_VPA_ENDPOINT: &str = "/upi/validatevpa";

// PGSi Endpoints
pub const CREATE_INVOICE_ENDPOINT: &str = "/invoices/create";
pub const RETRIEVE_INVOICE_ENDPOINT: &str = "/invoices/get";
pub const MANDATE_MIGRATION_ENDPOINT: &str = "/mandates/migrate";
pub const CREATE_REVOKE_ENDPOINT: &str = "/mandates/delete";
pub const RETRIEVE_MANDATE_ENDPOINT: &str = "/mandates/get";
pub const CREATE_MANDATE_ENDPOINT: &str = "/mandates/create";
pub const UPDATE_MANDATE_ENDPOINT: &str = "/mandates/update";
pub const LIST_MANDATE_ENDPOINT: &str = "/mandates/list";
pub const MANDATE_UPDATE_TOKEN_ENDPOINT: &str = "/mandates/settoken";
pub const UPDATE_MODIFY_ENDPOINT: &str = "/mandates/modify";
pub const AUTH_DETAILS_ENDPOINT: &str = "/transactions/getauthenticationdetails";

// Request IDs (from Haskell Endpoints.hs)
pub const UPI_INITIATE_REQUEST_ID: &str = "BDRDF007";
pub const AUTHORIZATION_REQUEST_ID: &str = "BDRDF002";
pub const NB_INITIATE_REQUEST_ID: &str = "BDRDF003";
pub const RECURRING_REQUEST_ID: &str = "BDRDF006";
pub const CARD_INITIATE_V1_REQUEST_ID: &str = "BDRDF001";
pub const CARD_INITIATE_V2_REQUEST_ID: &str = "BDRDF011";

// Content Types
pub const CONTENT_TYPE_JSON: &str = "application/json";
pub const CONTENT_TYPE_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";

// Headers
pub const HEADER_AUTHORIZATION: &str = "Authorization";
pub const HEADER_CONTENT_TYPE: &str = "Content-Type";
pub const HEADER_ACCEPT: &str = "Accept";

// Response Status Codes
pub const STATUS_SUCCESS: u16 = 200;
pub const STATUS_CREATED: u16 = 201;
pub const STATUS_BAD_REQUEST: u16 = 400;
pub const STATUS_UNAUTHORIZED: u16 = 401;
pub const STATUS_FORBIDDEN: u16 = 403;
pub const STATUS_NOT_FOUND: u16 = 404;
pub const STATUS_INTERNAL_SERVER_ERROR: u16 = 500;

// Error Codes
pub const ERROR_INVALID_REQUEST: &str = "INVALID_REQUEST";
pub const ERROR_AUTHENTICATION_FAILED: &str = "AUTHENTICATION_FAILED";
pub const ERROR_TRANSACTION_NOT_FOUND: &str = "TRANSACTION_NOT_FOUND";
pub const ERROR_INVALID_UPI_ID: &str = "INVALID_UPI_ID";
pub const ERROR_INSUFFICIENT_FUNDS: &str = "INSUFFICIENT_FUNDS";
pub const ERROR_TRANSACTION_FAILED: &str = "TRANSACTION_FAILED";

// Payment Status Codes (from Haskell types)
pub const STATUS_SUCCESS_CODE: &str = "SUCCESS";
pub const STATUS_PENDING_CODE: &str = "PENDING";
pub const STATUS_FAILURE_CODE: &str = "FAILURE";
pub const STATUS_AUTH_PENDING_CODE: &str = "AUTH_PENDING";

// UPI Specific Constants
pub const UPI_PAYMENT_METHOD: &str = "UPI";
pub const UPI_INTENT_FLOW: &str = "INTENT";
pub const UPI_COLLECT_FLOW: &str = "COLLECT";

// Default Values
pub const DEFAULT_CURRENCY: &str = "INR";
pub const DEFAULT_TIMEOUT_SECONDS: u64 = 30;