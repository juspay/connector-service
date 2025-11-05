pub const BILLDESK_UAT_BASE_URL: &str = "https://uat.billdesk.com/pgidsk/PGIDirectRequest";
pub const BILLDESK_PROD_BASE_URL: &str = "https://www.billdesk.com/pgidsk/PGIDirectRequest";

// Request IDs for different Billdesk operations based on Haskell implementation
pub const BILLDESK_UPI_INITIATE_REQID: &str = "BDRDF011";     // UPI Initiation
pub const BILLDESK_AUTH_REQID: &str = "BDRDF002";           // Authorization
pub const BILLDESK_STATUS_REQID: &str = "BDRDF003";         // Status Check
pub const BILLDESK_REFUND_REQID: &str = "BDRDF004";         // Refund
pub const BILLDESK_NB_INITIATE_REQID: &str = "BDRDF005";    // Net Banking Initiation
pub const BILLDESK_CARD_INITIATE_REQID: &str = "BDRDF006";  // Card Initiation
pub const BILLDESK_MANDATE_CREATE_REQID: &str = "BDRDF007"; // Mandate Creation
pub const BILLDESK_MANDATE_REVOKE_REQID: &str = "BDRDF008"; // Mandate Revocation

// Payment status codes from Billdesk based on Haskell implementation
pub const BILLDESK_STATUS_SUCCESS: &str = "0300";           // Success
pub const BILLDESK_STATUS_SUCCESS_ALT: &str = "0399";       // Success (alternative)
pub const BILLDESK_STATUS_PENDING: &str = "0396";          // Pending
pub const BILLDESK_STATUS_FAILURE: &str = "0398";          // Failure
pub const BILLDESK_STATUS_INITIATED: &str = "0301";        // Initiated
pub const BILLDESK_STATUS_IN_PROGRESS: &str = "0302";      // In Progress

// Error status codes
pub const BILLDESK_ERROR_SUCCESS: &str = "000";             // No Error
pub const BILLDESK_ERROR_FAILURE: &str = "001";             // Failure
pub const BILLDESK_ERROR_PENDING: &str = "002";             // Pending

// HTTP Error codes
pub const BILLDESK_ERROR_INVALID_REQUEST: &str = "400";
pub const BILLDESK_ERROR_AUTH_FAILED: &str = "401";
pub const BILLDESK_ERROR_NOT_FOUND: &str = "404";
pub const BILLDESK_ERROR_SERVER_ERROR: &str = "500";

// Headers
pub const BILLDESK_CONTENT_TYPE: &str = "application/json";
pub const BILLDESK_AUTH_HEADER: &str = "Authorization";
pub const BILLDESK_MERCHANT_ID_HEADER: &str = "Merchant-ID";

// Currency codes (ISO 4217 numeric)
pub const BILLDESK_CURRENCY_INR: &str = "356";           // Indian Rupee
pub const BILLDESK_CURRENCY_USD: &str = "840";           // US Dollar
pub const BILLDESK_CURRENCY_EUR: &str = "978";           // Euro
pub const BILLDESK_CURRENCY_GBP: &str = "826";           // British Pound

// Transaction types based on Haskell implementation
pub const BILLDESK_TXN_TYPE_UPI: &str = "UPI";            // UPI Transaction
pub const BILLDESK_TXN_TYPE_NB: &str = "NB";              // Net Banking
pub const BILLDESK_TXN_TYPE_CARD: &str = "CARD";          // Card Transaction
pub const BILLDESK_TXN_TYPE_WALLET: &str = "WALLET";      // Wallet Transaction
pub const BILLDESK_TXN_TYPE_RECURRING: &str = "RECURRING"; // Recurring Transaction

// Item codes
pub const BILLDESK_ITEM_CODE_DIRECT: &str = "DIRECT";     // Direct Payment
pub const BILLDESK_ITEM_CODE_RECURRING: &str = "RECURRING"; // Recurring Payment
pub const BILLDESK_ITEM_CODE_MANDATE: &str = "MANDATE";   // Mandate Registration

// Additional info field mappings based on Haskell implementation
pub const BILLDESK_ADDITIONAL_INFO_VPA: &str = "AdditionalInfo1";     // UPI VPA
pub const BILLDESK_ADDITIONAL_INFO_BANK_ID: &str = "AdditionalInfo2"; // Bank ID
pub const BILLDESK_ADDITIONAL_INFO_TXN_TYPE: &str = "AdditionalInfo3"; // Transaction Sub-type
pub const BILLDESK_ADDITIONAL_INFO_REMARKS: &str = "AdditionalInfo4";  // Remarks
pub const BILLDESK_ADDITIONAL_INFO_MERCHANT_DATA: &str = "AdditionalInfo5"; // Merchant Data
pub const BILLDESK_ADDITIONAL_INFO_CUSTOMER_DATA: &str = "AdditionalInfo6"; // Customer Data
pub const BILLDESK_ADDITIONAL_INFO_END_DATE: &str = "AdditionalInfo7"; // End Date (for mandates)

// Mandate related constants
pub const BILLDESK_MANDATE_FREQUENCY_DAILY: &str = "DAILY";
pub const BILLDESK_MANDATE_FREQUENCY_WEEKLY: &str = "WEEKLY";
pub const BILLDESK_MANDATE_FREQUENCY_MONTHLY: &str = "MONTHLY";
pub const BILLDESK_MANDATE_FREQUENCY_QUARTERLY: &str = "QUARTERLY";
pub const BILLDESK_MANDATE_FREQUENCY_YEARLY: &str = "YEARLY";
pub const BILLDESK_MANDATE_FREQUENCY_ASD: &str = "ASD"; // As and When Presented

// Refund related constants
pub const BILLDESK_REFUND_STATUS_SUCCESS: &str = "SUCCESS";
pub const BILLDESK_REFUND_STATUS_PENDING: &str = "PENDING";
pub const BILLDESK_REFUND_STATUS_FAILURE: &str = "FAILURE";
pub const BILLDESK_REFUND_STATUS_PROCESSING: &str = "PROCESSING";