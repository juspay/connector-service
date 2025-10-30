pub const BILLDESK_UAT_BASE_URL: &str = "https://uat.billdesk.com";
pub const BILLDESK_PROD_BASE_URL: &str = "https://www.billdesk.com";

pub const BILLDESK_AUTHORIZE_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF011";
pub const BILLDESK_STATUS_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF002";
pub const BILLDESK_UPI_INITIATE_ENDPOINT: &str = "/pgidsk/PGIDirectRequest?reqid=BDRDF011";

pub const BILLDESK_AUTH_SUCCESS_STATUS: &str = "0300";
pub const BILLDESK_AUTH_PENDING_STATUS: &str = "0396";
pub const BILLDESK_AUTH_FAILURE_STATUS: &str = "0397";

pub const BILLDESK_PAYMENT_METHOD_UPI: &str = "UPI";
pub const BILLDESK_TXN_TYPE_DIRECT: &str = "DIRECT";
pub const BILLDESK_ITEM_CODE_DIRECT: &str = "DIRECT";

pub const BILLDESK_RESPONSE_FIELD_MERCHANT_ID: &str = "_MerchantID";
pub const BILLDESK_RESPONSE_FIELD_CUSTOMER_ID: &str = "_CustomerID";
pub const BILLDESK_RESPONSE_FIELD_TXN_REFERENCE_NO: &str = "_TxnReferenceNo";
pub const BILLDESK_RESPONSE_FIELD_BANK_REFERENCE_NO: &str = "_BankReferenceNo";
pub const BILLDESK_RESPONSE_FIELD_TXN_AMOUNT: &str = "_TxnAmount";
pub const BILLDESK_RESPONSE_FIELD_AUTH_STATUS: &str = "_AuthStatus";
pub const BILLDESK_RESPONSE_FIELD_CURRENCY_TYPE: &str = "_CurrencyType";
pub const BILLDESK_RESPONSE_FIELD_TXN_DATE: &str = "_TxnDate";
pub const BILLDESK_RESPONSE_FIELD_ERROR_STATUS: &str = "_ErrorStatus";
pub const BILLDESK_RESPONSE_FIELD_ERROR_DESCRIPTION: &str = "_ErrorDescription";