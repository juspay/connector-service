// API endpoints for AirtelMoney connector based on Haskell implementation
pub const API_ENDPOINTS: &[(&str, &str, &str)] = &[
    // (request_type, is_test, endpoint)
    ("OtpGenerateRequest", "true", "https://apptest.airtelbank.com/apbnative/partners/:merchantId/customers/:customerId/authRequest"),
    ("OtpGenerateRequest", "false", "https://ecom.airtelbank.com/apbnative/partners/:merchantId/customers/:customerId/authRequest"),
    ("OtpVerificationRequest", "true", "https://apptest.airtelbank.com/apbnative/partners/:merchantId/customers/:customerId/authToken"),
    ("OtpVerificationRequest", "false", "https://ecom.airtelbank.com/apbnative/partners/:merchantId/customers/:customerId/authToken"),
    ("FetchCustProfRequest", "true", "https://apptest.airtelbank.com/apbnative/p1/customers/:customerId/profile"),
    ("FetchCustProfRequest", "false", "https://ecom.airtelbank.com/apbnative/p1/customers/:customerId/profile"),
    ("DelinkWalletRequest", "true", "https://apptest.airtelbank.com/apbnative/partners/:merchantId/customers/:customerId/delink"),
    ("DelinkWalletRequest", "false", "https://ecom.airtelbank.com/apbnative/partners/:merchantId/customers/:customerId/delink"),
    ("DirectDebitRequest", "true", "https://apptest.airtelbank.com/apbnative/p1/customers/:customerId/account/debit"),
    ("DirectDebitRequest", "false", "https://ecom.airtelbank.com/apbnative/p1/customers/:customerId/account/debit"),
    ("APBStatusRequest", "true", "https://apbuat.airtelbank.com:5050/bank/ecom/v2/inquiry"),
    ("APBStatusRequest", "false", "https://ecom.airtelbank.com/ecom/v2/inquiry"),
    ("RefundRequest", "true", "https://apbuat.airtelbank.com:5050/ecom/v2/reversal"),
    ("RefundRequest", "false", "https://ecom.airtelbank.com/ecom/v2/reversal"),
    ("TransactionRequest", "true", "https://apbuat.airtelbank.com:5050/ecom/v2/initiatePayment?"),
    ("TransactionRequest", "false", "https://ecom.airtelbank.com/ecom/v2/initiatePayment?"),
];

pub fn get_endpoint_for_req_and_env(request_type: &str, is_test: bool) -> &'static str {
    for (req_type, test_mode, endpoint) in API_ENDPOINTS {
        if *req_type == request_type && *test_mode == (if is_test { "true" } else { "false" }) {
            return endpoint;
        }
    }
    ""
}

pub mod headers {
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const AUTHORIZATION: &str = "Authorization";
    pub const X_API_KEY: &str = "X-API-Key";
    pub const X_MERCHANT_ID: &str = "X-Merchant-ID";
}