pub const TPSL_BASE_URL_PRODUCTION: &str = "https://www.tpsl-india.in";
pub const TPSL_BASE_URL_TEST: &str = "https://www.tekprocess.co.in";

pub const TPSL_TRANSACTION_ENDPOINT: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_AUTH_CAPTURE_ENDPOINT: &str = "/PaymentGateway/merchant2.pg";
pub const TPSL_SI_TRANSACTION_ENDPOINT: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_UPI_TRANSACTION_ENDPOINT: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_UPI_TOKEN_GENERATION_ENDPOINT: &str = "/PaymentGateway/services/TransactionDetailsNew";
pub const TPSL_REFUND_ARN_SYNC_ENDPOINT: &str = "/PaymentGateway/services/TransactionDetailsNew";

#[derive(Debug, Clone)]
pub enum TpslApiEndpoints {
    Transaction,
    AuthCapture,
    SITransaction,
    UPITransaction,
    UPITokenGeneration,
    RefundArnSync,
}

impl TpslApiEndpoints {
    pub fn get_endpoint(&self, is_test_mode: bool) -> &'static str {
        let base_url = if is_test_mode {
            TPSL_BASE_URL_TEST
        } else {
            TPSL_BASE_URL_PRODUCTION
        };

        match self {
            Self::Transaction => TPSL_TRANSACTION_ENDPOINT,
            Self::AuthCapture => TPSL_AUTH_CAPTURE_ENDPOINT,
            Self::SITransaction => TPSL_SI_TRANSACTION_ENDPOINT,
            Self::UPITransaction => TPSL_UPI_TRANSACTION_ENDPOINT,
            Self::UPITokenGeneration => TPSL_UPI_TOKEN_GENERATION_ENDPOINT,
            Self::RefundArnSync => TPSL_REFUND_ARN_SYNC_ENDPOINT,
        }
    }

    pub fn get_full_url(&self, is_test_mode: bool, merchant_code: Option<&str>) -> String {
        let base_url = if is_test_mode {
            TPSL_BASE_URL_TEST
        } else {
            TPSL_BASE_URL_PRODUCTION
        };

        match self {
            Self::AuthCapture => {
                if let Some(code) = merchant_code {
                    format!("{}{}/{}", base_url, TPSL_AUTH_CAPTURE_ENDPOINT, code)
                } else {
                    format!("{}{}", base_url, TPSL_AUTH_CAPTURE_ENDPOINT)
                }
            }
            _ => format!("{}{}", base_url, self.get_endpoint(is_test_mode)),
        }
    }
}