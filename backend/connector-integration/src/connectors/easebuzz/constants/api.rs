use serde::{Deserialize, Serialize};
use super::EaseBuzzConstants;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EaseBuzzApi {
    InitiatePayment,
    SeamlessTransaction,
    TransactionSync,
    Refund,
    RefundSync,
    Upiautopay,
    Upimandateexecute,
    MandateRetrieve,
    MandateCreate,
    NotificationRequest,
    NotificationSync,
    RevokeMandate,
}

impl EaseBuzzApi {
    pub fn get_api_endpoint(&self) -> &'static str {
        match self {
            EaseBuzzApi::InitiatePayment => EaseBuzzConstants::INITIATE_PAYMENT,
            EaseBuzzApi::SeamlessTransaction => EaseBuzzConstants::SEAMLESS_TRANSACTION,
            EaseBuzzApi::TransactionSync => EaseBuzzConstants::TRANSACTION_SYNC,
            EaseBuzzApi::Refund => EaseBuzzConstants::REFUND,
            EaseBuzzApi::RefundSync => EaseBuzzConstants::REFUND_SYNC,
            EaseBuzzApi::Upiautopay => EaseBuzzConstants::UPI_AUTOPAY,
            EaseBuzzApi::Upimandateexecute => EaseBuzzConstants::UPI_MANDATE_EXECUTE,
            EaseBuzzApi::MandateRetrieve => EaseBuzzConstants::MANDATE_RETRIEVE,
            EaseBuzzApi::MandateCreate => EaseBuzzConstants::MANDATE_CREATE,
            EaseBuzzApi::NotificationRequest => EaseBuzzConstants::NOTIFICATION_REQUEST,
            EaseBuzzApi::NotificationSync => EaseBuzzConstants::NOTIFICATION_SYNC,
            EaseBuzzApi::RevokeMandate => EaseBuzzConstants::REVOKE_MANDATE,
        }
    }

    pub fn get_base_url(is_test_mode: bool) -> &'static str {
        if is_test_mode {
            EaseBuzzConstants::BASE_URL_TEST
        } else {
            EaseBuzzConstants::BASE_URL_PROD
        }
    }
}