use serde::{Deserialize, Serialize};

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
            EaseBuzzApi::InitiatePayment => super::constants::EaseBuzzConstants::INITIATE_PAYMENT,
            EaseBuzzApi::SeamlessTransaction => super::constants::EaseBuzzConstants::SEAMLESS_TRANSACTION,
            EaseBuzzApi::TransactionSync => super::constants::EaseBuzzConstants::TRANSACTION_SYNC,
            EaseBuzzApi::Refund => super::constants::EaseBuzzConstants::REFUND,
            EaseBuzzApi::RefundSync => super::constants::EaseBuzzConstants::REFUND_SYNC,
            EaseBuzzApi::Upiautopay => super::constants::EaseBuzzConstants::UPI_AUTOPAY,
            EaseBuzzApi::Upimandateexecute => super::constants::EaseBuzzConstants::UPI_MANDATE_EXECUTE,
            EaseBuzzApi::MandateRetrieve => super::constants::EaseBuzzConstants::MANDATE_RETRIEVE,
            EaseBuzzApi::MandateCreate => super::constants::EaseBuzzConstants::MANDATE_CREATE,
            EaseBuzzApi::NotificationRequest => super::constants::EaseBuzzConstants::NOTIFICATION_REQUEST,
            EaseBuzzApi::NotificationSync => super::constants::EaseBuzzConstants::NOTIFICATION_SYNC,
            EaseBuzzApi::RevokeMandate => super::constants::EaseBuzzConstants::REVOKE_MANDATE,
        }
    }

    pub fn get_base_url(is_test_mode: bool) -> &'static str {
        if is_test_mode {
            super::constants::EaseBuzzConstants::BASE_URL_TEST
        } else {
            super::constants::EaseBuzzConstants::BASE_URL_PROD
        }
    }
}