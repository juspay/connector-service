use std::str::FromStr;

use common_utils::types::MinorUnit;
use domain_types::{
    errors,
    payment_method_data::{PaymentMethodDataTypes, RawCardNumber},
};
use error_stack::report;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct JpmorganTokenRequest {
    pub grant_type: String,
    pub scope: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganPaymentsRequest<T: PaymentMethodDataTypes> {
    pub capture_method: CapMethod,
    pub amount: MinorUnit,
    pub currency: common_enums::Currency,
    pub merchant: JpmorganMerchant,
    pub payment_method_type: JpmorganPaymentMethodType<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganPaymentMethodType<T: PaymentMethodDataTypes> {
    pub card: JpmorganCard<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganCard<T: PaymentMethodDataTypes> {
    pub account_number: RawCardNumber<T>,
    pub expiry: Expiry,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Expiry {
    pub month: Secret<i32>,
    pub year: Secret<i32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganMerchant {
    pub merchant_software: JpmorganMerchantSoftware,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganMerchantSoftware {
    pub company_name: Secret<String>,
    pub product_name: Secret<String>,
}

#[derive(Debug, Default, Copy, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum CapMethod {
    #[default]
    Now,
    Delayed,
    Manual,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganCaptureRequest {
    pub capture_method: Option<CapMethod>,
    pub amount: MinorUnit,
    pub currency: Option<common_enums::Currency>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReversalReason {
    NoResponse,
    LateResponse,
    UnableToDeliver,
    CardDeclined,
    MacNotVerified,
    MacSyncError,
    ZekSyncError,
    SystemMalfunction,
    SuspectedFraud,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganVoidRequest {
    pub amount: Option<MinorUnit>,
    pub is_void: Option<bool>,
    pub reversal_reason: Option<ReversalReason>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganRefundRequest {
    pub merchant: JpmorganMerchantRefund,
    pub amount: MinorUnit,
    pub currency: common_enums::Currency,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganMerchantRefund {
    pub merchant_software: JpmorganMerchantSoftware,
}

impl FromStr for ReversalReason {
    type Err = error_stack::Report<errors::ConnectorError>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "NO_RESPONSE" => Ok(Self::NoResponse),
            "LATE_RESPONSE" => Ok(Self::LateResponse),
            "UNABLE_TO_DELIVER" => Ok(Self::UnableToDeliver),
            "CARD_DECLINED" => Ok(Self::CardDeclined),
            "MAC_NOT_VERIFIED" => Ok(Self::MacNotVerified),
            "MAC_SYNC_ERROR" => Ok(Self::MacSyncError),
            "ZEK_SYNC_ERROR" => Ok(Self::ZekSyncError),
            "SYSTEM_MALFUNCTION" => Ok(Self::SystemMalfunction),
            "SUSPECTED_FRAUD" => Ok(Self::SuspectedFraud),
            _ => Err(report!(errors::ConnectorError::InvalidDataFormat {
                field_name: "cancellation_reason",
            })),
        }
    }
}
