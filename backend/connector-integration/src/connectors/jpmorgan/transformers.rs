use domain_types::{
    connector_flow::{Authorize, Capture, Refund, Void},
    connector_types::{
        EventType, PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, RefundFlowData, RefundsData, RefundsResponseData, PaymentsSyncData,
    },
};

use error_stack::{ResultExt, report, Report};

use hyperswitch_api_models::enums::{AttemptStatus, RefundStatus};

use hyperswitch_common_utils::{
    types::MinorUnit,
};

use hyperswitch_common_enums::CaptureMethod;

use hyperswitch_domain_models::{
    payment_method_data::{ self, PaymentMethodData},
    router_data::{ConnectorAuthType, ErrorResponse, RouterData}, // RouterData for TryFrom <(JpmorganPaymentsResponse, RouterData<...>), ...>
    router_data_v2::RouterDataV2,
    router_request_types::{ResponseId}, // ResponseId is imported here
    router_response_types::{MandateReference, RedirectForm},
};

use hyperswitch_interfaces::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE}, // Though JPM has its own error codes/messages
    errors::{self, ConnectorError},
};

use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};

use serde::{Deserialize, Serialize};

// Based on Hyperswitch Jpmorgan transformers.rs
pub struct JpmorganRouterData<T> {
    pub amount: MinorUnit,
    pub router_data: T,
}

impl<T> From<(MinorUnit, T)> for JpmorganRouterData<T> {
    fn from((amount, item): (MinorUnit, T)) -> Self {
        Self {
            amount,
            router_data: item,
        }
    }
}

#[derive(Debug, Default, Copy, Serialize, Deserialize, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum CapMethod {
    #[default]
    Now,
    Delayed,
    Manual,
}

#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganPaymentsRequest {
    capture_method: CapMethod,
    amount: MinorUnit,
    currency: hyperswitch_common_enums::Currency,
    merchant: JpmorganMerchant,
    payment_method_type: JpmorganPaymentMethodType,
}

#[derive(Serialize, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganMerchantSoftware {
    company_name: Secret<String>,
    product_name: Secret<String>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganMerchant {
    merchant_software: JpmorganMerchantSoftware,
}

#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganPaymentMethodType {
    card: JpmorganCard,
}

#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganCard {
    account_number: Secret<String>,
    expiry: Expiry,
}

#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Expiry {
    month: Secret<i32>,
    year: Secret<i32>,
}

pub trait ForeignTryFrom<F>: Sized {
    type Error;

    fn foreign_try_from(from: F) -> Result<Self, Self::Error>;
}

pub(crate) const SELECTED_PAYMENT_METHOD: &str = "Selected payment method";

pub(crate) fn get_unimplemented_payment_method_error_message(connector: &str) -> String {
    format!("{} through {}", SELECTED_PAYMENT_METHOD, connector)
}

pub fn attempt_status_from_transaction_state(
    transaction_state: JpmorganTransactionState,
) -> AttemptStatus {
    match transaction_state {
        JpmorganTransactionState::Authorized => AttemptStatus::Authorized,
        JpmorganTransactionState::Closed => AttemptStatus::Charged,
        JpmorganTransactionState::Declined | JpmorganTransactionState::Error => {
            AttemptStatus::Failure
        }
        JpmorganTransactionState::Pending => AttemptStatus::Pending,
        JpmorganTransactionState::Voided => AttemptStatus::Voided,
    }
}

#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpiryResponse {
    month: Option<Secret<i32>>,
    year: Option<Secret<i32>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardTypeIndicators {
    issuance_country_code: Option<Secret<String>>,
    is_durbin_regulated: Option<bool>,
    card_product_types: Secret<Vec<String>>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkResponse {
    address_verification_result: Option<Secret<String>>,
    address_verification_result_code: Option<Secret<String>>,
    card_verification_result_code: Option<Secret<String>>,
}

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum JpmorganTransactionState {
    Closed,
    Authorized,
    Voided,
    #[default]
    Pending,
    Declined,
    Error,
}

#[derive(Default, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentMethodType {
    card: Option<Card>,
}

#[derive(Default, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Card {
    expiry: Option<ExpiryResponse>,
    card_type: Option<Secret<String>>,
    card_type_name: Option<Secret<String>>,
    masked_account_number: Option<Secret<String>>,
    card_type_indicators: Option<CardTypeIndicators>,
    network_response: Option<NetworkResponse>,
}

#[derive(Default, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganPaymentsResponse {
    transaction_id: String,
    request_id: String,
    transaction_state: JpmorganTransactionState,
    response_status: String,
    response_code: String,
    response_message: String,
    payment_method_type: PaymentMethodType,
    capture_method: Option<CapMethod>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum JpmorganTransactionStatus {
    Success,
    Failure, 
    Pending, 
}

fn map_capture_method(
    capture_method: CaptureMethod,
) -> Result<CapMethod, error_stack::Report<errors::ConnectorError>> {
    match capture_method {
        CaptureMethod::Automatic => Ok(CapMethod::Now),
        CaptureMethod::Manual => Ok(CapMethod::Manual),
        CaptureMethod::Scheduled
        | CaptureMethod::ManualMultiple
         => {
            Err(errors::ConnectorError::NotImplemented("Capture Method".to_string()).into())
        }
    }
}

fn get_expiry_year_4_digit(card: &payment_method_data::Card) -> Secret<i32> {
    let mut year = card.card_exp_year.peek().clone();
    if year.len() == 2 {
        year = format!("20{}", year);
    }

    let year_int: i32 = year
        .parse()
        .unwrap_or_else(|_| 0);
    Secret::new(year_int)
}

fn get_expiry_month(card: &payment_method_data::Card) -> Secret<i32> {
    let month = card.card_exp_month.peek().clone();

    let month_int: i32 = month
        .parse()
        .unwrap_or_else(|_| 0);
    Secret::new(month_int)
}

impl TryFrom<&JpmorganRouterData<&RouterDataV2<Authorize,PaymentFlowData,PaymentsAuthorizeData,PaymentsResponseData>>> for JpmorganPaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &JpmorganRouterData<&RouterDataV2<Authorize,PaymentFlowData,PaymentsAuthorizeData,PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(req_card) => {
                if item.router_data.request.enrolled_for_3ds {
                    return Err(errors::ConnectorError::NotSupported {
                        message: "3DS payments".to_string(),
                        connector: "Jpmorgan",
                    }
                    .into());
                }

                let capture_method =
                    map_capture_method(item.router_data.request.capture_method.unwrap_or_default());

                let merchant_software = JpmorganMerchantSoftware {
                    company_name: String::from("JPMC").into(),
                    product_name: String::from("Hyperswitch").into(),
                };

                let merchant = JpmorganMerchant { merchant_software };

                let expiry: Expiry = Expiry {
                    month: get_expiry_month(&req_card),
                    year: get_expiry_year_4_digit(&req_card),
                };

                let account_number = Secret::new(req_card.card_number.to_string());

                let card = JpmorganCard {
                    account_number,
                    expiry,
                };

                let payment_method_type = JpmorganPaymentMethodType { card };

                Ok(Self {
                    capture_method: capture_method?,
                    currency: item.router_data.request.currency,
                    amount: item.amount,
                    merchant,
                    payment_method_type,
                })
            }
            PaymentMethodData::CardRedirect(_)
            | PaymentMethodData::Wallet(_)
            | PaymentMethodData::PayLater(_)
            | PaymentMethodData::BankRedirect(_)
            | PaymentMethodData::BankDebit(_)
            | PaymentMethodData::BankTransfer(_)
            | PaymentMethodData::Crypto(_)
            | PaymentMethodData::MandatePayment
            | PaymentMethodData::Reward
            | PaymentMethodData::RealTimePayment(_)
            | PaymentMethodData::Upi(_)
            | PaymentMethodData::Voucher(_)
            | PaymentMethodData::GiftCard(_)
            | PaymentMethodData::OpenBanking(_)
            | PaymentMethodData::CardToken(_)
             => Err(errors::ConnectorError::NotImplemented(
                get_unimplemented_payment_method_error_message("jpmorgan"),
            )
            .into()),
        }
    }
}

impl<F>
    ForeignTryFrom<(
        JpmorganPaymentsResponse,
        RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        u16,
        
    )> for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
{
    type Error = error_stack::Report<hyperswitch_interfaces::errors::ConnectorError>;
    fn foreign_try_from(
        (response, data, _http_code): (
            JpmorganPaymentsResponse,
            RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
            u16,
        ),
    ) -> Result<Self, Self::Error> {
        let transaction_state = match response.transaction_state {
            JpmorganTransactionState::Closed => match response.capture_method {
                Some(CapMethod::Now) => JpmorganTransactionState::Closed,
                _ => JpmorganTransactionState::Authorized,
            },
            JpmorganTransactionState::Authorized => JpmorganTransactionState::Authorized,
            JpmorganTransactionState::Voided => JpmorganTransactionState::Voided,
            JpmorganTransactionState::Pending => JpmorganTransactionState::Pending,
            JpmorganTransactionState::Declined => JpmorganTransactionState::Declined,
            JpmorganTransactionState::Error => JpmorganTransactionState::Error,
        };
        let status = attempt_status_from_transaction_state(transaction_state);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    response.transaction_id.clone(),
                ),
                redirection_data: Box::new(None),
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(response.transaction_id.clone()),
                incremental_authorization_allowed: None,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..data.resource_common_data
            },
            ..data
        })
    }
}

// Local wrapper for the response data to help with orphan rule
pub struct JpmorganResponseTransformWrapper {
    pub response: JpmorganPaymentsResponse,
    pub original_router_data_v2_authorize: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    pub http_status_code: u16,
}

// New ForeignTryFrom implementation using the local wrapper
// impl ForeignTryFrom<JpmorganResponseTransformWrapper> for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> {
//     type Error = connector_errors::ConnectorError;

//     fn foreign_try_from(
//         wrapper: JpmorganResponseTransformWrapper
//     ) -> Result<RouterDataV2<domain_types::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData, domain_types::connector_types::PaymentsResponseData>, error_stack::Report<hyperswitch_interfaces::errors::ConnectorError>> {
//         let mut router_data = wrapper.original_router_data_v2_authorize; 
//         let jpm_response = wrapper.response;

//         let status = match jpm_response.response_status {
//             JpmorganTransactionStatus::Success => AttemptStatus::Authorized,
//             JpmorganTransactionStatus::Failure => AttemptStatus::Failure,
//             JpmorganTransactionStatus::Pending => AttemptStatus::Pending, 
//         };

//         router_data.resource_common_data.status = status;
//         router_data.response = Ok(PaymentsResponseData::TransactionResponse {
//             resource_id: ResponseId::ConnectorTransactionId(jpm_response.transaction_id.clone()),
//             redirection_data: Box::new(None), 
//             connector_metadata: None, 
//             network_txn_id: None, 
//             connector_response_reference_id: Some(jpm_response.transaction_id),
//             incremental_authorization_allowed: None, 
//         });
//         Ok(router_data)
//     }
// }

// JPM Error Response Structure (from Hyperswitch)
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganErrorResponse {
    pub response_status: JpmorganTransactionStatus,
    pub response_code: String,
    pub response_message: Option<String>,
}

// #[derive(Debug, Serialize, Deserialize, PartialEq)]
// #[serde(rename_all = "camelCase")]
// pub struct JpmorganValidationErrors { // From HS
//     pub code: Option<String>,
//     pub message: Option<String>,
//     pub entity: Option<String>,
// }

// #[derive(Debug, Serialize, Deserialize, PartialEq)]
// #[serde(rename_all = "camelCase")]
// pub struct JpmorganErrorInformation { // From HS
//     pub code: Option<String>,
//     pub message: Option<String>,
// }

// Enum for CaptureMethod if needed, from Hyperswitch
// #[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
// #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
// pub enum CapMethod {
//     Manual,       // Manual Capture
//     NotApplicable,
//     Ecom,         // Auto Capture for ECOM
//     Moto,         // Auto Capture for MOTO
//     Installment,  // Auto Capture for Installment
//     Aggregated,   // Auto Capture for Aggregated
//     Recurring,    // Auto Capture for Recurring
//     Incremental,  // Auto Capture for Incremental
//     Resubmission, // Auto Capture for Resubmission
// }

// Utility to map our PaymentMethodData to what JPM expects, if more complex than direct field mapping.
// For now, direct mapping is used in TryFrom JpmorganPaymentsRequest.

// ... rest of the file remains unchanged ... 