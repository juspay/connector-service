// Basic structure for transformers.rs 

use domain_types::{
    connector_flow::{Authorize, Capture, Refund, Void},
    connector_types::{
        EventType, PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, RefundFlowData, RefundsData, RefundsResponseData, PaymentsSyncData,
    },
};
use error_stack::{ResultExt, report, Report};
use hyperswitch_api_models::enums::{self as api_enums, AttemptStatus, RefundStatus};
use hyperswitch_common_utils::{
    errors::CustomResult,
    request::RequestContent, // Added for consistency, though not directly used in JPM transformers yet
    types::MinorUnit,
};
use hyperswitch_domain_models::{
    payment_method_data::{Card, PaymentMethodData},
    router_data::{ConnectorAuthType, ErrorResponse, RouterData}, // RouterData for TryFrom <(JpmorganPaymentsResponse, RouterData<...>), ...>
    router_data_v2::RouterDataV2,
    router_request_types::{self as router_req_types, ResponseId}, // ResponseId is imported here
    router_response_types::{self as router_res_types, MandateReference, RedirectForm},
};
use hyperswitch_interfaces::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE}, // Though JPM has its own error codes/messages
    errors::{self as connector_errors, ConnectorError},
};
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use url::Url;
use domain_types::utils::ForeignTryFrom; // ENSURING THIS LINE IS CORRECT

// Based on Hyperswitch Jpmorgan transformers.rs

// Router Data wrapper (from guide)
pub struct JpmorganRouterData<'a, T> { // Added lifetime for references in T
    pub amount: MinorUnit, // Amount for the request
    pub router_data: &'a RouterDataV2<Authorize, PaymentFlowData, T, PaymentsResponseData>, // Reference to original router data
}

// We need a TryFrom for this to convert from (MinorUnit, &RouterDataV2)
impl<'a> TryFrom<(MinorUnit, &'a RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>)> for JpmorganRouterData<'a, PaymentsAuthorizeData> {
    type Error = error_stack::Report<connector_errors::ConnectorError>;
    fn try_from((amount, item): (MinorUnit, &'a RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>)) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            router_data: item,
        })
    }
}


// JPM specific request structures (inspired by Hyperswitch JpmorganPaymentsRequest)
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganPaymentsRequest {
    // Based on Hyperswitch JpmorganPaymentsRequest, but simplified for Authorize
    // capture_method: CapMethod, // Hyperswitch has this. Not directly in PaymentsAuthorizeData
    amount: MinorUnit,
    currency: api_enums::Currency,
    merchant: JpmorganMerchant, // Simplified, Hyperswitch has more fields
    payment_method_type: JpmorganPaymentMethodType, // Simplified Card for now
    // extended_data: Option<JpmorganExtendedData>, // Optional, not adding for now
    // transaction_interaction: String, // e.g., "CustomerPresent"
    // message_type_identifier: String, // e.g., "AuthorizationRequest"
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganMerchant { // Simplified from Hyperswitch
    merchant_id: String, // This should come from auth or config. For now, a placeholder.
                        // terminal_id: String, // From auth
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganPaymentMethodType {
    card: JpmorganCard, // Only card for now
                       // ach: Option<JpmorganAch>, // Future scope
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganCard {
    account_number: Secret<String>, // Card number
    expiry: Expiry,
    // security_code: Option<Secret<String>>, // CVV - Hyperswitch has this conditionally
    // card_holder_name: Option<Secret<String>>,
    // entry_mode: String, // e.g. "ManualKeyed"
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Expiry {
    month: Secret<String>,
    year: Secret<String>,
}

// TryFrom to convert PaymentsAuthorizeData to JpmorganPaymentsRequest
impl<'a> TryFrom<&JpmorganRouterData<'a, PaymentsAuthorizeData>> for JpmorganPaymentsRequest {
    type Error = Report<connector_errors::ConnectorError>;

    fn try_from(item: &JpmorganRouterData<'a, PaymentsAuthorizeData>) -> Result<Self, Self::Error> {
        let card_data = match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(card) => Ok(card),
            _ => {
                return Err(report!(connector_errors::ConnectorError::NotImplemented(
                    "Payment method not implemented".to_string()
                )));
            }
        }?; 

        let merchant_id = item.router_data.resource_common_data.merchant_id.to_string();

        Ok(Self {
            amount: item.amount, 
            currency: item.router_data.request.currency,
            merchant: JpmorganMerchant {
                merchant_id,
            },
            payment_method_type: JpmorganPaymentMethodType {
                card: JpmorganCard {
                    account_number: Secret::new(card_data.card_number.peek().peek().clone()), 
                    expiry: Expiry {
                        month: card_data.card_exp_month,
                        year: card_data.card_exp_year,
                    },
                },
            },
        })
    }
}

// JPM specific response structures (inspired by Hyperswitch JpmorganPaymentsResponse & JpmorganResponseStatus)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganPaymentsResponse {
    pub transaction_id: String,
    pub response_status: JpmorganTransactionStatus, // Renamed from JpmorganResponseStatus for clarity
    pub response_code: String,
    pub response_message: Option<String>,
    // pub merchant: Option<JpmorganMerchantResponseData>,
    // pub payment_method_type: Option<JpmorganPaymentMethodTypeResponse>,
    // pub transaction_amount: Option<TransactionAmountResponseData>,
    // pub auth_code: Option<String>,
    // ... other fields from Hyperswitch response if needed
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum JpmorganTransactionStatus {
    Success,
    Failure, 
    Pending, 
}

// Local wrapper for the response data to help with orphan rule
pub struct JpmorganResponseTransformWrapper {
    pub response: JpmorganPaymentsResponse,
    pub original_router_data_v2_authorize: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
    pub http_status_code: u16,
}

// New ForeignTryFrom implementation using the local wrapper
impl ForeignTryFrom<JpmorganResponseTransformWrapper> for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> {
    type Error = connector_errors::ConnectorError;

    fn foreign_try_from(
        wrapper: JpmorganResponseTransformWrapper
    ) -> Result<Self, Self::Error> {
        let mut router_data = wrapper.original_router_data_v2_authorize; 
        let jpm_response = wrapper.response;

        let status = match jpm_response.response_status {
            JpmorganTransactionStatus::Success => AttemptStatus::Authorized,
            JpmorganTransactionStatus::Failure => AttemptStatus::Failure,
            JpmorganTransactionStatus::Pending => AttemptStatus::Pending, 
        };

        router_data.resource_common_data.status = status;
        router_data.response = Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(jpm_response.transaction_id.clone()),
            redirection_data: Box::new(None), 
            connector_metadata: None, 
            network_txn_id: None, 
            connector_response_reference_id: Some(jpm_response.transaction_id),
            incremental_authorization_allowed: None, 
        });
        Ok(router_data)
    }
}

// JPM Error Response Structure (from Hyperswitch)
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JpmorganErrorResponse {
    pub response_status: String, // This seems to be a string in HS error, not the enum
    pub response_code: Option<String>, // Made Option as per HS, guide has non-optional
    pub response_message: Option<String>,
    pub reason: Option<String>, // Added for more detailed error, not in HS JpmorganErrorResponse directly
                                // pub validation_errors: Option<Vec<JpmorganValidationErrors>>,
                                // pub error_information: Option<JpmorganErrorInformation>,
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