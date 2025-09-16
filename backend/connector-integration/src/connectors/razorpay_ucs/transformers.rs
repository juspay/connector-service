use std::collections::HashMap;

use common_enums::{AttemptStatus, Currency, PaymentMethod};
use common_utils::{
    errors::CustomResult,

    types::{MinorUnit, StringMajorUnit},
};
use domain_types::{
    connector_types::{PaymentsResponseData, ResponseId},
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, UpiData},
    router_data::{ConnectorAuthType, ErrorResponse},
};
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use error_stack::ResultExt;


use crate::types::ResponseRouterData;



#[derive(Debug, Serialize)]
pub struct RazorpayUcsAuth {
    pub api_key: Secret<String>,
    pub api_secret: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for RazorpayUcsAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: key1.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Request and Response Types for UPI Payments

#[derive(Debug, Serialize)]
pub struct RazorpayUcsPaymentsRequest {
    pub amount: StringMajorUnit,
    pub currency: Currency,
    pub method: PaymentMethod,
    pub vpa: Option<Secret<String>>,
    pub order_id: Option<String>,
    pub customer: Option<RazorpayUcsCustomer>,
    pub notes: Option<RazorpayUcsNotes>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RazorpayUcsCustomer {
    pub name: Option<Secret<String>>,
    pub email: Option<Secret<String>>,
    pub contact: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
pub struct RazorpayUcsNotes {
    pub transaction_id: Option<String>,
    pub payment_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RazorpayUcsPaymentsResponse {
    pub id: String,
    pub entity: String,
    pub amount: i64,
    pub currency: Currency,
    pub status: String,
    pub order_id: Option<String>,
    pub method: Option<String>,
    pub vpa: Option<String>,
    pub created_at: Option<i64>,
    pub error_code: Option<String>,
    pub error_description: Option<String>,
    pub error_reason: Option<String>,
    pub error_source: Option<String>,
    pub error_step: Option<String>,
}

// Sync Response Types
#[derive(Debug, Serialize, Deserialize)]
pub struct RazorpayUcsPaymentsSyncResponse {
    pub id: String,
    pub entity: String,
    pub amount: i64,
    pub currency: Currency,
    pub status: String,
    pub order_id: Option<String>,
    pub method: Option<String>,
    pub vpa: Option<String>,
    pub created_at: Option<i64>,
    pub error_code: Option<String>,
    pub error_description: Option<String>,
    pub error_reason: Option<String>,
    pub error_source: Option<String>,
    pub error_step: Option<String>,
}

// Error Response Types
#[derive(Debug, Deserialize, Serialize)]
pub struct RazorpayUcsErrorResponse {
    pub error: RazorpayUcsError,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RazorpayUcsError {
    pub code: String,
    pub description: String,
    pub field: Option<String>,
    pub source: Option<String>,
    pub step: Option<String>,
    pub reason: Option<String>,
    pub metadata: Option<serde_json::Value>,
}



// Implementation for Authorize Request (owned version for macro compatibility)
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> TryFrom<super::RazorpayUcsRouterData<domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T>, domain_types::connector_types::PaymentsResponseData>, T>> for RazorpayUcsPaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: super::RazorpayUcsRouterData<domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T>, domain_types::connector_types::PaymentsResponseData>, T>) -> Result<Self, Self::Error> {
        let currency = item.router_data.request.currency;
        
        let (method, vpa) = match &item.router_data.request.payment_method_data {
            PaymentMethodData::Upi(upi_data) => {
                let vpa_id = match upi_data {
                    UpiData::UpiCollect(collect_data) => collect_data.vpa_id.as_ref().map(|vpa| Secret::new(vpa.clone().expose())),
                    UpiData::UpiIntent(_) => None,
                };
                (PaymentMethod::Upi, vpa_id)
            }
            _ => return Err(errors::ConnectorError::NotSupported {
                message: "Payment method not supported for UPI".to_string(),
                connector: "razorpay_ucs",
            }.into()),
        };

        let customer_email = item.router_data.request.email.as_ref().map(|email| Secret::new(email.clone().expose().expose()));

        let customer = Some(RazorpayUcsCustomer {
            name: item.router_data.request.customer_name.clone().map(Secret::new),
            email: customer_email,
            contact: item.router_data.resource_common_data.get_optional_billing_phone_number().map(|phone| Secret::new(phone.peek().to_string())),
        });

        let notes = Some(RazorpayUcsNotes {
            transaction_id: Some(item.router_data.resource_common_data.connector_request_reference_id.clone()),
            payment_id: Some(item.router_data.resource_common_data.attempt_id.clone()),
        });

        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            amount,
            currency,
            method,
            vpa,
            order_id: item.router_data.resource_common_data.reference_id.clone(),
            customer,
            notes,
            description: item.router_data.resource_common_data.description.clone(),
        })
    }
}

// Implementation for Authorize Request (reference version)
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> TryFrom<&super::RazorpayUcsRouterData<&domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T>, domain_types::connector_types::PaymentsResponseData>, T>> for RazorpayUcsPaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &super::RazorpayUcsRouterData<&domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T>, domain_types::connector_types::PaymentsResponseData>, T>) -> Result<Self, Self::Error> {
        let currency = item.router_data.request.currency;
        
        let (method, vpa) = match &item.router_data.request.payment_method_data {
            PaymentMethodData::Upi(upi_data) => {
                let vpa_id = match upi_data {
                    UpiData::UpiCollect(collect_data) => collect_data.vpa_id.as_ref().map(|vpa| Secret::new(vpa.clone().expose())),
                    UpiData::UpiIntent(_) => None,
                };
                (PaymentMethod::Upi, vpa_id)
            }
            _ => return Err(errors::ConnectorError::NotSupported {
                message: "Payment method not supported for UPI".to_string(),
                connector: "razorpay_ucs",
            }.into()),
        };

        let customer_email = item.router_data.request.email.as_ref().map(|email| Secret::new(email.clone().expose().expose()));

        let customer = Some(RazorpayUcsCustomer {
            name: item.router_data.request.customer_name.clone().map(Secret::new),
            email: customer_email,
            contact: item.router_data.resource_common_data.get_optional_billing_phone_number().map(|phone| Secret::new(phone.peek().to_string())),
        });

        let notes = Some(RazorpayUcsNotes {
            transaction_id: Some(item.router_data.resource_common_data.connector_request_reference_id.clone()),
            payment_id: Some(item.router_data.resource_common_data.attempt_id.clone()),
        });

        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            amount,
            currency,
            method,
            vpa,
            order_id: item.router_data.resource_common_data.reference_id.clone(),
            customer,
            notes,
            description: item.router_data.resource_common_data.description.clone(),
        })
    }
}

// Implementation for Authorize Response
impl<T> TryFrom<ResponseRouterData<RazorpayUcsPaymentsResponse, domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T>, domain_types::connector_types::PaymentsResponseData>>> for domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T>, domain_types::connector_types::PaymentsResponseData>
where
    T: PaymentMethodDataTypes,
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<RazorpayUcsPaymentsResponse, domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T>, domain_types::connector_types::PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let status = get_payment_status(&item.response.status)?;
        let _amount_received = Some(MinorUnit::new(item.response.amount / 100));
        
        let error_response = if status == AttemptStatus::Failure {
            Some(ErrorResponse {
                code: item.response.error_code.unwrap_or_else(|| "unknown_error".to_string()),
                message: item.response.error_description.unwrap_or_else(|| "Payment failed".to_string()),
                reason: item.response.error_reason,
                status_code: item.http_code,
                attempt_status: Some(status),
                connector_transaction_id: Some(item.response.id.clone()),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            })
        } else {
            None
        };

        let connector_response_reference_id = match status {
            AttemptStatus::Charged | AttemptStatus::AuthenticationSuccessful => {
                Some(item.response.id.clone())
            }
            _ => None,
        };

        let payment_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(item.response.id),
            redirection_data: None,
            connector_metadata: None,
            mandate_reference: None,
            network_txn_id: None,
            connector_response_reference_id,
            incremental_authorization_allowed: None,
            status_code: 200,
        };

        let mut router_data = item.router_data;
        
        router_data.response = if let Some(error) = error_response {
            Err(error)
        } else {
            Ok(payment_response_data)
        };

        Ok(router_data)
    }
}

// Implementation for Sync Response
impl TryFrom<ResponseRouterData<RazorpayUcsPaymentsSyncResponse, domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::PSync, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsSyncData, domain_types::connector_types::PaymentsResponseData>>> for domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::PSync, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsSyncData, domain_types::connector_types::PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<RazorpayUcsPaymentsSyncResponse, domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::PSync, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsSyncData, domain_types::connector_types::PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let status = get_payment_status(&item.response.status)?;
        let _amount_received = Some(MinorUnit::new(item.response.amount / 100));
        
        let error_response = if status == AttemptStatus::Failure {
            Some(ErrorResponse {
                code: item.response.error_code.unwrap_or_else(|| "unknown_error".to_string()),
                message: item.response.error_description.unwrap_or_else(|| "Payment failed".to_string()),
                reason: item.response.error_reason,
                status_code: item.http_code,
                attempt_status: Some(status),
                connector_transaction_id: Some(item.response.id.clone()),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            })
        } else {
            None
        };

        let connector_response_reference_id = match status {
            AttemptStatus::Charged | AttemptStatus::AuthenticationSuccessful => {
                Some(item.response.id.clone())
            }
            _ => None,
        };

        let payment_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(item.response.id),
            redirection_data: None,
            connector_metadata: None,
            mandate_reference: None,
            network_txn_id: None,
            connector_response_reference_id,
            incremental_authorization_allowed: None,
            status_code: 200,
        };

        let mut router_data = item.router_data;
        
        router_data.response = if let Some(error) = error_response {
            Err(error)
        } else {
            Ok(payment_response_data)
        };

        Ok(router_data)
    }
}

fn get_payment_status(status: &str) -> CustomResult<AttemptStatus, errors::ConnectorError> {
    match status {
        "created" => Ok(AttemptStatus::AuthenticationPending),
        "authorized" => Ok(AttemptStatus::Authorized),
        "captured" => Ok(AttemptStatus::Charged),
        "refunded" => Ok(AttemptStatus::AutoRefunded),
        "failed" => Ok(AttemptStatus::Failure),
        "cancelled" => Ok(AttemptStatus::Voided),
        _ => Ok(AttemptStatus::Pending),
    }
}

// Helper functions based on Haskell implementation

pub fn get_upi_transaction_mode(payment_method_data: &PaymentMethodData<impl PaymentMethodDataTypes>) -> Option<String> {
    match payment_method_data {
        PaymentMethodData::Upi(UpiData::UpiCollect(_)) => Some("collect".to_string()),
        PaymentMethodData::Upi(UpiData::UpiIntent(_)) => Some("intent".to_string()),
        _ => None,
    }
}

pub fn validate_upi_vpa(vpa: &str) -> CustomResult<(), errors::ConnectorError> {
    if vpa.contains('@') && vpa.len() > 3 {
        Ok(())
    } else {
        Err(errors::ConnectorError::RequestEncodingFailed.into())
    }
}

// Additional helper functions from Haskell implementation
pub fn extract_payment_id(connector_transaction_id: &str) -> CustomResult<String, errors::ConnectorError> {
    if connector_transaction_id.starts_with("pay_") {
        Ok(connector_transaction_id.to_string())
    } else {
        Err(errors::ConnectorError::RequestEncodingFailed.into())
    }
}

pub fn construct_razorpay_order_id(order_reference: &str) -> String {
    if order_reference.starts_with("order_") {
        order_reference.to_string()
    } else {
        format!("order_{}", order_reference)
    }
}

// Status mapping based on Haskell implementation
pub fn map_razorpay_status_to_attempt_status(status: &str, error_code: Option<&str>) -> AttemptStatus {
    match (status, error_code) {
        ("created", None) => AttemptStatus::AuthenticationPending,
        ("authorized", None) => AttemptStatus::Authorized,
        ("captured", None) => AttemptStatus::Charged,
        ("refunded", None) => AttemptStatus::AutoRefunded,
        ("failed", Some(_)) => AttemptStatus::Failure,
        ("cancelled", None) => AttemptStatus::Voided,
        (_, Some("GATEWAY_ERROR")) => AttemptStatus::Failure,
        (_, Some("BAD_REQUEST_ERROR")) => AttemptStatus::Failure,
        (_, Some("AUTHENTICATION_ERROR")) => AttemptStatus::AuthenticationFailed,
        (_, Some("AUTHORIZATION_ERROR")) => AttemptStatus::AuthorizationFailed,
        (_, Some("SERVER_ERROR")) => AttemptStatus::Pending,
        _ => AttemptStatus::Pending,
    }
}

// Missing struct definitions for various payment flows

#[derive(Debug, Serialize)]
pub struct RazorpayUcsPaymentsSyncRequest {
    pub payment_id: String,
}



#[derive(Debug, Serialize)]
pub struct RazorpayUcsRefundSyncRequest {
    pub refund_id: String,
}

#[derive(Debug, Deserialize)]
pub struct RazorpayUcsRefundSyncResponse {
    pub id: String,
    pub entity: String,
    pub amount: i64,
    pub currency: Currency,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct RazorpayUcsVoidRequest {
    pub payment_id: String,
}

#[derive(Debug, Deserialize)]
pub struct RazorpayUcsVoidResponse {
    pub id: String,
    pub entity: String,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct RazorpayUcsCaptureRequest {
    pub amount: i64,
    pub currency: Currency,
}

#[derive(Debug, Deserialize)]
pub struct RazorpayUcsCaptureResponse {
    pub id: String,
    pub entity: String,
    pub amount: i64,
    pub currency: Currency,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct RazorpayUcsRefundRequest {
    pub amount: i64,
    pub currency: Currency,
}

#[derive(Debug, Deserialize)]
pub struct RazorpayUcsRefundResponse {
    pub id: String,
    pub entity: String,
    pub amount: i64,
    pub currency: Currency,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct RazorpayUcsCreateOrderRequest {
    pub amount: i64,
    pub currency: Currency,
    pub receipt: String,
}

#[derive(Debug, Deserialize)]
pub struct RazorpayUcsCreateOrderResponse {
    pub id: String,
    pub entity: String,
    pub amount: i64,
    pub currency: Currency,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct RazorpayUcsSetupMandateRequest {
    pub amount: i64,
    pub currency: Currency,
    pub method: String,
}

#[derive(Debug, Deserialize)]
pub struct RazorpayUcsSetupMandateResponse {
    pub id: String,
    pub entity: String,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct RazorpayUcsRepeatPaymentRequest {
    pub amount: i64,
    pub currency: Currency,
}

#[derive(Debug, Deserialize)]
pub struct RazorpayUcsRepeatPaymentResponse {
    pub id: String,
    pub entity: String,
    pub amount: i64,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct RazorpayUcsAcceptRequest {
    pub dispute_id: String,
}

#[derive(Debug, Deserialize)]
pub struct RazorpayUcsAcceptResponse {
    pub id: String,
    pub entity: String,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct RazorpayUcsDefendDisputeRequest {
    pub dispute_id: String,
    pub evidence: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct RazorpayUcsDefendDisputeResponse {
    pub id: String,
    pub entity: String,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct RazorpayUcsSubmitEvidenceRequest {
    pub dispute_id: String,
    pub evidence: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct RazorpayUcsSubmitEvidenceResponse {
    pub id: String,
    pub entity: String,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct RazorpayUcsCreateSessionTokenRequest {
    pub customer_id: String,
}

#[derive(Debug, Deserialize)]
pub struct RazorpayUcsCreateSessionTokenResponse {
    pub token: String,
    pub expires_at: i64,
}
