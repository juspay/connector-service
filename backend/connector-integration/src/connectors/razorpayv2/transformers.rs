//! RazorpayV2 transformers for converting between domain types and RazorpayV2 API types
//!
//! This module contains all the request and response structures for RazorpayV2's UPI APIs,
//! as well as the transformation logic to convert between our domain types and RazorpayV2's expected formats.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use common_enums::AttemptStatus;
use common_utils::types::MinorUnit;
use domain_types::{
    connector_flow::{Authorize, CreateOrder},
    connector_types::{
        PaymentCreateOrderData, PaymentCreateOrderResponse, PaymentFlowData, PaymentsAuthorizeData,
        PaymentsResponseData, ResponseId,
    },
};
use hyperswitch_domain_models::payment_method_data::{PaymentMethodData, UpiData};
use hyperswitch_domain_models::{router_data::ConnectorAuthType, router_data_v2::RouterDataV2};
use hyperswitch_interfaces::errors;
use masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

// ============ Authentication Types ============

#[derive(Debug)]
pub struct RazorpayV2AuthType {
    pub merchant_id: Secret<String>,
    pub api_key: Secret<String>,
    pub api_secret: Secret<String>,
}

impl RazorpayV2AuthType {
    pub fn generate_authorization_header(&self) -> String {
        let credentials = format!("{}:{}", self.api_key.peek(), self.api_secret.peek());
        let encoded = STANDARD.encode(credentials);
        tracing::info!(
            "Generated RazorpayV2 authorization header: {}",
            encoded
        );
        format!("Basic {}", encoded)
    }
}

impl TryFrom<&ConnectorAuthType> for RazorpayV2AuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self {
                merchant_id: key1.to_owned(), // merchant_id is stored in key1
                api_key: api_key.to_owned(),
                api_secret: api_secret.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// ============ Router Data Wrapper ============

#[derive(Debug)]
pub struct RazorpayV2RouterData<T> {
    pub amount: MinorUnit,
    pub order_id: Option<String>,
    pub router_data: T,
}

impl<T> TryFrom<(MinorUnit, T, Option<String>)> for RazorpayV2RouterData<T> {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from((amount, item, order_id): (MinorUnit, T,  Option<String>)) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            order_id,
            router_data: item,
        })
    }
}

// ============ Create Order Types ============

#[derive(Debug, Serialize)]
pub struct RazorpayV2CreateOrderRequest {
    pub amount: i64,
    pub currency: String,
    pub receipt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_capture: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<RazorpayV2Notes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfers: Option<Vec<RazorpayV2Transfer>>,
}

#[derive(Debug, Serialize)]
pub struct RazorpayV2Notes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txn_uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merchant_order_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RazorpayV2Transfer {
    pub account: String,
    pub amount: i64,
    pub currency: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linked_account_notes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_hold: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_hold_until: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RazorpayV2CreateOrderResponse {
    pub id: String,
    pub entity: String,
    pub amount: i64,
    pub amount_paid: i64,
    pub amount_due: i64,
    pub currency: String,
    pub receipt: String,
    pub status: String,
    pub attempts: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offer_id: Option<String>,
    pub created_at: i64,
}

// ============ Payment Authorization Types ============

#[derive(Debug, Serialize)]
pub struct RazorpayV2PaymentsRequest {
    pub amount: i64,
    pub currency: String,
    pub order_id: String,
    pub email: String,
    pub contact: String,
    pub method: String,
    pub description: Option<String>,
    pub notes: Option<RazorpayV2Notes>,
    pub callback_url: Option<String>,
    pub upi: Option<RazorpayV2UpiDetails>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub save: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recurring: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RazorpayV2UpiDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>, // "collect" | "intent"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vpa: Option<String>, // Only for collect flow
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry_time: Option<i32>, // In minutes (5 to 5760)
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub upi_type: Option<String>, // "recurring" for mandates
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_date: Option<i64>, // For recurring payments
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RazorpayV2PaymentsResponse {
    pub id: String,
    pub entity: String,
    pub amount: i64,
    pub currency: String,
    pub status: String,
    pub order_id: Option<String>,
    pub invoice_id: Option<String>,
    pub international: Option<bool>,
    pub method: String,
    pub amount_refunded: Option<i64>,
    pub refund_status: Option<String>,
    pub captured: Option<bool>,
    pub description: Option<String>,
    pub card_id: Option<String>,
    pub bank: Option<String>,
    pub wallet: Option<String>,
    pub vpa: Option<String>,
    pub email: String,
    pub contact: String,
    pub notes: Option<Value>,
    pub fee: Option<i64>,
    pub tax: Option<i64>,
    pub error_code: Option<String>,
    pub error_description: Option<String>,
    pub error_source: Option<String>,
    pub error_step: Option<String>,
    pub error_reason: Option<String>,
    pub acquirer_data: Option<Value>,
    pub created_at: i64,
    // UPI specific fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upi: Option<RazorpayV2UpiResponseDetails>,
    // Links for UPI flows
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RazorpayV2UpiResponseDetails {
    pub flow: Option<String>,
    pub vpa: Option<String>,
    pub expiry_time: Option<i32>,
}

// ============ Error Types ============

#[derive(Debug, Serialize, Deserialize)]
pub struct RazorpayV2ErrorResponse {
    pub error: RazorpayV2Error,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RazorpayV2Error {
    pub code: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

// ============ Utility Types ============

pub trait ForeignTryFrom<F>: Sized {
    type Error;
    fn foreign_try_from(from: F) -> Result<Self, Self::Error>;
}

// ============ Request Transformations ============

impl TryFrom<&RazorpayV2RouterData<&PaymentCreateOrderData>> for RazorpayV2CreateOrderRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &RazorpayV2RouterData<&PaymentCreateOrderData>) -> Result<Self, Self::Error> {
        let amount_in_minor_units = item.amount.get_amount_as_i64();

        Ok(Self {
            amount: amount_in_minor_units,
            currency: item.router_data.currency.to_string(),
            receipt: format!("order_{}", common_utils::generate_id(12, "ord")),
            payment_capture: Some(true), // Auto-capture for most UPI payments
            notes: Some(RazorpayV2Notes {
                txn_uuid: Some(common_utils::generate_id(16, "txn")),
                merchant_order_id: None,
            }),
            transfers: None, // No split settlements for basic implementation
        })
    }
}

impl TryFrom<&RazorpayV2RouterData<&PaymentsAuthorizeData>> for RazorpayV2PaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &RazorpayV2RouterData<&PaymentsAuthorizeData>) -> Result<Self, Self::Error> {
        let amount_in_minor_units = MinorUnit::new(item.router_data.amount).get_amount_as_i64();

        // Determine UPI flow based on payment method data
        let (upi_flow, vpa) = match &item.router_data.payment_method_data {
            PaymentMethodData::Upi(upi_data) => match upi_data {
                UpiData::UpiCollect(collect_data) => {
                    let vpa_string = collect_data
                        .vpa_id
                        .as_ref()
                        .map(|vpa| vpa.peek().to_string());
                    (Some("collect".to_string()), vpa_string)
                }
                UpiData::UpiIntent(_) => (Some("intent".to_string()), None),
                UpiData::UpiQr(_) => (Some("intent".to_string()), None), // QR uses intent flow
            },
            _ => (None, None),
        };

        // Build UPI details if this is a UPI payment
        let upi_details = if upi_flow.is_some() {
            Some(RazorpayV2UpiDetails {
                flow: upi_flow,
                vpa,
                expiry_time: Some(15), // 15 minutes default
                upi_type: None,
                end_date: None,
            })
        } else {
            None
        };

        let order_id = item.order_id.as_ref().ok_or(errors::ConnectorError::MissingRequiredField { field_name: "order_id" })?;

        Ok(Self {
            amount: amount_in_minor_units,
            currency: item.router_data.currency.to_string(),
            order_id: order_id.to_string(),
            email: "customer@example.com".to_string(), // Extract from customer data
            contact: "9999999999".to_string(),         // Extract from customer data
            method: "upi".to_string(),
            description: Some("Payment via RazorpayV2".to_string()),
            notes: Some(RazorpayV2Notes {
                txn_uuid: Some(common_utils::generate_id(16, "txn")),
                merchant_order_id: None,
            }),
            callback_url: None,
            upi: upi_details,
            customer_id: None,
            save: Some(false),
            recurring: None,
        })
    }
}

// ============ Response Transformations ============

impl
    ForeignTryFrom<(
        RazorpayV2CreateOrderResponse,
        RouterDataV2<
            CreateOrder,
            PaymentFlowData,
            PaymentCreateOrderData,
            PaymentCreateOrderResponse,
        >,
        u16,
        bool,
    )>
    for RouterDataV2<
        CreateOrder,
        PaymentFlowData,
        PaymentCreateOrderData,
        PaymentCreateOrderResponse,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn foreign_try_from(
        (response, item, _http_code, _is_retry): (
            RazorpayV2CreateOrderResponse,
            RouterDataV2<
                CreateOrder,
                PaymentFlowData,
                PaymentCreateOrderData,
                PaymentCreateOrderResponse,
            >,
            u16,
            bool,
        ),
    ) -> Result<Self, Self::Error> {
        let order_response = PaymentCreateOrderResponse {
            order_id: response.id,
        };

        Ok(Self {
            response: Ok(order_response),
            ..item
        })
    }
}

impl
    ForeignTryFrom<(
        RazorpayV2PaymentsResponse,
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        u16,
        bool,
    )> for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn foreign_try_from(
        (response, item, _http_code, _is_retry): (
            RazorpayV2PaymentsResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
            u16,
            bool,
        ),
    ) -> Result<Self, Self::Error> {
        use hyperswitch_domain_models::router_response_types::RedirectForm;

        let _status = match response.status.as_str() {
            "created" => AttemptStatus::AuthenticationPending,
            "authorized" => AttemptStatus::Authorized,
            "captured" => AttemptStatus::Charged,
            "failed" => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        // Handle UPI-specific redirection for intent/QR flows
        let redirection_data = if let Some(link) = response.link {
            if link.starts_with("upi://") {
                // UPI Intent deep link
                Some(RedirectForm::Uri { uri: link })
            } else {
                // Other redirect forms
                None
            }
        } else {
            None
        };

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.id),
            redirection_data: Box::new(redirection_data),
            mandate_reference: Box::new(None),
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: response.order_id,
            incremental_authorization_allowed: None,
            raw_connector_response: None,
            transaction_token: None,
            transaction_amount: Some(response.amount.to_string()),
            merchant_name: None,
            merchant_vpa: response.vpa,
        };

        Ok(Self {
            response: Ok(payments_response_data),
            ..item
        })
    }
}

// ============ Utility Functions ============

/// Determine UPI flow based on payment method type
pub fn get_upi_flow(payment_method_data: &PaymentMethodData) -> Option<String> {
    match payment_method_data {
        PaymentMethodData::Upi(upi_data) => match upi_data {
            UpiData::UpiCollect(_) => Some("collect".to_string()),
            UpiData::UpiIntent(_) => Some("intent".to_string()),
            UpiData::UpiQr(_) => Some("intent".to_string()), // QR uses intent flow
        },
        _ => None,
    }
}

/// Check if VPA should be included in the request (only for collect flow)
pub fn should_include_vpa(payment_method_data: &PaymentMethodData) -> bool {
    matches!(
        payment_method_data,
        PaymentMethodData::Upi(UpiData::UpiCollect(_))
    )
}

/// Calculate expiry time in minutes (5 to 5760 minutes as per Razorpay docs)
pub fn calculate_expiry_time() -> i32 {
    15 // Default to 15 minutes
}
