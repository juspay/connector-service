//! RazorpayV2 transformers for converting between domain types and RazorpayV2 API types

use std::str::FromStr;

use base64::{engine::general_purpose::STANDARD, Engine};
use common_utils::{pii::Email, types::MinorUnit};
use domain_types::{
    connector_types::{PaymentCreateOrderData, PaymentsAuthorizeData, RefundsData},
    errors,
    payment_address::Address,
    payment_method_data::{PaymentMethodData, UpiData},
    router_data::ConnectorAuthType,
};
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
                merchant_id: key1.to_owned(),
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
    pub billing_address: Option<Address>,
}

impl<T> TryFrom<(MinorUnit, T, Option<String>, Option<Address>)> for RazorpayV2RouterData<T> {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        (amount, item, order_id, billing_address): (MinorUnit, T, Option<String>, Option<Address>),
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            order_id,
            router_data: item,
            billing_address,
        })
    }
}

// Keep backward compatibility for existing usage
impl<T> TryFrom<(MinorUnit, T, Option<String>)> for RazorpayV2RouterData<T> {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        (amount, item, order_id): (MinorUnit, T, Option<String>),
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            order_id,
            router_data: item,
            billing_address: None,
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
}

#[derive(Debug, Serialize)]
pub struct RazorpayV2Notes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txn_uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merchant_order_id: Option<String>,
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
    pub email: Email,
    pub contact: String,
    pub method: String,
    pub description: Option<String>,
    pub notes: Option<RazorpayV2Notes>,
    pub callback_url: String,
    pub upi: Option<RazorpayV2UpiDetails>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub save: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recurring: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UpiFlow {
    Collect,
    Intent,
}

#[derive(Debug, Serialize)]
pub struct RazorpayV2UpiDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<UpiFlow>,
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
    pub email: Email,
    pub contact: String,
    pub notes: Option<Value>,
    pub fee: Option<i64>,
    pub tax: Option<i64>,
    pub error_code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RazorpayV2OrderPaymentsCollectionResponse {
    pub entity: String,
    pub count: i32,
    pub items: Vec<RazorpayV2PaymentsResponse>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RazorpayV2SyncResponse {
    PaymentResponse(RazorpayV2PaymentsResponse),
    OrderPaymentsCollection(RazorpayV2OrderPaymentsCollectionResponse),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RazorpayV2UpiPaymentsResponse {
    SuccessIntent {
        razorpay_payment_id: String,
        link: String,
    },
    SuccessCollect {
        razorpay_payment_id: String,
    },
    Error {
        error: RazorpayV2ErrorResponse,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RazorpayV2ErrorResponse {
    StandardError {
        error: RazorpayV2ErrorDetails,
    },
    SimpleError {
        message: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RazorpayV2ErrorDetails {
    pub code: String,
    pub description: String,
    pub source: Option<String>,
    pub step: Option<String>,
    pub reason: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub field: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RazorpayV2UpiResponseDetails {
    pub flow: Option<String>,
    pub vpa: Option<String>,
    pub expiry_time: Option<i32>,
}

// ============ Error Types ============
// Error response structure is already defined above in the enum

// ============ Request Transformations ============

impl TryFrom<&RazorpayV2RouterData<&PaymentCreateOrderData>> for RazorpayV2CreateOrderRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &RazorpayV2RouterData<&PaymentCreateOrderData>) -> Result<Self, Self::Error> {
        let amount_in_minor_units = item.amount.get_amount_as_i64();
        Ok(Self {
            amount: amount_in_minor_units,
            currency: item.router_data.currency.to_string(),
            receipt: format!(
                "order_{}",
                uuid::Uuid::new_v4().to_string().replace('-', "")[..12].to_string()
            ),
            payment_capture: None,
            notes: Some(RazorpayV2Notes {
                txn_uuid: Some(uuid::Uuid::new_v4().to_string().replace('-', "")[..16].to_string()),
                merchant_order_id: None,
            }),
        })
    }
}

impl TryFrom<&RazorpayV2RouterData<&PaymentsAuthorizeData>> for RazorpayV2PaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &RazorpayV2RouterData<&PaymentsAuthorizeData>) -> Result<Self, Self::Error> {
        let amount_in_minor_units = item.amount.get_amount_as_i64();

        // Determine UPI flow based on payment method data
        let (upi_flow, vpa) = match &item.router_data.payment_method_data {
            PaymentMethodData::Upi(upi_data) => match upi_data {
                UpiData::UpiCollect(collect_data) => {
                    let vpa_string = collect_data
                        .vpa_id
                        .as_ref()
                        .map(|vpa| vpa.peek().to_string());
                    (Some(UpiFlow::Collect), vpa_string)
                }
                UpiData::UpiIntent(_) => (Some(UpiFlow::Intent), None),
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

        let order_id =
            item.order_id
                .as_ref()
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "order_id",
                })?;

        Ok(Self {
            amount: amount_in_minor_units,
            currency: item.router_data.currency.to_string(),
            order_id: order_id.to_string(),
            email: item
                .router_data
                .email
                .clone()
                .unwrap_or_else(|| Email::from_str("customer@example.com").unwrap()),
            contact: item
                .billing_address
                .as_ref()
                .and_then(|addr| addr.phone.as_ref())
                .and_then(|phone| phone.number.as_ref())
                .map(|num| num.peek().to_string())
                .unwrap_or_else(|| "9999999999".to_string()),
            method: "upi".to_string(),
            description: Some("Payment via RazorpayV2".to_string()),
            notes: Some(RazorpayV2Notes {
                txn_uuid: Some(uuid::Uuid::new_v4().to_string().replace('-', "")[..16].to_string()),
                merchant_order_id: None,
            }),
            callback_url: item
                .router_data
                .router_return_url
                .as_ref()
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "callback_url",
                })?
                .to_string(),
            upi: upi_details,
            customer_id: None,
            save: Some(false),
            recurring: None,
        })
    }
}

// ============ Refund Types ============

#[derive(Debug, Serialize)]
pub struct RazorpayV2RefundRequest {
    pub amount: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RazorpayV2RefundResponse {
    pub id: String,
    pub entity: String,
    pub amount: i64,
    pub currency: String,
    pub payment_id: String,
    pub status: String,
    pub speed_requested: Option<String>,
    pub speed_processed: Option<String>,
    pub receipt: Option<String>,
    pub created_at: i64,
}

impl TryFrom<&RazorpayV2RouterData<&RefundsData>> for RazorpayV2RefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &RazorpayV2RouterData<&RefundsData>) -> Result<Self, Self::Error> {
        let amount_in_minor_units = item.amount.get_amount_as_i64();
        Ok(Self {
            amount: amount_in_minor_units,
        })
    }
}
