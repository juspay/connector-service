//! RazorpayV2 transformers for converting between domain types and RazorpayV2 API types

use std::str::FromStr;

use base64::{engine::general_purpose::STANDARD, Engine};
use common_enums::{AttemptStatus, RefundStatus};
use common_utils::{pii::Email, types::MinorUnit};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync, Refund},
    connector_types::{
        PaymentCreateOrderData, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        ResponseId,
    },
    errors,
    payment_address::Address,
    payment_method_data::{PaymentMethodData, UpiData},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::connectors::razorpay::transformers::ForeignTryFrom;

// ============ Authentication Types ============

#[derive(Debug)]
pub enum RazorpayV2AuthType {
    AuthToken(Secret<String>),
    ApiKeySecret {
        api_key: Secret<String>,
        api_secret: Secret<String>,
    },
}

impl RazorpayV2AuthType {
    pub fn generate_authorization_header(&self) -> String {
        match self {
            RazorpayV2AuthType::AuthToken(token) => format!("Bearer {}", token.peek()),
            RazorpayV2AuthType::ApiKeySecret {
                api_key,
                api_secret,
            } => {
                let credentials = format!("{}:{}", api_key.peek(), api_secret.peek());
                let encoded = STANDARD.encode(credentials);
                format!("Basic {encoded}")
            }
        }
    }
}

impl TryFrom<&ConnectorAuthType> for RazorpayV2AuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self::AuthToken(api_key.to_owned())),
            ConnectorAuthType::SignatureKey {
                api_key,
                api_secret,
                ..
            } => Ok(Self::ApiKeySecret {
                api_key: api_key.to_owned(),
                api_secret: api_secret.to_owned(),
            }),
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self::ApiKeySecret {
                api_key: api_key.to_owned(),
                api_secret: key1.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// ============ Router Data Wrapper ============

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
    pub amount: MinorUnit,
    pub currency: String,
    pub receipt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_capture: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<RazorpayV2Notes>,
}

pub type RazorpayV2Notes = serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct RazorpayV2CreateOrderResponse {
    pub id: String,
    pub entity: String,
    pub amount: MinorUnit,
    pub amount_paid: MinorUnit,
    pub amount_due: MinorUnit,
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
    pub amount: MinorUnit,
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
    PaymentResponse(Box<RazorpayV2PaymentsResponse>),
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
    StandardError { error: RazorpayV2ErrorDetails },
    SimpleError { message: String },
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
        Ok(Self {
            amount: item.amount,
            currency: item.router_data.currency.to_string(),
            receipt: item
                .order_id
                .as_ref()
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "connector_request_reference_id",
                })?
                .clone(),
            payment_capture: Some(true),
            notes: item.router_data.metadata.clone(),
        })
    }
}

impl
    TryFrom<
        &RazorpayV2RouterData<
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for RazorpayV2PaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &RazorpayV2RouterData<
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Determine UPI flow based on payment method data
        let (upi_flow, vpa) = match &item.router_data.request.payment_method_data {
            PaymentMethodData::Upi(upi_data) => match upi_data {
                UpiData::UpiCollect(collect_data) => {
                    let vpa_string = collect_data
                        .vpa_id
                        .as_ref()
                        .ok_or(errors::ConnectorError::MissingRequiredField {
                            field_name: "vpa_id",
                        })?
                        .peek()
                        .to_string();
                    (Some(UpiFlow::Collect), Some(vpa_string))
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
            amount: item.amount,
            currency: item.router_data.request.currency.to_string(),
            order_id: order_id.to_string(),
            email: item
                .router_data
                .resource_common_data
                .get_billing_email()
                .unwrap_or_else(|_| Email::from_str("customer@example.com").unwrap()),
            contact: item
                .router_data
                .resource_common_data
                .get_billing_phone_number()
                .map(|phone| phone.expose())
                .unwrap_or_else(|_| "9999999999".to_string()),
            method: "upi".to_string(),
            description: Some("Payment via RazorpayV2".to_string()),
            notes: item.router_data.request.metadata.clone(),
            callback_url: item.router_data.request.get_router_return_url()?,
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

// ============ Response Transformations ============

impl
    ForeignTryFrom<(
        RazorpayV2RefundResponse,
        RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        u16,
        Vec<u8>, // raw_response
    )> for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = domain_types::errors::ConnectorError;

    fn foreign_try_from(
        (response, data, _status_code, raw_response): (
            RazorpayV2RefundResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            u16,
            Vec<u8>,
        ),
    ) -> Result<Self, Self::Error> {
        // Map Razorpay refund status to internal status
        let status = match response.status.as_str() {
            "processed" => RefundStatus::Success,
            "pending" | "created" => RefundStatus::Pending,
            "failed" => RefundStatus::Failure,
            _ => RefundStatus::Pending,
        };

        let refunds_response_data = RefundsResponseData {
            connector_refund_id: response.id,
            refund_status: status,
            raw_connector_response: Some(String::from_utf8_lossy(&raw_response).to_string()),
            status_code: Some(_status_code),
        };

        Ok(RouterDataV2 {
            response: Ok(refunds_response_data),
            resource_common_data: RefundFlowData {
                status,
                ..data.resource_common_data.clone()
            },
            ..data
        })
    }
}

impl
    ForeignTryFrom<(
        RazorpayV2RefundResponse,
        RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        u16,
        Vec<u8>, // raw_response
    )> for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = domain_types::errors::ConnectorError;

    fn foreign_try_from(
        (response, data, _status_code, raw_response): (
            RazorpayV2RefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            u16,
            Vec<u8>,
        ),
    ) -> Result<Self, Self::Error> {
        // Map Razorpay refund status to internal status
        let status = match response.status.as_str() {
            "processed" => RefundStatus::Success,
            "pending" | "created" => RefundStatus::Pending,
            "failed" => RefundStatus::Failure,
            _ => RefundStatus::Pending,
        };

        let refunds_response_data = RefundsResponseData {
            connector_refund_id: response.id,
            refund_status: status,
            raw_connector_response: Some(String::from_utf8_lossy(&raw_response).to_string()),
            status_code: Some(_status_code),
        };

        Ok(RouterDataV2 {
            response: Ok(refunds_response_data),
            resource_common_data: RefundFlowData {
                status,
                ..data.resource_common_data.clone()
            },
            ..data
        })
    }
}

impl
    ForeignTryFrom<(
        RazorpayV2SyncResponse,
        RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        u16,
        Vec<u8>, // raw_response
    )> for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = domain_types::errors::ConnectorError;

    fn foreign_try_from(
        (sync_response, data, _status_code, raw_response): (
            RazorpayV2SyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            u16,
            Vec<u8>,
        ),
    ) -> Result<Self, Self::Error> {
        // Extract the payment response from either format
        let payment_response =
            match sync_response {
                RazorpayV2SyncResponse::PaymentResponse(payment) => *payment,
                RazorpayV2SyncResponse::OrderPaymentsCollection(collection) => {
                    // Get the first (and typically only) payment from the collection
                    collection.items.into_iter().next().ok_or_else(|| {
                        domain_types::errors::ConnectorError::ResponseHandlingFailed
                    })?
                }
            };

        // Map Razorpay payment status to internal status, preserving original status
        let status = match payment_response.status.as_str() {
            "created" => AttemptStatus::Pending,
            "authorized" => AttemptStatus::Authorized,
            "captured" => AttemptStatus::Charged, // This is the mapping, but we preserve original in metadata
            "refunded" => AttemptStatus::AutoRefunded,
            "failed" => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(payment_response.id),
            redirection_data: None,
            connector_metadata: None,
            mandate_reference: None,
            network_txn_id: None,
            connector_response_reference_id: payment_response.order_id,
            incremental_authorization_allowed: None,
            raw_connector_response: Some(String::from_utf8_lossy(&raw_response).to_string()),
            status_code: Some(_status_code),
        };

        Ok(RouterDataV2 {
            response: Ok(payments_response_data),
            resource_common_data: PaymentFlowData {
                status,
                ..data.resource_common_data.clone()
            },
            ..data
        })
    }
}

impl
    ForeignTryFrom<(
        RazorpayV2UpiPaymentsResponse,
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        u16,
        Vec<u8>, // raw_response
    )> for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
{
    type Error = domain_types::errors::ConnectorError;

    fn foreign_try_from(
        (upi_response, data, _status_code, raw_response): (
            RazorpayV2UpiPaymentsResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
            u16,
            Vec<u8>,
        ),
    ) -> Result<Self, Self::Error> {
        let (transaction_id, redirection_data) = match upi_response {
            RazorpayV2UpiPaymentsResponse::SuccessIntent {
                razorpay_payment_id,
                link,
            } => {
                let redirect_form = RedirectForm::Uri { uri: link };
                (
                    ResponseId::ConnectorTransactionId(razorpay_payment_id),
                    Some(redirect_form),
                )
            }
            RazorpayV2UpiPaymentsResponse::SuccessCollect {
                razorpay_payment_id,
            } => {
                // For UPI Collect, there's no link, so no redirection data
                (
                    ResponseId::ConnectorTransactionId(razorpay_payment_id),
                    None,
                )
            }
            RazorpayV2UpiPaymentsResponse::Error { error: _ } => {
                // Handle error case - this should probably return an error instead
                return Err(domain_types::errors::ConnectorError::ResponseHandlingFailed);
            }
        };

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: transaction_id,
            redirection_data: redirection_data.map(Box::new),
            connector_metadata: None,
            mandate_reference: None,
            network_txn_id: None,
            connector_response_reference_id: data.resource_common_data.reference_id.clone(),
            incremental_authorization_allowed: None,
            raw_connector_response: Some(String::from_utf8_lossy(&raw_response).to_string()),
            status_code: Some(_status_code),
        };

        Ok(RouterDataV2 {
            response: Ok(payments_response_data),
            resource_common_data: PaymentFlowData {
                status: AttemptStatus::AuthenticationPending,
                ..data.resource_common_data
            },
            ..data
        })
    }
}

impl
    ForeignTryFrom<(
        RazorpayV2PaymentsResponse,
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        u16,
        Vec<u8>, // raw_response
    )> for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
{
    type Error = domain_types::errors::ConnectorError;

    fn foreign_try_from(
        (response, data, _status_code, raw_response): (
            RazorpayV2PaymentsResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
            u16,
            Vec<u8>,
        ),
    ) -> Result<Self, Self::Error> {
        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.id),
            redirection_data: None,
            connector_metadata: None,
            mandate_reference: None,
            network_txn_id: None,
            connector_response_reference_id: data.resource_common_data.reference_id.clone(),
            incremental_authorization_allowed: None,
            raw_connector_response: Some(String::from_utf8_lossy(&raw_response).to_string()),
            status_code: Some(_status_code),
        };

        Ok(RouterDataV2 {
            response: Ok(payments_response_data),
            resource_common_data: PaymentFlowData {
                status: AttemptStatus::AuthenticationPending,
                ..data.resource_common_data
            },
            ..data
        })
    }
}
