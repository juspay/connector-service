use crate::types::ResponseRouterData;
use common_enums::{AttemptStatus, RefundStatus};
use common_utils::types::MinorUnit;
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

// ===== HELPER FUNCTIONS =====

/// Determines the order type based on payment method
/// Most payments use redirect flow, but this can be customized per payment method
fn get_order_type_from_payment_method<T: PaymentMethodDataTypes>(
    _payment_method_data: &domain_types::payment_method_data::PaymentMethodData<T>,
) -> &'static str {
    // For now, MultiSafepay primarily uses redirect flow
    // This can be extended to return "direct" for specific payment methods if needed
    "redirect"
}

/// Maps payment method data to MultiSafepay gateway identifier
fn get_gateway_from_payment_method<T: PaymentMethodDataTypes>(
    payment_method_data: &domain_types::payment_method_data::PaymentMethodData<T>,
) -> Option<String> {
    use domain_types::payment_method_data::PaymentMethodData;

    match payment_method_data {
        PaymentMethodData::Card(card_data) => {
            // Map card network to gateway identifier
            card_data.card_network.as_ref().map(|network| {
                match network {
                    common_enums::CardNetwork::Visa => "VISA",
                    common_enums::CardNetwork::Mastercard => "MASTERCARD",
                    common_enums::CardNetwork::AmericanExpress => "AMEX",
                    common_enums::CardNetwork::Maestro => "MAESTRO",
                    common_enums::CardNetwork::DinersClub => "DINER",
                    common_enums::CardNetwork::Discover => "DISCOVER",
                    _ => "CREDITCARD", // Default for unrecognized card networks
                }
                .to_string()
            })
        }
        PaymentMethodData::BankRedirect(_) => Some("IDEAL".to_string()), // Example for iDEAL
        PaymentMethodData::Wallet(_) => Some("PAYPAL".to_string()),     // Example for PayPal
        // Add more payment methods as needed
        _ => None,
    }
}

// ===== STATUS ENUMS =====

/// MultiSafepay payment status enum
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MultisafepayPaymentStatus {
    Completed,
    #[default]
    Initialized,
    Uncleared,
    Declined,
    Cancelled,
    Void,
    Expired,
    Refunded,
    #[serde(rename = "partial_refunded")]
    PartialRefunded,
    Reserved,
    Shipped,
    Chargeback,
}

impl From<MultisafepayPaymentStatus> for AttemptStatus {
    fn from(status: MultisafepayPaymentStatus) -> Self {
        match status {
            MultisafepayPaymentStatus::Completed => Self::Charged,
            MultisafepayPaymentStatus::Initialized | MultisafepayPaymentStatus::Uncleared => {
                Self::Pending
            }
            MultisafepayPaymentStatus::Declined
            | MultisafepayPaymentStatus::Cancelled
            | MultisafepayPaymentStatus::Void
            | MultisafepayPaymentStatus::Expired => Self::Failure,
            MultisafepayPaymentStatus::Refunded | MultisafepayPaymentStatus::PartialRefunded => {
                Self::Charged
            }
            MultisafepayPaymentStatus::Reserved => Self::Authorized,
            MultisafepayPaymentStatus::Shipped => Self::Charged,
            MultisafepayPaymentStatus::Chargeback => Self::Charged,
        }
    }
}

/// MultiSafepay refund status enum
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MultisafepayRefundStatus {
    Completed,
    Refunded,
    #[default]
    Initialized,
    Uncleared,
    Declined,
    Cancelled,
    Void,
    Expired,
}

impl From<MultisafepayRefundStatus> for RefundStatus {
    fn from(status: MultisafepayRefundStatus) -> Self {
        match status {
            MultisafepayRefundStatus::Completed | MultisafepayRefundStatus::Refunded => {
                Self::Success
            }
            MultisafepayRefundStatus::Initialized | MultisafepayRefundStatus::Uncleared => {
                Self::Pending
            }
            MultisafepayRefundStatus::Declined
            | MultisafepayRefundStatus::Cancelled
            | MultisafepayRefundStatus::Void
            | MultisafepayRefundStatus::Expired => Self::Failure,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MultisafepayAuthType {
    pub api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for MultisafepayAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisafepayErrorResponse {
    pub success: bool,
    pub data: Option<MultisafepayErrorData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisafepayErrorData {
    pub error_code: Option<i32>,
    pub error_info: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MultisafepayPaymentsRequest {
    #[serde(rename = "type")]
    pub order_type: String,
    pub order_id: String,
    pub gateway: Option<String>,
    pub currency: String,
    pub amount: MinorUnit,
    pub description: String,
}

// Implementation for macro-generated wrapper type
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<
        crate::connectors::multisafepay::MultisafepayRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    > for MultisafepayPaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        wrapper: crate::connectors::multisafepay::MultisafepayRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let item = &wrapper.router_data;
        let order_type = get_order_type_from_payment_method(&item.request.payment_method_data);
        let gateway = get_gateway_from_payment_method(&item.request.payment_method_data);

        Ok(Self {
            order_type: order_type.to_string(),
            order_id: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            gateway,
            currency: item.request.currency.to_string(),
            amount: item.request.minor_amount,
            description: item
                .request
                .statement_descriptor
                .clone()
                .unwrap_or_else(|| "Payment".to_string()),
        })
    }
}

// Keep the original implementation for backwards compatibility
impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    > for MultisafepayPaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let order_type = get_order_type_from_payment_method(&item.request.payment_method_data);
        let gateway = get_gateway_from_payment_method(&item.request.payment_method_data);

        Ok(Self {
            order_type: order_type.to_string(),
            order_id: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            gateway,
            currency: item.request.currency.to_string(),
            amount: item.request.minor_amount,
            description: item
                .request
                .statement_descriptor
                .clone()
                .unwrap_or_else(|| "Payment".to_string()),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MultisafepayPaymentsResponse {
    pub success: bool,
    pub data: MultisafepayResponseData,
}

// Type aliases for different flows to avoid duplicate templating structs in macros
pub type MultisafepayPaymentsSyncResponse = MultisafepayPaymentsResponse;
pub type MultisafepayRefundSyncResponse = MultisafepayPaymentsResponse;

#[derive(Debug, Deserialize, Serialize)]
pub struct MultisafepayResponseData {
    pub order_id: String,
    pub payment_url: Option<String>,
    // transaction_id can be either a string or integer in different responses
    #[serde(deserialize_with = "deserialize_transaction_id", default)]
    pub transaction_id: Option<String>,
    #[serde(default)]
    pub status: MultisafepayPaymentStatus,
    pub amount: Option<MinorUnit>,
    pub currency: Option<String>,
    // Additional fields that may appear in GET response - using flatten to ignore unknown fields
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

// Custom deserializer to handle transaction_id as either string or integer
fn deserialize_transaction_id<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    let value: Option<serde_json::Value> = Option::deserialize(deserializer)?;
    Ok(value.and_then(|v| match v {
        serde_json::Value::String(s) => Some(s),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }))
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            MultisafepayPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            MultisafepayPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let response_data = &item.response.data;

        let status = response_data.status.clone().into();

        let redirection_data = response_data.payment_url.as_ref().map(|url| {
            Box::new(domain_types::router_response_types::RedirectForm::Uri { uri: url.clone() })
        });

        let transaction_id = response_data
            .transaction_id
            .clone()
            .unwrap_or_else(|| response_data.order_id.clone());

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(transaction_id),
                redirection_data,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(response_data.order_id.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// PSync Response Transformer - Reuses MultisafepayPaymentsResponse structure
impl
    TryFrom<
        ResponseRouterData<
            MultisafepayPaymentsResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            MultisafepayPaymentsResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response_data = &item.response.data;

        let status = response_data.status.clone().into();

        let transaction_id = response_data
            .transaction_id
            .clone()
            .unwrap_or_else(|| response_data.order_id.clone());

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(transaction_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(response_data.order_id.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// ===== CAPTURE FLOW STRUCTURES =====
// Capture flow not implemented - MultiSafepay doesn't support capture
// (requires manual capture support which MultiSafepay doesn't provide)

// ===== REFUND FLOW STRUCTURES =====

#[derive(Debug, Serialize)]
pub struct MultisafepayRefundRequest {
    pub currency: String,
    pub amount: MinorUnit,
}

// Implementation for macro-generated wrapper type
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<
        crate::connectors::multisafepay::MultisafepayRouterData<RouterDataV2<domain_types::connector_flow::Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for MultisafepayRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        wrapper: crate::connectors::multisafepay::MultisafepayRouterData<RouterDataV2<domain_types::connector_flow::Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let item = &wrapper.router_data;
        Ok(Self {
            currency: item.request.currency.to_string(),
            amount: item.request.minor_refund_amount,
        })
    }
}

// Keep the original implementation for backwards compatibility
impl<F> TryFrom<&RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>>
    for MultisafepayRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            currency: item.request.currency.to_string(),
            amount: item.request.minor_refund_amount,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MultisafepayRefundResponse {
    pub success: bool,
    pub data: MultisafepayRefundData,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MultisafepayRefundData {
    #[serde(deserialize_with = "deserialize_transaction_id", default)]
    pub transaction_id: Option<String>,
    #[serde(default)]
    pub status: MultisafepayRefundStatus,
    #[serde(deserialize_with = "deserialize_transaction_id", default)]
    pub refund_id: Option<String>,
}

impl<F>
    TryFrom<
        ResponseRouterData<
            MultisafepayRefundResponse,
            RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            MultisafepayRefundResponse,
            RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response_data = &item.response.data;

        let refund_status = response_data.status.clone().into();

        let connector_refund_id = response_data
            .refund_id
            .clone()
            .or_else(|| response_data.transaction_id.clone())
            .unwrap_or_else(|| "unknown".to_string());

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id,
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// Refund Sync Response - Uses MultisafepayPaymentsResponse (order response)
// MultiSafepay's refund sync endpoint returns the full order details, not a refund-specific response
impl
    TryFrom<
        ResponseRouterData<
            MultisafepayPaymentsResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            MultisafepayPaymentsResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response_data = &item.response.data;

        // Map payment status to refund status
        let refund_status = match response_data.status {
            MultisafepayPaymentStatus::Refunded | MultisafepayPaymentStatus::PartialRefunded => {
                RefundStatus::Success
            }
            MultisafepayPaymentStatus::Initialized | MultisafepayPaymentStatus::Uncleared => {
                RefundStatus::Pending
            }
            MultisafepayPaymentStatus::Declined
            | MultisafepayPaymentStatus::Cancelled
            | MultisafepayPaymentStatus::Void
            | MultisafepayPaymentStatus::Expired => RefundStatus::Failure,
            // For other payment statuses, treat as pending since refund may still be processing
            _ => RefundStatus::Pending,
        };

        let connector_refund_id = response_data
            .transaction_id
            .clone()
            .unwrap_or_else(|| response_data.order_id.clone());

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id,
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// ===== VOID FLOW STRUCTURES =====
// Void flow not implemented - MultiSafepay doesn't support void
// (requires manual capture support which MultiSafepay doesn't provide)
