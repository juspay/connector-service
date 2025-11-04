use crate::types::ResponseRouterData;
use common_enums::{AttemptStatus, RefundStatus};
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

// ===== HELPER FUNCTIONS FOR STATUS MAPPING =====

/// Maps MultiSafepay payment statuses to UCS AttemptStatus
///
/// MultiSafepay Status Reference:
/// - "completed": Payment successfully completed
/// - "initialized": Payment initiated but not yet completed
/// - "reserved": Payment authorized but not captured
/// - "declined": Payment declined by bank/processor
/// - "cancelled": Payment cancelled by merchant or customer
/// - "void": Payment voided
/// - "expired": Payment session expired
/// - "refunded"/"partial_refunded": Payment has been refunded
/// - "shipped": Payment completed and order shipped
/// - "chargeback": Payment subject to chargeback
fn map_payment_status_to_attempt_status(status: &str) -> AttemptStatus {
    match status {
        "completed" => AttemptStatus::Charged,
        "initialized" | "uncleared" => AttemptStatus::Pending,
        "declined" | "cancelled" | "void" | "expired" => AttemptStatus::Failure,
        "refunded" | "partial_refunded" => AttemptStatus::Charged,
        "reserved" => AttemptStatus::Authorized,
        "shipped" => AttemptStatus::Charged,
        "chargeback" => AttemptStatus::Charged,
        _ => AttemptStatus::Pending,
    }
}

/// Maps MultiSafepay refund statuses to UCS RefundStatus
fn map_refund_status(status: &str) -> RefundStatus {
    match status {
        "completed" | "refunded" => RefundStatus::Success,
        "initialized" | "uncleared" => RefundStatus::Pending,
        "declined" | "cancelled" | "void" | "expired" => RefundStatus::Failure,
        _ => RefundStatus::Pending,
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
    pub amount: i64,
    pub description: String,
}

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
        Ok(Self {
            order_type: "redirect".to_string(),
            order_id: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            gateway: None,
            currency: item.request.currency.to_string(),
            amount: item.request.minor_amount.get_amount_as_i64(),
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

#[derive(Debug, Deserialize, Serialize)]
pub struct MultisafepayResponseData {
    pub order_id: String,
    pub payment_url: Option<String>,
    // transaction_id can be either a string or integer in different responses
    #[serde(deserialize_with = "deserialize_transaction_id", default)]
    pub transaction_id: Option<String>,
    #[serde(default)]
    pub status: String,
    pub amount: Option<i64>,
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

        let status = map_payment_status_to_attempt_status(&response_data.status);

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

        let status = map_payment_status_to_attempt_status(&response_data.status);

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
    pub amount: i64,
}

impl<F> TryFrom<&RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>>
    for MultisafepayRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            currency: item.request.currency.to_string(),
            amount: item.request.minor_refund_amount.get_amount_as_i64(),
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
    pub status: String,
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

        let refund_status = map_refund_status(&response_data.status);

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

// Refund Sync Response - Reuses MultisafepayRefundResponse structure
impl
    TryFrom<
        ResponseRouterData<
            MultisafepayRefundResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            MultisafepayRefundResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response_data = &item.response.data;

        let refund_status = map_refund_status(&response_data.status);

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

// ===== VOID FLOW STRUCTURES =====
// Void flow not implemented - MultiSafepay doesn't support void
// (requires manual capture support which MultiSafepay doesn't provide)
