use crate::{types::ResponseRouterData, utils};
use common_enums::AttemptStatus;
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData, PaymentVoidData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, ResponseId},
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct FinixAuthType {
    pub username: Secret<String>,
    pub password: Secret<String>,
}

impl FinixAuthType {
    pub fn generate_basic_auth(&self) -> String {
        let credentials = format!("{}:{}", self.username.peek(), self.password.peek());
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, credentials)
    }
}

impl TryFrom<&ConnectorAuthType> for FinixAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                api_secret,
                ..
            } => Ok(Self {
                username: api_key.to_owned(),
                password: api_secret.to_owned(),
            }),
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                username: api_key.to_owned(),
                password: key1.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinixConnectorMetadata {
    pub merchant_id: String,
    pub payment_instrument_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinixErrorResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<i32>,
    #[serde(rename = "_embedded", skip_serializing_if = "Option::is_none")]
    pub embedded: Option<FinixEmbeddedErrors>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinixEmbeddedErrors {
    pub errors: Vec<FinixError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinixError {
    pub logref: String,
    pub message: String,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

impl FinixErrorResponse {
    pub fn get_error_code(&self) -> String {
        self.embedded
            .as_ref()
            .and_then(|e| e.errors.first())
            .map(|err| err.code.clone())
            .unwrap_or_else(|| "UNKNOWN_ERROR".to_string())
    }

    pub fn get_error_message(&self) -> String {
        self.embedded
            .as_ref()
            .and_then(|e| e.errors.first())
            .map(|err| err.message.clone())
            .unwrap_or_else(|| "Unknown error occurred".to_string())
    }
}

#[derive(Debug, Serialize)]
pub struct FinixPaymentsRequest {
    pub amount: i64,
    pub currency: String,
    pub merchant: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_code: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_descriptor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<HashMap<String, String>>,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    > for FinixPaymentsRequest
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
        // Extract metadata containing merchant_id and payment_instrument_id
        let metadata: FinixConnectorMetadata = utils::to_connector_meta_from_secret(
            item.resource_common_data.connector_meta_data.clone(),
        )
        .change_context(errors::ConnectorError::InvalidConnectorConfig {
            config: "merchant_connector_account.metadata",
        })?;

        // Extract security code (CVV) from payment method data if available
        let security_code = match &item.request.payment_method_data {
            PaymentMethodData::Card(card_data) => Some(card_data.card_cvc.clone()),
            _ => None,
        };

        Ok(Self {
            amount: item.request.minor_amount.get_amount_as_i64(),
            currency: item.request.currency.to_string(),
            merchant: metadata.merchant_id,
            source: metadata.payment_instrument_id,
            idempotency_id: Some(
                item.resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
            security_code,
            statement_descriptor: item.request.statement_descriptor.clone(),
            tags: None,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FinixPaymentsResponse {
    pub id: String,
    pub state: String,
    pub amount: Option<i64>,
    pub currency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            FinixPaymentsResponse,
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
            FinixPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        // Map Finix state to UCS AttemptStatus
        // For authorize flow, SUCCEEDED means authorized but not yet captured
        let status = match item.response.state.to_uppercase().as_str() {
            "SUCCEEDED" => {
                // Check if this is an authorization-only or immediate capture
                if item.response.transfer.is_some() {
                    AttemptStatus::Charged // Immediate capture completed
                } else {
                    AttemptStatus::Authorized // Authorization only
                }
            },
            "PENDING" => AttemptStatus::Pending,
            "FAILED" => AttemptStatus::Failure,
            "CANCELED" => AttemptStatus::Voided,
            _ => AttemptStatus::Pending,
        };

        // Handle failure cases
        if let (Some(failure_code), Some(failure_message)) =
            (&item.response.failure_code, &item.response.failure_message)
        {
            return Ok(Self {
                response: Err(domain_types::router_data::ErrorResponse {
                    code: failure_code.clone(),
                    message: failure_message.clone(),
                    reason: Some(failure_message.clone()),
                    status_code: item.http_code,
                    attempt_status: Some(AttemptStatus::Failure),
                    connector_transaction_id: Some(item.response.id.clone()),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                resource_common_data: PaymentFlowData {
                    status: AttemptStatus::Failure,
                    ..item.router_data.resource_common_data
                },
                ..item.router_data
            });
        }

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.transfer.clone(),
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

// PSync Request Structure (GET request - no body needed)
#[derive(Debug, Serialize)]
pub struct FinixPaymentsSyncRequest;

impl TryFrom<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for FinixPaymentsSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // For GET requests, we don't need a request body
        Ok(Self)
    }
}

// PSync Response - Reuse FinixPaymentsResponse from Authorize
impl TryFrom<
        ResponseRouterData<
            FinixPaymentsResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FinixPaymentsResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Map Finix state to UCS AttemptStatus
        let status = match item.response.state.to_uppercase().as_str() {
            "SUCCEEDED" => AttemptStatus::Charged,
            "PENDING" => AttemptStatus::Pending,
            "FAILED" => AttemptStatus::Failure,
            "CANCELED" => AttemptStatus::Voided,
            _ => AttemptStatus::Pending,
        };

        // Handle failure cases
        if let (Some(failure_code), Some(failure_message)) =
            (&item.response.failure_code, &item.response.failure_message)
        {
            return Ok(Self {
                response: Err(domain_types::router_data::ErrorResponse {
                    code: failure_code.clone(),
                    message: failure_message.clone(),
                    reason: Some(failure_message.clone()),
                    status_code: item.http_code,
                    attempt_status: Some(AttemptStatus::Failure),
                    connector_transaction_id: Some(item.response.id.clone()),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                resource_common_data: PaymentFlowData {
                    status: AttemptStatus::Failure,
                    ..item.router_data.resource_common_data
                },
                ..item.router_data
            });
        }

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.transfer.clone(),
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

// Capture Request Structure
#[derive(Debug, Serialize)]
pub struct FinixCaptureRequest {
    pub capture_amount: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee: Option<i64>,
}

impl TryFrom<&RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>
    for FinixCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            capture_amount: item.request.minor_amount_to_capture.get_amount_as_i64(),
            fee: None, // Finix doesn't require fee in standard capture flow
        })
    }
}

// Capture Response - Reuse FinixPaymentsResponse from Authorize
impl TryFrom<
        ResponseRouterData<
            FinixPaymentsResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FinixPaymentsResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Map Finix state to UCS AttemptStatus
        let status = match item.response.state.to_uppercase().as_str() {
            "SUCCEEDED" => AttemptStatus::Charged,
            "PENDING" => AttemptStatus::Pending,
            "FAILED" => AttemptStatus::Failure,
            "CANCELED" => AttemptStatus::Voided,
            _ => AttemptStatus::Pending,
        };

        // Handle failure cases
        if let (Some(failure_code), Some(failure_message)) =
            (&item.response.failure_code, &item.response.failure_message)
        {
            return Ok(Self {
                response: Err(domain_types::router_data::ErrorResponse {
                    code: failure_code.clone(),
                    message: failure_message.clone(),
                    reason: Some(failure_message.clone()),
                    status_code: item.http_code,
                    attempt_status: Some(AttemptStatus::Failure),
                    connector_transaction_id: Some(item.response.id.clone()),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                resource_common_data: PaymentFlowData {
                    status: AttemptStatus::Failure,
                    ..item.router_data.resource_common_data
                },
                ..item.router_data
            });
        }

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.transfer.clone(),
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

// ===== REFUND FLOW STRUCTURES =====

// Refund Request Structure
#[derive(Debug, Serialize)]
pub struct FinixRefundRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<HashMap<String, String>>,
}

impl TryFrom<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>
    for FinixRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            idempotency_id: Some(item.request.refund_id.clone()),
            tags: None,
        })
    }
}

// Refund Response Structure
#[derive(Debug, Deserialize, Serialize)]
pub struct FinixRefundResponse {
    pub id: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub transfer_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_message: Option<String>,
}

impl TryFrom<
        ResponseRouterData<
            FinixRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FinixRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Map Finix state to RefundStatus
        let refund_status = match item.response.state.to_uppercase().as_str() {
            "SUCCEEDED" => common_enums::RefundStatus::Success,
            "PENDING" => common_enums::RefundStatus::Pending,
            "FAILED" | "CANCELED" => common_enums::RefundStatus::Failure,
            _ => common_enums::RefundStatus::Pending,
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.clone(),
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// Refund Sync Request Structure (GET request - no body needed)
#[derive(Debug, Serialize)]
pub struct FinixRefundSyncRequest;

impl TryFrom<&RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>
    for FinixRefundSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self)
    }
}

// Refund Sync Response - Reuse FinixRefundResponse
impl TryFrom<
        ResponseRouterData<
            FinixRefundResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FinixRefundResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Map Finix state to RefundStatus
        let refund_status = match item.response.state.to_uppercase().as_str() {
            "SUCCEEDED" => common_enums::RefundStatus::Success,
            "PENDING" => common_enums::RefundStatus::Pending,
            "FAILED" | "CANCELED" => common_enums::RefundStatus::Failure,
            _ => common_enums::RefundStatus::Pending,
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.clone(),
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// ===== VOID FLOW STRUCTURES =====

// Void Request Structure
#[derive(Debug, Serialize)]
pub struct FinixVoidRequest {
    pub void_me: bool,
}

impl TryFrom<&RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>
    for FinixVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            void_me: true, // Always true for void requests
        })
    }
}

// Void Response - Reuse FinixPaymentsResponse from Authorize
impl TryFrom<
        ResponseRouterData<
            FinixPaymentsResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FinixPaymentsResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        // Map Finix state to UCS AttemptStatus
        let status = match item.response.state.to_uppercase().as_str() {
            "CANCELED" => AttemptStatus::Voided,
            "PENDING" => AttemptStatus::Pending,
            "FAILED" => AttemptStatus::VoidFailed,
            _ => AttemptStatus::VoidFailed,
        };

        // Handle failure cases
        if let (Some(failure_code), Some(failure_message)) =
            (&item.response.failure_code, &item.response.failure_message)
        {
            return Ok(Self {
                response: Err(domain_types::router_data::ErrorResponse {
                    code: failure_code.clone(),
                    message: failure_message.clone(),
                    reason: Some(failure_message.clone()),
                    status_code: item.http_code,
                    attempt_status: Some(AttemptStatus::VoidFailed),
                    connector_transaction_id: Some(item.response.id.clone()),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                resource_common_data: PaymentFlowData {
                    status: AttemptStatus::VoidFailed,
                    ..item.router_data.resource_common_data
                },
                ..item.router_data
            });
        }

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.transfer.clone(),
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
