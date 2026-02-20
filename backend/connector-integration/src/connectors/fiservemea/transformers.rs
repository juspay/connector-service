use crate::types::ResponseRouterData;
use common_enums::AttemptStatus;
use common_utils::types::StringMajorUnit;
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors::{self, ConnectorError},
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

// =============================================================================
// AUTHENTICATION TYPE
// =============================================================================
#[derive(Debug, Clone)]
pub struct FiservemeaAuthType {
    pub api_key: Secret<String>,
    pub api_secret: Secret<String>,
}

impl FiservemeaAuthType {
    /// Generate HMAC-SHA256 signature for Message-Signature header
    /// Signature = HMAC-SHA256(API-Key + Client-Request-Id + Timestamp + requestBody, api_secret)
    pub fn generate_signature(
        &self,
        client_request_id: &str,
        timestamp: &str,
        request_body: &str,
    ) -> String {
        let signature_payload = format!(
            "{}{}{}{}",
            self.api_key.peek(),
            client_request_id,
            timestamp,
            request_body
        );

        use ring::hmac;

        let key = hmac::Key::new(hmac::HMAC_SHA256, self.api_secret.peek().as_bytes());
        let tag = hmac::sign(&key, signature_payload.as_bytes());

        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, tag.as_ref())
    }
}

impl TryFrom<&ConnectorAuthType> for FiservemeaAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                api_secret,
                ..
            } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: api_secret.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

// =============================================================================
// ERROR RESPONSE
// =============================================================================
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FiservemeaErrorResponse {
    pub client_request_id: Option<String>,
    pub api_trace_id: Option<String>,
    pub response_type: Option<String>,
    #[serde(rename = "type")]
    pub error_type: Option<String>,
    pub error: Option<FiservemeaErrorDetail>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FiservemeaErrorDetail {
    pub code: String,
    pub message: String,
    pub details: Option<Vec<FiservemeaErrorFieldDetail>>,
    pub decline_reason_code: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FiservemeaErrorFieldDetail {
    pub field: String,
    pub message: String,
}

impl Default for FiservemeaErrorResponse {
    fn default() -> Self {
        Self {
            client_request_id: None,
            api_trace_id: None,
            response_type: Some("ServerError".to_string()),
            error_type: None,
            error: Some(FiservemeaErrorDetail {
                code: "UNKNOWN_ERROR".to_string(),
                message: "Unknown error occurred".to_string(),
                details: None,
                decline_reason_code: None,
            }),
        }
    }
}

// =============================================================================
// TRANSACTION TYPES
// =============================================================================
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FiservemeaTransactionType {
    PaymentCardSaleTransaction,
    PaymentCardPreAuthTransaction,
    PostAuthTransaction,
    ReturnTransaction,
    VoidTransaction,
}

// =============================================================================
// PAYMENT STATUS
// =============================================================================
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum FiservemeaTransactionResult {
    Approved,
    Declined,
    Failed,
    Waiting,
    Partial,
    Fraud,
}

impl From<FiservemeaTransactionResult> for AttemptStatus {
    fn from(result: FiservemeaTransactionResult) -> Self {
        match result {
            FiservemeaTransactionResult::Approved => Self::Charged,
            FiservemeaTransactionResult::Declined | FiservemeaTransactionResult::Failed => {
                Self::Failure
            }
            FiservemeaTransactionResult::Waiting => Self::Pending,
            FiservemeaTransactionResult::Partial => Self::PartialCharged,
            FiservemeaTransactionResult::Fraud => Self::Failure,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum FiservemeaTransactionState {
    Authorized,
    Captured,
    Declined,
    Checked,
    CompletedGet,
    Initialized,
    Pending,
    Ready,
    Template,
    Settled,
    Voided,
    Waiting,
}

impl From<FiservemeaTransactionState> for AttemptStatus {
    fn from(state: FiservemeaTransactionState) -> Self {
        match state {
            FiservemeaTransactionState::Authorized => Self::Authorized,
            FiservemeaTransactionState::Captured | FiservemeaTransactionState::Settled => {
                Self::Charged
            }
            FiservemeaTransactionState::Declined => Self::Failure,
            FiservemeaTransactionState::Voided => Self::Voided,
            FiservemeaTransactionState::Pending
            | FiservemeaTransactionState::Waiting
            | FiservemeaTransactionState::Initialized => Self::Pending,
            _ => Self::Pending,
        }
    }
}

// =============================================================================
// AUTHORIZE FLOW
// =============================================================================
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeRequest<T: PaymentMethodDataTypes> {
    pub request_type: FiservemeaTransactionType,
    pub transaction_amount: TransactionAmount,
    pub payment_method: PaymentMethod<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<Order>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionAmount {
    pub total: StringMajorUnit,
    pub currency: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentMethod<T: PaymentMethodDataTypes> {
    pub payment_card: PaymentCard<T>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentCard<T: PaymentMethodDataTypes> {
    pub number: RawCardNumber<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_code: Option<Secret<String>>,
    pub expiry_date: ExpiryDate,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpiryDate {
    pub month: Secret<String>,
    pub year: Secret<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_id: Option<String>,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        FiservemeaRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for FiservemeaAuthorizeRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: FiservemeaRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Determine transaction type based on capture method
        let request_type = if router_data.request.is_auto_capture() {
            FiservemeaTransactionType::PaymentCardSaleTransaction
        } else {
            FiservemeaTransactionType::PaymentCardPreAuthTransaction
        };

        // Extract card data
        let payment_method = match &router_data.request.payment_method_data {
            PaymentMethodData::Card(card_data) => PaymentMethod {
                payment_card: PaymentCard {
                    number: card_data.card_number.clone(),
                    security_code: Some(card_data.card_cvc.clone()),
                    expiry_date: ExpiryDate {
                        month: card_data.card_exp_month.clone(),
                        year: card_data.card_exp_year.clone(),
                    },
                },
            },
            _ => {
                return Err(error_stack::report!(
                    errors::ConnectorError::NotImplemented(
                        "Only card payments are supported".to_string()
                    )
                ))
            }
        };

        let order = Some(Order {
            order_id: Some(
                router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
        });

        Ok(Self {
            request_type,
            transaction_amount: TransactionAmount {
                total: item.amount,
                currency: router_data.request.currency.to_string(),
            },
            payment_method,
            order,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeResponse {
    pub client_request_id: Option<String>,
    pub api_trace_id: Option<String>,
    pub ipg_transaction_id: Option<String>,
    pub order_id: Option<String>,
    pub transaction_type: Option<String>,
    pub transaction_result: Option<FiservemeaTransactionResult>,
    pub transaction_state: Option<FiservemeaTransactionState>,
    pub approved_amount: Option<ApprovedAmount>,
    pub error: Option<FiservemeaErrorDetail>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovedAmount {
    pub total: Option<f64>,
    pub currency: Option<String>,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        ResponseRouterData<
            FiservemeaAuthorizeResponse,
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
            FiservemeaAuthorizeResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Handle error response
        if let Some(error) = &response.error {
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: AttemptStatus::Failure,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(domain_types::router_data::ErrorResponse {
                    status_code: item.http_code,
                    code: error.code.clone(),
                    message: error.message.clone(),
                    reason: error.decline_reason_code.clone(),
                    attempt_status: Some(AttemptStatus::Failure),
                    connector_transaction_id: response.ipg_transaction_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..router_data.clone()
            });
        }

        // Map status from transaction result or state
        let status = response
            .transaction_result
            .clone()
            .map(AttemptStatus::from)
            .or_else(|| response.transaction_state.clone().map(AttemptStatus::from))
            .unwrap_or(AttemptStatus::Pending);

        let connector_transaction_id = response.ipg_transaction_id.clone().unwrap_or_default();

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: response.order_id.clone(),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// =============================================================================
// PSYNC FLOW
// =============================================================================
#[derive(Debug, Clone, Serialize)]
pub struct FiservemeaSyncRequest;

impl
    TryFrom<
        FiservemeaRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            (), // No payment method data needed for sync
        >,
    > for FiservemeaSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: FiservemeaRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            (),
        >,
    ) -> Result<Self, Self::Error> {
        // GET request has no body
        Ok(Self)
    }
}

pub type FiservemeaSyncResponse = FiservemeaAuthorizeResponse;

impl
    TryFrom<
        ResponseRouterData<
            FiservemeaSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FiservemeaSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Handle error response
        if let Some(error) = &response.error {
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: AttemptStatus::Failure,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(domain_types::router_data::ErrorResponse {
                    status_code: item.http_code,
                    code: error.code.clone(),
                    message: error.message.clone(),
                    reason: error.decline_reason_code.clone(),
                    attempt_status: Some(AttemptStatus::Failure),
                    connector_transaction_id: response.ipg_transaction_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..router_data.clone()
            });
        }

        // Map status from transaction result or state
        let status = response
            .transaction_result
            .clone()
            .map(AttemptStatus::from)
            .or_else(|| response.transaction_state.clone().map(AttemptStatus::from))
            .unwrap_or(AttemptStatus::Pending);

        let connector_transaction_id = response.ipg_transaction_id.clone().unwrap_or_default();

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: response.order_id.clone(),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// =============================================================================
// CAPTURE FLOW
// =============================================================================
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaCaptureRequest {
    pub request_type: FiservemeaTransactionType,
    pub transaction_amount: TransactionAmount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<Order>,
}

impl
    TryFrom<
        FiservemeaRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            (),
        >,
    > for FiservemeaCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: FiservemeaRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            (),
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        Ok(Self {
            request_type: FiservemeaTransactionType::PostAuthTransaction,
            transaction_amount: TransactionAmount {
                total: item.amount,
                currency: router_data.request.currency.to_string(),
            },
            order: Some(Order {
                order_id: Some(
                    router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                ),
            }),
        })
    }
}

pub type FiservemeaCaptureResponse = FiservemeaAuthorizeResponse;

impl
    TryFrom<
        ResponseRouterData<
            FiservemeaCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FiservemeaCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Handle error response
        if let Some(error) = &response.error {
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: AttemptStatus::Failure,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(domain_types::router_data::ErrorResponse {
                    status_code: item.http_code,
                    code: error.code.clone(),
                    message: error.message.clone(),
                    reason: error.decline_reason_code.clone(),
                    attempt_status: Some(AttemptStatus::Failure),
                    connector_transaction_id: response.ipg_transaction_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..router_data.clone()
            });
        }

        // Map status from transaction result or state
        let status = response
            .transaction_result
            .clone()
            .map(AttemptStatus::from)
            .or_else(|| response.transaction_state.clone().map(AttemptStatus::from))
            .unwrap_or(AttemptStatus::Pending);

        let connector_transaction_id = response.ipg_transaction_id.clone().unwrap_or_default();

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: response.order_id.clone(),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// =============================================================================
// REFUND FLOW
// =============================================================================
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaRefundRequest {
    pub request_type: FiservemeaTransactionType,
    pub transaction_amount: TransactionAmount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comments: Option<String>,
}

impl
    TryFrom<
        FiservemeaRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            (),
        >,
    > for FiservemeaRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: FiservemeaRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            (),
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        Ok(Self {
            request_type: FiservemeaTransactionType::ReturnTransaction,
            transaction_amount: TransactionAmount {
                total: item.amount,
                currency: router_data.request.currency.to_string(),
            },
            comments: router_data.request.reason.clone(),
        })
    }
}

pub type FiservemeaRefundResponse = FiservemeaAuthorizeResponse;

impl
    TryFrom<
        ResponseRouterData<
            FiservemeaRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FiservemeaRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Handle error response
        if let Some(error) = &response.error {
            return Ok(Self {
                resource_common_data: RefundFlowData {
                    status: common_enums::RefundStatus::Failure,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(domain_types::router_data::ErrorResponse {
                    status_code: item.http_code,
                    code: error.code.clone(),
                    message: error.message.clone(),
                    reason: error.decline_reason_code.clone(),
                    attempt_status: None,
                    connector_transaction_id: response.ipg_transaction_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..router_data.clone()
            });
        }

        // Map status from transaction result
        let refund_status = match &response.transaction_result {
            Some(FiservemeaTransactionResult::Approved) => common_enums::RefundStatus::Success,
            Some(FiservemeaTransactionResult::Declined)
            | Some(FiservemeaTransactionResult::Failed)
            | Some(FiservemeaTransactionResult::Fraud) => common_enums::RefundStatus::Failure,
            Some(FiservemeaTransactionResult::Waiting) => common_enums::RefundStatus::Pending,
            Some(FiservemeaTransactionResult::Partial) => common_enums::RefundStatus::Success,
            None => common_enums::RefundStatus::Pending,
        };

        let connector_refund_id = response.ipg_transaction_id.clone().unwrap_or_default();

        let refunds_response_data = RefundsResponseData {
            connector_refund_id,
            refund_status,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(refunds_response_data),
            ..router_data.clone()
        })
    }
}

// =============================================================================
// RSYNC FLOW
// =============================================================================
pub type FiservemeaRSyncRequest = FiservemeaSyncRequest;
pub type FiservemeaRSyncResponse = FiservemeaAuthorizeResponse;

impl
    TryFrom<
        ResponseRouterData<
            FiservemeaRSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FiservemeaRSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Handle error response
        if let Some(error) = &response.error {
            return Ok(Self {
                resource_common_data: RefundFlowData {
                    status: common_enums::RefundStatus::Failure,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(domain_types::router_data::ErrorResponse {
                    status_code: item.http_code,
                    code: error.code.clone(),
                    message: error.message.clone(),
                    reason: error.decline_reason_code.clone(),
                    attempt_status: None,
                    connector_transaction_id: response.ipg_transaction_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..router_data.clone()
            });
        }

        // Map status from transaction result
        let refund_status = match &response.transaction_result {
            Some(FiservemeaTransactionResult::Approved) => common_enums::RefundStatus::Success,
            Some(FiservemeaTransactionResult::Declined)
            | Some(FiservemeaTransactionResult::Failed)
            | Some(FiservemeaTransactionResult::Fraud) => common_enums::RefundStatus::Failure,
            Some(FiservemeaTransactionResult::Waiting) => common_enums::RefundStatus::Pending,
            Some(FiservemeaTransactionResult::Partial) => common_enums::RefundStatus::Success,
            None => common_enums::RefundStatus::Pending,
        };

        let connector_refund_id = response.ipg_transaction_id.clone().unwrap_or_default();

        let refunds_response_data = RefundsResponseData {
            connector_refund_id,
            refund_status,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(refunds_response_data),
            ..router_data.clone()
        })
    }
}

// =============================================================================
// VOID FLOW
// =============================================================================
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaVoidRequest {
    pub request_type: FiservemeaTransactionType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comments: Option<String>,
}

impl
    TryFrom<
        FiservemeaRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            (),
        >,
    > for FiservemeaVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: FiservemeaRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            (),
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        Ok(Self {
            request_type: FiservemeaTransactionType::VoidTransaction,
            comments: router_data.request.cancellation_reason.clone(),
        })
    }
}

pub type FiservemeaVoidResponse = FiservemeaAuthorizeResponse;

impl
    TryFrom<
        ResponseRouterData<
            FiservemeaVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FiservemeaVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Handle error response
        if let Some(error) = &response.error {
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: AttemptStatus::VoidFailed,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(domain_types::router_data::ErrorResponse {
                    status_code: item.http_code,
                    code: error.code.clone(),
                    message: error.message.clone(),
                    reason: error.decline_reason_code.clone(),
                    attempt_status: Some(AttemptStatus::VoidFailed),
                    connector_transaction_id: response.ipg_transaction_id.clone(),
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..router_data.clone()
            });
        }

        // Map status from transaction result or state
        let status = response
            .transaction_result
            .clone()
            .map(|result| match result {
                FiservemeaTransactionResult::Approved => AttemptStatus::Voided,
                FiservemeaTransactionResult::Declined
                | FiservemeaTransactionResult::Failed
                | FiservemeaTransactionResult::Fraud => AttemptStatus::VoidFailed,
                FiservemeaTransactionResult::Waiting => AttemptStatus::Pending,
                FiservemeaTransactionResult::Partial => AttemptStatus::Voided,
            })
            .or_else(|| {
                response.transaction_state.clone().map(|state| match state {
                    FiservemeaTransactionState::Voided => AttemptStatus::Voided,
                    _ => AttemptStatus::Pending,
                })
            })
            .unwrap_or(AttemptStatus::Pending);

        let connector_transaction_id = response.ipg_transaction_id.clone().unwrap_or_default();

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: response.order_id.clone(),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// =============================================================================
// HELPER STRUCT
// =============================================================================
pub struct FiservemeaRouterData<T, U> {
    pub amount: StringMajorUnit,
    pub router_data: T,
    pub _phantom: std::marker::PhantomData<U>,
}

impl<T, U> TryFrom<(StringMajorUnit, T, U)> for FiservemeaRouterData<T, U> {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from((amount, router_data, _): (StringMajorUnit, T, U)) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            router_data,
            _phantom: std::marker::PhantomData,
        })
    }
}
