use crate::types::ResponseRouterData;
use common_enums::AttemptStatus;
use common_utils::ext_traits::ByteSliceExt;
use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId},
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Maskable, Secret};
use serde::{Deserialize, Serialize};

// ============================================================================
// AUTHENTICATION TYPE
// ============================================================================

#[derive(Debug, Clone)]
pub struct FiservemeaAuthType {
    pub api_key: Secret<String>,
    pub api_secret: Secret<String>,
}

impl FiservemeaAuthType {
    /// Generate HMAC-SHA256 message signature
    ///
    /// Signature is computed as: Base64(HMAC-SHA256(API-Key + ClientRequestId + Timestamp + requestBody))
    pub fn generate_message_signature(
        &self,
        client_request_id: &str,
        timestamp: i64,
        request_body: &str,
    ) -> Result<String, errors::ConnectorError> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        // Concatenate signature components: API-Key + ClientRequestId + Timestamp + requestBody
        let signature_input = format!(
            "{}{}{}{}",
            self.api_key.expose(),
            client_request_id,
            timestamp,
            request_body
        );

        // Generate HMAC-SHA256
        let mut mac =
            HmacSha256::new_from_slice(self.api_secret.expose().as_bytes()).map_err(|_| {
                errors::ConnectorError::RequestEncodingFailed {
                    message: "Invalid API secret for HMAC".to_string(),
                }
            })?;
        mac.update(signature_input.as_bytes());

        // Encode result as Base64
        let signature_bytes = mac.finalize().into_bytes();
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            signature_bytes,
        ))
    }

    /// Generate a unique Client-Request-Id (UUID v4)
    pub fn generate_client_request_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// Get current timestamp in milliseconds since Unix epoch
    pub fn generate_timestamp() -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
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

// ============================================================================
// ERROR RESPONSE
// ============================================================================

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaErrorResponse {
    pub client_request_id: String,
    pub api_trace_id: String,
    pub response_type: FiservemeaResponseType,
    #[serde(default)]
    #[serde(rename = "type")]
    pub response_object_type: Option<String>,
    pub error: FiservemeaErrorDetail,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum FiservemeaResponseType {
    BadRequest,
    Unauthenticated,
    Unauthorized,
    NotFound,
    GatewayDeclined,
    EndpointDeclined,
    ServerError,
    EndpointCommunicationError,
    UnsupportedMediaType,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FiservemeaErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub details: Option<Vec<FiservemeaErrorField>>,
    #[serde(default)]
    pub decline_reason_code: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FiservemeaErrorField {
    pub field: String,
    pub message: String,
}

// ============================================================================
// REQUEST STRUCTURES
// ============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeRequest {
    pub request_type: FiservemeaRequestType,
    pub transaction_amount: FiservemeaTransactionAmount,
    pub payment_method: FiservemeaPaymentMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<FiservemeaOrder>,
}

#[derive(Debug, Serialize, Clone, Copy)]
#[serde(rename_all = "PascalCase")]
pub enum FiservemeaRequestType {
    PaymentCardSaleTransaction,
    PaymentCardPreAuthTransaction,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaTransactionAmount {
    pub total: String,
    pub currency: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentMethod {
    pub payment_card: FiservemeaPaymentCard,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentCard {
    pub number: String,
    pub security_code: String,
    pub expiry_date: FiservemeaExpiryDate,
}

#[derive(Debug, Serialize)]
pub struct FiservemeaExpiryDate {
    pub month: String,
    pub year: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaOrder {
    pub order_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing: Option<FiservemeaBilling>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaBilling {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
}

// ============================================================================
// RESPONSE STRUCTURES
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeResponse {
    pub client_request_id: String,
    pub api_trace_id: String,
    pub ipg_transaction_id: String,
    pub order_id: String,
    pub transaction_type: String,
    pub transaction_result: FiservemeaTransactionResult,
    pub transaction_state: FiservemeaTransactionState,
    #[serde(default)]
    pub approval_code: Option<String>,
    #[serde(default)]
    pub scheme_response_code: Option<String>,
    #[serde(default)]
    pub error_message: Option<String>,
    #[serde(default)]
    pub approved_amount: Option<FiservemeaApprovedAmount>,
    #[serde(default)]
    pub processor: Option<FiservemeaProcessor>,
    #[serde(default)]
    pub payment_method_details: Option<FiservemeaPaymentMethodDetails>,
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "UPPERCASE")]
pub enum FiservemeaTransactionResult {
    Approved,
    Declined,
    Failed,
    Waiting,
    Partial,
    Fraud,
}

#[derive(Debug, Deserialize, Clone, Copy)]
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaApprovedAmount {
    pub total: f64,
    pub currency: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaProcessor {
    pub reference_number: Option<String>,
    pub authorization_code: Option<String>,
    pub response_code: Option<String>,
    pub response_message: Option<String>,
    pub security_code_response: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentMethodDetails {
    pub payment_method_type: Option<String>,
    pub payment_method_brand: Option<String>,
}

// ============================================================================
// REQUEST TRANSFORMATION
// ============================================================================

impl<T: PaymentMethodDataTypes>
    TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for FiservemeaAuthorizeRequest
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
        // Extract payment method data
        let payment_method = match &item.request.payment_method_data {
            PaymentMethodData::Card(card_data) => {
                // Get card number as string
                let card_number = card_data
                    .card_number
                    .get_card_number()
                    .change_context(errors::ConnectorError::RequestEncodingFailed {
                        message: "Failed to get card number".to_string(),
                    })?;

                // Get expiry month and year
                let exp_month = card_data
                    .card_exp_month
                    .expose()
                    .chars()
                    .take(2)
                    .collect::<String>();
                let exp_year = card_data
                    .card_exp_year
                    .expose()
                    .chars()
                    .rev()
                    .take(2)
                    .collect::<Vec<char>>()
                    .into_iter()
                    .rev()
                    .collect::<String>();

                FiservemeaPaymentMethod {
                    payment_card: FiservemeaPaymentCard {
                        number: card_number,
                        security_code: card_data.card_cvc.expose().clone(),
                        expiry_date: FiservemeaExpiryDate {
                            month: exp_month,
                            year: exp_year,
                        },
                    },
                }
            }
            _ => {
                return Err(error_stack::report!(
                    errors::ConnectorError::NotImplemented("Only card payments are supported for Fiserv EMEA connector".to_string())
                ))
            }
        };

        // Convert amount to major units (string format)
        let amount_major = format!(
            "{:.2}",
            item.request.minor_amount.get_amount_as_i64() as f64 / 100.0
        );

        // Build order if available
        let order = item
            .resource_common_data
            .connector_request_reference_id
            .as_ref()
            .map(|ref_id| FiservemeaOrder {
                order_id: ref_id.clone(),
                billing: item.request.customer_name.as_ref().map(|name| FiservemeaBilling {
                    name: name.clone(),
                    customer_id: None,
                }),
            });

        // Determine request type based on capture method
        let request_type = if item.request.capture_method == Some(domain_types::connector_types::CaptureMethod::Automatic) {
            FiservemeaRequestType::PaymentCardSaleTransaction
        } else {
            FiservemeaRequestType::PaymentCardPreAuthTransaction
        };

        Ok(Self {
            request_type,
            transaction_amount: FiservemeaTransactionAmount {
                total: amount_major,
                currency: item.request.currency.to_string(),
            },
            payment_method,
            order,
        })
    }
}

// ============================================================================
// STATUS MAPPING
// ============================================================================

/// Map Fiserv EMEA transaction status to standard AttemptStatus
///
/// This function combines transactionResult and transactionState to determine
/// the appropriate AttemptStatus. The mapping follows these rules:
///
/// - APPROVED + AUTHORIZED = Authorized (manual capture)
/// - APPROVED + CAPTURED = Charged (auto capture)
/// - DECLINED/FAILED + DECLINED = Failure
/// - WAITING + PENDING/WAITING = Pending
/// - FRAUD = Failure
pub fn map_fiservemea_status_to_attempt_status(
    transaction_result: FiservemeaTransactionResult,
    transaction_state: FiservemeaTransactionState,
    is_auto_capture: bool,
) -> AttemptStatus {
    match (transaction_result, transaction_state) {
        // Successful transactions
        (FiservemeaTransactionResult::Approved, FiservemeaTransactionState::Authorized) => {
            if is_auto_capture {
                AttemptStatus::Charged
            } else {
                AttemptStatus::Authorized
            }
        }
        (FiservemeaTransactionResult::Approved, FiservemeaTransactionState::Captured) => {
            AttemptStatus::Charged
        }

        // Failed/Declined transactions
        (
            FiservemeaTransactionResult::Declined | FiservemeaTransactionResult::Failed,
            FiservemeaTransactionState::Declined,
        ) => AttemptStatus::Failure,

        // Pending transactions
        (
            FiservemeaTransactionResult::Waiting,
            FiservemeaTransactionState::Pending
            | FiservemeaTransactionState::Waiting
            | FiservemeaTransactionState::Initialized,
        ) => AttemptStatus::Pending,

        // Fraud detection
        (FiservemeaTransactionResult::Fraud, _) => AttemptStatus::Failure,

        // Partial approval
        (FiservemeaTransactionResult::Partial, _) => AttemptStatus::Pending,

        // Default to Pending for unknown combinations
        _ => AttemptStatus::Pending,
    }
}

// ============================================================================
// RESPONSE TRANSFORMATION
// ============================================================================

impl<T: PaymentMethodDataTypes>
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
    >
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
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

        // Determine if auto capture was requested
        let is_auto_capture =
            router_data.request.capture_method == Some(domain_types::connector_types::CaptureMethod::Automatic);

        // Map connector status to standard AttemptStatus
        let status = map_fiservemea_status_to_attempt_status(
            response.transaction_result,
            response.transaction_state,
            is_auto_capture,
        );

        // Build payments response data
        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.ipg_transaction_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: response.processor.as_ref().and_then(|p| p.reference_number.clone()),
            connector_response_reference_id: Some(response.order_id.clone()),
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