use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::ResponseRouterData;
use base64::{engine::general_purpose, Engine};
use common_enums::{AttemptStatus, RefundStatus};
use common_utils::{
    crypto::{self, SignMessage},
    types::{AmountConvertor, FloatMajorUnit, FloatMajorUnitForConnector},
};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ===== AUTHENTICATION STRUCTURE =====

#[derive(Debug, Clone)]
pub struct FiservemeaAuthType {
    pub api_key: Secret<String>,
    pub api_secret: Secret<String>,
}

impl FiservemeaAuthType {
    /// Generate HMAC-SHA256 signature for Fiserv EMEA API
    /// Raw signature: API-Key + ClientRequestId + time + requestBody
    /// Then HMAC-SHA256 with API Secret as key, then Base64 encode
    pub fn generate_hmac_signature(
        &self,
        api_key: &str,
        client_request_id: &str,
        timestamp: &str,
        request_body: &str,
    ) -> Result<String, error_stack::Report<errors::ConnectorError>> {
        // Raw signature: apiKey + ClientRequestId + time + requestBody
        let raw_signature = format!("{api_key}{client_request_id}{timestamp}{request_body}");

        // Generate HMAC-SHA256 with API Secret as key
        let signature = crypto::HmacSha256
            .sign_message(
                self.api_secret.clone().expose().as_bytes(),
                raw_signature.as_bytes(),
            )
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        // Base64 encode the result
        Ok(general_purpose::STANDARD.encode(signature))
    }

    /// Generate unique Client-Request-Id using UUID v4
    pub fn generate_client_request_id() -> String {
        Uuid::new_v4().to_string()
    }

    /// Generate timestamp in milliseconds since Unix epoch
    pub fn generate_timestamp() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .to_string()
    }
}

impl TryFrom<&ConnectorAuthType> for FiservemeaAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1, .. } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: key1.to_owned(), // key1 is the API secret for Fiserv EMEA
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

// ===== ERROR RESPONSE STRUCTURES =====

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaErrorResponse {
    pub code: Option<String>,
    pub message: Option<String>,
    pub details: Option<Vec<ErrorDetail>>,
    pub api_trace_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorDetail {
    pub field: Option<String>,
    pub message: Option<String>,
}

impl Default for FiservemeaErrorResponse {
    fn default() -> Self {
        Self {
            code: Some("UNKNOWN_ERROR".to_string()),
            message: Some("Unknown error occurred".to_string()),
            details: None,
            api_trace_id: None,
        }
    }
}

// ===== REQUEST TYPE ENUMS =====

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FiservemeaRequestType {
    PaymentCardSaleTransaction,
    PaymentCardPreAuthTransaction,
    PostAuthTransaction,
    ReturnTransaction,
    VoidPreAuthTransactions,
    VoidTransaction,
}

// ===== REQUEST STRUCTURES =====

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentsRequest<T: PaymentMethodDataTypes> {
    pub request_type: FiservemeaRequestType,
    pub merchant_transaction_id: String,
    pub transaction_amount: TransactionAmount,
    pub order: OrderDetails,
    pub payment_method: PaymentMethod<T>,
}

#[derive(Debug, Serialize)]
pub struct TransactionAmount {
    pub total: FloatMajorUnit,
    pub currency: common_enums::Currency,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderDetails {
    pub order_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentMethod<T: PaymentMethodDataTypes> {
    pub payment_card: PaymentCard<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentCard<T: PaymentMethodDataTypes> {
    pub number: RawCardNumber<T>,
    pub expiry_date: ExpiryDate,
    pub security_code: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder: Option<Secret<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpiryDate {
    pub month: Secret<String>,
    pub year: Secret<String>,
}

// ===== REQUEST TRANSFORMATION =====

impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    > for FiservemeaPaymentsRequest<T>
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
        // Use FloatMajorUnitForConnector to properly convert minor to major unit
        let converter = FloatMajorUnitForConnector;
        let amount_major = converter
            .convert(item.request.minor_amount, item.request.currency)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let transaction_amount = TransactionAmount {
            total: amount_major,
            currency: item.request.currency,
        };

        // Extract payment method data
        let payment_method = match &item.request.payment_method_data {
            PaymentMethodData::Card(card_data) => {
                // Use utility function to get year in YY format (2 digits)
                let year_yy = card_data.get_card_expiry_year_2_digit()?;

                let payment_card = PaymentCard {
                    number: card_data.card_number.clone(),
                    expiry_date: ExpiryDate {
                        month: Secret::new(card_data.card_exp_month.peek().clone()),
                        year: year_yy,
                    },
                    security_code: Some(card_data.card_cvc.clone()),
                    holder: item.request.customer_name.clone().map(Secret::new),
                };
                PaymentMethod { payment_card }
            }
            _ => {
                return Err(error_stack::report!(
                    errors::ConnectorError::NotImplemented(
                        "Only card payments are supported".to_string()
                    )
                ))
            }
        };

        // Determine transaction type based on capture_method
        let is_manual_capture = item
            .request
            .capture_method
            .map(|cm| matches!(cm, common_enums::CaptureMethod::Manual))
            .unwrap_or(false);

        // Generate unique merchant transaction ID using connector request reference ID
        let merchant_transaction_id = item
            .resource_common_data
            .connector_request_reference_id
            .clone();

        // Create order details with same ID
        let order = OrderDetails {
            order_id: merchant_transaction_id.clone(),
        };

        if is_manual_capture {
            Ok(Self {
                request_type: FiservemeaRequestType::PaymentCardPreAuthTransaction,
                merchant_transaction_id,
                transaction_amount,
                order,
                payment_method,
            })
        } else {
            Ok(Self {
                request_type: FiservemeaRequestType::PaymentCardSaleTransaction,
                merchant_transaction_id,
                transaction_amount,
                order,
                payment_method,
            })
        }
    }
}

// ===== CAPTURE REQUEST STRUCTURE =====

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaCaptureRequest {
    pub request_type: FiservemeaRequestType,
    pub transaction_amount: TransactionAmount,
}

// ===== CAPTURE REQUEST TRANSFORMATION =====

impl TryFrom<&RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>
    for FiservemeaCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Get capture amount from minor_amount_to_capture
        let capture_amount = item.request.minor_amount_to_capture;

        // Convert amount to FloatMajorUnit format
        let converter = FloatMajorUnitForConnector;
        let amount_major = converter
            .convert(capture_amount, item.request.currency)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let transaction_amount = TransactionAmount {
            total: amount_major,
            currency: item.request.currency,
        };

        Ok(Self {
            request_type: FiservemeaRequestType::PostAuthTransaction,
            transaction_amount,
        })
    }
}

// ===== RESPONSE STATUS ENUMS =====

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservemeaTransactionType {
    Sale,
    Preauth,
    Credit,
    ForcedTicket,
    Void,
    Return,
    Postauth,
    PayerAuth,
    Disbursement,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservemeaPaymentStatus {
    Approved,
    Waiting,
    Partial,
    ValidationFailed,
    ProcessingFailed,
    Declined,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservemeaPaymentResult {
    Approved,
    Declined,
    Failed,
    Waiting,
    Partial,
    Fraud,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

// ===== RESPONSE STRUCTURES =====

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentCardResponse {
    pub expiry_date: Option<ExpiryDate>,
    pub bin: Option<String>,
    pub last4: Option<String>,
    pub brand: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentMethodDetails {
    pub payment_card: Option<FiservemeaPaymentCardResponse>,
    pub payment_method_type: Option<String>,
    pub payment_method_brand: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AmountDetails {
    pub total: Option<FloatMajorUnit>,
    pub currency: Option<common_enums::Currency>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvsResponse {
    pub street_match: Option<String>,
    pub postal_code_match: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Processor {
    pub reference_number: Option<String>,
    pub authorization_code: Option<String>,
    pub response_code: Option<String>,
    pub response_message: Option<String>,
    pub network: Option<String>,
    pub association_response_code: Option<String>,
    pub association_response_message: Option<String>,
    pub avs_response: Option<AvsResponse>,
    pub security_code_response: Option<String>,
    pub merchant_advice_code_indicator: Option<String>,
    pub response_indicator: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentToken {
    pub value: Option<String>,
    pub reusable: Option<bool>,
    pub decline_duplicates: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentsResponse {
    pub client_request_id: Option<String>,
    pub api_trace_id: Option<String>,
    pub response_type: Option<String>,
    #[serde(rename = "type")]
    pub response_type_field: Option<String>,
    pub ipg_transaction_id: String,
    pub order_id: Option<String>,
    pub user_id: Option<String>,
    pub transaction_type: FiservemeaTransactionType,
    pub payment_method_details: Option<FiservemeaPaymentMethodDetails>,
    pub merchant_transaction_id: Option<String>,
    pub transaction_time: Option<i64>,
    pub approved_amount: Option<AmountDetails>,
    pub transaction_amount: Option<AmountDetails>,
    pub transaction_status: Option<FiservemeaPaymentStatus>,
    pub transaction_result: Option<FiservemeaPaymentResult>,
    pub transaction_state: Option<FiservemeaTransactionState>,
    pub approval_code: Option<String>,
    pub scheme_response_code: Option<String>,
    pub error_message: Option<String>,
    pub scheme_transaction_id: Option<String>,
    pub processor: Option<Processor>,
    pub payment_token: Option<PaymentToken>,
}

// ===== HELPER FUNCTIONS TO AVOID CODE DUPLICATION =====

/// Extract connector metadata from payment token
fn extract_connector_metadata(payment_token: Option<&PaymentToken>) -> Option<serde_json::Value> {
    payment_token.map(|token| {
        let mut metadata = HashMap::new();
        if let Some(value) = &token.value {
            metadata.insert("payment_token".to_string(), value.clone());
        }
        if let Some(reusable) = token.reusable {
            metadata.insert("token_reusable".to_string(), reusable.to_string());
        }
        serde_json::Value::Object(
            metadata
                .into_iter()
                .map(|(k, v)| (k, serde_json::Value::String(v)))
                .collect(),
        )
    })
}

/// Extract network-specific fields from processor object
fn extract_network_fields(
    processor: Option<&Processor>,
) -> (Option<String>, Option<String>, Option<String>) {
    if let Some(processor) = processor {
        (
            processor.network.clone(),
            processor.association_response_code.clone(),
            processor.association_response_message.clone(),
        )
    } else {
        (None, None, None)
    }
}

// ===== STATUS MAPPING FUNCTION =====

fn map_status(
    fiservemea_status: Option<FiservemeaPaymentStatus>,
    fiservemea_result: Option<FiservemeaPaymentResult>,
    fiservemea_state: Option<FiservemeaTransactionState>,
    transaction_type: FiservemeaTransactionType,
) -> AttemptStatus {
    // First check transaction_state for additional validation
    if let Some(state) = fiservemea_state {
        match state {
            FiservemeaTransactionState::Declined => return AttemptStatus::Failure,
            FiservemeaTransactionState::Voided => return AttemptStatus::Voided,
            FiservemeaTransactionState::Authorized => {
                // Only trust AUTHORIZED state if transaction type matches
                if matches!(transaction_type, FiservemeaTransactionType::Preauth) {
                    return AttemptStatus::Authorized;
                }
            }
            FiservemeaTransactionState::Captured | FiservemeaTransactionState::Settled => {
                // Only trust CAPTURED/SETTLED if transaction type matches
                if matches!(
                    transaction_type,
                    FiservemeaTransactionType::Sale | FiservemeaTransactionType::Postauth
                ) {
                    return AttemptStatus::Charged;
                }
            }
            _ => {} // Continue to check status/result
        }
    }

    // Then check transaction_status (deprecated field)
    match fiservemea_status {
        Some(status) => match status {
            FiservemeaPaymentStatus::Approved => match transaction_type {
                FiservemeaTransactionType::Preauth => AttemptStatus::Authorized,
                FiservemeaTransactionType::Void => AttemptStatus::Voided,
                FiservemeaTransactionType::Sale | FiservemeaTransactionType::Postauth => {
                    AttemptStatus::Charged
                }
                FiservemeaTransactionType::Credit
                | FiservemeaTransactionType::ForcedTicket
                | FiservemeaTransactionType::Return
                | FiservemeaTransactionType::PayerAuth
                | FiservemeaTransactionType::Disbursement
                | FiservemeaTransactionType::Unknown => AttemptStatus::Failure,
            },
            FiservemeaPaymentStatus::Waiting => AttemptStatus::Pending,
            FiservemeaPaymentStatus::Partial => AttemptStatus::PartialCharged,
            FiservemeaPaymentStatus::ValidationFailed
            | FiservemeaPaymentStatus::ProcessingFailed
            | FiservemeaPaymentStatus::Declined => AttemptStatus::Failure,
        },
        // If transaction_status not present, check transaction_result (current field)
        None => match fiservemea_result {
            Some(result) => match result {
                FiservemeaPaymentResult::Approved => match transaction_type {
                    FiservemeaTransactionType::Preauth => AttemptStatus::Authorized,
                    FiservemeaTransactionType::Void => AttemptStatus::Voided,
                    FiservemeaTransactionType::Sale | FiservemeaTransactionType::Postauth => {
                        AttemptStatus::Charged
                    }
                    FiservemeaTransactionType::Credit
                    | FiservemeaTransactionType::ForcedTicket
                    | FiservemeaTransactionType::Return
                    | FiservemeaTransactionType::PayerAuth
                    | FiservemeaTransactionType::Disbursement
                    | FiservemeaTransactionType::Unknown => AttemptStatus::Failure,
                },
                FiservemeaPaymentResult::Waiting => AttemptStatus::Pending,
                FiservemeaPaymentResult::Partial => AttemptStatus::PartialCharged,
                FiservemeaPaymentResult::Declined
                | FiservemeaPaymentResult::Failed
                | FiservemeaPaymentResult::Fraud => AttemptStatus::Failure,
            },
            None => AttemptStatus::Pending,
        },
    }
}

// ===== RESPONSE TRANSFORMATION =====

impl<T: PaymentMethodDataTypes> TryFrom<ResponseRouterData<FiservemeaPaymentsResponse, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservemeaPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        // Map transaction status using status/result, state, AND transaction type
        let status = map_status(
            item.response.transaction_status.clone(),
            item.response.transaction_result.clone(),
            item.response.transaction_state.clone(),
            item.response.transaction_type.clone(),
        );

        // Extract connector metadata from payment token using helper function
        let connector_metadata = extract_connector_metadata(item.response.payment_token.as_ref());

        // Extract network-specific fields from processor object using helper function
        let (network_txn_id, _network_decline_code, _network_error_message) =
            extract_network_fields(item.response.processor.as_ref());

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.ipg_transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata,
                network_txn_id: network_txn_id.or(item.response.api_trace_id.clone()),
                connector_response_reference_id: item.response.client_request_id.clone(),
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

// ===== PSYNC RESPONSE TRANSFORMATION =====

impl TryFrom<ResponseRouterData<FiservemeaPaymentsResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservemeaPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        // Map transaction status using status/result, state, AND transaction type
        let status = map_status(
            item.response.transaction_status.clone(),
            item.response.transaction_result.clone(),
            item.response.transaction_state.clone(),
            item.response.transaction_type.clone(),
        );

        // Extract connector metadata from payment token using helper function
        let connector_metadata = extract_connector_metadata(item.response.payment_token.as_ref());

        // Extract network-specific fields from processor object using helper function
        let (network_txn_id, _network_decline_code, _network_error_message) =
            extract_network_fields(item.response.processor.as_ref());

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.ipg_transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata,
                network_txn_id: network_txn_id.or(item.response.api_trace_id.clone()),
                connector_response_reference_id: item.response.client_request_id.clone(),
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

// ===== CAPTURE RESPONSE TRANSFORMATION =====

impl TryFrom<ResponseRouterData<FiservemeaPaymentsResponse, Self>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservemeaPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        // Map transaction status using status/result, state, AND transaction type
        let status = map_status(
            item.response.transaction_status.clone(),
            item.response.transaction_result.clone(),
            item.response.transaction_state.clone(),
            item.response.transaction_type.clone(),
        );

        // Extract connector metadata from payment token using helper function
        let connector_metadata = extract_connector_metadata(item.response.payment_token.as_ref());

        // Extract network-specific fields from processor object using helper function
        let (network_txn_id, _network_decline_code, _network_error_message) =
            extract_network_fields(item.response.processor.as_ref());

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.ipg_transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata,
                network_txn_id: network_txn_id.or(item.response.api_trace_id.clone()),
                connector_response_reference_id: item.response.client_request_id.clone(),
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

// ===== REFUND REQUEST STRUCTURE =====

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaRefundRequest {
    pub request_type: FiservemeaRequestType,
    pub transaction_amount: TransactionAmount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comments: Option<String>,
}

// ===== REFUND REQUEST TRANSFORMATION =====

impl TryFrom<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>
    for FiservemeaRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Convert refund amount to major unit format
        let converter = FloatMajorUnitForConnector;
        let amount_major = converter
            .convert(item.request.minor_refund_amount, item.request.currency)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let transaction_amount = TransactionAmount {
            total: amount_major,
            currency: item.request.currency,
        };

        Ok(Self {
            request_type: FiservemeaRequestType::ReturnTransaction,
            transaction_amount,
            comments: item.request.reason.clone(),
        })
    }
}

// ===== VOID REQUEST STRUCTURE =====

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaVoidRequest {
    pub request_type: FiservemeaRequestType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comments: Option<String>,
}

// ===== VOID REQUEST TRANSFORMATION =====

impl TryFrom<&RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>
    for FiservemeaVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            request_type: FiservemeaRequestType::VoidPreAuthTransactions,
            comments: item.request.cancellation_reason.clone(),
        })
    }
}

// ===== REFUND STATUS MAPPING FUNCTION =====

fn map_refund_status(
    transaction_type: Option<FiservemeaTransactionType>,
    transaction_status: Option<FiservemeaPaymentStatus>,
    transaction_result: Option<FiservemeaPaymentResult>,
    transaction_state: Option<FiservemeaTransactionState>,
) -> RefundStatus {
    // Validate transaction type is RETURN first
    if let Some(tx_type) = transaction_type {
        if tx_type != FiservemeaTransactionType::Return {
            // If transactionType is NOT RETURN, this is NOT a valid refund
            return RefundStatus::Failure;
        }
    } else {
        // No transaction type provided
        return RefundStatus::Pending;
    }

    // Check transaction_state first (most reliable)
    if let Some(state) = transaction_state {
        match state {
            FiservemeaTransactionState::Captured | FiservemeaTransactionState::Settled => {
                // Verify result/status is also success
                if matches!(transaction_result, Some(FiservemeaPaymentResult::Approved))
                    || matches!(transaction_status, Some(FiservemeaPaymentStatus::Approved))
                {
                    return RefundStatus::Success;
                }
            }
            FiservemeaTransactionState::Declined => return RefundStatus::Failure,
            FiservemeaTransactionState::Pending | FiservemeaTransactionState::Waiting => {
                return RefundStatus::Pending;
            }
            _ => {} // Continue to check status/result
        }
    }

    // Check transaction_result (newer field)
    if let Some(result) = transaction_result {
        return match result {
            FiservemeaPaymentResult::Approved => {
                // If state not available or unclear, check if it's likely settled
                RefundStatus::Success
            }
            FiservemeaPaymentResult::Waiting => RefundStatus::Pending,
            FiservemeaPaymentResult::Declined
            | FiservemeaPaymentResult::Failed
            | FiservemeaPaymentResult::Fraud => RefundStatus::Failure,
            FiservemeaPaymentResult::Partial => RefundStatus::Pending,
        };
    }

    // Check transaction_status (deprecated field) if transaction_result not present
    if let Some(status) = transaction_status {
        return match status {
            FiservemeaPaymentStatus::Approved => {
                // If state not available or unclear, treat as success
                RefundStatus::Success
            }
            FiservemeaPaymentStatus::Waiting => RefundStatus::Pending,
            FiservemeaPaymentStatus::ValidationFailed
            | FiservemeaPaymentStatus::ProcessingFailed
            | FiservemeaPaymentStatus::Declined => RefundStatus::Failure,
            FiservemeaPaymentStatus::Partial => RefundStatus::Pending,
        };
    }

    // Default to Pending for unknown/incomplete status combinations
    RefundStatus::Pending
}

impl TryFrom<ResponseRouterData<FiservemeaPaymentsResponse, Self>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservemeaPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        // Map refund status with validation of ALL fields
        let refund_status = map_refund_status(
            Some(item.response.transaction_type.clone()),
            item.response.transaction_status.clone(),
            item.response.transaction_result.clone(),
            item.response.transaction_state.clone(),
        );

        let mut router_data = item.router_data;
        router_data.response = Ok(RefundsResponseData {
            connector_refund_id: item.response.ipg_transaction_id.clone(),
            refund_status,
            status_code: item.http_code,
        });

        Ok(router_data)
    }
}

// ===== REFUND SYNC RESPONSE TRANSFORMATION =====

impl TryFrom<ResponseRouterData<FiservemeaPaymentsResponse, Self>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservemeaPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        // Map refund status with validation of ALL fields
        let refund_status = map_refund_status(
            Some(item.response.transaction_type.clone()),
            item.response.transaction_status.clone(),
            item.response.transaction_result.clone(),
            item.response.transaction_state.clone(),
        );

        let mut router_data = item.router_data;
        router_data.response = Ok(RefundsResponseData {
            connector_refund_id: item.response.ipg_transaction_id.clone(),
            refund_status,
            status_code: item.http_code,
        });

        Ok(router_data)
    }
}

// ===== VOID STATUS MAPPING FUNCTION =====

fn map_void_status(
    transaction_type: FiservemeaTransactionType,
    transaction_status: Option<FiservemeaPaymentStatus>,
    transaction_result: Option<FiservemeaPaymentResult>,
    transaction_state: Option<FiservemeaTransactionState>,
) -> AttemptStatus {
    // First validate transactionType is VOID
    if transaction_type != FiservemeaTransactionType::Void {
        // Not a void transaction - this is an error
        return AttemptStatus::VoidFailed;
    }

    // Check transactionState first for most accurate status
    if let Some(state) = transaction_state {
        match state {
            FiservemeaTransactionState::Voided => {
                // Verify result/status is also APPROVED for complete validation
                if matches!(transaction_result, Some(FiservemeaPaymentResult::Approved))
                    || matches!(transaction_status, Some(FiservemeaPaymentStatus::Approved))
                {
                    return AttemptStatus::Voided;
                }
                // State is VOIDED but no confirmation from result/status, still consider voided
                return AttemptStatus::Voided;
            }
            FiservemeaTransactionState::Declined => return AttemptStatus::VoidFailed,
            FiservemeaTransactionState::Pending | FiservemeaTransactionState::Waiting => {
                return AttemptStatus::Pending;
            }
            _ => {} // Continue to check result/status
        }
    }

    // Check transaction_result (newer field)
    if let Some(result) = transaction_result {
        return match result {
            FiservemeaPaymentResult::Approved => AttemptStatus::Voided,
            FiservemeaPaymentResult::Waiting => AttemptStatus::Pending,
            FiservemeaPaymentResult::Declined
            | FiservemeaPaymentResult::Failed
            | FiservemeaPaymentResult::Fraud => AttemptStatus::VoidFailed,
            FiservemeaPaymentResult::Partial => AttemptStatus::Pending,
        };
    }

    // Check transaction_status (deprecated field) if transaction_result not present
    if let Some(status) = transaction_status {
        return match status {
            FiservemeaPaymentStatus::Approved => AttemptStatus::Voided,
            FiservemeaPaymentStatus::Waiting => AttemptStatus::Pending,
            FiservemeaPaymentStatus::ValidationFailed
            | FiservemeaPaymentStatus::ProcessingFailed
            | FiservemeaPaymentStatus::Declined => AttemptStatus::VoidFailed,
            FiservemeaPaymentStatus::Partial => AttemptStatus::Pending,
        };
    }

    // Default to Pending if no clear status
    AttemptStatus::Pending
}

impl TryFrom<ResponseRouterData<FiservemeaPaymentsResponse, Self>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservemeaPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        // Map void status with validation of ALL fields
        let status = map_void_status(
            item.response.transaction_type.clone(),
            item.response.transaction_status.clone(),
            item.response.transaction_result.clone(),
            item.response.transaction_state.clone(),
        );

        // Extract network-specific fields from processor object using helper function
        let (network_txn_id, _network_decline_code, _network_error_message) =
            extract_network_fields(item.response.processor.as_ref());

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.ipg_transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: network_txn_id.or(item.response.api_trace_id.clone()),
                connector_response_reference_id: item.response.client_request_id.clone(),
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

// ===== TYPE ALIASES FOR MACRO COMPATIBILITY =====
pub type FiservemeaAuthorizeResponse = FiservemeaPaymentsResponse;
pub type FiservemeaSyncResponse = FiservemeaPaymentsResponse;
pub type FiservemeaVoidResponse = FiservemeaPaymentsResponse;
pub type FiservemeaCaptureResponse = FiservemeaPaymentsResponse;
pub type FiservemeaRefundResponse = FiservemeaPaymentsResponse;
pub type FiservemeaRefundSyncResponse = FiservemeaPaymentsResponse;

// ===== TRYFROM IMPLEMENTATIONS FOR MACRO COMPATIBILITY =====

use crate::connectors::fiservemea::FiservemeaRouterData;

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
    > for FiservemeaPaymentsRequest<T>
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
        Self::try_from(&item.router_data)
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        FiservemeaRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for FiservemeaVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: FiservemeaRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&item.router_data)
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        FiservemeaRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for FiservemeaCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: FiservemeaRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&item.router_data)
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        FiservemeaRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for FiservemeaRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: FiservemeaRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&item.router_data)
    }
}
