use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::ResponseRouterData;
use base64::{engine::general_purpose, Engine};
use common_enums::AttemptStatus;
use common_utils::{
    crypto::{self, SignMessage},
    types::{AmountConvertor, FloatMajorUnit, FloatMajorUnitForConnector},
};
use domain_types::{
    connector_flow::Authorize,
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId,
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
    /// Generate HMAC-SHA256 signature for Fiserv API
    /// Raw signature: API-Key + ClientRequestId + Timestamp + requestBody
    /// Then HMAC-SHA256 with API Secret as key, then Base64 encode
    pub fn generate_hmac_signature(
        &self,
        api_key: &str,
        client_request_id: &str,
        timestamp: &str,
        request_body: &str,
    ) -> Result<String, error_stack::Report<errors::ConnectorError>> {
        // Raw signature: apiKey + ClientRequestId + Timestamp + requestBody
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
                api_secret: key1.to_owned(),
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
}

// ===== REQUEST STRUCTURES =====

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeRequest<T: PaymentMethodDataTypes> {
    pub request_type: FiservemeaRequestType,
    pub transaction_amount: TransactionAmount,
    pub payment_method: PaymentMethod<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<Order>,
}

#[derive(Debug, Serialize)]
pub struct TransactionAmount {
    pub total: FloatMajorUnit,
    pub currency: common_enums::Currency,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
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
    pub security_code: Secret<String>,
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
    > for FiservemeaAuthorizeRequest<T>
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
        // Convert amount to FloatMajorUnit format
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
                // Get year in YY format (2 digits)
                let year_yy = card_data.get_card_expiry_year_2_digit()?;

                let payment_card = PaymentCard {
                    number: card_data.card_number.clone(),
                    expiry_date: ExpiryDate {
                        month: Secret::new(card_data.card_exp_month.peek().clone()),
                        year: year_yy,
                    },
                    security_code: card_data.card_cvc.clone(),
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

        let request_type = if is_manual_capture {
            FiservemeaRequestType::PaymentCardPreAuthTransaction
        } else {
            FiservemeaRequestType::PaymentCardSaleTransaction
        };

        // Create order with connector request reference ID
        let order = Some(Order {
            order_id: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
        });

        Ok(Self {
            request_type,
            transaction_amount,
            payment_method,
            order,
        })
    }
}

// ===== RESPONSE STATUS ENUMS =====

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservemeaTransactionState {
    Authorized,
    Captured,
    Declined,
    Settled,
    Voided,
    Waiting,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservemeaTransactionResult {
    Approved,
    Declined,
    Failed,
    Waiting,
    Partial,
    Fraud,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservemeaTransactionType {
    Sale,
    Preauth,
    #[serde(other)]
    Unknown,
}

// ===== RESPONSE STRUCTURES =====

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovedAmount {
    pub total: FloatMajorUnit,
    pub currency: common_enums::Currency,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeResponse {
    pub ipg_transaction_id: String,
    pub transaction_type: FiservemeaTransactionType,
    pub transaction_result: FiservemeaTransactionResult,
    pub transaction_state: FiservemeaTransactionState,
    pub approval_code: Option<String>,
    pub approved_amount: Option<ApprovedAmount>,
    pub error: Option<FiservemeaErrorDetail>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaErrorDetail {
    pub code: Option<String>,
    pub message: Option<String>,
}

// ===== STATUS MAPPING FUNCTION =====

fn map_fiservemea_status_to_attempt_status(
    state: &FiservemeaTransactionState,
    result: &FiservemeaTransactionResult,
    transaction_type: &FiservemeaTransactionType,
) -> AttemptStatus {
    match (state, result) {
        (FiservemeaTransactionState::Captured, FiservemeaTransactionResult::Approved) => {
            AttemptStatus::Charged
        }
        (FiservemeaTransactionState::Authorized, FiservemeaTransactionResult::Approved) => {
            // For preauth transactions, return Authorized; for sale, check if auto-captured
            match transaction_type {
                FiservemeaTransactionType::Preauth => AttemptStatus::Authorized,
                _ => AttemptStatus::Charged,
            }
        }
        (FiservemeaTransactionState::Declined, _) => AttemptStatus::Failure,
        (FiservemeaTransactionState::Waiting, _) => AttemptStatus::Pending,
        (FiservemeaTransactionState::Voided, _) => AttemptStatus::Voided,
        (_, FiservemeaTransactionResult::Failed) => AttemptStatus::Failure,
        (_, FiservemeaTransactionResult::Declined) => AttemptStatus::Failure,
        (_, FiservemeaTransactionResult::Fraud) => AttemptStatus::Failure,
        _ => AttemptStatus::Pending,
    }
}

// ===== RESPONSE TRANSFORMATION =====

impl<T: PaymentMethodDataTypes> TryFrom<ResponseRouterData<FiservemeaAuthorizeResponse, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservemeaAuthorizeResponse, Self>,
    ) -> Result<Self, Self::Error> {
        // Map transaction status using state, result, and transaction type
        let status = map_fiservemea_status_to_attempt_status(
            &item.response.transaction_state,
            &item.response.transaction_result,
            &item.response.transaction_type,
        );

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.ipg_transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.approval_code.clone(),
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
        Self::try_from(&item.router_data)
    }
}
