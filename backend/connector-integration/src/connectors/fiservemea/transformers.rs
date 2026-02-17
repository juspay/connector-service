use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::ResponseRouterData;
use common_enums::AttemptStatus;
use common_utils::{crypto::SignMessage, types::{FloatMajorUnitForConnector, AmountConvertor, FloatMajorUnit}};
use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId},
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
}

impl FiservemeaAuthType {
    /// Generate HMAC-SHA256 signature for Fiservemea API
    /// Raw signature: API-Key + ClientRequestId + Timestamp + requestBody
    /// Then HMAC-SHA256 with API Key as key, then Base64 encode
    pub fn generate_hmac_signature(
        &self,
        api_key: &str,
        client_request_id: &str,
        timestamp: &str,
        request_body: &str,
    ) -> Result<String, error_stack::Report<errors::ConnectorError>> {
        let raw_signature = format!("{}{}{}{}", api_key, client_request_id, timestamp, request_body);

        let signature = SignMessage::sign_message(
            self.api_key.clone().expose().as_bytes(),
            raw_signature.as_bytes(),
        )
        .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        Ok(base64::engine::general_purpose::STANDARD.encode(signature))
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
            ConnectorAuthType::BodyKey { api_key, .. } => Ok(Self {
                api_key: api_key.to_owned(),
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

// ===== REQUEST STRUCTURES =====

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeRequest<T: PaymentMethodDataTypes> {
    pub request_type: String,
    pub transaction_amount: TransactionAmount,
    pub payment_method: PaymentMethod,
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
    pub billing_address: Option<Address>,
    pub shipping_address: Option<Address>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Address {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub address_line1: Option<String>,
    pub address_line2: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentMethod {
    pub payment_card: PaymentCard,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentCard {
    pub number: RawCardNumber<T>,
    pub expiry_date: ExpiryDate,
    pub security_code: Option<Secret<String>>,
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
        let converter = FloatMajorUnitForConnector;
        let amount_major = converter
            .convert(item.request.minor_amount, item.request.currency)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let transaction_amount = TransactionAmount {
            total: amount_major,
            currency: item.request.currency,
        };

        let payment_method = match &item.request.payment_method_data {
            PaymentMethodData::Card(card_data) => {
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

        let order = Order {
            order_id: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            billing_address: None,
            shipping_address: None,
        };

        Ok(Self {
            request_type: "PaymentCardPreAuthTransaction".to_string(),
            transaction_amount,
            payment_method,
            order: Some(order),
        })
    }
}

// ===== RESPONSE STRUCTURES =====

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeResponse {
    pub client_request_id: String,
    pub ipg_transaction_id: String,
    pub transaction_type: String,
    pub transaction_result: String,
    pub transaction_state: String,
    pub processor: Option<Processor>,
    pub error: Option<Error>,
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
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvsResponse {
    pub street_match: Option<String>,
    pub postal_code_match: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Error {
    pub code: Option<String>,
    pub message: Option<String>,
}

// ===== STATUS MAPPING FUNCTION =====

fn map_fiservemea_status_to_attempt_status(
    transaction_result: &str,
    transaction_state: &str,
) -> AttemptStatus {
    match transaction_state {
        "AUTHORIZED" => AttemptStatus::Authorized,
        "CAPTURED" => AttemptStatus::Charged,
        "DECLINED" => AttemptStatus::Failure,
        "WAITING" => AttemptStatus::Pending,
        "VOIDED" => AttemptStatus::Voided,
        _ => {
            if transaction_result == "APPROVED" {
                AttemptStatus::Authorized
            } else if transaction_result == "DECLINED" {
                AttemptStatus::Failure
            } else {
                AttemptStatus::Pending
            }
        }
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
        let status = map_fiservemea_status_to_attempt_status(
            &item.response.transaction_result,
            &item.response.transaction_state,
        );

        let (network_txn_id, _network_decline_code, _network_error_message) =
            if let Some(processor) = &item.response.processor {
                (
                    processor.network.clone(),
                    processor.association_response_code.clone(),
                    processor.association_response_message.clone(),
                )
            } else {
                (None, None, None)
            };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.ipg_transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: network_txn_id.or_else(|| item.response.client_request_id.clone()),
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
