use crate::types::ResponseRouterData;
use common_enums::AttemptStatus;
use common_utils::types::StringMajorUnit;
use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId},
    errors,
    payment_method_data::{Card, PaymentMethodData, PaymentMethodDataTypes},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use hyperswitch_masking::{ExposeInterface, RawCardNumber, Secret};
use serde::{Deserialize, Serialize};

use crate::connectors::fiservemea::FiservmeaRouterData;

#[derive(Debug, Clone)]
pub struct FiservmeaAuthType {
    pub api_key: Secret<String>,
    pub api_secret: Secret<String>,
}

impl FiservmeaAuthType {
    pub fn generate_signature(&self, client_request_id: &str, timestamp: i64, request_body: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let concatenated = format!(
            "{}{}{}",
            self.api_key.expose(),
            client_request_id,
            timestamp
        );

        let mut mac = HmacSha256::new_from_slice(self.api_secret.expose().as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(concatenated.as_bytes());
        mac.update(request_body.as_bytes());

        let result = mac.finalize();
        base64::encode(result.into_bytes())
    }
}

impl TryFrom<&ConnectorAuthType> for FiservmeaAuthType {
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

#[derive(Debug, Clone, Deserialize, PartialEq, strum::Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservmeaTransactionResult {
    Approved,
    Declined,
    Failed,
    Waiting,
    Partial,
    Fraud,
}

#[derive(Debug, Clone, Deserialize, PartialEq, strum::Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservmeaTransactionState {
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

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservmeaSecurityCodeResponse {
    Matched,
    NotMatched,
    NotProcessed,
    NotPresent,
    NotCertified,
    NotChecked,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservmeaAuthorizeRequest<T> {
    pub request_type: String,
    pub transaction_amount: FiservmeaTransactionAmount,
    pub payment_method: FiservmeaPaymentMethod<T>,
    pub order: Option<FiservmeaOrder>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservmeaTransactionAmount {
    pub total: String,
    pub currency: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservmeaPaymentMethod<T> {
    pub payment_card: FiservmeaPaymentCard<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservmeaPaymentCard<T> {
    pub number: RawCardNumber<T>,
    pub security_code: Secret<String>,
    pub expiry_date: FiservmeaExpiryDate,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservmeaExpiryDate {
    pub month: String,
    pub year: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservmeaOrder {
    pub order_id: Option<String>,
    pub billing: Option<FiservmeaBilling>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservmeaBilling {
    pub name: Option<Secret<String>>,
    pub customer_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservmeaAuthorizeResponse {
    pub client_request_id: String,
    pub api_trace_id: String,
    pub ipg_transaction_id: String,
    pub order_id: String,
    pub transaction_type: String,
    pub transaction_result: FiservmeaTransactionResult,
    pub transaction_state: FiservmeaTransactionState,
    pub approval_code: Option<String>,
    pub scheme_response_code: Option<String>,
    pub error_message: Option<String>,
    pub approved_amount: Option<FiservmeaAmount>,
    pub processor: Option<FiservmeaProcessor>,
    pub payment_method_details: Option<FiservmeaPaymentMethodDetails>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservmeaAmount {
    pub total: Option<f64>,
    pub currency: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservmeaProcessor {
    pub reference_number: Option<String>,
    pub authorization_code: Option<String>,
    pub response_code: Option<String>,
    pub response_message: Option<String>,
    pub security_code_response: Option<FiservmeaSecurityCodeResponse>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservmeaPaymentMethodDetails {
    pub payment_method_type: Option<String>,
    pub payment_method_brand: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservmeaErrorResponse {
    pub client_request_id: Option<String>,
    pub api_trace_id: Option<String>,
    pub response_type: Option<String>,
    pub error: Option<FiservmeaErrorDetail>,
}

impl Default for FiservmeaErrorResponse {
    fn default() -> Self {
        Self {
            client_request_id: Some(String::new()),
            api_trace_id: Some(String::new()),
            response_type: Some(String::new()),
            error: None,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservmeaErrorDetail {
    pub code: Option<String>,
    pub message: Option<String>,
    pub details: Option<Vec<FiservmeaErrorField>>,
    pub decline_reason_code: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservmeaErrorField {
    pub field: Option<String>,
    pub message: Option<String>,
}

pub fn map_fiservmea_status_to_attempt_status(
    transaction_result: &FiservmeaTransactionResult,
    transaction_state: &FiservmeaTransactionState,
) -> AttemptStatus {
    match (transaction_result, transaction_state) {
        (FiservmeaTransactionResult::Approved, FiservmeaTransactionState::Authorized) => {
            AttemptStatus::Authorized
        }
        (
            FiservmeaTransactionResult::Declined
            | FiservmeaTransactionResult::Failed
            | FiservmeaTransactionResult::Fraud,
            _,
        )
        | (_, FiservmeaTransactionState::Declined) => AttemptStatus::Failure,
        (
            FiservmeaTransactionResult::Waiting | FiservmeaTransactionResult::Partial,
            _,
        )
        | (_, FiservmeaTransactionState::Pending | FiservmeaTransactionState::Waiting) => {
            AttemptStatus::Pending
        }
        _ => AttemptStatus::Failure,
    }
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        FiservmeaRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for FiservmeaAuthorizeRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: FiservmeaRouterData<
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

impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    > for FiservmeaAuthorizeRequest<T>
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
        let card_data = match &item.request.payment_method_data {
            PaymentMethodData::Card(card) => card,
            _ => {
                return Err(errors::ConnectorError::NotImplemented(
                    "Only card payments are supported for FiservMEA".to_string(),
                )
                .into())
            }
        };

        let amount_converter = &StringMajorUnit;
        let total = amount_converter.convert(item.request.minor_amount.get_amount_as_i64())?;

        let expiry_month = card_data.card_exp_month.to_string();
        let expiry_year = card_data.card_exp_year.expose().to_string();

        let order = if !item.resource_common_data.connector_request_reference_id.is_empty()
            || item.resource_common_data.customer_id.is_some()
        {
            Some(FiservmeaOrder {
                order_id: if item.resource_common_data.connector_request_reference_id.is_empty() {
                    None
                } else {
                    Some(item.resource_common_data.connector_request_reference_id.clone())
                },
                billing: item.resource_common_data.customer_id.as_ref().map(|_| FiservmeaBilling {
                    name: None,
                    customer_id: item.resource_common_data.customer_id.as_ref().map(|id| id.get_string_repr().to_string()),
                }),
            })
        } else {
            None
        };

        Ok(Self {
            request_type: "PaymentCardPreAuthTransaction".to_string(),
            transaction_amount: FiservmeaTransactionAmount {
                total,
                currency: item.request.currency.to_string(),
            },
            payment_method: FiservmeaPaymentMethod {
                payment_card: FiservmeaPaymentCard {
                    number: card_data.card_number.clone(),
                    security_code: card_data.card_cvc.clone(),
                    expiry_date: FiservmeaExpiryDate {
                        month: expiry_month,
                        year: expiry_year,
                    },
                },
            },
            order,
        })
    }
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            FiservmeaAuthorizeResponse,
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
            FiservmeaAuthorizeResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let status =
            map_fiservmea_status_to_attempt_status(&item.response.transaction_result, &item.response.transaction_state);
        let ipg_transaction_id = item.response.ipg_transaction_id.clone();
        let response = match status {
            AttemptStatus::Authorized => Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(ipg_transaction_id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: item.response.processor.as_ref().and_then(|p| p.reference_number.clone()),
                connector_response_reference_id: Some(ipg_transaction_id.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            AttemptStatus::Failure => Err(domain_types::router_data::ErrorResponse {
                status_code: item.http_code,
                code: item.response.scheme_response_code.clone().unwrap_or_else(|| {
                    item.response.transaction_result.to_string()
                }),
                message: item.response.error_message.clone().unwrap_or_else(|| {
                    item.response.transaction_result.to_string()
                }),
                reason: item.response.processor.as_ref().and_then(|p| p.response_message.clone()),
                attempt_status: Some(status),
                connector_transaction_id: Some(ipg_transaction_id.clone()),
                network_decline_code: item.response.scheme_response_code,
                network_advice_code: None,
                network_error_message: item.response.error_message,
            }),
            AttemptStatus::Pending => Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(ipg_transaction_id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: item.response.processor.as_ref().and_then(|p| p.reference_number.clone()),
                connector_response_reference_id: Some(ipg_transaction_id.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            _ => Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(ipg_transaction_id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: item.response.processor.as_ref().and_then(|p| p.reference_number.clone()),
                connector_response_reference_id: Some(ipg_transaction_id),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
        };

        Ok(Self {
            response,
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}