use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::ResponseRouterData;
use base64::{engine::general_purpose, Engine};
use common_enums::AttemptStatus;
use common_utils::{
    crypto::{self, SignMessage},
    types::{AmountConvertor, StringMajorUnit},
};
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
use strum::Display;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct FiservemeaAuthType {
    pub api_key: Secret<String>,
    pub api_secret: Secret<String>,
}

impl FiservemeaAuthType {
    pub fn generate_hmac_signature(
        &self,
        api_key: &str,
        client_request_id: &str,
        timestamp: &str,
        request_body: &str,
    ) -> Result<String, error_stack::Report<errors::ConnectorError>> {
        let raw_signature = format!("{api_key}{client_request_id}{timestamp}{request_body}");

        let signature = crypto::HmacSha256
            .sign_message(
                self.api_secret.clone().expose().as_bytes(),
                raw_signature.as_bytes(),
            )
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        Ok(general_purpose::STANDARD.encode(signature))
    }

    pub fn generate_client_request_id() -> String {
        Uuid::new_v4().to_string()
    }

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaErrorResponse {
    pub client_request_id: String,
    pub api_trace_id: String,
    pub response_type: FiservemeaResponseType,
    pub error: Option<FiservemeaErrorDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaErrorDetail {
    pub code: String,
    pub message: String,
    pub details: Option<Vec<FiservemeaErrorField>>,
    pub decline_reason_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaErrorField {
    pub field: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeRequest<T: PaymentMethodDataTypes> {
    pub request_type: String,
    pub transaction_amount: FiservemeaTransactionAmount,
    pub payment_method: FiservemeaPaymentMethod<T>,
    pub order: Option<FiservemeaOrder>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaTransactionAmount {
    pub total: String,
    pub currency: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentMethod<T: PaymentMethodDataTypes> {
    pub payment_card: FiservemeaPaymentCard<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentCard<T: PaymentMethodDataTypes> {
    pub number: RawCardNumber<T>,
    pub security_code: Secret<String>,
    pub expiry_date: FiservemeaExpiryDate,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaExpiryDate {
    pub month: String,
    pub year: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaOrder {
    pub order_id: String,
    pub billing: Option<FiservemeaBilling>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaBilling {
    pub address: Option<FiservemeaAddress>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAddress {
    pub city: Option<String>,
    pub country: Option<String>,
    pub zip: Option<String>,
    pub state: Option<String>,
    pub street1: Option<String>,
    pub street2: Option<String>,
}

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
        let converter = StringMajorUnit;
        let amount_str = converter
            .convert(item.request.minor_amount, item.request.currency)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let transaction_amount = FiservemeaTransactionAmount {
            total: amount_str,
            currency: item.request.currency.to_string(),
        };

        let payment_method = match &item.request.payment_method_data {
            PaymentMethodData::Card(card_data) => {
                let year_yy = card_data.get_card_expiry_year_2_digit()?;

                let payment_card = FiservemeaPaymentCard {
                    number: card_data.card_number.clone(),
                    expiry_date: FiservemeaExpiryDate {
                        month: card_data.card_exp_month.peek().clone(),
                        year: year_yy.expose().clone(),
                    },
                    security_code: card_data.card_cvc.clone(),
                };
                FiservemeaPaymentMethod { payment_card }
            }
            _ => {
                return Err(error_stack::report!(errors::ConnectorError::NotImplemented(
                    "Only card payments are supported".to_string(),
                )))
            }
        };

        let order_id = item
            .resource_common_data
            .connector_request_reference_id
            .clone();

        let order = Some(FiservemeaOrder {
            order_id: order_id.clone(),
            billing: item.request.billing_address.as_ref().map(|addr| FiservemeaBilling {
                address: Some(FiservemeaAddress {
                    city: addr.city.clone(),
                    country: addr.country.map(|c| c.to_string()),
                    zip: addr.zip.clone(),
                    state: addr.state.clone(),
                    street1: addr.line1.clone(),
                    street2: addr.line2.clone(),
                }),
            }),
        });

        Ok(Self {
            request_type: "PaymentCardPreAuthTransaction".to_string(),
            transaction_amount,
            payment_method,
            order,
        })
    }
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeResponse {
    pub client_request_id: String,
    pub api_trace_id: String,
    pub ipg_transaction_id: String,
    pub order_id: String,
    pub transaction_type: String,
    pub transaction_result: FiservemeaTransactionResult,
    pub transaction_state: FiservemeaTransactionState,
    pub approval_code: Option<String>,
    pub scheme_response_code: Option<String>,
    pub error_message: Option<String>,
    pub approved_amount: Option<FiservemeaAmount>,
    pub transaction_amount: Option<FiservemeaAmount>,
    pub processor: Option<FiservemeaProcessor>,
    pub payment_method_details: Option<FiservemeaPaymentMethodDetails>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAmount {
    pub total: Option<String>,
    pub currency: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaProcessor {
    pub reference_number: Option<String>,
    pub authorization_code: Option<String>,
    pub response_code: Option<String>,
    pub response_message: Option<String>,
    pub network: Option<String>,
    pub association_response_code: Option<String>,
    pub association_response_message: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentMethodDetails {
    pub payment_card: Option<FiservemeaPaymentCardResponse>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentCardResponse {
    pub bin: Option<String>,
    pub last4: Option<String>,
    pub brand: Option<String>,
}

pub fn map_fiservemea_status_to_attempt_status(
    transaction_result: &FiservemeaTransactionResult,
    transaction_state: &FiservemeaTransactionState,
) -> AttemptStatus {
    match transaction_result {
        FiservemeaTransactionResult::Approved => match transaction_state {
            FiservemeaTransactionState::Authorized => AttemptStatus::Authorized,
            FiservemeaTransactionState::Captured => AttemptStatus::Charged,
            _ => AttemptStatus::Authorized,
        },
        FiservemeaTransactionResult::Declined => AttemptStatus::Failure,
        FiservemeaTransactionResult::Failed => AttemptStatus::Failure,
        FiservemeaTransactionResult::Waiting => AttemptStatus::Pending,
        FiservemeaTransactionResult::Fraud => AttemptStatus::Failure,
        FiservemeaTransactionResult::Partial => AttemptStatus::Pending,
    }
}

impl<T: PaymentMethodDataTypes>
    TryFrom<ResponseRouterData<FiservemeaAuthorizeResponse, Self>>
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

        let network_txn_id = item
            .response
            .processor
            .as_ref()
            .and_then(|p| p.network.clone())
            .or_else(|| Some(item.response.api_trace_id.clone()));

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.ipg_transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id,
                connector_response_reference_id: Some(item.response.client_request_id.clone()),
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

use crate::connectors::fiservemea::FiservemeaRouterData;

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + serde::Serialize>
    TryFrom<
        FiservemeaRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    > for FiservemeaAuthorizeRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: FiservemeaRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&item.router_data)
    }
}