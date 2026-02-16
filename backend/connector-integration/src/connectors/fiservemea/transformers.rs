use crate::types::ResponseRouterData;
use common_enums::AttemptStatus;
use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId},
    errors,
    payment_method_data::{Card, PaymentMethodData, PaymentMethodDataTypes},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct FiservemeaAuthType {
    pub api_key: Secret<String>,
    pub api_secret: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for FiservemeaAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, api_secret, .. } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: Some(api_secret.to_owned()),
            }),
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: None,
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
    pub code: Option<String>,
    pub message: String,
    pub details: Option<Vec<FiservemeaErrorDetail>>,
    pub decline_reason_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiservemeaErrorDetail {
    pub field: Option<String>,
    pub message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeRequest<T: PaymentMethodDataTypes> {
    pub request_type: String,
    pub transaction_amount: FiservemeaTransactionAmount,
    pub payment_method: FiservemeaPaymentMethod<T>,
    pub order: Option<FiservemeaOrder>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaTransactionAmount {
    pub total: String,
    pub currency: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "paymentMethodType", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservemeaPaymentMethod<T: PaymentMethodDataTypes> {
    PaymentCard(FiservemeaCard<T>),
}

#[derive(Debug, Serialize)]
pub struct FiservemeaCard<T: PaymentMethodDataTypes> {
    pub number: Secret<String>,
    pub security_code: Option<Secret<String>>,
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
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeResponse {
    pub ipg_transaction_id: String,
    pub transaction_result: FiservemeaTransactionResult,
    pub transaction_state: FiservemeaTransactionState,
    pub approval_code: Option<String>,
    pub transaction_amount: Option<FiservemeaTransactionAmount>,
    pub processor: Option<FiservemeaProcessor>,
    pub error_message: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum FiservemeaTransactionResult {
    Approved,
    Declined,
    Failed,
    Waiting,
    Partial,
    Fraud,
}

#[derive(Debug, Deserialize)]
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
pub struct FiservemeaProcessor {
    pub authorization_code: Option<String>,
    pub response_code: Option<String>,
    pub response_message: Option<String>,
}

pub fn map_fiservemea_status_to_attempt_status(
    transaction_result: &FiservemeaTransactionResult,
    transaction_state: &FiservemeaTransactionState,
) -> AttemptStatus {
    match (transaction_result, transaction_state) {
        (FiservemeaTransactionResult::Approved, FiservemeaTransactionState::Authorized) => {
            AttemptStatus::Authorized
        }
        (FiservemeaTransactionResult::Approved, FiservemeaTransactionState::Captured) => {
            AttemptStatus::Charged
        }
        (FiservemeaTransactionResult::Approved, FiservemeaTransactionState::Settled) => {
            AttemptStatus::Charged
        }
        (FiservemeaTransactionResult::Declined, _)
        | (FiservemeaTransactionResult::Failed, _) => AttemptStatus::Failure,
        (FiservemeaTransactionResult::Waiting, _)
        | (FiservemeaTransactionResult::Partial, _) => AttemptStatus::Pending,
        (FiservemeaTransactionResult::Fraud, _) => AttemptStatus::Failure,
        (_, FiservemeaTransactionState::Pending) => AttemptStatus::Pending,
        (_, FiservemeaTransactionState::Initialized) => AttemptStatus::Pending,
        (_, FiservemeaTransactionState::Waiting) => AttemptStatus::Pending,
        (_, FiservemeaTransactionState::Voided) => AttemptStatus::Voided,
        _ => AttemptStatus::Pending,
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        super::FiservemeaRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    > for FiservemeaAuthorizeRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::FiservemeaRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        let payment_method = match &router_data.request.payment_method_data {
            PaymentMethodData::Card(card_data) => {
                FiservemeaPaymentMethod::PaymentCard(FiservemeaCard {
                    number: Secret::new(card_data.card_number.peek().to_string()),
                    security_code: Some(card_data.card_cvc.clone()),
                    expiry_date: FiservemeaExpiryDate {
                        month: card_data.card_exp_month.expose().to_string(),
                        year: card_data.get_expiry_year_4_digit().expose().to_string(),
                    },
                })
            }
            _ => {
                return Err(error_stack::report!(
                    errors::ConnectorError::NotImplemented("Payment method not supported".to_string())
                ))
            }
        };

        let order = Some(FiservemeaOrder {
            order_id: router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
        });

        let amount = item
            .connector
            .amount_converter
            .convert(
                router_data.request.minor_amount,
                router_data.request.currency,
            )
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            request_type: "PaymentCardPreAuthTransaction".to_string(),
            transaction_amount: FiservemeaTransactionAmount {
                total: amount.to_string(),
                currency: router_data.request.currency.to_string(),
            },
            payment_method,
            order,
        })
    }
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            FiservemeaAuthorizeResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FiservemeaAuthorizeResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        let status = map_fiservemea_status_to_attempt_status(
            &response.transaction_result,
            &response.transaction_state,
        );

        if matches!(
            response.transaction_result,
            FiservemeaTransactionResult::Declined
                | FiservemeaTransactionResult::Failed
                | FiservemeaTransactionResult::Fraud
        ) {
            let error_message = response
                .error_message
                .clone()
                .or_else(|| response.processor.as_ref().and_then(|p| p.response_message.clone()))
                .unwrap_or_else(|| "Transaction declined".to_string());

            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(domain_types::router_data::ErrorResponse {
                    status_code: item.http_code,
                    code: format!("{:?}", response.transaction_result),
                    message: error_message.clone(),
                    reason: Some(error_message),
                    attempt_status: Some(status),
                    connector_transaction_id: Some(response.ipg_transaction_id.clone()),
                    network_decline_code: response
                        .processor
                        .as_ref()
                        .and_then(|p| p.response_code.clone()),
                    network_advice_code: None,
                    network_error_message: response
                        .processor
                        .as_ref()
                        .and_then(|p| p.response_message.clone()),
                }),
                ..router_data.clone()
            });
        }

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.ipg_transaction_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: response
                .processor
                .as_ref()
                .and_then(|p| p.authorization_code.clone()),
            connector_response_reference_id: response.approval_code.clone(),
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