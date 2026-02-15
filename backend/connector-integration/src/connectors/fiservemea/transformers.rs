use crate::types::ResponseRouterData;
use common_enums::AttemptStatus;
use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId},
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use hyperswitch_masking::Secret;
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
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: None,
            }),
            ConnectorAuthType::SignatureKey { api_key, api_secret, .. } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: Some(api_secret.to_owned()),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiservemeaErrorResponse {
    pub code: Option<String>,
    pub message: String,
    pub details: Option<Vec<FiservemeaErrorDetail>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FiservemeaErrorDetail {
    pub field: Option<String>,
    pub message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeRequest<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize> {
    pub request_type: String,
    pub transaction_amount: FiservemeaTransactionAmount,
    pub payment_method: FiservemeaPaymentMethod<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaTransactionAmount {
    pub total: String,
    pub currency: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "paymentCard", rename_all = "camelCase")]
pub struct FiservemeaPaymentMethod<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize> {
    pub number: Secret<String>,
    pub security_code: Secret<String>,
    pub expiry_date: FiservemeaExpiryDate,
}

#[derive(Debug, Serialize)]
pub struct FiservemeaExpiryDate {
    pub month: String,
    pub year: String,
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
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservemeaTransactionResult {
    Approved,
    Declined,
    Failed,
    Waiting,
    Partial,
    Fraud,
}

#[derive(Debug, Deserialize)]
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
        (FiservemeaTransactionResult::Waiting, _)
        | (_, FiservemeaTransactionState::Waiting)
        | (_, FiservemeaTransactionState::Pending) => AttemptStatus::Pending,
        (FiservemeaTransactionResult::Declined, _)
        | (FiservemeaTransactionResult::Failed, _)
        | (_, FiservemeaTransactionState::Declined) => AttemptStatus::Failure,
        (_, FiservemeaTransactionState::Voided) => AttemptStatus::Voided,
        (FiservemeaTransactionResult::Partial, _) => AttemptStatus::PartialCharged,
        (FiservemeaTransactionResult::Fraud, _) => AttemptStatus::Failure,
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
            domain_types::payment_method_data::PaymentMethodData::Card(card_data) => {
                FiservemeaPaymentMethod {
                    number: card_data.card_number.clone(),
                    security_code: card_data.card_cvc.clone(),
                    expiry_date: FiservemeaExpiryDate {
                        month: card_data.card_exp_month.expose().to_string(),
                        year: card_data.card_exp_year.expose().to_string(),
                    },
                }
            }
            _ => {
                return Err(errors::ConnectorError::NotImplemented(
                    "Payment method not supported".to_string(),
                )
                .into())
            }
        };

        let request_type = if router_data.request.capture_method.is_some() {
            "PaymentCardSaleTransaction".to_string()
        } else {
            "PaymentCardPreAuthTransaction".to_string()
        };

        Ok(Self {
            request_type,
            transaction_amount: FiservemeaTransactionAmount {
                total: item.amount.to_string(),
                currency: router_data.request.currency.to_string(),
            },
            payment_method,
        })
    }
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            FiservemeaAuthorizeResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    >
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FiservemeaAuthorizeResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status = map_fiservemea_status_to_attempt_status(
            &item.response.transaction_result,
            &item.response.transaction_state,
        );

        let network_txn_id = item
            .response
            .processor
            .as_ref()
            .and_then(|p| p.authorization_code.clone());

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.ipg_transaction_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id,
                connector_response_reference_id: None,
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