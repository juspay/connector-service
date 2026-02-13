use crate::types::ResponseRouterData;
use common_enums::AttemptStatus;
use common_utils::types::StringMajorUnit;
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
}

impl TryFrom<&ConnectorAuthType> for FiservemeaAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiservemeaErrorResponse {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservemeaStatus {
    Approved,
    Declined,
    Failed,
    Waiting,
    Partial,
    Fraud,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeRequest<T> {
    pub request_type: String,
    pub transaction_amount: FiservemeaTransactionAmount,
    pub payment_method: FiservemeaPaymentMethod<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaTransactionAmount {
    pub total: StringMajorUnit,
    pub currency: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum FiservemeaPaymentMethod<T> {
    Card(FiservemeaCardPaymentMethod),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaCardPaymentMethod {
    pub payment_card: FiservemeaPaymentCard,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentCard {
    pub number: Secret<String>,
    pub security_code: Secret<String>,
    pub expiry_date: FiservemeaExpiryDate,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaExpiryDate {
    pub month: String,
    pub year: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeResponse {
    pub ipg_transaction_id: String,
    pub transaction_result: FiservemeaStatus,
    pub transaction_state: FiservemeaTransactionState,
    pub approval_code: Option<String>,
    pub scheme_response_code: Option<String>,
    pub error_message: Option<String>,
    pub transaction_amount: Option<FiservemeaTransactionAmount>,
    pub processor: Option<FiservemeaProcessor>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaProcessor {
    pub authorization_code: Option<String>,
    pub response_code: Option<String>,
    pub response_message: Option<String>,
    pub association_response_code: Option<String>,
    pub association_response_message: Option<String>,
}

fn map_fiservemea_status_to_attempt_status(
    status: &FiservemeaStatus,
    state: &FiservemeaTransactionState,
) -> AttemptStatus {
    match (status, state) {
        (FiservemeaStatus::Approved, FiservemeaTransactionState::Authorized) => {
            AttemptStatus::Authorized
        }
        (FiservemeaStatus::Approved, FiservemeaTransactionState::Captured) => {
            AttemptStatus::Charged
        }
        (FiservemeaStatus::Approved, FiservemeaTransactionState::Settled) => {
            AttemptStatus::Charged
        }
        (FiservemeaStatus::Declined, _) | (FiservemeaStatus::Failed, _) => {
            AttemptStatus::Failure
        }
        (FiservemeaStatus::Waiting, _) | (FiservemeaStatus::Partial, _) => {
            AttemptStatus::Pending
        }
        (FiservemeaStatus::Fraud, _) => AttemptStatus::Failure,
        (_, FiservemeaTransactionState::Pending) => AttemptStatus::Pending,
        (_, FiservemeaTransactionState::Waiting) => AttemptStatus::Pending,
        (_, FiservemeaTransactionState::Initialized) => AttemptStatus::Pending,
        (_, FiservemeaTransactionState::Voided) => AttemptStatus::Voided,
        (_, FiservemeaTransactionState::Declined) => AttemptStatus::Failure,
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
        let payment_method = match item.router_data.request.payment_method_data.clone() {
            domain_types::payment_method_data::PaymentMethodData::Card(card_data) => {
                FiservemeaPaymentMethod::Card(FiservemeaCardPaymentMethod {
                    payment_card: FiservemeaPaymentCard {
                        number: Secret::new(card_data.card_number.peek().to_string()),
                        security_code: card_data.card_cvc.clone(),
                        expiry_date: FiservemeaExpiryDate {
                            month: card_data.card_exp_month.peek().to_string(),
                            year: card_data.get_expiry_year_2_digit(),
                        },
                    },
                })
            }
            _ => {
                return Err(errors::ConnectorError::NotSupported {
                    message: "Payment Method".to_string(),
                    connector: "Fiservemea",
                }
                .into())
            }
        };

        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .map_err(|e| {
                errors::ConnectorError::RequestEncodingFailedWithReason(format!(
                    "Amount conversion failed: {e}"
                ))
            })?;

        Ok(Self {
            request_type: "PaymentCardPreAuthTransaction".to_string(),
            transaction_amount: FiservemeaTransactionAmount {
                total: amount,
                currency: item.router_data.request.currency.to_string(),
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
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FiservemeaAuthorizeResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status =
            map_fiservemea_status_to_attempt_status(&item.response.transaction_result, &item.response.transaction_state);

        let network_txn_id = item
            .response
            .processor
            .as_ref()
            .and_then(|p| p.authorization_code.clone())
            .or(item.response.approval_code.clone());

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