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
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct FiservemeaAuthType {
    pub api_key: Secret<String>,
    pub api_secret: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for FiservemeaAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, api_secret, .. } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: api_secret.to_owned(),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeRequest<T> {
    pub request_type: String,
    pub transaction_amount: TransactionAmount,
    pub payment_method: PaymentMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<Order>,
    #[serde(skip)]
    pub _phantom: std::marker::PhantomData<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionAmount {
    pub total: String,
    pub currency: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentMethod {
    pub payment_card: PaymentCard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentCard {
    pub number: Secret<String>,
    pub security_code: Secret<String>,
    pub expiry_date: ExpiryDate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpiryDate {
    pub month: String,
    pub year: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    pub order_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeResponse {
    pub ipg_transaction_id: String,
    pub transaction_result: FiservemeaTransactionResult,
    pub transaction_state: FiservemeaTransactionState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_amount: Option<TransactionAmount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservemeaTransactionResult {
    Approved,
    Declined,
    Failed,
    Waiting,
    Partial,
    Fraud,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone)]
pub struct FiservemeaRouterData<T: PaymentMethodDataTypes> {
    pub amount: StringMajorUnit,
    pub router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
}

impl<T: PaymentMethodDataTypes> TryFrom<(StringMajorUnit, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>)> for FiservemeaRouterData<T> {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        (amount, router_data): (StringMajorUnit, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>),
    ) -> Result<Self, Self::Error> {
        Ok(Self { amount, router_data })
    }
}

impl<T: PaymentMethodDataTypes> TryFrom<FiservemeaRouterData<T>> for FiservemeaAuthorizeRequest<T> {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: FiservemeaRouterData<T>) -> Result<Self, Self::Error> {
        let card_data = match item.router_data.request.payment_method_data {
            domain_types::payment_method_data::PaymentMethodData::Card(card_data) => card_data,
            _ => {
                return Err(error_stack::report!(
                    errors::ConnectorError::MissingRequiredField {
                        field_name: "payment_method_data.card",
                    }
                ))
            }
        };

        let expiry_month = card_data.card_exp_month.peek().to_string();
        let expiry_year = card_data.card_exp_year.peek().to_string();

        let payment_card = PaymentCard {
            number: Secret::new(card_data.card_number.peek().to_string()),
            security_code: card_data.card_cvc.clone(),
            expiry_date: ExpiryDate {
                month: expiry_month,
                year: expiry_year,
            },
        };

        let order = Some(Order {
            order_id: item.router_data.resource_common_data.connector_request_reference_id.clone(),
        });

        Ok(Self {
            request_type: "PaymentCardPreAuthTransaction".to_string(),
            transaction_amount: TransactionAmount {
                total: item.amount.get_amount_as_string(),
                currency: item.router_data.request.currency.to_string(),
            },
            payment_method: PaymentMethod {
                payment_card,
            },
            order,
            _phantom: std::marker::PhantomData,
        })
    }
}

fn map_fiservemea_status_to_attempt_status(
    result: &FiservemeaTransactionResult,
    state: &FiservemeaTransactionState,
) -> AttemptStatus {
    match (result, state) {
        (FiservemeaTransactionResult::Approved, FiservemeaTransactionState::Authorized) => {
            AttemptStatus::Authorized
        }
        (FiservemeaTransactionResult::Approved, FiservemeaTransactionState::Captured) => {
            AttemptStatus::Charged
        }
        (FiservemeaTransactionResult::Declined, _) |
        (_, FiservemeaTransactionState::Declined) => {
            AttemptStatus::Failure
        }
        (FiservemeaTransactionResult::Waiting, _) |
        (_, FiservemeaTransactionState::Pending) |
        (_, FiservemeaTransactionState::Waiting) => {
            AttemptStatus::Pending
        }
        (_, FiservemeaTransactionState::Voided) => AttemptStatus::Voided,
        _ => AttemptStatus::Pending,
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
        let status = map_fiservemea_status_to_attempt_status(
            &item.response.transaction_result,
            &item.response.transaction_state,
        );

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.ipg_transaction_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.approval_code,
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