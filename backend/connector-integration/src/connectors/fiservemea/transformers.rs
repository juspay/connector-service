use crate::{
    connectors::fiservemea::FiservemeaRouterData,
    types::ResponseRouterData,
};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaExpiryDate {
    pub month: String,
    pub year: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentCard {
    pub number: Secret<String>,
    pub security_code: Secret<String>,
    pub expiry_date: FiservemeaExpiryDate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentMethod {
    pub payment_card: FiservemeaPaymentCard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaTransactionAmount {
    pub total: String,
    pub currency: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeRequest {
    pub request_type: String,
    pub transaction_amount: FiservemeaTransactionAmount,
    pub payment_method: FiservemeaPaymentMethod,
    pub order_id: Option<String>,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    > for FiservemeaAuthorizeRequest
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
        let payment_method = item
            .request
            .payment_method_data
            .as_ref()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "payment_method_data",
            })?;

        let card = match payment_method {
            PaymentMethodData::Card(card) => card,
            _ => {
                return Err(errors::ConnectorError::NotImplemented("Only card payments are supported".to_string()).into());
            }
        };

        let amount = item.request.minor_amount.get_amount_as_i64();
        let amount_str = format!("{}.{:02}", amount / 100, amount % 100);

        Ok(Self {
            request_type: "PaymentCardPreAuthTransaction".to_string(),
            transaction_amount: FiservemeaTransactionAmount {
                total: amount_str,
                currency: item.request.currency.to_string(),
            },
            payment_method: FiservemeaPaymentMethod {
                payment_card: FiservemeaPaymentCard {
                    number: card.card_number.peek().to_string().into(),
                    security_code: card.card_cvc.clone(),
                    expiry_date: FiservemeaExpiryDate {
                        month: format!("{:02}", card.card_exp_month.expose()),
                        year: card.card_exp_year.expose().to_string(),
                    },
                },
            },
            order_id: Some(
                item.resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<
        FiservemeaRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    > for FiservemeaAuthorizeRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: FiservemeaRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        FiservemeaAuthorizeRequest::try_from(&item.router_data)
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum FiservemeaTransactionResult {
    Approved,
    Declined,
    Failed,
    Waiting,
    Partial,
    Fraud,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeResponse {
    pub ipg_transaction_id: String,
    pub transaction_state: FiservemeaTransactionState,
    pub transaction_result: FiservemeaTransactionResult,
    pub approval_code: Option<String>,
    pub scheme_response_code: Option<String>,
    pub error_message: Option<String>,
    pub approved_amount: Option<FiservemeaTransactionAmount>,
}

fn map_fiservemea_status_to_attempt_status(
    transaction_state: &FiservemeaTransactionState,
    transaction_result: &FiservemeaTransactionResult,
) -> AttemptStatus {
    match (transaction_state, transaction_result) {
        (FiservemeaTransactionState::Authorized, FiservemeaTransactionResult::Approved) => {
            AttemptStatus::Authorized
        }
        (FiservemeaTransactionState::Captured, FiservemeaTransactionResult::Approved) => {
            AttemptStatus::Charged
        }
        (FiservemeaTransactionState::Declined, FiservemeaTransactionResult::Declined)
        | (_, FiservemeaTransactionResult::Failed) => AttemptStatus::Failure,
        (FiservemeaTransactionState::Pending, _)
        | (_, FiservemeaTransactionResult::Waiting) => AttemptStatus::Pending,
        (FiservemeaTransactionState::Voided, _) => AttemptStatus::Voided,
        _ => AttemptStatus::Pending,
    }
}

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
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
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
        let status = map_fiservemea_status_to_attempt_status(
            &item.response.transaction_state,
            &item.response.transaction_result,
        );

        let network_txn_id = match (
            item.response.scheme_response_code,
            item.response.approval_code,
        ) {
            (Some(scheme), Some(approval)) => Some(format!("{}:{}", scheme, approval)),
            (Some(scheme), None) => Some(scheme),
            (None, Some(approval)) => Some(approval),
            _ => None,
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.ipg_transaction_id,
                ),
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

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<
        ResponseRouterData<
            FiservemeaAuthorizeResponse,
            FiservemeaRouterData<
                RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
                T,
            >,
        >,
    > for FiservemeaRouterData<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        T,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FiservemeaAuthorizeResponse,
            FiservemeaRouterData<
                RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
                T,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data: RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        > = ResponseRouterData {
            response: item.response,
            router_data: item.router_data.router_data,
            http_code: item.http_code,
        }
        .try_into()?;

        Ok(FiservemeaRouterData {
            connector: item.router_data.connector,
            router_data,
        })
    }
}
