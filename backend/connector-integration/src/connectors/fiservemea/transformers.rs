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

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservemeaStatus {
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
#[serde(rename_all = "UPPERCASE")]
pub enum FiservemeaTransactionResult {
    Approved,
    Declined,
    Failed,
    Waiting,
    Partial,
    Fraud,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaTransactionAmount {
    pub total: String,
    pub currency: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentCard {
    pub card_number: String,
    pub expiration_month: String,
    pub expiration_year: String,
    pub cvv: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentMethod {
    pub payment_card: FiservemeaPaymentCard,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaOrder {
    pub order_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeRequest {
    pub request_type: String,
    pub transaction_amount: FiservemeaTransactionAmount,
    pub payment_method: FiservemeaPaymentMethod,
    pub order: Option<FiservemeaOrder>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAmount {
    pub value: String,
    pub currency: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeResponse {
    pub ipg_transaction_id: String,
    pub transaction_state: FiservemeaStatus,
    pub transaction_result: Option<FiservemeaTransactionResult>,
    pub transaction_type: String,
    pub approved_amount: Option<FiservemeaAmount>,
    pub approval_code: Option<String>,
}

fn map_fiservemea_status_to_attempt_status(
    status: &FiservemeaStatus,
    transaction_result: Option<&FiservemeaTransactionResult>,
) -> AttemptStatus {
    match (status, transaction_result) {
        (FiservemeaStatus::Authorized, Some(FiservemeaTransactionResult::Approved)) => {
            AttemptStatus::Authorized
        }
        (FiservemeaStatus::Captured, Some(FiservemeaTransactionResult::Approved)) => {
            AttemptStatus::Charged
        }
        (FiservemeaStatus::Declined, _) | (_, Some(FiservemeaTransactionResult::Declined)) => {
            AttemptStatus::Failure
        }
        (_, Some(FiservemeaTransactionResult::Failed)) => AttemptStatus::Failure,
        (FiservemeaStatus::Pending, _) | (FiservemeaStatus::Waiting, _) => AttemptStatus::Pending,
        (FiservemeaStatus::Voided, _) => AttemptStatus::Voided,
        _ => AttemptStatus::Pending,
    }
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        crate::connectors::fiservemea::FiservemeaRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    > for FiservemeaAuthorizeRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: crate::connectors::fiservemea::FiservemeaRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let item = &item.router_data;
        let amount_str = item
            .request
            .minor_amount
            .get_amount_as_i64()
            .to_string();

        let currency = item.request.currency.to_string();

        let payment_card = match &item.request.payment_method_data {
            domain_types::payment_method_data::PaymentMethodData::Card(card_data) => {
                FiservemeaPaymentCard {
                    card_number: card_data.card_number.peek().to_string(),
                    expiration_month: card_data.card_exp_month.clone().expose().to_string(),
                    expiration_year: card_data.card_exp_year.clone().expose().to_string(),
                    cvv: Some(card_data.card_cvc.clone().expose().to_string()),
                }
            }
            _ => {
                return Err(error_stack::report!(
                    errors::ConnectorError::NotImplemented("Only card payments are supported".to_string())
                ))
            }
        };

        Ok(Self {
            request_type: "PaymentCardPreAuthTransaction".to_string(),
            transaction_amount: FiservemeaTransactionAmount {
                total: amount_str,
                currency,
            },
            payment_method: FiservemeaPaymentMethod {
                payment_card,
            },
            order: Some(FiservemeaOrder {
                order_id: Some(
                    item
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                ),
            }),
        })
    }
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            FiservemeaAuthorizeResponse,
            crate::connectors::fiservemea::FiservemeaRouterData<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            FiservemeaAuthorizeResponse,
            crate::connectors::fiservemea::FiservemeaRouterData<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data.router_data;
        let status =
            map_fiservemea_status_to_attempt_status(&item.response.transaction_state, item.response.transaction_result.as_ref());

        Ok(RouterDataV2 {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.ipg_transaction_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: item.response.approval_code,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            ..router_data
        })
    }
}