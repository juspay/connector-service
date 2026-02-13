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
use hyperswitch_masking::{PeekInterface, Secret};
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
pub struct FiservemeaAuthorizeRequest {
    pub request_type: String,
    pub transaction_amount: FiservemeaTransactionAmount,
    pub payment_method: FiservemeaPaymentMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<FiservemeaOrder>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaTransactionAmount {
    pub total: String,
    pub currency: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentMethod {
    pub payment_card: FiservemeaPaymentCard,
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
pub struct FiservemeaExpiryDate {
    pub month: String,
    pub year: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaOrder {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing: Option<FiservemeaBilling>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaBilling {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
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
    pub scheme_response_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_amount: Option<FiservemeaAmount>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAmount {
    pub total: f64,
    pub currency: String,
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
        (FiservemeaTransactionResult::Declined, _)
        | (FiservemeaTransactionResult::Failed, _)
        | (FiservemeaTransactionResult::Fraud, _) => AttemptStatus::Failure,
        (FiservemeaTransactionResult::Waiting, _)
        | (FiservemeaTransactionResult::Partial, _) => AttemptStatus::Pending,
        (_, FiservemeaTransactionState::Voided) => AttemptStatus::Voided,
        _ => AttemptStatus::Pending,
    }
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
        let card_details = match &item.request.payment_method_data {
            PaymentMethodData::Card(card) => card,
            _ => {
                return Err(error_stack::report!(
                    errors::ConnectorError::MissingRequiredField {
                        field_name: "payment_method.card"
                    }
                ))
            }
        };

        let expiry_month = card_details.card_exp_month.peek().clone();
        let expiry_year = card_details.card_exp_year.peek().clone();
        let cvc = card_details.card_cvc.peek().clone();

        let amount_major = item
            .request
            .minor_amount
            .get_amount_as_i64() as f64 / 100.0;

        Ok(Self {
            request_type: "PaymentCardSaleTransaction".to_string(),
            transaction_amount: FiservemeaTransactionAmount {
                total: format!("{:.2}", amount_major),
                currency: item.request.currency.to_string(),
            },
            payment_method: FiservemeaPaymentMethod {
                payment_card: FiservemeaPaymentCard {
                    number: Secret::new(card_details.card_number.peek().to_string()),
                    security_code: Secret::new(cvc),
                    expiry_date: FiservemeaExpiryDate {
                        month: expiry_month,
                        year: expiry_year,
                    },
                },
            },
            order: Some(FiservemeaOrder {
                order_id: Some(
                    item.resource_common_data
                        .connector_request_reference_id
                        .clone(),
                ),
                billing: None,
            }),
        })
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
        let status =
            map_fiservemea_status_to_attempt_status(&item.response.transaction_result, &item.response.transaction_state);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.ipg_transaction_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: item.response.approval_code,
                connector_response_reference_id: item.response.scheme_response_code,
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