use crate::connectors::fiservemea::FiservemeaRouterData;
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

use crate::types::ResponseRouterData;
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
            ConnectorAuthType::SignatureKey {
                api_key,
                api_secret,
            } => Ok(Self {
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
pub struct FiservemeaErrorResponse {
    pub error: String,
    pub response_type: String,
    pub error_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaTransactionAmount {
    pub value: String,
    pub currency: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaCard {
    pub number: Secret<String>,
    pub security_code: Secret<String>,
    pub expiry_date: FiservemeaExpiryDate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiservemeaExpiryDate {
    pub month: String,
    pub year: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "paymentMethodType", rename_all = "camelCase")]
pub enum FiservemeaPaymentMethod<T> {
    Card(FiservemeaCard),
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaOrder {
    pub order_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeRequest<T> {
    pub request_type: String,
    pub transaction_amount: FiservemeaTransactionAmount,
    pub payment_method: FiservemeaPaymentMethod<T>,
    pub order: Option<FiservemeaOrder>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeResponse {
    pub ipg_transaction_id: String,
    pub transaction_result: FiservemeaTransactionResult,
    pub transaction_state: FiservemeaTransactionState,
    pub approval_code: Option<String>,
    pub processor: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum FiservemeaTransactionResult {
    Approved,
    Declined,
    Failed,
    Waiting,
    Partial,
    Fraud,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum FiservemeaTransactionState {
    Authorized,
    Captured,
    Declined,
    Failed,
    Pending,
    Voided,
    Refunded,
}

fn map_fiservemea_status_to_attempt_status(
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
        (FiservemeaTransactionResult::Declined, _) | (FiservemeaTransactionResult::Failed, _) => {
            AttemptStatus::Failure
        }
        (FiservemeaTransactionResult::Waiting, _) | (_, FiservemeaTransactionState::Pending) => {
            AttemptStatus::Pending
        }
        (FiservemeaTransactionResult::Fraud, _) => AttemptStatus::Failure,
        (FiservemeaTransactionResult::Partial, _) => AttemptStatus::Pending,
        (_, FiservemeaTransactionState::Voided) => AttemptStatus::Voided,
        (_, FiservemeaTransactionState::Refunded) => AttemptStatus::AutoRefunded,
        _ => AttemptStatus::Pending,
    }
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
        let amount = domain_types::utils::convert_amount(
            &common_utils::types::StringMajorUnitForConnector,
            item.request.minor_amount,
            item.request.currency,
        )
        .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let payment_method = match &item.request.payment_method_data {
            PaymentMethodData::Card(card) => {
                let expiry_month = card.card_exp_month.peek();
                let expiry_year = card.card_exp_year.peek();
                let expiry_year_4digit = if expiry_year.len() == 2 {
                    format!("20{}", expiry_year)
                } else {
                    expiry_year.to_string()
                };

                FiservemeaPaymentMethod::Card(FiservemeaCard {
                    number: card.card_number.peek().to_string().into(),
                    security_code: card.card_cvc.peek().to_string().into(),
                    expiry_date: FiservemeaExpiryDate {
                        month: expiry_month.to_string(),
                        year: expiry_year_4digit,
                    },
                })
            }
            _ => {
                return Err(error_stack::report!(
                    errors::ConnectorError::RequestEncodingFailed
                )
                .attach_printable("Unsupported payment method for FiservEMEA"))
            }
        };

        let order = Some(FiservemeaOrder {
            order_id: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
        });

        Ok(Self {
            request_type: "PaymentCardPreAuthTransaction".to_string(),
            transaction_amount: FiservemeaTransactionAmount {
                value: amount,
                currency: item.request.currency.to_string(),
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
            &item.response.transaction_result,
            &item.response.transaction_state,
        );

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.ipg_transaction_id,
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
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