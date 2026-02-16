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
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

pub struct FiservemeaRouterData<RD: FlowTypes, T: PaymentMethodDataTypes> {
    pub connector: crate::connectors::fiservemea::Fiservemea<T>,
    pub router_data: RD,
}

impl<RD: FlowTypes, T: PaymentMethodDataTypes> FlowTypes for FiservemeaRouterData<RD, T> {
    type Flow = RD::Flow;
    type FlowCommonData = RD::FlowCommonData;
    type Request = RD::Request;
    type Response = RD::Response;
}

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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeRequest {
    pub request_type: String,
    pub transaction_amount: FiservemeaTransactionAmount,
    pub payment_method: FiservemeaPaymentMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<FiservemeaOrder>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaTransactionAmount {
    pub total: String,
    pub currency: String,
}

#[derive(Debug, Serialize)]
pub struct FiservemeaPaymentMethod {
    pub payment_card: FiservemeaPaymentCard,
}

#[derive(Debug, Serialize)]
pub struct FiservemeaPaymentCard {
    pub number: Secret<String>,
    pub security_code: Secret<String>,
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

impl<T: PaymentMethodDataTypes>
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
        let payment_method_data = item
            .router_data
            .request
            .payment_method_data
            .get_payment_method_value()
            .change_context(errors::ConnectorError::MissingRequiredField {
                field_name: "payment_method_data",
            })?;

        let (card_number, card_expiry_month, card_expiry_year, card_cvv) = match payment_method_data
        {
            domain_types::payment_method_data::PaymentMethod::Card(card) => (
                card.card_number.clone(),
                card.card_exp_month.clone(),
                card.card_exp_year.clone(),
                card.card_cvc.clone(),
            ),
            _ => {
                return Err(error_stack::report!(
                    errors::ConnectorError::NotImplemented("Only card payments are supported".to_string())
                ))
            }
        };

        let amount = utils::convert_amount::<StringMajorUnit>(
            &StringMajorUnitForConnector,
            common_utils::types::MinorUnit::new(
                item.router_data
                    .request
                    .minor_amount
                    .get_amount_as_i64(),
            ),
            item.router_data.request.currency,
        )
        .change_context(errors::ConnectorError::AmountConversionFailed)?
        .to_string();

        let order = Some(FiservemeaOrder {
            order_id: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
        });

        Ok(Self {
            request_type: "PaymentCardPreAuthTransaction".to_string(),
            transaction_amount: FiservemeaTransactionAmount {
                total: amount,
                currency: item.router_data.request.currency.to_string(),
            },
            payment_method: FiservemeaPaymentMethod {
                payment_card: FiservemeaPaymentCard {
                    number: card_number,
                    security_code: card_cvv,
                    expiry_date: FiservemeaExpiryDate {
                        month: card_expiry_month,
                        year: card_expiry_year,
                    },
                },
            },
            order,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeResponse {
    pub ipg_transaction_id: String,
    pub transaction_result: FiservemeaTransactionResult,
    pub transaction_state: FiservemeaTransactionState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_amount: Option<FiservemeaTransactionAmount>,
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

pub fn map_fiservemea_status_to_attempt_status(
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
        (FiservemeaTransactionResult::Declined, _)
        | (FiservemeaTransactionResult::Failed, _) => AttemptStatus::Failure,
        (FiservemeaTransactionResult::Waiting, _) => AttemptStatus::Pending,
        _ => AttemptStatus::Pending,
    }
}

impl<T: PaymentMethodDataTypes>
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
        let status =
            map_fiservemea_status_to_attempt_status(&item.response.transaction_result, &item.response.transaction_state);

        Ok(Self {
            connector: item.router_data.connector,
            router_data: RouterDataV2 {
                response: Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(
                        item.response.ipg_transaction_id,
                    ),
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
                    ..item.router_data.router_data.resource_common_data
                },
                ..item.router_data.router_data
            },
        })
    }
}
