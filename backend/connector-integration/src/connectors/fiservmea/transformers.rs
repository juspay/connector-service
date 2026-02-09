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

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservemeaStatus {
    Approved,
    Declined,
    Pending,
    Processing,
    Failed,
    Cancelled,
    Unknown,
}

pub fn map_fiservemea_status_to_attempt_status(
    status: FiservemeaStatus,
) -> AttemptStatus {
    match status {
        FiservemeaStatus::Approved => AttemptStatus::Charged,
        FiservemeaStatus::Declined => AttemptStatus::AuthorizationFailed,
        FiservemeaStatus::Pending => AttemptStatus::Pending,
        FiservemeaStatus::Processing => AttemptStatus::Processing,
        FiservemeaStatus::Failed => AttemptStatus::Failure,
        FiservemeaStatus::Cancelled => AttemptStatus::Voided,
        FiservemeaStatus::Unknown => AttemptStatus::Pending,
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeRequest<T: PaymentMethodDataTypes> {
    pub amount: u64,
    pub currency: String,
    pub payment_method: FiservemeaPaymentMethod<T>,
    pub merchant_reference: Option<String>,
    pub customer: Option<CustomerData>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum FiservemeaPaymentMethod<T: PaymentMethodDataTypes> {
    Card(CardData),
    Wallet(WalletData),
    BankTransfer(BankTransferData),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardData {
    pub number: String,
    pub exp_month: String,
    pub exp_year: String,
    pub cvc: Option<String>,
    pub holder_name: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletData {
    pub wallet_type: String,
    pub wallet_token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BankTransferData {
    pub bank_account_number: String,
    pub bank_routing_number: String,
    pub account_holder_name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomerData {
    pub email: Option<String>,
    pub phone: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeResponse {
    pub id: String,
    pub status: FiservemeaStatus,
    pub amount: u64,
    pub currency: String,
    pub created_at: String,
    pub response_code: Option<String>,
    pub response_message: Option<String>,
    pub risk_data: Option<RiskData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskData {
    pub score: Option<i32>,
    pub decision: Option<String>,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
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
        let payment_method = match &item.request.payment_method_data {
            domain_types::payment_method_data::PaymentMethodData::Card(card_data) => {
                FiservemeaPaymentMethod::Card(CardData {
                    number: card_data.card_number.get_card_number().to_string(),
                    exp_month: card_data.card_exp_month.peek().to_string(),
                    exp_year: card_data.card_exp_year.peek().to_string(),
                    cvc: Some(card_data.card_cvc.peek().to_string()),
                    holder_name: item.request.customer_name.as_ref().map(|n| n.peek().to_string()),
                })
            }
            _ => {
                return Err(error_stack::report!(
                    errors::ConnectorError::NotImplemented("Payment method not supported".to_string())
                ))
            }
        };

        let customer = item
            .request
            .email
            .as_ref()
            .map(|email| CustomerData {
                email: Some(email.peek().to_string()),
                phone: None,
                name: item.request.customer_name.as_ref().map(|n| n.peek().to_string()),
            });

        Ok(Self {
            amount: item.request.minor_amount.get_amount_as_u64(),
            currency: item.request.currency.to_string(),
            payment_method,
            merchant_reference: Some(
                item.resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
            customer,
            metadata: None,
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
        let status = map_fiservemea_status_to_attempt_status(item.response.status);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id),
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