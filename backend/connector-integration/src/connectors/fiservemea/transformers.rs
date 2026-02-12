use crate::types::ResponseRouterData;
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
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret};
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaErrorResponse {
    pub client_request_id: String,
    pub api_trace_id: String,
    pub response_type: FiservemeaResponseType,
    pub error: FiservemeaErrorDetail,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservemeaResponseType {
    BadRequest,
    Unauthenticated,
    Unauthorized,
    NotFound,
    GatewayDeclined,
    EndpointDeclined,
    ServerError,
    EndpointCommunicationError,
    UnsupportedMediaType,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaErrorDetail {
    pub code: String,
    pub message: String,
    pub decline_reason_code: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeRequest<T: PaymentMethodDataTypes> {
    pub request_type: String,
    pub transaction_amount: FiservemeaTransactionAmount,
    pub payment_method: FiservemeaPaymentMethod<T>,
    pub order: Option<FiservemeaOrder>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaTransactionAmount {
    pub total: String,
    pub currency: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentMethod<T: PaymentMethodDataTypes> {
    pub payment_card: FiservemeaPaymentCard<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentCard<T: PaymentMethodDataTypes> {
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaOrder {
    pub order_id: String,
    pub billing: Option<FiservemeaBilling>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaBilling {
    pub name: String,
    pub customer_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeResponse {
    pub client_request_id: String,
    pub api_trace_id: String,
    pub ipg_transaction_id: String,
    pub order_id: String,
    pub transaction_type: String,
    pub transaction_result: FiservemeaTransactionResult,
    pub transaction_state: FiservemeaTransactionState,
    pub approval_code: Option<String>,
    pub scheme_response_code: Option<String>,
    pub error_message: Option<String>,
    pub processor: Option<FiservemeaProcessor>,
    pub error: Option<FiservemeaErrorDetail>,
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
    Pending,
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
    pub association_response_code: Option<String>,
    pub association_response_message: Option<String>,
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
        | (FiservemeaTransactionResult::Approved, FiservemeaTransactionState::Pending)
        | (FiservemeaTransactionResult::Approved, FiservemeaTransactionState::Waiting) => {
            AttemptStatus::Pending
        }
        (FiservemeaTransactionResult::Declined, _)
        | (FiservemeaTransactionResult::Failed, _)
        | (_, FiservemeaTransactionState::Declined) => AttemptStatus::Failure,
        (FiservemeaTransactionResult::Fraud, _) => AttemptStatus::Failure,
        _ => AttemptStatus::Failure,
    }
}

pub struct FiservemeaRouterData<T, U> {
    pub amount: StringMajorUnit,
    pub router_data: T,
    pub connector: U,
}

impl<T, U> TryFrom<(StringMajorUnit, T, U)> for FiservemeaRouterData<T, U> {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from((amount, router_data, connector): (StringMajorUnit, T, U)) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            router_data,
            connector,
        })
    }
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        FiservemeaRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    > for FiservemeaAuthorizeRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: FiservemeaRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        let payment_method = match &router_data.request.payment_method_data {
            PaymentMethodData::Card(card_data) => {
                let expiry_month = card_data
                    .card_exp_month
                    .expose()
                    .chars()
                    .take(2)
                    .collect::<String>();
                let expiry_year = card_data
                    .card_exp_year
                    .expose()
                    .chars()
                    .skip(2)
                    .take(2)
                    .collect::<String>();

                FiservemeaPaymentMethod {
                    payment_card: FiservemeaPaymentCard {
                        number: card_data.card_number.clone(),
                        security_code: card_data.card_cvc.clone(),
                        expiry_date: FiservemeaExpiryDate {
                            month: expiry_month,
                            year: expiry_year,
                        },
                    },
                }
            }
            _ => {
                return Err(error_stack::report!(errors::ConnectorError::NotImplemented(
                    "Only card payments are supported".to_string(),
                )))
            }
        };

        let order = router_data
            .resource_common_data
            .connector_request_reference_id
            .as_ref()
            .map(|order_id| FiservemeaOrder {
                order_id: order_id.clone(),
                billing: router_data.request.customer_name.as_ref().map(|name| {
                    FiservemeaBilling {
                        name: name.clone(),
                        customer_id: router_data
                            .resource_common_data
                            .payment_id
                            .as_ref()
                            .map(|pid| pid.get_string_repr().to_string()),
                    }
                }),
            });

        Ok(Self {
            request_type: "PaymentCardPreAuthTransaction".to_string(),
            transaction_amount: FiservemeaTransactionAmount {
                total: item.amount.get_amount_as_string(),
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

        let status =
            map_fiservemea_status_to_attempt_status(&response.transaction_result, &response.transaction_state);

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.ipg_transaction_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(response.order_id.clone()),
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

pub fn generate_client_request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn generate_timestamp() -> i64 {
    common_utils::date_time::now_unix_timestamp_millis()
}

pub fn generate_message_signature(
    api_key: &str,
    client_request_id: &str,
    timestamp: i64,
    request_body: &str,
    api_secret: &str,
) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let message = format!("{}{}{}{}", api_key, client_request_id, timestamp, request_body);

    let mut mac = HmacSha256::new_from_slice(api_secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(message.as_bytes());

    let signature = mac.finalize().into_bytes();
    base64::engine::general_purpose::STANDARD.encode(signature)
}