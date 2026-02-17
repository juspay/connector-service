use crate::types::ResponseRouterData;
use common_enums::{AttemptStatus, Currency};
use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId},
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    pub details: Vec<ErrorDetail>,
    pub decline_reason_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub field: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionAmount {
    pub total: String,
    pub currency: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentCard {
    pub number: String,
    pub security_code: String,
    pub expiry_date: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentMethod {
    pub payment_card: PaymentCard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    pub order_id: String,
    pub billing: HashMap<String, String>,
    pub shipping: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationRequest {
    pub authentication_type: String,
    pub authentication_data: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FiservemeaAuthorizeRequest<T: PaymentMethodDataTypes> {
    pub request_type: String,
    pub transaction_amount: TransactionAmount,
    pub payment_method: PaymentMethod,
    pub order: Option<Order>,
    pub authentication_request: Option<AuthenticationRequest>,
    pub client_request_id: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovedAmount {
    pub total: String,
    pub currency: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentMethodDetails {
    pub payment_card: PaymentCard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Processor {
    pub name: String,
    pub response_code: String,
    pub response_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiservemeaAuthorizeResponse {
    pub client_request_id: String,
    pub api_trace_id: String,
    pub ipg_transaction_id: String,
    pub order_id: String,
    pub transaction_type: String,
    pub transaction_result: String,
    pub transaction_state: String,
    pub approved_amount: ApprovedAmount,
    pub payment_method_details: PaymentMethodDetails,
    pub processor: Processor,
    pub error: Option<FiservemeaErrorResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FiservemeaStatus {
    Authorized,
    Captured,
    Declined,
    Settled,
    Voided,
    Waiting,
    Processing,
    Failed,
}

impl TryFrom<&str> for FiservemeaStatus {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "AUTHORIZED" => Ok(FiservemeaStatus::Authorized),
            "CAPTURED" => Ok(FiservemeaStatus::Captured),
            "DECLINED" => Ok(FiservemeaStatus::Declined),
            "SETTLED" => Ok(FiservemeaStatus::Settled),
            "VOIDED" => Ok(FiservemeaStatus::Voided),
            "WAITING" => Ok(FiservemeaStatus::Waiting),
            "PROCESSING" => Ok(FiservemeaStatus::Processing),
            "FAILED" => Ok(FiservemeaStatus::Failed),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

pub fn map_fiservemea_status_to_attempt_status(status: &FiservemeaStatus) -> AttemptStatus {
    match status {
        FiservemeaStatus::Authorized => AttemptStatus::Authorized,
        FiservemeaStatus::Captured => AttemptStatus::Charged,
        FiservemeaStatus::Settled => AttemptStatus::Charged,
        FiservemeaStatus::Declined => AttemptStatus::Failure,
        FiservemeaStatus::Failed => AttemptStatus::Failure,
        FiservemeaStatus::Voided => AttemptStatus::Voided,
        FiservemeaStatus::Waiting | FiservemeaStatus::Processing => AttemptStatus::Pending,
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
        let amount = item.request.minor_amount.get_amount_as_i64();
        let currency = item.request.currency.to_string();
        let client_request_id = item
            .resource_common_data
            .connector_request_reference_id
            .clone();

        let request_type = "PaymentCardPreAuthTransaction".to_string();

        let payment_card = match &item.request.payment_method_data {
            PaymentMethodData::Card(card_data) => PaymentCard {
                number: card_data.card_number.peek().to_string(),
                security_code: card_data.card_cvc.clone().into_inner(),
                expiry_date: format!(
                    "{}{}",
                    card_data.card_exp_month.clone().expose(),
                    card_data.get_expiry_year_4_digit().clone().expose()
                ),
            },
            _ => return Err(error_stack::report!(errors::ConnectorError::RequestEncodingFailed)),
        };

        let payment_method = PaymentMethod { payment_card };

        let order = None;

        let authentication_request = None;

        let timestamp = chrono::Utc::now().to_rfc3339();

        Ok(Self {
            request_type,
            transaction_amount: TransactionAmount {
                total: amount.to_string(),
                currency,
            },
            payment_method,
            order,
            authentication_request,
            client_request_id,
            timestamp,
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
    > for RouterDataV2<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    >
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
        let response = item.response;

        let status = if let Some(error) = &response.error {
            AttemptStatus::Failure
        } else {
            let fiservemea_status = FiservemeaStatus::try_from(response.transaction_state.as_str())
                .unwrap_or(FiservemeaStatus::Failed);
            map_fiservemea_status_to_attempt_status(&fiservemea_status)
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.ipg_transaction_id),
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
