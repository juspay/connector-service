use crate::types::ResponseRouterData;
use base64::{engine::general_purpose, Engine};
use common_enums::AttemptStatus;
use common_utils::{
    crypto::{self, SignMessage},
    types::{AmountConvertor, FloatMajorUnit, FloatMajorUnitForConnector},
};
use domain_types::{
    connector_flow::Authorize,
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct FiservemeaAuthType {
    pub api_key: Secret<String>,
    pub api_secret: Secret<String>,
}

impl FiservemeaAuthType {
    pub fn generate_hmac_signature(
        &self,
        api_key: &str,
        client_request_id: &str,
        timestamp: &str,
        request_body: &str,
    ) -> Result<String, error_stack::Report<errors::ConnectorError>> {
        let raw_signature = format!("{}{}{}{}", api_key, client_request_id, timestamp, request_body);
        let signature = crypto::HmacSha256
            .sign_message(
                self.api_secret.clone().expose().as_bytes(),
                raw_signature.as_bytes(),
            )
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        Ok(general_purpose::STANDARD.encode(signature))
    }

    pub fn generate_client_request_id() -> String {
        Uuid::new_v4().to_string()
    }

    pub fn generate_timestamp() -> String {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .to_string()
    }
}

impl TryFrom<&ConnectorAuthType> for FiservemeaAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1, .. } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: key1.to_owned(),
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
pub struct FiservemeaAuthorizeRequest<T: PaymentMethodDataTypes> {
    pub request_type: String,
    pub transaction_amount: TransactionAmount,
    pub payment_method: PaymentMethod,
    pub order: Option<Order>,
}

#[derive(Debug, Serialize)]
pub struct TransactionAmount {
    pub total: FloatMajorUnit,
    pub currency: common_enums::Currency,
}

#[derive(Debug, Serialize)]
pub struct Order {
    pub order_id: String,
}

#[derive(Debug, Serialize)]
pub struct PaymentMethod {
    pub payment_card: PaymentCard,
}

#[derive(Debug, Serialize)]
pub struct PaymentCard {
    pub number: RawCardNumber<T>,
    pub expiry_date: ExpiryDate,
    pub security_code: Secret<String>,
}

#[derive(Debug, Serialize)]
pub struct ExpiryDate {
    pub month: Secret<String>,
    pub year: Secret<String>,
}

#[derive(Debug, Deserialize)]
pub struct FiservemeaAuthorizeResponse {
    pub client_request_id: String,
    pub api_trace_id: String,
    pub ipg_transaction_id: String,
    pub order_id: String,
    pub transaction_type: String,
    pub transaction_result: String,
    pub transaction_state: String,
    pub approval_code: Option<String>,
    pub approved_amount: Option<ApprovedAmount>,
    pub processor: Option<Processor>,
    pub error: Option<Error>,
}

#[derive(Debug, Deserialize)]
pub struct ApprovedAmount {
    pub total: FloatMajorUnit,
    pub currency: common_enums::Currency,
}

#[derive(Debug, Deserialize)]
pub struct Processor {
    pub reference_number: String,
    pub authorization_code: String,
    pub response_code: String,
    pub response_message: String,
}

#[derive(Debug, Deserialize)]
pub struct Error {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservemeaStatus {
    Authorized,
    Declined,
    Failed,
    Waiting,
    Processing,
    Settled,
    Voided,
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
        let converter = FloatMajorUnitForConnector;
        let amount_major = converter
            .convert(item.request.minor_amount, item.request.currency)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        let transaction_amount = TransactionAmount {
            total: amount_major,
            currency: item.request.currency,
        };

        let payment_method = match &item.request.payment_method_data {
            PaymentMethodData::Card(card_data) => {
                let year_yy = card_data.get_card_expiry_year_2_digit()?;
                let payment_card = PaymentCard {
                    number: card_data.card_number.clone(),
                    expiry_date: ExpiryDate {
                        month: Secret::new(card_data.card_exp_month.peek().clone()),
                        year: year_yy,
                    },
                    security_code: card_data.card_cvc.clone(),
                };
                PaymentMethod { payment_card }
            }
            _ => {
                return Err(error_stack::report!(
                    errors::ConnectorError::NotImplemented(
                        "Only card payments are supported".to_string()
                    )
                ))
            }
        };

        let merchant_transaction_id = item
            .resource_common_data
            .connector_request_reference_id
            .clone();

        let order = Order {
            order_id: merchant_transaction_id.clone(),
        };

        Ok(Self {
            request_type: "PaymentCardPreAuthTransaction".to_string(),
            transaction_amount,
            payment_method,
            order: Some(order),
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
        let status = match item.response.transaction_state.as_str() {
            "AUTHORIZED" => AttemptStatus::Authorized,
            "SETTLED" => AttemptStatus::Charged,
            "WAITING" | "PROCESSING" => AttemptStatus::Pending,
            "DECLINED" | "FAILED" => AttemptStatus::Failure,
            "VOIDED" => AttemptStatus::Voided,
            _ => AttemptStatus::Pending,
        };

        let (network_txn_id, approval_code) = match &item.response.processor {
            Some(processor) => (
                Some(processor.reference_number.clone()),
                Some(processor.authorization_code.clone()),
            ),
            None => (None, None),
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.ipg_transaction_id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id,
                connector_response_reference_id: Some(item.response.client_request_id.clone()),
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
