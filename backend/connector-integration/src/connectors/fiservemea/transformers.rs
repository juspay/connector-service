use crate::types::ResponseRouterData;
use common_enums::AttemptStatus;
use common_utils::types::StringMinorUnit;
use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId},
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use hyperswitch_masking::{Mask, Maskable, Secret};
use masking::Secret as NewSecret;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct FiservemeaAuthType {
    pub api_key: Secret<String>,
    pub secret: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for FiservemeaAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, secret } => Ok(Self {
                api_key: api_key.to_owned(),
                secret: secret.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

impl FiservemeaAuthType {
    pub fn generate_client_request_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    pub fn generate_timestamp() -> String {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis().to_string())
            .unwrap_or_else(|_| "0".to_string())
    }

    pub fn generate_hmac_signature(
        &self,
        _api_key: &str,
        _client_request_id: &str,
        _timestamp: &str,
        request_body: &str,
    ) -> Result<String, errors::ConnectorError> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let secret_bytes = self.secret.expose().as_bytes();
        let mut mac =
            HmacSha256::new_from_slice(secret_bytes).map_err(|_| {
                errors::ConnectorError::InvalidRequestConfig {
                    message: "Invalid secret key length".to_string(),
                }
            })?;

        mac.update(request_body.as_bytes());
        let signature = mac.finalize().into_bytes();

        Ok(base64::encode(signature))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiservemeaErrorResponse {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeRequest<T> {
    pub request_type: String,
    pub transaction_amount: FiservemeaTransactionAmount,
    pub payment_method: FiservemeaPaymentMethod<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaTransactionAmount {
    pub total: String,
    pub currency: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum FiservemeaPaymentMethod<T> {
    Card(FiservemeaCardData),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaCardData {
    pub payment_card: FiservemeaPaymentCard,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeResponse {
    pub ipg_transaction_id: String,
    pub transaction_result: FiservemeaTransactionResult,
    pub transaction_state: FiservemeaTransactionState,
    pub approval_code: Option<String>,
    pub transaction_amount: Option<FiservemeaTransactionAmount>,
    pub processor: Option<FiservemeaProcessor>,
    pub error: Option<FiservemeaErrorDetail>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservemeaTransactionResult {
    Approved,
    Declined,
    Failed,
    Waiting,
    Partial,
    Fraud,
}

#[derive(Debug, Deserialize, Serialize)]
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaProcessor {
    pub authorization_code: Option<String>,
    pub response_code: Option<String>,
    pub response_message: Option<String>,
    pub network: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FiservemeaErrorDetail {
    pub code: Option<String>,
    pub message: Option<String>,
}

impl<T: PaymentMethodDataTypes> TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for FiservemeaAuthorizeRequest<T>
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
        let payment_method_data = item
            .request
            .payment_method_data
            .as_ref()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "payment_method_data",
            })?;

        let card_data = match payment_method_data {
            PaymentMethodDataTypes::Card(card) => card,
            _ => {
                return Err(error_stack::report!(
                    errors::ConnectorError::NotImplemented {
                        message: "Only card payments are supported".to_string(),
                    }
                ))
            }
        };

        let card_number = card
            .card_number
            .as_ref()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "card_number",
            })?;

        let card_cvc = card
            .card_cvc
            .as_ref()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "card_cvc",
            })?;

        let card_exp_month = card
            .card_exp_month
            .as_ref()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "card_exp_month",
            })?;

        let card_exp_year = card
            .card_exp_year
            .as_ref()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "card_exp_year",
            })?;

        let amount_str = StringMinorUnit::get_minor_unit_amount_as_string(
            item.request.minor_amount.get_amount_as_i64(),
        );

        let expiry_month = format!("{:02}", card_exp_month.get_inner_value());
        let expiry_year = format!("{:02}", card_exp_year.get_inner_value() % 100);

        Ok(Self {
            request_type: "PaymentCardPreAuthTransaction".to_string(),
            transaction_amount: FiservemeaTransactionAmount {
                total: amount_str,
                currency: item.request.currency.to_string(),
            },
            payment_method: FiservemeaPaymentMethod::Card(FiservemeaCardData {
                payment_card: FiservemeaPaymentCard {
                    number: Secret::new(card_number.get_inner_value().clone()),
                    security_code: Secret::new(card_cvc.get_inner_value().clone()),
                    expiry_date: FiservemeaExpiryDate {
                        month: expiry_month,
                        year: expiry_year,
                    },
                },
            }),
        })
    }
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            FiservemeaAuthorizeResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    >
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
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

        let network_txn_id = item
            .response
            .processor
            .as_ref()
            .and_then(|p| p.network.clone());

        let network_decline_code = item
            .response
            .processor
            .as_ref()
            .and_then(|p| p.response_code.clone());

        let network_error_message = item
            .response
            .processor
            .as_ref()
            .and_then(|p| p.response_message.clone());

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.ipg_transaction_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id,
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
        (FiservemeaTransactionResult::Declined, _)
        | (FiservemeaTransactionResult::Failed, _)
        | (FiservemeaTransactionResult::Fraud, _) => AttemptStatus::Failure,
        (FiservemeaTransactionResult::Waiting, _) => AttemptStatus::Pending,
        (FiservemeaTransactionResult::Partial, _) => AttemptStatus::PartiallyAuthorized,
        _ => AttemptStatus::Pending,
    }
}