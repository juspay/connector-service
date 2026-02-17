use crate::types::ResponseRouterData;
use common_enums::AttemptStatus;
use common_utils::{errors::CustomResult, types::StringMajorUnit};
use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId},
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

use super::FiservemeaRouterData;

#[derive(Debug, Clone)]
pub struct FiservemeaAuthType {
    pub api_key: Secret<String>,
    pub api_secret: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for FiservemeaAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, api_secret } => Ok(Self {
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

pub fn generate_message_signature(
    api_key: &str,
    client_request_id: &str,
    timestamp: &str,
    api_secret: &str,
) -> CustomResult<String, errors::ConnectorError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let message = format!("{}{}{}", api_key, client_request_id, timestamp);
    
    let mut mac = Hmac::<Sha256>::new_from_slice(api_secret.as_bytes())
        .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;
    mac.update(message.as_bytes());
    let signature = mac.finalize().into_bytes();
    
    Ok(base64::encode(signature))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiservemeaErrorResponse {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaTransactionAmount {
    pub total: String,
    pub currency: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaCard<T> {
    pub card_number: Secret<String>,
    pub card_expiry_year: String,
    pub card_expiry_month: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_cvn: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_holder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub _phantom: Option<std::marker::PhantomData<T>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "paymentMethodType", rename_all = "camelCase")]
pub enum FiservemeaPaymentMethod<T> {
    Card(FiservemeaCard<T>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaOrder {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeRequest<T> {
    pub request_type: String,
    pub transaction_amount: FiservemeaTransactionAmount,
    pub payment_method: FiservemeaPaymentMethod<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<FiservemeaOrder>,
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
        (FiservemeaTransactionResult::Approved, FiservemeaTransactionState::Settled) => {
            AttemptStatus::Charged
        }
        (FiservemeaTransactionResult::Approved, FiservemeaTransactionState::Pending) => {
            AttemptStatus::Pending
        }
        (FiservemeaTransactionResult::Approved, FiservemeaTransactionState::Waiting) => {
            AttemptStatus::Pending
        }
        (FiservemeaTransactionResult::Approved, FiservemeaTransactionState::Initialized) => {
            AttemptStatus::Pending
        }
        (FiservemeaTransactionResult::Approved, FiservemeaTransactionState::Ready) => {
            AttemptStatus::Pending
        }
        (FiservemeaTransactionResult::Declined, _) => AttemptStatus::Failure,
        (FiservemeaTransactionResult::Failed, _) => AttemptStatus::Failure,
        (FiservemeaTransactionResult::Fraud, _) => AttemptStatus::Failure,
        (FiservemeaTransactionResult::Waiting, _) => AttemptStatus::Pending,
        (FiservemeaTransactionResult::Partial, FiservemeaTransactionState::Captured) => {
            AttemptStatus::Charged
        }
        (FiservemeaTransactionResult::Partial, FiservemeaTransactionState::Authorized) => {
            AttemptStatus::Authorized
        }
        (FiservemeaTransactionResult::Partial, _) => AttemptStatus::Pending,
        (_, FiservemeaTransactionState::Voided) => AttemptStatus::Voided,
        (_, FiservemeaTransactionState::Declined) => AttemptStatus::Failure,
        _ => AttemptStatus::Pending,
    }
}

impl<T: PaymentMethodDataTypes> TryFrom<&FiservemeaRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for FiservemeaAuthorizeRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &FiservemeaRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let payment_method_data = router_data
            .request
            .payment_method_data
            .as_ref()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "payment_method_data",
            })?;

        let card = match payment_method_data {
            PaymentMethodData::Card(card) => card,
            _ => {
                return Err(error_stack::report!(
                    errors::ConnectorError::NotImplemented("Only card payments are supported".to_string())
                ))
            }
        };

        let card_number = card
            .card_number
            .as_ref()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "card_number",
            })?;

        let expiry_month = card
            .card_exp_month
            .as_ref()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "card_exp_month",
            })?;

        let expiry_year = card
            .card_exp_year
            .as_ref()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "card_exp_year",
            })?;

        let amount_converter = StringMajorUnit;
        let amount = amount_converter.convert(router_data.request.minor_amount.get_amount_as_i64());

        let request_type = match router_data.request.capture_method {
            Some(capture_method) => {
                if capture_method == common_enums::CaptureMethod::AutomaticMultiple
                    || capture_method == common_enums::CaptureMethod::ManualMultiple
                {
                    "PaymentCardPreAuthTransaction"
                } else {
                    "PaymentCardSaleTransaction"
                }
            }
            None => "PaymentCardSaleTransaction",
        };

        Ok(Self {
            request_type: request_type.to_string(),
            transaction_amount: FiservemeaTransactionAmount {
                total: amount,
                currency: router_data.request.currency.to_string(),
            },
            payment_method: FiservemeaPaymentMethod::Card(FiservemeaCard {
                card_number: card_number.clone(),
                card_expiry_year: expiry_year.to_string(),
                card_expiry_month: format!("{:02}", expiry_month),
                card_cvn: card.card_cvn.clone(),
                card_holder: card.card_holder_name.clone(),
                card_type: card.card_network.map(|n| n.to_string()),
                _phantom: None,
            }),
            order: Some(FiservemeaOrder {
                order_id: Some(
                    router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                ),
                order_description: None,
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
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
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