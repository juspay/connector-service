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
pub struct FiservemeaPaymentsRequest<T: PaymentMethodDataTypes> {
    pub request_type: String,
    pub transaction_amount: TransactionAmount,
    pub payment_method: PaymentMethod,
    pub order: Option<Order>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionAmount {
    pub total: i64,
    pub currency: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PaymentMethod {
    PaymentCard(PaymentCard),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentCard {
    pub number: RawCardNumber<T>,
    pub security_code: Secret<String>,
    pub expiry_date: ExpiryDate,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RawCardNumber<T: PaymentMethodDataTypes> {
    pub value: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpiryDate {
    pub month: String,
    pub year: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    pub id: String,
    pub amount: i64,
    pub currency: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentsResponse {
    pub client_request_id: String,
    pub ipg_transaction_id: String,
    pub transaction_type: String,
    pub transaction_result: String,
    pub transaction_state: String,
    pub approved_amount: ApprovedAmount,
    pub processor: ProcessorResponse,
    pub payment_method_details: PaymentMethodDetails,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovedAmount {
    pub total: i64,
    pub currency: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessorResponse {
    pub response_code: String,
    pub response_message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentMethodDetails {
    pub payment_card: Option<PaymentCardDetails>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentCardDetails {
    pub card_number: String,
    pub cardholder_name: Option<String>,
    pub expiry_date: ExpiryDate,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
    > for FiservemeaPaymentsRequest<T>
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
                PaymentMethod::PaymentCard(PaymentCard {
                    number: RawCardNumber {
                        value: card_data.card_number.get_card_number().to_string(),
                    },
                    security_code: card_data.card_cvc.clone(),
                    expiry_date: ExpiryDate {
                        month: card_data.card_exp_month.peek().to_string(),
                        year: card_data.card_exp_year.peek().to_string(),
                    },
                })
            }
            _ => {
                return Err(error_stack::report!(
                    errors::ConnectorError::NotImplemented("Payment method not supported".to_string())
                ))
            }
        };

        let request_type = if item.request.is_pre_auth {
            "PaymentCardPreAuthTransaction".to_string()
        } else {
            "PaymentCardSaleTransaction".to_string()
        };

        Ok(Self {
            request_type,
            transaction_amount: TransactionAmount {
                total: item.request.minor_amount.get_amount_as_i64(),
                currency: item.request.currency.to_string(),
            },
            payment_method,
            order: None,
        })
    }
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            FiservemeaPaymentsResponse,
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
            FiservemeaPaymentsResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let status = map_fiservemea_status_to_attempt_status(
            FiservemeaStatus::from_str(&item.response.transaction_state)
                .unwrap_or(FiservemeaStatus::Unknown)
        );

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.ipg_transaction_id),
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

impl FiservemeaStatus {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "AUTHORIZED" => Some(FiservemeaStatus::Approved),
            "CAPTURED" => Some(FiservemeaStatus::Approved),
            "DECLINED" => Some(FiservemeaStatus::Declined),
            "SETTLED" => Some(FiservemeaStatus::Approved),
            "VOIDED" => Some(FiservemeaStatus::Cancelled),
            "WAITING" => Some(FiservemeaStatus::Pending),
            "PROCESSING" => Some(FiservemeaStatus::Processing),
            "FAILED" => Some(FiservemeaStatus::Failed),
            _ => None,
        }
    }
}