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
};
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
            ConnectorAuthType::SignatureKey {
                api_key,
                key1: _,
                api_secret,
            } => Ok(Self {
                api_key: api_key.clone(),
                api_secret: api_secret.clone(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaErrorResponse {
    pub code: String,
    pub message: String,
    pub reason: Option<String>,
    pub ipg_transaction_id: Option<String>,
    pub scheme_response_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeRequest {
    pub request_type: String,
    pub transaction_amount: FiservemeaTransactionAmount,
    pub payment_method: FiservemeaPaymentMethod,
    pub order: Option<FiservemeaOrder>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaTransactionAmount {
    pub total: StringMajorUnit,
    pub currency: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentMethod {
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
#[serde(rename_all = "camelCase")]
pub struct FiservemeaExpiryDate {
    pub month: String,
    pub year: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaOrder {
    pub order_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeResponse {
    pub ipg_transaction_id: String,
    pub transaction_result: FiservemeaTransactionResult,
    pub transaction_state: FiservemeaTransactionState,
    pub approval_code: Option<String>,
    pub scheme_response_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum FiservemeaTransactionResult {
    Approved,
    Declined,
    Failed,
    Waiting,
    Partial,
    Fraud,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum FiservemeaTransactionState {
    Authorized,
    Captured,
    Declined,
    Pending,
    Settled,
    Voided,
    Waiting,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + serde::Serialize>
    TryFrom<
        super::FiservemeaRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    > for FiservemeaAuthorizeRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: super::FiservemeaRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let req = &item.router_data;

        let payment_method = match req.request.payment_method_data.clone() {
            domain_types::payment_method_data::PaymentMethodData::Card(card_data) => {
                let year_4digit = card_data.get_expiry_year_4_digit().expose();
                let year_2digit = if year_4digit.len() >= 2 {
                    year_4digit[year_4digit.len() - 2..].to_string()
                } else {
                    year_4digit.clone()
                };

                FiservemeaPaymentMethod {
                    payment_card: FiservemeaPaymentCard {
                        number: Secret::new(card_data.card_number.peek().to_string()),
                        security_code: card_data.card_cvc,
                        expiry_date: FiservemeaExpiryDate {
                            month: card_data.card_exp_month.expose(),
                            year: year_2digit,
                        },
                    },
                }
            }
            _ => {
                return Err(errors::ConnectorError::NotSupported {
                    message: "Payment Method".to_string(),
                    connector: "Fiservemea",
                }
                .into())
            }
        };

        let request_type = match req.request.capture_method {
            Some(common_enums::CaptureMethod::Manual) => "PaymentCardPreAuthTransaction",
            Some(common_enums::CaptureMethod::Automatic) | None => "PaymentCardSaleTransaction",
            _ => "PaymentCardSaleTransaction",
        };

        let amount = item
            .connector
            .amount_converter
            .convert(req.request.minor_amount, req.request.currency)
            .map_err(|e| {
                errors::ConnectorError::RequestEncodingFailedWithReason(format!(
                    "Amount conversion failed: {e}"
                ))
            })?;

        let order = Some(FiservemeaOrder {
            order_id: req.resource_common_data.connector_request_reference_id.clone(),
        });

        Ok(Self {
            request_type: request_type.to_string(),
            transaction_amount: FiservemeaTransactionAmount {
                total: amount,
                currency: req.request.currency.to_string(),
            },
            payment_method,
            order,
        })
    }
}

fn map_fiservemea_status_to_attempt_status(
    transaction_result: &FiservemeaTransactionResult,
    transaction_state: &FiservemeaTransactionState,
    _capture_method: Option<common_enums::CaptureMethod>,
) -> AttemptStatus {
    match (transaction_result, transaction_state) {
        (FiservemeaTransactionResult::Approved, FiservemeaTransactionState::Authorized) => {
            AttemptStatus::Authorized
        }
        (FiservemeaTransactionResult::Approved, FiservemeaTransactionState::Captured)
        | (FiservemeaTransactionResult::Approved, FiservemeaTransactionState::Settled) => {
            AttemptStatus::Charged
        }
        (FiservemeaTransactionResult::Approved, FiservemeaTransactionState::Declined)
        | (FiservemeaTransactionResult::Approved, FiservemeaTransactionState::Pending)
        | (FiservemeaTransactionResult::Approved, FiservemeaTransactionState::Waiting) => {
            AttemptStatus::Pending
        }
        (FiservemeaTransactionResult::Approved, FiservemeaTransactionState::Voided) => {
            AttemptStatus::Voided
        }
        (FiservemeaTransactionResult::Declined, _)
        | (FiservemeaTransactionResult::Failed, _) => AttemptStatus::Failure,
        (FiservemeaTransactionResult::Waiting, _)
        | (_, FiservemeaTransactionState::Pending)
        | (_, FiservemeaTransactionState::Waiting) => AttemptStatus::Pending,
        (_, FiservemeaTransactionState::Voided) => AttemptStatus::Voided,
        (FiservemeaTransactionResult::Partial, _) => AttemptStatus::Pending,
        (FiservemeaTransactionResult::Fraud, _) => AttemptStatus::Failure,
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
            item.router_data.request.capture_method,
        );

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.ipg_transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: item.response.approval_code.clone(),
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