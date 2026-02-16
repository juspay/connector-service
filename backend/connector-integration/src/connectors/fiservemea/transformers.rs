use crate::types::ResponseRouterData;
use common_enums::AttemptStatus;
use common_utils::types::StringMajorUnit;
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
pub struct FiservemeaAuthorizeRequest<T: PaymentMethodDataTypes> {
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
    pub payment_card: Option<FiservemeaPaymentCard>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentCard {
    pub number: Secret<String>,
    pub expiry_date: FiservemeaExpiryDate,
    pub security_code: Secret<String>,
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
    pub address: FiservemeaAddress,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAddress {
    pub street: String,
    pub city: String,
    pub state_province: String,
    pub postal_code: String,
    pub country: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeResponse {
    pub ipg_transaction_id: String,
    pub transaction_result: FiservemeaTransactionResult,
    pub transaction_state: FiservemeaTransactionState,
    pub approval_code: Option<String>,
    pub scheme_response_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "UPPERCASE")]
pub enum FiservemeaTransactionResult {
    Approved,
    Declined,
    Failed,
    Waiting,
    Partial,
    Fraud,
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "UPPERCASE")]
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

#[derive(Debug, Serialize)]
pub struct FiservemeaPaymentsRequest {
    pub amount: i64,
    pub currency: String,
    pub reference: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
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
        let payment_method_data = &item.request.payment_method_data;

        let payment_card = match payment_method_data {
            PaymentMethodData::Card(card_data) => Some(FiservemeaPaymentCard {
                number: Secret::new(card_data.card_number.peek().to_string()),
                expiry_date: FiservemeaExpiryDate {
                    month: card_data.card_exp_month.expose().to_string(),
                    year: card_data.get_expiry_year_4_digit().expose().to_string(),
                },
                security_code: card_data.card_cvc.clone(),
            }),
            _ => return Err(errors::ConnectorError::NotSupported {
                message: "Payment method not supported".to_string(),
                connector: "Fiservemea",
            }
            .into()),
        };

        let request_type = match item.request.capture_method {
            Some(common_enums::CaptureMethod::Automatic) => "PaymentCardSaleTransaction".to_string(),
            Some(common_enums::CaptureMethod::Manual) | None => "PaymentCardPreAuthTransaction".to_string(),
        };

        let billing = item
            .resource_common_data
            .address
            .get_payment_billing()
            .and_then(|addr| {
                Some(FiservemeaBilling {
                    name: item
                        .resource_common_data
                        .get_billing_full_name()
                        .ok()
                        .unwrap_or_default(),
                    address: FiservemeaAddress {
                        street: addr.line1.clone().unwrap_or_default(),
                        city: addr.city.clone().unwrap_or_default(),
                        state_province: addr.state.clone().unwrap_or_default(),
                        postal_code: addr.zip.clone().unwrap_or_default(),
                        country: addr
                            .country
                            .as_ref()
                            .and_then(|c| c.convert_country_alpha2_to_alpha3())
                            .unwrap_or_default(),
                    },
                })
            });

        let order = Some(FiservemeaOrder {
            order_id: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            billing,
        });

        Ok(Self {
            request_type,
            transaction_amount: FiservemeaTransactionAmount {
                total: item.amount,
                currency: item.request.currency.to_string(),
            },
            payment_method: FiservemeaPaymentMethod { payment_card },
            order,
        })
    }
}

fn map_fiservemea_status_to_attempt_status(
    transaction_result: FiservemeaTransactionResult,
    transaction_state: FiservemeaTransactionState,
) -> AttemptStatus {
    match (transaction_result, transaction_state) {
        (FiservemeaTransactionResult::Approved, FiservemeaTransactionState::Captured) => {
            AttemptStatus::Charged
        }
        (FiservemeaTransactionResult::Approved, FiservemeaTransactionState::Authorized) => {
            AttemptStatus::Authorized
        }
        (FiservemeaTransactionResult::Declined, _) | (FiservemeaTransactionResult::Failed, _) => {
            AttemptStatus::Failure
        }
        (FiservemeaTransactionResult::Waiting, FiservemeaTransactionState::Pending) => {
            AttemptStatus::Pending
        }
        (_, FiservemeaTransactionState::Voided) => AttemptStatus::Voided,
        (FiservemeaTransactionResult::Fraud, _) => AttemptStatus::Failure,
        _ => AttemptStatus::Pending,
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
            item.response.transaction_result,
            item.response.transaction_state,
        );

        Ok(Self {
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
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}
