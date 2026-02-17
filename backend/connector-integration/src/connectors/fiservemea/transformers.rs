use crate::types::ResponseRouterData;
use common_enums::AttemptStatus;
use common_utils::types::{AmountConvertor, StringMajorUnit, StringMajorUnitForConnector};
use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId},
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeRequest<T: PaymentMethodDataTypes> {
    pub request_type: String,
    pub transaction_amount: FiservemeaTransactionAmount,
    pub payment_method: FiservemeaPaymentMethod<T>,
    pub order: Option<FiservemeaOrder>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaTransactionAmount {
    pub total: StringMajorUnit,
    pub currency: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "paymentMethodType")]
pub enum FiservemeaPaymentMethod<T: PaymentMethodDataTypes> {
    #[serde(rename = "card")]
    PaymentCard(FiservemeaPaymentCard<T>),
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentCard<T: PaymentMethodDataTypes> {
    pub number: RawCardNumber<T>,
    pub security_code: Secret<String>,
    pub expiry_date: FiservemeaExpiryDate,
}

#[derive(Debug, Clone, Serialize)]
pub struct FiservemeaExpiryDate {
    pub month: String,
    pub year: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaOrder {
    pub order_id: String,
    pub billing: Option<FiservemeaBillingAddress>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaBillingAddress {
    pub name: Option<String>,
    pub address1: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthorizeResponse {
    pub ipg_transaction_id: String,
    pub transaction_result: FiservemeaTransactionResult,
    pub transaction_state: FiservemeaTransactionState,
    pub approval_code: Option<String>,
    pub scheme_response_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FiservemeaTransactionResult {
    Approved,
    Declined,
    Failed,
    Waiting,
    Partial,
    Fraud,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
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
        let amount_converter = StringMajorUnitForConnector;
        let amount_in_major_units = amount_converter
            .convert(item.request.amount, item.request.currency)
            .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;

        let payment_method = match &item.request.payment_method_data {
            PaymentMethodData::Card(card) => {
                let expiry_month = card.card_exp_month.clone().expose();
                let expiry_year = card.card_exp_year.clone().expose();
                let month = if expiry_month.len() == 1 {
                    format!("0{}", expiry_month)
                } else {
                    expiry_month.clone()
                };
                let year = if expiry_year.len() == 2 {
                    format!("20{}", expiry_year)
                } else {
                    expiry_year.clone()
                };

                FiservemeaPaymentMethod::PaymentCard(FiservemeaPaymentCard {
                    number: card.card_number.clone(),
                    security_code: card.card_cvc.clone(),
                    expiry_date: FiservemeaExpiryDate { month, year },
                })
            }
            _ => {
                return Err(error_stack::report!(
                    errors::ConnectorError::NotImplemented("Payment method not supported".into())
                ))
            }
        };

        let billing_address = item
            .resource_common_data
            .address
            .get_payment_billing()
            .and_then(|addr| addr.address.as_ref())
            .map(|addr_details| FiservemeaBillingAddress {
                name: item.request.customer_name.clone(),
                address1: addr_details.line1.as_ref().map(|s| s.expose().clone()),
                city: addr_details.city.as_ref().map(|s| s.expose().clone()),
                state: addr_details.state.as_ref().map(|s| s.expose().clone()),
                postal_code: addr_details.zip.as_ref().map(|s| s.expose().clone()),
                country: addr_details.country.map(|c| c.to_string()),
            });

        let order = Some(FiservemeaOrder {
            order_id: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            billing: billing_address,
        });

        Ok(Self {
            request_type: "PaymentCardPreAuthTransaction".to_string(),
            transaction_amount: FiservemeaTransactionAmount {
                total: amount_in_major_units,
                currency: item.request.currency.to_string(),
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
        );

        let error_response = if matches!(
            status,
            AttemptStatus::Failure | AttemptStatus::AutoRefunded
        ) {
            Some(errors::router_data::ErrorResponse {
                status_code: item.http_code,
                code: item
                    .response
                    .scheme_response_code
                    .unwrap_or_else(|| "UNKNOWN".to_string()),
                message: item
                    .response
                    .error_message
                    .unwrap_or_else(|| "Transaction failed".to_string()),
                reason: None,
                attempt_status: Some(status),
                connector_transaction_id: Some(item.response.ipg_transaction_id.clone()),
                network_decline_code: item.response.scheme_response_code,
                network_advice_code: None,
                network_error_message: item.response.error_message,
            })
        } else {
            None
        };

        Ok(Self {
            response: error_response.map_or_else(
                || {
                    Ok(PaymentsResponseData::TransactionResponse {
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
                    })
                },
                Err,
            ),
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
        (FiservemeaTransactionResult::Waiting, _)
        | (FiservemeaTransactionResult::Partial, _) => AttemptStatus::Pending,
        _ => AttemptStatus::Pending,
    }
}