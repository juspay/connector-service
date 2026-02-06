use std::fmt::Debug;

use common_utils::{
    errors::CustomResult,
    ext_traits::{ByteSliceExt, ValueExt},
    types::{AmountMinorUnit, MinorUnit},
};
use domain_types::{
    connector_flow::Authorize,
    errors::ConnectorError,
    payment_method_data::{ApplePayCard, BankTransfer, Card, GooglePayCard, PaymentMethodData},
    router_data_v2::RouterDataV2,
    types::MinorUnitForConnector,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable};
use serde::{Deserialize, Serialize};

use super::headers;

#[derive(Debug, Clone, Serialize)]
pub struct FiservemeaPaymentsRequest<T> {
    pub request_type: String,
    pub transaction_amount: FiservemeaTransactionAmount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method: Option<FiservemeaPaymentMethod<T>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<FiservemeaOrder>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FiservemeaTransactionAmount {
    pub total: String,
    pub currency: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FiservemeaPaymentMethod<T> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_card: Option<FiservemeaPaymentCard>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_token: Option<FiservemeaPaymentToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet: Option<FiservemeaWallet>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sepa: Option<FiservemeaSepa>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apm: Option<FiservemeaApm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method_brand: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub _phantom: Option<T>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FiservemeaPaymentCard {
    pub number: Maskable<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_code: Option<Maskable<String>>,
    pub expiry_date: FiservemeaExpiryDate,
}

#[derive(Debug, Clone, Serialize)]
pub struct FiservemeaExpiryDate {
    pub month: String,
    pub year: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FiservemeaPaymentToken {
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FiservemeaWallet {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apple_pay: Option<FiservemeaApplePay>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub google_pay: Option<FiservemeaGooglePay>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FiservemeaApplePay {
    pub payment_data: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FiservemeaGooglePay {
    pub payment_data: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FiservemeaSepa {
    pub iban: Maskable<String>,
    pub bic: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FiservemeaApm {
    pub payment_method_type: String,
    pub payment_data: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FiservemeaOrder {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing: Option<FiservemeaBilling>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FiservemeaBilling {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<FiservemeaAddress>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FiservemeaAddress {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FiservemeaAuthorizeResponse {
    pub client_request_id: String,
    pub api_trace_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipg_transaction_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_result: Option<FiservemeaTransactionResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_state: Option<FiservemeaTransactionState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme_response_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_amount: Option<FiservemeaAmount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processor: Option<FiservemeaProcessor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method_details: Option<FiservemeaPaymentMethodDetails>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FiservemeaSyncResponse {
    pub client_request_id: String,
    pub api_trace_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipg_transaction_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_result: Option<FiservemeaTransactionResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_state: Option<FiservemeaTransactionState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme_response_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_amount: Option<FiservemeaAmount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processor: Option<FiservemeaProcessor>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FiservemeaVoidRequest {
    pub request_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comments: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FiservemeaVoidResponse {
    pub client_request_id: String,
    pub api_trace_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipg_transaction_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_result: Option<FiservemeaTransactionResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_state: Option<FiservemeaTransactionState>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FiservemeaCaptureRequest {
    pub request_type: String,
    pub transaction_amount: FiservemeaTransactionAmount,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FiservemeaCaptureResponse {
    pub client_request_id: String,
    pub api_trace_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipg_transaction_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_result: Option<FiservemeaTransactionResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_state: Option<FiservemeaTransactionState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_amount: Option<FiservemeaAmount>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FiservemeaRefundRequest {
    pub request_type: String,
    pub transaction_amount: FiservemeaTransactionAmount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comments: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FiservemeaRefundResponse {
    pub client_request_id: String,
    pub api_trace_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipg_transaction_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_result: Option<FiservemeaTransactionResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_state: Option<FiservemeaTransactionState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_amount: Option<FiservemeaAmount>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FiservemeaRefundSyncResponse {
    pub client_request_id: String,
    pub api_trace_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipg_transaction_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_result: Option<FiservemeaTransactionResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_state: Option<FiservemeaTransactionState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_amount: Option<FiservemeaAmount>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FiservemeaErrorResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<FiservemeaErrorDetail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipg_transaction_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FiservemeaErrorDetail {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservemeaTransactionResult {
    Approved,
    Declined,
    Failed,
    Waiting,
    Partial,
    Fraud,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct FiservemeaAmount {
    pub total: f64,
    pub currency: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FiservemeaProcessor {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_code_response: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FiservemeaPaymentMethodDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method_brand: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FiservemeaRouterData<RD, T> {
    pub router_data: RD,
    pub _phantom: std::marker::PhantomData<T>,
}

impl<T: Debug + Clone + Serialize> TryFrom<&FiservemeaRouterData<RouterDataV2<Authorize, _, _, _>, T>>
    for FiservemeaPaymentsRequest<T>
{
    type Error = ConnectorError;

    fn try_from(
        value: &FiservemeaRouterData<RouterDataV2<Authorize, _, _, _>, T>,
    ) -> Result<Self, Self::Error> {
        let router_data = &value.router_data;
        let payment_method = router_data.request.payment_method_data.clone();

        let payment_method_obj = match payment_method {
            PaymentMethodData::Card(card) => Some(FiservemeaPaymentMethod {
                payment_card: Some(FiservemeaPaymentCard {
                    number: card.card_number.clone().into_masked(),
                    security_code: card.card_cvc.map(|c| c.into_masked()),
                    expiry_date: FiservemeaExpiryDate {
                        month: card.card_exp_month.clone(),
                        year: card.card_exp_year.clone(),
                    },
                }),
                payment_token: None,
                wallet: None,
                sepa: None,
                apm: None,
                payment_method_type: Some("PAYMENT_CARD".to_string()),
                payment_method_brand: Some(card.card_network.to_string()),
                _phantom: None,
            }),
            PaymentMethodData::ApplePayCard(apple_pay) => Some(FiservemeaPaymentMethod {
                payment_card: None,
                payment_token: None,
                wallet: Some(FiservemeaWallet {
                    apple_pay: Some(FiservemeaApplePay {
                        payment_data: apple_pay.payment_data.clone(),
                    }),
                    google_pay: None,
                }),
                sepa: None,
                apm: None,
                payment_method_type: Some("PAYPAL".to_string()),
                payment_method_brand: Some("APPLE_PAY".to_string()),
                _phantom: None,
            }),
            PaymentMethodData::GooglePayCard(google_pay) => Some(FiservemeaPaymentMethod {
                payment_card: None,
                payment_token: None,
                wallet: Some(FiservemeaWallet {
                    apple_pay: None,
                    google_pay: Some(FiservemeaGooglePay {
                        payment_data: google_pay.payment_data.clone(),
                    }),
                }),
                sepa: None,
                apm: None,
                payment_method_type: Some("PAYPAL".to_string()),
                payment_method_brand: Some("GOOGLE_PAY".to_string()),
                _phantom: None,
            }),
            PaymentMethodData::BankTransfer(bank_transfer) => Some(FiservemeaPaymentMethod {
                payment_card: None,
                payment_token: None,
                wallet: None,
                sepa: Some(FiservemeaSepa {
                    iban: bank_transfer.iban.clone().into_masked(),
                    bic: bank_transfer.bic.clone(),
                }),
                apm: None,
                payment_method_type: Some("SEPA".to_string()),
                payment_method_brand: None,
                _phantom: None,
            }),
            PaymentMethodData::PaymentToken(token) => Some(FiservemeaPaymentMethod {
                payment_card: None,
                payment_token: Some(FiservemeaPaymentToken {
                    value: token.token_value.clone(),
                }),
                wallet: None,
                sepa: None,
                apm: None,
                payment_method_type: Some("PAYMENT_TOKEN".to_string()),
                payment_method_brand: None,
                _phantom: None,
            }),
            _ => Err(ConnectorError::NotSupported {
                message: "Payment method not supported".to_string(),
            })?,
        };

        let order = router_data
            .request
            .order_details
            .as_ref()
            .map(|order| FiservemeaOrder {
                order_id: Some(order.order_id.clone()),
                billing: order.billing_address.as_ref().map(|addr| FiservemeaBilling {
                    name: addr.first_name.clone(),
                    address: Some(FiservemeaAddress {
                        street: addr.address.line1.clone(),
                        city: addr.city.clone(),
                        postal_code: addr.zip.clone(),
                        country: addr.country.clone(),
                    }),
                }),
            });

        Ok(FiservemeaPaymentsRequest {
            request_type: "PaymentCardSaleTransaction".to_string(),
            transaction_amount: FiservemeaTransactionAmount {
                total: router_data.request.amount.to_string(),
                currency: router_data.request.currency.to_string(),
            },
            payment_method: payment_method_obj,
            order,
        })
    }
}

impl<T> TryFrom<&FiservemeaRouterData<RouterDataV2<Void, _, _, _>, T>> for FiservemeaVoidRequest {
    type Error = ConnectorError;

    fn try_from(
        _value: &FiservemeaRouterData<RouterDataV2<Void, _, _, _>, T>,
    ) -> Result<Self, Self::Error> {
        Ok(FiservemeaVoidRequest {
            request_type: "VoidTransaction".to_string(),
            comments: None,
        })
    }
}

impl<T> TryFrom<&FiservemeaRouterData<RouterDataV2<Capture, _, _, _>, T>>
    for FiservemeaCaptureRequest
{
    type Error = ConnectorError;

    fn try_from(
        value: &FiservemeaRouterData<RouterDataV2<Capture, _, _, _>, T>,
    ) -> Result<Self, Self::Error> {
        let router_data = &value.router_data;
        Ok(FiservemeaCaptureRequest {
            request_type: "PostAuthTransaction".to_string(),
            transaction_amount: FiservemeaTransactionAmount {
                total: router_data.request.amount.to_string(),
                currency: router_data.request.currency.to_string(),
            },
        })
    }
}

impl<T> TryFrom<&FiservemeaRouterData<RouterDataV2<Refund, _, _, _>, T>> for FiservemeaRefundRequest {
    type Error = ConnectorError;

    fn try_from(
        value: &FiservemeaRouterData<RouterDataV2<Refund, _, _, _>, T>,
    ) -> Result<Self, Self::Error> {
        let router_data = &value.router_data;
        Ok(FiservemeaRefundRequest {
            request_type: "ReturnTransaction".to_string(),
            transaction_amount: FiservemeaTransactionAmount {
                total: router_data.request.amount.to_string(),
                currency: router_data.request.currency.to_string(),
            },
            comments: None,
        })
    }
}

pub fn map_fiservemea_status_to_attempt_status(
    result: &Option<FiservemeaTransactionResult>,
    state: &Option<FiservemeaTransactionState>,
) -> common_enums::AttemptStatus {
    match (result, state) {
        (Some(FiservemeaTransactionResult::Approved), Some(FiservemeaTransactionState::Authorized)) => {
            common_enums::AttemptStatus::Authorized
        }
        (Some(FiservemeaTransactionResult::Approved), Some(FiservemeaTransactionState::Captured)) => {
            common_enums::AttemptStatus::Charged
        }
        (Some(FiservemeaTransactionResult::Approved), Some(FiservemeaTransactionState::Settled)) => {
            common_enums::AttemptStatus::Charged
        }
        (Some(FiservemeaTransactionResult::Declined), _) | (_, Some(FiservemeaTransactionState::Declined)) => {
            common_enums::AttemptStatus::Failure
        }
        (Some(FiservemeaTransactionResult::Failed), _) => {
            common_enums::AttemptStatus::Failure
        }
        (Some(FiservemeaTransactionResult::Waiting), _) | (_, Some(FiservemeaTransactionState::Waiting)) => {
            common_enums::AttemptStatus::Pending
        }
        (Some(FiservemeaTransactionResult::Partial), _) => {
            common_enums::AttemptStatus::Pending
        }
        (Some(FiservemeaTransactionResult::Fraud), _) => {
            common_enums::AttemptStatus::Failure
        }
        (_, Some(FiservemeaTransactionState::Voided)) => {
            common_enums::AttemptStatus::Voided
        }
        (_, Some(FiservemeaTransactionState::Pending)) => {
            common_enums::AttemptStatus::Pending
        }
        _ => common_enums::AttemptStatus::Pending,
    }
}

#[derive(Debug, Clone)]
pub struct FiservemeaAuthType {
    pub api_key: Secret<String>,
}

impl TryFrom<&domain_types::router_data::ConnectorAuthType> for FiservemeaAuthType {
    type Error = ConnectorError;

    fn try_from(auth_type: &domain_types::router_data::ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            domain_types::router_data::ConnectorAuthType::Header { api_key } => {
                Ok(FiservemeaAuthType {
                    api_key: api_key.clone(),
                })
            }
            _ => Err(ConnectorError::FailedToObtainAuthType),
        }
    }
}