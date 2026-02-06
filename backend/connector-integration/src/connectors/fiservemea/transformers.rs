use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::ResponseRouterData;
use base64::{engine::general_purpose, Engine};
use common_enums::{AttemptStatus, RefundStatus};
use common_utils::{
    crypto::{self, SignMessage},
    types::{AmountConvertor, FloatMajorUnit, FloatMajorUnitForConnector},
};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Mask, Maskable, PeekInterface, Secret};
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
        let raw_signature = format!("{api_key}{client_request_id}{timestamp}{request_body}");

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
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
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
#[serde(rename_all = "camelCase")]
pub struct FiservemeaErrorResponse {
    pub code: Option<String>,
    pub message: Option<String>,
    pub details: Option<Vec<ErrorDetail>>,
    pub ipg_transaction_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub field: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FiservemeaPaymentsRequest {
    pub request_type: String,
    pub transaction_amount: FiservemeaTransactionAmount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method: Option<FiservemeaPaymentMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<FiservemeaOrder>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FiservemeaTransactionAmount {
    pub total: String,
    pub currency: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FiservemeaPaymentMethod {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_card: Option<FiservemeaPaymentCard>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_token: Option<FiservemeaPaymentToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet: Option<FiservemeaWallet>,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaVoidRequest {
    pub request_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comments: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaCaptureRequest {
    pub request_type: String,
    pub transaction_amount: FiservemeaTransactionAmount,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaRefundRequest {
    pub request_type: String,
    pub transaction_amount: FiservemeaTransactionAmount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comments: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAmount {
    pub total: f64,
    pub currency: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentMethodDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method_brand: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FiservemeaRouterData<RD> {
    pub router_data: RD,
}

impl TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for FiservemeaPaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        value: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
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
            }),
            PaymentMethodData::PaymentToken(token) => Some(FiservemeaPaymentMethod {
                payment_card: None,
                payment_token: Some(FiservemeaPaymentToken {
                    value: token.token_value.clone(),
                }),
                wallet: None,
            }),
            _ => Err(error_stack::report!(errors::ConnectorError::NotSupported {
                message: "Payment method not supported".to_string(),
                connector: "fiservemea".to_string(),
            }))?,
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

impl TryFrom<&RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>
    for FiservemeaVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _value: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(FiservemeaVoidRequest {
            request_type: "VoidTransaction".to_string(),
            comments: None,
        })
    }
}

impl TryFrom<&FiservemeaRouterData<RouterDataV2<Capture, _, _, _>>>
    for FiservemeaCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        value: &FiservemeaRouterData<RouterDataV2<Capture, _, _, _>>,
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

impl TryFrom<&FiservemeaRouterData<RouterDataV2<Refund, _, _, _>>> for FiservemeaRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        value: &FiservemeaRouterData<RouterDataV2<Refund, _, _, _>>,
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
) -> AttemptStatus {
    match (result, state) {
        (Some(FiservemeaTransactionResult::Approved), Some(FiservemeaTransactionState::Authorized)) => {
            AttemptStatus::Authorized
        }
        (Some(FiservemeaTransactionResult::Approved), Some(FiservemeaTransactionState::Captured)) => {
            AttemptStatus::Charged
        }
        (Some(FiservemeaTransactionResult::Approved), Some(FiservemeaTransactionState::Settled)) => {
            AttemptStatus::Charged
        }
        (Some(FiservemeaTransactionResult::Declined), _)
        | (_, Some(FiservemeaTransactionState::Declined)) => AttemptStatus::Failure,
        (Some(FiservemeaTransactionResult::Failed), _) => AttemptStatus::Failure,
        (Some(FiservemeaTransactionResult::Waiting), _)
        | (_, Some(FiservemeaTransactionState::Waiting)) => AttemptStatus::Pending,
        (Some(FiservemeaTransactionResult::Partial), _) => AttemptStatus::Pending,
        (Some(FiservemeaTransactionResult::Fraud), _) => AttemptStatus::Failure,
        (_, Some(FiservemeaTransactionState::Voided)) => AttemptStatus::Voided,
        (_, Some(FiservemeaTransactionState::Pending)) => AttemptStatus::Pending,
        _ => AttemptStatus::Pending,
    }
}

pub fn map_fiservemea_status_to_refund_status(
    result: &Option<FiservemeaTransactionResult>,
    state: &Option<FiservemeaTransactionState>,
) -> common_enums::RefundStatus {
    match (result, state) {
        (Some(FiservemeaTransactionResult::Approved), _) => common_enums::RefundStatus::Success,
        (Some(FiservemeaTransactionResult::Declined), _)
        | (_, Some(FiservemeaTransactionState::Declined)) => common_enums::RefundStatus::Failure,
        (Some(FiservemeaTransactionResult::Failed), _) => common_enums::RefundStatus::Failure,
        (Some(FiservemeaTransactionResult::Waiting), _)
        | (_, Some(FiservemeaTransactionState::Waiting)) => common_enums::RefundStatus::Pending,
        (Some(FiservemeaTransactionResult::Partial), _) => common_enums::RefundStatus::Pending,
        (Some(FiservemeaTransactionResult::Fraud), _) => common_enums::RefundStatus::Failure,
        (_, Some(FiservemeaTransactionState::Pending)) => common_enums::RefundStatus::Pending,
        _ => common_enums::RefundStatus::Pending,
    }
}

impl<T: PaymentMethodDataTypes> TryFrom<ResponseRouterData<FiservemeaAuthorizeResponse, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservemeaAuthorizeResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = map_fiservemea_status_to_attempt_status(
            &item.response.transaction_result,
            &item.response.transaction_state,
        );

        let network_txn_id = item
            .response
            .processor
            .as_ref()
            .and_then(|p| p.reference_number.clone());

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.ipg_transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: network_txn_id.or(item.response.api_trace_id.clone()),
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

impl TryFrom<ResponseRouterData<FiservemeaSyncResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservemeaSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = map_fiservemea_status_to_attempt_status(
            &item.response.transaction_result,
            &item.response.transaction_state,
        );

        let network_txn_id = item
            .response
            .processor
            .as_ref()
            .and_then(|p| p.reference_number.clone());

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.ipg_transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: network_txn_id.or(item.response.api_trace_id.clone()),
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

impl TryFrom<ResponseRouterData<FiservemeaVoidResponse, Self>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservemeaVoidResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = map_fiservemea_status_to_attempt_status(
            &item.response.transaction_result,
            &item.response.transaction_state,
        );

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.ipg_transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: item.response.api_trace_id.clone(),
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

impl TryFrom<ResponseRouterData<FiservemeaCaptureResponse, Self>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservemeaCaptureResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = map_fiservemea_status_to_attempt_status(
            &item.response.transaction_result,
            &item.response.transaction_state,
        );

        let network_txn_id = item
            .response
            .processor
            .as_ref()
            .and_then(|p| p.reference_number.clone());

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.response.ipg_transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: network_txn_id.or(item.response.api_trace_id.clone()),
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

impl TryFrom<ResponseRouterData<FiservemeaRefundResponse, Self>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservemeaRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let refund_status = map_fiservemea_status_to_refund_status(
            &item.response.transaction_result,
            &item.response.transaction_state,
        );

        let network_txn_id = item
            .response
            .processor
            .as_ref()
            .and_then(|p| p.reference_number.clone());

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.ipg_transaction_id.clone(),
                refund_status,
                connector_response_reference_id: Some(item.response.client_request_id.clone()),
                network_txn_id: network_txn_id.or(item.response.api_trace_id.clone()),
                connector_metadata: None,
                status_code: item.http_code,
            }),
            resource_common_data: RefundFlowData {
                refund_status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

impl TryFrom<ResponseRouterData<FiservemeaRefundSyncResponse, Self>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FiservemeaRefundSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let refund_status = map_fiservemea_status_to_refund_status(
            &item.response.transaction_result,
            &item.response.transaction_state,
        );

        let network_txn_id = item
            .response
            .processor
            .as_ref()
            .and_then(|p| p.reference_number.clone());

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.ipg_transaction_id.clone(),
                refund_status,
                connector_response_reference_id: Some(item.response.client_request_id.clone()),
                network_txn_id: network_txn_id.or(item.response.api_trace_id.clone()),
                connector_metadata: None,
                status_code: item.http_code,
            }),
            resource_common_data: RefundFlowData {
                refund_status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}