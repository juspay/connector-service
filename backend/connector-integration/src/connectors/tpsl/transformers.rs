use std::collections::HashMap;

use common_utils::{Email, request::Method};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use crate::types::ResponseRouterData;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAuth {
    pub merchant_code: Option<Secret<String>>,
    pub merchant_key: Option<Secret<String>>,
    pub checksum_key: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for TpslAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1 } => Ok(Self {
                merchant_code: Some(Secret::new(api_key.clone())),
                merchant_key: key1.clone().map(Secret::new),
                checksum_key: None,
            }),
            ConnectorAuthType::MultiAccountKey { api_key, key1, key2 } => Ok(Self {
                merchant_code: Some(Secret::new(api_key.clone())),
                merchant_key: key1.clone().map(Secret::new),
                checksum_key: key2.clone().map(Secret::new),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsRequest {
    pub merchant: TpslMerchantPayload,
    pub transaction: TpslTransactionPayload,
    pub consumer: TpslConsumerPayload,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslMerchantPayload {
    pub identifier: String,
    pub response_endpoint_url: String,
    pub description: String,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TpslTransactionPayload {
    pub amount: String,
    pub currency: String,
    pub identifier: String,
    pub date_time: String,
    pub request_type: String,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TpslConsumerPayload {
    pub email_id: Option<Email>,
    pub identifier: String,
    pub vpa: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsSyncRequest {
    pub merchant: TpslMerchantDataType,
    pub transaction: TpslTransactionSyncType,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslMerchantDataType {
    pub identifier: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslTransactionSyncType {
    pub amount: String,
    pub currency: String,
    pub request_type: String,
    pub token: String,
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
> TryFrom<&TPSLRouterData<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for TpslPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &TPSLRouterData<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = TpslAuth::try_from(&item.router_data.connector_auth_type)?;
        let merchant_code = auth.merchant_code.ok_or(ConnectorError::FailedToObtainAuthType)?;
        
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let return_url = item.router_data.request.get_router_return_url()?;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let transaction_id = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        let currency = item.router_data.request.currency.to_string();
        let email = item.router_data.request.email.clone();

        // Extract VPA for UPI payments
        let vpa = item
            .router_data
            .request
            .payment_method_data
            .as_ref()
            .and_then(|pm| pm.get_upi())
            .and_then(|upi| upi.vpa.clone());

        match item.router_data.resource_common_data.payment_method {
            common_enums::PaymentMethod::Upi => Ok(Self {
                merchant: TpslMerchantPayload {
                    identifier: merchant_code.expose().clone(),
                    response_endpoint_url: return_url.clone(),
                    description: "UPI Payment".to_string(),
                },
                transaction: TpslTransactionPayload {
                    amount: amount.clone(),
                    currency: currency.clone(),
                    identifier: transaction_id.clone(),
                    date_time: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                        .to_string(),
                    request_type: "SALE".to_string(),
                },
                consumer: TpslConsumerPayload {
                    email_id: email,
                    identifier: customer_id.to_string(),
                    vpa,
                },
            }),
            _ => Err(errors::ConnectorError::NotImplemented("Payment method".to_string()).into()),
        }
    }
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
> TryFrom<&TPSLRouterData<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for TpslPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &TPSLRouterData<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = TpslAuth::try_from(&item.router_data.connector_auth_type)?;
        let merchant_code = auth.merchant_code.ok_or(ConnectorError::FailedToObtainAuthType)?;
        
        let transaction_id = item
            .router_data
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| ConnectorError::RequestEncodingFailed)?;

        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let currency = item.router_data.request.currency.to_string();

        Ok(Self {
            merchant: TpslMerchantDataType {
                identifier: merchant_code.expose().clone(),
            },
            transaction: TpslTransactionSyncType {
                amount,
                currency,
                request_type: "STATUS".to_string(),
                token: transaction_id,
            },
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsResponse {
    pub code: i32,
    pub status: String,
    pub response: TpslResponseData,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TpslResponseData {
    Success(TpslSuccessResponse),
    Error(TpslErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslSuccessResponse {
    pub merchant_transaction_identifier: String,
    pub transaction_state: Option<String>,
    pub payment_method: TpslPaymentMethodResponse,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentMethodResponse {
    pub payment_transaction: TpslPaymentTransactionResponse,
    pub error: TpslPaymentMethodError,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentTransactionResponse {
    pub amount: String,
    pub bank_reference_identifier: Option<String>,
    pub status_code: String,
    pub reference: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentMethodError {
    pub code: String,
    pub desc: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslErrorResponse {
    pub error_code: String,
    pub error_message: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsSyncResponse {
    pub merchant_transaction_identifier: String,
    pub transaction_state: String,
    pub payment_method: TpslPaymentMethodResponse,
    pub status_code: Option<String>,
}

impl From<&TpslPaymentsResponse> for common_enums::AttemptStatus {
    fn from(response: &TpslPaymentsResponse) -> Self {
        match response.status.to_uppercase().as_str() {
            "SUCCESS" | "COMPLETED" => Self::Charged,
            "PENDING" | "PROCESSING" => Self::AuthenticationPending,
            "FAILURE" | "FAILED" => Self::Failure,
            "INITIATED" => Self::Started,
            _ => Self::AuthenticationPending,
        }
    }
}

impl From<&TpslPaymentsSyncResponse> for common_enums::AttemptStatus {
    fn from(response: &TpslPaymentsSyncResponse) -> Self {
        match response.transaction_state.to_uppercase().as_str() {
            "SUCCESS" | "COMPLETED" => Self::Charged,
            "PENDING" | "PROCESSING" => Self::AuthenticationPending,
            "FAILURE" | "FAILED" => Self::Failure,
            "INITIATED" => Self::Started,
            _ => Self::AuthenticationPending,
        }
    }
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
> TryFrom<ResponseRouterData<TpslPaymentsResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TpslPaymentsResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response_data) = match response.response {
            TpslResponseData::Success(success_data) => {
                let status = common_enums::AttemptStatus::from(&response);
                
                (
                    status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            success_data.merchant_transaction_identifier,
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: success_data.payment_method.payment_transaction.bank_reference_identifier,
                        connector_response_reference_id: Some(success_data.payment_method.payment_transaction.reference),
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            TpslResponseData::Error(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.error_code,
                    status_code: http_code,
                    message: error_data.error_message.clone(),
                    reason: Some(error_data.error_message),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: response_data,
            ..router_data
        })
    }
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
> TryFrom<ResponseRouterData<TpslPaymentsSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TpslPaymentsSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let status = common_enums::AttemptStatus::from(&response);

        let response_data = Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(
                response.merchant_transaction_identifier,
            ),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: response.payment_method.payment_transaction.bank_reference_identifier,
            connector_response_reference_id: Some(response.payment_method.payment_transaction.reference),
            incremental_authorization_allowed: None,
            status_code: http_code,
        });

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: response_data,
            ..router_data
        })
    }
}