use common_enums::{AttemptStatus, RefundStatus, CaptureMethod};
use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    types::{AmountConvertor, StringMinorUnit, StringMinorUnitForConnector},
};
use domain_types::{
    connector_flow::{
        Authorize, Capture, PSync, RSync, Refund, Void,
    },
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData,
        RefundsData, RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::{
        PaymentMethodData, PaymentMethodDataTypes, RawCardNumber,
    },
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};


use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use crate::types::ResponseRouterData;
use super::HelcimRouterData;

type Error = error_stack::Report<domain_types::errors::ConnectorError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelcimAuthType {
    pub api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for HelcimAuthType {
    type Error = Error;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelcimCard<T: PaymentMethodDataTypes> {
    pub card_number: RawCardNumber<T>,
    pub card_expiry: Secret<String>, // MMYY format
    pub card_cvv: Secret<String>,
    pub card_holder_name: Option<Secret<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HelcimPaymentsRequest<T: PaymentMethodDataTypes> {
    pub amount: StringMinorUnit,
    pub currency: String,
    pub payment_type: String,
    pub card_data: HelcimCard<T>,
    pub idempotency_key: String,
    pub invoice_number: Option<String>,
    pub customer_code: Option<String>,
    pub billing_address: Option<HelcimBillingAddress>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HelcimBillingAddress {
    pub name: Option<Secret<String>>,
    pub street1: Option<Secret<String>>,
    pub street2: Option<Secret<String>>,
    pub city: Option<String>,
    pub province: Option<Secret<String>>,
    pub country: Option<String>,
    pub postal_code: Option<Secret<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HelcimPaymentsResponse {
    pub transaction_id: Option<String>,
    pub card_token: Option<String>,
    pub amount: Option<f64>,
    pub currency: Option<String>,
    pub avs_response: Option<String>,
    pub cvv_response: Option<String>,
    pub approval_code: Option<String>,
    pub order_number: Option<String>,
    pub customer_code: Option<String>,
    pub invoice_number: Option<String>,
    pub type_: Option<String>,
    pub response: Option<i32>,
    #[serde(rename = "responseMessage")]
    pub response_message: Option<String>,
    pub notice: Option<String>,
    #[serde(rename = "dateCreated")]
    pub date_created: Option<String>,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HelcimCaptureRequest {
    pub transaction_id: String,
    pub amount: StringMinorUnit,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HelcimVoidRequest {
    pub transaction_id: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HelcimRefundRequest {
    pub transaction_id: String,
    pub amount: StringMinorUnit,
    pub idempotency_key: String,
}

// Create separate response types for each flow to avoid macro conflicts
pub type HelcimAuthorizeResponse = HelcimPaymentsResponse;
pub type HelcimSyncResponse = HelcimPaymentsResponse;
pub type HelcimCaptureResponse = HelcimPaymentsResponse;
pub type HelcimVoidResponse = HelcimPaymentsResponse;
pub type HelcimRSyncResponse = HelcimRefundResponse;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HelcimRefundResponse {
    pub transaction_id: Option<String>,
    pub amount: Option<f64>,
    pub currency: Option<String>,
    pub type_: Option<String>,
    pub response: Option<i32>,
    #[serde(rename = "responseMessage")]
    pub response_message: Option<String>,
    pub notice: Option<String>,
    #[serde(rename = "dateCreated")]
    pub date_created: Option<String>,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HelcimSyncRequest {
    pub transaction_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HelcimRSyncRequest {
    pub transaction_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HelcimErrorResponse {
    pub error_code: Option<String>,
    pub message: Option<String>,
    pub errors: Option<Vec<String>>,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + serde::Serialize>
    TryFrom<HelcimRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for HelcimPaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: HelcimRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        match &item.router_data.request.payment_method_data {
            PaymentMethodData::Card(req_card) => {
                let card_data = HelcimCard {
                    card_number: req_card.card_number.clone(),
                    card_expiry: Secret::new(format!("{}{}", req_card.card_exp_month.peek(), req_card.card_exp_year.peek())),
                    card_cvv: req_card.card_cvc.clone(),
                    card_holder_name: req_card.card_holder_name.clone(),
                };

                let billing_address = item.router_data.resource_common_data.get_optional_billing().map(|billing| {
                    HelcimBillingAddress {
                        name: billing.address.as_ref().and_then(|addr| addr.get_optional_full_name()),
                        street1: billing.address.as_ref().and_then(|addr| addr.line1.clone()),
                        street2: billing.address.as_ref().and_then(|addr| addr.line2.clone()),
                        city: billing.address.as_ref().and_then(|addr| addr.city.clone()),
                        province: billing.address.as_ref().and_then(|addr| addr.state.clone()),
                        country: billing.address.as_ref().and_then(|addr| addr.country.map(|c| c.to_string())),
                        postal_code: billing.address.as_ref().and_then(|addr| addr.zip.clone()),
                    }
                });

                Ok(Self {
                    amount: StringMinorUnitForConnector.convert(item.router_data.request.minor_amount, item.router_data.request.currency)
                        .map_err(|_| errors::ConnectorError::ParsingFailed)?,
                    currency: item.router_data.request.currency.to_string(),
                    payment_type: "purchase".to_string(),
                    card_data,
                    idempotency_key: format!("HS_{}", item.router_data.resource_common_data.connector_request_reference_id),
                    invoice_number: Some(item.router_data.resource_common_data.payment_id.clone()),
                    customer_code: item.router_data.resource_common_data.customer_id.as_ref().map(|id| id.get_string_repr().to_string()),
                    billing_address,
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented("Payment method".to_string()).into()),
        }
    }
}

impl<T: PaymentMethodDataTypes>
    TryFrom<ResponseRouterData<HelcimAuthorizeResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = Error;
    fn try_from(
        item: ResponseRouterData<HelcimAuthorizeResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let status = get_payment_status(item.response.response, item.router_data.request.capture_method);
        let response_id = item.response.transaction_id.clone()
            .map(ResponseId::ConnectorTransactionId)
            .unwrap_or(ResponseId::NoResponseId);

        Ok(Self {
            response: match status {
                AttemptStatus::Charged | AttemptStatus::Authorized => {
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: response_id,
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: item.response.transaction_id,
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    })
                }
                _ => Err(ErrorResponse {
                    code: item.response.response.map(|r| r.to_string()).unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                    message: item.response.response_message.unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    reason: item.response.notice,
                    status_code: item.http_code,
                    attempt_status: Some(status),
                    connector_transaction_id: item.response.transaction_id,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
            },
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + serde::Serialize> TryFrom<HelcimRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for HelcimSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: HelcimRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            transaction_id: item.router_data.request.get_connector_transaction_id()?,
        })
    }
}

impl TryFrom<ResponseRouterData<HelcimSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = Error;
    fn try_from(
        item: ResponseRouterData<HelcimSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let status = get_payment_status(item.response.response, item.router_data.request.capture_method);
        let response_id = item.response.transaction_id.clone()
            .map(ResponseId::ConnectorTransactionId)
            .unwrap_or(ResponseId::NoResponseId);

        Ok(Self {
            response: match status {
                AttemptStatus::Charged | AttemptStatus::Authorized => {
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: response_id,
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: item.response.transaction_id,
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    })
                }
                _ => Err(ErrorResponse {
                    code: item.response.response.map(|r| r.to_string()).unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                    message: item.response.response_message.unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    reason: item.response.notice,
                    status_code: item.http_code,
                    attempt_status: Some(status),
                    connector_transaction_id: item.response.transaction_id,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
            },
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + serde::Serialize> TryFrom<HelcimRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, T>>
    for HelcimCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: HelcimRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            transaction_id: item.router_data.request.get_connector_transaction_id()?,
            amount: StringMinorUnitForConnector.convert(item.router_data.request.minor_amount_to_capture, item.router_data.request.currency)
                .map_err(|_| errors::ConnectorError::ParsingFailed)?,
            idempotency_key: format!("HS_{}", item.router_data.resource_common_data.connector_request_reference_id),
        })
    }
}

impl TryFrom<ResponseRouterData<HelcimCaptureResponse, RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = Error;
    fn try_from(
        item: ResponseRouterData<HelcimCaptureResponse, RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let status = get_payment_status(item.response.response, None);
        let response_id = item.response.transaction_id.clone()
            .map(ResponseId::ConnectorTransactionId)
            .unwrap_or(ResponseId::NoResponseId);

        Ok(Self {
            response: match status {
                AttemptStatus::Charged => {
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: response_id,
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: item.response.transaction_id,
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    })
                }
                _ => Err(ErrorResponse {
                    code: item.response.response.map(|r| r.to_string()).unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                    message: item.response.response_message.unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    reason: item.response.notice,
                    status_code: item.http_code,
                    attempt_status: Some(status),
                    connector_transaction_id: item.response.transaction_id,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
            },
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + serde::Serialize> TryFrom<HelcimRouterData<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, T>>
    for HelcimVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: HelcimRouterData<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            transaction_id: item.router_data.request.connector_transaction_id.clone(),
            idempotency_key: format!("HS_{}", item.router_data.resource_common_data.connector_request_reference_id),
        })
    }
}

impl TryFrom<ResponseRouterData<HelcimVoidResponse, RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = Error;
    fn try_from(
        item: ResponseRouterData<HelcimVoidResponse, RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let status = get_payment_status(item.response.response, None);
        let response_id = item.response.transaction_id.clone()
            .map(ResponseId::ConnectorTransactionId)
            .unwrap_or(ResponseId::NoResponseId);

        Ok(Self {
            response: match status {
                AttemptStatus::Voided => {
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: response_id,
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: item.response.transaction_id,
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    })
                }
                _ => Err(ErrorResponse {
                    code: item.response.response.map(|r| r.to_string()).unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                    message: item.response.response_message.unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    reason: item.response.notice,
                    status_code: item.http_code,
                    attempt_status: Some(status),
                    connector_transaction_id: item.response.transaction_id,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
            },
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + serde::Serialize> TryFrom<HelcimRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>>
    for HelcimRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: HelcimRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            transaction_id: item.router_data.request.connector_transaction_id.clone(),
            amount: StringMinorUnitForConnector.convert(item.router_data.request.minor_refund_amount, item.router_data.request.currency)
                .map_err(|_| errors::ConnectorError::ParsingFailed)?,
            idempotency_key: format!("HS_{}", item.router_data.resource_common_data.connector_request_reference_id),
        })
    }
}

impl TryFrom<ResponseRouterData<HelcimRefundResponse, RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = Error;
    fn try_from(
        item: ResponseRouterData<HelcimRefundResponse, RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let refund_status = get_refund_status(item.response.response);
        
        Ok(Self {
            response: match refund_status {
                RefundStatus::Success => {
                    Ok(RefundsResponseData {
                        connector_refund_id: item.response.transaction_id.unwrap_or_default(),
                        refund_status,
                        status_code: item.http_code,
                    })
                }
                _ => Err(ErrorResponse {
                    code: item.response.response.map(|r| r.to_string()).unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                    message: item.response.response_message.unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    reason: item.response.notice,
                    status_code: item.http_code,
                    attempt_status: None,
                    connector_transaction_id: item.response.transaction_id,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
            },
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + serde::Serialize> TryFrom<HelcimRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>>
    for HelcimRSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: HelcimRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            transaction_id: item.router_data.request.connector_refund_id.clone(),
        })
    }
}

impl TryFrom<ResponseRouterData<HelcimRSyncResponse, RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = Error;
    fn try_from(
        item: ResponseRouterData<HelcimRSyncResponse, RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let refund_status = get_refund_status(item.response.response);
        
        Ok(Self {
            response: match refund_status {
                RefundStatus::Success => {
                    Ok(RefundsResponseData {
                        connector_refund_id: item.response.transaction_id.unwrap_or_default(),
                        refund_status,
                        status_code: item.http_code,
                    })
                }
                _ => Err(ErrorResponse {
                    code: item.response.response.map(|r| r.to_string()).unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                    message: item.response.response_message.unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    reason: item.response.notice,
                    status_code: item.http_code,
                    attempt_status: None,
                    connector_transaction_id: item.response.transaction_id,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
            },
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

fn get_payment_status(response_code: Option<i32>, capture_method: Option<CaptureMethod>) -> AttemptStatus {
    match response_code {
        Some(1) => {
            // Success - determine if authorized or charged based on capture method
            match capture_method {
                Some(CaptureMethod::Manual) => AttemptStatus::Authorized,
                _ => AttemptStatus::Charged,
            }
        }
        Some(0) => AttemptStatus::Voided,
        _ => AttemptStatus::Failure,
    }
}

fn get_refund_status(response_code: Option<i32>) -> RefundStatus {
    match response_code {
        Some(1) => RefundStatus::Success,
        _ => RefundStatus::Failure,
    }
}