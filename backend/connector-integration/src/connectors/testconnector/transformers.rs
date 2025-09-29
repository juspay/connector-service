use std::collections::HashMap;

use common_utils::{
    errors::CustomResult, ext_traits::ValueExt, id_type, request::Method, types::StringMinorUnit,
    Email,
};
use domain_types::{
    connector_flow::{Authorize, PSync, Capture, Void, Refund, RSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, 
                      PaymentsCaptureData, PaymentVoidData, RefundFlowData, RefundsData, 
                      RefundsResponseData, RefundSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};
use common_enums::AttemptStatus;

use crate::{connectors::testconnector::TestconnectorRouterData, types::ResponseRouterData};

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestconnectorPaymentsRequest {
    amount: StringMinorUnit,
    currency: common_enums::Currency,
    transaction_id: String,
    user_id: Secret<String>,
    email: Option<Email>,
    payment_method: String,
    return_url: String,
    cancel_url: String,
    api_key: Secret<String>,
    description: Option<String>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestconnectorPaymentsSyncRequest {
    transaction_id: String,
    api_key: Secret<String>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestconnectorCaptureRequest {
    transaction_id: String,
    amount: StringMinorUnit,
    api_key: Secret<String>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestconnectorVoidRequest {
    transaction_id: String,
    api_key: Secret<String>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestconnectorRefundRequest {
    payment_id: String,
    refund_id: String,
    amount: StringMinorUnit,
    reason: Option<String>,
    api_key: Secret<String>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestconnectorRefundSyncRequest {
    refund_id: String,
    api_key: Secret<String>,
}

fn get_auth_credentials(auth_type: &ConnectorAuthType) -> Result<Secret<String>, ConnectorError> {
    match auth_type {
        ConnectorAuthType::BodyKey { api_key, .. } => Ok(api_key.clone()),
        ConnectorAuthType::HeaderKey { api_key } => Ok(api_key.clone()),
        _ => Err(ConnectorError::FailedToObtainAuthType),
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        TestconnectorRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for TestconnectorPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: TestconnectorRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let return_url = item.router_data.request.get_router_return_url()?;
        let api_key = get_auth_credentials(&item.router_data.connector_auth_type)?;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let payment_method = item.router_data.request.payment_method_type
            .map(|pm| pm.to_string())
            .unwrap_or_else(|| "card".to_string());

        Ok(Self {
            amount,
            currency: item.router_data.request.currency,
            transaction_id: item.router_data.resource_common_data.connector_request_reference_id.clone(),
            user_id: Secret::new(customer_id.get_string_repr()),
            email: item.router_data.request.email.clone(),
            payment_method,
            return_url: return_url.clone(),
            cancel_url: return_url,
            api_key,
            description: item.router_data.request.description.clone(),
        })
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        TestconnectorRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for TestconnectorPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: TestconnectorRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let api_key = get_auth_credentials(&item.router_data.connector_auth_type)?;
        let transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            transaction_id,
            api_key,
        })
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        TestconnectorRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for TestconnectorCaptureRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: TestconnectorRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let api_key = get_auth_credentials(&item.router_data.connector_auth_type)?;
        let transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| ConnectorError::RequestEncodingFailed)?;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount_to_capture,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            transaction_id,
            amount,
            api_key,
        })
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        TestconnectorRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for TestconnectorVoidRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: TestconnectorRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let api_key = get_auth_credentials(&item.router_data.connector_auth_type)?;
        let transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            transaction_id,
            api_key,
        })
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        TestconnectorRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for TestconnectorRefundRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: TestconnectorRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let api_key = get_auth_credentials(&item.router_data.connector_auth_type)?;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_refund_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            payment_id: item.router_data.request.connector_transaction_id.clone(),
            refund_id: item.router_data.request.refund_id.clone(),
            amount,
            reason: item.router_data.request.reason.clone(),
            api_key,
        })
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        TestconnectorRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for TestconnectorRefundSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: TestconnectorRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let api_key = get_auth_credentials(&item.router_data.connector_auth_type)?;

        Ok(Self {
            refund_id: item.router_data.request.refund_id.clone(),
            api_key,
        })
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TestconnectorPaymentStatus {
    Success,
    #[default]
    Pending,
    Failed,
    Cancelled,
}

impl From<TestconnectorPaymentStatus> for AttemptStatus {
    fn from(item: TestconnectorPaymentStatus) -> Self {
        match item {
            TestconnectorPaymentStatus::Success => Self::Charged,
            TestconnectorPaymentStatus::Pending => Self::Pending,
            TestconnectorPaymentStatus::Failed => Self::Failure,
            TestconnectorPaymentStatus::Cancelled => Self::Voided,
        }
    }
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct TestconnectorErrorInfo {
    pub code: String,
    pub message: String,
    pub details: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TestconnectorPaymentsResponse {
    TestconnectorError(TestconnectorErrorResponse),
    TestconnectorData(TestconnectorPaymentsResponseData),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestconnectorPaymentsResponseData {
    pub transaction_id: String,
    pub status: TestconnectorPaymentStatus,
    pub payment_url: Option<url::Url>,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestconnectorPaymentsSyncResponse {
    pub transaction_id: String,
    pub status: TestconnectorPaymentStatus,
    pub amount: Option<f64>,
    pub currency: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestconnectorCaptureResponse {
    pub transaction_id: String,
    pub status: TestconnectorPaymentStatus,
    pub captured_amount: Option<f64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestconnectorVoidResponse {
    pub transaction_id: String,
    pub status: TestconnectorPaymentStatus,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestconnectorRefundResponse {
    pub refund_id: String,
    pub payment_id: String,
    pub status: TestconnectorRefundStatus,
    pub refunded_amount: Option<f64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestconnectorRefundSyncResponse {
    pub refund_id: String,
    pub status: TestconnectorRefundStatus,
    pub refunded_amount: Option<f64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TestconnectorRefundStatus {
    Success,
    #[default]
    Pending,
    Failed,
}

impl From<TestconnectorRefundStatus> for common_enums::RefundStatus {
    fn from(item: TestconnectorRefundStatus) -> Self {
        match item {
            TestconnectorRefundStatus::Success => Self::Success,
            TestconnectorRefundStatus::Pending => Self::Pending,
            TestconnectorRefundStatus::Failed => Self::Failure,
        }
    }
}

fn get_redirect_form_data(
    response_data: TestconnectorPaymentsResponseData,
) -> CustomResult<RedirectForm, errors::ConnectorError> {
    if let Some(payment_url) = response_data.payment_url {
        Ok(RedirectForm::Form {
            endpoint: payment_url.to_string(),
            method: Method::Get,
            form_fields: Default::default(),
        })
    } else {
        Err(ConnectorError::MissingRequiredField {
            field_name: "payment_url",
        })?
    }
}

impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<ResponseRouterData<TestconnectorPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: ResponseRouterData<TestconnectorPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        
        let (status, response) = match response {
            TestconnectorPaymentsResponse::TestconnectorError(error_data) => (
                AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.error.code.clone(),
                    status_code: http_code,
                    message: error_data.error.message.clone(),
                    reason: error_data.error.details.clone(),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            TestconnectorPaymentsResponse::TestconnectorData(response_data) => {
                let status = AttemptStatus::from(response_data.status.clone());
                let redirection_data = if response_data.payment_url.is_some() {
                    Some(Box::new(get_redirect_form_data(response_data.clone())?))
                } else {
                    None
                };
                
                (
                    status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(response_data.transaction_id),
                        redirection_data,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response,
            ..router_data
        })
    }
}

impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<ResponseRouterData<TestconnectorPaymentsSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: ResponseRouterData<TestconnectorPaymentsSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        
        let status = AttemptStatus::from(response.status);
        
        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.transaction_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TestconnectorErrorResponse {
    pub error: TestconnectorErrorInfo,
    pub request_id: Option<String>,
}