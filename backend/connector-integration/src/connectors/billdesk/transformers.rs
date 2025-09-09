use std::collections::HashMap;

use common_utils::{
    errors::CustomResult, ext_traits::ValueExt, id_type, pii::IpAddress, types::StringMinorUnit,
    Email,
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsResponseData, ResponseId},
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

use crate::{connectors::billdesk::BilldeskRouterData, types::ResponseRouterData};

// UPI Payment Request Structure
#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsRequest {
    pub msg: String,
    pub useragent: Option<String>,
    pub ipaddress: Option<String>,
}

// UPI Payment Response Structure
#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(untagged)]
pub enum BilldeskPaymentsResponse {
    Success(BilldeskUPISuccessResponse),
    Error(BilldeskErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskUPISuccessResponse {
    pub msg: Option<String>,
    pub rdata: Option<BilldeskRData>,
    pub txnrefno: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskRData {
    pub parameters: Option<HashMap<String, String>>,
    pub url: Option<String>,
}

// Payment Sync Request Structure
#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsSyncRequest {
    pub msg: String,
}

// Payment Sync Response Structure
#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(untagged)]
pub enum BilldeskPaymentsSyncResponse {
    Success(BilldeskStatusSuccessResponse),
    Error(BilldeskErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskStatusSuccessResponse {
    pub msg: Option<String>,
    pub rdata: Option<BilldeskStatusRData>,
    pub txnrefno: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskStatusRData {
    pub parameters: Option<HashMap<String, String>>,
    pub url: Option<String>,
}

// Error Response Structure
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskErrorResponse {
    pub error: String,
    pub error_code: String,
    pub error_message: String,
    pub error_description: Option<String>,
}

// UPI Object Structure
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpiObject {
    pub vpa: String,
}

// Authorization Request Message Structure
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskAuthorizationRequestMsg {
    pub merchant_id: String,
    pub customer_id: String,
    pub txn_reference_no: String,
    pub bank_reference_no: Option<String>,
    pub txn_amount: String,
    pub bank_id: Option<String>,
    pub txn_type: String,
    pub currency_type: String,
    pub item_code: String,
    pub txn_date: String,
    pub auth_status: String,
    pub additional_info1: Option<String>,
    pub additional_info2: Option<String>,
    pub additional_info3: Option<String>,
    pub additional_info4: Option<String>,
    pub additional_info5: Option<String>,
    pub additional_info6: Option<String>,
    pub additional_info7: Option<String>,
    pub error_status: Option<String>,
    pub error_description: Option<String>,
    pub checksum: String,
}

// Status Request Message Structure
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskStatusRequestMsg {
    pub request_type: Option<String>,
    pub merchant_id: String,
    pub customer_id: String,
    pub txn_reference_no: String,
    pub bank_reference_no: Option<String>,
    pub txn_amount: String,
    pub bank_id: Option<String>,
    pub txn_type: Option<String>,
    pub currency_type: String,
    pub item_code: String,
    pub txn_date: Option<String>,
    pub auth_status: String,
    pub additional_info1: Option<String>,
    pub additional_info2: Option<String>,
    pub additional_info3: Option<String>,
    pub additional_info4: Option<String>,
    pub additional_info5: Option<String>,
    pub additional_info6: Option<String>,
    pub additional_info7: Option<String>,
    pub error_status: String,
    pub error_description: Option<String>,
    pub refund_status: Option<String>,
    pub total_refund_amount: Option<String>,
    pub last_refund_date: Option<String>,
    pub last_refund_ref_no: Option<String>,
    pub query_status: String,
    pub checksum: String,
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > TryFrom<BilldeskRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for BilldeskPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: BilldeskRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let ip_address = item.router_data.request.get_ip_address_as_optional()
            .map(|ip| ip.expose())
            .unwrap_or_else(|| "127.0.0.1".to_string());

        let user_agent = item.router_data.request.browser_info
            .as_ref()
            .and_then(|info| info.user_agent.clone())
            .unwrap_or_else(|| "Mozilla/5.0".to_string());

        // Create UPI authorization request message
        let auth_msg = BilldeskAuthorizationRequestMsg {
            merchant_id: item.router_data.resource_common_data.merchant_id.get_string_repr(),
            customer_id: customer_id.get_string_repr(),
            txn_reference_no: item.router_data.resource_common_data.connector_request_reference_id.clone(),
            bank_reference_no: None,
            txn_amount: amount,
            bank_id: None,
            txn_type: "UPI".to_string(),
            currency_type: item.router_data.request.currency.to_string(),
            item_code: "UPI".to_string(),
            txn_date: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            auth_status: "PENDING".to_string(),
            additional_info1: None,
            additional_info2: None,
            additional_info3: None,
            additional_info4: None,
            additional_info5: None,
            additional_info6: None,
            additional_info7: None,
            error_status: None,
            error_description: None,
            checksum: "dummy_checksum".to_string(), // STUB: Will implement actual checksum generation
        };

        let msg = serde_json::to_string(&auth_msg)
            .change_context(ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            msg,
            useragent: Some(user_agent),
            ipaddress: Some(ip_address),
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
    > TryFrom<BilldeskRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for BilldeskPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: BilldeskRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Create status request message
        let status_msg = BilldeskStatusRequestMsg {
            request_type: Some("STATUS".to_string()),
            merchant_id: item.router_data.resource_common_data.merchant_id.get_string_repr(),
            customer_id: item.router_data.resource_common_data.get_customer_id()?.get_string_repr(),
            txn_reference_no: item.router_data.request.get_connector_transaction_id()?,
            bank_reference_no: None,
            txn_amount: amount,
            bank_id: None,
            txn_type: Some("UPI".to_string()),
            currency_type: item.router_data.request.currency.to_string(),
            item_code: "UPI".to_string(),
            txn_date: None,
            auth_status: "SUCCESS".to_string(),
            additional_info1: None,
            additional_info2: None,
            additional_info3: None,
            additional_info4: None,
            additional_info5: None,
            additional_info6: None,
            additional_info7: None,
            error_status: "SUCCESS".to_string(),
            error_description: None,
            refund_status: None,
            total_refund_amount: None,
            last_refund_date: None,
            last_refund_ref_no: None,
            query_status: "SUCCESS".to_string(),
            checksum: "dummy_checksum".to_string(), // STUB: Will implement actual checksum generation
        };

        let msg = serde_json::to_string(&status_msg)
            .change_context(ConnectorError::RequestEncodingFailed)?;

        Ok(Self { msg })
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + serde::Serialize,
    > TryFrom<BilldeskRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>>
    for BilldeskPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: BilldeskRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_refund_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Create refund status request message
        let status_msg = BilldeskStatusRequestMsg {
            request_type: Some("REFUND_STATUS".to_string()),
            merchant_id: item.router_data.resource_common_data.merchant_id.get_string_repr(),
            customer_id: item.router_data.resource_common_data.get_customer_id()?.get_string_repr(),
            txn_reference_no: item.router_data.request.connector_transaction_id.clone(),
            bank_reference_no: None,
            txn_amount: amount,
            bank_id: None,
            txn_type: Some("REFUND".to_string()),
            currency_type: item.router_data.request.currency.to_string(),
            item_code: "REFUND".to_string(),
            txn_date: None,
            auth_status: "SUCCESS".to_string(),
            additional_info1: None,
            additional_info2: None,
            additional_info3: None,
            additional_info4: None,
            additional_info5: None,
            additional_info6: None,
            additional_info7: None,
            error_status: "SUCCESS".to_string(),
            error_description: None,
            refund_status: Some("SUCCESS".to_string()),
            total_refund_amount: None,
            last_refund_date: None,
            last_refund_ref_no: None,
            query_status: "SUCCESS".to_string(),
            checksum: "dummy_checksum".to_string(), // STUB: Will implement actual checksum generation
        };

        let msg = serde_json::to_string(&status_msg)
            .change_context(ConnectorError::RequestEncodingFailed)?;

        Ok(Self { msg })
    }
}

impl<
    F,
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize
        + serde::Serialize,
> TryFrom<ResponseRouterData<BilldeskPaymentsResponse, Self>>
for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<BilldeskPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            BilldeskPaymentsResponse::Success(success_response) => {
                let redirection_data = if let Some(rdata) = success_response.rdata {
                    if let Some(url) = rdata.url {
                        Some(Box::new(RedirectForm::Form {
                            endpoint: url,
                            method: common_utils::request::Method::Get,
                            form_fields: HashMap::new(),
                        }))
                    } else {
                        None
                    }
                } else {
                    None
                };

                (
                    common_enums::AttemptStatus::AuthenticationPending,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            router_data
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                        ),
                        redirection_data,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: success_response.txnrefno,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            BilldeskPaymentsResponse::Error(error_response) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    status_code: http_code,
                    code: error_response.error_code,
                    message: error_response.error_message.clone(),
                    reason: Some(error_response.error_description),
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
        + serde::Serialize
        + serde::Serialize,
> TryFrom<ResponseRouterData<BilldeskPaymentsSyncResponse, Self>>
for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<BilldeskPaymentsSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            BilldeskPaymentsSyncResponse::Success(success_response) => {
                let status = if success_response.msg.as_deref() == Some("SUCCESS") {
                    common_enums::AttemptStatus::Charged
                } else {
                    common_enums::AttemptStatus::Pending
                };

                (
                    status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            router_data
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: success_response.txnrefno,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            BilldeskPaymentsSyncResponse::Error(error_response) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    status_code: http_code,
                    code: error_response.error_code,
                    message: error_response.error_message.clone(),
                    reason: Some(error_response.error_description),
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
        + serde::Serialize
        + serde::Serialize,
> TryFrom<ResponseRouterData<BilldeskPaymentsSyncResponse, Self>>
for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<BilldeskPaymentsSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (refund_status, response) = match response {
            BilldeskPaymentsSyncResponse::Success(success_response) => {
                let refund_status = if success_response.msg.as_deref() == Some("SUCCESS") {
                    common_enums::RefundStatus::Success
                } else {
                    common_enums::RefundStatus::Pending
                };

                (
                    refund_status,
                    Ok(RefundsResponseData {
                        connector_refund_id: success_response.txnrefno.unwrap_or_default(),
                        refund_status,
                        status_code: http_code,
                    }),
                )
            }
            BilldeskPaymentsSyncResponse::Error(error_response) => (
                common_enums::RefundStatus::Failure,
                Err(ErrorResponse {
                    status_code: http_code,
                    code: error_response.error_code,
                    message: error_response.error_message.clone(),
                    reason: Some(error_response.error_description),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
        };

        Ok(Self {
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..router_data.resource_common_data
            },
            response,
            ..router_data
        })
    }
}