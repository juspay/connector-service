use std::collections::HashMap;

use common_utils::{
    errors::CustomResult, ext_traits::ValueExt, id_type, request::Method, types::StringMinorUnit,
    Email,
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsResponseData, ResponseId,
    },
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::billdesk::BilldeskRouterData, types::ResponseRouterData};

// UPI Payment Request
#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsRequest {
    msg: String,
    useragent: String,
    ipaddress: String,
}

// UPI Payment Response
#[derive(Default, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsResponse {
    msg: Option<String>,
    rdata: Option<BilldeskRData>,
    txnrefno: Option<String>,
}

#[derive(Default, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskRData {
    parameters: HashMap<String, String>,
    url: Option<String>,
}

// Payment Sync Request
#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsSyncRequest {
    msg: String,
}

// Payment Sync Response
#[derive(Default, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsSyncResponse {
    msg: Option<String>,
    rdata: Option<BilldeskSyncRData>,
    txnrefno: Option<String>,
}

#[derive(Default, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskSyncRData {
    parameters: HashMap<String, String>,
    url: Option<String>,
}

// Refund Sync Request
#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskRefundSyncRequest {
    msg: String,
}

// Refund Sync Response
#[derive(Default, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskRefundSyncResponse {
    msg: Option<String>,
    rdata: Option<BilldeskRefundSyncRData>,
    txnrefno: Option<String>,
}

#[derive(Default, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskRefundSyncRData {
    parameters: HashMap<String, String>,
    url: Option<String>,
}

// Authorization Response Message (from Haskell)
#[derive(Default, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskAuthorizationResponseMsg {
    merchant_id: String,
    customer_id: String,
    txn_reference_no: String,
    bank_reference_no: Option<String>,
    txn_amount: String,
    bank_id: Option<String>,
    filler1: Option<String>,
    txn_type: Option<String>,
    currency_type: String,
    item_code: String,
    filler2: Option<String>,
    filler3: Option<String>,
    filler4: Option<String>,
    txn_date: String,
    auth_status: String,
    filler5: Option<String>,
    additional_info1: Option<String>,
    additional_info2: Option<String>,
    additional_info3: Option<String>,
    additional_info4: Option<String>,
    additional_info5: Option<String>,
    additional_info6: Option<String>,
    additional_info7: Option<String>,
    error_status: String,
    error_description: Option<String>,
    checksum: String,
}

// Status Response Message (from Haskell)
#[derive(Default, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusResponseMsg {
    request_type: Option<String>,
    merchant_id: String,
    customer_id: String,
    txn_reference_no: String,
    bank_reference_no: Option<String>,
    txn_amount: String,
    bank_id: Option<String>,
    filler1: Option<String>,
    txn_type: Option<String>,
    currency_type: String,
    item_code: String,
    filler2: Option<String>,
    filler3: Option<String>,
    filler4: Option<String>,
    txn_date: Option<String>,
    auth_status: String,
    filler5: Option<String>,
    additional_info1: Option<String>,
    additional_info2: Option<String>,
    additional_info3: Option<String>,
    additional_info4: Option<String>,
    additional_info5: Option<String>,
    additional_info6: Option<String>,
    additional_info7: Option<String>,
    error_status: String,
    error_description: Option<String>,
    filler6: Option<String>,
    refund_status: String,
    total_refund_amount: String,
    last_refund_date: Option<String>,
    last_refund_ref_no: Option<String>,
    query_status: String,
    checksum: String,
}

// Error Response
#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
}

// Stub types for unsupported flows
#[derive(Debug, Clone, Serialize)]
pub struct BilldeskVoidRequest;
#[derive(Debug, Clone)]
pub struct BilldeskVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskCaptureRequest;
#[derive(Debug, Clone)]
pub struct BilldeskCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskRefundRequest;
#[derive(Debug, Clone)]
pub struct BilldeskRefundResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct BilldeskCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskSessionTokenRequest;
#[derive(Debug, Clone)]
pub struct BilldeskSessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskSetupMandateRequest;
#[derive(Debug, Clone)]
pub struct BilldeskSetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct BilldeskRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskAcceptRequest;
#[derive(Debug, Clone)]
pub struct BilldeskAcceptResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskSubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct BilldeskSubmitEvidenceResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct BilldeskDefendDisputeResponse;

// Payment status mapping
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BilldeskPaymentStatus {
    #[default]
    Pending,
    Success,
    Failure,
    Processing,
}

impl From<BilldeskPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: BilldeskPaymentStatus) -> Self {
        match item {
            BilldeskPaymentStatus::Success => Self::Charged,
            BilldeskPaymentStatus::Failure => Self::Failure,
            BilldeskPaymentStatus::Pending => Self::AuthenticationPending,
            BilldeskPaymentStatus::Processing => Self::Pending,
        }
    }
}

// Convert UPI payment request from router data
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        BilldeskRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    > for BilldeskPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: BilldeskRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
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

        // Get IP address
        let ip_address = item.router_data.request.get_ip_address_as_optional()
            .map(|ip| ip.expose())
            .unwrap_or_else(|| "127.0.0.1".to_string());

        // Get user agent
        let user_agent = item.router_data.request.browser_info
            .as_ref()
            .and_then(|info| info.user_agent.clone())
            .unwrap_or_else(|| "Mozilla/5.0".to_string());

        // Create message payload (simplified for UPI)
        let msg = serde_json::json!({
            "merchant_id": customer_id.get_string_repr(),
            "customer_id": customer_id.get_string_repr(),
            "txn_amount": amount,
            "currency": item.router_data.request.currency.to_string(),
            "txn_reference_no": item.router_data.resource_common_data.connector_request_reference_id,
            "payment_method_type": "UPI"
        }).to_string();

        Ok(Self {
            msg,
            useragent: user_agent,
            ipaddress: ip_address,
        })
    }
}

// Convert payment sync request from router data
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        BilldeskRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for BilldeskPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: BilldeskRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let connector_transaction_id = item.router_data.request.connector_transaction_id;

        // Create message payload for status check
        let msg = serde_json::json!({
            "merchant_id": item.router_data.resource_common_data.get_customer_id()?.get_string_repr(),
            "txn_reference_no": connector_transaction_id,
            "request_type": "STATUS"
        }).to_string();

        Ok(Self { msg })
    }
}

// Convert refund sync request from router data
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        BilldeskRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for BilldeskRefundSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: BilldeskRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let connector_transaction_id = item.router_data.request.connector_transaction_id;

        // Create message payload for refund status check
        let msg = serde_json::json!({
            "merchant_id": "merchant_id", // TODO: Get from appropriate source
            "txn_reference_no": connector_transaction_id,
            "request_type": "REFUND_STATUS"
        }).to_string();

        Ok(Self { msg })
    }
}

// Convert UPI payment response to router data
impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
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

        let (status, response_data) = match response {
            BilldeskPaymentsResponse {
                msg: Some(msg_str),
                rdata: Some(rdata),
                txnrefno: Some(txn_ref_no),
            } => {
                // Try to parse the message as authorization response
                let auth_response: Result<BilldeskAuthorizationResponseMsg, _> = 
                    serde_json::from_str(&msg_str)
                        .change_context(errors::ConnectorError::ResponseDeserializationFailed);

                match auth_response {
                    Ok(auth_resp) => {
                        let status = map_auth_status(&auth_resp.auth_status);
                        let response_id = ResponseId::ConnectorTransactionId(txn_ref_no.clone());

                        (
                            status,
                            Ok(PaymentsResponseData::TransactionResponse {
                                resource_id: response_id,
                                redirection_data: rdata.url.map(|url| {
                                    Box::new(RedirectForm::Form {
                                        endpoint: url,
                                        method: Method::Get,
                                        form_fields: HashMap::new(),
                                    })
                                }),
                                mandate_reference: None,
                                connector_metadata: None,
                                network_txn_id: auth_resp.bank_reference_no,
                                connector_response_reference_id: Some(txn_ref_no),
                                incremental_authorization_allowed: None,
                                status_code: http_code,
                            }),
                        )
                    }
                    Err(_) => {
                        // If we can't parse as auth response, treat as pending
                        (
                            common_enums::AttemptStatus::AuthenticationPending,
                            Ok(PaymentsResponseData::TransactionResponse {
                                resource_id: ResponseId::ConnectorTransactionId(txn_ref_no.clone()),
                                redirection_data: rdata.url.map(|url| {
                                    Box::new(RedirectForm::Form {
                                        endpoint: url,
                                        method: Method::Get,
                                        form_fields: HashMap::new(),
                                    })
                                }),
                                mandate_reference: None,
                                connector_metadata: None,
                                network_txn_id: None,
                                connector_response_reference_id: Some(txn_ref_no),
                                incremental_authorization_allowed: None,
                                status_code: http_code,
                            }),
                        )
                    }
                }
            }
            _ => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    status_code: http_code,
                    code: "INVALID_RESPONSE".to_string(),
                    message: "Invalid response from Billdesk".to_string(),
                    reason: Some("Invalid response format".to_string()),
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

// Convert payment sync response to router data
impl<
        F,
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

        let (status, response_data) = match response {
            BilldeskPaymentsSyncResponse {
                msg: Some(msg_str),
                rdata: _,
                txnrefno: Some(txn_ref_no),
            } => {
                // Try to parse the message as status response
                let status_response: Result<StatusResponseMsg, _> = 
                    serde_json::from_str(&msg_str)
                        .change_context(errors::ConnectorError::ResponseDeserializationFailed);

                match status_response {
                    Ok(status_resp) => {
                        let status = map_auth_status(&status_resp.auth_status);
                        let response_id = ResponseId::ConnectorTransactionId(txn_ref_no.clone());

                        (
                            status,
                            Ok(PaymentsResponseData::TransactionResponse {
                                resource_id: response_id,
                                redirection_data: None,
                                mandate_reference: None,
                                connector_metadata: None,
                                network_txn_id: status_resp.bank_reference_no,
                                connector_response_reference_id: Some(txn_ref_no),
                                incremental_authorization_allowed: None,
                                status_code: http_code,
                            }),
                        )
                    }
                    Err(_) => {
                        // If we can't parse as status response, treat as failure
                        (
                            common_enums::AttemptStatus::Failure,
                            Err(ErrorResponse {
                                status_code: http_code,
                                code: "INVALID_SYNC_RESPONSE".to_string(),
                                message: "Invalid sync response from Billdesk".to_string(),
                                reason: Some("Invalid response format".to_string()),
                                attempt_status: None,
                                connector_transaction_id: None,
                                network_advice_code: None,
                                network_decline_code: None,
                                network_error_message: None,
                            }),
                        )
                    }
                }
            }
            _ => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    status_code: http_code,
                    code: "INVALID_SYNC_RESPONSE".to_string(),
                    message: "Invalid sync response from Billdesk".to_string(),
                    reason: Some("Invalid response format".to_string()),
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

// Convert refund sync response to router data
impl<
        F,
    > TryFrom<ResponseRouterData<BilldeskRefundSyncResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<BilldeskRefundSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (_status, response_data) = match response {
            BilldeskRefundSyncResponse {
                msg: Some(msg_str),
                rdata: _,
                txnrefno: Some(txn_ref_no),
            } => {
                // Try to parse the message as refund status response
                let status_response: Result<StatusResponseMsg, _> = 
                    serde_json::from_str(&msg_str)
                        .change_context(errors::ConnectorError::ResponseDeserializationFailed);

                match status_response {
                    Ok(status_resp) => {
                        let refund_status = map_refund_status(&status_resp.refund_status);
                        let refund_status_enum = map_to_refund_status(&status_resp.refund_status);

                        (
                            refund_status,
                            Ok(RefundsResponseData {
                                connector_refund_id: txn_ref_no,
                                refund_status: refund_status_enum,
                                status_code: http_code,
                            }),
                        )
                    }
                    Err(_) => {
                        // If we can't parse as refund status response, treat as failure
                        (
                            common_enums::AttemptStatus::Failure,
                            Err(ErrorResponse {
                                status_code: http_code,
                                code: "INVALID_REFUND_SYNC_RESPONSE".to_string(),
                                message: "Invalid refund sync response from Billdesk".to_string(),
                                reason: Some("Invalid response format".to_string()),
                                attempt_status: None,
                                connector_transaction_id: None,
                                network_advice_code: None,
                                network_decline_code: None,
                                network_error_message: None,
                            }),
                        )
                    }
                }
            }
            _ => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    status_code: http_code,
                    code: "INVALID_REFUND_SYNC_RESPONSE".to_string(),
                    message: "Invalid refund sync response from Billdesk".to_string(),
                    reason: Some("Invalid response format".to_string()),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
        };

        Ok(Self {
            resource_common_data: router_data.resource_common_data,
            response: response_data,
            ..router_data
        })
    }
}

// Helper function to map authorization status
fn map_auth_status(auth_status: &str) -> common_enums::AttemptStatus {
    match auth_status.to_uppercase().as_str() {
        "0300" | "SUCCESS" => common_enums::AttemptStatus::Charged,
        "0399" | "FAILURE" => common_enums::AttemptStatus::Failure,
        "0001" | "0002" | "PENDING" => common_enums::AttemptStatus::AuthenticationPending,
        _ => common_enums::AttemptStatus::Pending,
    }
}

// Helper function to map refund status to AttemptStatus
fn map_refund_status(refund_status: &str) -> common_enums::AttemptStatus {
    match refund_status.to_uppercase().as_str() {
        "SUCCESS" => common_enums::AttemptStatus::Charged,
        "FAILURE" => common_enums::AttemptStatus::Failure,
        "PENDING" => common_enums::AttemptStatus::Pending,
        _ => common_enums::AttemptStatus::Pending,
    }
}

// Helper function to map refund status to RefundStatus
fn map_to_refund_status(refund_status: &str) -> common_enums::RefundStatus {
    match refund_status.to_uppercase().as_str() {
        "SUCCESS" => common_enums::RefundStatus::Success,
        "FAILURE" => common_enums::RefundStatus::Failure,
        "PENDING" => common_enums::RefundStatus::Pending,
        "REQUIRES_ACTION" => common_enums::RefundStatus::Pending,
        _ => common_enums::RefundStatus::Pending,
    }
}