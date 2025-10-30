use std::collections::HashMap;

use common_utils::{
    request::Method,
    types::{StringMinorUnit, AmountConvertor},
    Email,
};
use sha2::Digest;
use domain_types::{
    connector_flow::{Authorize, PSync, Refund, RSync},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, 
        RefundFlowData, RefundsData, RefundsResponseData, RefundSyncData, ResponseId
    },
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    
};
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{types::ResponseRouterData};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzAuth {
    pub key: Secret<String>,
    pub salt: Secret<String>,
    pub merchant_id: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for EaseBuzzAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1, .. } => Ok(Self {
                key: api_key.clone(),
                salt: key1.clone(),
                merchant_id: None,
            }),
            ConnectorAuthType::MultiAuthKey { api_key, key1, .. } => Ok(Self {
                key: api_key.clone(),
                salt: key1.clone(),
                merchant_id: None,
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsRequest {
    pub key: Secret<String>,
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub productinfo: String,
    pub firstname: Option<Secret<String>>,
    pub email: Option<Email>,
    pub phone: Option<Secret<String>>,
    pub surl: String,
    pub furl: String,
    pub hash: Secret<String>,
    pub udf1: Option<String>,
    pub udf2: Option<String>,
    pub udf3: Option<String>,
    pub udf4: Option<String>,
    pub udf5: Option<String>,
    pub udf6: Option<String>,
    pub udf7: Option<String>,
    pub udf8: Option<String>,
    pub udf9: Option<String>,
    pub udf10: Option<String>,
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub zipcode: Option<String>,
    pub pg: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzUpiIntentRequest {
    pub key: Secret<String>,
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub vpa: Option<String>,
    pub customer_name: Option<Secret<String>>,
    pub customer_email: Option<Email>,
    pub customer_mobile: Option<Secret<String>>,
    pub hash: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSyncRequest {
    pub key: Secret<String>,
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub email: Option<Email>,
    pub phone: Option<Secret<String>>,
    pub hash: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzRefundRequest {
    pub key: Secret<String>,
    pub txnid: String,
    pub refund_amount: StringMinorUnit,
    pub refund_refid: String,
    pub hash: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzRSyncRequest {
    pub key: Secret<String>,
    pub easebuzz_id: String,
    pub hash: Secret<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsResponse {
    pub status: i32,
    pub error_desc: Option<String>,
    pub data: Option<EaseBuzzResponseData>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzResponseData {
    pub payment_url: Option<String>,
    pub transaction_id: Option<String>,
    pub easebuzz_id: Option<String>,
    pub status: Option<String>,
    pub amount: Option<String>,
    pub currency: Option<String>,
    pub name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub productinfo: Option<String>,
    pub txnid: Option<String>,
    pub hash: Option<String>,
    pub payment_source: Option<String>,
    pub card_no: Option<String>,
    pub card_name: Option<String>,
    pub bank_ref_num: Option<String>,
    pub bankcode: Option<String>,
    pub error: Option<String>,
    pub error_message: Option<String>,
    pub unmappedstatus: Option<String>,
    pub additional_charges: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzUpiIntentResponse {
    pub status: bool,
    pub msg_desc: String,
    pub qr_link: Option<String>,
    pub msg_title: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSyncResponse {
    pub status: bool,
    pub msg: EaseBuzzTxnSyncMessageType,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EaseBuzzTxnSyncMessageType {
    Success(EaseBuzzResponseData),
    Error(String),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzRefundResponse {
    pub status: bool,
    pub reason: Option<String>,
    pub easebuzz_id: Option<String>,
    pub refund_id: Option<String>,
    pub refund_amount: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzRSyncResponse {
    pub code: i32,
    pub status: String,
    pub response: EaseBuzzRefundSyncResponse,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EaseBuzzRefundSyncResponse {
    Success(EaseBuzzRefundSyncSuccessResponse),
    Failure(EaseBuzzRefundSyncFailureResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzRefundSyncSuccessResponse {
    pub txnid: String,
    pub easebuzz_id: String,
    pub net_amount_debit: String,
    pub amount: String,
    pub refunds: Option<Vec<EaseBuzzRefundSyncType>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzRefundSyncFailureResponse {
    pub status: String,
    pub message: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzRefundSyncType {
    pub refund_id: String,
    pub refund_status: String,
    pub merchant_refund_id: String,
    pub merchant_refund_date: String,
    pub refund_settled_date: Option<String>,
    pub refund_amount: String,
    pub arn_number: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzErrorResponse {
    pub status: i32,
    pub error_desc: Option<String>,
    pub error_code: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EaseBuzzPaymentsResponseEnum {
    Success(EaseBuzzPaymentsResponse),
    Error(EaseBuzzErrorResponse),
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for EaseBuzzPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = EaseBuzzAuth::try_from(&item.connector_auth_type)?;
        let customer_id = item.resource_common_data.get_customer_id()?;
        let return_url = item.request.get_router_return_url()?;

        // CRITICAL: Use amount converter properly - never hardcode amounts
        let amount_converter = common_utils::types::StringMinorUnitForConnector;
        let amount = amount_converter
            .convert(item.request.minor_amount, item.request.currency)
            .map_err(|_| ConnectorError::RequestEncodingFailed)?;

        // Generate hash - this would typically involve SHA512 of parameters + salt
        let hash_string = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            auth.key.peek(),
            item.resource_common_data.connector_request_reference_id,
            amount.to_string(),
            "Payment", // productinfo
            customer_id.get_string_repr(),
            item.request.email.as_ref().map(|e| e.to_string()).unwrap_or_default(),
            String::new(), // Phone number not available in standard flow
            return_url.clone(),
            return_url, // furl same as surl
            "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", // udf fields
            auth.salt.peek()
        );
        
        let hash = Secret::new(format!("{:x}", sha2::Sha512::digest(hash_string)));

        Ok(Self {
            key: auth.key,
            txnid: item.resource_common_data.connector_request_reference_id.clone(),
            amount,
            productinfo: "Payment".to_string(),
            firstname: Some(Secret::new(customer_id.get_string_repr().to_string())),
            email: item.request.email.clone(),
            phone: None, // Phone number not available in standard flow
            surl: return_url.clone(),
            furl: return_url,
            hash,
            udf1: None,
            udf2: None,
            udf3: None,
            udf4: None,
            udf5: None,
            udf6: None,
            udf7: None,
            udf8: None,
            udf9: None,
            udf10: None,
            address1: None,
            address2: None,
            city: None,
            state: None,
            country: None,
            zipcode: None,
            pg: Some("upi".to_string()), // UPI focused as per requirements
        })
    }
}

impl TryFrom<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for EaseBuzzPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = EaseBuzzAuth::try_from(&item.connector_auth_type)?;
        
        // CRITICAL: Use amount converter properly - never hardcode amounts
        let amount_converter = common_utils::types::StringMinorUnitForConnector;
        let amount = amount_converter
            .convert(item.request.amount, item.request.currency)
            .map_err(|_| ConnectorError::RequestEncodingFailed)?;

        // Generate hash for sync request
        let hash_string = format!(
            "{}|{}|{}|{}|{}|{}",
            auth.key.peek(),
            item.request.connector_transaction_id.get_connector_transaction_id()
                .map_err(|_| ConnectorError::MissingRequiredField { field_name: "connector_transaction_id" })?,
            amount.to_string(),
            String::new(), // Email not available in sync request
            String::new(), // Phone number not available in sync request
            auth.salt.peek()
        );
        
        let hash = Secret::new(format!("{:x}", sha2::Sha512::digest(hash_string)));

        Ok(Self {
            key: auth.key,
            txnid: item.request.connector_transaction_id.get_connector_transaction_id()
                .map_err(|_| ConnectorError::MissingRequiredField { field_name: "connector_transaction_id" })?,
            amount,
            email: None, // Email not available in sync request
            phone: None, // Phone number not available in sync request
            hash,
        })
    }
}

impl TryFrom<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>
    for EaseBuzzRefundRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = EaseBuzzAuth::try_from(&item.connector_auth_type)?;
        
        // CRITICAL: Use amount converter properly - never hardcode amounts
        let amount_converter = common_utils::types::StringMinorUnitForConnector;
        let refund_amount = amount_converter
            .convert(item.request.minor_refund_amount, item.request.currency)
            .map_err(|_| ConnectorError::RequestEncodingFailed)?;

        // Generate hash for refund request
        let hash_string = format!(
            "{}|{}|{}|{}|{}",
            auth.key.peek(),
            item.request.connector_transaction_id.get_connector_transaction_id()
                .map_err(|_| ConnectorError::MissingRequiredField { field_name: "connector_transaction_id" })?,
            refund_amount.to_string(),
            item.request.refund_id.clone(),
            auth.salt.peek()
        );
        
        let hash = Secret::new(format!("{:x}", sha2::Sha512::digest(hash_string)));

        Ok(Self {
            key: auth.key,
            txnid: item.request.connector_transaction_id.get_connector_transaction_id()
                .map_err(|_| ConnectorError::MissingRequiredField { field_name: "connector_transaction_id" })?,
            refund_amount,
            refund_refid: item.request.refund_id.clone(),
            hash,
        })
    }
}

impl TryFrom<&RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>
    for EaseBuzzRSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = EaseBuzzAuth::try_from(&item.connector_auth_type)?;

        // Generate hash for refund sync request
        let hash_string = format!(
            "{}|{}|{}",
            auth.key.peek(),
            item.request.connector_transaction_id.get_connector_transaction_id()
                .map_err(|_| ConnectorError::MissingRequiredField { field_name: "connector_transaction_id" })?,
            auth.salt.peek()
        );
        
        let hash = Secret::new(format!("{:x}", sha2::Sha512::digest(hash_string)));

        Ok(Self {
            key: auth.key,
            easebuzz_id: item.request.connector_transaction_id.get_connector_transaction_id()
                .map_err(|_| ConnectorError::MissingRequiredField { field_name: "connector_transaction_id" })?,
            hash,
        })
    }
}

impl<T: PaymentMethodDataTypes> TryFrom<ResponseRouterData<EaseBuzzPaymentsResponseEnum, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
where
    T: std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EaseBuzzPaymentsResponseEnum, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            EaseBuzzPaymentsResponseEnum::Success(success_data) => {
                if success_data.status == 1 {
                    if let Some(data) = success_data.data {
                        if let Some(payment_url) = data.payment_url {
                            let redirection_data = RedirectForm::Form {
                                endpoint: payment_url,
                                method: Method::Get,
                                form_fields: HashMap::new(),
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
                                    redirection_data: Some(Box::new(redirection_data)),
                                    mandate_reference: None,
                                    connector_metadata: None,
                                    network_txn_id: data.easebuzz_id,
                                    connector_response_reference_id: data.transaction_id,
                                    incremental_authorization_allowed: None,
                                    status_code: http_code,
                                }),
                            )
                        } else {
                            (
                                common_enums::AttemptStatus::Charged,
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
                                    network_txn_id: data.easebuzz_id,
                                    connector_response_reference_id: data.transaction_id,
                                    incremental_authorization_allowed: None,
                                    status_code: http_code,
                                }),
                            )
                        }
                    } else {
                        (
                            common_enums::AttemptStatus::Pending,
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
                                network_txn_id: None,
                                connector_response_reference_id: None,
                                incremental_authorization_allowed: None,
                                status_code: http_code,
                            }),
                        )
                    }
                } else {
                    (
                        common_enums::AttemptStatus::Failure,
                        Err(ErrorResponse {
                            status_code: http_code,
                            code: success_data.status.to_string(),
                            message: success_data.error_desc.clone().unwrap_or_default(),
                            reason: success_data.error_desc,
                            attempt_status: None,
                            connector_transaction_id: None,
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: None,
                        }),
                    )
                }
            }
            EaseBuzzPaymentsResponseEnum::Error(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    status_code: http_code,
                    code: error_data.status.to_string(),
                    message: error_data.error_desc.as_ref().or(error_data.message.as_ref()).cloned().unwrap_or_default(),
                    reason: error_data.error_desc.as_ref().or(error_data.message.as_ref()).cloned(),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
        };

        Ok(Self {
            flow: router_data.flow,
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            connector_auth_type: router_data.connector_auth_type,
            request: router_data.request,
            response,
        })
    }
}

impl TryFrom<ResponseRouterData<EaseBuzzPaymentsSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EaseBuzzPaymentsSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = if response.status {
            match response.msg {
                EaseBuzzTxnSyncMessageType::Success(data) => {
                    let attempt_status = match data.status.as_deref() {
                        Some("success") => common_enums::AttemptStatus::Charged,
                        Some("pending") => common_enums::AttemptStatus::Pending,
                        Some("failure") => common_enums::AttemptStatus::Failure,
                        _ => common_enums::AttemptStatus::Pending,
                    };

                    (
                        attempt_status,
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
                            network_txn_id: data.easebuzz_id,
                            connector_response_reference_id: data.transaction_id,
                            incremental_authorization_allowed: None,
                            status_code: http_code,
                        }),
                    )
                }
                EaseBuzzTxnSyncMessageType::Error(_) => (
                    common_enums::AttemptStatus::Failure,
                    Err(ErrorResponse {
                        status_code: http_code,
                        code: "SYNC_ERROR".to_string(),
                        message: "Transaction sync failed".to_string(),
                        reason: Some("Transaction sync failed".to_string()),
                        attempt_status: None,
                        connector_transaction_id: None,
                        network_advice_code: None,
                        network_decline_code: None,
                        network_error_message: None,
                    }),
                ),
            }
        } else {
            (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    status_code: http_code,
                    code: "SYNC_FAILED".to_string(),
                    message: "Transaction sync failed".to_string(),
                    reason: Some("Transaction sync failed".to_string()),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            )
        };

        Ok(Self {
            flow: router_data.flow,
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            connector_auth_type: router_data.connector_auth_type,
            request: router_data.request,
            response,
        })
    }
}

impl TryFrom<ResponseRouterData<EaseBuzzRefundResponse, RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EaseBuzzRefundResponse, RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = if response.status {
            (
                common_enums::AttemptStatus::Charged,
                Ok(RefundsResponseData {
                    refund_id: response.refund_id.clone(),
                    connector_refund_id: response.refund_id,
                    refund_status: common_enums::RefundStatus::Success,
                    connector_transaction_id: response.easebuzz_id,
                    amount_received: response.refund_amount.and_then(|amt| {
                        amt.parse::<f64>().ok().map(|f| common_utils::types::MinorUnit::new((f * 100.0) as i64))
                    }),
                }),
            )
        } else {
            (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    status_code: http_code,
                    code: "REFUND_FAILED".to_string(),
                    message: response.reason.clone().unwrap_or_default(),
                    reason: response.reason,
                    attempt_status: None,
                    connector_transaction_id: response.easebuzz_id,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            )
        };

        Ok(Self {
            flow: router_data.flow,
            resource_common_data: router_data.resource_common_data,
            connector_auth_type: router_data.connector_auth_type,
            request: router_data.request,
            response,
        })
    }
}

impl TryFrom<ResponseRouterData<EaseBuzzRSyncResponse, RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EaseBuzzRSyncResponse, RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response.response {
            EaseBuzzRefundSyncResponse::Success(success_data) => {
                let refund_status = if let Some(refunds) = success_data.refunds {
                    if let Some(refund) = refunds.first() {
                        match refund.refund_status.as_str() {
                            "success" => common_enums::RefundStatus::Success,
                            "pending" => common_enums::RefundStatus::Pending,
                            "failure" => common_enums::RefundStatus::Failure,
                            _ => common_enums::RefundStatus::Pending,
                        }
                    } else {
                        common_enums::RefundStatus::Pending
                    }
                } else {
                    common_enums::RefundStatus::Pending
                };

                (
                    common_enums::AttemptStatus::Charged,
                    Ok(RefundsResponseData {
                        refund_id: success_data.refunds.as_ref()
                            .and_then(|r| r.first())
                            .map(|r| r.refund_id.clone()),
                        connector_refund_id: success_data.refunds.as_ref()
                            .and_then(|r| r.first())
                            .map(|r| r.refund_id.clone()),
                        refund_status,
                        connector_transaction_id: Some(success_data.easebuzz_id),
                        amount_received: success_data.refunds.as_ref()
                            .and_then(|r| r.first())
                            .and_then(|r| r.refund_amount.parse::<f64>().ok())
                            .map(|f| common_utils::types::MinorUnit::new((f * 100.0) as i64)),
                    }),
                )
            }
            EaseBuzzRefundSyncResponse::Failure(failure_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    status_code: http_code,
                    code: "REFUND_SYNC_FAILED".to_string(),
                    message: failure_data.message.clone(),
                    reason: Some(failure_data.message),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
        };

        Ok(Self {
            flow: router_data.flow,
            resource_common_data: router_data.resource_common_data,
            connector_auth_type: router_data.connector_auth_type,
            request: router_data.request,
            response,
        })
    }
}