use std::collections::HashMap;

use common_utils::{
    errors::CustomResult, ext_traits::ValueExt, request::Method, types::StringMinorUnit,
    Email,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::easebuzz::EaseBuzzRouterData, types::ResponseRouterData};

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
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsRequest {
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub productinfo: String,
    pub firstname: Option<Secret<String>>,
    pub email: Option<Email>,
    pub phone: Option<Secret<String>>,
    pub surl: String,
    pub furl: String,
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
    pub hash: Secret<String>,
    pub payment_source: String,
    pub pg: Option<String>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzSeamlessTxnRequest {
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub email: Option<Email>,
    pub phone: Option<Secret<String>>,
    pub firstname: Option<Secret<String>>,
    pub surl: String,
    pub furl: String,
    pub hash: Secret<String>,
    pub payment_source: String,
    pub bankcode: Option<String>,
    pub vpa: Option<String>,
    pub card_no: Option<Secret<String>>,
    pub card_name: Option<Secret<String>>,
    pub expiry_month: Option<String>,
    pub expiry_year: Option<String>,
    pub cvv: Option<Secret<String>>,
    pub card_token: Option<Secret<String>>,
    pub emi_plan_id: Option<String>,
    pub pg: Option<String>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzTxnSyncRequest {
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub email: Option<Email>,
    pub phone: Option<Secret<String>>,
    pub key: Secret<String>,
    pub hash: Secret<String>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzRefundRequest {
    pub txnid: String,
    pub refund_amount: StringMinorUnit,
    pub refund_reason: Option<String>,
    pub refund_refid: String,
    pub key: Secret<String>,
    pub hash: Secret<String>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzRefundSyncRequest {
    pub key: Secret<String>,
    pub easebuzz_id: String,
    pub hash: Secret<String>,
    pub merchant_refund_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsResponse {
    pub status: bool,
    pub data: Option<EaseBuzzResponseData>,
    pub error_desc: Option<String>,
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
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzSeamlessTxnResponse {
    pub status: bool,
    pub data: Option<EaseBuzzSeamlessTxnData>,
    pub error_desc: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzSeamlessTxnData {
    pub transaction_id: Option<String>,
    pub easebuzz_id: Option<String>,
    pub status: Option<String>,
    pub amount: Option<String>,
    pub currency: Option<String>,
    pub payment_source: Option<String>,
    pub bank_ref_num: Option<String>,
    pub bankcode: Option<String>,
    pub card_no: Option<String>,
    pub name_on_card: Option<String>,
    pub card_token: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzTxnSyncResponse {
    pub status: bool,
    pub msg: EaseBuzzTxnSyncMessage,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EaseBuzzTxnSyncMessage {
    Success(EaseBuzzSeamlessTxnResponse),
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
pub struct EaseBuzzRefundSyncResponse {
    pub code: i32,
    pub status: String,
    pub response: EaseBuzzRefundSyncData,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzRefundSyncData {
    pub txnid: String,
    pub easebuzz_id: String,
    pub net_amount_debit: String,
    pub amount: String,
    pub refunds: Option<Vec<EaseBuzzRefundSyncType>>,
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
    pub data: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzUpiIntentResponse {
    pub status: bool,
    pub msg_desc: String,
    pub qr_link: Option<String>,
    pub msg_title: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<EaseBuzzRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for EaseBuzzPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: EaseBuzzRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = EaseBuzzAuth::try_from(&item.router_data.connector_auth_type)?;
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

        let hash = generate_easebuzz_hash(
            &auth.key.peek(),
            &item.router_data.resource_common_data.connector_request_reference_id,
            &amount.to_string(),
            &item.router_data.request.currency.to_string(),
            &auth.salt.peek(),
        )?;

        Ok(Self {
            txnid: item.router_data.resource_common_data.connector_request_reference_id.clone(),
            amount,
            productinfo: "Payment".to_string(),
            firstname: None,
            email: item.router_data.request.email.clone(),
            phone: None,
            surl: return_url.clone(),
            furl: return_url,
            udf1: Some(customer_id.get_string_repr().to_string()),
            hash: Secret::new(hash),
            payment_source: get_payment_source(item.router_data.request.payment_method_type)?,
            pg: None,
            udf2: None,
            udf3: None,
            udf4: None,
            udf5: None,
            udf6: None,
            udf7: None,
            udf8: None,
            udf9: None,
            udf10: None,
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<EaseBuzzRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for EaseBuzzSeamlessTxnRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: EaseBuzzRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = EaseBuzzAuth::try_from(&item.router_data.connector_auth_type)?;
        let return_url = item.router_data.request.get_router_return_url()?;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let hash = generate_easebuzz_hash(
            &auth.key.peek(),
            &item.router_data.resource_common_data.connector_request_reference_id,
            &amount.to_string(),
            &item.router_data.request.currency.to_string(),
            &auth.salt.peek(),
        )?;

        Ok(Self {
            txnid: item.router_data.resource_common_data.connector_request_reference_id.clone(),
            amount,
            email: item.router_data.request.email.clone(),
            phone: None,
            firstname: None,
            surl: return_url.clone(),
            furl: return_url,
            hash: Secret::new(hash),
            payment_source: get_payment_source(item.router_data.request.payment_method_type)?,
            bankcode: None,
            vpa: extract_upi_vpa(&item.router_data.request.payment_method_data)?,
            card_no: None,
            card_name: None,
            expiry_month: None,
            expiry_year: None,
            cvv: None,
            card_token: None,
            emi_plan_id: None,
            pg: None,
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<EaseBuzzRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for EaseBuzzTxnSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: EaseBuzzRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = EaseBuzzAuth::try_from(&item.router_data.connector_auth_type)?;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                common_utils::types::MinorUnit(1000), // Default amount for sync - should be extracted from request
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let hash = generate_sync_hash(
            &auth.key.peek(),
            &item.router_data.request.connector_transaction_id.get_connector_transaction_id()
                .map_err(|_| ConnectorError::MissingRequiredField { field_name: "connector_transaction_id" })?,
            &amount.to_string(),
            &item.router_data.request.currency.to_string(),
            &auth.salt.peek(),
        )?;

        Ok(Self {
            txnid: item.router_data.request.connector_transaction_id.get_connector_transaction_id()
                .map_err(|_| ConnectorError::MissingRequiredField { field_name: "connector_transaction_id" })?,
            amount,
            email: None,
            phone: None,
            key: auth.key,
            hash: Secret::new(hash),
        })
    }
}

impl<F, T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<EaseBuzzPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EaseBuzzPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response_data) = if response.status {
            if let Some(data) = response.data {
                let redirection_data = if let Some(payment_url) = data.payment_url {
                    Some(Box::new(RedirectForm::Form {
                        endpoint: payment_url,
                        method: Method::Get,
                        form_fields: HashMap::new(),
                    }))
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
                        network_txn_id: data.easebuzz_id,
                        connector_response_reference_id: data.transaction_id,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            } else {
                (
                    common_enums::AttemptStatus::Failure,
                    Err(ErrorResponse {
                        code: "NO_DATA".to_string(),
                        status_code: http_code,
                        message: "No response data received".to_string(),
                        reason: Some("No response data received".to_string()),
                        attempt_status: None,
                        connector_transaction_id: None,
                        network_advice_code: None,
                        network_decline_code: None,
                        network_error_message: None,
                    }),
                )
            }
        } else {
            (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: "PAYMENT_FAILED".to_string(),
                    status_code: http_code,
                    message: response.error_desc.clone().unwrap_or_default(),
                    reason: response.error_desc,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            )
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

impl<F, T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<EaseBuzzTxnSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EaseBuzzTxnSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response_data) = if response.status {
            match response.msg {
                EaseBuzzTxnSyncMessage::Success(success_response) => {
                    if success_response.status {
                        let attempt_status = map_easebuzz_status_to_attempt_status(
                            success_response.data.as_ref().and_then(|d| d.status.as_deref()),
                        );

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
                                network_txn_id: success_response
                                    .data
                                    .as_ref()
                                    .and_then(|d| d.easebuzz_id.clone()),
                                connector_response_reference_id: success_response
                                    .data
                                    .as_ref()
                                    .and_then(|d| d.transaction_id.clone()),
                                incremental_authorization_allowed: None,
                                status_code: http_code,
                            }),
                        )
                    } else {
                        (
                            common_enums::AttemptStatus::Failure,
                            Err(ErrorResponse {
                                code: "SYNC_FAILED".to_string(),
                                status_code: http_code,
                                message: success_response.error_desc.unwrap_or_default(),
                                reason: success_response.error_desc,
                                attempt_status: None,
                                connector_transaction_id: None,
                                network_advice_code: None,
                                network_decline_code: None,
                                network_error_message: None,
                            }),
                        )
                    }
                }
                EaseBuzzTxnSyncMessage::Error(error_msg) => (
                    common_enums::AttemptStatus::Failure,
                    Err(ErrorResponse {
                        code: "SYNC_ERROR".to_string(),
                        status_code: http_code,
                        message: error_msg,
                        reason: Some(error_msg),
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
                    code: "SYNC_FAILED".to_string(),
                    status_code: http_code,
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
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: response_data,
            ..router_data
        })
    }
}

fn generate_easebuzz_hash(
    key: &str,
    txnid: &str,
    amount: &str,
    currency: &str,
    salt: &str,
) -> CustomResult<String, ConnectorError> {
    use common_utils::crypto;
    
    let hash_string = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        key, txnid, amount, "Payment", "", "", "", "", "", "", currency, salt
    );
    
    let digest = crypto::Sha512::digest(hash_string.as_bytes());
    Ok(hex::encode(digest))
}

fn generate_sync_hash(
    key: &str,
    txnid: &str,
    amount: &str,
    currency: &str,
    salt: &str,
) -> CustomResult<String, ConnectorError> {
    use common_utils::crypto;
    
    let hash_string = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        key, txnid, amount, "", "", "", "", "", "", "", currency, salt
    );
    
    let digest = crypto::Sha512::digest(hash_string.as_bytes());
    Ok(hex::encode(digest))
}

fn get_payment_source(
    payment_method_type: Option<common_enums::PaymentMethodType>,
) -> CustomResult<String, ConnectorError> {
    match payment_method_type {
        Some(common_enums::PaymentMethodType::UpiCollect) => Ok("upi".to_string()),
        Some(common_enums::PaymentMethodType::UpiIntent) => Ok("upi".to_string()),
        _ => Ok("upi".to_string()), // Default to UPI for EaseBuzz
    }
}

fn extract_upi_vpa<T>(
    payment_method_data: &domain_types::payment_method_data::PaymentMethodData<T>,
) -> CustomResult<Option<String>, ConnectorError>
where
    T: PaymentMethodDataTypes,
{
    match payment_method_data {
        domain_types::payment_method_data::PaymentMethodData::Upi(upi_data) => {
            Ok(None) // TODO: Extract VPA when UPI data structure is available
        }
        _ => Ok(None),
    }
}

fn map_easebuzz_status_to_attempt_status(status: Option<&str>) -> common_enums::AttemptStatus {
    match status {
        Some("success") => common_enums::AttemptStatus::Charged,
        Some("failure") => common_enums::AttemptStatus::Failure,
        Some("pending") => common_enums::AttemptStatus::Pending,
        Some("user_pending") => common_enums::AttemptStatus::AuthenticationPending,
        _ => common_enums::AttemptStatus::Pending,
    }
}