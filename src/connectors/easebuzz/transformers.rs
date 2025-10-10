use std::collections::HashMap;

use common_enums::{AttemptStatus, Currency, PaymentMethodType};
use common_utils::{
    crypto,
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    pii::SecretSerdeValue,
    request::RequestContent,
    types::{self, MinorUnit},
};
use domain_types::{
    connector_types::{PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundsData, RefundsResponseData, RefundSyncData},
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use crate::{
    services::{api::ConnectorIntegrationV2, connector::ConnectorCommon},
    types::{ConnectorAuthType, ConnectorRequestHeaders, ConnectorRequestParams},
    utils::crypto_utils,
};

// Request/Response types for EaseBuzz

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzPaymentsRequest {
    pub key: Secret<String>,
    pub txnid: String,
    pub amount: String,
    pub productinfo: String,
    pub firstname: String,
    pub email: String,
    pub phone: String,
    pub surl: String,
    pub furl: String,
    pub hash: Secret<String>,
    pub payment_source: String,
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzPaymentsResponse {
    pub status: i32,
    pub error_desc: Option<String>,
    pub data: Option<EaseBuzzSeamlessTxnResponse>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzSeamlessTxnResponse {
    pub easebuzz_id: String,
    pub status: String,
    pub amount: String,
    pub txnid: String,
    pub card_no: Option<String>,
    pub bank_ref_num: Option<String>,
    pub bankcode: Option<String>,
    pub mode: String,
    pub card_type: Option<String>,
    pub name_on_card: Option<String>,
    pub addedon: String,
    pub email: String,
    pub phone: String,
    pub payment_source: String,
    pub vpa: Option<String>,
    pub error_desc: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzPaymentsSyncRequest {
    pub key: Secret<String>,
    pub txnid: String,
    pub amount: String,
    pub email: String,
    pub phone: String,
    pub hash: Secret<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzPaymentsSyncResponse {
    pub status: bool,
    pub msg: EaseBuzzTxnSyncMessageType,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum EaseBuzzTxnSyncMessageType {
    Success(EaseBuzzSeamlessTxnResponse),
    Error(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzRefundRequest {
    pub key: Secret<String>,
    pub txnid: String,
    pub refund_amount: String,
    pub refund_refno: String,
    pub hash: Secret<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzRefundResponse {
    pub status: bool,
    pub reason: Option<String>,
    pub easebuzz_id: Option<String>,
    pub refund_id: Option<String>,
    pub refund_amount: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzRefundSyncRequest {
    pub key: Secret<String>,
    pub easebuzz_id: String,
    pub hash: Secret<String>,
    pub merchant_refund_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzRefundSyncResponse {
    pub code: i32,
    pub status: String,
    pub response: EaseBuzzRefundSyncData,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzRefundSyncData {
    pub txnid: String,
    pub easebuzz_id: String,
    pub net_amount_debit: String,
    pub amount: String,
    pub refunds: Option<Vec<RefundSyncType>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RefundSyncType {
    pub refund_id: String,
    pub refund_status: String,
    pub merchant_refund_id: String,
    pub merchant_refund_date: String,
    pub refund_settled_date: Option<String>,
    pub refund_amount: String,
    pub arn_number: Option<String>,
}

// Helper functions for authentication and hash generation

fn get_auth_credentials(auth_type: &ConnectorAuthType) -> Result<(Secret<String>, Secret<String>), errors::ConnectorError> {
    match auth_type {
        ConnectorAuthType::SignatureKey { api_key, .. } => {
            let key = api_key.peek().clone();
            let salt = Secret::new("default_salt".to_string()); // In real implementation, this should come from auth_type
            Ok((Secret::new(key), salt))
        }
        _ => Err(errors::ConnectorError::AuthenticationFailed.into()),
    }
}

fn generate_easebuzz_hash(
    key: &str,
    txnid: &str,
    amount: &str,
    productinfo: &str,
    firstname: &str,
    email: &str,
    salt: &str,
) -> Result<String, errors::ConnectorError> {
    let hash_string = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        key, txnid, amount, productinfo, firstname, email, salt
    );
    
    let hash = crypto_utils::sha512_hash(hash_string.as_bytes())
        .change_context(errors::ConnectorError::RequestEncodingFailed)?;
    
    Ok(hex::encode(hash))
}

fn generate_refund_hash(
    key: &str,
    txnid: &str,
    refund_amount: &str,
    refund_refno: &str,
    salt: &str,
) -> Result<String, errors::ConnectorError> {
    let hash_string = format!(
        "{}|{}|{}|{}|{}",
        key, txnid, refund_amount, refund_refno, salt
    );
    
    let hash = crypto_utils::sha512_hash(hash_string.as_bytes())
        .change_context(errors::ConnectorError::RequestEncodingFailed)?;
    
    Ok(hex::encode(hash))
}

// Transformer implementations

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<&RouterDataV2<crate::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for EaseBuzzPaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &RouterDataV2<crate::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>) -> Result<Self, Self::Error> {
        let (key, salt) = get_auth_credentials(&item.connector_auth_type)?;
        
        let amount = item.amount.get_amount_as_string();
        let currency = item.router_data.request.currency.to_string();
        
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let customer_id_string = customer_id.get_string_repr();
        
        let transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;
        
        let return_url = item.router_data.request.get_router_return_url()?;
        let email = item.router_data.request.email.clone().unwrap_or_default().to_string();
        let phone = item.router_data.request.phone.clone().unwrap_or_default().to_string();
        
        let productinfo = format!("Payment for {}", transaction_id);
        
        let hash = generate_easebuzz_hash(
            key.peek(),
            &transaction_id,
            &amount,
            &productinfo,
            &customer_id_string,
            &email,
            salt.peek(),
        )?;
        
        let payment_source = match item.router_data.request.payment_method_type {
            PaymentMethodType::Upi => "upi",
            PaymentMethodType::UpiCollect => "upi_collect",
            PaymentMethodType::UpiIntent => "upi_intent",
            _ => "upi",
        };
        
        Ok(Self {
            key,
            txnid: transaction_id,
            amount,
            productinfo,
            firstname: customer_id_string,
            email,
            phone,
            surl: return_url.clone(),
            furl: return_url,
            hash: Secret::new(hash),
            payment_source: payment_source.to_string(),
            udf1: Some(currency),
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

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<&RouterDataV2<crate::connector_flow::PSync, domain_types::connector_types::PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for EaseBuzzPaymentsSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &RouterDataV2<crate::connector_flow::PSync, domain_types::connector_types::PaymentFlowData, PaymentsSyncData, PaymentsResponseData>) -> Result<Self, Self::Error> {
        let (key, salt) = get_auth_credentials(&item.connector_auth_type)?;
        
        let amount = item.amount.get_amount_as_string();
        let transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;
        
        let email = item.router_data.request.email.clone().unwrap_or_default().to_string();
        let phone = item.router_data.request.phone.clone().unwrap_or_default().to_string();
        
        let hash = generate_easebuzz_hash(
            key.peek(),
            &transaction_id,
            &amount,
            "payment_sync",
            "sync",
            &email,
            salt.peek(),
        )?;
        
        Ok(Self {
            key,
            txnid: transaction_id,
            amount,
            email,
            phone,
            hash: Secret::new(hash),
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<&RouterDataV2<crate::connector_flow::Refund, RefundFlowData, RefundsData, RefundsResponseData>>
    for EaseBuzzRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &RouterDataV2<crate::connector_flow::Refund, RefundFlowData, RefundsData, RefundsResponseData>) -> Result<Self, Self::Error> {
        let (key, salt) = get_auth_credentials(&item.connector_auth_type)?;
        
        let amount = item.amount.get_amount_as_string();
        let transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;
        
        let refund_id = item.router_data.request.refund_id.clone();
        
        let hash = generate_refund_hash(
            key.peek(),
            &transaction_id,
            &amount,
            &refund_id,
            salt.peek(),
        )?;
        
        Ok(Self {
            key,
            txnid: transaction_id,
            refund_amount: amount,
            refund_refno: refund_id,
            hash: Secret::new(hash),
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<&RouterDataV2<crate::connector_flow::RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>
    for EaseBuzzRefundSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &RouterDataV2<crate::connector_flow::RSync, RefundFlowData, RefundSyncData, RefundsResponseData>) -> Result<Self, Self::Error> {
        let (key, _salt) = get_auth_credentials(&item.connector_auth_type)?;
        
        let transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;
        
        let refund_id = item.router_data.request.refund_id.clone();
        
        // For RSync, we need the easebuzz_id from the original transaction
        // This would typically be stored in the database or retrieved from the payment response
        let easebuzz_id = item.router_data.request.get_connector_response_id()
            .unwrap_or_else(|| "unknown".to_string());
        
        let hash_string = format!("{}|{}|{}", key.peek(), &easebuzz_id, &refund_id);
        let hash = crypto_utils::sha512_hash(hash_string.as_bytes())
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        
        Ok(Self {
            key,
            easebuzz_id,
            hash: Secret::new(hex::encode(hash)),
            merchant_refund_id: refund_id,
        })
    }
}

// Response transformers

impl TryFrom<EaseBuzzPaymentsResponse> for PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: EaseBuzzPaymentsResponse) -> Result<Self, Self::Error> {
        match response.data {
            Some(txn_response) => {
                let status = match txn_response.status.as_str() {
                    "success" => AttemptStatus::Charged,
                    "pending" => AttemptStatus::Pending,
                    "failure" => AttemptStatus::Failure,
                    _ => AttemptStatus::Pending,
                };
                
                let amount_received = txn_response.amount.parse::<f64>()
                    .ok()
                    .map(|amt| MinorUnit::from_major_unit_as_i64(amt));
                
                Ok(Self {
                    status,
                    amount_received,
                    connector_transaction_id: Some(txn_response.txnid),
                    connector_response_id: Some(txn_response.easebuzz_id),
                    error_message: txn_response.error_desc,
                    ..Default::default()
                })
            }
            None => {
                let status = if response.status == 1 {
                    AttemptStatus::Pending
                } else {
                    AttemptStatus::Failure
                };
                
                Ok(Self {
                    status,
                    error_message: response.error_desc,
                    ..Default::default()
                })
            }
        }
    }
}

impl TryFrom<EaseBuzzPaymentsSyncResponse> for PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: EaseBuzzPaymentsSyncResponse) -> Result<Self, Self::Error> {
        match response.msg {
            EaseBuzzTxnSyncMessageType::Success(txn_response) => {
                let status = match txn_response.status.as_str() {
                    "success" => AttemptStatus::Charged,
                    "pending" => AttemptStatus::Pending,
                    "failure" => AttemptStatus::Failure,
                    _ => AttemptStatus::Pending,
                };
                
                let amount_received = txn_response.amount.parse::<f64>()
                    .ok()
                    .map(|amt| MinorUnit::from_major_unit_as_i64(amt));
                
                Ok(Self {
                    status,
                    amount_received,
                    connector_transaction_id: Some(txn_response.txnid),
                    connector_response_id: Some(txn_response.easebuzz_id),
                    error_message: txn_response.error_desc,
                    ..Default::default()
                })
            }
            EaseBuzzTxnSyncMessageType::Error(error_msg) => {
                Ok(Self {
                    status: AttemptStatus::Failure,
                    error_message: Some(error_msg),
                    ..Default::default()
                })
            }
        }
    }
}

impl TryFrom<EaseBuzzRefundResponse> for RefundsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: EaseBuzzRefundResponse) -> Result<Self, Self::Error> {
        let status = if response.status {
            AttemptStatus::Charged
        } else {
            AttemptStatus::Failure
        };
        
        let refund_amount = response.refund_amount
            .and_then(|amt| amt.parse::<f64>().ok())
            .map(|amt| MinorUnit::from_major_unit_as_i64(amt));
        
        Ok(Self {
            status,
            refund_id: response.refund_id,
            connector_refund_id: response.refund_id,
            refund_amount_received: refund_amount,
            error_message: response.reason,
            ..Default::default()
        })
    }
}

impl TryFrom<EaseBuzzRefundSyncResponse> for RefundsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: EaseBuzzRefundSyncResponse) -> Result<Self, Self::Error> {
        let sync_data = response.response;
        
        // Find the refund with matching merchant_refund_id
        let refund_info = sync_data.refunds
            .and_then(|refunds| refunds.into_iter().find(|r| r.merchant_refund_id == sync_data.txnid));
        
        match refund_info {
            Some(refund) => {
                let status = match refund.refund_status.as_str() {
                    "success" => AttemptStatus::Charged,
                    "pending" => AttemptStatus::Pending,
                    "failure" => AttemptStatus::Failure,
                    _ => AttemptStatus::Pending,
                };
                
                let refund_amount = refund.refund_amount.parse::<f64>()
                    .ok()
                    .map(|amt| MinorUnit::from_major_unit_as_i64(amt));
                
                Ok(Self {
                    status,
                    refund_id: Some(refund.merchant_refund_id),
                    connector_refund_id: Some(refund.refund_id),
                    refund_amount_received: refund_amount,
                    ..Default::default()
                })
            }
            None => {
                Ok(Self {
                    status: AttemptStatus::Failure,
                    error_message: Some("Refund not found".to_string()),
                    ..Default::default()
                })
            }
        }
    }
}