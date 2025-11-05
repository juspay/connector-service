// EaseBuzz Transformers - Request/Response transformations

use std::collections::HashMap;

use common_enums::{AttemptStatus, PaymentMethodType, RefundStatus};
use common_utils::{
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    request::RequestContent,
    types::{self, StringMinorUnit},
};
use domain_types::{
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    types as domain_types,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use super::constants::*;

// Request/Response Types for EaseBuzz

#[derive(Debug, Serialize)]
pub struct EaseBuzzPaymentsRequest {
    pub txnid: String,
    pub amount: String,
    pub currency: String,
    pub email: Option<String>,
    pub phone: Option<String>,
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
    pub surl: Option<String>,
    pub furl: Option<String>,
    pub hash: String,
    pub payment_source: String,
    pub payment_mode: Option<String>,
    pub upi_vpa: Option<String>,
    pub upi_intent_app: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzPaymentsResponse {
    pub status: i32,
    pub error_desc: Option<String>,
    pub data: EaseBuzzPaymentsResponseData,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzPaymentsResponseData {
    pub txnid: Option<String>,
    pub easebuzz_id: Option<String>,
    pub status: Option<String>,
    pub amount: Option<String>,
    pub currency: Option<String>,
    pub payment_source: Option<String>,
    pub payment_mode: Option<String>,
    pub card_no: Option<String>,
    pub card_type: Option<String>,
    pub bank_ref_no: Option<String>,
    pub bank_code: Option<String>,
    pub name_on_card: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub error_desc: Option<String>,
    pub error_code: Option<String>,
    pub pg_resp_code: Option<String>,
    pub pg_resp_msg: Option<String>,
    pub created_at: Option<String>,
    pub modified_at: Option<String>,
    pub upi_vpa: Option<String>,
    pub upi_intent_app: Option<String>,
    pub qr_link: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EaseBuzzPaymentsSyncRequest {
    pub txnid: String,
    pub amount: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub key: String,
    pub hash: String,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzPaymentsSyncResponse {
    pub status: bool,
    pub msg: EaseBuzzTxnSyncMessageType,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum EaseBuzzTxnSyncMessageType {
    Success(EaseBuzzPaymentsResponseData),
    Error(String),
}

#[derive(Debug, Serialize)]
pub struct EaseBuzzRefundRequest {
    pub txnid: String,
    pub refund_amount: String,
    pub refund_note: Option<String>,
    pub key: String,
    pub hash: String,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundResponse {
    pub status: bool,
    pub reason: Option<String>,
    pub easebuzz_id: Option<String>,
    pub refund_id: Option<String>,
    pub refund_amount: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EaseBuzzRefundSyncRequest {
    pub key: String,
    pub easebuzz_id: String,
    pub hash: String,
    pub merchant_refund_id: String,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundSyncResponse {
    pub code: i32,
    pub status: String,
    pub response: EaseBuzzRefundSyncData,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundSyncData {
    pub txnid: String,
    pub easebuzz_id: String,
    pub net_amount_debit: String,
    pub amount: String,
    pub refunds: Option<Vec<EaseBuzzRefundSyncType>>,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundSyncType {
    pub refund_id: String,
    pub refund_status: String,
    pub merchant_refund_id: String,
    pub merchant_refund_date: String,
    pub refund_settled_date: Option<String>,
    pub refund_amount: String,
    pub arn_number: Option<String>,
}

// Transformer implementations

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<&RouterDataV2<domain_types::connector_flow::Authorize, domain_types::PaymentFlowData, domain_types::PaymentsAuthorizeData<T>, domain_types::PaymentsResponseData>>
    for EaseBuzzPaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<
            domain_types::connector_flow::Authorize,
            domain_types::PaymentFlowData,
            domain_types::PaymentsAuthorizeData<T>,
            domain_types::PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let amount = item.amount.get_amount_as_string();
        let currency = item.router_data.request.currency.to_string();
        
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let customer_id_string = customer_id.get_string_repr();
        
        let transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        let email = item.router_data.request.email.as_ref().map(|e| e.to_string());
        let phone = item.router_data.request.phone.as_ref().map(|p| p.to_string());

        let return_url = item.router_data.request.get_router_return_url()?;

        // Extract payment method details
        let (payment_mode, upi_vpa, upi_intent_app) = match &item.router_data.request.payment_method_data {
            Some(domain_types::PaymentMethodData::Upi(upi_data)) => {
                let payment_mode = match upi_data.upi_payment_method {
                    domain_types::UpiPaymentMethod::Intent => Some("upi_intent".to_string()),
                    domain_types::UpiPaymentMethod::Collect => Some("upi_collect".to_string()),
                    domain_types::UpiPaymentMethod::Qr => Some("upi_qr".to_string()),
                    domain_types::UpiPaymentMethod::None => None,
                };
                (
                    payment_mode,
                    upi_data.vpa.as_ref().map(|vpa| vpa.to_string()),
                    upi_data.intent_app_name.as_ref().map(|app| app.to_string()),
                )
            }
            _ => (None, None, None),
        };

        // Generate hash (simplified - in real implementation, use proper hash generation)
        let hash_string = format!("{}|{}|{}|{}", transaction_id, amount, currency, customer_id_string);
        let hash = crypto::Sha512::hash_bytes(hash_string.as_bytes()).to_string();

        Ok(Self {
            txnid: transaction_id,
            amount,
            currency,
            email,
            phone,
            udf1: Some(customer_id_string),
            udf2: None,
            udf3: None,
            udf4: None,
            udf5: None,
            udf6: None,
            udf7: None,
            udf8: None,
            udf9: None,
            udf10: None,
            surl: Some(return_url.clone()),
            furl: Some(return_url),
            hash,
            payment_source: "upi".to_string(),
            payment_mode,
            upi_vpa,
            upi_intent_app,
        })
    }
}

impl<T> TryFrom<EaseBuzzPaymentsResponse> for domain_types::PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: EaseBuzzPaymentsResponse) -> Result<Self, Self::Error> {
        let status = match response.status {
            1 => AttemptStatus::Charged,
            0 => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        let error_message = response.error_desc.or_else(|| {
            response.data.error_desc.clone()
        });

        Ok(Self {
            status,
            amount_received: response.data.amount.as_ref().and_then(|amt| {
                amt.parse::<f64>().ok().map(|f| types::MinorUnit::from_major_unit_as_i64(f))
            }),
            currency: response.data.currency.as_ref().and_then(|c| c.parse().ok()),
            transaction_id: response.data.txnid.clone(),
            gateway_transaction_id: response.data.easebuzz_id.clone(),
            error_message,
            error_code: response.data.error_code.clone(),
            capture_method: Some(domain_types::CaptureMethod::Automatic),
            connector_transaction_id: response.data.txnid,
            refund_id: None,
            payment_method_type: response.data.payment_mode.as_ref().and_then(|pm| {
                EASEBUZZ_PAYMENT_METHOD_MAPPINGS.get(pm.as_str()).cloned()
            }),
            payment_method_details: None,
            redirection_response: None,
            mandate_reference: None,
            connector_metadata: Some(serde_json::to_value(response.data).change_context(errors::ConnectorError::RequestEncodingFailed)?),
            network_transaction_id: response.data.bank_ref_no.clone(),
            connector_response_reference_id: response.data.easebuzz_id.clone(),
            incremental_authorization_allowed: None,
            charges: None,
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<&RouterDataV2<domain_types::connector_flow::PSync, domain_types::PaymentFlowData, domain_types::PaymentsSyncData, domain_types::PaymentsResponseData>>
    for EaseBuzzPaymentsSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<
            domain_types::connector_flow::PSync,
            domain_types::PaymentFlowData,
            domain_types::PaymentsSyncData,
            domain_types::PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let amount = item.amount.get_amount_as_string();
        
        let transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        let email = item.router_data.request.email.as_ref().map(|e| e.to_string());
        let phone = item.router_data.request.phone.as_ref().map(|p| p.to_string());

        // Extract API key from auth type
        let key = match &item.router_data.connector_auth_type {
            domain_types::ConnectorAuthType::HeaderKey { api_key, .. } => api_key.peek().to_string(),
            domain_types::ConnectorAuthType::SignatureKey { api_key, .. } => api_key.peek().to_string(),
            _ => return Err(errors::ConnectorError::AuthenticationFailed.into()),
        };

        // Generate hash
        let hash_string = format!("{}|{}|{}", transaction_id, amount, key);
        let hash = crypto::Sha512::hash_bytes(hash_string.as_bytes()).to_string();

        Ok(Self {
            txnid: transaction_id,
            amount,
            email,
            phone,
            key,
            hash,
        })
    }
}

impl<T> TryFrom<EaseBuzzPaymentsSyncResponse> for domain_types::PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: EaseBuzzPaymentsSyncResponse) -> Result<Self, Self::Error> {
        match response.msg {
            EaseBuzzTxnSyncMessageType::Success(data) => {
                let status = data.status.as_ref()
                    .and_then(|s| EASEBUZZ_STATUS_MAPPINGS.get(s.as_str()))
                    .copied()
                    .unwrap_or(AttemptStatus::Pending);

                Ok(Self {
                    status,
                    amount_received: data.amount.as_ref().and_then(|amt| {
                        amt.parse::<f64>().ok().map(|f| types::MinorUnit::from_major_unit_as_i64(f))
                    }),
                    currency: data.currency.as_ref().and_then(|c| c.parse().ok()),
                    transaction_id: data.txnid.clone(),
                    gateway_transaction_id: data.easebuzz_id.clone(),
                    error_message: data.error_desc.clone(),
                    error_code: data.error_code.clone(),
                    capture_method: Some(domain_types::CaptureMethod::Automatic),
                    connector_transaction_id: data.txnid,
                    refund_id: None,
                    payment_method_type: data.payment_mode.as_ref().and_then(|pm| {
                        EASEBUZZ_PAYMENT_METHOD_MAPPINGS.get(pm.as_str()).cloned()
                    }),
                    payment_method_details: None,
                    redirection_response: None,
                    mandate_reference: None,
                    connector_metadata: Some(serde_json::to_value(data).change_context(errors::ConnectorError::RequestEncodingFailed)?),
                    network_transaction_id: data.bank_ref_no.clone(),
                    connector_response_reference_id: data.easebuzz_id.clone(),
                    incremental_authorization_allowed: None,
                    charges: None,
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

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<&RouterDataV2<domain_types::connector_flow::Refund, domain_types::PaymentFlowData, domain_types::RefundFlowData, domain_types::RefundsResponseData>>
    for EaseBuzzRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<
            domain_types::connector_flow::Refund,
            domain_types::PaymentFlowData,
            domain_types::RefundFlowData,
            domain_types::RefundsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let amount = item.amount.get_amount_as_string();
        
        let transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        let refund_note = item.router_data.request.reason.clone();

        // Extract API key from auth type
        let key = match &item.router_data.connector_auth_type {
            domain_types::ConnectorAuthType::HeaderKey { api_key, .. } => api_key.peek().to_string(),
            domain_types::ConnectorAuthType::SignatureKey { api_key, .. } => api_key.peek().to_string(),
            _ => return Err(errors::ConnectorError::AuthenticationFailed.into()),
        };

        // Generate hash
        let hash_string = format!("{}|{}|{}", transaction_id, amount, key);
        let hash = crypto::Sha512::hash_bytes(hash_string.as_bytes()).to_string();

        Ok(Self {
            txnid: transaction_id,
            refund_amount: amount,
            refund_note,
            key,
            hash,
        })
    }
}

impl<T> TryFrom<EaseBuzzRefundResponse> for domain_types::RefundsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: EaseBuzzRefundResponse) -> Result<Self, Self::Error> {
        let status = if response.status {
            RefundStatus::Success
        } else {
            RefundStatus::Failure
        };

        Ok(Self {
            refund_id: response.refund_id,
            connector_refund_id: response.refund_id.clone(),
            refund_amount_received: response.refund_amount.as_ref().and_then(|amt| {
                amt.parse::<f64>().ok().map(|f| types::MinorUnit::from_major_unit_as_i64(f))
            }),
            refund_status: status,
            refund_error_message: response.reason.clone(),
            connector_metadata: Some(serde_json::to_value(response).change_context(errors::ConnectorError::RequestEncodingFailed)?),
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<&RouterDataV2<domain_types::connector_flow::RSync, domain_types::PaymentFlowData, domain_types::RefundSyncData, domain_types::RefundsResponseData>>
    for EaseBuzzRefundSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<
            domain_types::connector_flow::RSync,
            domain_types::PaymentFlowData,
            domain_types::RefundSyncData,
            domain_types::RefundsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let refund_id = item.router_data.request.get_refund_id()?;
        
        let gateway_refund_id = item.router_data.request.connector_refund_id
            .get_connector_refund_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        // Extract API key from auth type
        let key = match &item.router_data.connector_auth_type {
            domain_types::ConnectorAuthType::HeaderKey { api_key, .. } => api_key.peek().to_string(),
            domain_types::ConnectorAuthType::SignatureKey { api_key, .. } => api_key.peek().to_string(),
            _ => return Err(errors::ConnectorError::AuthenticationFailed.into()),
        };

        // Generate hash
        let hash_string = format!("{}|{}|{}", gateway_refund_id, refund_id, key);
        let hash = crypto::Sha512::hash_bytes(hash_string.as_bytes()).to_string();

        Ok(Self {
            key,
            easebuzz_id: gateway_refund_id,
            hash,
            merchant_refund_id: refund_id,
        })
    }
}

impl<T> TryFrom<EaseBuzzRefundSyncResponse> for domain_types::RefundsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: EaseBuzzRefundSyncResponse) -> Result<Self, Self::Error> {
        let refund_data = response.response;
        
        // Find the specific refund if multiple exist
        let refund_info = refund_data.refunds.and_then(|refunds| {
            refunds.into_iter().find(|r| !r.refund_id.is_empty())
        });

        let status = refund_info
            .as_ref()
            .and_then(|r| EASEBUZZ_REFUND_STATUS_MAPPINGS.get(r.refund_status.as_str()))
            .copied()
            .unwrap_or(RefundStatus::Pending);

        Ok(Self {
            refund_id: refund_info.as_ref().map(|r| r.refund_id.clone()),
            connector_refund_id: Some(refund_data.easebuzz_id),
            refund_amount_received: refund_info.as_ref().and_then(|r| {
                r.refund_amount.parse::<f64>().ok().map(|f| types::MinorUnit::from_major_unit_as_i64(f))
            }),
            refund_status: status,
            refund_error_message: None,
            connector_metadata: Some(serde_json::to_value(response).change_context(errors::ConnectorError::RequestEncodingFailed)?),
        })
    }
}