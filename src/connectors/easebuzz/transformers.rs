use std::collections::HashMap;

use common_enums::{AttemptStatus, Currency, PaymentMethodType};
use common_utils::{
    crypto,
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    types::{self, StringMinorUnit},
};
use domain_types::{
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    types as domain_types,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use masking::{ExposeInterface, Mask, SecretTrait};
use serde::{Deserialize, Serialize};

// Request/Response types for EaseBuzz API

#[derive(Debug, Serialize)]
pub struct EaseBuzzPaymentsRequest {
    pub key: Secret<String>,
    pub txnid: String,
    pub amount: String,
    pub productinfo: String,
    pub firstname: String,
    pub email: Option<String>,
    pub phone: Option<String>,
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
    #[serde(rename = "payment_source")]
    pub payment_source: String,
    pub vpa: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzPaymentsResponse {
    pub status: i32,
    pub error_desc: Option<String>,
    #[serde(rename = "data")]
    pub data: String,
}

#[derive(Debug, Serialize)]
pub struct EaseBuzzPaymentsSyncRequest {
    pub key: Secret<String>,
    pub txnid: String,
    pub amount: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub hash: Secret<String>,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzPaymentsSyncResponse {
    pub status: bool,
    pub msg: String,
}

#[derive(Debug, Serialize)]
pub struct EaseBuzzRefundRequest {
    pub key: Secret<String>,
    pub txnid: String,
    pub refund_amount: String,
    pub refund_reason: Option<String>,
    pub hash: Secret<String>,
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
    pub key: Secret<String>,
    pub easebuzz_id: String,
    pub hash: Secret<String>,
    pub merchant_refund_id: String,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundSyncResponse {
    pub status: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzErrorResponse {
    pub status: i32,
    pub error_code: Option<String>,
    pub error_desc: Option<String>,
}

// Transformer implementations

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<&RouterDataV2<domain_types::connector_flow::Authorize, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsAuthorizeData<T>, domain_types::connector_types::PaymentsResponseData>>
    for EaseBuzzPaymentsRequest
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<
            domain_types::connector_flow::Authorize,
            domain_types::connector_types::PaymentFlowData,
            domain_types::connector_types::PaymentsAuthorizeData<T>,
            domain_types::connector_types::PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        // Extract authentication credentials
        let auth = get_auth_credentials(&item.connector_auth_type)?;
        
        // Extract customer information
        let customer_id = item.resource_common_data.get_customer_id()?;
        let customer_id_string = customer_id.get_string_repr().to_string();
        
        // Extract transaction details
        let transaction_id = item.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| domain_types::errors::ConnectorError::RequestEncodingFailed)?;
        
        // Extract amount using proper converter
        let amount = item.amount.get_amount_as_string();
        
        // Extract URLs
        let return_url = item.request.get_router_return_url()
            .map_err(|_e| domain_types::errors::ConnectorError::RequestEncodingFailed)?;
        
        // Extract email and phone
        let email = item.request.email.as_ref().map(|e| e.get_string_repr().to_string());
        let phone = item.request.phone.as_ref().map(|p| p.get_string_repr().to_string());
        
        // Generate hash
        let hash = generate_payment_hash(
            &auth.key.expose(),
            &transaction_id,
            &amount,
            "product_info",
            &customer_id_string,
            email.as_deref().unwrap_or(""),
            phone.as_deref().unwrap_or(""),
            &return_url,
            &return_url,
            &auth.salt.expose(),
        )?;

        Ok(Self {
            key: auth.key,
            txnid: transaction_id,
            amount,
            productinfo: "product_info".to_string(),
            firstname: customer_id_string,
            email,
            phone,
            surl: return_url.clone(),
            furl: return_url,
            hash: Secret::new(hash),
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
            payment_source: "upi".to_string(),
            vpa: extract_upi_vpa(&item.request.payment_method_data),
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<&RouterDataV2<domain_types::connector_flow::PSync, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsSyncData, domain_types::connector_types::PaymentsResponseData>>
    for EaseBuzzPaymentsSyncRequest
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<
            domain_types::connector_flow::PSync,
            domain_types::connector_types::PaymentFlowData,
            domain_types::connector_types::PaymentsSyncData,
            domain_types::connector_types::PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = get_auth_credentials(&item.connector_auth_type)?;
        let transaction_id = item.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| domain_types::errors::ConnectorError::RequestEncodingFailed)?;
        let amount = item.amount.get_amount_as_string();
        
        let email = item.request.email.as_ref().map(|e| e.get_string_repr().to_string());
        let phone = item.request.phone.as_ref().map(|p| p.get_string_repr().to_string());
        
        let hash = generate_sync_hash(
            &auth.key.expose(),
            &transaction_id,
            &amount,
            email.as_deref().unwrap_or(""),
            phone.as_deref().unwrap_or(""),
            &auth.salt.expose(),
        )?;

        Ok(Self {
            key: auth.key,
            txnid: transaction_id,
            amount,
            email,
            phone,
            hash: Secret::new(hash),
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<&RouterDataV2<domain_types::connector_flow::Refund, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundsResponseData>>
    for EaseBuzzRefundRequest
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<
            domain_types::connector_flow::Refund,
            domain_types::connector_types::PaymentFlowData,
            domain_types::connector_types::RefundFlowData,
            domain_types::connector_types::RefundsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = get_auth_credentials(&item.connector_auth_type)?;
        let transaction_id = item.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| domain_types::errors::ConnectorError::RequestEncodingFailed)?;
        let refund_amount = item.amount.get_amount_as_string();
        
        let hash = generate_refund_hash(
            &auth.key.expose(),
            &transaction_id,
            &refund_amount,
            item.request.reason.as_deref().unwrap_or(""),
            &auth.salt.expose(),
        )?;

        Ok(Self {
            key: auth.key,
            txnid: transaction_id,
            refund_amount,
            refund_reason: item.request.reason.clone(),
            hash: Secret::new(hash),
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<&RouterDataV2<domain_types::connector_flow::RSync, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::RefundSyncData, domain_types::connector_types::RefundsResponseData>>
    for EaseBuzzRefundSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<
            domain_types::connector_flow::RSync,
            domain_types::connector_types::PaymentFlowData,
            domain_types::connector_types::RefundSyncData,
            domain_types::connector_types::RefundsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = get_auth_credentials(&item.connector_auth_type)?;
        let refund_id = item.request.connector_refund_id
            .get_connector_refund_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;
        let merchant_refund_id = item.request.refund_id.clone();
        
        let hash = generate_refund_sync_hash(
            &auth.key.expose(),
            &refund_id,
            &merchant_refund_id,
            &auth.salt.expose(),
        )?;

        Ok(Self {
            key: auth.key,
            easebuzz_id: refund_id,
            hash: Secret::new(hash),
            merchant_refund_id,
        })
    }
}

// Response transformers

impl TryFrom<EaseBuzzPaymentsResponse> for domain_types::connector_types::PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: EaseBuzzPaymentsResponse) -> Result<Self, Self::Error> {
        let status = match response.status {
            1 => AttemptStatus::Charged,
            0 => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        Ok(Self {
            status,
            error: response.error_desc,
            ..Default::default()
        })
    }
}

impl TryFrom<EaseBuzzPaymentsSyncResponse> for domain_types::connector_types::PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: EaseBuzzPaymentsSyncResponse) -> Result<Self, Self::Error> {
        let status = if response.status {
            AttemptStatus::Charged
        } else {
            AttemptStatus::Failure
        };

        Ok(Self {
            status,
            error: Some(response.msg),
            ..Default::default()
        })
    }
}

impl TryFrom<EaseBuzzRefundResponse> for domain_types::connector_types::RefundsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: EaseBuzzRefundResponse) -> Result<Self, Self::Error> {
        let status = if response.status {
            AttemptStatus::Charged
        } else {
            AttemptStatus::Failure
        };

        Ok(Self {
            status,
            error: response.reason,
            refund_id: response.refund_id,
            ..Default::default()
        })
    }
}

impl TryFrom<EaseBuzzRefundSyncResponse> for domain_types::connector_types::RefundsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: EaseBuzzRefundSyncResponse) -> Result<Self, Self::Error> {
        let status = match response.status.as_str() {
            "success" => AttemptStatus::Charged,
            "pending" => AttemptStatus::Pending,
            _ => AttemptStatus::Failure,
        };

        Ok(Self {
            status,
            error: Some(response.message),
            ..Default::default()
        })
    }
}

// Helper functions

#[derive(Debug, Clone)]
pub struct EaseBuzzAuth {
    pub key: Secret<String>,
    pub salt: Secret<String>,
}

fn get_auth_credentials(auth_type: &domain_types::ConnectorAuthType) -> CustomResult<EaseBuzzAuth, errors::ConnectorError> {
    match auth_type {
        domain_types::ConnectorAuthType::SignatureKey {
            api_key,
            key,
            ..
        } => {
            let key = key
                .clone()
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "key",
                })?;
            
            let salt = api_key
                .clone()
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "salt",
                })?;

            Ok(EaseBuzzAuth {
                key: Secret::new(key),
                salt: Secret::new(salt),
            })
        }
        _ => Err(errors::ConnectorError::AuthenticationFailed.into()),
    }
}

fn extract_upi_vpa<T: PaymentMethodDataTypes>(payment_method_data: &T) -> Option<String> {
    // This would need to be implemented based on the specific payment method data structure
    // For now, return None as placeholder
    None
}

fn generate_payment_hash(
    key: &str,
    txnid: &str,
    amount: &str,
    productinfo: &str,
    firstname: &str,
    email: &str,
    phone: &str,
    surl: &str,
    furl: &str,
    salt: &str,
) -> CustomResult<String, errors::ConnectorError> {
    let hash_string = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        key, txnid, amount, productinfo, firstname, email, phone, surl, furl, salt
    );
    
    crypto::compute_sha512_hash(&hash_string)
        .change_context(errors::ConnectorError::RequestEncodingFailed)
}

fn generate_sync_hash(
    key: &str,
    txnid: &str,
    amount: &str,
    email: &str,
    phone: &str,
    salt: &str,
) -> CustomResult<String, errors::ConnectorError> {
    let hash_string = format!(
        "{}|{}|{}|{}|{}|{}",
        key, txnid, amount, email, phone, salt
    );
    
    crypto::compute_sha512_hash(&hash_string)
        .change_context(errors::ConnectorError::RequestEncodingFailed)
}

fn generate_refund_hash(
    key: &str,
    txnid: &str,
    refund_amount: &str,
    refund_reason: &str,
    salt: &str,
) -> CustomResult<String, errors::ConnectorError> {
    let hash_string = format!(
        "{}|{}|{}|{}|{}",
        key, txnid, refund_amount, refund_reason, salt
    );
    
    crypto::compute_sha512_hash(&hash_string)
        .change_context(errors::ConnectorError::RequestEncodingFailed)
}

fn generate_refund_sync_hash(
    key: &str,
    easebuzz_id: &str,
    merchant_refund_id: &str,
    salt: &str,
) -> CustomResult<String, errors::ConnectorError> {
    let hash_string = format!(
        "{}|{}|{}|{}",
        key, easebuzz_id, merchant_refund_id, salt
    );
    
    crypto::compute_sha512_hash(&hash_string)
        .change_context(errors::ConnectorError::RequestEncodingFailed)
}