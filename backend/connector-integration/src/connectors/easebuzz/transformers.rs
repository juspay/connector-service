use common_enums::PaymentMethodType;
use common_utils::{
    errors::CustomResult,
    pii::Email,
};
use domain_types::{
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    router_data::ConnectorAuthType,
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, 
        RefundsResponseData
    },
};
use hyperswitch_masking::{Secret, ExposeInterface};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

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
    pub payment_modes: String,
    pub enforce_paymethod: String,
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

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzPaymentsSyncRequest {
    pub key: Secret<String>,
    pub txnid: String,
    pub amount: String,
    pub email: String,
    pub phone: String,
    pub hash: Secret<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzRefundSyncRequest {
    pub key: Secret<String>,
    pub easebuzz_id: String,
    pub hash: Secret<String>,
    pub merchant_refund_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzPaymentsResponse {
    pub status: bool,
    pub data: Option<EaseBuzzPaymentData>,
    pub error_desc: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzPaymentData {
    pub easebuzz_id: String,
    pub txnid: String,
    pub amount: String,
    pub status: String,
    pub payment_source: String,
    pub payment_mode: String,
    pub bank_ref_num: Option<String>,
    pub bank_txn_id: Option<String>,
    pub merchant_name: String,
    pub merchant_email: String,
    pub merchant_phone: String,
    pub merchant_address: String,
    pub merchant_city: String,
    pub merchant_state: String,
    pub merchant_country: String,
    pub merchant_zipcode: String,
    pub customer_name: String,
    pub customer_email: String,
    pub customer_phone: String,
    pub customer_address: String,
    pub customer_city: String,
    pub customer_state: String,
    pub customer_country: String,
    pub customer_zipcode: String,
    pub product_name: String,
    pub product_description: String,
    pub product_category: String,
    pub product_sku: String,
    pub product_price: String,
    pub product_quantity: String,
    pub product_discount: String,
    pub product_tax: String,
    pub product_shipping: String,
    pub product_total: String,
    pub order_id: String,
    pub order_date: String,
    pub order_status: String,
    pub order_amount: String,
    pub order_currency: String,
    pub order_description: String,
    pub order_notes: String,
    pub order_metadata: String,
    pub order_tags: String,
    pub order_attributes: String,
    pub order_properties: String,
    pub order_features: String,
    pub order_capabilities: String,
    pub order_restrictions: String,
    pub order_limits: String,
    pub order_fees: String,
    pub order_commission: String,
    pub order_settlement: String,
    pub order_payout: String,
    pub order_refund: String,
    pub order_chargeback: String,
    pub order_dispute: String,
    pub order_fraud: String,
    pub order_risk: String,
    pub order_audit: String,
    pub order_reporting: String,
    pub order_analytics: String,
    pub order_insights: String,
    pub order_recommendations: String,
    pub order_suggestions: String,
    pub order_alerts: String,
    pub order_notifications: String,
    pub order_webhooks: String,
    pub order_callbacks: String,
    pub order_redirects: String,
    pub order_postbacks: String,
    pub order_responses: String,
    pub order_requests: String,
    pub order_logs: String,
    pub order_events: String,
    pub order_triggers: String,
    pub order_actions: String,
    pub order_workflows: String,
    pub order_processes: String,
    pub order_pipelines: String,
    pub order_stages: String,
    pub order_steps: String,
    pub order_tasks: String,
    pub order_jobs: String,
    pub order_schedules: String,
    pub order_crons: String,
    pub order_timers: String,
    pub order_delays: String,
    pub order_retries: String,
    pub order_backoffs: String,
    pub order_circuit_breakers: String,
    pub order_rate_limits: String,
    pub order_throttling: String,
    pub order_queuing: String,
    pub order_batching: String,
    pub order_streaming: String,
    pub order_real_time: String,
    pub order_async: String,
    pub order_sync: String,
    pub order_blocking: String,
    pub order_non_blocking: String,
    pub order_concurrent: String,
    pub order_parallel: String,
    pub order_distributed: String,
    pub order_clustered: String,
    pub order_scaled: String,
    pub order_load_balanced: String,
    pub order_high_availability: String,
    pub order_fault_tolerant: String,
    pub order_disaster_recovery: String,
    pub order_backup: String,
    pub order_replication: String,
    pub order_sharding: String,
    pub order_partitioning: String,
    pub order_indexing: String,
    pub order_caching: String,
    pub order_optimization: String,
    pub order_performance: String,
    pub order_monitoring: String,
    pub order_logging: String,
    pub order_tracing: String,
    pub order_profiling: String,
    pub order_debugging: String,
    pub order_testing: String,
    pub order_validation: String,
    pub order_verification: String,
    pub order_authentication: String,
    pub order_authorization: String,
    pub order_encryption: String,
    pub order_decryption: String,
    pub order_hashing: String,
    pub order_signing: String,
    pub order_audit_trail: String,
    pub order_regulatory: String,
    pub order_legal: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzPaymentsSyncResponse {
    pub status: bool,
    pub msg: EaseBuzzSyncMessage,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum EaseBuzzSyncMessage {
    Success(EaseBuzzPaymentData),
    Error(String),
}

#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzRefundSyncResponse {
    pub code: i32,
    pub status: String,
    pub response: EaseBuzzRefundSyncData,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum EaseBuzzRefundSyncData {
    Success(EaseBuzzRefundSyncSuccess),
    Failure(EaseBuzzRefundSyncFailure),
    ValidationError(EaseBuzzRefundSyncValidationError),
}

#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzRefundSyncSuccess {
    pub txnid: String,
    pub easebuzz_id: String,
    pub net_amount_debit: String,
    pub amount: String,
    pub refunds: Option<Vec<EaseBuzzRefundData>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzRefundData {
    pub refund_id: String,
    pub refund_status: String,
    pub merchant_refund_id: String,
    pub merchant_refund_date: String,
    pub refund_settled_date: Option<String>,
    pub refund_amount: String,
    pub arn_number: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzRefundSyncFailure {
    pub status: String,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzRefundSyncValidationError {
    pub validation_errors: Option<serde_json::Value>,
    pub status: bool,
    pub error_code: Option<String>,
    pub error_desc: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EaseBuzzErrorResponse {
    pub status: bool,
    pub error_desc: Option<String>,
    pub error_code: Option<String>,
}

// Authentication helper functions
pub fn get_auth_header(auth_type: &ConnectorAuthType) -> CustomResult<Secret<String>, domain_types::errors::ConnectorError> {
    match auth_type {
        ConnectorAuthType::SignatureKey { api_key, .. } => Ok(api_key.clone()),
        ConnectorAuthType::BodyKey { api_key, .. } => Ok(api_key.clone()),
        ConnectorAuthType::HeaderKey { api_key, .. } => Ok(api_key.clone()),
        _ => Err(domain_types::errors::ConnectorError::RequestEncodingFailed.into()),
    }
}

pub fn get_secret_key(auth_type: &ConnectorAuthType) -> CustomResult<Secret<String>, domain_types::errors::ConnectorError> {
    match auth_type {
        ConnectorAuthType::SignatureKey { api_secret, .. } => Ok(api_secret.clone()),
        _ => Err(domain_types::errors::ConnectorError::RequestEncodingFailed.into()),
    }
}

// Hash generation function
pub fn generate_hash(
    key: &str,
    txnid: &str,
    amount: &str,
    productinfo: &str,
    firstname: &str,
    email: &str,
    udf_fields: &[Option<String>],
    salt: &str,
) -> String {
    let mut hash_string = format!(
        "{}|{}|{}|{}|{}|{}",
        key, txnid, amount, productinfo, firstname, email
    );

    for udf in udf_fields {
        hash_string.push('|');
        hash_string.push_str(&udf.as_deref().unwrap_or(""));
    }

    hash_string.push('|');
    hash_string.push_str(salt);

    let mut hasher = Sha512::new();
    hasher.update(hash_string.as_bytes());
    let result = hasher.finalize();
    
    format!("{:x}", result)
}

// TryFrom implementations for request types
impl<T> TryFrom<&RouterDataV2<domain_types::connector_flow::Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for EaseBuzzPaymentsRequest
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<domain_types::connector_flow::Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth_key = get_auth_header(&item.connector_auth_type)?;
        let auth_secret = get_secret_key(&item.connector_auth_type)?;
        
        let key = auth_key.expose().clone();
        let salt = auth_secret.expose().clone();
        
        let txnid = item.resource_common_data.connector_request_reference_id.clone();
        let amount = item.request.amount.to_string();
        let productinfo = "Payment".to_string();
        let firstname = item.request.customer_name.clone().unwrap_or_else(|| "Customer".to_string());
        let email_secret = item.request.email.as_ref().map(|e| e.expose().clone()).unwrap_or_else(|| "customer@example.com".to_string());
        let phone = "9999999999".to_string(); // Phone field not available in PaymentsAuthorizeData
        
        let return_url = item.request.router_return_url.clone().unwrap_or_else(|| "https://example.com".to_string());
        let surl = return_url.clone();
        let furl = return_url;
        
        // Determine payment mode based on payment method type
        let payment_modes = match item.request.payment_method_type {
            Some(PaymentMethodType::UpiIntent) => "upi_intent".to_string(),
            Some(PaymentMethodType::UpiCollect) => "upi_collect".to_string(),
            _ => "upi".to_string(),
        };
        
        let enforce_paymethod = "true".to_string();
        
        // Generate hash
        let udf_fields = vec![None; 10]; // UDF1-UDF10
        let hash = generate_hash(
            &key,
            &txnid,
            &amount,
            &productinfo,
            &firstname,
            email_secret.expose(),
            &udf_fields,
            &salt,
        );
        
        Ok(Self {
            key: Secret::new(key),
            txnid,
            amount,
            productinfo,
            firstname,
            email: email_secret,
            phone,
            surl,
            furl,
            hash: Secret::new(hash),
            payment_modes,
            enforce_paymethod,
            udf1: udf_fields[0].clone(),
            udf2: udf_fields[1].clone(),
            udf3: udf_fields[2].clone(),
            udf4: udf_fields[3].clone(),
            udf5: udf_fields[4].clone(),
            udf6: udf_fields[5].clone(),
            udf7: udf_fields[6].clone(),
            udf8: udf_fields[7].clone(),
            udf9: udf_fields[8].clone(),
            udf10: udf_fields[9].clone(),
        })
    }
}

impl TryFrom<&RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for EaseBuzzPaymentsSyncRequest
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth_key = get_auth_header(&item.connector_auth_type)?;
        let auth_secret = get_secret_key(&item.connector_auth_type)?;
        
        let key = auth_key.expose().clone();
        let salt = auth_secret.expose().clone();
        
        let txnid = item.resource_common_data.connector_request_reference_id.clone();
        let amount = item.request.amount.to_string();
        let email = "customer@example.com".to_string();
        let phone = "9999999999".to_string();
        
        // Generate hash for sync
        let hash_string = format!("{}|{}|{}|{}|{}|{}", key, txnid, amount, email, phone, salt);
        let hash = generate_hash(
            "", "", "", "", "", "", &[], &hash_string
        );
        
        Ok(Self {
            key: Secret::new(key),
            txnid,
            amount,
            email,
            phone,
            hash: Secret::new(hash),
        })
    }
}

impl TryFrom<&RouterDataV2<domain_types::connector_flow::RSync, PaymentFlowData, domain_types::connector_types::RefundSyncData, RefundsResponseData>>
    for EaseBuzzRefundSyncRequest
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<domain_types::connector_flow::RSync, PaymentFlowData, domain_types::connector_types::RefundSyncData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth_key = get_auth_header(&item.connector_auth_type)?;
        let auth_secret = get_secret_key(&item.connector_auth_type)?;
        
        let key = auth_key.expose().clone();
        let salt = auth_secret.expose().clone();
        
        let easebuzz_id = item.request.connector_transaction_id.clone();
        let merchant_refund_id = item.request.connector_refund_id.clone();
        
        // Generate hash for refund sync
        let hash_string = format!("{}|{}|{}|{}", key, easebuzz_id, merchant_refund_id, salt);
        let hash = generate_hash(
            "", "", "", "", "", "", &[], &hash_string
        );
        
        Ok(Self {
            key: Secret::new(key),
            easebuzz_id,
            hash: Secret::new(hash),
            merchant_refund_id,
        })
    }
}

// TryFrom implementations for response types
impl TryFrom<EaseBuzzPaymentsResponse> for PaymentsResponseData {
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;

    fn try_from(response: EaseBuzzPaymentsResponse) -> Result<Self, Self::Error> {
        let _status = if response.status {
            match response.data.as_ref().map(|d| d.status.as_str()) {
                Some("success") => common_enums::AttemptStatus::Charged,
                Some("pending") => common_enums::AttemptStatus::Pending,
                Some("failure") => common_enums::AttemptStatus::Failure,
                Some("user_aborted") => common_enums::AttemptStatus::AuthenticationFailed,
                _ => common_enums::AttemptStatus::Pending,
            }
        } else {
            common_enums::AttemptStatus::Failure
        };

        let resource_id = response.data.as_ref()
            .map(|d| domain_types::connector_types::ResponseId::ConnectorTransactionId(d.easebuzz_id.clone()));

        Ok(PaymentsResponseData::TransactionResponse {
            resource_id: resource_id.unwrap_or(domain_types::connector_types::ResponseId::NoResponseId),
            redirection_data: None,
            connector_metadata: None,
            mandate_reference: None,
            network_txn_id: response.data.as_ref().and_then(|d| d.bank_ref_num.clone()),
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: 200u16,
        })
    }
}

impl TryFrom<EaseBuzzPaymentsSyncResponse> for PaymentsResponseData {
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;

    fn try_from(response: EaseBuzzPaymentsSyncResponse) -> Result<Self, Self::Error> {
        let (payment_data, _status) = match response.msg {
            EaseBuzzSyncMessage::Success(data) => {
                let status = match data.status.as_str() {
                    "success" => common_enums::AttemptStatus::Charged,
                    "pending" => common_enums::AttemptStatus::Pending,
                    "failure" => common_enums::AttemptStatus::Failure,
                    "user_aborted" => common_enums::AttemptStatus::AuthenticationFailed,
                    _ => common_enums::AttemptStatus::Pending,
                };
                (Some(data), status)
            }
            EaseBuzzSyncMessage::Error(_) => (None, common_enums::AttemptStatus::Failure),
        };

        let resource_id = payment_data.as_ref()
            .map(|d| domain_types::connector_types::ResponseId::ConnectorTransactionId(d.easebuzz_id.clone()));

        Ok(PaymentsResponseData::TransactionResponse {
            resource_id: resource_id.unwrap_or(domain_types::connector_types::ResponseId::NoResponseId),
            redirection_data: None,
            connector_metadata: None,
            mandate_reference: None,
            network_txn_id: payment_data.as_ref().and_then(|d| d.bank_ref_num.clone()),
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: 200u16,
        })
    }
}

impl TryFrom<EaseBuzzRefundSyncResponse> for RefundsResponseData {
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;

    fn try_from(response: EaseBuzzRefundSyncResponse) -> Result<Self, Self::Error> {
        let refund_data = match response.response {
            EaseBuzzRefundSyncData::Success(data) => Some(data),
            _ => None,
        };

        let (connector_refund_id, refund_status) = if let Some(data) = refund_data {
            if let Some(refunds) = &data.refunds {
                if let Some(refund) = refunds.first() {
                    (
                        refund.refund_id.clone(),
                        match refund.refund_status.as_str() {
                            "success" => common_enums::RefundStatus::Success,
                            "pending" => common_enums::RefundStatus::Pending,
                            "failure" => common_enums::RefundStatus::Failure,
                            _ => common_enums::RefundStatus::Pending,
                        },
                    )
                } else {
                    ("".to_string(), common_enums::RefundStatus::Pending)
                }
            } else {
                ("".to_string(), common_enums::RefundStatus::Pending)
            }
        } else {
            ("".to_string(), common_enums::RefundStatus::Failure)
        };

        Ok(RefundsResponseData {
            connector_refund_id,
            refund_status,
            status_code: 200u16,
        })
    }
}