use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    crypto,
    errors::CustomResult,
    pii::SecretSerdeValue,
    types::{MinorUnit, StringMinorUnit},
};
use domain_types::{
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    router_data::ConnectorAuthType,
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, 
        RefundSyncData, RefundsResponseData
    },
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use crate::{
    core::errors::{self, ConnectorError},
    services::connector::ConnectorCommon,
};

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
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub zipcode: Option<String>,
    pub pg: Option<String>,
    pub customer_unique_id: Option<String>,
    pub split_payments: Option<String>,
    pub sub_merchant_id: Option<String>,
    pub sub_merchant_name: Option<String>,
    pub sub_merchant_email: Option<String>,
    pub sub_merchant_mobile: Option<String>,
    pub sub_merchant_address: Option<String>,
    pub sub_merchant_city: Option<String>,
    pub sub_merchant_state: Option<String>,
    pub sub_merchant_country: Option<String>,
    pub sub_merchant_zipcode: Option<String>,
    pub sub_merchant_tin: Option<String>,
    pub sub_merchant_pan: Option<String>,
    pub sub_merchant_gst: Option<String>,
    pub sub_merchant_sac: Option<String>,
    pub sub_merchant_service_tax: Option<String>,
    pub sub_merchant_cess: Option<String>,
    pub sub_merchant_discount: Option<String>,
    pub sub_merchant_other_charges: Option<String>,
    pub sub_merchant_shipping_charges: Option<String>,
    pub sub_merchant_total_amount: Option<String>,
    pub sub_merchant_additional_info: Option<String>,
    pub sub_merchant_custom_fields: Option<String>,
    pub sub_merchant_merchant_order_id: Option<String>,
    pub sub_merchant_merchant_transaction_id: Option<String>,
    pub sub_merchant_merchant_reference_id: Option<String>,
    pub sub_merchant_merchant_description: Option<String>,
    pub sub_merchant_merchant_notes: Option<String>,
    pub sub_merchant_merchant_metadata: Option<String>,
    pub sub_merchant_merchant_tags: Option<String>,
    pub sub_merchant_merchant_attributes: Option<String>,
    pub sub_merchant_merchant_properties: Option<String>,
    pub sub_merchant_merchant_features: Option<String>,
    pub sub_merchant_merchant_capabilities: Option<String>,
    pub sub_merchant_merchant_restrictions: Option<String>,
    pub sub_merchant_merchant_limits: Option<String>,
    pub sub_merchant_merchant_fees: Option<String>,
    pub sub_merchant_merchant_commission: Option<String>,
    pub sub_merchant_merchant_settlement: Option<String>,
    pub sub_merchant_merchant_payout: Option<String>,
    pub sub_merchant_merchant_refund: Option<String>,
    pub sub_merchant_merchant_chargeback: Option<String>,
    pub sub_merchant_merchant_dispute: Option<String>,
    pub sub_merchant_merchant_fraud: Option<String>,
    pub sub_merchant_merchant_risk: Option<String>,
    pub sub_merchant_merchant_compliance: Option<String>,
    pub sub_merchant_merchant_audit: Option<String>,
    pub sub_merchant_merchant_reporting: Option<String>,
    pub sub_merchant_merchant_analytics: Option<String>,
    pub sub_merchant_merchant_insights: Option<String>,
    pub sub_merchant_merchant_recommendations: Option<String>,
    pub sub_merchant_merchant_suggestions: Option<String>,
    pub sub_merchant_merchant_alerts: Option<String>,
    pub sub_merchant_merchant_notifications: Option<String>,
    pub sub_merchant_merchant_webhooks: Option<String>,
    pub sub_merchant_merchant_callbacks: Option<String>,
    pub sub_merchant_merchant_redirects: Option<String>,
    pub sub_merchant_merchant_postbacks: Option<String>,
    pub sub_merchant_merchant_responses: Option<String>,
    pub sub_merchant_merchant_requests: Option<String>,
    pub sub_merchant_merchant_logs: Option<String>,
    pub sub_merchant_merchant_events: Option<String>,
    pub sub_merchant_merchant_triggers: Option<String>,
    pub sub_merchant_merchant_actions: Option<String>,
    pub sub_merchant_merchant_workflows: Option<String>,
    pub sub_merchant_merchant_processes: Option<String>,
    pub sub_merchant_merchant_pipelines: Option<String>,
    pub sub_merchant_merchant_stages: Option<String>,
    pub sub_merchant_merchant_steps: Option<String>,
    pub sub_merchant_merchant_tasks: Option<String>,
    pub sub_merchant_merchant_jobs: Option<String>,
    pub sub_merchant_merchant_schedules: Option<String>,
    pub sub_merchant_merchant_crons: Option<String>,
    pub sub_merchant_merchant_timers: Option<String>,
    pub sub_merchant_merchant_delays: Option<String>,
    pub sub_merchant_merchant_retries: Option<String>,
    pub sub_merchant_merchant_backoffs: Option<String>,
    pub sub_merchant_merchant_circuit_breakers: Option<String>,
    pub sub_merchant_merchant_rate_limits: Option<String>,
    pub sub_merchant_merchant_throttling: Option<String>,
    pub sub_merchant_merchant_queuing: Option<String>,
    pub sub_merchant_merchant_batching: Option<String>,
    pub sub_merchant_merchant_streaming: Option<String>,
    pub sub_merchant_merchant_real_time: Option<String>,
    pub sub_merchant_merchant_async: Option<String>,
    pub sub_merchant_merchant_sync: Option<String>,
    pub sub_merchant_merchant_blocking: Option<String>,
    pub sub_merchant_merchant_non_blocking: Option<String>,
    pub sub_merchant_merchant_concurrent: Option<String>,
    pub sub_merchant_merchant_parallel: Option<String>,
    pub sub_merchant_merchant_distributed: Option<String>,
    pub sub_merchant_merchant_clustered: Option<String>,
    pub sub_merchant_merchant_scaled: Option<String>,
    pub sub_merchant_merchant_load_balanced: Option<String>,
    pub sub_merchant_merchant_high_availability: Option<String>,
    pub sub_merchant_merchant_fault_tolerant: Option<String>,
    pub sub_merchant_merchant_disaster_recovery: Option<String>,
    pub sub_merchant_merchant_backup: Option<String>,
    pub sub_merchant_merchant_replication: Option<String>,
    pub sub_merchant_merchant_sharding: Option<String>,
    pub sub_merchant_merchant_partitioning: Option<String>,
    pub sub_merchant_merchant_indexing: Option<String>,
    pub sub_merchant_merchant_caching: Option<String>,
    pub sub_merchant_merchant_optimization: Option<String>,
    pub sub_merchant_merchant_performance: Option<String>,
    pub sub_merchant_merchant_monitoring: Option<String>,
    pub sub_merchant_merchant_logging: Option<String>,
    pub sub_merchant_merchant_tracing: Option<String>,
    pub sub_merchant_merchant_profiling: Option<String>,
    pub sub_merchant_merchant_debugging: Option<String>,
    pub sub_merchant_merchant_testing: Option<String>,
    pub sub_merchant_merchant_validation: Option<String>,
    pub sub_merchant_merchant_verification: Option<String>,
    pub sub_merchant_merchant_authentication: Option<String>,
    pub sub_merchant_merchant_authorization: Option<String>,
    pub sub_merchant_merchant_encryption: Option<String>,
    pub sub_merchant_merchant_decryption: Option<String>,
    pub sub_merchant_merchant_hashing: Option<String>,
    pub sub_merchant_merchant_signing: Option<String>,
    pub sub_merchant_merchant_audit_trail: Option<String>,
    pub sub_merchant_master_merchant_id: Option<String>,
    pub sub_merchant_master_merchant_name: Option<String>,
    pub sub_merchant_master_merchant_email: Option<String>,
    pub sub_merchant_master_merchant_mobile: Option<String>,
    pub sub_merchant_master_merchant_address: Option<String>,
    pub sub_merchant_master_merchant_city: Option<String>,
    pub sub_merchant_master_merchant_state: Option<String>,
    pub sub_merchant_master_merchant_country: Option<String>,
    pub sub_merchant_master_merchant_zipcode: Option<String>,
    pub sub_merchant_master_merchant_tin: Option<String>,
    pub sub_merchant_master_merchant_pan: Option<String>,
    pub sub_merchant_master_merchant_gst: Option<String>,
    pub sub_merchant_master_merchant_sac: Option<String>,
    pub sub_merchant_master_merchant_service_tax: Option<String>,
    pub sub_merchant_master_merchant_cess: Option<String>,
    pub sub_merchant_master_merchant_discount: Option<String>,
    pub sub_merchant_master_merchant_other_charges: Option<String>,
    pub sub_merchant_master_merchant_shipping_charges: Option<String>,
    pub sub_merchant_master_merchant_total_amount: Option<String>,
    pub sub_merchant_master_merchant_additional_info: Option<String>,
    pub sub_merchant_master_merchant_custom_fields: Option<String>,
    pub sub_merchant_master_merchant_order_id: Option<String>,
    pub sub_merchant_master_merchant_transaction_id: Option<String>,
    pub sub_merchant_master_merchant_reference_id: Option<String>,
    pub sub_merchant_master_merchant_description: Option<String>,
    pub sub_merchant_master_merchant_notes: Option<String>,
    pub sub_merchant_master_merchant_metadata: Option<String>,
    pub sub_merchant_master_merchant_tags: Option<String>,
    pub sub_merchant_master_merchant_attributes: Option<String>,
    pub sub_merchant_master_merchant_properties: Option<String>,
    pub sub_merchant_master_merchant_features: Option<String>,
    pub sub_merchant_master_merchant_capabilities: Option<String>,
    pub sub_merchant_master_merchant_restrictions: Option<String>,
    pub sub_merchant_master_merchant_limits: Option<String>,
    pub sub_merchant_master_merchant_fees: Option<String>,
    pub sub_merchant_master_merchant_commission: Option<String>,
    pub sub_merchant_master_merchant_settlement: Option<String>,
    pub sub_merchant_master_merchant_payout: Option<String>,
    pub sub_merchant_master_merchant_refund: Option<String>,
    pub sub_merchant_master_merchant_chargeback: Option<String>,
    pub sub_merchant_master_merchant_dispute: Option<String>,
    pub sub_merchant_master_merchant_fraud: Option<String>,
    pub sub_merchant_master_merchant_risk: Option<String>,
    pub sub_merchant_master_merchant_compliance: Option<String>,
    pub sub_merchant_master_merchant_audit: Option<String>,
    pub sub_merchant_master_merchant_reporting: Option<String>,
    pub sub_merchant_master_merchant_analytics: Option<String>,
    pub sub_merchant_master_merchant_insights: Option<String>,
    pub sub_merchant_master_merchant_recommendations: Option<String>,
    pub sub_merchant_master_merchant_suggestions: Option<String>,
    pub sub_merchant_master_merchant_alerts: Option<String>,
    pub sub_merchant_master_merchant_notifications: Option<String>,
    pub sub_merchant_master_merchant_webhooks: Option<String>,
    pub sub_merchant_master_merchant_callbacks: Option<String>,
    pub sub_merchant_master_merchant_redirects: Option<String>,
    pub sub_merchant_master_merchant_postbacks: Option<String>,
    pub sub_merchant_master_merchant_responses: Option<String>,
    pub sub_merchant_master_merchant_requests: Option<String>,
    pub sub_merchant_master_merchant_logs: Option<String>,
    pub sub_merchant_master_merchant_events: Option<String>,
    pub sub_merchant_master_merchant_triggers: Option<String>,
    pub sub_merchant_master_merchant_actions: Option<String>,
    pub sub_merchant_master_merchant_workflows: Option<String>,
    pub sub_merchant_master_merchant_processes: Option<String>,
    pub sub_merchant_master_merchant_pipelines: Option<String>,
    pub sub_merchant_master_merchant_stages: Option<String>,
    pub sub_merchant_master_merchant_steps: Option<String>,
    pub sub_merchant_master_merchant_tasks: Option<String>,
    pub sub_merchant_master_merchant_jobs: Option<String>,
    pub sub_merchant_master_merchant_schedules: Option<String>,
    pub sub_merchant_master_merchant_crons: Option<String>,
    pub sub_merchant_master_merchant_timers: Option<String>,
    pub sub_merchant_master_merchant_delays: Option<String>,
    pub sub_merchant_master_merchant_retries: Option<String>,
    pub sub_merchant_master_merchant_backoffs: Option<String>,
    pub sub_merchant_master_merchant_circuit_breakers: Option<String>,
    pub sub_merchant_master_merchant_rate_limits: Option<String>,
    pub sub_merchant_master_merchant_throttling: Option<String>,
    pub sub_merchant_master_merchant_queuing: Option<String>,
    pub sub_merchant_master_merchant_batching: Option<String>,
    pub sub_merchant_master_merchant_streaming: Option<String>,
    pub sub_merchant_master_merchant_real_time: Option<String>,
    pub sub_merchant_master_merchant_async: Option<String>,
    pub sub_merchant_master_merchant_sync: Option<String>,
    pub sub_merchant_master_merchant_blocking: Option<String>,
    pub sub_merchant_master_merchant_non_blocking: Option<String>,
    pub sub_merchant_master_merchant_concurrent: Option<String>,
    pub sub_merchant_master_merchant_parallel: Option<String>,
    pub sub_merchant_master_merchant_distributed: Option<String>,
    pub sub_merchant_master_merchant_clustered: Option<String>,
    pub sub_merchant_master_merchant_scaled: Option<String>,
    pub sub_merchant_master_merchant_load_balanced: Option<String>,
    pub sub_merchant_master_merchant_high_availability: Option<String>,
    pub sub_merchant_master_merchant_fault_tolerant: Option<String>,
    pub sub_merchant_master_merchant_disaster_recovery: Option<String>,
    pub sub_merchant_master_merchant_backup: Option<String>,
    pub sub_merchant_master_merchant_replication: Option<String>,
    pub sub_merchant_master_merchant_sharding: Option<String>,
    pub sub_merchant_master_merchant_partitioning: Option<String>,
    pub sub_merchant_master_merchant_indexing: Option<String>,
    pub sub_merchant_master_merchant_caching: Option<String>,
    pub sub_merchant_master_merchant_optimization: Option<String>,
    pub sub_merchant_master_merchant_performance: Option<String>,
    pub sub_merchant_master_merchant_monitoring: Option<String>,
    pub sub_merchant_master_merchant_logging: Option<String>,
    pub sub_merchant_master_merchant_tracing: Option<String>,
    pub sub_merchant_master_merchant_profiling: Option<String>,
    pub sub_merchant_master_merchant_debugging: Option<String>,
    pub sub_merchant_master_merchant_testing: Option<String>,
    pub sub_merchant_master_merchant_validation: Option<String>,
    pub sub_merchant_master_merchant_verification: Option<String>,
    pub sub_merchant_master_merchant_authentication: Option<String>,
    pub sub_merchant_master_merchant_authorization: Option<String>,
    pub sub_merchant_master_merchant_encryption: Option<String>,
    pub sub_merchant_master_merchant_decryption: Option<String>,
    pub sub_merchant_master_merchant_hashing: Option<String>,
    pub sub_merchant_master_merchant_signing: Option<String>,
    pub sub_merchant_master_merchant_audit_trail: Option<String>,
    pub sub_merchant_master_merchant_legal: Option<String>,
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
    pub order_compliance: String,
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
    pub order_compliance: String,
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
pub fn get_auth_header(auth_type: &ConnectorAuthType) -> CustomResult<Secret<String>, ConnectorError> {
    match auth_type {
        ConnectorAuthType::SignatureKey { api_key, .. } => Ok(Secret::new(api_key.clone())),
        ConnectorAuthType::BodyKey { api_key, .. } => Ok(Secret::new(api_key.clone())),
        ConnectorAuthType::HeaderKey { api_key, .. } => Ok(Secret::new(api_key.clone())),
        _ => Err(errors::ConnectorError::AuthenticationFailed.into()),
    }
}

pub fn get_secret_key(auth_type: &ConnectorAuthType) -> CustomResult<Secret<String>, ConnectorError> {
    match auth_type {
        ConnectorAuthType::SignatureKey { api_secret, .. } => Ok(Secret::new(api_secret.clone())),
        ConnectorAuthType::BodyKey { api_secret, .. } => Ok(Secret::new(api_secret.clone())),
        ConnectorAuthType::HeaderKey { api_secret, .. } => Ok(Secret::new(api_secret.clone())),
        _ => Err(errors::ConnectorError::AuthenticationFailed.into()),
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

    crypto::Sha512Hasher::hash_string(hash_string)
}

// TryFrom implementations for request types
impl<T> TryFrom<&RouterDataV2<domain_types::connector_flow::Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for EaseBuzzPaymentsRequest
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<domain_types::connector_flow::Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth_key = get_auth_header(&item.connector_auth_type)?;
        let auth_secret = get_secret_key(&item.connector_auth_type)?;
        
        let key = auth_key.expose().clone();
        let salt = auth_secret.expose().clone();
        
        let txnid = item.router_data.resource_common_data.connector_request_reference_id.clone();
        let amount = item.amount.get_amount_as_string();
        let productinfo = item.router_data.request.description.clone().unwrap_or_else(|| "Payment".to_string());
        let firstname = item.router_data.request.get_customer_name().unwrap_or_else(|| "Customer".to_string());
        let email = item.router_data.request.email.as_ref().map(|e| e.to_string()).unwrap_or_else(|| "customer@example.com".to_string());
        let phone = item.router_data.request.phone.as_ref().map(|p| p.to_string()).unwrap_or_else(|| "9999999999".to_string());
        
        let surl = item.router_data.request.get_router_return_url()?.unwrap_or_else(|| "https://example.com/success".to_string());
        let furl = item.router_data.request.get_router_return_url()?.unwrap_or_else(|| "https://example.com/failure".to_string());
        
        // Determine payment mode based on payment method type
        let payment_modes = match item.router_data.request.payment_method_type {
            PaymentMethodType::Upi | PaymentMethodType::UpiIntent => "upi_intent".to_string(),
            PaymentMethodType::UpiCollect => "upi_collect".to_string(),
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
            &email,
            &udf_fields,
            &salt,
        );
        
        Ok(Self {
            key: Secret::new(key),
            txnid,
            amount,
            productinfo,
            firstname,
            email,
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
            address1: None,
            address2: None,
            city: None,
            state: None,
            country: None,
            zipcode: None,
            pg: None,
            customer_unique_id: None,
            split_payments: None,
            sub_merchant_id: None,
            sub_merchant_name: None,
            sub_merchant_email: None,
            sub_merchant_mobile: None,
            sub_merchant_address: None,
            sub_merchant_city: None,
            sub_merchant_state: None,
            sub_merchant_country: None,
            sub_merchant_zipcode: None,
            sub_merchant_tin: None,
            sub_merchant_pan: None,
            sub_merchant_gst: None,
            sub_merchant_sac: None,
            sub_merchant_service_tax: None,
            sub_merchant_cess: None,
            sub_merchant_discount: None,
            sub_merchant_other_charges: None,
            sub_merchant_shipping_charges: None,
            sub_merchant_total_amount: None,
            sub_merchant_additional_info: None,
            sub_merchant_custom_fields: None,
            sub_merchant_merchant_order_id: None,
            sub_merchant_merchant_transaction_id: None,
            sub_merchant_merchant_reference_id: None,
            sub_merchant_merchant_description: None,
            sub_merchant_merchant_notes: None,
            sub_merchant_merchant_metadata: None,
            sub_merchant_merchant_tags: None,
            sub_merchant_merchant_attributes: None,
            sub_merchant_merchant_properties: None,
            sub_merchant_merchant_features: None,
            sub_merchant_merchant_capabilities: None,
            sub_merchant_merchant_restrictions: None,
            sub_merchant_merchant_limits: None,
            sub_merchant_merchant_fees: None,
            sub_merchant_merchant_commission: None,
            sub_merchant_merchant_settlement: None,
            sub_merchant_merchant_payout: None,
            sub_merchant_merchant_refund: None,
            sub_merchant_merchant_chargeback: None,
            sub_merchant_merchant_dispute: None,
            sub_merchant_merchant_fraud: None,
            sub_merchant_merchant_risk: None,
            sub_merchant_merchant_compliance: None,
            sub_merchant_merchant_audit: None,
            sub_merchant_merchant_reporting: None,
            sub_merchant_merchant_analytics: None,
            sub_merchant_merchant_insights: None,
            sub_merchant_merchant_recommendations: None,
            sub_merchant_merchant_suggestions: None,
            sub_merchant_merchant_alerts: None,
            sub_merchant_merchant_notifications: None,
            sub_merchant_merchant_webhooks: None,
            sub_merchant_merchant_callbacks: None,
            sub_merchant_merchant_redirects: None,
            sub_merchant_merchant_postbacks: None,
            sub_merchant_merchant_responses: None,
            sub_merchant_merchant_requests: None,
            sub_merchant_merchant_logs: None,
            sub_merchant_merchant_events: None,
            sub_merchant_merchant_triggers: None,
            sub_merchant_merchant_actions: None,
            sub_merchant_merchant_workflows: None,
            sub_merchant_merchant_processes: None,
            sub_merchant_merchant_pipelines: None,
            sub_merchant_merchant_stages: None,
            sub_merchant_merchant_steps: None,
            sub_merchant_merchant_tasks: None,
            sub_merchant_merchant_jobs: None,
            sub_merchant_merchant_schedules: None,
            sub_merchant_merchant_crons: None,
            sub_merchant_merchant_timers: None,
            sub_merchant_merchant_delays: None,
            sub_merchant_merchant_retries: None,
            sub_merchant_merchant_backoffs: None,
            sub_merchant_merchant_circuit_breakers: None,
            sub_merchant_merchant_rate_limits: None,
            sub_merchant_merchant_throttling: None,
            sub_merchant_merchant_queuing: None,
            sub_merchant_merchant_batching: None,
            sub_merchant_merchant_streaming: None,
            sub_merchant_merchant_real_time: None,
            sub_merchant_merchant_async: None,
            sub_merchant_merchant_sync: None,
            sub_merchant_merchant_blocking: None,
            sub_merchant_merchant_non_blocking: None,
            sub_merchant_merchant_concurrent: None,
            sub_merchant_merchant_parallel: None,
            sub_merchant_merchant_distributed: None,
            sub_merchant_merchant_clustered: None,
            sub_merchant_merchant_scaled: None,
            sub_merchant_merchant_load_balanced: None,
            sub_merchant_merchant_high_availability: None,
            sub_merchant_merchant_fault_tolerant: None,
            sub_merchant_merchant_disaster_recovery: None,
            sub_merchant_merchant_backup: None,
            sub_merchant_merchant_replication: None,
            sub_merchant_merchant_sharding: None,
            sub_merchant_merchant_partitioning: None,
            sub_merchant_merchant_indexing: None,
            sub_merchant_merchant_caching: None,
            sub_merchant_merchant_optimization: None,
            sub_merchant_merchant_performance: None,
            sub_merchant_merchant_monitoring: None,
            sub_merchant_merchant_logging: None,
            sub_merchant_merchant_tracing: None,
            sub_merchant_merchant_profiling: None,
            sub_merchant_merchant_debugging: None,
            sub_merchant_merchant_testing: None,
            sub_merchant_merchant_validation: None,
            sub_merchant_merchant_verification: None,
            sub_merchant_merchant_authentication: None,
            sub_merchant_merchant_authorization: None,
            sub_merchant_merchant_encryption: None,
            sub_merchant_merchant_decryption: None,
            sub_merchant_merchant_hashing: None,
            sub_merchant_merchant_signing: None,
            sub_merchant_merchant_audit_trail: None,
            sub_merchant_merchant_compliance: None,
            sub_merchant_master_merchant_id: None,
            sub_merchant_master_merchant_name: None,
            sub_merchant_master_merchant_email: None,
            sub_merchant_master_merchant_mobile: None,
            sub_merchant_master_merchant_address: None,
            sub_merchant_master_merchant_city: None,
            sub_merchant_master_merchant_state: None,
            sub_merchant_master_merchant_country: None,
            sub_merchant_master_merchant_zipcode: None,
            sub_merchant_master_merchant_tin: None,
            sub_merchant_master_merchant_pan: None,
            sub_merchant_master_merchant_gst: None,
            sub_merchant_master_merchant_sac: None,
            sub_merchant_master_merchant_service_tax: None,
            sub_merchant_master_merchant_cess: None,
            sub_merchant_master_merchant_discount: None,
            sub_merchant_master_merchant_other_charges: None,
            sub_merchant_master_merchant_shipping_charges: None,
            sub_merchant_master_merchant_total_amount: None,
            sub_merchant_master_merchant_additional_info: None,
            sub_merchant_master_merchant_custom_fields: None,
            sub_merchant_master_merchant_order_id: None,
            sub_merchant_master_merchant_transaction_id: None,
            sub_merchant_master_merchant_reference_id: None,
            sub_merchant_master_merchant_description: None,
            sub_merchant_master_merchant_notes: None,
            sub_merchant_master_merchant_metadata: None,
            sub_merchant_master_merchant_tags: None,
            sub_merchant_master_merchant_attributes: None,
            sub_merchant_master_merchant_properties: None,
            sub_merchant_master_merchant_features: None,
            sub_merchant_master_merchant_capabilities: None,
            sub_merchant_master_merchant_restrictions: None,
            sub_merchant_master_merchant_limits: None,
            sub_merchant_master_merchant_fees: None,
            sub_merchant_master_merchant_commission: None,
            sub_merchant_master_merchant_settlement: None,
            sub_merchant_master_merchant_payout: None,
            sub_merchant_master_merchant_refund: None,
            sub_merchant_master_merchant_chargeback: None,
            sub_merchant_master_merchant_dispute: None,
            sub_merchant_master_merchant_fraud: None,
            sub_merchant_master_merchant_risk: None,
            sub_merchant_master_merchant_compliance: None,
            sub_merchant_master_merchant_audit: None,
            sub_merchant_master_merchant_reporting: None,
            sub_merchant_master_merchant_analytics: None,
            sub_merchant_master_merchant_insights: None,
            sub_merchant_master_merchant_recommendations: None,
            sub_merchant_master_merchant_suggestions: None,
            sub_merchant_master_merchant_alerts: None,
            sub_merchant_master_merchant_notifications: None,
            sub_merchant_master_merchant_webhooks: None,
            sub_merchant_master_merchant_callbacks: None,
            sub_merchant_master_merchant_redirects: None,
            sub_merchant_master_merchant_postbacks: None,
            sub_merchant_master_merchant_responses: None,
            sub_merchant_master_merchant_requests: None,
            sub_merchant_master_merchant_logs: None,
            sub_merchant_master_merchant_events: None,
            sub_merchant_master_merchant_triggers: None,
            sub_merchant_master_merchant_actions: None,
            sub_merchant_master_merchant_workflows: None,
            sub_merchant_master_merchant_processes: None,
            sub_merchant_master_merchant_pipelines: None,
            sub_merchant_master_merchant_stages: None,
            sub_merchant_master_merchant_steps: None,
            sub_merchant_master_merchant_tasks: None,
            sub_merchant_master_merchant_jobs: None,
            sub_merchant_master_merchant_schedules: None,
            sub_merchant_master_merchant_crons: None,
            sub_merchant_master_merchant_timers: None,
            sub_merchant_master_merchant_delays: None,
            sub_merchant_master_merchant_retries: None,
            sub_merchant_master_merchant_backoffs: None,
            sub_merchant_master_merchant_circuit_breakers: None,
            sub_merchant_master_merchant_rate_limits: None,
            sub_merchant_master_merchant_throttling: None,
            sub_merchant_master_merchant_queuing: None,
            sub_merchant_master_merchant_batching: None,
            sub_merchant_master_merchant_streaming: None,
            sub_merchant_master_merchant_real_time: None,
            sub_merchant_master_merchant_async: None,
            sub_merchant_master_merchant_sync: None,
            sub_merchant_master_merchant_blocking: None,
            sub_merchant_master_merchant_non_blocking: None,
            sub_merchant_master_merchant_concurrent: None,
            sub_merchant_master_merchant_parallel: None,
            sub_merchant_master_merchant_distributed: None,
            sub_merchant_master_merchant_clustered: None,
            sub_merchant_master_merchant_scaled: None,
            sub_merchant_master_merchant_load_balanced: None,
            sub_merchant_master_merchant_high_availability: None,
            sub_merchant_master_merchant_fault_tolerant: None,
            sub_merchant_master_merchant_disaster_recovery: None,
            sub_merchant_master_merchant_backup: None,
            sub_merchant_master_merchant_replication: None,
            sub_merchant_master_merchant_sharding: None,
            sub_merchant_master_merchant_partitioning: None,
            sub_merchant_master_merchant_indexing: None,
            sub_merchant_master_merchant_caching: None,
            sub_merchant_master_merchant_optimization: None,
            sub_merchant_master_merchant_performance: None,
            sub_merchant_master_merchant_monitoring: None,
            sub_merchant_master_merchant_logging: None,
            sub_merchant_master_merchant_tracing: None,
            sub_merchant_master_merchant_profiling: None,
            sub_merchant_master_merchant_debugging: None,
            sub_merchant_master_merchant_testing: None,
            sub_merchant_master_merchant_validation: None,
            sub_merchant_master_merchant_verification: None,
            sub_merchant_master_merchant_authentication: None,
            sub_merchant_master_merchant_authorization: None,
            sub_merchant_master_merchant_encryption: None,
            sub_merchant_master_merchant_decryption: None,
            sub_merchant_master_merchant_hashing: None,
            sub_merchant_master_merchant_signing: None,
            sub_merchant_master_merchant_audit_trail: None,
            sub_merchant_master_merchant_legal: None,
        })
    }
}

impl TryFrom<&RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for EaseBuzzPaymentsSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth_key = get_auth_header(&item.connector_auth_type)?;
        let auth_secret = get_secret_key(&item.connector_auth_type)?;
        
        let key = auth_key.expose().clone();
        let salt = auth_secret.expose().clone();
        
        let txnid = item.router_data.resource_common_data.connector_request_reference_id.clone();
        let amount = item.amount.get_amount_as_string();
        let email = item.router_data.request.email.as_ref().map(|e| e.to_string()).unwrap_or_else(|| "customer@example.com".to_string());
        let phone = item.router_data.request.phone.as_ref().map(|p| p.to_string()).unwrap_or_else(|| "9999999999".to_string());
        
        // Generate hash for sync
        let hash_string = format!("{}|{}|{}|{}|{}|{}", key, txnid, amount, email, phone, salt);
        let hash = crypto::Sha512Hasher::hash_string(hash_string);
        
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

impl TryFrom<&RouterDataV2<domain_types::connector_flow::RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>>
    for EaseBuzzRefundSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<domain_types::connector_flow::RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth_key = get_auth_header(&item.connector_auth_type)?;
        let auth_secret = get_secret_key(&item.connector_auth_type)?;
        
        let key = auth_key.expose().clone();
        let salt = auth_secret.expose().clone();
        
        let easebuzz_id = item.router_data.request.connector_transaction_id.get_connector_transaction_id().map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?.to_string();
        let merchant_refund_id = item.router_data.request.refund_id.clone();
        
        // Generate hash for refund sync
        let hash_string = format!("{}|{}|{}|{}", key, easebuzz_id, merchant_refund_id, salt);
        let hash = crypto::Sha512Hasher::hash_string(hash_string);
        
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
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: EaseBuzzPaymentsResponse) -> Result<Self, Self::Error> {
        let status = if response.status {
            match response.data.as_ref().map(|d| d.status.as_str()) {
                Some("success") => AttemptStatus::Charged,
                Some("pending") => AttemptStatus::Pending,
                Some("failure") => AttemptStatus::Failure,
                Some("user_aborted") => AttemptStatus::AuthenticationFailed,
                _ => AttemptStatus::Pending,
            }
        } else {
            AttemptStatus::Failure
        };

        Ok(Self {
            status,
            amount_received: response.data.as_ref().and_then(|d| {
                d.amount.parse::<f64>().ok().map(MinorUnit::from_major_unit_as_i64)
            }),
            connector_transaction_id: response.data.as_ref().map(|d| d.easebuzz_id.clone()),
            error_message: response.error_desc,
            ..Default::default()
        })
    }
}

impl TryFrom<EaseBuzzPaymentsSyncResponse> for PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: EaseBuzzPaymentsSyncResponse) -> Result<Self, Self::Error> {
        let (status, payment_data) = match response.msg {
            EaseBuzzSyncMessage::Success(data) => {
                let status = match data.status.as_str() {
                    "success" => AttemptStatus::Charged,
                    "pending" => AttemptStatus::Pending,
                    "failure" => AttemptStatus::Failure,
                    "user_aborted" => AttemptStatus::AuthenticationFailed,
                    _ => AttemptStatus::Pending,
                };
                (status, Some(data))
            }
            EaseBuzzSyncMessage::Error(_) => (AttemptStatus::Failure, None),
        };

        Ok(Self {
            status,
            amount_received: payment_data.as_ref().and_then(|d| {
                d.amount.parse::<f64>().ok().map(MinorUnit::from_major_unit_as_i64)
            }),
            connector_transaction_id: payment_data.as_ref().map(|d| d.easebuzz_id.clone()),
            ..Default::default()
        })
    }
}

impl TryFrom<EaseBuzzRefundSyncResponse> for RefundsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: EaseBuzzRefundSyncResponse) -> Result<Self, Self::Error> {
        let refund_data = match response.response {
            EaseBuzzRefundSyncData::Success(data) => Some(data),
            _ => None,
        };

        Ok(Self {
            refund_id: refund_data.as_ref().and_then(|d| d.refunds.as_ref()).and_then(|refunds| refunds.first()).map(|r| r.refund_id.clone()),
            refund_status: refund_data.as_ref().and_then(|d| d.refunds.as_ref()).and_then(|refunds| refunds.first()).map(|r| {
                match r.refund_status.as_str() {
                    "success" => common_enums::RefundStatus::Success,
                    "pending" => common_enums::RefundStatus::Pending,
                    "failure" => common_enums::RefundStatus::Failure,
                    _ => common_enums::RefundStatus::Pending,
                }
            }),
            refund_amount_received: refund_data.as_ref().and_then(|d| d.refunds.as_ref()).and_then(|refunds| refunds.first()).and_then(|r| {
                r.refund_amount.parse::<f64>().ok().map(MinorUnit::from_major_unit_as_i64)
            }),
            ..Default::default()
        })
    }
}