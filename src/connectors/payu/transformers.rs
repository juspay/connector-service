use std::collections::HashMap;

use common_enums::{AttemptStatus, Currency, PaymentMethodType};
use common_utils::{
    crypto,
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    pii::SecretSerdeValue,
    request::RequestContent,
    types::{MinorUnit, StringMinorUnit},
};
use domain_types::{
    connector_types::{PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, RefundSyncData, RefundsResponseData},
    errors,
    payment_method_data::UpiData,
    router_data_v2::{ConnectorRouterData, RouterDataV2},
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use masking::{ExposeInterface, Mask};
use serde::{Deserialize, Serialize};

use crate::services;

// Request/Response types for Payu UPI flows

#[derive(Debug, Serialize)]
pub struct PayuPaymentsRequest {
    pub key: String,
    pub command: String,
    pub hash: Secret<String>,
    pub var1: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub var2: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub var3: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PayuPaymentsResponse {
    pub status: String,
    pub msg: Option<String>,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PayuPaymentsSyncRequest {
    pub key: String,
    pub command: String,
    pub hash: Secret<String>,
    pub var1: String,
}

#[derive(Debug, Deserialize)]
pub struct PayuPaymentsSyncResponse {
    pub status: String,
    pub msg: Option<String>,
    pub transaction_details: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Serialize)]
pub struct PayuRefundSyncRequest {
    pub key: String,
    pub command: String,
    pub hash: Secret<String>,
    pub var1: String,
}

#[derive(Debug, Deserialize)]
pub struct PayuRefundSyncResponse {
    pub status: String,
    pub msg: Option<String>,
    pub refund_details: Option<HashMap<String, serde_json::Value>>,
}

// Helper functions for authentication and hashing

fn generate_hash(
    key: &str,
    command: &str,
    var1: &str,
    salt: &str,
) -> Result<Secret<String>, errors::ConnectorError> {
    let hash_string = format!("{}|{}|{}|{}", key, command, var1, salt);
    let hash = crypto::Sha512::generate_hash(hash_string.as_bytes())
        .change_context(errors::ConnectorError::RequestEncodingFailed)?;
    Ok(Secret::new(hex::encode(hash)))
}

fn extract_auth_credentials(
    auth_type: &domain_types::connector_types::ConnectorAuthType,
) -> Result<(String, String), errors::ConnectorError> {
    match auth_type {
        domain_types::connector_types::ConnectorAuthType::SignatureKey {
            api_key,
            api_secret,
        } => Ok((
            api_key.expose().clone(),
            api_secret.expose().clone(),
        )),
        domain_types::connector_types::ConnectorAuthType::BodyKey { api_key, .. } => {
            Err(errors::ConnectorError::MissingConnectorAuthField {
                field: "api_secret".to_string(),
            }
            .into())
        }
        _ => Err(errors::ConnectorError::MissingConnectorAuthField {
            field: "api_key".to_string(),
        }
        .into()),
    }
}

// Transformer implementations

impl<T> TryFrom<&RouterDataV2<Authorize, domain_types::connector_types::PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for PayuPaymentsRequest
where
    T: serde::Serialize,
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Authorize, domain_types::connector_types::PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let (key, salt) = extract_auth_credentials(&item.connector_auth_type)?;
        
        let transaction_id = item
            .resource_common_data
            .connector_request_reference_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        let amount = item.amount.get_amount_as_string();
        let currency = item.router_data.request.currency.to_string();

        // Build UPI specific data
        let upi_data = match &item.router_data.request.payment_method_data {
            domain_types::payment_method_data::PaymentMethodData::Upi(upi_data) => upi_data,
            _ => {
                return Err(errors::ConnectorError::MissingRequiredField {
                    field_name: "upi_payment_method_data".to_string(),
                }
                .into())
            }
        };

        let var1 = build_upi_transaction_data(
            transaction_id,
            &amount,
            &currency,
            upi_data,
            &item.router_data.request,
        )?;

        let hash = generate_hash(&key, "upi_collect", &var1, &salt)?;

        Ok(Self {
            key,
            command: "upi_collect".to_string(),
            hash,
            var1,
            var2: None,
            var3: None,
        })
    }
}

fn build_upi_transaction_data<T>(
    transaction_id: String,
    amount: &str,
    currency: &str,
    upi_data: &UpiData,
    request_data: &PaymentsAuthorizeData<T>,
) -> Result<String, errors::ConnectorError>
where
    T: serde::Serialize,
{
    let mut transaction_data = HashMap::new();
    
    transaction_data.insert("txnid".to_string(), transaction_id);
    transaction_data.insert("amount".to_string(), amount.to_string());
    transaction_data.insert("currency".to_string(), currency.to_string());
    
    // Add UPI specific fields
    if let Some(vpa) = &upi_data.vpa {
        transaction_data.insert("vpa".to_string(), vpa.expose().clone());
    }
    
    if let Some(payee_name) = &upi_data.payee_name {
        transaction_data.insert("payee_name".to_string(), payee_name.expose().clone());
    }

    // Add customer information
    if let Some(email) = &request_data.email {
        transaction_data.insert("email".to_string(), email.to_string());
    }

    if let Some(phone) = &request_data.phone {
        transaction_data.insert("phone".to_string(), phone.to_string());
    }

    // Add return URLs
    if let Some(return_url) = request_data.get_router_return_url() {
        transaction_data.insert("surl".to_string(), return_url.clone());
        transaction_data.insert("furl".to_string(), return_url);
    }

    // Add product info
    transaction_data.insert("productinfo".to_string(), "UPI Payment".to_string());

    serde_json::to_string(&transaction_data)
        .change_context(errors::ConnectorError::RequestEncodingFailed)
}

impl<T> TryFrom<&RouterDataV2<PSync, domain_types::connector_types::PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for PayuPaymentsSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<PSync, domain_types::connector_types::PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let (key, salt) = extract_auth_credentials(&item.connector_auth_type)?;
        
        let transaction_id = item
            .resource_common_data
            .connector_request_reference_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        let hash = generate_hash(&key, "verify_payment", &transaction_id, &salt)?;

        Ok(Self {
            key,
            command: "verify_payment".to_string(),
            hash,
            var1: transaction_id,
        })
    }
}

impl<T> TryFrom<&RouterDataV2<RSync, domain_types::connector_types::PaymentFlowData, RefundSyncData, RefundsResponseData>>
    for PayuRefundSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<RSync, domain_types::connector_types::PaymentFlowData, RefundSyncData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let (key, salt) = extract_auth_credentials(&item.connector_auth_type)?;
        
        let refund_id = item
            .resource_common_data
            .connector_request_reference_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        let hash = generate_hash(&key, "get_all_refunds_from_txn_ids", &refund_id, &salt)?;

        Ok(Self {
            key,
            command: "get_all_refunds_from_txn_ids".to_string(),
            hash,
            var1: refund_id,
        })
    }
}

// Response transformers

impl TryFrom<PayuPaymentsResponse> for PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: PayuPaymentsResponse) -> Result<Self, Self::Error> {
        let status = match response.status.as_str() {
            "success" | "1" => AttemptStatus::Charged,
            "pending" | "0" => AttemptStatus::Pending,
            "failure" | "-1" => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        let error_message = response.error.or(response.msg).or(response.message);

        Ok(Self {
            status,
            error_message,
            // Add other fields as needed
            ..Default::default()
        })
    }
}

impl TryFrom<PayuPaymentsSyncResponse> for PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: PayuPaymentsSyncResponse) -> Result<Self, Self::Error> {
        let status = match response.status.as_str() {
            "success" | "1" => AttemptStatus::Charged,
            "pending" | "0" => AttemptStatus::Pending,
            "failure" | "-1" => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        let error_message = response.msg;

        Ok(Self {
            status,
            error_message,
            // Add other fields as needed
            ..Default::default()
        })
    }
}

impl TryFrom<PayuRefundSyncResponse> for RefundsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: PayuRefundSyncResponse) -> Result<Self, Self::Error> {
        let status = match response.status.as_str() {
            "success" | "1" => AttemptStatus::Charged,
            "pending" | "0" => AttemptStatus::Pending,
            "failure" | "-1" => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        let error_message = response.msg;

        Ok(Self {
            status,
            error_message,
            // Add other fields as needed
            ..Default::default()
        })
    }
}