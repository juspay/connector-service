// AirtelMoney Transformers - Request/Response Data Structures

use common_enums::{AttemptStatus, RefundStatus};
use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
    types::{self, MinorUnit},
};
use domain_types::{
    connector_types::{HttpMethod, RedirectForm, ResponseId},
    errors::ConnectorError,
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

// Request/Response Types based on Haskell implementation

#[derive(Debug, Clone, Serialize)]
pub struct AirtelMoneyPaymentsRequest {
    pub channel: String,
    pub hash: String,
    pub fe_session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ver: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub otp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consent: Option<ConsentType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_ref_no: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cust_alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txn_ref_no: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merchant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txn_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_ref_no: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lang_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txn_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConsentType {
    pub count: String,
    pub expiry_date: String,
    pub max_amount: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AirtelMoneyPaymentsResponse {
    pub code: i32,
    pub status: String,
    pub response: AirtelMoneyResponseData,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum AirtelMoneyResponseData {
    ValidResponse(AirtelMoneyValidResponse),
    ErrorResponse(AirtelMoneyErrorResponse),
    RedirectResponse(AirtelMoneyRedirectResponse),
}

#[derive(Debug, Clone, Deserialize)]
pub struct AirtelMoneyValidResponse {
    pub meta: AirtelMoneyMetaType,
    #[serde(rename = "_data")]
    pub data: AirtelMoneyDataType,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AirtelMoneyErrorResponse {
    pub meta: AirtelMoneyMetaType,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AirtelMoneyRedirectResponse {
    pub code: String,
    pub description: String,
    pub redirection_link: String,
    pub payment_ref_no: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AirtelMoneyMetaType {
    pub error_code: String,
    pub error_msg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_cash_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AirtelMoneyDataType {
    pub auth_token: String,
    pub merchant_auth_needed: bool,
    pub redirection_needed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cust_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avl_balance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consent: Option<ConsentType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<NameType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fe_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amp_txn_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txn_date_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txn_charge_details: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txn_tax_details: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NameType {
    pub first: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle: Option<String>,
    pub last: String,
}

// Transformer implementations

impl<T> TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>> for AirtelMoneyPaymentsRequest {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>) -> Result<Self, Self::Error> {
        let amount = item.amount.get_amount_as_string();
        
        // Extract customer ID
        let customer_id = item.resource_common_data.get_customer_id()?;
        let customer_id_string = customer_id.get_string_repr();
        
        // Extract transaction ID
        let transaction_id = item.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| ConnectorError::RequestEncodingFailed)?;
        
        // Generate hash (simplified - in real implementation this would use proper hashing)
        let hash = format!("hash_{}", transaction_id);
        
        Ok(Self {
            channel: "APP".to_string(),
            hash,
            fe_session_id: transaction_id.clone(),
            ver: Some("1.0".to_string()),
            end_channel: Some("WEB".to_string()),
            payment_ref_no: Some(transaction_id),
            amount: Some(amount),
            cust_alias: Some(customer_id_string),
            otp: None,
            verification_token: None,
            auth_value: None,
            consent: None,
            txn_ref_no: None,
            request: None,
            merchant_id: None,
            txn_date: None,
            refund_ref_no: None,
            lang_id: None,
            txn_id: None,
        })
    }
}

impl<T> TryFrom<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>> for AirtelMoneyPaymentsRequest {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(item: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>) -> Result<Self, Self::Error> {
        let amount = item.amount.get_amount_as_string();
        
        // Extract transaction ID
        let transaction_id = item.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| ConnectorError::RequestEncodingFailed)?;
        
        // Generate hash (simplified)
        let hash = format!("hash_{}", transaction_id);
        
        Ok(Self {
            channel: "APP".to_string(),
            hash,
            fe_session_id: transaction_id.clone(),
            ver: Some("1.0".to_string()),
            end_channel: Some("WEB".to_string()),
            payment_ref_no: Some(transaction_id),
            amount: Some(amount),
            cust_alias: None,
            otp: None,
            verification_token: None,
            auth_value: None,
            consent: None,
            txn_ref_no: Some(transaction_id.clone()),
            request: Some("SYNC".to_string()),
            merchant_id: Some("merchant".to_string()),
            txn_date: Some("2024-01-01".to_string()),
            refund_ref_no: None,
            lang_id: Some("en".to_string()),
            txn_id: None,
        })
    }
}

impl<T> TryFrom<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>> for AirtelMoneyPaymentsRequest {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(item: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>) -> Result<Self, Self::Error> {
        let amount = item.amount.get_amount_as_string();
        
        // Extract transaction ID
        let transaction_id = item.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| ConnectorError::RequestEncodingFailed)?;
        
        // Generate hash (simplified)
        let hash = format!("hash_{}", transaction_id);
        
        Ok(Self {
            channel: "APP".to_string(),
            hash,
            fe_session_id: transaction_id.clone(),
            ver: Some("1.0".to_string()),
            end_channel: Some("WEB".to_string()),
            payment_ref_no: Some(transaction_id.clone()),
            amount: Some(amount),
            cust_alias: None,
            otp: None,
            verification_token: None,
            auth_value: None,
            consent: None,
            txn_ref_no: None,
            request: Some("REFUND".to_string()),
            merchant_id: Some("merchant".to_string()),
            txn_date: Some("2024-01-01".to_string()),
            refund_ref_no: Some(format!("refund_{}", transaction_id)),
            lang_id: Some("en".to_string()),
            txn_id: Some(transaction_id),
        })
    }
}

impl<T> TryFrom<&RouterDataV2<RSync, RefundSyncData, RefundSyncData, RefundsResponseData>> for AirtelMoneyPaymentsRequest {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(item: &RouterDataV2<RSync, RefundSyncData, RefundSyncData, RefundsResponseData>) -> Result<Self, Self::Error> {
        let amount = item.amount.get_amount_as_string();
        
        // Extract transaction ID
        let transaction_id = item.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| ConnectorError::RequestEncodingFailed)?;
        
        // Generate hash (simplified)
        let hash = format!("hash_{}", transaction_id);
        
        Ok(Self {
            channel: "APP".to_string(),
            hash,
            fe_session_id: transaction_id.clone(),
            ver: Some("1.0".to_string()),
            end_channel: Some("WEB".to_string()),
            payment_ref_no: Some(transaction_id.clone()),
            amount: Some(amount),
            cust_alias: None,
            otp: None,
            verification_token: None,
            auth_value: None,
            consent: None,
            txn_ref_no: Some(transaction_id.clone()),
            request: Some("REFUND_SYNC".to_string()),
            merchant_id: Some("merchant".to_string()),
            txn_date: Some("2024-01-01".to_string()),
            refund_ref_no: Some(format!("refund_{}", transaction_id)),
            lang_id: Some("en".to_string()),
            txn_id: Some(transaction_id),
        })
    }
}