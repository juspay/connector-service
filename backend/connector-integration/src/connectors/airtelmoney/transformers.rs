// AirtelMoney Transformers - Request/Response Data Structures

use common_enums::{AttemptStatus, RefundStatus};
use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
    types::{self, MinorUnit},
};
use domain_types::{
    connector_types::{HttpMethod, RedirectForm},
    errors::{ConnectorError, ConnectorErrorType},
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::{ConnectorRouterData, RouterDataV2},
    router_request_types::{self, ResponseId},
    router_response_types::{self, PaymentsResponseData, RefundsResponseData},
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

// Sync Request
#[derive(Debug, Clone, Serialize)]
pub struct AirtelMoneyPaymentsSyncRequest {
    pub fe_session_id: String,
    pub txn_ref_no: String,
    pub txn_date: String,
    pub request: String,
    pub merchant_id: String,
    pub hash: String,
    pub lang_id: String,
    pub amount: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_ref_no: Option<String>,
}

// Refund Request
#[derive(Debug, Clone, Serialize)]
pub struct AirtelMoneyRefundRequest {
    pub fe_session_id: String,
    pub txn_id: String,
    pub txn_date: String,
    pub request: String,
    pub merchant_id: String,
    pub hash: String,
    pub refund_ref_no: String,
    pub amount: String,
}

// Refund Response
#[derive(Debug, Clone, Deserialize)]
pub struct AirtelMoneyRefundResponse {
    pub code: i32,
    pub status: String,
    pub response: AirtelMoneyRefundResponseData,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum AirtelMoneyRefundResponseData {
    ValidRefund(AirtelMoneyValidRefund),
    ErrorRefund(AirtelMoneyErrorRefund),
    InvalidRefund(AirtelMoneyInvalidRefund),
}

#[derive(Debug, Clone, Deserialize)]
pub struct AirtelMoneyValidRefund {
    pub txn_id: String,
    pub amount: String,
    pub status: String,
    pub txn_date: String,
    pub merchant_id: String,
    pub fe_session_id: String,
    pub hash: String,
    pub message_text: String,
    pub code: String,
    pub error_code: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AirtelMoneyErrorRefund {
    pub status: String,
    pub merchant_id: String,
    pub fe_session_id: String,
    pub hash: String,
    pub message_text: String,
    pub code: String,
    pub error_code: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AirtelMoneyInvalidRefund {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    pub message_text: String,
    pub code: String,
    pub error_code: String,
}

// Refund Sync Request
#[derive(Debug, Clone, Serialize)]
pub struct AirtelMoneyRefundSyncRequest {
    pub fe_session_id: String,
    pub txn_ref_no: String,
    pub txn_date: String,
    pub request: String,
    pub merchant_id: String,
    pub hash: String,
    pub lang_id: String,
    pub amount: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_ref_no: Option<String>,
}

// Stub types for unimplemented flows
#[derive(Debug, Clone, Serialize)]
pub struct AirtelMoneyVoidRequest;
#[derive(Debug, Clone)]
pub struct AirtelMoneyVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct AirtelMoneyCaptureRequest;
#[derive(Debug, Clone)]
pub struct AirtelMoneyCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct AirtelMoneyCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct AirtelMoneyCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct AirtelMoneySessionTokenRequest;
#[derive(Debug, Clone)]
pub struct AirtelMoneySessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct AirtelMoneySetupMandateRequest;
#[derive(Debug, Clone)]
pub struct AirtelMoneySetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct AirtelMoneyRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct AirtelMoneyRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct AirtelMoneyAcceptDisputeRequest;
#[derive(Debug, Clone)]
pub struct AirtelMoneyAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct AirtelMoneyDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct AirtelMoneyDefendDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct AirtelMoneySubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct AirtelMoneySubmitEvidenceResponse;

// Transformer implementations

impl<T> TryFrom<&ConnectorRouterData<&router_request_types::PaymentsAuthorizeData<T>>> for AirtelMoneyPaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &ConnectorRouterData<&router_request_types::PaymentsAuthorizeData<T>>) -> Result<Self, Self::Error> {
        let amount = item.amount.get_amount_as_string();
        let currency = item.router_data.request.currency.to_string();
        
        // Extract customer ID
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let customer_id_string = customer_id.get_string_repr();
        
        // Extract transaction ID
        let transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;
        
        // Extract return URL
        let return_url = item.router_data.request.get_router_return_url()?;
        
        // Extract email
        let email = item.router_data.request.email.clone();
        
        // Extract IP address
        let ip_address = item.router_data.request.get_ip_address_as_optional()
            .map(|ip| ip.expose())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        
        // Extract user agent
        let user_agent = item.router_data.request.browser_info
            .as_ref()
            .and_then(|info| info.user_agent.clone())
            .unwrap_or_else(|| "Mozilla/5.0".to_string());
        
        // Check if test mode
        let is_test = item.router_data.resource_common_data.test_mode.unwrap_or(false);
        
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

impl<T> TryFrom<AirtelMoneyPaymentsResponse> for router_response_types::PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: AirtelMoneyPaymentsResponse) -> Result<Self, Self::Error> {
        match response.response {
            AirtelMoneyResponseData::ValidResponse(valid_resp) => {
                let status = match response.status.as_str() {
                    "SUCCESS" => AttemptStatus::Charged,
                    "PENDING" => AttemptStatus::Pending,
                    _ => AttemptStatus::Failure,
                };

                Ok(Self {
                    status,
                    amount_received: valid_resp.data.avl_balance.as_ref()
                        .and_then(|balance| balance.parse::<f64>().ok())
                        .map(|amt| MinorUnit::from_major_unit_as_i64(amt)),
                    connector_transaction_id: valid_resp.data.fe_session_id,
                    error: None,
                    redirection_data: if valid_resp.data.redirection_needed {
                        Some(RedirectForm {
                            url: valid_resp.data.redirect_url.unwrap_or_default(),
                            method: HttpMethod::Get,
                            form_fields: std::collections::HashMap::new(),
                        })
                    } else {
                        None
                    },
                    network_txn_id: valid_resp.data.amp_txn_id,
                    connector_response: response,
                    ..Default::default()
                })
            }
            AirtelMoneyResponseData::ErrorResponse(error_resp) => {
                Ok(Self {
                    status: AttemptStatus::Failure,
                    error: Some(ConnectorError::from(
                        ConnectorErrorType::UnexpectedResponseError(
                            error_resp.meta.error_msg,
                        ),
                    )),
                    connector_response: response,
                    ..Default::default()
                })
            }
            AirtelMoneyResponseData::RedirectResponse(redirect_resp) => {
                Ok(Self {
                    status: AttemptStatus::AuthenticationPending,
                    redirection_data: Some(RedirectForm {
                        url: redirect_resp.redirection_link,
                        method: HttpMethod::Get,
                        form_fields: std::collections::HashMap::new(),
                    }),
                    connector_response: response,
                    ..Default::default()
                })
            }
        }
    }
}

impl<T> TryFrom<&ConnectorRouterData<&router_request_types::PaymentsSyncData>> for AirtelMoneyPaymentsSyncRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &ConnectorRouterData<&router_request_types::PaymentsSyncData>) -> Result<Self, Self::Error> {
        let amount = item.amount.get_amount_as_string();
        
        // Extract transaction ID
        let transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;
        
        // Generate hash (simplified)
        let hash = format!("hash_{}", transaction_id);
        
        Ok(Self {
            fe_session_id: transaction_id.clone(),
            txn_ref_no: transaction_id.clone(),
            txn_date: "2024-01-01".to_string(), // TODO: Use proper date
            request: "SYNC".to_string(),
            merchant_id: "merchant".to_string(),
            hash,
            lang_id: "en".to_string(),
            amount,
            refund_ref_no: None,
        })
    }
}

impl<T> TryFrom<&ConnectorRouterData<&router_request_types::RefundsData>> for AirtelMoneyRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &ConnectorRouterData<&router_request_types::RefundsData>) -> Result<Self, Self::Error> {
        let amount = item.amount.get_amount_as_string();
        
        // Extract transaction ID
        let transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;
        
        // Generate hash (simplified)
        let hash = format!("hash_{}", transaction_id);
        
        Ok(Self {
            fe_session_id: transaction_id.clone(),
            txn_id: transaction_id.clone(),
            txn_date: "2024-01-01".to_string(), // TODO: Use proper date
            request: "REFUND".to_string(),
            merchant_id: "merchant".to_string(),
            hash,
            refund_ref_no: format!("refund_{}", transaction_id),
            amount,
        })
    }
}

impl<T> TryFrom<AirtelMoneyRefundResponse> for router_response_types::RefundsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: AirtelMoneyRefundResponse) -> Result<Self, Self::Error> {
        match response.response {
            AirtelMoneyRefundResponseData::ValidRefund(valid_refund) => {
                let status = match valid_refund.status.as_str() {
                    "SUCCESS" => RefundStatus::Success,
                    "PENDING" => RefundStatus::Pending,
                    _ => RefundStatus::Failure,
                };

                Ok(Self {
                    refund_id: Some(valid_refund.txn_id),
                    status,
                    amount: valid_refund.amount.parse::<f64>().ok()
                        .map(|amt| MinorUnit::from_major_unit_as_i64(amt)),
                    connector_response: response,
                    ..Default::default()
                })
            }
            AirtelMoneyRefundResponseData::ErrorRefund(error_refund) => {
                Ok(Self {
                    status: RefundStatus::Failure,
                    error: Some(ConnectorError::from(
                        ConnectorErrorType::UnexpectedResponseError(
                            error_refund.message_text,
                        ),
                    )),
                    connector_response: response,
                    ..Default::default()
                })
            }
            AirtelMoneyRefundResponseData::InvalidRefund(invalid_refund) => {
                Ok(Self {
                    status: RefundStatus::Failure,
                    error: Some(ConnectorError::from(
                        ConnectorErrorType::UnexpectedResponseError(
                            invalid_refund.message_text,
                        ),
                    )),
                    connector_response: response,
                    ..Default::default()
                })
            }
        }
    }
}

impl<T> TryFrom<&ConnectorRouterData<&router_request_types::RefundSyncData>> for AirtelMoneyRefundSyncRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &ConnectorRouterData<&router_request_types::RefundSyncData>) -> Result<Self, Self::Error> {
        let amount = item.amount.get_amount_as_string();
        
        // Extract transaction ID
        let transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;
        
        // Generate hash (simplified)
        let hash = format!("hash_{}", transaction_id);
        
        Ok(Self {
            fe_session_id: transaction_id.clone(),
            txn_ref_no: transaction_id.clone(),
            txn_date: "2024-01-01".to_string(), // TODO: Use proper date
            request: "REFUND_SYNC".to_string(),
            merchant_id: "merchant".to_string(),
            hash,
            lang_id: "en".to_string(),
            amount,
            refund_ref_no: Some(format!("refund_{}", transaction_id)),
        })
    }
}