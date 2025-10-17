use std::collections::HashMap;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    crypto,
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    types::{self, MinorUnit},
};
use domain_types::{
    connector_types::{PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, RefundSyncData, RefundsResponseData},
    errors,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_domain_models::{
    router_data_v2::{self, ConnectorCommonData},
    router_request_types::ResponseId,
};
use masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};
use sha2::Digest;

// Request/Response types based on the Haskell implementation

#[derive(Debug, Clone, Serialize)]
pub struct PayTMv2PaymentsRequest {
    pub head: PayTMv2RequestHead,
    pub body: PayTMv2PaymentsRequestBody,
}

#[derive(Debug, Clone, Serialize)]
pub struct PayTMv2RequestHead {
    pub client_id: String,
    pub version: String,
    pub request_timestamp: String,
    pub channel_id: String,
    pub signature: Secret<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PayTMv2PaymentsRequestBody {
    pub request_type: String,
    pub mid: String,
    pub order_id: String,
    pub website_name: String,
    pub txn_amount: PayTMv2Amount,
    pub user_info: PayTMv2UserInfo,
    pub payment_mode: String,
    pub payer_account: Option<String>,
    pub callback_url: Option<String>,
    pub extend_info: Option<PayTMv2ExtendInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PayTMv2Amount {
    pub value: String,
    pub currency: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PayTMv2UserInfo {
    pub cust_id: String,
    pub mobile: Option<String>,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PayTMv2ExtendInfo {
    pub udf1: Option<String>,
    pub udf2: Option<String>,
    pub udf3: Option<String>,
    pub merc_unq_ref: Option<String>,
    pub comments: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayTMv2PaymentsResponse {
    pub head: PayTMv2ResponseHead,
    pub body: PayTMv2PaymentsResponseBody,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayTMv2ResponseHead {
    pub response_timestamp: Option<String>,
    pub version: String,
    pub client_id: Option<String>,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayTMv2PaymentsResponseBody {
    pub result_info: PayTMv2ResultInfo,
    pub txn_token: Option<String>,
    pub is_promo_code_valid: Option<bool>,
    pub authenticated: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayTMv2ResultInfo {
    pub result_status: String,
    pub result_code: String,
    pub result_msg: String,
    pub retry: Option<bool>,
    pub bank_retry: Option<bool>,
    pub auth_ref_id: Option<String>,
}

// Sync request types
#[derive(Debug, Clone, Serialize)]
pub struct PayTMv2PaymentsSyncRequest {
    pub head: PayTMv2SyncRequestHead,
    pub body: PayTMv2PaymentsSyncRequestBody,
}

#[derive(Debug, Clone, Serialize)]
pub struct PayTMv2SyncRequestHead {
    pub signature: Secret<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PayTMv2PaymentsSyncRequestBody {
    pub mid: String,
    pub order_id: String,
    pub txn_type: Option<String>,
}

// Refund sync request types
#[derive(Debug, Clone, Serialize)]
pub struct PayTMv2RefundSyncRequest {
    pub head: PayTMv2RefundSyncRequestHead,
    pub body: PayTMv2RefundSyncRequestBody,
}

#[derive(Debug, Clone, Serialize)]
pub struct PayTMv2RefundSyncRequestHead {
    pub client_id: String,
    pub version: String,
    pub request_timestamp: String,
    pub channel_id: String,
    pub signature: Secret<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PayTMv2RefundSyncRequestBody {
    pub mid: String,
    pub order_id: String,
    pub ref_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayTMv2RefundSyncResponse {
    pub head: PayTMv2RefundSyncResponseHead,
    pub body: PayTMv2RefundSyncResponseBody,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayTMv2RefundSyncResponseHead {
    pub client_id: Option<String>,
    pub version: String,
    pub response_timestamp: Option<String>,
    pub channel_id: Option<String>,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayTMv2RefundSyncResponseBody {
    pub order_id: Option<String>,
    pub user_credit_initiate_status: Option<String>,
    pub mid: Option<String>,
    pub merchant_refund_request_timestamp: Option<String>,
    pub result_info: PayTMv2SyncResultInfo,
    pub txn_timestamp: Option<String>,
    pub accept_refund_timestamp: Option<String>,
    pub accept_refund_status: Option<String>,
    pub refund_detail_info_list: Option<Vec<PayTMv2RefundDetailInfo>>,
    pub user_credit_initiate_timestamp: Option<String>,
    pub total_refund_amount: Option<String>,
    pub ref_id: Option<String>,
    pub txn_amount: Option<String>,
    pub refund_id: Option<String>,
    pub txn_id: Option<String>,
    pub refund_amount: Option<String>,
    pub refund_reason: Option<String>,
    pub agent_info: Option<PayTMv2AgentInfo>,
    pub gateway_info: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayTMv2SyncResultInfo {
    pub result_status: String,
    pub result_code: String,
    pub result_msg: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayTMv2RefundDetailInfo {
    pub refund_type: String,
    pub pay_method: Option<String>,
    pub refund_amount: Option<String>,
    pub user_credit_expected_date: Option<String>,
    pub user_mobile_no: Option<String>,
    pub masked_bank_account_number: Option<String>,
    pub masked_vpa: Option<String>,
    pub card_scheme: Option<String>,
    pub masked_card_number: Option<String>,
    pub issuing_bank_name: Option<String>,
    pub rrn: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayTMv2AgentInfo {
    pub employee_id: Option<String>,
    pub name: Option<String>,
    pub phone_no: Option<String>,
    pub email: Option<String>,
}

// Error response type
#[derive(Debug, Clone, Deserialize)]
pub struct PayTMv2ErrorResponse {
    pub error_code: String,
    pub error_message: String,
}

// Transformer implementations

impl<T> TryFrom<&RouterDataV2<router_data_v2::Authorize, ConnectorCommonData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for PayTMv2PaymentsRequest
where
    T: domain_types::payment_method_data::PaymentMethodDataTypes,
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<router_data_v2::Authorize, ConnectorCommonData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = get_auth_credentials(&item.router_data.connector_auth_type)?;
        let amount = item.amount.get_amount_as_string();
        let currency = item.router_data.request.currency.to_string();
        
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let customer_id_string = customer_id.get_string_repr();
        
        let order_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;
        
        let return_url = item.router_data.request.get_router_return_url()?;
        
        let email = item.router_data.request.email.clone()
            .map(|e| e.expose().to_string());
        
        let phone = item.router_data.request.phone.clone()
            .map(|p| p.number().to_string());

        // Extract UPI specific data
        let (payment_mode, payer_account) = match &item.router_data.request.payment_method_data {
            domain_types::payment_method_data::PaymentMethodData::Upi(upi_data) => {
                let mode = match upi_data.upi_payment_method {
                    domain_types::payment_method_data::UpiPaymentMethod::Intent(_) => "UPI_INTENT",
                    domain_types::payment_method_data::UpiPaymentMethod::Collect(_) => "UPI_COLLECT",
                    domain_types::payment_method_data::UpiPaymentMethod::Qr(_) => "UPI_QR",
                };
                let vpa = upi_data.vpa.as_ref().map(|v| v.expose().to_string());
                (mode.to_string(), vpa)
            }
            _ => ("UPI".to_string(), None),
        };

        let request_head = PayTMv2RequestHead {
            client_id: auth.client_id,
            version: "v1".to_string(),
            request_timestamp: chrono::Utc::now().timestamp().to_string(),
            channel_id: "WEB".to_string(),
            signature: auth.signature,
        };

        let request_body = PayTMv2PaymentsRequestBody {
            request_type: "PAYMENT".to_string(),
            mid: auth.merchant_id,
            order_id,
            website_name: "DEFAULT".to_string(),
            txn_amount: PayTMv2Amount {
                value: amount,
                currency,
            },
            user_info: PayTMv2UserInfo {
                cust_id: customer_id_string,
                mobile: phone,
                email,
                first_name: None,
                last_name: None,
            },
            payment_mode,
            payer_account,
            callback_url: Some(return_url),
            extend_info: None,
        };

        Ok(Self {
            head: request_head,
            body: request_body,
        })
    }
}

impl<T> TryFrom<&RouterDataV2<router_data_v2::PSync, ConnectorCommonData, PaymentsSyncData, PaymentsResponseData>>
    for PayTMv2PaymentsSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<router_data_v2::PSync, ConnectorCommonData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = get_auth_credentials(&item.router_data.connector_auth_type)?;
        
        let order_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        let request_head = PayTMv2SyncRequestHead {
            signature: auth.signature,
        };

        let request_body = PayTMv2PaymentsSyncRequestBody {
            mid: auth.merchant_id,
            order_id,
            txn_type: Some("SALE".to_string()),
        };

        Ok(Self {
            head: request_head,
            body: request_body,
        })
    }
}

impl<T> TryFrom<&RouterDataV2<router_data_v2::RSync, ConnectorCommonData, RefundSyncData, RefundsResponseData>>
    for PayTMv2RefundSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<router_data_v2::RSync, ConnectorCommonData, RefundSyncData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = get_auth_credentials(&item.router_data.connector_auth_type)?;
        
        let order_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;
        
        let refund_id = item.router_data.request.connector_refund_id
            .get_connector_refund_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        let request_head = PayTMv2RefundSyncRequestHead {
            client_id: auth.client_id,
            version: "v1".to_string(),
            request_timestamp: chrono::Utc::now().timestamp().to_string(),
            channel_id: "WEB".to_string(),
            signature: auth.signature,
        };

        let request_body = PayTMv2RefundSyncRequestBody {
            mid: auth.merchant_id,
            order_id,
            ref_id: refund_id,
        };

        Ok(Self {
            head: request_head,
            body: request_body,
        })
    }
}

impl<T> TryFrom<PayTMv2PaymentsResponse> for PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: PayTMv2PaymentsResponse) -> Result<Self, Self::Error> {
        let status = match response.body.result_info.result_status.as_str() {
            "SUCCESS" => AttemptStatus::Charged,
            "PENDING" => AttemptStatus::Pending,
            "FAILURE" => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        Ok(Self {
            status,
            response: Ok(hyperswitch_domain_models::payments::PaymentResponseData::TransactionResponse {
                transaction_id: response.body.txn_token,
                gateway_response: response,
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                fraud_check: None,
                incremental_authorization_allowed: None,
                chargebacks: None,
            }),
            ..Default::default()
        })
    }
}

impl<T> TryFrom<PayTMv2RefundSyncResponse> for RefundsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: PayTMv2RefundSyncResponse) -> Result<Self, Self::Error> {
        let status = match response.body.result_info.result_status.as_str() {
            "SUCCESS" => AttemptStatus::Charged,
            "PENDING" => AttemptStatus::Pending,
            "FAILURE" => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        let refund_amount = response.body.refund_amount
            .and_then(|amt| amt.parse::<i64>().ok())
            .map(MinorUnit::new);

        Ok(Self {
            status,
            response: Ok(hyperswitch_domain_models::refunds::RefundResponseData {
                refund_id: response.body.refund_id,
                connector_refund_id: response.body.refund_id,
                gateway_response: response,
                refund_amount_received: refund_amount,
                connector_metadata: None,
            }),
            ..Default::default()
        })
    }
}

// Helper function to extract auth credentials
#[derive(Debug, Clone)]
pub struct PayTMv2AuthCredentials {
    pub client_id: String,
    pub merchant_id: String,
    pub signature: Secret<String>,
}

fn get_auth_credentials(auth_type: &domain_types::types::ConnectorAuthType) -> CustomResult<PayTMv2AuthCredentials, errors::ConnectorError> {
    match auth_type {
        domain_types::types::ConnectorAuthType::SignatureKey { api_key, key } => {
            Ok(PayTMv2AuthCredentials {
                client_id: api_key.expose().to_string(),
                merchant_id: key.expose().to_string(),
                signature: Secret::new(generate_signature(api_key.expose(), key.expose())?),
            })
        }
        _ => Err(errors::ConnectorError::AuthenticationFailed.into()),
    }
}

fn generate_signature(client_id: &str, merchant_id: &str) -> CustomResult<String, errors::ConnectorError> {
    // Generate signature using SHA256 hash
    let data = format!("{}|{}", client_id, merchant_id);
    let mut hasher = sha2::Sha256::new();
    hasher.update(data.as_bytes());
    let hash = hasher.finalize();
    Ok(hex::encode(hash))
}