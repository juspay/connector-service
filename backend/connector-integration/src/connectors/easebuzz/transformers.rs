use common_utils::{
    crypto,
    errors::CustomResult,
    pii::SecretSerdeValue,
    types::StringMinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, RefundSyncData, RefundsResponseData},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_request_types::ResponseId,
    router_request_types::AccessToken,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use masking::Secret;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct EaseBuzzPaymentsRequest {
    pub txnid: String,
    pub amount: String,
    pub currency: String,
    pub email: String,
    pub phone: String,
    pub surl: String,
    pub furl: String,
    pub key: Secret<String>,
    pub hash: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf2: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf3: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf5: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf6: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf7: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf8: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf9: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf10: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub productinfo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firstname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lastname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address2: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zipcode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pg: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzPaymentsResponse {
    pub status: i32,
    #[serde(rename = "error_desc")]
    pub error_desc: Option<String>,
    pub data: String,
}

#[derive(Debug, Serialize)]
pub struct EaseBuzzPaymentsSyncRequest {
    pub txnid: String,
    pub amount: String,
    pub email: String,
    pub phone: String,
    pub key: Secret<String>,
    pub hash: Secret<String>,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzPaymentsSyncResponse {
    pub status: bool,
    pub msg: String,
}

#[derive(Debug, Serialize)]
pub struct EaseBuzzRefundSyncRequest {
    pub key: Secret<String>,
    #[serde(rename = "easebuzz_id")]
    pub easebuzz_id: String,
    pub hash: Secret<String>,
    #[serde(rename = "merchant_refund_id")]
    pub merchant_refund_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "status", content = "response")]
pub enum EaseBuzzRefundSyncResponse {
    #[serde(rename = "1")]
    Success(EaseBuzzRefundSyncSuccessResponse),
    #[serde(rename = "0")]
    Failure(EaseBuzzRefundSyncFailureResponse),
    #[serde(rename = "validation_error")]
    ValidationError(EaseBuzzRefundSyncValidationErrorResponse),
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundSyncSuccessResponse {
    #[serde(rename = "txnid")]
    pub txnid: String,
    #[serde(rename = "easebuzz_id")]
    pub easebuzz_id: String,
    #[serde(rename = "net_amount_debit")]
    pub net_amount_debit: String,
    pub amount: String,
    pub refunds: Option<Vec<RefundSyncType>>,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundSyncFailureResponse {
    pub status: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundSyncValidationErrorResponse {
    #[serde(rename = "validation_errors")]
    pub validation_errors: Option<serde_json::Value>,
    pub status: bool,
    #[serde(rename = "error_code")]
    pub error_code: Option<String>,
    #[serde(rename = "error_desc")]
    pub error_desc: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RefundSyncType {
    #[serde(rename = "refund_id")]
    pub refund_id: String,
    #[serde(rename = "refund_status")]
    pub refund_status: String,
    #[serde(rename = "merchant_refund_id")]
    pub merchant_refund_id: String,
    #[serde(rename = "merchant_refund_date")]
    pub merchant_refund_date: String,
    #[serde(rename = "refund_settled_date")]
    pub refund_settled_date: Option<String>,
    #[serde(rename = "refund_amount")]
    pub refund_amount: String,
    #[serde(rename = "arn_number")]
    pub arn_number: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundSyncResponseWrapper {
    pub code: i32,
    pub status: String,
    pub response: EaseBuzzRefundSyncResponse,
}

impl EaseBuzzRefundSyncResponse {
    pub fn get_refund_id(&self) -> Option<String> {
        match self {
            EaseBuzzRefundSyncResponse::Success(resp) => {
                resp.refunds.as_ref().and_then(|refunds| refunds.first().map(|r| r.refund_id.clone()))
            }
            _ => None,
        }
    }

    pub fn get_connector_refund_id(&self) -> Option<String> {
        match self {
            EaseBuzzRefundSyncResponse::Success(resp) => Some(resp.easebuzz_id.clone()),
            _ => None,
        }
    }

    pub fn get_refund_status(&self) -> Option<String> {
        match self {
            EaseBuzzRefundSyncResponse::Success(resp) => {
                resp.refunds.as_ref().and_then(|refunds| refunds.first().map(|r| r.refund_status.clone()))
            }
            _ => None,
        }
    }
}

impl<T> TryFrom<&RouterDataV2<Authorize, domain_types::connector_types::PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for EaseBuzzPaymentsRequest
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;

    fn try_from(item: &RouterDataV2<Authorize, domain_types::connector_types::PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>) -> Result<Self, Self::Error> {
        let auth = get_auth_credentials(&item.connector_auth_type)?;
        let amount = item.amount.get_amount_as_string();
        let currency = item.router_data.request.currency.to_string();
        
        let txnid = item.router_data.resource_common_data.connector_request_reference_id.clone();
        let email = item.router_data.request.email.as_ref().map(|e| e.get_string_repr().to_string()).unwrap_or_default();
        let phone = item.router_data.request.phone.as_ref().map(|p| p.get_string_repr().to_string()).unwrap_or_default();
        
        let return_url = item.router_data.request.get_router_return_url().unwrap_or_default();
        let surl = return_url.clone();
        let furl = return_url;

        let hash = generate_hash(&txnid, &amount, &currency, &email, &phone, &auth.key.expose(), &auth.secret.expose())?;

        Ok(Self {
            txnid,
            amount,
            currency,
            email,
            phone,
            surl,
            furl,
            key: auth.key,
            hash,
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
            productinfo: Some("Payment".to_string()),
            firstname: item.router_data.request.customer_name.clone(),
            lastname: None,
            address1: None,
            address2: None,
            city: None,
            state: None,
            country: None,
            zipcode: None,
            pg: Some("UPI".to_string()),
        })
    }
}

impl<T> TryFrom<&RouterDataV2<PSync, domain_types::connector_types::PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for EaseBuzzPaymentsSyncRequest
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;

    fn try_from(item: &RouterDataV2<PSync, domain_types::connector_types::PaymentFlowData, PaymentsSyncData, PaymentsResponseData>) -> Result<Self, Self::Error> {
        let auth = get_auth_credentials(&item.connector_auth_type)?;
        let amount = item.amount.get_amount_as_string();
        
        let txnid = item.router_data.request.connector_transaction_id.get_connector_transaction_id()?;
        let email = item.router_data.request.email.as_ref().map(|e| e.get_string_repr().to_string()).unwrap_or_default();
        let phone = item.router_data.request.phone.as_ref().map(|p| p.get_string_repr().to_string()).unwrap_or_default();

        let hash = generate_hash(&txnid, &amount, "INR", &email, &phone, &auth.key.expose(), &auth.secret.expose())?;

        Ok(Self {
            txnid,
            amount,
            email,
            phone,
            key: auth.key,
            hash,
        })
    }
}

impl<T> TryFrom<&RouterDataV2<RSync, domain_types::connector_types::PaymentFlowData, RefundSyncData, RefundsResponseData>>
    for EaseBuzzRefundSyncRequest
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;

    fn try_from(item: &RouterDataV2<RSync, domain_types::connector_types::PaymentFlowData, RefundSyncData, RefundsResponseData>) -> Result<Self, Self::Error> {
        let auth = get_auth_credentials(&item.connector_auth_type)?;
        
        let easebuzz_id = item.router_data.request.connector_transaction_id.get_connector_transaction_id()?;
        let merchant_refund_id = item.router_data.request.refund_id.get_string_repr().to_string();

        let hash_string = format!("{}|{}|{}", auth.key.expose(), easebuzz_id, auth.secret.expose());
        let hash = crypto::Sha512::hash_to_hex(hash_string.as_bytes());

        Ok(Self {
            key: auth.key,
            easebuzz_id,
            hash: Secret::new(hash),
            merchant_refund_id,
        })
    }
}

#[derive(Debug, Clone)]
pub struct EaseBuzzAuth {
    pub key: Secret<String>,
    pub secret: Secret<String>,
}

pub fn get_auth_credentials(auth_type: &ConnectorAuthType) -> CustomResult<EaseBuzzAuth, domain_types::errors::ConnectorError> {
    match auth_type {
        ConnectorAuthType::SignatureKey { api_key, api_secret } => Ok(EaseBuzzAuth {
            key: api_key.clone(),
            secret: api_secret.clone(),
        }),
        ConnectorAuthType::BodyKey { api_key, key1 } => Ok(EaseBuzzAuth {
            key: api_key.clone(),
            secret: key1.clone(),
        }),
        _ => Err(domain_types::errors::ConnectorError::AuthenticationFailed.into()),
    }
}

pub fn generate_hash(
    txnid: &str,
    amount: &str,
    currency: &str,
    email: &str,
    phone: &str,
    key: &str,
    salt: &str,
) -> CustomResult<Secret<String>, domain_types::errors::ConnectorError> {
    let hash_string = format!("{}|{}|{}|{}|{}|{}|{}", key, txnid, amount, currency, email, phone, salt);
    let hash = crypto::Sha512::hash_to_hex(hash_string.as_bytes());
    Ok(Secret::new(hash))
}

pub fn get_auth_header(auth_type: &ConnectorAuthType) -> CustomResult<Vec<(String, String)>, domain_types::errors::ConnectorError> {
    let auth = get_auth_credentials(auth_type)?;
    Ok(vec![
        ("Authorization".to_string(), format!("Bearer {}", auth.key.expose())),
        ("X-Api-Key".to_string(), auth.key.expose()),
    ])
}