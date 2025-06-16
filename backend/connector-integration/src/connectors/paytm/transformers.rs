//! Paytm transformers for converting between domain types and Paytm API types
//!
//! This module contains all the request and response structures for Paytm's UPI APIs,
//! as well as the transformation logic to convert between our domain types and Paytm's expected formats.

use base64::Engine;
use cbc::{
    cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit},
    Encryptor,
};
use common_enums::Currency;
use common_utils::types::MinorUnit;
use common_utils::{errors::CustomResult, request::RequestContent};
use domain_types::{
    connector_flow::{Authorize, CreateSessionToken},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, SessionTokenRequestData,
        SessionTokenResponseData,
    },
};
use hyperswitch_domain_models::payment_method_data::{PaymentMethodData, UpiData};
use hyperswitch_domain_models::{router_data::ConnectorAuthType, router_data_v2::RouterDataV2};
use hyperswitch_interfaces::errors;
use masking::{PeekInterface, Secret};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// ============ CreateSessionToken (InitiateTransaction) Types ============

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytmInitiateTransactionRequest {
    pub head: PaytmRequestHead,
    pub body: PaytmInitiateTransactionBody,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytmRequestHead {
    pub client_id: Option<String>,
    pub version: String,
    pub request_timestamp: String,
    pub channel_id: String,
    pub signature: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PaytmInitiateTransactionBody {
    pub request_type: String,
    pub mid: String,
    pub order_id: String,
    pub website_name: String,
    pub txn_amount: PaytmAmount,
    pub user_info: PaytmUserInfo,
    pub enable_payment_mode: Vec<PaytmPaymentMode>,
    pub disabled_payment_mode: Option<String>,
    pub callback_url: String,
    pub extend_info: Option<PaytmExtendInfo>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PaytmAmount {
    pub value: MinorUnit,
    pub currency: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PaytmUserInfo {
    pub cust_id: String,
    pub mobile: Option<String>,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub middle_name: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PaytmPaymentMode {
    pub mode: String,
    pub channels: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PaytmExtendInfo {
    pub udf1: Option<String>,
    pub udf2: Option<String>,
    pub udf3: Option<String>,
    pub currency: String,
    pub return_url: Option<String>,
    pub merc_unq_ref: Option<String>,
}

// ============ Response Types ============

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytmInitiateTransactionResponse {
    pub head: PaytmResponseHead,
    pub body: PaytmInitiateTransactionResponseBody,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytmResponseHead {
    pub client_id: Option<String>,
    pub version: Option<String>,
    pub response_timestamp: Option<String>,
    pub channel_id: Option<String>,
    pub signature: Option<String>,
    pub request_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytmInitiateTransactionResponseBody {
    pub txn_token: Option<String>,
    #[serde(rename = "isPromoCodeValid")]
    pub is_promo_code_valid: Option<bool>,
    pub authenticated: Option<bool>,
    pub result_info: PaytmResultInfo,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytmResultInfo {
    pub result_status: String,
    pub result_code: String,
    pub result_msg: String,
}

// ============ ProcessTransaction (Authorize) Types ============

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytmProcessTransactionRequest {
    pub head: PaytmProcessRequestHead,
    pub body: PaytmProcessTransactionBody,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytmProcessRequestHead {
    pub version: String,
    pub request_timestamp: String,
    pub channel_id: String,
    pub txn_token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytmProcessTransactionBody {
    pub request_type: String,
    pub mid: String,
    pub order_id: String,

    pub payment_mode: String,
    pub payer_account: Option<String>,
    pub channel_code: Option<String>,
    pub channel_id: Option<String>,
    pub extend_info: Option<PaytmExtendInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytmProcessTransactionResponse {
    pub head: PaytmResponseHead,
    pub body: PaytmProcessTransactionResponseBody,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytmProcessTransactionResponseBody {
    pub result_info: PaytmResultInfo,
    pub bank_form: Option<PaytmBankForm>,
    pub risk_content: Option<PaytmRiskContent>,
    pub txn_info: Option<PaytmTxnInfo>,
    pub call_back_url: Option<String>,
    pub extra_params_map: Option<serde_json::Value>,
    pub deep_link_info: Option<PaytmDeepLinkInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytmBankForm {
    pub page_type: String,
    pub is_force_resend_otp: bool,
    pub redirect_form: Option<PaytmRedirectForm>,
    pub upi_direct_form: Option<PaytmUpiDirectForm>,
    pub display_field: Option<PaytmDisplayField>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytmRedirectForm {
    pub action_url: String,
    pub method: String,
    #[serde(rename = "type")]
    pub form_type: String,
    pub headers: HashMap<String, String>,
    pub content: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytmUpiDirectForm {
    pub action_url: String,
    pub method: String,
    #[serde(rename = "type")]
    pub form_type: String,
    pub headers: HashMap<String, String>,
    pub content: PaytmUpiDirectContent,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytmUpiDirectContent {
    pub order_id: String,
    pub mid: String,
    pub token_type: String,
    pub version: String,
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytmDisplayField {
    pub status_timeout: String,
    pub status_interval: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytmRiskContent {
    pub event_link_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytmDeepLinkInfo {
    pub deep_link: String,
    pub order_id: String,
    pub cashier_request_id: String,
    pub trans_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub struct PaytmTxnInfo {
    #[serde(rename = "BANKTXNID")]
    pub bank_txn_id: String,
    #[serde(rename = "CHECKSUMHASH")]
    pub checksum_hash: String,
    #[serde(rename = "CURRENCY")]
    pub currency: String,
    #[serde(rename = "GATEWAYNAME")]
    pub gateway_name: String,
    #[serde(rename = "MERC_UNQ_REF")]
    pub merc_unq_ref: String,
    #[serde(rename = "MID")]
    pub mid: String,
    #[serde(rename = "ORDERID")]
    pub order_id: String,
    #[serde(rename = "PAYMENTMODE")]
    pub payment_mode: String,
    #[serde(rename = "RESPCODE")]
    pub resp_code: String,
    #[serde(rename = "RESPMSG")]
    pub resp_msg: String,
    #[serde(rename = "STATUS")]
    pub status: String,
    #[serde(rename = "TXNAMOUNT")]
    pub txn_amount: String,
    #[serde(rename = "TXNDATE")]
    pub txn_date: String,
    #[serde(rename = "TXNID")]
    pub txn_id: String,
}

// ============ Error Types ============

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytmErrorResponse {
    pub head: PaytmResponseHead,
    pub body: PaytmErrorBody,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytmErrorBody {
    pub result_info: PaytmResultInfo,
    pub extra_params_map: Option<serde_json::Value>,
}

// ============ Utility Functions ============

impl PaytmAmount {
    pub fn new(amount: MinorUnit, currency: &str) -> Self {
        Self {
            value: amount,
            currency: currency.to_string(),
        }
    }
}

impl PaytmUserInfo {
    pub fn new(
        cust_id: String,
        mobile: Option<String>,
        email: Option<String>,
        first_name: Option<String>,
        last_name: Option<String>,
    ) -> Self {
        Self {
            cust_id,
            mobile,
            email,
            first_name,
            last_name,
            middle_name: None,
        }
    }
}

impl PaytmPaymentMode {
    pub fn upi() -> Self {
        Self {
            mode: "UPI".to_string(),
            channels: vec!["UPIPUSH".to_string(), "UPI".to_string()],
        }
    }
}

impl PaytmExtendInfo {
    pub fn new(
        currency: String,
        udf1: Option<String>,
        return_url: Option<String>,
        merc_unq_ref: Option<String>,
    ) -> Self {
        Self {
            udf1,
            udf2: None,
            udf3: None,
            currency,
            return_url,
            merc_unq_ref,
        }
    }
}

// ============ Authentication Types ============

#[derive(Debug)]
pub struct PaytmAuthType {
    pub merchant_id: Secret<String>,
    pub key: Secret<String>,
    pub website: String,
}

impl TryFrom<&ConnectorAuthType> for PaytmAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self {
                merchant_id: api_key.to_owned(),
                key: key1.to_owned(),
                website: api_secret.peek().to_string(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// ============ Router Data Wrapper ============

pub struct PaytmRouterData<T> {
    pub amount: MinorUnit,
    pub currency: Currency,
    pub merchant_id: String,
    pub website: String,
    pub key: String,
    pub order_id: String,
    pub customer_id: String,
    pub customer_mobile: Option<String>,
    pub customer_email: Option<String>,
    pub customer_name: Option<String>,
    pub callback_url: String,
    pub session_token: Option<String>,
    pub item: T,
}

impl
    TryFrom<
        &RouterDataV2<
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
    > for PaytmRouterData<SessionTokenRequestData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<
            CreateSessionToken,
            PaymentFlowData,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = PaytmAuthType::try_from(&item.connector_auth_type)?;

        // Extract customer information from payment flow data
        let customer_name = None; // PaymentAddress doesn't have first_name/last_name fields

        Ok(Self {
            amount: item.request.amount,
            currency: item.request.currency,
            merchant_id: auth.merchant_id.peek().to_string(),
            website: auth.website,
            key: auth.key.peek().to_string(),
            order_id: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            customer_id: generate_customer_id(
                &item.resource_common_data.connector_request_reference_id,
            ),
            customer_mobile: None, // PaymentAddress doesn't have phone_number field
            customer_email: None,  // PaymentAddress doesn't have email field
            customer_name,
            session_token: item.session_token.clone(),
            callback_url: "https://securegw.paytm.in/theia/paytmCallback".to_string(), // Default callback
            item: item.request.clone(),
        })
    }
}

impl TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>>
    for PaytmRouterData<PaymentsAuthorizeData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = PaytmAuthType::try_from(&item.connector_auth_type)?;

        Ok(Self {
            amount: MinorUnit::new(item.request.amount),
            currency: item.request.currency,
            merchant_id: auth.merchant_id.peek().to_string(),
            website: auth.website,
            key: auth.key.peek().to_string(),
            order_id: item
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            customer_id: generate_customer_id(
                &item.resource_common_data.connector_request_reference_id,
            ),
            customer_mobile: None,
            customer_email: None,
            customer_name: None,
            session_token: item.session_token.clone(),
            callback_url: "https://securegw.paytm.in/theia/paytmCallback".to_string(),
            item: item.request.clone(),
        })
    }
}

// ============ Request Transformations ============

impl TryFrom<&PaytmRouterData<SessionTokenRequestData>> for PaytmInitiateTransactionRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &PaytmRouterData<SessionTokenRequestData>) -> Result<Self, Self::Error> {
        let timestamp = get_current_timestamp();
        let body = PaytmInitiateTransactionBody {
            request_type: "Payment".to_string(),
            mid: item.merchant_id.clone(),
            order_id: item.order_id.clone(),
            website_name: item.website.clone(),
            txn_amount: PaytmAmount::new(item.amount, &item.currency.to_string()),
            user_info: PaytmUserInfo::new(
                item.customer_id.clone(),
                item.customer_mobile.clone(),
                item.customer_email.clone(),
                item.customer_name.clone(),
                None,
            ),
            enable_payment_mode: vec![PaytmPaymentMode::upi()],
            disabled_payment_mode: None,
            callback_url: item.callback_url.clone(),
            extend_info: Some(PaytmExtendInfo::new(
                item.currency.to_string(),
                None,
                None,
                Some(item.order_id.clone()),
            )),
        };

        tracing::info!("Paytm InitiateTransaction Request Body {}", item.key);
        let signature =
            generate_signature(&RequestContent::Json(Box::new(body.clone())), &item.key)?;

        Ok(Self {
            head: PaytmRequestHead {
                client_id: None,
                version: "v2".to_string(),
                request_timestamp: timestamp.clone(),
                channel_id: "WEB".to_string(),
                signature: signature.to_string(), // Will be filled by get_headers
            },
            body,
        })
    }
}

impl TryFrom<&PaytmRouterData<PaymentsAuthorizeData>> for PaytmProcessTransactionRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &PaytmRouterData<PaymentsAuthorizeData>) -> Result<Self, Self::Error> {
        let timestamp = get_current_timestamp();

        // Extract session token from payment_flow_data if available
        let session_token =
            item.session_token
                .as_ref()
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "session_token",
                })?;

        // Determine payment flow and payer account based on payment method data
        let (payment_mode, payer_account) = match &item.item.payment_method_data {
            PaymentMethodData::Upi(upi_data) => {
                match upi_data {
                    UpiData::UpiIntent(_) => {
                        // For UPI Intent, payer_account is empty since user will select UPI app
                        ("UPI_INTENT".to_string(), None)
                    }
                    UpiData::UpiCollect(collect_data) => {
                        // For UPI Collect, payer_account should be the VPA/UPI ID
                        let vpa = collect_data.vpa_id.clone().unwrap_or_default();
                        ("UPI".to_string(), Some(vpa.peek().to_string()))
                    }
                    UpiData::UpiQr(_) => {
                        // For UPI QR, payer_account is empty since QR will be scanned
                        ("UPI_INTENT".to_string(), None)
                    }
                }
            }
            _ => {
                return Err(errors::ConnectorError::NotSupported {
                    message: "Payment method not supported".to_string(),
                    connector: "Paytm",
                }
                .into())
            }
        };

        Ok(Self {
            head: PaytmProcessRequestHead {
                version: "v1".to_string(),
                request_timestamp: timestamp,
                channel_id: "WEB".to_string(),
                txn_token: session_token.clone(),
            },
            body: PaytmProcessTransactionBody {
                request_type: "NATIVE".to_string(),
                mid: item.merchant_id.clone(),
                order_id: item.order_id.clone(),

                payment_mode,
                payer_account,
                channel_code: None, // Can be populated if gateway method code is available
                channel_id: Some(item.website.clone()), // Using website as channel_id
                // payment_flow,
                extend_info: Some(PaytmExtendInfo::new(
                    item.currency.to_string(),
                    None,
                    None,
                    Some(item.order_id.clone()),
                )),
            },
        })
    }
}

// ============ Response Transformations ============

pub struct ResponseRouterData<T, F, Req, Resp> {
    pub response: T,
    pub data: RouterDataV2<F, PaymentFlowData, Req, Resp>,
    pub http_code: u16,
}

impl
    TryFrom<
        ResponseRouterData<
            PaytmInitiateTransactionResponse,
            CreateSessionToken,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
    >
    for RouterDataV2<
        CreateSessionToken,
        PaymentFlowData,
        SessionTokenRequestData,
        SessionTokenResponseData,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            PaytmInitiateTransactionResponse,
            CreateSessionToken,
            SessionTokenRequestData,
            SessionTokenResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        // Check if the response indicates failure or missing token
        if item.response.body.result_info.result_status == "F"
            || item.response.body.txn_token.is_none()
        {
            return Ok(Self {
                response: Err(hyperswitch_domain_models::router_data::ErrorResponse {
                    code: item.response.body.result_info.result_code.clone(),
                    message: item.response.body.result_info.result_msg.clone(),
                    reason: Some(item.response.body.result_info.result_msg.clone()),
                    status_code: item.http_code,
                    attempt_status: Some(common_enums::AttemptStatus::Failure),
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..item.data
            });
        }

        let session_token = item.response.body.txn_token.unwrap();
        let session_token_response = SessionTokenResponseData { session_token };

        Ok(Self {
            response: Ok(session_token_response),
            ..item.data
        })
    }
}

impl
    TryFrom<
        ResponseRouterData<
            PaytmProcessTransactionResponse,
            Authorize,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            PaytmProcessTransactionResponse,
            Authorize,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        use common_enums::AttemptStatus;
        use hyperswitch_domain_models::router_response_types::RedirectForm;

        // Check if this is a failure response first
        if item.response.body.result_info.result_status == "F" {
            return Ok(Self {
                response: Err(hyperswitch_domain_models::router_data::ErrorResponse {
                    code: item.response.body.result_info.result_code.clone(),
                    message: item.response.body.result_info.result_msg.clone(),
                    reason: Some(item.response.body.result_info.result_msg.clone()),
                    status_code: item.http_code,
                    attempt_status: Some(AttemptStatus::Failure),
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                }),
                ..item.data
            });
        }

        // Determine redirection data based on payment method and response content
        let redirection_data = match &item.data.request.payment_method_data {
            PaymentMethodData::Upi(UpiData::UpiIntent(_)) => {
                // For UPI Intent, prefer deep_link from deep_link_info, fallback to bank_form
                if let Some(deep_link_info) = &item.response.body.deep_link_info {
                    Some(RedirectForm::Uri {
                        uri: deep_link_info.deep_link.clone(),
                    })
                } else if let Some(bank_form) = &item.response.body.bank_form {
                    bank_form
                        .redirect_form
                        .as_ref()
                        .map(|redirect_form| RedirectForm::Uri {
                            uri: redirect_form.action_url.clone(),
                        })
                } else {
                    None
                }
            }
            _ => {
                // For UPI Collect/QR and other methods, use bank_form if available
                item.response.body.bank_form.as_ref().and_then(|bank_form| {
                    bank_form
                        .redirect_form
                        .as_ref()
                        .map(|redirect_form| RedirectForm::Uri {
                            uri: redirect_form.action_url.clone(),
                        })
                })
            }
        };

        // Determine transaction ID and network details
        let (resource_id, network_txn_id, connector_response_reference_id, transaction_amount) =
            if let Some(deep_link_info) = &item.response.body.deep_link_info {
                (
                    deep_link_info.trans_id.clone(),
                    Some(deep_link_info.trans_id.clone()),
                    Some(deep_link_info.cashier_request_id.clone()),
                    None,
                )
            } else if let Some(txn_info) = &item.response.body.txn_info {
                (
                    txn_info.txn_id.clone(),
                    Some(txn_info.bank_txn_id.clone()),
                    Some(txn_info.order_id.clone()),
                    Some(txn_info.txn_amount.clone()),
                )
            } else {
                (
                    item.response.body.result_info.result_code.clone(),
                    None,
                    None,
                    None,
                )
            };

        // Extract additional fields from bank_form if available
        let (transaction_token, merchant_vpa) = item
            .response
            .body
            .bank_form
            .as_ref()
            .and_then(|bank_form| bank_form.redirect_form.as_ref())
            .map(|redirect_form| {
                (
                    redirect_form.content.get("txnToken").cloned(),
                    redirect_form.content.get("MERCHANT_VPA").cloned(),
                )
            })
            .unwrap_or((None, None));

        let response_data = PaymentsResponseData::TransactionResponse {
            resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(
                resource_id,
            ),
            redirection_data: Box::new(redirection_data),
            mandate_reference: Box::new(None),
            connector_metadata: None,
            network_txn_id,
            connector_response_reference_id,
            incremental_authorization_allowed: None,
            raw_connector_response: None,
            transaction_token,
            transaction_amount,
            merchant_name: None,
            merchant_vpa,
        };

        Ok(Self {
            response: Ok(response_data),
            ..item.data
        })
    }
}

// ============ Utility Functions ============

pub fn get_current_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Format: epoch timestamp in seconds
    now.to_string()
}

pub fn generate_customer_id(order_id: &str) -> String {
    format!("CUST_{}", order_id)
}

pub fn generate_signature(
    request_body: &RequestContent,
    key: &str,
) -> CustomResult<String, errors::ConnectorError> {
    // Convert the request body to JSON string
    let params = match request_body {
        RequestContent::Json(body) => serde_json::to_string(body)
            .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?,
        _ => return Err(errors::ConnectorError::RequestEncodingFailed.into()),
    };

    generate_signature_by_string(&params, key)
}

/// Generate signature for Paytm authentication
/// Equivalent to Python's generateSignature function
fn generate_signature_by_string(
    params: &str,
    key: &str,
) -> CustomResult<String, errors::ConnectorError> {
    let salt = generate_random_string(4);
    calculate_checksum(params, key, &salt)
}

/// Calculate checksum by creating hash and encrypting it
/// Equivalent to Python's calculateChecksum function
fn calculate_checksum(
    params: &str,
    key: &str,
    salt: &str,
) -> CustomResult<String, errors::ConnectorError> {
    let hash_string = calculate_hash(params, salt);
    encrypt(&hash_string, key)
}

/// Calculate SHA-256 hash with salt
/// Equivalent to Python's calculateHash function
fn calculate_hash(params: &str, salt: &str) -> String {
    let final_string = format!("{}|{}", params, salt);
    let mut hasher = Sha256::new();
    hasher.update(final_string.as_bytes());
    let hash_bytes = hasher.finalize();
    let hash_string = hex::encode(hash_bytes);
    format!("{}{}", hash_string, salt)
}

/// Generate random alphanumeric string of specified length
/// Equivalent to Python's generateRandomString function
fn generate_random_string(length: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARS.len());
            CHARS[idx] as char
        })
        .collect()
}

/// AES encryption using CBC mode with PKCS7 padding
/// Equivalent to Python's encrypt function
fn encrypt(input: &str, key: &str) -> CustomResult<String, errors::ConnectorError> {
    const IV: &[u8] = b"@@@@&&&&####$$$$"; // 16 bytes IV as in Python

    // Ensure key is exactly 16 bytes for AES-128
    let mut key_bytes = [0u8; 16];
    let key_input = key.as_bytes();
    if key_input.len() >= 16 {
        key_bytes.copy_from_slice(&key_input[..16]);
    } else {
        key_bytes[..key_input.len()].copy_from_slice(key_input);
    }

    // Prepare buffer for encryption (need to allocate enough space for padding)
    let input_bytes = input.as_bytes();
    let mut buffer = vec![0u8; input_bytes.len() + 16]; // Extra space for padding
    buffer[..input_bytes.len()].copy_from_slice(input_bytes);

    // Create AES cipher in CBC mode
    type Aes128CbcEnc = Encryptor<aes::Aes128>;
    let encryptor = Aes128CbcEnc::new(&key_bytes.into(), IV.into());

    // Encrypt the data with PKCS7 padding
    let encrypted_data = encryptor
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, input_bytes.len())
        .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;

    // Encode to base64
    let encoded = base64::engine::general_purpose::STANDARD.encode(encrypted_data);
    Ok(encoded)
}
