use std::collections::HashMap;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    crypto,
    errors::CustomResult,
    ext_traits::BytesExt,
    request::RequestContent,
    types::{self, StringMinorUnit},
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync, Refund},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundsData, RefundsResponseData, RefundSyncData, ResponseId,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

// Request/Response types for EaseBuzz

#[derive(Debug, Serialize)]
pub struct EaseBuzzPaymentsRequest {
    pub txnid: String,
    pub amount: String,
    pub productinfo: String,
    pub firstname: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub surl: String,
    pub furl: String,
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
    pub hash: String,
    pub key: Secret<String>,
    #[serde(rename = "payment_source")]
    pub payment_source: String,
    #[serde(rename = "bank_code")]
    pub bank_code: Option<String>,
    #[serde(rename = "vpa")]
    pub vpa: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzPaymentsResponse {
    pub status: i32,
    #[serde(rename = "error_desc")]
    pub error_desc: Option<String>,
    pub data: EaseBuzzPaymentData,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzPaymentData {
    pub txnid: String,
    #[serde(rename = "easebuzz_id")]
    pub easebuzz_id: String,
    pub status: String,
    pub amount: String,
    #[serde(rename = "payment_source")]
    pub payment_source: String,
    #[serde(rename = "bank_code")]
    pub bank_code: Option<String>,
    #[serde(rename = "vpa")]
    pub vpa: Option<String>,
    #[serde(rename = "card_no")]
    pub card_no: Option<String>,
    #[serde(rename = "name_on_card")]
    pub name_on_card: Option<String>,
    #[serde(rename = "card_type")]
    pub card_type: Option<String>,
    #[serde(rename = "card_token")]
    pub card_token: Option<String>,
    #[serde(rename = "net_amount_debit")]
    pub net_amount_debit: String,
    #[serde(rename = "addedon")]
    pub addedon: String,
    #[serde(rename = "productinfo")]
    pub productinfo: String,
    pub firstname: String,
    pub lastname: Option<String>,
    pub email: String,
    pub phone: String,
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub zipcode: Option<String>,
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
    #[serde(rename = "field1")]
    pub field1: Option<String>,
    #[serde(rename = "field2")]
    pub field2: Option<String>,
    #[serde(rename = "field3")]
    pub field3: Option<String>,
    #[serde(rename = "field4")]
    pub field4: Option<String>,
    #[serde(rename = "field5")]
    pub field5: Option<String>,
    #[serde(rename = "field6")]
    pub field6: Option<String>,
    #[serde(rename = "field7")]
    pub field7: Option<String>,
    #[serde(rename = "field8")]
    pub field8: Option<String>,
    #[serde(rename = "field9")]
    pub field9: Option<String>,
    #[serde(rename = "pg_type")]
    pub pg_type: String,
    #[serde(rename = "bank_ref_num")]
    pub bank_ref_num: Option<String>,
    #[serde(rename = "mode")]
    pub mode: String,
}

#[derive(Debug, Serialize)]
pub struct EaseBuzzPaymentsSyncRequest {
    pub txnid: String,
    pub amount: String,
    pub email: String,
    pub phone: String,
    pub key: Secret<String>,
    pub hash: String,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzPaymentsSyncResponse {
    pub status: bool,
    pub msg: EaseBuzzSyncMessage,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum EaseBuzzSyncMessage {
    Success(EaseBuzzPaymentData),
    Error(String),
}

#[derive(Debug, Serialize)]
pub struct EaseBuzzRefundRequest {
    pub txnid: String,
    pub amount: String,
    pub refund_amount: String,
    pub refund_note: Option<String>,
    pub key: Secret<String>,
    pub hash: String,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundResponse {
    pub status: bool,
    pub reason: Option<String>,
    #[serde(rename = "easebuzz_id")]
    pub easebuzz_id: Option<String>,
    #[serde(rename = "refund_id")]
    pub refund_id: Option<String>,
    #[serde(rename = "refund_amount")]
    pub refund_amount: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EaseBuzzRefundSyncRequest {
    pub key: Secret<String>,
    #[serde(rename = "easebuzz_id")]
    pub easebuzz_id: String,
    pub hash: String,
    #[serde(rename = "merchant_refund_id")]
    pub merchant_refund_id: String,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundSyncResponse {
    pub code: i32,
    pub status: String,
    pub response: EaseBuzzRefundSyncData,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum EaseBuzzRefundSyncData {
    Success(EaseBuzzRefundSyncSuccess),
    Failure(EaseBuzzRefundSyncFailure),
    Validation(EaseBuzzRefundSyncValidation),
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundSyncSuccess {
    pub txnid: String,
    #[serde(rename = "easebuzz_id")]
    pub easebuzz_id: String,
    #[serde(rename = "net_amount_debit")]
    pub net_amount_debit: String,
    pub amount: String,
    pub refunds: Option<Vec<EaseBuzzRefundSyncType>>,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundSyncType {
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
pub struct EaseBuzzRefundSyncFailure {
    pub status: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct EaseBuzzRefundSyncValidation {
    #[serde(rename = "validation_errors")]
    pub validation_errors: Option<serde_json::Value>,
    pub status: bool,
    #[serde(rename = "error_code")]
    pub error_code: Option<String>,
    #[serde(rename = "error_desc")]
    pub error_desc: Option<String>,
}

// Helper functions for hash generation
fn generate_hash(
    key: &str,
    txnid: &str,
    amount: &str,
    productinfo: &str,
    firstname: &str,
    email: &str,
    salt: &str,
) -> String {
    let hash_string = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        key, txnid, amount, productinfo, firstname, email, salt
    );
    crypto::Sha512::generate_hash(&hash_string)
}

fn generate_refund_hash(
    key: &str,
    txnid: &str,
    amount: &str,
    refund_amount: &str,
    salt: &str,
) -> String {
    let hash_string = format!(
        "{}|{}|{}|{}|{}",
        key, txnid, amount, refund_amount, salt
    );
    crypto::Sha512::generate_hash(&hash_string)
}

fn generate_sync_hash(
    key: &str,
    txnid: &str,
    amount: &str,
    email: &str,
    phone: &str,
    salt: &str,
) -> String {
    let hash_string = format!(
        "{}|{}|{}|{}|{}|{}",
        key, txnid, amount, email, phone, salt
    );
    crypto::Sha512::generate_hash(&hash_string)
}

// Define router data type alias
pub type EaseBuzzRouterData<T> = crate::types::ResponseRouterData<EaseBuzzPaymentsRequest, T>;

// Implement TryFrom for request types
impl<T> TryFrom<EaseBuzzRouterData<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for EaseBuzzPaymentsRequest
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: EaseBuzzRouterData<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let auth = get_auth_credentials(&item.router_data.connector_auth_type)?;
        let key = auth.key.expose();
        let salt = auth.salt.expose();

        let txnid = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();
        
        let amount = item.amount.get_amount_as_string();
        let productinfo = item
            .router_data
            .request
            .description
            .clone()
            .unwrap_or_else(|| "Payment".to_string());
        
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let firstname = customer_id.get_string_repr();
        
        let email = item.router_data.request.email.clone();
        let phone = item.router_data.request.phone.as_ref().map(|p| p.to_string());

        let return_url = item.router_data.request.get_router_return_url()?;
        let surl = return_url.clone();
        let furl = return_url;

        let hash = generate_hash(
            &key,
            &txnid,
            &amount,
            &productinfo,
            &firstname,
            &email.as_ref().map(|e| e.to_string()).unwrap_or_else(|| "".to_string()).as_str(),
            &salt,
        );

        let (payment_source, bank_code, vpa) = match item.router_data.request.payment_method_type {
            PaymentMethodType::Upi => {
                if let Some(upi_data) = &item.router_data.request.payment_method_data.upi {
                    (
                        "upi".to_string(),
                        None,
                        Some(upi_data.upi_id.to_string()),
                    )
                } else {
                    ("upi".to_string(), None, None)
                }
            }
            _ => return Err(errors::ConnectorError::NotImplemented("Payment method not supported".to_string()).into()),
        };

        Ok(Self {
            txnid,
            amount,
            productinfo,
            firstname,
            email: email.map(|e| e.to_string()),
            phone,
            surl,
            furl,
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
            hash,
            key: Secret::new(key),
            payment_source,
            bank_code,
            vpa,
        })
    }
}

impl TryFrom<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for EaseBuzzPaymentsSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = get_auth_credentials(&item.connector_auth_type)?;
        let key = auth.key.expose();
        let salt = auth.salt.expose();

        let txnid = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();
        
        let amount = item.amount.get_amount_as_string();
        let email = item.router_data.request.email.as_deref().unwrap_or("").to_string();
        let phone = item.router_data.request.phone.as_deref().unwrap_or("").to_string();

        let hash = generate_sync_hash(&key, &txnid, &amount, &email, &phone, &salt);

        Ok(Self {
            txnid,
            amount,
            email,
            phone,
            key: Secret::new(key),
            hash,
        })
    }
}

impl TryFrom<&RouterDataV2<Refund, PaymentFlowData, RefundFlowData, RefundsResponseData>>
    for EaseBuzzRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Refund, PaymentFlowData, RefundFlowData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = get_auth_credentials(&item.connector_auth_type)?;
        let key = auth.key.expose();
        let salt = auth.salt.expose();

        let txnid = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();
        
        let amount = item.amount.get_amount_as_string();
        let refund_amount = item.amount.get_amount_as_string();
        let refund_note = item.router_data.request.reason.clone();

        let hash = generate_refund_hash(&key, &txnid, &amount, &refund_amount, &salt);

        Ok(Self {
            txnid,
            amount,
            refund_amount,
            refund_note,
            key: Secret::new(key),
            hash,
        })
    }
}

impl TryFrom<&RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>>
    for EaseBuzzRefundSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = get_auth_credentials(&item.connector_auth_type)?;
        let key = auth.key.expose();
        let salt = auth.salt.expose();

        let easebuzz_id = item
            .router_data
            .resource_common_data
            .connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;
        
        let merchant_refund_id = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        let hash_string = format!("{}|{}|{}", key, easebuzz_id, salt);
        let hash = crypto::Sha512::generate_hash(&hash_string);

        Ok(Self {
            key: Secret::new(key),
            easebuzz_id,
            hash,
            merchant_refund_id,
        })
    }
}

// Implement TryFrom for response types
impl TryFrom<EaseBuzzPaymentsResponse> for PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: EaseBuzzPaymentsResponse) -> Result<Self, Self::Error> {
        let status = match response.status {
            1 => AttemptStatus::Charged,
            0 => AttemptStatus::Failure,
            _ => AttemptStatus::Pending,
        };

        Ok(Self {
            status,
            connector_transaction_id: Some(ResponseId::ConnectorTransactionId(response.data.easebuzz_id)),
            amount_received: Some(types::MinorUnit::from_major_unit_as_i64(
                response.data.amount.parse().unwrap_or(0.0),
            )),
            error_message: response.error_desc,
            ..Default::default()
        })
    }
}

impl TryFrom<EaseBuzzPaymentsSyncResponse> for PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: EaseBuzzPaymentsSyncResponse) -> Result<Self, Self::Error> {
        if !response.status {
            return Err(errors::ConnectorError::RequestEncodingFailed.into());
        }

        match response.msg {
            EaseBuzzSyncMessage::Success(data) => {
                let status = match data.status.as_str() {
                    "success" => AttemptStatus::Charged,
                    "failure" => AttemptStatus::Failure,
                    "pending" => AttemptStatus::Pending,
                    _ => AttemptStatus::Pending,
                };

                Ok(Self {
                    status,
                    connector_transaction_id: Some(ResponseId::ConnectorTransactionId(data.easebuzz_id)),
                    amount_received: Some(types::MinorUnit::from_major_unit_as_i64(
                        data.amount.parse().unwrap_or(0.0),
                    )),
                    ..Default::default()
                })
            }
            EaseBuzzSyncMessage::Error(error) => Err(errors::ConnectorError::RequestEncodingFailed
                .attach_printable_lazy(|| format!("Sync error: {}", error))),
        }
    }
}

impl TryFrom<EaseBuzzRefundResponse> for RefundsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: EaseBuzzRefundResponse) -> Result<Self, Self::Error> {
        let status = if response.status {
            AttemptStatus::Charged
        } else {
            AttemptStatus::Failure
        };

        Ok(Self {
            status,
            connector_refund_id: response.refund_id.map(ResponseId::ConnectorRefundId),
            refund_amount_received: response.refund_amount.and_then(|amt| {
                amt.parse::<f64>()
                    .ok()
                    .map(|f| types::MinorUnit::from_major_unit_as_i64(f))
            }),
            error_message: response.reason,
            ..Default::default()
        })
    }
}

impl TryFrom<EaseBuzzRefundSyncResponse> for RefundsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: EaseBuzzRefundSyncResponse) -> Result<Self, Self::Error> {
        match response.response {
            EaseBuzzRefundSyncData::Success(data) => {
                let status = if let Some(refunds) = data.refunds {
                    if refunds.is_empty() {
                        AttemptStatus::Pending
                    } else {
                        match refunds[0].refund_status.as_str() {
                            "success" => AttemptStatus::Charged,
                            "failure" => AttemptStatus::Failure,
                            "pending" => AttemptStatus::Pending,
                            _ => AttemptStatus::Pending,
                        }
                    }
                } else {
                    AttemptStatus::Pending
                };

                Ok(Self {
                    status,
                    connector_refund_id: data
                        .refunds
                        .and_then(|r| r.first().map(|refund| ResponseId::ConnectorRefundId(refund.refund_id.clone()))),
                    refund_amount_received: data
                        .refunds
                        .and_then(|r| r.first().and_then(|refund| {
                            refund.refund_amount.parse::<f64>().ok().map(|f| {
                                types::MinorUnit::from_major_unit_as_i64(f)
                            })
                        })),
                    ..Default::default()
                })
            }
            EaseBuzzRefundSyncData::Failure(failure) => Err(errors::ConnectorError::RequestEncodingFailed
                .attach_printable_lazy(|| format!("Refund sync failure: {}", failure.message))),
            EaseBuzzRefundSyncData::Validation(validation) => Err(errors::ConnectorError::RequestEncodingFailed
                .attach_printable_lazy(|| format!("Refund sync validation error: {:?}", validation.error_desc))),
        }
    }
}

// Auth credentials structure
#[derive(Debug)]
pub struct EaseBuzzAuthCredentials {
    pub key: Secret<String>,
    pub salt: Secret<String>,
}

fn get_auth_credentials(auth_type: &ConnectorAuthType) -> CustomResult<EaseBuzzAuthCredentials, errors::ConnectorError> {
    match auth_type {
        ConnectorAuthType::SignatureKey { api_key, key1 } => Ok(EaseBuzzAuthCredentials {
            key: api_key.clone(),
            salt: key1.clone(),
        }),
        _ => Err(errors::ConnectorError::MissingRequiredField {
            field_name: "auth_type",
        }
        .into()),
    }
}