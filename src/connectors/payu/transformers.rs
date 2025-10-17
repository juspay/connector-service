use std::collections::HashMap;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    crypto::Sha512,
    errors::CustomResult,
    ext_traits::BytesExt,
    request::RequestContent,
    types::{self, StringMinorUnit},
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
        RefundSyncData, RefundsResponseData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    types as domain_types,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use masking::{ExposeInterface, Mask};
use serde::{Deserialize, Serialize};

use crate::utils;

#[derive(Debug, Clone)]
pub enum PayuAuthType {
    KeySecret { key: Secret<String>, salt: Secret<String> },
}

impl PayuAuthType {
    pub fn get_auth_header(&self) -> String {
        match self {
            PayuAuthType::KeySecret { key, .. } => key.expose().clone(),
        }
    }

    pub fn generate_hash(&self, data: &str) -> String {
        match self {
            PayuAuthType::KeySecret { salt, .. } => {
                let hash_input = format!("{}|{}", data, salt.expose());
                Sha512::sign_with_key(hash_input.as_bytes(), salt.expose().as_bytes())
            }
        }
    }
}

impl TryFrom<&domain_types::ConnectorAuthType> for PayuAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &domain_types::ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            domain_types::ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                key2,
            } => Ok(PayuAuthType::KeySecret {
                key: api_key.clone(),
                salt: key1
                    .clone()
                    .ok_or(errors::ConnectorError::MissingRequiredField {
                        field: "salt",
                    })?,
            }),
            _ => Err(errors::ConnectorError::AuthenticationFailed.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PayuPaymentsRequest {
    pub key: String,
    pub command: String,
    pub hash: String,
    pub var1: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub var2: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub var3: Option<String>,
}

impl<T: PaymentMethodDataTypes> TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for PayuPaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = PayuAuthType::try_from(&item.connector_auth_type)?;
        let key = match &auth {
            PayuAuthType::KeySecret { key, .. } => key.expose().clone(),
        };

        let amount = item.amount.get_amount_as_string();
        let currency = item.router_data.request.currency.to_string();
        let transaction_id = item
            .router_data
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        let product_info = item
            .router_data
            .request
            .description
            .clone()
            .unwrap_or_else(|| "Payment".to_string());

        let customer_id = item
            .router_data
            .resource_common_data
            .get_customer_id()?
            .get_string_repr();

        let email = item
            .router_data
            .request
            .email
            .clone()
            .unwrap_or_else(|| "customer@example.com".to_string());

        let phone = item
            .router_data
            .request
            .phone
            .clone()
            .map(|p| p.get_string_repr())
            .unwrap_or_else(|| "9999999999".to_string());

        let surl = item
            .router_data
            .request
            .get_router_return_url()?
            .unwrap_or_else(|| "https://example.com/success".to_string());

        let furl = item
            .router_data
            .request
            .get_router_return_url()?
            .unwrap_or_else(|| "https://example.com/failure".to_string());

        // For UPI payments
        let payment_method = match item.router_data.request.payment_method_type {
            PaymentMethodType::UpiCollect => {
                let vpa = item
                    .router_data
                    .request
                    .payment_method_data
                    .get_upi_vpa()
                    .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;
                format!("UPI|{}", vpa)
            }
            PaymentMethodType::UpiIntent => "UPI_INTENT".to_string(),
            _ => "NB".to_string(),
        };

        let hash_string = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            key,
            transaction_id,
            amount,
            product_info,
            customer_id,
            customer_id,
            email,
            phone,
            surl,
            furl,
            "UDF1",
            "UDF2",
            "UDF3",
            "UDF4"
        );

        let hash = auth.generate_hash(&hash_string);

        let var1 = serde_json::json!({
            "txnid": transaction_id,
            "amount": amount,
            "productinfo": product_info,
            "firstname": customer_id,
            "email": email,
            "phone": phone,
            "surl": surl,
            "furl": furl,
            "udf1": "UDF1",
            "udf2": "UDF2",
            "udf3": "UDF3",
            "udf4": "UDF4",
            "pg": payment_method
        })
        .to_string();

        Ok(Self {
            key,
            command: "create_transaction".to_string(),
            hash,
            var1,
            var2: None,
            var3: None,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "status")]
pub enum PayuPaymentsResponse {
    #[serde(rename = "success")]
    Success(PayuSuccessResponse),
    #[serde(rename = "failure")]
    Failure(PayuFailureResponse),
    #[serde(rename = "pending")]
    Pending(PayuPendingResponse),
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayuSuccessResponse {
    pub mihpayid: String,
    pub txnid: String,
    pub amount: String,
    pub status: String,
    pub bank_ref_num: Option<String>,
    pub mode: String,
    pub card_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayuFailureResponse {
    pub mihpayid: Option<String>,
    pub txnid: String,
    pub error_code: String,
    pub error_message: String,
    pub status: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayuPendingResponse {
    pub mihpayid: String,
    pub txnid: String,
    pub amount: String,
    pub status: String,
    pub mode: String,
}

impl TryFrom<PayuPaymentsResponse> for PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: PayuPaymentsResponse) -> Result<Self, Self::Error> {
        match response {
            PayuPaymentsResponse::Success(success) => Ok(Self {
                status: AttemptStatus::Charged,
                gateway_transaction_id: Some(success.mihpayid),
                connector_transaction_id: Some(success.txnid),
                amount_received: Some(types::MinorUnit::from_major_unit_as_i64(
                    success.amount.parse::<f64>().map_err(|_| {
                        errors::ConnectorError::ResponseDeserializationFailed
                    })?,
                )),
                capture_method: Some(common_enums::CaptureMethod::Automatic),
                error_message: None,
                error_code: None,
                redirection_data: None,
                network_transaction_id: success.bank_ref_num,
                connector_response: Some(serde_json::to_value(success)?),
                additional_payment_method_data: None,
            }),
            PayuPaymentsResponse::Failure(failure) => Ok(Self {
                status: AttemptStatus::Failure,
                gateway_transaction_id: failure.mihpayid,
                connector_transaction_id: Some(failure.txnid),
                amount_received: None,
                capture_method: None,
                error_message: Some(failure.error_message),
                error_code: Some(failure.error_code),
                redirection_data: None,
                network_transaction_id: None,
                connector_response: Some(serde_json::to_value(failure)?),
                additional_payment_method_data: None,
            }),
            PayuPaymentsResponse::Pending(pending) => Ok(Self {
                status: AttemptStatus::Pending,
                gateway_transaction_id: Some(pending.mihpayid),
                connector_transaction_id: Some(pending.txnid),
                amount_received: None,
                capture_method: None,
                error_message: None,
                error_code: None,
                redirection_data: None,
                network_transaction_id: None,
                connector_response: Some(serde_json::to_value(pending)?),
                additional_payment_method_data: None,
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PayuPaymentsSyncRequest {
    pub key: String,
    pub command: String,
    pub hash: String,
    pub var1: String,
}

impl TryFrom<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for PayuPaymentsSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = PayuAuthType::try_from(&item.connector_auth_type)?;
        let key = match &auth {
            PayuAuthType::KeySecret { key, .. } => key.expose().clone(),
        };

        let transaction_id = item
            .router_data
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        let hash_string = format!("{}|{}|{}", key, "verify_payment", transaction_id);
        let hash = auth.generate_hash(&hash_string);

        Ok(Self {
            key,
            command: "verify_payment".to_string(),
            hash,
            var1: transaction_id,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayuPaymentsSyncResponse {
    pub status: String,
    pub txn_details: Option<PayuTransactionDetails>,
    pub msg: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayuTransactionDetails {
    pub mihpayid: String,
    pub txnid: String,
    pub amount: String,
    pub status: String,
    pub mode: String,
    pub bank_ref_num: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

impl TryFrom<PayuPaymentsSyncResponse> for PaymentsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: PayuPaymentsSyncResponse) -> Result<Self, Self::Error> {
        let status = match response.status.as_str() {
            "success" => AttemptStatus::Charged,
            "failure" => AttemptStatus::Failure,
            "pending" => AttemptStatus::Pending,
            _ => AttemptStatus::AuthenticationPending,
        };

        let (gateway_transaction_id, connector_transaction_id, amount_received, error_message, error_code, network_transaction_id) =
            if let Some(txn_details) = response.txn_details {
                (
                    Some(txn_details.mihpayid),
                    Some(txn_details.txnid),
                    Some(types::MinorUnit::from_major_unit_as_i64(
                        txn_details.amount.parse::<f64>().map_err(|_| {
                            errors::ConnectorError::ResponseDeserializationFailed
                        })?,
                    )),
                    txn_details.error_message,
                    txn_details.error_code,
                    txn_details.bank_ref_num,
                )
            } else {
                (None, None, None, response.msg, None, None)
            };

        Ok(Self {
            status,
            gateway_transaction_id,
            connector_transaction_id,
            amount_received,
            capture_method: Some(common_enums::CaptureMethod::Automatic),
            error_message,
            error_code,
            redirection_data: None,
            network_transaction_id,
            connector_response: Some(serde_json::to_value(response)?),
            additional_payment_method_data: None,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PayuRefundSyncRequest {
    pub key: String,
    pub command: String,
    pub hash: String,
    pub var1: String,
}

impl TryFrom<&RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>>
    for PayuRefundSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = PayuAuthType::try_from(&item.connector_auth_type)?;
        let key = match &auth {
            PayuAuthType::KeySecret { key, .. } => key.expose().clone(),
        };

        let transaction_id = item
            .router_data
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        let hash_string = format!("{}|{}|{}", key, "get_all_refunds_from_txn_id", transaction_id);
        let hash = auth.generate_hash(&hash_string);

        Ok(Self {
            key,
            command: "get_all_refunds_from_txn_id".to_string(),
            hash,
            var1: transaction_id,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayuRefundSyncResponse {
    pub status: String,
    pub msg: Option<String>,
    pub refund_details: Option<Vec<PayuRefundDetail>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayuRefundDetail {
    pub refund_id: String,
    pub txnid: String,
    pub amount: String,
    pub status: String,
    pub bank_ref_num: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

impl TryFrom<PayuRefundSyncResponse> for RefundsResponseData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(response: PayuRefundSyncResponse) -> Result<Self, Self::Error> {
        let status = match response.status.as_str() {
            "success" => common_enums::RefundStatus::Success,
            "failure" => common_enums::RefundStatus::Failure,
            "pending" => common_enums::RefundStatus::Pending,
            _ => common_enums::RefundStatus::Pending,
        };

        let (refund_id, connector_transaction_id, amount_received, error_message, error_code, network_transaction_id) =
            if let Some(refund_details) = response.refund_details {
                if let Some(refund) = refund_details.first() {
                    (
                        Some(refund.refund_id.clone()),
                        Some(refund.txnid.clone()),
                        Some(types::MinorUnit::from_major_unit_as_i64(
                            refund.amount.parse::<f64>().map_err(|_| {
                                errors::ConnectorError::ResponseDeserializationFailed
                            })?,
                        )),
                        refund.error_message.clone(),
                        refund.error_code.clone(),
                        refund.bank_ref_num.clone(),
                    )
                } else {
                    (None, None, None, response.msg, None, None)
                }
            } else {
                (None, None, None, response.msg, None, None)
            };

        Ok(Self {
            status,
            refund_id,
            connector_transaction_id,
            amount_received,
            error_message,
            error_code,
            network_transaction_id,
            connector_response: Some(serde_json::to_value(response)?),
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "status")]
pub enum PayuWebhookResponse {
    #[serde(rename = "success")]
    Success(PayuWebhookSuccess),
    #[serde(rename = "failure")]
    Failure(PayuWebhookFailure),
    #[serde(rename = "pending")]
    Pending(PayuWebhookPending),
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayuWebhookSuccess {
    pub mihpayid: String,
    pub txnid: String,
    pub amount: String,
    pub status: String,
    pub mode: String,
    pub bank_ref_num: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayuWebhookFailure {
    pub mihpayid: Option<String>,
    pub txnid: String,
    pub error_code: String,
    pub error_message: String,
    pub status: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayuWebhookPending {
    pub mihpayid: String,
    pub txnid: String,
    pub amount: String,
    pub status: String,
    pub mode: String,
}

impl PayuWebhookResponse {
    pub fn get_transaction_id(&self) -> String {
        match self {
            PayuWebhookResponse::Success(success) => success.txnid.clone(),
            PayuWebhookResponse::Failure(failure) => failure.txnid.clone(),
            PayuWebhookResponse::Pending(pending) => pending.txnid.clone(),
        }
    }

    pub fn get_event_type(&self) -> String {
        match self {
            PayuWebhookResponse::Success(_) => "payment.success".to_string(),
            PayuWebhookResponse::Failure(_) => "payment.failure".to_string(),
            PayuWebhookResponse::Pending(_) => "payment.pending".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayuErrorResponse {
    pub error_code: String,
    pub error_message: String,
    pub status: String,
}

impl PayuErrorResponse {
    pub fn get_error_response(res: utils::Response) -> CustomResult<serde_json::Value, errors::ConnectorError> {
        let response: PayuErrorResponse = res
            .response
            .parse_struct("PayuErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        serde_json::to_value(response)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)
    }
}