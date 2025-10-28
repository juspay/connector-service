use std::collections::HashMap;

use common_utils::{
    types::StringMinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::types::ResponseRouterData;

// Request/Response types based on Haskell implementation

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslTransactionRequest {
    pub get_transaction_token: TransactionMessage,
}

#[derive(Debug, Serialize)]
pub struct TransactionMessage {
    pub msg: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslTransactionResponse {
    #[serde(rename = "return")]
    pub response_data: String,
}

#[derive(Debug, Deserialize)]
pub struct TpslTxnDecodedPayload {
    #[serde(rename = "soapenv:Envelope")]
    pub envelope: TpslTxnEnvelope,
}

#[derive(Debug, Deserialize)]
pub struct TpslTxnEnvelope {
    #[serde(rename = "soapenv:Body")]
    pub body: TpslTxnBody,
}

#[derive(Debug, Deserialize)]
pub struct TpslTxnBody {
    pub get_transaction_token_response: TpslTokenResponse,
}

#[derive(Debug, Deserialize)]
pub struct TpslTokenResponse {
    #[serde(rename = "getTransactionTokenReturn")]
    pub token: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TpslRedirectResponse {
    RedirectionMessage(TpslRedirectMessage),
    DecodedMessage(TpslDecodedRedirectionResponse),
    VerificationFailed(FailureResponse),
    ValidationError(ValidationErrorResponse),
    UPISyncResponse(TpslUPISyncResponse),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslRedirectMessage {
    pub msg: String,
    pub tpsl_mrct_cd: String,
    pub tpsl_err_msg: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslDecodedRedirectionResponse {
    pub txn_status: String,
    pub txn_msg: Option<String>,
    pub txn_err_msg: String,
    pub clnt_txn_ref: String,
    pub tpsl_bank_cd: Option<String>,
    pub tpsl_txn_id: Option<String>,
    pub txn_amt: Option<String>,
    pub clnt_rqst_meta: Option<String>,
    pub tpsl_txn_time: Option<String>,
    pub tpsl_rfnd_id: Option<String>,
    pub bal_amt: Option<String>,
    pub rqst_token: Option<String>,
    pub token: Option<String>,
    pub card_id: Option<String>,
    #[serde(rename = "BankTransactionID")]
    pub bank_transaction_id: Option<String>,
    pub alias_name: Option<String>,
    pub mandate_reg_no: Option<String>,
    pub hash: Option<String>,
    #[serde(rename = "REFUND_DETAILS")]
    pub refund_details: Option<String>,
    pub tpsl_err_msg: Option<String>,
    pub vpa_name: Option<String>,
    pub auth: Option<String>,
    #[serde(rename = "MandateId")]
    pub mandate_id: Option<String>,
    #[serde(rename = "VPA")]
    pub vpa: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FailureResponse {
    pub error_message: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ValidationErrorResponse {
    pub message: String,
    pub error_code: String,
    pub response: serde_json::Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPISyncResponse {
    pub merchant_code: String,
    pub merchant_transaction_identifier: String,
    pub merchant_transaction_request_type: String,
    pub response_type: String,
    pub transaction_state: String,
    pub payment_method: UPIPaymentPayload,
    pub error: Option<serde_json::Value>,
    pub merchant_response_string: Option<serde_json::Value>,
    pub status_code: Option<String>,
    pub status_message: Option<String>,
    pub identifier: Option<String>,
    pub bank_reference_identifier: Option<String>,
    pub merchant_additional_details: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UPIPaymentPayload {
    pub token: Option<String>,
    pub instrument_alias_name: String,
    pub instrument_token: String,
    pub bank_selection_code: String,
    pub acs: AcsPayload,
    pub otp: Option<serde_json::Value>,
    pub payment_transaction: PaymentTxnPayload,
    pub authentication: Option<serde_json::Value>,
    pub error: TpslPaymentMethodErrorPayload,
    pub payment_mode: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AcsPayload {
    pub bank_acs_form_name: String,
    pub bank_acs_http_method: serde_json::Value,
    pub bank_acs_params: Option<serde_json::Value>,
    pub bank_acs_url: serde_json::Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentTxnPayload {
    pub amount: String,
    pub balance_amount: Option<String>,
    pub bank_reference_identifier: Option<String>,
    pub date_time: Option<String>,
    pub error_message: Option<String>,
    pub identifier: Option<String>,
    pub refund_identifier: String,
    pub status_code: String,
    pub status_message: String,
    pub instruction: Option<serde_json::Value>,
    pub reference: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslPaymentMethodErrorPayload {
    pub code: String,
    pub desc: String,
}

// UPI Token Request/Response
#[derive(Debug, Serialize)]
pub struct TpslUPITokenRequest {
    pub merchant: MerchantDataType,
    pub cart: UPITokenCart,
    pub transaction: UPITokenTxn,
    pub consumer: ConsumerDataType,
}

#[derive(Debug, Serialize)]
pub struct MerchantDataType {
    pub identifier: String,
}

#[derive(Debug, Serialize)]
pub struct UPITokenCart {
    pub item: Vec<UPIItem>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UPIItem {
    pub amount: String,
    pub com_amt: String,
    pub sku: String,
    pub reference: String,
    pub identifier: String,
}

#[derive(Debug, Serialize)]
pub struct UPITokenTxn {
    pub amount: String,
    #[serde(rename = "type")]
    pub txn_type: String,
    pub currency: String,
    pub identifier: String,
    pub sub_type: String,
    pub request_type: String,
}

#[derive(Debug, Serialize)]
pub struct ConsumerDataType {
    pub identifier: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslUPITokenResponse {
    pub merchant_code: String,
    pub merchant_transaction_identifier: String,
    pub merchant_transaction_request_type: String,
    pub response_type: String,
    pub payment_method: UPIPaymentPayload,
    pub error: Option<serde_json::Value>,
}

// UPI Transaction Request
#[derive(Debug, Serialize)]
pub struct TpslUPITxnRequest {
    pub merchant: MerchantPayload,
    pub cart: UPITokenCart,
    pub payment: PaymentIntentPayload,
    pub transaction: TpslTxnPayload,
    pub consumer: ConsumerIntentPayload,
    pub merchant_input_flags: TpslFlagsType,
}

#[derive(Debug, Serialize)]
pub struct MerchantPayload {
    pub webhook_endpoint_url: String,
    pub response_type: String,
    pub response_endpoint_url: String,
    pub description: String,
    pub identifier: String,
    pub webhook_type: String,
}

#[derive(Debug, Serialize)]
pub struct PaymentIntentPayload {
    pub method: MethodUPIPayload,
    pub instrument: UPIInstrumentPayload,
    pub instruction: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct MethodUPIPayload {
    pub token: String,
    #[serde(rename = "type")]
    pub method_type: String,
}

#[derive(Debug, Serialize)]
pub struct UPIInstrumentPayload {
    pub expiry: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct TpslTxnPayload {
    pub device_identifier: String,
    pub sms_sending: String,
    pub amount: String,
    pub forced_3ds_call: String,
    #[serde(rename = "type")]
    pub txn_type: String,
    pub description: String,
    pub currency: String,
    pub is_registration: String,
    pub identifier: String,
    pub date_time: String,
    pub token: String,
    pub security_token: String,
    pub sub_type: String,
    pub request_type: String,
    pub reference: String,
    pub merchant_initiated: String,
    pub tenure_id: String,
}

#[derive(Debug, Serialize)]
pub struct ConsumerIntentPayload {
    pub mobile_number: String,
    pub email_id: String,
    pub identifier: String,
    pub account_no: String,
    pub account_type: String,
    pub account_holder_name: String,
    pub vpa: String,
    pub aadhar_no: String,
}

#[derive(Debug, Serialize)]
pub struct TpslFlagsType {
    pub account_no: bool,
    pub mobile_number: bool,
    pub email_id: bool,
    pub card_details: bool,
    pub mandate_details: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslUPITxnResponse {
    pub merchant_code: String,
    pub merchant_transaction_identifier: String,
    pub merchant_transaction_request_type: String,
    pub response_type: String,
    pub transaction_state: String,
    pub merchant_additional_details: serde_json::Value,
    pub payment_method: UPIPaymentPayload,
    pub error: Option<serde_json::Value>,
    pub merchant_response_string: Option<serde_json::Value>,
    pub pdf_download_url: Option<serde_json::Value>,
}

// Sync Request
#[derive(Debug, Serialize)]
pub struct TPSLUPISyncRequest {
    pub merchant: MerchantDataType,
    pub payment: PaymentUPISyncType,
    pub transaction: TransactionUPITxnType,
    pub consumer: ConsumerDataType,
}

#[derive(Debug, Serialize)]
pub struct PaymentUPISyncType {
    pub instruction: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct TransactionUPITxnType {
    pub device_identifier: String,
    #[serde(rename = "type")]
    pub txn_type: Option<String>,
    pub sub_type: Option<String>,
    pub amount: String,
    pub currency: String,
    pub date_time: String,
    pub request_type: String,
    pub token: String,
}

// Auth types
#[derive(Debug, Deserialize)]
pub struct TpslAuthType {
    pub merchant_code: Secret<String>,
    pub merchant_key: Secret<String>,
    pub test_mode: bool,
}

impl TryFrom<&ConnectorAuthType> for TpslAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, .. } => {
                let auth_data: TpslAuthType = serde_json::from_str(api_key.peek())
                    .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
                Ok(auth_data)
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Payment request types for different flows
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum TpslPaymentsRequest {
    UPIToken(TpslUPITokenRequest),
    UPITransaction(TpslUPITxnRequest),
    Sync(TPSLUPISyncRequest),
    Transaction(TpslTransactionRequest),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TpslPaymentsResponse {
    UPIToken(TpslUPITokenResponse),
    UPITransaction(TpslUPITxnResponse),
    Sync(TpslUPISyncResponse),
    Transaction(TpslTransactionResponse),
    Redirect(TpslRedirectResponse),
    Error(TpslErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TpslErrorResponse {
    #[serde(rename = "ErrorCode")]
    pub error_code: String,
    #[serde(rename = "ErrorMessage")]
    pub error_message: String,
}

// Status mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TpslTransactionStatus {
    Success,
    Pending,
    Failure,
    AuthenticationPending,
    #[serde(other)]
    Unknown,
}

impl From<TpslTransactionStatus> for common_enums::AttemptStatus {
    fn from(item: TpslTransactionStatus) -> Self {
        match item {
            TpslTransactionStatus::Success => Self::Charged,
            TpslTransactionStatus::Pending => Self::Pending,
            TpslTransactionStatus::Failure => Self::Failure,
            TpslTransactionStatus::AuthenticationPending => Self::AuthenticationPending,
            TpslTransactionStatus::Unknown => Self::Pending,
        }
    }
}

impl From<&str> for TpslTransactionStatus {
    fn from(status: &str) -> Self {
        match status.to_uppercase().as_str() {
            "SUCCESS" | "SUCCESSFUL" => TpslTransactionStatus::Success,
            "PENDING" | "PROCESSING" => TpslTransactionStatus::Pending,
            "FAILURE" | "FAILED" => TpslTransactionStatus::Failure,
            "AUTHENTICATION_PENDING" => TpslTransactionStatus::AuthenticationPending,
            _ => TpslTransactionStatus::Unknown,
        }
    }
}

// Transformer implementations
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
> TryFrom<super::TPSLRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for TpslPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: super::TPSLRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = TpslAuthType::try_from(&item.router_data.connector_auth_type)?;
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        match item.router_data.request.payment_method_type {
            Some(common_enums::PaymentMethodType::UpiCollect) => {
                // Create UPI transaction request
                let request = TpslUPITxnRequest {
                    merchant: MerchantPayload {
                        webhook_endpoint_url: item.router_data.request.get_router_return_url()?.to_string(),
                        response_type: "URL".to_string(),
                        response_endpoint_url: item.router_data.request.get_router_return_url()?.to_string(),
                        description: item.router_data.request.statement_descriptor.clone().unwrap_or_default(),
                        identifier: auth.merchant_code.peek().to_string(),
                        webhook_type: "HTTP".to_string(),
                    },
                    cart: UPITokenCart {
                        item: vec![UPIItem {
                            amount: amount.to_string(),
                            com_amt: "0".to_string(),
                            sku: "UPI".to_string(),
                            reference: item.router_data.resource_common_data.connector_request_reference_id.clone(),
                            identifier: "UPI_ITEM".to_string(),
                        }],
                        description: Some("UPI Transaction".to_string()),
                    },
                    payment: PaymentIntentPayload {
                        method: MethodUPIPayload {
                            token: "UPI".to_string(),
                            method_type: "UPI".to_string(),
                        },
                        instrument: UPIInstrumentPayload {
                            expiry: serde_json::Value::Null,
                        },
                        instruction: serde_json::Value::Null,
                    },
                    transaction: TpslTxnPayload {
                        device_identifier: item
                            .router_data
                            .request
                            .get_ip_address_as_optional()
                            .map(|ip| ip.expose())
                            .unwrap_or_else(|| "127.0.0.1".to_string()),
                        sms_sending: "N".to_string(),
                        amount: amount.to_string(),
                        forced_3ds_call: "N".to_string(),
                        txn_type: "SALE".to_string(),
                        description: item.router_data.request.statement_descriptor.clone().unwrap_or_default(),
                        currency: item.router_data.request.currency.to_string(),
                        is_registration: "N".to_string(),
                        identifier: item.router_data.resource_common_data.connector_request_reference_id.clone(),
                        date_time: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                        .to_string(),
                        token: auth.merchant_key.peek().to_string(),
                        security_token: auth.merchant_key.peek().to_string(),
                        sub_type: "SALE".to_string(),
                        request_type: "TXN".to_string(),
                        reference: item.router_data.resource_common_data.connector_request_reference_id.clone(),
                        merchant_initiated: "N".to_string(),
                        tenure_id: "".to_string(),
                    },
                    consumer: ConsumerIntentPayload {
                        mobile_number: item.router_data.request.browser_info
                            .as_ref()
                            .and_then(|bi| bi.get_optional_billing_phone_number())
                            .and_then(|phone| phone.expose().ok())
                            .unwrap_or_default(),
                        email_id: item.router_data.request.email
                            .clone()
                            .map(|e| e.peek().to_string())
                            .unwrap_or_default(),
                        identifier: customer_id.get_string_repr().to_string(),
                        account_no: "".to_string(),
                        account_type: "".to_string(),
                        account_holder_name: item.router_data.request.customer_name.clone().unwrap_or_default(),
                        vpa: match &item.router_data.request.payment_method_data {
                            domain_types::payment_method_data::PaymentMethodData::Upi(upi_data) => {
                                upi_data.vpa.as_ref().map(|vpa| vpa.to_string()).unwrap_or_default()
                            }
                            _ => String::default(),
                        },
                        aadhar_no: "".to_string(),
                    },
                    merchant_input_flags: TpslFlagsType {
                        account_no: false,
                        mobile_number: true,
                        email_id: true,
                        card_details: false,
                        mandate_details: false,
                    },
                };
                Ok(TpslPaymentsRequest::UPITransaction(request))
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                "Payment method not supported".to_string(),
            )
            .into()),
        }
    }
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
> TryFrom<super::TPSLRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for TpslPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: super::TPSLRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = TpslAuthType::try_from(&item.router_data.connector_auth_type)?;
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let request = TPSLUPISyncRequest {
            merchant: MerchantDataType {
                identifier: auth.merchant_code.peek().to_string(),
            },
            payment: PaymentUPISyncType {
                instruction: serde_json::Value::Null,
            },
            transaction: TransactionUPITxnType {
                device_identifier: item
                    .router_data
                    .request
                    .get_optional_billing_phone_number()
                    .and_then(|phone| phone.expose().ok())
                    .unwrap_or_else(|| "127.0.0.1".to_string()),
                txn_type: Some("SALE".to_string()),
                sub_type: Some("SALE".to_string()),
                amount: amount.to_string(),
                currency: item.router_data.request.currency.to_string(),
                date_time: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                        .to_string(),
                request_type: "STATUS".to_string(),
                token: auth.merchant_key.peek().to_string(),
            },
            consumer: ConsumerDataType {
                identifier: item.router_data.resource_common_data.get_customer_id()?.get_string_repr().to_string(),
            },
        };

        Ok(TpslPaymentsRequest::Sync(request))
    }
}

// Response transformers
impl<
    F,
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize
        + serde::de::DeserializeOwned,
> TryFrom<ResponseRouterData<TpslPaymentsResponse, RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TpslPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            TpslPaymentsResponse::UPITransaction(upi_response) => {
                let status = TpslTransactionStatus::from(upi_response.transaction_state.as_str());
                let attempt_status = status.into();

                let redirection_data = if attempt_status == common_enums::AttemptStatus::AuthenticationPending {
                    Some(Box::new(RedirectForm::Form {
                        endpoint: upi_response
                            .merchant_additional_details
                            .get("redirectUrl")
                            .and_then(|url| url.as_str())
                            .unwrap_or("")
                            .to_string(),
                        method: Method::Post,
                        form_fields: HashMap::new(),
                    }))
                } else {
                    None
                };

                (
                    attempt_status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            upi_response.merchant_transaction_identifier.clone(),
                        ),
                        redirection_data,
                        mandate_reference: None,
                        connector_metadata: Some(serde_json::json!({
                            "merchant_code": upi_response.merchant_code,
                            "transaction_state": upi_response.transaction_state,
                            "payment_method": upi_response.payment_method
                        })),
                        network_txn_id: upi_response.payment_method.payment_transaction.identifier,
                        connector_response_reference_id: Some(upi_response.merchant_transaction_identifier),
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            TpslPaymentsResponse::Error(error_response) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_response.error_code,
                    status_code: http_code,
                    message: error_response.error_message.clone(),
                    reason: Some(error_response.error_message),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            _ => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: "UNKNOWN_RESPONSE".to_string(),
                    status_code: http_code,
                    message: "Unexpected response format".to_string(),
                    reason: Some("Unexpected response format".to_string()),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response,
            ..router_data
        })
    }
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize
        + serde::de::DeserializeOwned,
> TryFrom<ResponseRouterData<TpslPaymentsResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TpslPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            TpslPaymentsResponse::Sync(sync_response) => {
                let status = TpslTransactionStatus::from(sync_response.transaction_state.as_str());
                let attempt_status = status.into();

                let amount_received = sync_response
                    .payment_method
                    .payment_transaction
                    .amount
                    .parse::<f64>()
                    .ok()
                    .map(|amt| (amt * 100.0) as i64);

                (
                    attempt_status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            sync_response.merchant_transaction_identifier.clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: Some(serde_json::json!({
                            "merchant_code": sync_response.merchant_code,
                            "transaction_state": sync_response.transaction_state,
                            "payment_method": sync_response.payment_method
                        })),
                        network_txn_id: sync_response.payment_method.payment_transaction.identifier,
                        connector_response_reference_id: Some(sync_response.merchant_transaction_identifier),
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            TpslPaymentsResponse::Error(error_response) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_response.error_code,
                    status_code: http_code,
                    message: error_response.error_message.clone(),
                    reason: Some(error_response.error_message),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            _ => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: "UNKNOWN_RESPONSE".to_string(),
                    status_code: http_code,
                    message: "Unexpected response format".to_string(),
                    reason: Some("Unexpected response format".to_string()),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response,
            ..router_data
        })
    }
}