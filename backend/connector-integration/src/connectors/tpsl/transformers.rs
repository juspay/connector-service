use common_utils::{
    errors::CustomResult, request::Method,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Secret, PeekInterface};
use serde::{Deserialize, Serialize};

use crate::types::ResponseRouterData;
use super::TPSLAmountConvertor;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslTransactionRequest {
    #[serde(rename = "getTransactionToken")]
    pub get_transaction_token: TpslTransactionMessage,
}

#[derive(Debug, Serialize)]
pub struct TpslTransactionMessage {
    pub msg: String,
}

#[derive(Debug, Deserialize)]
pub struct TpslTransactionResponse {
    #[serde(rename = "getTransactionTokenReturn")]
    pub get_transaction_token_return: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPITokenRequest {
    pub merchant: TpslMerchantDataType,
    pub cart: TpslUPITokenCart,
    pub transaction: TpslUPITokenTxn,
    pub consumer: TpslConsumerDataType,
}

#[derive(Debug, Serialize)]
pub struct TpslMerchantDataType {
    pub identifier: String,
}

#[derive(Debug, Serialize)]
pub struct TpslUPITokenCart {
    pub item: Vec<TpslUPIItem>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TpslUPIItem {
    pub amount: String,
    pub com_amt: String,
    pub s_k_u: String,
    pub reference: String,
    pub identifier: String,
}

#[derive(Debug, Serialize)]
pub struct TpslUPITokenTxn {
    pub amount: String,
    #[serde(rename = "type")]
    pub txn_type: String,
    pub currency: String,
    pub identifier: String,
    #[serde(rename = "subType")]
    pub sub_type: String,
    #[serde(rename = "requestType")]
    pub request_type: String,
}

#[derive(Debug, Serialize)]
pub struct TpslConsumerDataType {
    pub identifier: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPITxnRequest {
    pub merchant: TpslMerchantPayload,
    pub cart: TpslUPITokenCart,
    pub payment: TpslPaymentIntentPayload,
    pub transaction: TpslTxnPayload,
    pub consumer: TpslConsumerIntentPayload,
    #[serde(rename = "merchantInputFlags")]
    pub merchant_input_flags: TpslFlagsType,
}

#[derive(Debug, Serialize)]
pub struct TpslMerchantPayload {
    #[serde(rename = "webhookEndpointURL")]
    pub webhook_endpoint_url: String,
    #[serde(rename = "responseType")]
    pub response_type: String,
    #[serde(rename = "responseEndpointURL")]
    pub response_endpoint_url: String,
    pub description: String,
    pub identifier: String,
    #[serde(rename = "webhookType")]
    pub webhook_type: String,
}

#[derive(Debug, Serialize)]
pub struct TpslPaymentIntentPayload {
    pub method: TpslMethodUPIPayload,
    pub instrument: TpslUPIInstrumentPayload,
    pub instruction: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct TpslMethodUPIPayload {
    pub token: String,
    #[serde(rename = "type")]
    pub method_type: String,
}

#[derive(Debug, Serialize)]
pub struct TpslUPIInstrumentPayload {
    pub expiry: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct TpslTxnPayload {
    #[serde(rename = "deviceIdentifier")]
    pub device_identifier: String,
    #[serde(rename = "smsSending")]
    pub sms_sending: String,
    pub amount: String,
    #[serde(rename = "forced3DSCall")]
    pub forced_3ds_call: String,
    #[serde(rename = "type")]
    pub txn_type: String,
    pub description: String,
    pub currency: String,
    #[serde(rename = "isRegistration")]
    pub is_registration: String,
    pub identifier: String,
    #[serde(rename = "dateTime")]
    pub date_time: String,
    pub token: String,
    #[serde(rename = "securityToken")]
    pub security_token: String,
    #[serde(rename = "subType")]
    pub sub_type: String,
    #[serde(rename = "requestType")]
    pub request_type: String,
    pub reference: String,
    #[serde(rename = "merchantInitiated")]
    pub merchant_initiated: String,
    #[serde(rename = "tenureId")]
    pub tenure_id: String,
}

#[derive(Debug, Serialize)]
pub struct TpslConsumerIntentPayload {
    #[serde(rename = "mobileNumber")]
    pub mobile_number: String,
    #[serde(rename = "emailID")]
    pub email_id: String,
    pub identifier: String,
    #[serde(rename = "accountNo")]
    pub account_no: String,
    #[serde(rename = "accountType")]
    pub account_type: String,
    #[serde(rename = "accountHolderName")]
    pub account_holder_name: String,
    pub vpa: String,
    #[serde(rename = "aadharNo")]
    pub aadhar_no: String,
}

#[derive(Debug, Serialize)]
pub struct TpslFlagsType {
    #[serde(rename = "accountNo")]
    pub account_no: bool,
    #[serde(rename = "mobileNumber")]
    pub mobile_number: bool,
    #[serde(rename = "emailID")]
    pub email_id: bool,
    #[serde(rename = "cardDetails")]
    pub card_details: bool,
    #[serde(rename = "mandateDetails")]
    pub mandate_details: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPISyncRequest {
    pub merchant: TpslMerchantDataType,
    pub payment: TpslPaymentUPISyncType,
    pub transaction: TpslTransactionUPITxnType,
    pub consumer: TpslConsumerDataType,
}

#[derive(Debug, Serialize)]
pub struct TpslPaymentUPISyncType {
    pub instruction: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct TpslTransactionUPITxnType {
    #[serde(rename = "deviceIdentifier")]
    pub device_identifier: String,
    #[serde(rename = "type")]
    pub txn_type: Option<String>,
    #[serde(rename = "subType")]
    pub sub_type: Option<String>,
    pub amount: String,
    pub currency: String,
    #[serde(rename = "dateTime")]
    pub date_time: String,
    #[serde(rename = "requestType")]
    pub request_type: String,
    pub token: String,
}

// Response types
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPITokenResponse {
    #[serde(rename = "merchantCode")]
    pub merchant_code: String,
    #[serde(rename = "merchantTransactionIdentifier")]
    pub merchant_transaction_identifier: String,
    #[serde(rename = "merchantTransactionRequestType")]
    pub merchant_transaction_request_type: String,
    #[serde(rename = "responseType")]
    pub response_type: String,
    #[serde(rename = "paymentMethod")]
    pub payment_method: TpslUPIPaymentPayload,
    pub error: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPITxnResponse {
    #[serde(rename = "merchantCode")]
    pub merchant_code: String,
    #[serde(rename = "merchantTransactionIdentifier")]
    pub merchant_transaction_identifier: String,
    #[serde(rename = "merchantTransactionRequestType")]
    pub merchant_transaction_request_type: String,
    #[serde(rename = "responseType")]
    pub response_type: String,
    #[serde(rename = "transactionState")]
    pub transaction_state: String,
    #[serde(rename = "merchantAdditionalDetails")]
    pub merchant_additional_details: serde_json::Value,
    #[serde(rename = "paymentMethod")]
    pub payment_method: TpslUPIPaymentPayload,
    pub error: Option<serde_json::Value>,
    #[serde(rename = "merchantResponseString")]
    pub merchant_response_string: Option<serde_json::Value>,
    #[serde(rename = "pdfDownloadUrl")]
    pub pdf_download_url: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPIPaymentPayload {
    pub token: Option<String>,
    #[serde(rename = "instrumentAliasName")]
    pub instrument_alias_name: String,
    #[serde(rename = "instrumentToken")]
    pub instrument_token: String,
    #[serde(rename = "bankSelectionCode")]
    pub bank_selection_code: String,
    #[serde(rename = "aCS")]
    pub acs: TpslAcsPayload,
    #[serde(rename = "oTP")]
    pub otp: Option<serde_json::Value>,
    #[serde(rename = "paymentTransaction")]
    pub payment_transaction: TpslPaymentTxnPayload,
    pub authentication: Option<serde_json::Value>,
    pub error: TpslPaymentMethodErrorPayload,
    #[serde(rename = "paymentMode")]
    pub payment_mode: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAcsPayload {
    #[serde(rename = "bankAcsFormName")]
    pub bank_acs_form_name: String,
    #[serde(rename = "bankAcsHttpMethod")]
    pub bank_acs_http_method: serde_json::Value,
    #[serde(rename = "bankAcsParams")]
    pub bank_acs_params: Option<serde_json::Value>,
    #[serde(rename = "bankAcsUrl")]
    pub bank_acs_url: serde_json::Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentTxnPayload {
    pub amount: String,
    #[serde(rename = "balanceAmount")]
    pub balance_amount: Option<String>,
    #[serde(rename = "bankReferenceIdentifier")]
    pub bank_reference_identifier: Option<String>,
    #[serde(rename = "dateTime")]
    pub date_time: Option<String>,
    #[serde(rename = "errorMessage")]
    pub error_message: Option<String>,
    pub identifier: Option<String>,
    #[serde(rename = "refundIdentifier")]
    pub refund_identifier: String,
    #[serde(rename = "statusCode")]
    pub status_code: String,
    #[serde(rename = "statusMessage")]
    pub status_message: String,
    pub instruction: Option<serde_json::Value>,
    pub reference: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentMethodErrorPayload {
    pub code: String,
    pub desc: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslUPISyncResponse {
    #[serde(rename = "merchantCode")]
    pub merchant_code: String,
    #[serde(rename = "merchantTransactionIdentifier")]
    pub merchant_transaction_identifier: String,
    #[serde(rename = "merchantTransactionRequestType")]
    pub merchant_transaction_request_type: String,
    #[serde(rename = "responseType")]
    pub response_type: String,
    #[serde(rename = "transactionState")]
    pub transaction_state: String,
    #[serde(rename = "paymentMethod")]
    pub payment_method: TpslUPIPaymentPayload,
    pub error: Option<serde_json::Value>,
    #[serde(rename = "merchantResponseString")]
    pub merchant_response_string: Option<serde_json::Value>,
    #[serde(rename = "statusCode")]
    pub status_code: Option<String>,
    #[serde(rename = "statusMessage")]
    pub status_message: Option<String>,
    pub identifier: Option<String>,
    #[serde(rename = "bankReferenceIdentifier")]
    pub bank_reference_identifier: Option<String>,
    #[serde(rename = "merchantAdditionalDetails")]
    pub merchant_additional_details: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslDecodedRedirectionResponse {
    #[serde(rename = "txn_status")]
    pub txn_status: String,
    #[serde(rename = "txn_msg")]
    pub txn_msg: Option<String>,
    #[serde(rename = "txn_err_msg")]
    pub txn_err_msg: String,
    #[serde(rename = "clnt_txn_ref")]
    pub clnt_txn_ref: String,
    #[serde(rename = "tpsl_bank_cd")]
    pub tpsl_bank_cd: Option<String>,
    #[serde(rename = "tpsl_txn_id")]
    pub tpsl_txn_id: Option<String>,
    #[serde(rename = "txn_amt")]
    pub txn_amt: Option<String>,
    #[serde(rename = "clnt_rqst_meta")]
    pub clnt_rqst_meta: Option<String>,
    #[serde(rename = "tpsl_txn_time")]
    pub tpsl_txn_time: Option<String>,
    #[serde(rename = "tpsl_rfnd_id")]
    pub tpsl_rfnd_id: Option<String>,
    #[serde(rename = "bal_amt")]
    pub bal_amt: Option<String>,
    #[serde(rename = "rqst_token")]
    pub rqst_token: Option<String>,
    pub token: Option<String>,
    #[serde(rename = "card_id")]
    pub card_id: Option<String>,
    #[serde(rename = "_BankTransactionID")]
    pub bank_transaction_id: Option<String>,
    #[serde(rename = "alias_name")]
    pub alias_name: Option<String>,
    #[serde(rename = "mandate_reg_no")]
    pub mandate_reg_no: Option<String>,
    pub hash: Option<String>,
    #[serde(rename = "_REFUND_DETAILS")]
    pub refund_details: Option<String>,
    #[serde(rename = "tpsl_err_msg")]
    pub tpsl_err_msg: Option<String>,
    #[serde(rename = "vpa_name")]
    pub vpa_name: Option<String>,
    pub auth: Option<String>,
    #[serde(rename = "_MandateId")]
    pub mandate_id: Option<String>,
    #[serde(rename = "_VPA")]
    pub vpa: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslErrorResponse {
    #[serde(rename = "_ErrorCode")]
    pub error_code: String,
    #[serde(rename = "_ErrorMessage")]
    pub error_message: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TpslPaymentsResponse {
    TokenResponse(TpslUPITokenResponse),
    TxnResponse(TpslUPITxnResponse),
    SyncResponse(TpslUPISyncResponse),
    DecodedResponse(TpslDecodedRedirectionResponse),
    ErrorResponse(TpslErrorResponse),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAuthType {
    pub merchant_code: Secret<String>,
    pub merchant_key: Secret<String>,
    pub salt_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for TpslAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(_auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        // For now, return a default auth type - this should be properly implemented
        // based on the actual auth structure needed for TPSL
        Ok(TpslAuthType {
            merchant_code: Secret::new("default_merchant_code".to_string()),
            merchant_key: Secret::new("default_merchant_key".to_string()),
            salt_key: Secret::new("default_salt_key".to_string()),
        })
    }
}

fn get_merchant_code(
    connector_auth_type: &ConnectorAuthType,
) -> Result<Secret<String>, errors::ConnectorError> {
    match TpslAuthType::try_from(connector_auth_type) {
        Ok(tpsl_auth) => Ok(tpsl_auth.merchant_code),
        Err(_) => Err(errors::ConnectorError::FailedToObtainAuthType),
    }
}

fn get_merchant_key(
    connector_auth_type: &ConnectorAuthType,
) -> Result<Secret<String>, errors::ConnectorError> {
    match TpslAuthType::try_from(connector_auth_type) {
        Ok(tpsl_auth) => Ok(tpsl_auth.merchant_key),
        Err(_) => Err(errors::ConnectorError::FailedToObtainAuthType),
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for TpslUPITokenRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let customer_id = item.resource_common_data.get_customer_id()?;
        let merchant_code = get_merchant_code(&item.connector_auth_type)?;
        let amount = TpslAmountConvertor::convert(
            item.request.minor_amount,
            item.request.currency,
        )?;

        match item.resource_common_data.payment_method {
            common_enums::PaymentMethod::Upi => Ok(Self {
                merchant: TpslMerchantDataType {
                    identifier: merchant_code.peek().clone(),
                },
                cart: TpslUPITokenCart {
                    item: vec![TpslUPIItem {
                        amount: amount.to_string(),
                        com_amt: "0".to_string(),
                        s_k_u: "UPI".to_string(),
                        reference: item
                            .resource_common_data
                            .connector_request_reference_id
                            .clone(),
                        identifier: customer_id.get_string_repr().to_string(),
                    }],
                    description: Some("UPI Payment".to_string()),
                },
                transaction: TpslUPITokenTxn {
                    amount: amount.to_string(),
                    txn_type: "SALE".to_string(),
                    currency: item.request.currency.to_string(),
                    identifier: item
                        .resource_common_data
                        .connector_request_reference_id,
                    sub_type: "UPI".to_string(),
                    request_type: "SALE".to_string(),
                },
                consumer: TpslConsumerDataType {
                    identifier: customer_id.get_string_repr().to_string(),
                },
            }),
            _ => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("TPSL"),
            )
            .into()),
        }
    }
}

impl TryFrom<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for TpslUPISyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let customer_id = item.resource_common_data.get_customer_id()?;
        let merchant_code = get_merchant_code(&item.connector_auth_type)?;
        let amount = TpslAmountConvertor::convert(
            item.request.amount,
            item.request.currency,
        )?;

        Ok(Self {
            merchant: TpslMerchantDataType {
                identifier: merchant_code.peek().clone(),
            },
            payment: TpslPaymentUPISyncType {
                instruction: serde_json::Value::Null,
            },
            transaction: TpslTransactionUPITxnType {
                device_identifier: "WEB".to_string(),
                txn_type: Some("SALE".to_string()),
                sub_type: Some("UPI".to_string()),
                amount: amount.to_string(),
                currency: item.request.currency.to_string(),
                date_time: "2025-01-20 12:00:00".to_string(),
                request_type: "STATUS".to_string(),
                token: item
                    .request
                    .connector_transaction_id
                    .get_connector_transaction_id()
                    .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?,
            },
            consumer: TpslConsumerDataType {
                identifier: customer_id.get_string_repr().to_string(),
            },
        })
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TpslPaymentStatus {
    #[default]
    Pending,
    Success,
    Failure,
    Processing,
}

impl From<TpslPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: TpslPaymentStatus) -> Self {
        match item {
            TpslPaymentStatus::Success => Self::Charged,
            TpslPaymentStatus::Pending => Self::AuthenticationPending,
            TpslPaymentStatus::Failure => Self::Failure,
            TpslPaymentStatus::Processing => Self::Pending,
        }
    }
}

impl<F, T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<TpslPaymentsResponse, Self>>
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
            TpslPaymentsResponse::TokenResponse(token_response) => {
                let redirection_data = get_redirect_form_data(
                    common_enums::PaymentMethodType::UpiCollect,
                    &token_response,
                )?;
                (
                    common_enums::AttemptStatus::AuthenticationPending,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            router_data
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                        ),
                        redirection_data: Some(Box::new(redirection_data)),
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            TpslPaymentsResponse::TxnResponse(txn_response) => {
                let status = map_transaction_status(&txn_response.transaction_state);
                (
                    status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            router_data
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: txn_response.payment_method.payment_transaction.identifier,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            TpslPaymentsResponse::ErrorResponse(error_response) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_response.error_code,
                    status_code: item.http_code,
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
                    status_code: item.http_code,
                    message: "Unknown response format".to_string(),
                    reason: Some("Unknown response format".to_string()),
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

impl TryFrom<ResponseRouterData<TpslPaymentsResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
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
            TpslPaymentsResponse::SyncResponse(sync_response) => {
                let status = map_transaction_status(&sync_response.transaction_state);
                let _amount_received = sync_response
                    .payment_method
                    .payment_transaction
                    .amount
                    .parse::<f64>()
                    .ok()
                    .and_then(|amt| Some(common_utils::types::MinorUnit::new(amt as i64)));

                (
                    status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            router_data
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: sync_response.payment_method.payment_transaction.identifier,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            TpslPaymentsResponse::DecodedResponse(decoded_response) => {
                let status = map_txn_status(&decoded_response.txn_status);
                let _amount_received = decoded_response
                    .txn_amt
                    .as_ref()
                    .and_then(|amt| amt.parse::<f64>().ok())
                    .and_then(|amt| Some(common_utils::types::MinorUnit::new(amt as i64)));

                (
                    status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            decoded_response.clnt_txn_ref.clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: decoded_response.tpsl_txn_id.clone(),
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            TpslPaymentsResponse::ErrorResponse(error_response) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_response.error_code,
                    status_code: item.http_code,
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
                    status_code: item.http_code,
                    message: "Unknown response format".to_string(),
                    reason: Some("Unknown response format".to_string()),
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

fn get_redirect_form_data(
    payment_method_type: common_enums::PaymentMethodType,
    response_data: &TpslUPITokenResponse,
) -> CustomResult<RedirectForm, errors::ConnectorError> {
    match payment_method_type {
        common_enums::PaymentMethodType::UpiCollect => Ok(RedirectForm::Form {
            endpoint: format!(
                "upi://pay?pa={}&pn={}&am={}&cu={}",
                response_data.payment_method.instrument_alias_name,
                "Merchant",
                response_data.payment_method.payment_transaction.amount,
                "INR"
            ),
            method: Method::Get,
            form_fields: Default::default(),
        }),
        _ => Err(errors::ConnectorError::NotImplemented(
            utils::get_unimplemented_payment_method_error_message("TPSL"),
        ))?,
    }
}

fn map_transaction_status(status: &str) -> common_enums::AttemptStatus {
    match status.to_uppercase().as_str() {
        "SUCCESS" | "COMPLETED" => common_enums::AttemptStatus::Charged,
        "PENDING" | "PROCESSING" => common_enums::AttemptStatus::Pending,
        "FAILURE" | "FAILED" => common_enums::AttemptStatus::Failure,
        "AUTHENTICATION_PENDING" => common_enums::AttemptStatus::AuthenticationPending,
        _ => common_enums::AttemptStatus::Pending,
    }
}

fn map_txn_status(status: &str) -> common_enums::AttemptStatus {
    match status.to_uppercase().as_str() {
        "SUCCESS" | "COMPLETED" => common_enums::AttemptStatus::Charged,
        "PENDING" | "PROCESSING" => common_enums::AttemptStatus::Pending,
        "FAILURE" | "FAILED" => common_enums::AttemptStatus::Failure,
        "AUTHENTICATION_PENDING" => common_enums::AttemptStatus::AuthenticationPending,
        _ => common_enums::AttemptStatus::Pending,
    }
}