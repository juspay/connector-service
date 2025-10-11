use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

use common_utils::{
    request::Method,
    types::StringMinorUnit,
    Email,
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

use crate::{connectors::paytmv2::PayTMv2RouterData, types::ResponseRouterData};

// Request Types

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayTMv2InitiateRequestHead {
    client_id: String,
    version: String,
    request_timestamp: String,
    channel_id: String,
    signature: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayTMv2Amount {
    value: StringMinorUnit,
    currency: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayTMv2UserInfo {
    cust_id: String,
    mobile: Option<String>,
    email: Option<Email>,
    first_name: Option<String>,
    last_name: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayTMv2ExtendInfo {
    udf1: Option<serde_json::Value>,
    udf2: Option<String>,
    udf3: Option<String>,
    merc_unq_ref: Option<Secret<String>>,
    comments: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayTMv2InitiateRequestBody {
    request_type: String,
    mid: String,
    order_id: String,
    website_name: String,
    txn_amount: PayTMv2Amount,
    user_info: PayTMv2UserInfo,
    callback_url: Option<String>,
    extend_info: Option<PayTMv2ExtendInfo>,
}

#[derive(Debug, Serialize)]
pub struct PayTMv2InitiateTransactionRequest {
    head: PayTMv2InitiateRequestHead,
    body: PayTMv2InitiateRequestBody,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayTMv2ProcessRequestHead {
    version: String,
    request_timestamp: String,
    channel_id: String,
    txn_token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayTMv2ProcessRequestBody {
    mid: String,
    order_id: String,
    request_type: String,
    payment_mode: String,
    payment_flow: Option<String>,
    payer_account: Option<String>,
    extend_info: Option<PayTMv2ExtendInfo>,
}

#[derive(Debug, Serialize)]
pub struct PayTMv2ProcessTransactionRequest {
    head: PayTMv2ProcessRequestHead,
    body: PayTMv2ProcessRequestBody,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayTMv2StatusRequestHead {
    version: String,
    request_timestamp: String,
    channel_id: String,
    signature: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayTMv2StatusRequestBody {
    mid: String,
    order_id: String,
}

#[derive(Debug, Serialize)]
pub struct PayTMv2TransactionStatusRequest {
    head: PayTMv2StatusRequestHead,
    body: PayTMv2StatusRequestBody,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayTMv2ValidateVpaRequestHead {
    version: String,
    request_timestamp: String,
    channel_id: String,
    signature: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayTMv2ValidateVpaRequestBody {
    vpa: String,
    mid: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PayTMv2ValidateVpaRequest {
    head: PayTMv2ValidateVpaRequestHead,
    body: PayTMv2ValidateVpaRequestBody,
}

// Response Types

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayTMv2ResponseHead {
    response_timestamp: Option<String>,
    version: String,
    client_id: Option<String>,
    signature: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayTMv2ResultInfo {
    result_status: String,
    result_code: String,
    result_msg: String,
    retry: Option<bool>,
    bank_retry: Option<bool>,
    auth_ref_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayTMv2InitiateResponseBody {
    txn_token: String,
    result_info: PayTMv2ResultInfo,
    is_promo_code_valid: Option<bool>,
    promo_code_valid: Option<bool>,
    authenticated: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct PayTMv2InitiateTransactionResponse {
    head: PayTMv2ResponseHead,
    body: PayTMv2InitiateResponseBody,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayTMv2ProcessResponseBody {
    result_info: PayTMv2ResultInfo,
    txn_info: Option<PayTMv2TransactionInfo>,
    call_back_url: Option<String>,
    bank_form: Option<PayTMv2BankForm>,
}

#[derive(Debug, Deserialize)]
pub struct PayTMv2ProcessTransactionResponse {
    head: PayTMv2ResponseHead,
    body: PayTMv2ProcessResponseBody,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayTMv2TransactionInfo {
    mid: String,
    txn_id: Option<String>,
    order_id: String,
    bank_txn_id: Option<String>,
    txn_amount: String,
    currency: Option<String>,
    status: String,
    resp_code: String,
    resp_msg: String,
    txn_date: Option<String>,
    gateway_name: Option<String>,
    bank_name: Option<String>,
    payment_mode: Option<String>,
    udf_1: Option<String>,
    udf_2: Option<String>,
    udf_3: Option<String>,
    merc_unq_ref: Option<String>,
    checksum_hash: Option<String>,
    additional_info: Option<String>,
    subs_id: Option<String>,
    vpa: Option<String>,
    auth_ref_id: Option<String>,
    split_settlement_info: Option<String>,
    upi_mode_sub_type: Option<String>,
    bin_number: Option<String>,
    auth_code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayTMv2BankForm {
    page_type: String,
    redirect_form: PayTMv2RedirectForm,
    direct_forms: Option<Vec<PayTMv2DirectForm>>,
    display_field: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayTMv2RedirectForm {
    action_url: String,
    method: String,
    r#type: String,
    headers: Option<PayTMv2Headers>,
    content: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayTMv2DirectForm {
    action_url: String,
    method: String,
    r#type: String,
    headers: PayTMv2Headers,
    content: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayTMv2Headers {
    #[serde(rename = "__Content-Type")]
    content_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayTMv2StatusResponseBody {
    result_info: PayTMv2ResultInfo,
    txn_id: Option<String>,
    order_id: String,
    txn_amount: String,
    txn_type: String,
    mid: String,
    txn_date: String,
    bank_name: Option<String>,
    payment_mode: Option<String>,
    gateway_name: Option<String>,
    bank_txn_id: Option<String>,
    refund_amt: Option<String>,
    result_status: Option<String>,
    result_code: Option<String>,
    result_msg: Option<String>,
    subs_id: Option<String>,
    payable_amount: Option<String>,
    payment_promo_checkout_data: Option<String>,
    transfer_mode: Option<String>,
    utr: Option<String>,
    bank_transaction_date: Option<String>,
    rrn_code: Option<String>,
    auth_code: Option<String>,
    merchant_unique_reference: Option<String>,
    card_scheme: Option<String>,
    bin: Option<String>,
    last_four_digit: Option<String>,
    international_card_payment: Option<bool>,
    base_currency: Option<String>,
    auth_ref_id: Option<String>,
    emi_subvention_info: Option<String>,
    merc_uniq_ref: Option<String>,
    merc_unq_ref: Option<String>,
    upi_mode_sub_type: Option<String>,
    bank_result_info: Option<serde_json::Value>,
    bin_number: Option<String>,
    vpa: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PayTMv2TransactionStatusResponse {
    head: PayTMv2ResponseHead,
    body: PayTMv2StatusResponseBody,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayTMv2ValidateVpaResponseBody {
    result_info: PayTMv2ResultInfo,
    vpa: Option<String>,
    valid: Option<bool>,
    recurring_details: Option<PayTMv2VpaSubsDetails>,
    extra_params_map: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayTMv2VpaSubsDetails {
    psp_supported_recurring: bool,
    bank_supported_recurring: bool,
}

#[derive(Debug, Deserialize)]
pub struct PayTMv2ValidateVpaResponse {
    head: PayTMv2ResponseHead,
    body: PayTMv2ValidateVpaResponseBody,
}

// Error Response Types

#[derive(Debug, Deserialize)]
pub struct PayTMv2ErrorResponse {
    error: String,
    error_description: Option<String>,
    gateway_response: serde_json::Value,
}

// Auth Types

#[derive(Debug, Deserialize)]
pub struct PayTMv2Auth {
    pub mid: Secret<String>,
    pub client_id: Secret<String>,
    pub client_secret: Secret<String>,
    pub website_name: String,
}

impl TryFrom<&ConnectorAuthType> for PayTMv2Auth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => {
                let auth = PayTMv2Auth {
                    mid: api_key.clone(),
                    client_id: key1.clone(),
                    client_secret: api_secret.clone(),
                    website_name: "DEFAULT".to_string(),
                };
                Ok(auth)
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Request conversion implementations

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<PayTMv2RouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for PayTMv2InitiateTransactionRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: PayTMv2RouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = PayTMv2Auth::try_from(&item.router_data.connector_auth_type)?;
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let return_url = item.router_data.request.get_router_return_url()?;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let timestamp = time::OffsetDateTime::now_utc().unix_timestamp().to_string();
        
        Ok(Self {
            head: PayTMv2InitiateRequestHead {
                client_id: auth.client_id.expose().clone(),
                version: "v1".to_string(),
                request_timestamp: timestamp,
                channel_id: "WEB".to_string(),
                signature: auth.client_secret.clone(),
            },
            body: PayTMv2InitiateRequestBody {
                request_type: "PAYMENT".to_string(),
                mid: auth.mid.expose().clone(),
                order_id: item.router_data.resource_common_data.connector_request_reference_id.clone(),
                website_name: auth.website_name,
                txn_amount: PayTMv2Amount {
                    value: amount,
                    currency: item.router_data.request.currency.to_string(),
                },
                user_info: PayTMv2UserInfo {
                    cust_id: customer_id.get_string_repr(),
                    mobile: item.router_data.request.phone.clone().map(|p| p.to_string()),
                    email: item.router_data.request.email.clone(),
                    first_name: None,
                    last_name: None,
                },
                callback_url: Some(return_url),
                extend_info: None,
            },
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<PayTMv2RouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for PayTMv2TransactionStatusRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: PayTMv2RouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = PayTMv2Auth::try_from(&item.router_data.connector_auth_type)?;
        let timestamp = time::OffsetDateTime::now_utc().unix_timestamp().to_string();
        
        Ok(Self {
            head: PayTMv2StatusRequestHead {
                version: "v1".to_string(),
                request_timestamp: timestamp,
                channel_id: "WEB".to_string(),
                signature: auth.client_secret,
            },
            body: PayTMv2StatusRequestBody {
                mid: auth.mid.expose().clone(),
                order_id: item.router_data.request.connector_transaction_id.get_connector_transaction_id()
                    .map_err(|_e| ConnectorError::RequestEncodingFailed)?,
            },
        })
    }
}

// Response conversion implementations

impl<F, T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<PayTMv2InitiateTransactionResponse, F>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<PayTMv2InitiateTransactionResponse, F>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let status = if response.body.result_info.result_status == "SUCCESS" {
            common_enums::AttemptStatus::AuthenticationPending
        } else {
            common_enums::AttemptStatus::Failure
        };

        let response_data = if response.body.result_info.result_status == "SUCCESS" {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                ),
                redirection_data: Some(Box::new(RedirectForm::Form {
                    endpoint: format!("https://securegw.paytm.in/theia/api/v1/showPaymentPage?orderId={}&txnToken={}", 
                        router_data.resource_common_data.connector_request_reference_id,
                        response.body.txn_token),
                    method: Method::Get,
                    form_fields: Default::default(),
                })),
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: http_code,
            })
        } else {
            Err(ErrorResponse {
                code: response.body.result_info.result_code,
                status_code: http_code,
                message: response.body.result_info.result_msg.clone(),
                reason: Some(response.body.result_info.result_msg),
                attempt_status: None,
                connector_transaction_id: None,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            })
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: response_data,
            ..router_data
        })
    }
}

impl<F, T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<PayTMv2TransactionStatusResponse, F>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<PayTMv2TransactionStatusResponse, F>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let status = match response.body.result_info.result_status.as_str() {
            "SUCCESS" | "TXN_SUCCESS" => common_enums::AttemptStatus::Charged,
            "PENDING" | "TXN_PENDING" => common_enums::AttemptStatus::Pending,
            _ => common_enums::AttemptStatus::Failure,
        };

        let response_data = Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(
                response.body.order_id.clone(),
            ),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: response.body.txn_id.clone(),
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: http_code,
        });

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: response_data,
            ..router_data
        })
    }
}

// Status mapping
pub fn get_paytmv2_status(status: &str) -> common_enums::AttemptStatus {
    match status {
        "SUCCESS" | "TXN_SUCCESS" => common_enums::AttemptStatus::Charged,
        "PENDING" | "TXN_PENDING" => common_enums::AttemptStatus::Pending,
        "FAILURE" | "TXN_FAILURE" => common_enums::AttemptStatus::Failure,
        _ => common_enums::AttemptStatus::AuthenticationPending,
    }
}