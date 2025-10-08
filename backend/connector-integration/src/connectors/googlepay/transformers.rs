use std::collections::HashMap;

use chrono;
use common_utils::{
    errors::CustomResult,
    ext_traits::ValueExt,
    id_type,
    request::Method,
    types::{AmountConvertor, StringMinorUnit},
    Email,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::{PaymentMethodDataTypes, UpiData},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use crate::{connectors::googlepay::GooglePayRouterData, types::ResponseRouterData};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GooglePayPaymentsRequest {
    pub merchant_id: String,
    pub amount: StringMinorUnit,
    pub payer_vpa: Option<String>,
    pub payee_vpa: Option<String>,
    pub expiry: i32,
    pub transaction_type: String,
    pub initiate_request: bool,
    pub remarks: String,
    pub merchant_order_id: String,
    pub mobile_number: String,
    pub originating_platform: OriginatingPlatform,
    pub callback_url: String,
    pub upi_request_id: Option<String>,
    pub register_intent: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OriginatingPlatform {
    AndroidApp,
    AndroidWeb,
    IosApp,
    IosWeb,
    InstorePos,
    Desktop,
    Ivr,
    Other,
}

impl Default for OriginatingPlatform {
    fn default() -> Self {
        Self::AndroidApp
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GooglePayPaymentsSyncRequest {
    pub tr: String,
    pub vpa: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GooglePayRefundRequest {
    pub merchant_id: String,
    pub amount: String,
    pub payee_vpa: String,
    pub remarks: String,
    pub merchant_order_id: String,
    pub merchant_refund_id: String,
    pub add_info: Option<AdditionalInfo>,
    pub customer_vpa: Option<String>,
    pub instant: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdditionalInfo {
    pub add_info1: Option<String>,
    pub add_info2: Option<String>,
    pub add_info3: Option<String>,
    pub add_info4: Option<String>,
    pub add_info5: Option<String>,
    pub add_info6: Option<String>,
    pub add_info7: Option<String>,
    pub add_info8: Option<String>,
    pub add_info9: Option<String>,
    pub add_info10: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GooglePayRefundSyncRequest {
    pub merchant_id: String,
}

// Stub types for unsupported flows
#[derive(Debug, Clone, Serialize)]
pub struct GooglePayVoidRequest;
#[derive(Debug, Clone)]
pub struct GooglePayVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct GooglePayCaptureRequest;
#[derive(Debug, Clone)]
pub struct GooglePayCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct GooglePayCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct GooglePayCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct GooglePaySessionTokenRequest;
#[derive(Debug, Clone)]
pub struct GooglePaySessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct GooglePaySetupMandateRequest;
#[derive(Debug, Clone)]
pub struct GooglePayDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct GooglePayRepeatPaymentRequest;

#[derive(Debug, Clone, Serialize)]
pub struct GooglePayAcceptDisputeRequest;

#[derive(Debug, Clone, Serialize)]
pub struct GooglePayDefendDisputeRequest;

#[derive(Debug, Clone, Serialize)]
pub struct GooglePaySubmitEvidenceRequest;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GooglePayAuth {
    pub merchant_id: Option<Secret<String>>,
    pub api_key: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for GooglePayAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, .. } => Ok(Self {
                merchant_id: None,
                api_key: Some(api_key.clone()),
            }),
            ConnectorAuthType::BodyKey { api_key, .. } => Ok(Self {
                merchant_id: None,
                api_key: Some(api_key.clone()),
            }),
            ConnectorAuthType::MultiAuthKey { .. } => {
                // For multi-auth, we'll need to extract the appropriate key
                Ok(Self {
                    merchant_id: None,
                    api_key: None,
                })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
>
TryFrom<
    GooglePayRouterData<
        RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >,
        T,
    >,
> for GooglePayPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: GooglePayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let return_url = item.router_data.request.get_router_return_url()?;
        
        // Extract UPI data from payment method
        let upi_data = item.router_data.request.payment_method_data
            .as_ref()
            .and_then(|pm| pm.upi.clone())
            .ok_or(errors::ConnectorError::MissingPaymentMethodData)?;

        // Extract merchant ID from auth or use a default
        let merchant_id = match GooglePayAuth::try_from(&item.router_data.connector_auth_type) {
            Ok(auth) => auth.merchant_id
                .map(|m| m.expose().clone())
                .unwrap_or_else(|| "default_merchant".to_string()),
            Err(_) => "default_merchant".to_string(),
        };

        // Extract mobile number from UPI data or use default
        let mobile_number = upi_data.mobile_number
            .clone()
            .unwrap_or_else(|| "9999999999".to_string());

        // Determine originating platform from browser info
        let originating_platform = item.router_data.request.browser_info
            .as_ref()
            .and_then(|info| info.user_agent.as_ref())
            .map(|user_agent| {
                if user_agent.contains("Android") {
                    OriginatingPlatform::AndroidApp
                } else if user_agent.contains("iPhone") || user_agent.contains("iPad") {
                    OriginatingPlatform::IosApp
                } else {
                    OriginatingPlatform::AndroidWeb
                }
            })
            .unwrap_or_default();

        // Get amount as string using the amount converter
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Generate UPI request ID if not provided
        let upi_request_id = Some(format!(
            "UPI_{}_{}",
            item.router_data.resource_common_data.connector_request_reference_id,
            chrono::Utc::now().timestamp()
        ));

        // Determine transaction type based on payment method
        let transaction_type = match upi_data.upi_intent {
            Some(_) => "INTENT",
            None => "COLLECT",
        };

        Ok(Self {
            merchant_id,
            amount,
            payer_vpa: upi_data.vpa,
            payee_vpa: None, // Will be set by connector
            expiry: 900, // 15 minutes default
            transaction_type: transaction_type.to_string(),
            initiate_request: true,
            remarks: item.router_data.request.description.clone().unwrap_or_default(),
            merchant_order_id: item.router_data.resource_common_data.connector_request_reference_id.clone(),
            mobile_number,
            originating_platform,
            callback_url: return_url,
            upi_request_id,
            register_intent: upi_data.upi_intent.is_some(),
        })
    }
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
>
TryFrom<
    GooglePayRouterData<
        RouterDataV2<
            PSync,
            PaymentFlowData,
            PaymentsSyncData,
            PaymentsResponseData,
        >,
        T,
    >,
> for GooglePayPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: GooglePayRouterData<
            RouterDataV2<
                PSync,
                PaymentFlowData,
                PaymentsSyncData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        // Extract transaction reference from the request
        let transaction_ref = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        // Extract VPA from payment method data if available
        let vpa = item.router_data.request.payment_method_data
            .as_ref()
            .and_then(|pm| pm.upi.as_ref())
            .and_then(|upi| upi.vpa.clone())
            .unwrap_or_else(|| "default@vpa".to_string());

        Ok(Self {
            tr: transaction_ref,
            vpa,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EulerTransactionResponse {
    #[serde(rename = "_id")]
    pub id: Option<String>,
    #[serde(rename = "_AgencyId")]
    pub agency_id: String,
    #[serde(rename = "_OrderId")]
    pub order_id: Option<String>,
    pub transaction_ref: Option<String>,
    #[serde(rename = "_PayeeVpaId")]
    pub payee_vpa_id: String,
    pub payer_vpa: Option<String>,
    pub payee_vpa: Option<String>,
    pub payer_info: Option<serde_json::Value>,
    pub payee_info: Option<serde_json::Value>,
    pub txn_info: Option<serde_json::Value>,
    pub self_initiated: Option<bool>,
    pub mode: String,
    pub amount: Option<String>,
    pub upi_request_id: Option<String>,
    #[serde(rename = "_type")]
    pub transaction_type: String,
    pub status: String,
    pub upi_msg_id: Option<String>,
    pub npci_response: Option<serde_json::Value>,
    pub remarks: String,
    pub expiry: Option<String>,
    pub currency: Option<String>,
    pub cust_ref: Option<String>,
    pub ref_url: Option<String>,
    pub settlement_status: Option<String>,
    #[serde(rename = "_CustomerId")]
    pub customer_id: Option<String>,
    #[serde(rename = "_EmployeeId")]
    pub employee_id: Option<String>,
    pub udf1: Option<String>,
    pub udf2: Option<String>,
    pub udf3: Option<String>,
    pub udf4: Option<String>,
    pub udf5: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub transaction_at: Option<String>,
    #[serde(rename = "_BharatQRTxnId")]
    pub bharat_qr_txn_id: Option<String>,
    pub callback_url: Option<String>,
    pub transaction_source: Option<String>,
    pub info: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EulerErrorResponse {
    pub error: bool,
    pub error_message: String,
    pub user_message: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum InitTransactionResponse {
    ValidResponse(EulerTransactionResponse),
    ErrorResponse(EulerErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GooglePayPaymentsResponse {
    pub code: i32,
    pub status: String,
    pub response: InitTransactionResponse,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum GooglePayRefundResponse {
    ValidRefundResponse(GooglePayRefundResponseData),
    RefundErrorResponse(EulerErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GooglePayRefundResponseData {
    #[serde(rename = "_id")]
    pub id: String,
    #[serde(rename = "_AgencyId")]
    pub agency_id: String,
    #[serde(rename = "_OrderId")]
    pub order_id: Option<String>,
    #[serde(rename = "_TransactionId")]
    pub transaction_id: String,
    pub refund_date: String,
    pub refund_ref_id: String,
    pub transaction_ref: Option<String>,
    pub status: String,
    pub amount: String,
    pub response_code: Option<String>,
    pub info: Option<serde_json::Value>,
    pub customer_info: Option<serde_json::Value>,
    pub udf1: Option<String>,
    pub udf2: Option<String>,
    pub udf3: Option<String>,
    pub udf4: Option<String>,
    pub udf5: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EulerSyncResponse {
    #[serde(rename = "_id")]
    pub id: Option<String>,
    #[serde(rename = "_AgencyId")]
    pub agency_id: Option<String>,
    #[serde(rename = "_OrderId")]
    pub order_id: Option<String>,
    pub transaction_ref: Option<String>,
    #[serde(rename = "_PayeeVpaId")]
    pub payee_vpa_id: Option<String>,
    pub payer_vpa: Option<String>,
    pub payee_vpa: Option<String>,
    pub payer_info: Option<serde_json::Value>,
    pub payee_info: Option<serde_json::Value>,
    pub txn_info: Option<serde_json::Value>,
    pub self_initiated: Option<bool>,
    pub mode: Option<String>,
    pub amount: Option<String>,
    pub upi_request_id: Option<String>,
    #[serde(rename = "_type")]
    pub transaction_type: Option<String>,
    pub status: String,
    pub upi_msg_id: Option<String>,
    pub npci_response: Option<serde_json::Value>,
    pub remarks: Option<String>,
    pub expiry: Option<String>,
    pub currency: Option<String>,
    pub cust_ref: Option<String>,
    pub ref_url: Option<String>,
    pub settlement_status: Option<String>,
    #[serde(rename = "_CustomerId")]
    pub customer_id: Option<String>,
    #[serde(rename = "_EmployeeId")]
    pub employee_id: Option<String>,
    pub udf1: Option<String>,
    pub udf2: Option<String>,
    pub udf3: Option<String>,
    pub udf4: Option<String>,
    pub udf5: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub transaction_at: Option<String>,
    #[serde(rename = "_BharatQRTxnId")]
    pub bharat_qr_txn_id: Option<String>,
    pub callback_url: Option<String>,
    pub transaction_source: Option<String>,
    pub info: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum GetStatusResp {
    ValidGetStatusResponse(EulerSyncResponse),
    StatusErrorResponse(EulerErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetStatusResponse {
    pub code: i32,
    pub status: String,
    pub response: GetStatusResp,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GooglePayStatusResponse {
    pub transaction_id: String,
    pub google_transaction_id: String,
    pub payment_mode: Option<String>,
    pub transaction_status: TransactionStatus,
    pub upi_transaction_details: Option<serde_json::Value>,
    pub amount_paid: Option<serde_json::Value>,
    pub last_updated_time: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TransactionStatus {
    pub status: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum GpayGatewayResponse {
    GooglePayStatusResp(GooglePayStatusResponse),
    EulerSyncResp(EulerSyncResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GooglePayErrorResponse {
    pub code: i32,
    pub status: String,
    pub error_message: Option<String>,
}

impl From<String> for common_enums::AttemptStatus {
    fn from(status: String) -> Self {
        match status.to_lowercase().as_str() {
            "success" | "charged" | "completed" => Self::Charged,
            "pending" | "processing" | "initiated" => Self::AuthenticationPending,
            "failed" | "failure" | "declined" => Self::Failure,
            "refunded" => Self::AutoRefunded,
            _ => Self::AuthenticationPending,
        }
    }
}

impl From<&EulerTransactionResponse> for common_enums::AttemptStatus {
    fn from(response: &EulerTransactionResponse) -> Self {
        response.status.clone().into()
    }
}

impl From<&EulerSyncResponse> for common_enums::AttemptStatus {
    fn from(response: &EulerSyncResponse) -> Self {
        response.status.clone().into()
    }
}

fn get_redirect_form_data(
    response_data: &EulerTransactionResponse,
) -> CustomResult<RedirectForm, errors::ConnectorError> {
    // For UPI Intent, we need to construct the appropriate redirect
    if let Some(ref_url) = &response_data.ref_url {
        Ok(RedirectForm::Form {
            endpoint: ref_url.clone(),
            method: Method::Get,
            form_fields: std::collections::HashMap::new(),
        })
    } else {
        Err(errors::ConnectorError::MissingRequiredField {
            field_name: "ref_url",
        })
    }
}

impl<
    F,
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize
        + Serialize,
> TryFrom<ResponseRouterData<GooglePayPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: ResponseRouterData<GooglePayPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response_data) = match response.response {
            InitTransactionResponse::ValidResponse(transaction_response) => {
                let attempt_status = common_enums::AttemptStatus::from(&transaction_response);
                
                // For UPI payments, we might need to redirect
                let redirection_data = if attempt_status == common_enums::AttemptStatus::AuthenticationPending {
                    get_redirect_form_data(&transaction_response).ok().map(Box::new)
                } else {
                    None
                };

                (
                    attempt_status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            transaction_response.transaction_ref.clone().unwrap_or_default(),
                        ),
                        redirection_data,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: transaction_response.upi_request_id.clone(),
                        connector_response_reference_id: transaction_response.id.clone(),
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            InitTransactionResponse::ErrorResponse(error_response) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_response.error_message.clone(),
                    status_code: item.http_code,
                    message: error_response.user_message.clone(),
                    reason: Some(error_response.error_message),
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
            response: response_data,
            ..router_data
        })
    }
}

impl<
    F,
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize
        + Serialize,
> TryFrom<ResponseRouterData<GooglePayPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: ResponseRouterData<GooglePayPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response_data) = match response.response {
            InitTransactionResponse::ValidResponse(transaction_response) => {
                let attempt_status = common_enums::AttemptStatus::from(&transaction_response);
                
                (
                    attempt_status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            transaction_response.transaction_ref.clone().unwrap_or_default(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: transaction_response.upi_request_id.clone(),
                        connector_response_reference_id: transaction_response.id.clone(),
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            InitTransactionResponse::ErrorResponse(error_response) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_response.error_message.clone(),
                    status_code: item.http_code,
                    message: error_response.user_message.clone(),
                    reason: Some(error_response.error_message),
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
            response: response_data,
            ..router_data
        })
    }
}