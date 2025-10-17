use std::collections::HashMap;

use common_utils::{
    errors::CustomResult, ext_traits::ValueExt, id_type, request::Method, types::StringMinorUnit,
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
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::easebuzz::EaseBuzzRouterData, types::ResponseRouterData};

// Request Types
#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsRequest {
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub email: Option<Email>,
    pub phone: Option<String>,
    pub productinfo: String,
    pub firstname: Option<String>,
    pub lastname: Option<String>,
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
    pub vpa: Option<String>,
    pub customer_unique_id: Option<String>,
    pub split_payments: Option<String>,
    pub customer_name: Option<String>,
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub zipcode: Option<String>,
    pub show_payment_mode: Option<String>,
    pub emit_oneway: Option<String>,
    pub sub_merchant_id: Option<String>,
    pub unique_id: Option<String>,
    pub ben_account: Option<String>,
    pub ben_name: Option<String>,
    pub ben_email: Option<String>,
    pub ben_mobile: Option<String>,
    pub ben_vpa: Option<String>,
    pub ben_address: Option<String>,
    pub ben_city: Option<String>,
    pub ben_state: Option<String>,
    pub ben_country: Option<String>,
    pub ben_zipcode: Option<String>,
    pub ben_pincode: Option<String>,
    pub payment_category: Option<String>,
    pub payment_workflow: Option<String>,
    pub mandate_type: Option<String>,
    pub mandate_max_amount: Option<String>,
    pub mandate_start_date: Option<String>,
    pub mandate_end_date: Option<String>,
    pub mandate_frequency: Option<String>,
    pub mandate_auth: Option<String>,
    pub mandate_reg_ref_id: Option<String>,
    pub tr: Option<String>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSyncRequest {
    pub txnid: String,
    pub amount: StringMinorUnit,
    pub email: String,
    pub phone: String,
    pub key: String,
    pub hash: String,
}

// Response Types
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EaseBuzzPaymentsResponse {
    Success(EaseBuzzPaymentsSuccessResponse),
    Error(EaseBuzzErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSuccessResponse {
    pub status: i32,
    pub error_desc: Option<String>,
    pub data: EaseBuzzPaymentData,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentData {
    pub payment_url: Option<String>,
    pub transaction_id: Option<String>,
    pub easebuzz_id: Option<String>,
    pub status: Option<String>,
    pub amount: Option<String>,
    pub currency: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzErrorResponse {
    pub status: i32,
    pub error_desc: Option<String>,
    pub data: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzPaymentsSyncResponse {
    pub status: bool,
    pub msg: EaseBuzzSyncMessageType,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EaseBuzzSyncMessageType {
    Success(EaseBuzzSeamlessTxnResponse),
    Error(String),
    ErrorType(EaseBuzzTxnSyncErrorType),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzSeamlessTxnResponse {
    pub transaction_id: String,
    pub easebuzz_id: String,
    pub status: String,
    pub amount: String,
    pub currency: String,
    pub payment_mode: Option<String>,
    pub bank_ref_num: Option<String>,
    pub card_no: Option<String>,
    pub name_on_card: Option<String>,
    pub issuing_bank: Option<String>,
    pub card_type: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EaseBuzzTxnSyncErrorType {
    pub error_code: String,
    pub error_message: String,
}

// Authentication Types
#[derive(Default, Debug, Deserialize)]
pub struct EaseBuzzAuthType {
    pub key: Secret<String>,
    pub salt: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for EaseBuzzAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1 } => {
                let key = api_key
                    .clone()
                    .ok_or(errors::ConnectorError::FailedToObtainAuthType)?;
                let salt = key1
                    .clone()
                    .ok_or(errors::ConnectorError::FailedToObtainAuthType)?;
                
                Ok(Self { key, salt })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Status Mapping
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EaseBuzzPaymentStatus {
    #[default]
    Pending,
    Success,
    Failure,
    UserAborted,
}

impl From<EaseBuzzPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: EaseBuzzPaymentStatus) -> Self {
        match item {
            EaseBuzzPaymentStatus::Success => Self::Charged,
            EaseBuzzPaymentStatus::Pending => Self::AuthenticationPending,
            EaseBuzzPaymentStatus::Failure => Self::Failure,
            EaseBuzzPaymentStatus::UserAborted => Self::AuthorizationFailed,
        }
    }
}

// Request Transformations
impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> TryFrom<EaseBuzzRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for EaseBuzzPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: EaseBuzzRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let return_url = item.router_data.request.get_router_return_url()?;
        
        let auth = EaseBuzzAuthType::try_from(&item.router_data.connector_auth_type)?;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Extract UPI VPA if available
        let vpa = item
            .router_data
            .request
            .payment_method_data
            .as_ref()
            .and_then(|pm| pm.get_upi_data())
            .and_then(|upi| upi.vpa.clone());

        Ok(Self {
            txnid: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            amount,
            email: item.router_data.request.email.clone(),
            phone: item.router_data.request.get_phone_number().map(|p| p.to_string()),
            productinfo: "Payment".to_string(),
            firstname: item.router_data.request.get_customer_name().map(|n| n.first_name.clone()),
            lastname: item.router_data.request.get_customer_name().and_then(|n| n.last_name.clone()),
            surl: return_url.clone(),
            furl: return_url,
            vpa,
            customer_unique_id: Some(customer_id.get_string_repr()),
            ..Default::default()
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
> TryFrom<EaseBuzzRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for EaseBuzzPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: EaseBuzzRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = EaseBuzzAuthType::try_from(&item.router_data.connector_auth_type)?;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Generate hash (simplified - in real implementation, this would use proper hashing)
        let hash = format!("{}|{}|{}|{}|{}", 
            auth.key.peek(),
            item.router_data.resource_common_data.connector_request_reference_id,
            amount.get_amount_as_string(),
            item.router_data.request.email.as_ref().map(|e| e.to_string()).unwrap_or_default(),
            auth.salt.peek()
        );

        Ok(Self {
            txnid: item.router_data.resource_common_data.connector_request_reference_id.clone(),
            amount,
            email: item.router_data.request.email.as_ref().map(|e| e.to_string()).unwrap_or_default(),
            phone: item.router_data.request.get_phone_number().map(|p| p.to_string()).unwrap_or_default(),
            key: auth.key.peek().to_string(),
            hash,
        })
    }
}

// Response Transformations
impl<
    F,
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> TryFrom<ResponseRouterData<EaseBuzzPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EaseBuzzPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            EaseBuzzPaymentsResponse::Success(success_data) => {
                let redirection_data = success_data.data.payment_url.map(|url| {
                    Box::new(RedirectForm::Form {
                        endpoint: url,
                        method: Method::Get,
                        form_fields: std::collections::HashMap::new(),
                    })
                });

                (
                    common_enums::AttemptStatus::AuthenticationPending,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            router_data
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                        ),
                        redirection_data,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: success_data.data.easebuzz_id,
                        connector_response_reference_id: success_data.data.transaction_id,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            EaseBuzzPaymentsResponse::Error(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.status.to_string(),
                    status_code: http_code,
                    message: error_data.error_desc.clone(),
                    reason: error_data.error_desc,
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
        + Serialize,
> TryFrom<ResponseRouterData<EaseBuzzPaymentsSyncResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EaseBuzzPaymentsSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response.msg {
            EaseBuzzSyncMessageType::Success(txn_data) => {
                let attempt_status = match txn_data.status.as_str() {
                    "success" => common_enums::AttemptStatus::Charged,
                    "pending" => common_enums::AttemptStatus::Pending,
                    "failure" => common_enums::AttemptStatus::Failure,
                    "user_aborted" => common_enums::AttemptStatus::AuthorizationFailed,
                    _ => common_enums::AttemptStatus::Pending,
                };

                (
                    attempt_status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(txn_data.transaction_id),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: Some(txn_data.easebuzz_id),
                        connector_response_reference_id: Some(txn_data.transaction_id),
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            EaseBuzzSyncMessageType::Error(error_msg) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: "SYNC_ERROR".to_string(),
                    status_code: http_code,
                    message: Some(error_msg.clone()),
                    reason: Some(error_msg),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            EaseBuzzSyncMessageType::ErrorType(error_type) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_type.error_code,
                    status_code: http_code,
                    message: Some(error_type.error_message.clone()),
                    reason: Some(error_type.error_message),
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

// Stub types for unsupported flows
#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzVoidRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzCaptureRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzRefundRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzRefundResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzRefundSyncRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzRefundSyncResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzCreateOrderRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzSessionTokenRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzSessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzSetupMandateRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzSetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzRepeatPaymentRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzAcceptDisputeRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzSubmitEvidenceRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzSubmitEvidenceResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzDefendDisputeRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzDefendDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzPreAuthenticateRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzPreAuthenticateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzAuthenticateRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzAuthenticateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzPostAuthenticateRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzPostAuthenticateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzCreateAccessTokenRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzCreateAccessTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzCreateConnectorCustomerRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzCreateConnectorCustomerResponse;

#[derive(Debug, Clone, Serialize)]
pub struct EaseBuzzPaymentMethodTokenRequest;

#[derive(Debug, Clone)]
pub struct EaseBuzzPaymentMethodTokenResponse;