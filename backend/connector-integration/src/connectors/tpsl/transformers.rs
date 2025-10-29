use common_utils::{
    errors::CustomResult, request::Method,
};
use error_stack::ResultExt;
use domain_types::{
    connector_flow::{
        Authorize, PSync, PostAuthenticate, Authenticate, PreAuthenticate, Void, Capture, 
        Refund, RSync, SetupMandate, RepeatPayment, Accept, SubmitEvidence, DefendDispute,
        CreateOrder, CreateSessionToken, PaymentMethodToken, CreateAccessToken, 
        CreateConnectorCustomer, VoidPC
    },
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId,
        PaymentsPostAuthenticateData, PaymentsAuthenticateData, PaymentsPreAuthenticateData,
        PaymentVoidData, PaymentsCaptureData, RefundFlowData, RefundsData, RefundsResponseData,
        RefundSyncData, SetupMandateRequestData, RepeatPaymentData, DisputeFlowData,
        AcceptDisputeData, DisputeResponseData, SubmitEvidenceData, PaymentCreateOrderData,
        PaymentCreateOrderResponse, SessionTokenRequestData, SessionTokenResponseData,
        PaymentMethodTokenizationData, PaymentMethodTokenResponse, AccessTokenRequestData,
        AccessTokenResponseData, ConnectorCustomerData, ConnectorCustomerResponse,
        PaymentsCancelPostCaptureData
    },
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use hyperswitch_masking::{Secret, PeekInterface};
use serde::{Deserialize, Serialize};

use crate::{connectors::tpsl::TPSLRouterData, types::ResponseRouterData};

// CRITICAL: Authentication type based on Haskell implementation
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslAuthType {
    pub merchant_code: Secret<String>,
    pub merchant_key: Secret<String>,
    pub salt_key: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for TpslAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, .. } => {
                // Extract merchant code and key from the auth type
                let parts: Vec<&str> = api_key.peek().split(':').collect();
                if parts.len() >= 2 {
                    Ok(TpslAuthType {
                        merchant_code: Secret::new(parts[0].to_string()),
                        merchant_key: Secret::new(parts[1].to_string()),
                        salt_key: None,
                    })
                } else {
                    Err(errors::ConnectorError::FailedToObtainAuthType.into())
                }
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// CRITICAL: Separate request types for each flow to avoid macro conflicts
// Authorize flow request types
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsRequest {
    pub merchant: TpslMerchantDataType,
    pub cart: TpslUPITokenCart,
    pub transaction: TpslUPITokenTxn,
    pub consumer: TpslConsumerDataType,
}

// PSync flow request types (alias to avoid conflicts)
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsSyncRequest {
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

// CRITICAL: Separate response types for each flow to avoid macro conflicts
// Authorize flow response types
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsResponse {
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

// PSync flow response types (alias to avoid conflicts)
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpslPaymentsSyncResponse {
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

// Stub types for additional flows to avoid macro conflicts
#[derive(Debug, Serialize)]
pub struct TpslPostAuthenticateRequest;
#[derive(Debug, Deserialize, Serialize)]
pub struct TpslPostAuthenticateResponse;

#[derive(Debug, Serialize)]
pub struct TpslAuthenticateRequest;
#[derive(Debug, Deserialize, Serialize)]
pub struct TpslAuthenticateResponse;

#[derive(Debug, Serialize)]
pub struct TpslPreAuthenticateRequest;
#[derive(Debug, Deserialize, Serialize)]
pub struct TpslPreAuthenticateResponse;

#[derive(Debug, Serialize)]
pub struct TpslVoidRequest;
#[derive(Debug, Deserialize, Serialize)]
pub struct TpslVoidResponse;

#[derive(Debug, Serialize)]
pub struct TpslCaptureRequest;
#[derive(Debug, Deserialize, Serialize)]
pub struct TpslCaptureResponse;

#[derive(Debug, Serialize)]
pub struct TpslRefundRequest;
#[derive(Debug, Deserialize, Serialize)]
pub struct TpslRefundResponse;

#[derive(Debug, Serialize)]
pub struct TpslRSyncRequest;
#[derive(Debug, Deserialize, Serialize)]
pub struct TpslRSyncResponse;

#[derive(Debug, Serialize)]
pub struct TpslSetupMandateRequest;
#[derive(Debug, Deserialize, Serialize)]
pub struct TpslSetupMandateResponse;

#[derive(Debug, Serialize)]
pub struct TpslRepeatPaymentRequest;
#[derive(Debug, Deserialize, Serialize)]
pub struct TpslRepeatPaymentResponse;

#[derive(Debug, Serialize)]
pub struct TpslAcceptDisputeRequest;
#[derive(Debug, Deserialize, Serialize)]
pub struct TpslAcceptDisputeResponse;

#[derive(Debug, Serialize)]
pub struct TpslSubmitEvidenceRequest;
#[derive(Debug, Deserialize, Serialize)]
pub struct TpslSubmitEvidenceResponse;

#[derive(Debug, Serialize)]
pub struct TpslDefendDisputeRequest;
#[derive(Debug, Deserialize, Serialize)]
pub struct TpslDefendDisputeResponse;

#[derive(Debug, Serialize)]
pub struct TpslCreateOrderRequest;
#[derive(Debug, Deserialize, Serialize)]
pub struct TpslCreateOrderResponse;

#[derive(Debug, Serialize)]
pub struct TpslCreateSessionTokenRequest;
#[derive(Debug, Deserialize, Serialize)]
pub struct TpslCreateSessionTokenResponse;

#[derive(Debug, Serialize)]
pub struct TpslPaymentMethodTokenRequest;
#[derive(Debug, Deserialize, Serialize)]
pub struct TpslPaymentMethodTokenResponse;

#[derive(Debug, Serialize)]
pub struct TpslCreateAccessTokenRequest;
#[derive(Debug, Deserialize, Serialize)]
pub struct TpslCreateAccessTokenResponse;

#[derive(Debug, Serialize)]
pub struct TpslCreateConnectorCustomerRequest;
#[derive(Debug, Deserialize, Serialize)]
pub struct TpslCreateConnectorCustomerResponse;

#[derive(Debug, Serialize)]
pub struct TpslVoidPCRequest;
#[derive(Debug, Deserialize, Serialize)]
pub struct TpslVoidPCResponse;

// CRITICAL: Dynamic extraction functions - NEVER HARDCODE VALUES
fn get_merchant_code(
    connector_auth_type: &ConnectorAuthType,
) -> Result<Secret<String>, errors::ConnectorError> {
    match TpslAuthType::try_from(connector_auth_type) {
        Ok(tpsl_auth) => Ok(tpsl_auth.merchant_code),
        Err(_) => Err(errors::ConnectorError::FailedToObtainAuthType),
    }
}

// CRITICAL: Implement TryFrom for Authorize flow with proper router data extraction
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<
        TPSLRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    > for TpslPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: TPSLRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        // CRITICAL: Extract customer ID dynamically - NEVER HARDCODE
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let customer_id_string = customer_id.get_string_repr();

        // CRITICAL: Extract merchant code from auth type - NEVER HARDCODE
        let merchant_code = get_merchant_code(&item.router_data.connector_auth_type)?;

        // CRITICAL: Use amount converter properly - NEVER HARDCODE AMOUNTS
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;
        let currency = item.router_data.request.currency.to_string();

        // CRITICAL: Extract transaction ID dynamically - NEVER HARDCODE
        let transaction_id = item.router_data.resource_common_data.connector_request_reference_id.clone();

        // CRITICAL: Extract return URL dynamically - NEVER HARDCODE
        let _return_url = item.router_data.request.get_router_return_url()?;

        // CRITICAL: Extract email dynamically - NEVER HARDCODE
        let _email = item.router_data.request.email.clone().unwrap_or_default();

        match item.router_data.resource_common_data.payment_method {
            common_enums::PaymentMethod::Upi => Ok(Self {
                merchant: TpslMerchantDataType {
                    identifier: merchant_code.peek().clone(),
                },
                cart: TpslUPITokenCart {
                    item: vec![TpslUPIItem {
                        amount: amount.to_string(),
                        com_amt: "0".to_string(),
                        s_k_u: "UPI".to_string(),
                        reference: transaction_id.clone(),
                        identifier: customer_id_string.to_string(),
                    }],
                    description: Some("UPI Payment".to_string()),
                },
                transaction: TpslUPITokenTxn {
                    amount: amount.to_string(),
                    txn_type: "SALE".to_string(),
                    currency,
                    identifier: transaction_id.clone(),
                    sub_type: "UPI".to_string(),
                    request_type: "SALE".to_string(),
                },
                consumer: TpslConsumerDataType {
                    identifier: customer_id_string.to_string(),
                },
            }),
            _ => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("TPSL"),
            )
            .into()),
        }
    }
}

// CRITICAL: Implement TryFrom for PSync flow with proper router data extraction
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<
        TPSLRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    > for TpslPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: TPSLRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        // CRITICAL: Extract customer ID dynamically - NEVER HARDCODE
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let customer_id_string = customer_id.get_string_repr();

        // CRITICAL: Extract merchant code from auth type - NEVER HARDCODE
        let merchant_code = get_merchant_code(&item.router_data.connector_auth_type)?;

        // CRITICAL: Use amount converter properly - NEVER HARDCODE AMOUNTS
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;
        let currency = item.router_data.request.currency.to_string();

        // CRITICAL: Extract transaction ID dynamically - NEVER HARDCODE
        let transaction_id = item.router_data.resource_common_data.connector_request_reference_id.clone();

        Ok(Self {
            merchant: TpslMerchantDataType {
                identifier: merchant_code.peek().clone(),
            },
            cart: TpslUPITokenCart {
                item: vec![TpslUPIItem {
                    amount: amount.to_string(),
                    com_amt: "0".to_string(),
                    s_k_u: "UPI".to_string(),
                    reference: transaction_id.clone(),
                    identifier: customer_id_string.to_string(),
                }],
                description: Some("UPI Sync".to_string()),
            },
            transaction: TpslUPITokenTxn {
                amount: amount.to_string(),
                txn_type: "STATUS".to_string(),
                currency,
                identifier: transaction_id.clone(),
                sub_type: "UPI".to_string(),
                request_type: "STATUS".to_string(),
            },
            consumer: TpslConsumerDataType {
                identifier: customer_id_string.to_string(),
            },
        })
    }
}

// Status mapping functions
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

// CRITICAL: Response transformation for Authorize flow
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
            TpslPaymentsResponse { .. } => {
                let redirection_data = get_redirect_form_data(
                    common_enums::PaymentMethodType::UpiCollect,
                    &response,
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

// CRITICAL: Response transformation for PSync flow
impl TryFrom<ResponseRouterData<TpslPaymentsSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<TpslPaymentsSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            TpslPaymentsSyncResponse { .. } => {
                let status = map_transaction_status(&response.transaction_state);
                let _amount_received = response
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
                        network_txn_id: response.payment_method.payment_transaction.identifier,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
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
    response_data: &TpslPaymentsResponse,
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

// CRITICAL: TryFrom implementations for all request/response types
// These are required for the macro framework to work properly

// PostAuthenticate flow
impl<T: PaymentMethodDataTypes> TryFrom<TPSLRouterData<RouterDataV2<PostAuthenticate, PaymentFlowData, PaymentsPostAuthenticateData<T>, PaymentsResponseData>, T>>
    for TpslPostAuthenticateRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(_item: TPSLRouterData<RouterDataV2<PostAuthenticate, PaymentFlowData, PaymentsPostAuthenticateData<T>, PaymentsResponseData>, T>) -> Result<Self, Self::Error> {
        Ok(TpslPostAuthenticateRequest)
    }
}

impl<T: PaymentMethodDataTypes> TryFrom<ResponseRouterData<TpslPostAuthenticateResponse, RouterDataV2<PostAuthenticate, PaymentFlowData, PaymentsPostAuthenticateData<T>, PaymentsResponseData>>>
    for RouterDataV2<PostAuthenticate, PaymentFlowData, PaymentsPostAuthenticateData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(item: ResponseRouterData<TpslPostAuthenticateResponse, RouterDataV2<PostAuthenticate, PaymentFlowData, PaymentsPostAuthenticateData<T>, PaymentsResponseData>>) -> Result<Self, Self::Error> {
        Ok(item.router_data)
    }
}

// Authenticate flow
impl<T: PaymentMethodDataTypes> TryFrom<TPSLRouterData<RouterDataV2<Authenticate, PaymentFlowData, PaymentsAuthenticateData<T>, PaymentsResponseData>, T>>
    for TpslAuthenticateRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(_item: TPSLRouterData<RouterDataV2<Authenticate, PaymentFlowData, PaymentsAuthenticateData<T>, PaymentsResponseData>, T>) -> Result<Self, Self::Error> {
        Ok(TpslAuthenticateRequest)
    }
}

impl<T: PaymentMethodDataTypes> TryFrom<ResponseRouterData<TpslAuthenticateResponse, RouterDataV2<Authenticate, PaymentFlowData, PaymentsAuthenticateData<T>, PaymentsResponseData>>>
    for RouterDataV2<Authenticate, PaymentFlowData, PaymentsAuthenticateData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(item: ResponseRouterData<TpslAuthenticateResponse, RouterDataV2<Authenticate, PaymentFlowData, PaymentsAuthenticateData<T>, PaymentsResponseData>>) -> Result<Self, Self::Error> {
        Ok(item.router_data)
    }
}

// PreAuthenticate flow
impl<T: PaymentMethodDataTypes> TryFrom<TPSLRouterData<RouterDataV2<PreAuthenticate, PaymentFlowData, PaymentsPreAuthenticateData<T>, PaymentsResponseData>, T>>
    for TpslPreAuthenticateRequest
{
    fn from(_item: TPSLRouterData<RouterDataV2<PreAuthenticate, PaymentFlowData, PaymentsPreAuthenticateData<T>, PaymentsResponseData>, T>) -> Self {
        TpslPreAuthenticateRequest
    }
}

impl<T: PaymentMethodDataTypes> From<ResponseRouterData<TpslPreAuthenticateResponse, RouterDataV2<PreAuthenticate, PaymentFlowData, PaymentsPreAuthenticateData<T>, PaymentsResponseData>>>
    for RouterDataV2<PreAuthenticate, PaymentFlowData, PaymentsPreAuthenticateData<T>, PaymentsResponseData>
{
    fn from(item: ResponseRouterData<TpslPreAuthenticateResponse, RouterDataV2<PreAuthenticate, PaymentFlowData, PaymentsPreAuthenticateData<T>, PaymentsResponseData>>) -> Self {
        item.router_data
    }
}

// Void flow
impl<T: PaymentMethodDataTypes> TryFrom<TPSLRouterData<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, T>>
    for TpslVoidRequest
{
    fn from(_item: TPSLRouterData<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, T>) -> Self {
        TpslVoidRequest
    }
}

impl<T: PaymentMethodDataTypes> From<ResponseRouterData<TpslVoidResponse, RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    fn from(item: ResponseRouterData<TpslVoidResponse, RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>) -> Self {
        item.router_data
    }
}

// Capture flow
impl<T: PaymentMethodDataTypes> TryFrom<TPSLRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, T>>
    for TpslCaptureRequest
{
    fn from(_item: TPSLRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, T>) -> Self {
        TpslCaptureRequest
    }
}

impl<T: PaymentMethodDataTypes> From<ResponseRouterData<TpslCaptureResponse, RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    fn from(item: ResponseRouterData<TpslCaptureResponse, RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>) -> Self {
        item.router_data
    }
}

// Refund flow
impl<T: PaymentMethodDataTypes> TryFrom<TPSLRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>>
    for TpslRefundRequest
{
    fn from(_item: TPSLRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>) -> Self {
        TpslRefundRequest
    }
}

impl<T: PaymentMethodDataTypes> From<ResponseRouterData<TpslRefundResponse, RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    fn from(item: ResponseRouterData<TpslRefundResponse, RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>) -> Self {
        item.router_data
    }
}

// RSync flow
impl<T: PaymentMethodDataTypes> TryFrom<TPSLRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>>
    for TpslRSyncRequest
{
    fn from(_item: TPSLRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>) -> Self {
        TpslRSyncRequest
    }
}

impl<T: PaymentMethodDataTypes> From<ResponseRouterData<TpslRSyncResponse, RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    fn from(item: ResponseRouterData<TpslRSyncResponse, RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>) -> Self {
        item.router_data
    }
}

// SetupMandate flow
impl<T: PaymentMethodDataTypes> TryFrom<TPSLRouterData<RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>, T>>
    for TpslSetupMandateRequest
{
    fn from(_item: TPSLRouterData<RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>, T>) -> Self {
        TpslSetupMandateRequest
    }
}

impl<T: PaymentMethodDataTypes> From<ResponseRouterData<TpslSetupMandateResponse, RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>>>
    for RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>
{
    fn from(item: ResponseRouterData<TpslSetupMandateResponse, RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>>) -> Self {
        item.router_data
    }
}

// RepeatPayment flow
impl<T: PaymentMethodDataTypes> TryFrom<TPSLRouterData<RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>, T>>
    for TpslRepeatPaymentRequest
{
    fn from(_item: TPSLRouterData<RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>, T>) -> Self {
        TpslRepeatPaymentRequest
    }
}

impl<T: PaymentMethodDataTypes> From<ResponseRouterData<TpslRepeatPaymentResponse, RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>>>
    for RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
{
    fn from(item: ResponseRouterData<TpslRepeatPaymentResponse, RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>>) -> Self {
        item.router_data
    }
}

// AcceptDispute flow
impl<T: PaymentMethodDataTypes> TryFrom<TPSLRouterData<RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>, T>>
    for TpslAcceptDisputeRequest
{
    fn from(_item: TPSLRouterData<RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>, T>) -> Self {
        TpslAcceptDisputeRequest
    }
}

impl<T: PaymentMethodDataTypes> From<ResponseRouterData<TpslAcceptDisputeResponse, RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>>>
    for RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>
{
    fn from(item: ResponseRouterData<TpslAcceptDisputeResponse, RouterDataV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData>>) -> Self {
        item.router_data
    }
}

// SubmitEvidence flow
impl<T: PaymentMethodDataTypes> TryFrom<TPSLRouterData<RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>, T>>
    for TpslSubmitEvidenceRequest
{
    fn from(_item: TPSLRouterData<RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>, T>) -> Self {
        TpslSubmitEvidenceRequest
    }
}

impl<T: PaymentMethodDataTypes> From<ResponseRouterData<TpslSubmitEvidenceResponse, RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>>>
    for RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>
{
    fn from(item: ResponseRouterData<TpslSubmitEvidenceResponse, RouterDataV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData>>) -> Self {
        item.router_data
    }
}

// DefendDispute flow
impl<T: PaymentMethodDataTypes> TryFrom<TPSLRouterData<RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>, T>>
    for TpslDefendDisputeRequest
{
    fn from(_item: TPSLRouterData<RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>, T>) -> Self {
        TpslDefendDisputeRequest
    }
}

impl<T: PaymentMethodDataTypes> From<ResponseRouterData<TpslDefendDisputeResponse, RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>>>
    for RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>
{
    fn from(item: ResponseRouterData<TpslDefendDisputeResponse, RouterDataV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData>>) -> Self {
        item.router_data
    }
}

// CreateOrder flow
impl<T: PaymentMethodDataTypes> TryFrom<TPSLRouterData<RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>, T>>
    for TpslCreateOrderRequest
{
    fn from(_item: TPSLRouterData<RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>, T>) -> Self {
        TpslCreateOrderRequest
    }
}

impl<T: PaymentMethodDataTypes> From<ResponseRouterData<TpslCreateOrderResponse, RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>>>
    for RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>
{
    fn from(item: ResponseRouterData<TpslCreateOrderResponse, RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>>) -> Self {
        item.router_data
    }
}

// CreateSessionToken flow
impl<T: PaymentMethodDataTypes> TryFrom<TPSLRouterData<RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>, T>>
    for TpslCreateSessionTokenRequest
{
    fn from(_item: TPSLRouterData<RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>, T>) -> Self {
        TpslCreateSessionTokenRequest
    }
}

impl<T: PaymentMethodDataTypes> From<ResponseRouterData<TpslCreateSessionTokenResponse, RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>>>
    for RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>
{
    fn from(item: ResponseRouterData<TpslCreateSessionTokenResponse, RouterDataV2<CreateSessionToken, PaymentFlowData, SessionTokenRequestData, SessionTokenResponseData>>) -> Self {
        item.router_data
    }
}

// PaymentMethodToken flow
impl<T: PaymentMethodDataTypes> TryFrom<TPSLRouterData<RouterDataV2<PaymentMethodToken, PaymentFlowData, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>, T>>
    for TpslPaymentMethodTokenRequest
{
    fn from(_item: TPSLRouterData<RouterDataV2<PaymentMethodToken, PaymentFlowData, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>, T>) -> Self {
        TpslPaymentMethodTokenRequest
    }
}

impl<T: PaymentMethodDataTypes> From<ResponseRouterData<TpslPaymentMethodTokenResponse, RouterDataV2<PaymentMethodToken, PaymentFlowData, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>>>
    for RouterDataV2<PaymentMethodToken, PaymentFlowData, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>
{
    fn from(item: ResponseRouterData<TpslPaymentMethodTokenResponse, RouterDataV2<PaymentMethodToken, PaymentFlowData, PaymentMethodTokenizationData<T>, PaymentMethodTokenResponse>>) -> Self {
        item.router_data
    }
}

// CreateAccessToken flow
impl<T: PaymentMethodDataTypes> TryFrom<TPSLRouterData<RouterDataV2<CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData>, T>>
    for TpslCreateAccessTokenRequest
{
    fn from(_item: TPSLRouterData<RouterDataV2<CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData>, T>) -> Self {
        TpslCreateAccessTokenRequest
    }
}

impl<T: PaymentMethodDataTypes> From<ResponseRouterData<TpslCreateAccessTokenResponse, RouterDataV2<CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData>>>
    for RouterDataV2<CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData>
{
    fn from(item: ResponseRouterData<TpslCreateAccessTokenResponse, RouterDataV2<CreateAccessToken, PaymentFlowData, AccessTokenRequestData, AccessTokenResponseData>>) -> Self {
        item.router_data
    }
}

// CreateConnectorCustomer flow
impl<T: PaymentMethodDataTypes> TryFrom<TPSLRouterData<RouterDataV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>, T>>
    for TpslCreateConnectorCustomerRequest
{
    fn from(_item: TPSLRouterData<RouterDataV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>, T>) -> Self {
        TpslCreateConnectorCustomerRequest
    }
}

impl<T: PaymentMethodDataTypes> From<ResponseRouterData<TpslCreateConnectorCustomerResponse, RouterDataV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>>>
    for RouterDataV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>
{
    fn from(item: ResponseRouterData<TpslCreateConnectorCustomerResponse, RouterDataV2<CreateConnectorCustomer, PaymentFlowData, ConnectorCustomerData, ConnectorCustomerResponse>>) -> Self {
        item.router_data
    }
}

// VoidPC flow
impl<T: PaymentMethodDataTypes> TryFrom<TPSLRouterData<RouterDataV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>, T>>
    for TpslVoidPCRequest
{
    fn from(_item: TPSLRouterData<RouterDataV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>, T>) -> Self {
        TpslVoidPCRequest
    }
}

impl<T: PaymentMethodDataTypes> From<ResponseRouterData<TpslVoidPCResponse, RouterDataV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>>>
    for RouterDataV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>
{
    fn from(item: ResponseRouterData<TpslVoidPCResponse, RouterDataV2<VoidPC, PaymentFlowData, PaymentsCancelPostCaptureData, PaymentsResponseData>>) -> Self {
        item.router_data
    }
}