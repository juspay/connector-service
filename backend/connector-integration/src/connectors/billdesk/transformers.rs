use std::collections::HashMap;

use common_utils::{
    errors::CustomResult,
    request::Method,
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
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use crate::{connectors::billdesk::BilldeskRouterData, types::ResponseRouterData};

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsRequest {
    msg: String,
    paydata: Option<String>,
    ipaddress: Option<String>,
    useragent: Option<String>,
    txtBankID: Option<String>,
}

#[derive(Default, Debug, Serialize)]
pub struct BilldeskPaymentsSyncRequest {
    msg: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BilldeskPaymentsResponse {
    BilldeskError(BilldeskErrorResponse),
    BilldeskInitNB(BilldeskNBInitiateResponse),
    BilldeskAU(BilldeskAuthorizationResponse),
    BilldeskInitCard(BilldeskInitiateCardTxnResponse),
    BilldeskInitNonCard(BilldeskV2NonCardResponse),
    BilldeskEnachResp(BilldeskEnachResponse),
    BilldeskEnachDecryptResp(BilldeskEnachDecryptResponse),
    BilldeskRecurringEnachResp(RecurringEnachTxnResponse),
    SuccessSyncResponse(StatusResponseMsg),
    ErrorSyncResponse(BilldeskErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskPaymentsSyncResponse {
    #[serde(flatten)]
    pub response_data: StatusResponseMsg,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskNBInitiateResponse {
    msg: Option<String>,
    rdata: NBrdataResp,
    txnrefno: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NBrdataResp {
    parameters: HashMap<String, String>,
    url: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskAuthorizationResponse {
    msg: String,
    txnrefno: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskInitiateCardTxnResponse {
    msg: Option<String>,
    rdata: InitiateSuccessResp,
    txnrefno: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct InitiateSuccessResp {
    parameters: HashMap<String, String>,
    url: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskV2NonCardResponse {
    transaction_response: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskEnachResponse;

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskEnachDecryptResponse;

#[derive(Debug, Deserialize, Serialize)]
pub struct RecurringEnachTxnResponse;

#[derive(Debug, Deserialize, Serialize)]
pub struct StatusResponseMsg {
    #[serde(rename = "RequestType")]
    pub request_type: Option<String>,
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    #[serde(rename = "CustomerID")]
    pub customer_id: String,
    #[serde(rename = "TxnReferenceNo")]
    pub txn_reference_no: String,
    #[serde(rename = "BankReferenceNo")]
    pub bank_reference_no: String,
    #[serde(rename = "TxnAmount")]
    pub txn_amount: String,
    #[serde(rename = "BankID")]
    pub bank_id: String,
    #[serde(rename = "Filler1")]
    pub filler1: Option<String>,
    #[serde(rename = "TxnType")]
    pub txn_type: Option<String>,
    #[serde(rename = "CurrencyType")]
    pub currency_type: String,
    #[serde(rename = "ItemCode")]
    pub item_code: String,
    #[serde(rename = "Filler2")]
    pub filler2: Option<String>,
    #[serde(rename = "Filler3")]
    pub filler3: Option<String>,
    #[serde(rename = "Filler4")]
    pub filler4: Option<String>,
    #[serde(rename = "TxnDate")]
    pub txn_date: Option<String>,
    #[serde(rename = "AuthStatus")]
    pub auth_status: String,
    #[serde(rename = "Filler5")]
    pub filler5: Option<String>,
    #[serde(rename = "AdditionalInfo1")]
    pub additional_info1: Option<String>,
    #[serde(rename = "AdditionalInfo2")]
    pub additional_info2: Option<String>,
    #[serde(rename = "AdditionalInfo3")]
    pub additional_info3: Option<String>,
    #[serde(rename = "AdditionalInfo4")]
    pub additional_info4: Option<String>,
    #[serde(rename = "AdditionalInfo5")]
    pub additional_info5: Option<String>,
    #[serde(rename = "AdditionalInfo6")]
    pub additional_info6: Option<String>,
    #[serde(rename = "AdditionalInfo7")]
    pub additional_info7: Option<String>,
    #[serde(rename = "ErrorStatus")]
    pub error_status: String,
    #[serde(rename = "ErrorDescription")]
    pub error_description: String,
    #[serde(rename = "Filler6")]
    pub filler6: Option<String>,
    #[serde(rename = "RefundStatus")]
    pub refund_status: String,
    #[serde(rename = "TotalRefundAmount")]
    pub total_refund_amount: String,
    #[serde(rename = "LastRefundDate")]
    pub last_refund_date: Option<String>,
    #[serde(rename = "LastRefundRefNo")]
    pub last_refund_ref_no: Option<String>,
    #[serde(rename = "QueryStatus")]
    pub query_status: String,
    #[serde(rename = "Checksum")]
    pub checksum: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskAuthType {
    pub merchant_id: Secret<String>,
    pub checksum_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for BilldeskAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1, .. } => {
                Ok(Self {
                    merchant_id: api_key.clone(),
                    checksum_key: key1.clone(),
                })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

impl TryFrom<&ConnectorAuthType> for BilldeskAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        let auth = BilldeskAuthType::try_from(auth_type)?;
        Ok(Self {
            merchant_id: auth.merchant_id,
            checksum_key: auth.checksum_key,
        })
    }
}

#[derive(Debug, Clone)]
pub struct BilldeskAuth {
    pub merchant_id: Secret<String>,
    pub checksum_key: Secret<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BilldeskPaymentStatus {
    #[default]
    Pending,
    Success,
    Failure,
}

impl From<BilldeskPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: BilldeskPaymentStatus) -> Self {
        match item {
            BilldeskPaymentStatus::Success => Self::Charged,
            BilldeskPaymentStatus::Failure => Self::Failure,
            BilldeskPaymentStatus::Pending => Self::AuthenticationPending,
        }
    }
}

fn construct_billdesk_message<T: PaymentMethodDataTypes>(
    router_data: &BilldeskRouterData<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        T,
    >,
) -> Result<String, errors::ConnectorError> {
    let customer_id = router_data
        .router_data
        .resource_common_data
        .get_customer_id()?;
    let amount = router_data
        .connector
        .amount_converter
        .convert(
            router_data.router_data.request.minor_amount,
            router_data.router_data.request.currency,
        )
        .change_context(ConnectorError::RequestEncodingFailed)?;
    
    let transaction_id = router_data
        .router_data
        .resource_common_data
        .connector_request_reference_id;

    // Construct the message based on Billdesk format
    // This is a simplified version - actual implementation would follow Billdesk's specific format
    let message = format!(
        "MerchantID={}&CustomerID={}&TxnReferenceNo={}&TxnAmount={}&CurrencyType={}&ItemCode=DIRECT&Checksum={}",
        "MERCHANT_ID", // This should come from auth
        customer_id,
        transaction_id,
        amount,
        router_data.router_data.request.currency,
        "CHECKSUM" // This should be calculated
    );

    Ok(message)
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
        BilldeskRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for BilldeskPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: BilldeskRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let ip_address = item
            .router_data
            .request
            .get_ip_address_as_optional()
            .map(|ip| ip.expose())
            .unwrap_or_else(|| "127.0.0.1".to_string());

        let user_agent = item
            .router_data
            .request
            .browser_info
            .as_ref()
            .and_then(|info| info.user_agent.clone())
            .unwrap_or_else(|| "Mozilla/5.0".to_string());

        let message = construct_billdesk_message(&item)?;

        match item.router_data.resource_common_data.payment_method {
            common_enums::PaymentMethod::Upi => {
                let paydata = Some(format!(
                    "UPI|{}|{}|{}",
                    item.router_data.request.payment_method_data.as_ref()
                        .and_then(|pm| pm.get_upi_data())
                        .and_then(|upi| upi.vpa.clone())
                        .unwrap_or_else(|| "".to_string()),
                    item.router_data.request.minor_amount,
                    item.router_data.request.currency
                ));

                Ok(Self {
                    msg: message,
                    paydata,
                    ipaddress: Some(ip_address),
                    useragent: Some(user_agent),
                    txtBankID: None,
                })
            }
            common_enums::PaymentMethod::PayLater => {
                // Handle PayLater if needed
                Ok(Self {
                    msg: message,
                    paydata: None,
                    ipaddress: Some(ip_address),
                    useragent: Some(user_agent),
                    txtBankID: None,
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                "Payment method".to_string(),
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
            + Serialize,
    >
    TryFrom<
        BilldeskRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for BilldeskPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: BilldeskRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let transaction_id = item
            .router_data
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        let message = format!(
            "MerchantID={}&TxnReferenceNo={}&Checksum={}",
            "MERCHANT_ID", // This should come from auth
            transaction_id,
            "CHECKSUM" // This should be calculated
        );

        Ok(Self { msg: message })
    }
}

fn get_redirect_form_data(
    payment_method_type: common_enums::PaymentMethodType,
    response_data: &InitiateSuccessResp,
) -> CustomResult<RedirectForm, errors::ConnectorError> {
    match payment_method_type {
        common_enums::PaymentMethodType::UpiCollect => Ok(RedirectForm::Form {
            endpoint: response_data.url.clone(),
            method: Method::Post,
            form_fields: response_data
                .parameters
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        }),
        _ => Err(errors::ConnectorError::NotImplemented(
            utils::get_unimplemented_payment_method_error_message("Billdesk"),
        ))?,
    }
}

impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<ResponseRouterData<BilldeskPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<BilldeskPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        let (status, response) = match response {
            BilldeskPaymentsResponse::BilldeskError(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.error.to_string(),
                    status_code: item.http_code,
                    message: error_data.error_description.clone().unwrap_or_default(),
                    reason: error_data.error_description.clone(),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            BilldeskPaymentsResponse::BilldeskInitNB(response_data) => {
                let payment_method_type = router_data
                    .request
                    .payment_method_type
                    .ok_or(errors::ConnectorError::MissingPaymentMethodType)?;
                // For NB initiate response, we need to handle differently
                let redirection_data = Ok(RedirectForm::Form {
                    endpoint: response_data.rdata.url.clone(),
                    method: Method::Post,
                    form_fields: response_data
                        .rdata
                        .parameters
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
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
            BilldeskPaymentsResponse::BilldeskInitCard(response_data) => {
                let payment_method_type = router_data
                    .request
                    .payment_method_type
                    .ok_or(errors::ConnectorError::MissingPaymentMethodType)?;
                // For NB initiate response, we need to handle differently
                let redirection_data = Ok(RedirectForm::Form {
                    endpoint: response_data.rdata.url.clone(),
                    method: Method::Post,
                    form_fields: response_data
                        .rdata
                        .parameters
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
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
            BilldeskPaymentsResponse::BilldeskInitNonCard(_) => (
                common_enums::AttemptStatus::AuthenticationPending,
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
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    status_code: http_code,
                }),
            ),
            BilldeskPaymentsResponse::SuccessSyncResponse(response_data) => {
                let status = match response_data.auth_status.as_str() {
                    "0300" | "0399" => common_enums::AttemptStatus::Charged,
                    "0396" => common_enums::AttemptStatus::AuthenticationPending,
                    "0398" => common_enums::AttemptStatus::Failure,
                    _ => common_enums::AttemptStatus::Failure,
                };

                (
                    status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            response_data.txn_reference_no.clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: Some(response_data.bank_reference_no.clone()),
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            _ => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: "UNKNOWN_RESPONSE".to_string(),
                    status_code: item.http_code,
                    message: "Unknown response type".to_string(),
                    reason: Some("Unknown response type".to_string()),
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
    >
    TryFrom<ResponseRouterData<BilldeskPaymentsSyncResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<BilldeskPaymentsSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let status = match response.response_data.auth_status.as_str() {
            "0300" | "0399" => common_enums::AttemptStatus::Charged,
            "0396" => common_enums::AttemptStatus::AuthenticationPending,
            "0398" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Failure,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    response.response_data.txn_reference_no.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: Some(response.response_data.bank_reference_no.clone()),
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

// Stub types for unsupported flows
#[derive(Debug, Clone, Serialize)]
pub struct BilldeskVoidRequest;

#[derive(Debug, Clone)]
pub struct BilldeskVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskCaptureRequest;

#[derive(Debug, Clone)]
pub struct BilldeskCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskRefundRequest;

#[derive(Debug, Clone)]
pub struct BilldeskRefundResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskRefundSyncRequest;

#[derive(Debug, Clone)]
pub struct BilldeskRefundSyncResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskCreateOrderRequest;

#[derive(Debug, Clone)]
pub struct BilldeskCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskSessionTokenRequest;

#[derive(Debug, Clone)]
pub struct BilldeskSessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskSetupMandateRequest;

#[derive(Debug, Clone)]
pub struct BilldeskSetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskRepeatPaymentRequest;

#[derive(Debug, Clone)]
pub struct BilldeskRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskAcceptDisputeRequest;

#[derive(Debug, Clone)]
pub struct BilldeskAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskDefendDisputeRequest;

#[derive(Debug, Clone)]
pub struct BilldeskDefendDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskSubmitEvidenceRequest;

#[derive(Debug, Clone)]
pub struct BilldeskSubmitEvidenceResponse;