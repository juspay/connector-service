use std::collections::HashMap;

use common_utils::{
    errors::CustomResult,
    ext_traits::ValueExt,
    id_type,
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
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use crate::{connectors::billdesk::BilldeskRouterData, types::ResponseRouterData};

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsRequest {
    pub msg: String,
    pub useragent: Option<String>,
    pub ipaddress: Option<String>,
}

#[derive(Default, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskAuth {
    pub merchant_id: Option<Secret<String>>,
    pub checksum_key: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for BilldeskAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, .. } => {
                // TODO: Implement proper auth parsing from api_key
                // For now, return empty auth - this needs to be implemented based on actual auth format
                Ok(BilldeskAuth {
                    merchant_id: None,
                    checksum_key: None,
                })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
            BilldeskPaymentStatus::Pending => Self::AuthenticationPending,
            BilldeskPaymentStatus::Failure => Self::Failure,
        }
    }
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct BilldeskErrors {
    pub message: String,
    pub path: String,
    #[serde(rename = "type")]
    pub event_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BilldeskPaymentsResponse {
    BilldeskError(BilldeskErrorResponse),
    BilldeskData(BilldeskPaymentsResponseData),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsResponseData {
    pub msg: Option<String>,
    pub rdata: Option<BilldeskRdata>,
    pub txnrefno: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskRdata {
    pub parameters: Option<HashMap<String, String>>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsSyncResponse {
    pub msg: Option<String>,
    pub status: Option<BilldeskPaymentStatus>,
    pub txnrefno: Option<String>,
}

// PSync request type
#[derive(Debug, Clone, Serialize)]
pub struct BilldeskPaymentsSyncRequest {
    pub msg: String,
    pub useragent: Option<String>,
    pub ipaddress: Option<String>,
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
pub struct BilldeskSubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct BilldeskSubmitEvidenceResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct BilldeskDefendDisputeResponse;

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskErrorResponse {
    pub error: serde_json::Value,
    pub error_description: String,
    pub errors: Option<Vec<BilldeskErrors>>,
}

fn create_billdesk_message<T: PaymentMethodDataTypes>(
    router_data: &BilldeskRouterData<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        T,
    >,
) -> Result<String, errors::ConnectorError> {
    let customer_id = router_data.router_data.resource_common_data.get_customer_id()?;
    let amount = router_data
        .connector
        .amount_converter
        .convert(
            router_data.router_data.request.minor_amount,
            router_data.router_data.request.currency,
        )
        .change_context(ConnectorError::RequestEncodingFailed)?;

    // Create Billdesk message format based on UPI payment requirements
    let message = format!(
        "merchant_id={}&customer_id={}&amount={}&currency={}&order_id={}",
        customer_id.get_string_repr(),
        customer_id.get_string_repr(),
        amount,
        router_data.router_data.request.currency.to_string(),
        router_data.router_data.resource_common_data.connector_request_reference_id
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
        match item.router_data.resource_common_data.payment_method {
            common_enums::PaymentMethod::Upi => {
                let msg = create_billdesk_message(&item)?;
                
                // Extract IP address and user agent
                let ip_address = item.router_data.request.get_ip_address_as_optional()
                    .map(|ip| ip.expose())
                    .unwrap_or_else(|| "127.0.0.1".to_string());
                
                let user_agent = item.router_data.request.browser_info
                    .as_ref()
                    .and_then(|info| info.user_agent.clone())
                    .unwrap_or_else(|| "Mozilla/5.0".to_string());

                Ok(Self {
                    msg,
                    useragent: Some(user_agent),
                    ipaddress: Some(ip_address),
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("Billdesk"),
            )
            .into()),
        }
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
                    message: error_data.error_description.clone(),
                    reason: Some(error_data.error_description),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            BilldeskPaymentsResponse::BilldeskData(response_data) => {
                let payment_method_type = router_data
                    .request
                    .payment_method_type
                    .ok_or(errors::ConnectorError::MissingPaymentMethodType)?;
                
                // Handle UPI payment response
                match payment_method_type {
                    common_enums::PaymentMethodType::UpiIntent | common_enums::PaymentMethodType::UpiCollect => {
                        if let Some(rdata) = response_data.rdata {
                            if let Some(url) = rdata.url {
                                let redirection_data = RedirectForm::Form {
                                    endpoint: url,
                                    method: Method::Post,
                                    form_fields: rdata.parameters.unwrap_or_default(),
                                };
                                
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
                                        network_txn_id: response_data.txnrefno,
                                        connector_response_reference_id: None,
                                        incremental_authorization_allowed: None,
                                        status_code: http_code,
                                    }),
                                )
                            } else {
                                (
                                    common_enums::AttemptStatus::Failure,
                                    Err(ErrorResponse {
                                        code: "MISSING_REDIRECT_URL".to_string(),
                                        status_code: http_code,
                                        message: "No redirect URL provided by Billdesk".to_string(),
                                        reason: Some("Missing redirect URL in response".to_string()),
                                        attempt_status: None,
                                        connector_transaction_id: None,
                                        network_advice_code: None,
                                        network_decline_code: None,
                                        network_error_message: None,
                                    }),
                                )
                            }
                        } else {
                            (
                                common_enums::AttemptStatus::Failure,
                                Err(ErrorResponse {
                                    code: "MISSING_RESPONSE_DATA".to_string(),
                                    status_code: http_code,
                                    message: "No response data provided by Billdesk".to_string(),
                                    reason: Some("Missing response data".to_string()),
                                    attempt_status: None,
                                    connector_transaction_id: None,
                                    network_advice_code: None,
                                    network_decline_code: None,
                                    network_error_message: None,
                                }),
                            )
                        }
                    }
                    _ => (
                        common_enums::AttemptStatus::Failure,
                        Err(ErrorResponse {
                            code: "UNSUPPORTED_PAYMENT_METHOD".to_string(),
                            status_code: http_code,
                            message: format!("Payment method {:?} is not supported", payment_method_type),
                            reason: Some("Unsupported payment method".to_string()),
                            attempt_status: None,
                            connector_transaction_id: None,
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: None,
                        }),
                    ),
                }
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

// PSync implementation
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
        // Create sync request message
        let message = format!(
            "merchant_id={}&order_id={}",
            item.router_data.resource_common_data.get_customer_id()?.get_string_repr(),
            item.router_data.resource_common_data.connector_request_reference_id
        );

        Ok(Self {
            msg: message,
            useragent: None,
            ipaddress: None,
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
> TryFrom<ResponseRouterData<BilldeskPaymentsSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
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
        
        let status = response
            .status
            .map(|s| s.into())
            .unwrap_or(common_enums::AttemptStatus::Pending);

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    response
                        .txnrefno
                        .unwrap_or_else(|| router_data.resource_common_data.connector_request_reference_id.clone()),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: response.txnrefno,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}