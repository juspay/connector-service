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
    router_data::ErrorResponse,
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, ExposeInterface};
use serde::{Deserialize, Serialize};

use crate::{connectors::billdesk::BilldeskRouterData, types::ResponseRouterData};

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsRequest {
    pub msg: String,
    pub useragent: Option<String>,
    pub ipaddress: Option<String>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsSyncRequest {
    pub msg: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BilldeskPaymentsResponse {
    BilldeskError(BilldeskErrorResponse),
    BilldeskData(BilldeskPaymentsResponseData),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BilldeskPaymentsSyncResponse {
    BilldeskError(BilldeskErrorResponse),
    BilldeskData(BilldeskAuthorizationResponseMsg),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsResponseData {
    pub msg: Option<String>,
    pub rdata: Option<BilldeskRData>,
    pub txnrefno: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskRData {
    pub parameters: HashMap<String, String>,
    pub url: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskAuthorizationResponseMsg {
    pub _MerchantID: String,
    pub _CustomerID: String,
    pub _TxnReferenceNo: String,
    pub _BankReferenceNo: Option<String>,
    pub _TxnAmount: String,
    pub _BankID: Option<String>,
    pub _Filler1: Option<String>,
    pub _TxnType: Option<String>,
    pub _CurrencyType: String,
    pub _ItemCode: String,
    pub _Filler2: Option<String>,
    pub _Filler3: Option<String>,
    pub _Filler4: Option<String>,
    pub _TxnDate: Option<String>,
    pub _AuthStatus: String,
    pub _Filler5: Option<String>,
    pub _AdditionalInfo1: Option<String>,
    pub _AdditionalInfo2: Option<String>,
    pub _AdditionalInfo3: Option<String>,
    pub _AdditionalInfo4: Option<String>,
    pub _AdditionalInfo5: Option<String>,
    pub _AdditionalInfo6: Option<String>,
    pub _AdditionalInfo7: Option<String>,
    pub _ErrorStatus: String,
    pub _ErrorDescription: String,
    pub _Checksum: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
    pub error_code: String,
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
pub struct BilldeskMandateRequest;
#[derive(Debug, Clone)]
pub struct BilldeskMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct BilldeskRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct BilldeskCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskSessionTokenRequest;
#[derive(Debug, Clone)]
pub struct BilldeskSessionTokenResponse;

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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BilldeskPaymentStatus {
    Success,
    Pending,
    Failure,
    #[default]
    Unknown,
}

impl From<BilldeskPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: BilldeskPaymentStatus) -> Self {
        match item {
            BilldeskPaymentStatus::Success => Self::Charged,
            BilldeskPaymentStatus::Pending => Self::AuthenticationPending,
            BilldeskPaymentStatus::Failure => Self::Failure,
            BilldeskPaymentStatus::Unknown => Self::AuthenticationPending,
        }
    }
}

fn build_billdesk_message<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize, F>(
    router_data: &BilldeskRouterData<RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    is_sync: bool,
) -> CustomResult<String, errors::ConnectorError> {
    let customer_id = router_data.router_data.resource_common_data.get_customer_id()?;
    let customer_id_string = customer_id.get_string_repr();
    let amount = router_data
        .connector
        .amount_converter
        .convert(
            router_data.router_data.request.minor_amount,
            router_data.router_data.request.currency,
        )
        .change_context(ConnectorError::RequestEncodingFailed)?;

    let currency = router_data.router_data.request.currency.to_string();
    let transaction_id = router_data
        .router_data
        .resource_common_data
        .connector_request_reference_id
        .clone();

    // Build the message based on Billdesk's expected format
    let mut message_parts = Vec::new();
    
    if is_sync {
        // For sync requests, we typically need the transaction reference
        message_parts.push(format!("{}_{}", transaction_id, customer_id_string));
    } else {
        // For payment initiation, build the complete message
        message_parts.push(format!("{}_{}_{}_{}", transaction_id, customer_id_string, amount, currency));
        
        // Add additional fields based on payment method
        let payment_method = router_data.router_data.resource_common_data.payment_method;
        match payment_method {
            common_enums::PaymentMethod::Upi => {
                // Add UPI specific fields
                let upi_data = &router_data.router_data.request.payment_method_data;
                if let Some(upi_details) = upi_data.get_upi() {
                    message_parts.push(upi_details.vpa.clone());
                }
            }
            _ => {
                return Err(errors::ConnectorError::NotImplemented(
                    "Payment method not supported".to_string(),
                )
                .into());
            }
        }
    }

    Ok(message_parts.join("|"))
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
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    > for BilldeskPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: BilldeskRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let msg = build_billdesk_message(&item, false)?;
        
        let user_agent = item.router_data.request.browser_info
            .as_ref()
            .and_then(|info| info.user_agent.clone());
            
        let ip_address = item.router_data.request.get_ip_address_as_optional()
            .map(|ip| ip.expose());

        Ok(Self {
            msg,
            useragent: user_agent,
            ipaddress: ip_address,
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
        let msg = build_billdesk_message(&item, true)?;

        Ok(Self { msg })
    }
}

fn get_redirect_form_data(
    response_data: BilldeskPaymentsResponseData,
) -> CustomResult<RedirectForm, errors::ConnectorError> {
    if let Some(rdata) = response_data.rdata {
        if let Some(url) = rdata.url {
            Ok(RedirectForm::Form {
                endpoint: url,
                method: Method::Post,
                form_fields: rdata.parameters,
            })
        } else {
            Err(errors::ConnectorError::MissingRequiredField {
                field_name: "redirect_url",
            }
            .into())
        }
    } else {
        Err(errors::ConnectorError::MissingRequiredField {
            field_name: "rdata",
        }
        .into())
    }
}

impl<F> TryFrom<ResponseRouterData<BilldeskPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<domain_types::payment_method_data::DefaultPCIHolder>, PaymentsResponseData>
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
                    code: error_data.error_code.to_string(),
                    status_code: item.http_code,
                    message: error_data.error_description.clone().unwrap_or_default(),
                    reason: error_data.error_description,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            BilldeskPaymentsResponse::BilldeskData(response_data) => {
                let redirection_data = get_redirect_form_data(response_data)?;
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

impl<F> TryFrom<ResponseRouterData<BilldeskPaymentsSyncResponse, Self>>
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
        
        let (status, response) = match response {
            BilldeskPaymentsSyncResponse::BilldeskError(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.error_code.to_string(),
                    status_code: item.http_code,
                    message: error_data.error_description.clone().unwrap_or_default(),
                    reason: error_data.error_description,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            BilldeskPaymentsSyncResponse::BilldeskData(response_data) => {
                let status = match response_data._AuthStatus.as_str() {
                    "0300" | "0399" => common_enums::AttemptStatus::Charged,
                    "0396" => common_enums::AttemptStatus::AuthenticationPending,
                    "0397" => common_enums::AttemptStatus::Failure,
                    _ => common_enums::AttemptStatus::AuthenticationPending,
                };

                (
                    status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            response_data._TxnReferenceNo.clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: response_data._BankReferenceNo,
                        connector_response_reference_id: Some(response_data._TxnReferenceNo),
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