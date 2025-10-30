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
};

use hyperswitch_masking::{Secret, ExposeInterface, PeekInterface, Mask, Maskable};
use serde::{Deserialize, Serialize};

use crate::{connectors::billdesk::BilldeskRouterData, types::ResponseRouterData};

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsRequest {
    msg: String,
    useragent: Option<String>,
    ipaddress: Option<String>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsSyncRequest {
    msg: String,
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
    pub rdata: Option<BilldeskRData>,
    pub txnrefno: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskRData {
    pub parameters: HashMap<String, String>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsSyncResponse {
    pub msg: Option<String>,
    pub txn_reference_no: Option<String>,
    pub bank_reference_no: Option<String>,
    pub txn_amount: Option<String>,
    pub bank_id: Option<String>,
    pub txn_type: Option<String>,
    pub currency_type: Option<String>,
    pub item_code: Option<String>,
    pub txn_date: Option<String>,
    pub auth_status: Option<String>,
    pub error_status: Option<String>,
    pub error_description: Option<String>,
    pub checksum: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskAuth {
    pub merchant_id: Secret<String>,
    pub checksum_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for BilldeskAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret: _,
            } => Ok(Self {
                merchant_id: api_key.clone(),
                checksum_key: key1.clone(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

pub fn get_billdesk_auth_header(auth: &BilldeskAuth) -> CustomResult<Maskable<String>, errors::ConnectorError> {
    // Billdesk uses custom authentication with merchant ID and checksum
    // For now, return a basic auth header - this will need to be implemented
    // based on Billdesk's specific authentication requirements
    Ok(format!("Bearer {}", auth.merchant_id.peek()).into_masked())
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> TryFrom<
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
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        // For now, use a simple amount conversion - this will need to be properly implemented
        let amount = item.router_data.request.minor_amount.to_string();

        // Only support UPI payments
        match item.router_data.resource_common_data.payment_method {
            common_enums::PaymentMethod::Upi => {
                // Create the message payload for Billdesk UPI initiation
                let msg_payload = create_upi_initiate_message(
                    &item.router_data,
                    &customer_id.get_string_repr(),
                    &amount,
                )?;

                let ip_address = item.router_data.request.get_ip_address_as_optional()
                    .map(|ip| ip.expose())
                    .unwrap_or_else(|| "127.0.0.1".to_string());

                let user_agent = item.router_data.request.browser_info
                    .as_ref()
                    .and_then(|info| info.user_agent.clone())
                    .unwrap_or_else(|| "Mozilla/5.0".to_string());

                Ok(Self {
                    msg: msg_payload,
                    useragent: Some(user_agent),
                    ipaddress: Some(ip_address),
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                "Payment method not supported".to_string(),
            )
            .into()),
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> TryFrom<
        BilldeskRouterData<
            RouterDataV2<
                PSync,
                PaymentFlowData,
                PaymentsSyncData,
                PaymentsResponseData,
            >,
            T,
        >,
    > for BilldeskPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: BilldeskRouterData<
            RouterDataV2<
                PSync,
                PaymentFlowData,
                PaymentsSyncData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let connector_transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        // Create the message payload for Billdesk status check
        let msg_payload = create_status_check_message(&connector_transaction_id)?;

        Ok(Self {
            msg: msg_payload,
        })
    }
}

fn create_upi_initiate_message(
    router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<impl PaymentMethodDataTypes>, PaymentsResponseData>,
    customer_id: &str,
    amount: &str,
) -> CustomResult<String, errors::ConnectorError> {
    // Based on the Haskell implementation, create the UPI initiate message
    // This is a simplified version - actual implementation would need to match Billdesk's exact format
    
    let merchant_id = match &router_data.connector_auth_type {
        ConnectorAuthType::SignatureKey { api_key, .. } => api_key.peek(),
        _ => return Err(errors::ConnectorError::FailedToObtainAuthType.into()),
    };

    let transaction_id = &router_data.resource_common_data.connector_request_reference_id;
    let currency = router_data.request.currency.to_string();
    let return_url = router_data.request.get_router_return_url()?;

    // Create the message in the format expected by Billdesk
    // This is based on the BilldeskNBInitiateRequest structure from the Haskell code
    let msg = format!(
        "MerchantID={}&CustomerID={}&TxnReferenceNo={}&TxnAmount={}&Currency={}&ItemCode=UPI&ReturnURL={}",
        merchant_id,
        customer_id,
        transaction_id,
        amount,
        currency,
        return_url
    );

    Ok(msg)
}

fn create_status_check_message(transaction_id: &str) -> CustomResult<String, errors::ConnectorError> {
    // Create the message for status check
    // Based on BilldeskOnlineStatusRequest from Haskell implementation
    let msg = format!(
        "TxnReferenceNo={}",
        transaction_id
    );

    Ok(msg)
}

fn get_redirect_form_data(
    response_data: BilldeskPaymentsResponseData,
) -> CustomResult<RedirectForm, errors::ConnectorError> {
    match response_data.rdata {
        Some(rdata) => {
            let url = rdata.url.ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "redirect_url",
            })?;
            
            Ok(RedirectForm::Form {
                endpoint: url,
                method: Method::Post,
                form_fields: rdata
                    .parameters
                    .into_iter()
                    .collect(),
            })
        }
        None => Err(errors::ConnectorError::MissingRequiredField {
            field_name: "rdata",
        }.into()),
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

impl<
    F,
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

        let status = match response.auth_status.as_deref() {
            Some("0300") | Some("Success") => common_enums::AttemptStatus::Charged,
            Some("0399") | Some("Failure") => common_enums::AttemptStatus::Failure,
            Some("0001") | Some("Pending") => common_enums::AttemptStatus::AuthenticationPending,
            _ => common_enums::AttemptStatus::Pending,
        };

        let _amount_received = response.txn_amount.as_ref().and_then(|amt| {
            amt.parse::<f64>()
                .ok()
                .map(|major_amount| {
                    let minor_amount = (major_amount * 100.0) as i64;
                    common_utils::types::MinorUnit::new(minor_amount)
                })
        });

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    response.txn_reference_no.clone().unwrap_or_default(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: response.bank_reference_no,
                connector_response_reference_id: response.txn_reference_no,
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskErrorResponse {
    pub error: serde_json::Value,
    pub error_description: String,
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