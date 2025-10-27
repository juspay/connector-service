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
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use crate::{connectors::billdesk::BilldeskRouterData, types::ResponseRouterData};
use hyperswitch_masking::ExposeInterface;

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
    pub rdata: Option<BilldeskRdata>,
    pub txnrefno: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskRdata {
    pub parameters: HashMap<String, String>,
    pub url: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsSyncResponse {
    #[serde(rename = "_MerchantID")]
    pub merchant_id: String,
    #[serde(rename = "_CustomerID")]
    pub customer_id: String,
    #[serde(rename = "_TxnReferenceNo")]
    pub txn_reference_no: String,
    #[serde(rename = "_BankReferenceNo")]
    pub bank_reference_no: String,
    #[serde(rename = "_TxnAmount")]
    pub txn_amount: String,
    #[serde(rename = "_BankID")]
    pub bank_id: String,
    #[serde(rename = "_TxnType")]
    pub txn_type: Option<String>,
    #[serde(rename = "_CurrencyType")]
    pub currency_type: String,
    #[serde(rename = "_ItemCode")]
    pub item_code: String,
    #[serde(rename = "_TxnDate")]
    pub txn_date: Option<String>,
    #[serde(rename = "_AuthStatus")]
    pub auth_status: String,
    #[serde(rename = "_ErrorStatus")]
    pub error_status: String,
    #[serde(rename = "_ErrorDescription")]
    pub error_description: String,
    #[serde(rename = "_Checksum")]
    pub checksum: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskErrorResponse {
    pub error: String,
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskAuth {
    pub merchant_id: Secret<String>,
    pub checksum_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for BilldeskAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1, .. } => {
                let merchant_id = api_key.clone();
                let checksum_key = key1.clone();
                
                Ok(Self {
                    merchant_id,
                    checksum_key,
                })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
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
            BilldeskPaymentStatus::Pending => Self::AuthenticationPending,
            BilldeskPaymentStatus::Failure => Self::Failure,
        }
    }
}

fn create_billdesk_message<T>(
    router_data: &BilldeskRouterData<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        T,
    >,
) -> CustomResult<String, errors::ConnectorError>
where
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
{
    let customer_id = router_data.router_data.resource_common_data.get_customer_id()?;
    let amount = router_data
        .connector
        .amount_converter
        .convert(
            router_data.router_data.request.minor_amount,
            router_data.router_data.request.currency,
        )
        .change_context(ConnectorError::RequestEncodingFailed)?;

    let message_data = HashMap::from([
        ("merchantid".to_string(), "MERCHANT_ID".to_string()), // Will be replaced with actual merchant ID
        ("customerid".to_string(), customer_id.get_string_repr().to_string()),
        ("txnamount".to_string(), amount.to_string()),
        ("currency".to_string(), router_data.router_data.request.currency.to_string()),
        ("txnreferenceNo".to_string(), router_data.router_data.resource_common_data.connector_request_reference_id.clone()),
        ("txntype".to_string(), "UPI".to_string()),
        ("itemcode".to_string(), "DIRECT".to_string()),
    ]);

    serde_json::to_string(&message_data)
        .change_context(errors::ConnectorError::RequestEncodingFailed)
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
> TryFrom<
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
        let msg = create_billdesk_message(&item)?;
        
        let user_agent = item.router_data.request.browser_info
            .as_ref()
            .and_then(|info| info.user_agent.clone());
            
        let ip_address = item.router_data.request.get_ip_address_as_optional()
            .map(|ip| ip.expose())
            .unwrap_or_else(|| "127.0.0.1".to_string());

        match item.router_data.resource_common_data.payment_method {
            common_enums::PaymentMethod::Upi => Ok(Self {
                msg,
                useragent: user_agent,
                ipaddress: Some(ip_address),
            }),
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
        + serde::Serialize,
> TryFrom<
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
        let message_data = HashMap::from([
            ("merchantid".to_string(), "MERCHANT_ID".to_string()), // Will be replaced with actual merchant ID
            ("customerid".to_string(), item.router_data.resource_common_data.get_customer_id()?.get_string_repr().to_string()),
            ("txnreferenceNo".to_string(), item.router_data.resource_common_data.connector_request_reference_id.clone()),
            ("requesttype".to_string(), "STATUSQUERY".to_string()),
        ]);

        let msg = serde_json::to_string(&message_data)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        Ok(Self { msg })
    }
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
                    .map(|(k, v)| (k, v.into()))
                    .collect(),
            })
        }
        None => Err(errors::ConnectorError::MissingRequiredField {
            field_name: "rdata",
        }
        .into()),
    }
}

impl<T> TryFrom<ResponseRouterData<BilldeskPaymentsResponse, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
where
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
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
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + serde::Serialize,
> TryFrom<ResponseRouterData<BilldeskPaymentsSyncResponse, Self>>
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

        let status = match response.auth_status.as_str() {
            "0300" | "0399" => common_enums::AttemptStatus::Charged,
            "0396" => common_enums::AttemptStatus::AuthenticationPending,
            "0398" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Failure,
        };

        let response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.txn_reference_no),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: Some(response.bank_reference_no),
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(response_data),
            ..router_data
        })
    }
}