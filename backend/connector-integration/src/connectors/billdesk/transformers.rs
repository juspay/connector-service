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
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{
    connectors::billdesk::BilldeskRouterData,
    types::ResponseRouterData,
};



#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsRequest {
    msg: String,
    paydata: Option<String>,
    ipaddress: Option<String>,
    useragent: Option<String>,
}

#[derive(Default, Debug, Serialize)]
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
    pub _MerchantID: String,
    pub _CustomerID: String,
    pub _TxnReferenceNo: String,
    pub _BankReferenceNo: Option<String>,
    pub _TxnAmount: String,
    pub _BankID: Option<String>,
    pub _TxnType: Option<String>,
    pub _CurrencyType: String,
    pub _ItemCode: String,
    pub _TxnDate: Option<String>,
    pub _AuthStatus: String,
    pub _ErrorStatus: String,
    pub _ErrorDescription: String,
    pub _Checksum: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskAuth {
    pub api_key: Secret<String>,
    pub merchant_id: Secret<String>,
    pub checksum_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for BilldeskAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1, .. } => Ok(Self {
                api_key: api_key.clone(),
                merchant_id: key1.clone(),
                checksum_key: Secret::new("".to_string()), // TODO: Implement proper checksum key handling
            }),
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
            BilldeskPaymentStatus::Failure => Self::Failure,
            BilldeskPaymentStatus::Pending => Self::AuthenticationPending,
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
pub struct BilldeskErrorResponse {
    pub error: serde_json::Value,
    pub error_description: String,
    pub errors: Option<Vec<BilldeskErrors>>,
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
        let customer_id = item.router_data.resource_common_data.get_customer_id()?.to_string();
        let transaction_id = item
            .router_data
            .resource_common_data
            .connector_request_reference_id;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Extract IP address
        let ip_address = item.router_data.request.get_ip_address_as_optional()
            .map(|ip| ip.expose())
            .unwrap_or_else(|| "127.0.0.1".to_string());

        // Extract user agent
        let user_agent = item.router_data.request.browser_info
            .as_ref()
            .and_then(|info| info.user_agent.clone())
            .unwrap_or_else(|| "Mozilla/5.0".to_string());

        // Build message based on payment method type
        let msg = match item.router_data.request.payment_method_type {
            Some(common_enums::PaymentMethodType::UpiCollect) => {
                build_upi_message(&item, &customer_id, &transaction_id, &amount)?
            }
            _ => return Err(errors::ConnectorError::NotImplemented(
                "Payment method not supported".to_string(),
            )
            .into()),
        };

        Ok(Self {
            msg,
            paydata: None, // TODO: Implement paydata for UPI collect
            ipaddress: Some(ip_address),
            useragent: Some(user_agent),
        })
    }
}

fn build_upi_message<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>(
    item: &BilldeskRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    customer_id: &str,
    transaction_id: &str,
    amount: &str,
) -> CustomResult<String, errors::ConnectorError> {
    let auth_type = BilldeskAuth::try_from(&item.router_data.connector_auth_type)?;
    
    // Build UPI message according to Billdesk format
    let message = format!(
        "merchantid={}&customerid={}&txnreference={}&amount={}&currency={}",
        auth_type.merchant_id.peek(),
        customer_id,
        transaction_id,
        amount,
        item.router_data.request.currency
    );
    
    Ok(message)
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
                
                let redirection_data = if let Some(rdata) = response_data.rdata {
                    if let Some(url) = rdata.url {
                        Some(Box::new(RedirectForm::Form {
                            endpoint: url,
                            method: Method::Post,
                            form_fields: rdata
                                .parameters
                                .into_iter()
                                .map(|(k, v)| (k, v.into()))
                                .collect(),
                        }))
                    } else {
                        None
                    }
                } else {
                    None
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
                        redirection_data,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: response_data.txnrefno,
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
        let auth_type = BilldeskAuth::try_from(&item.router_data.connector_auth_type)?;
        let transaction_id = item
            .router_data
            .resource_common_data
            .connector_request_reference_id;
        
        let msg = format!(
            "merchantid={}&txnreference={}",
            auth_type.merchant_id.peek(),
            transaction_id
        );

        Ok(Self { msg })
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

        let status = match response._AuthStatus.as_str() {
            "0300" | "0399" => common_enums::AttemptStatus::Charged,
            "0396" => common_enums::AttemptStatus::Failure,
            "0001" | "0002" => common_enums::AttemptStatus::AuthenticationPending,
            _ => common_enums::AttemptStatus::Pending,
        };

        let response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response._TxnReferenceNo),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: response._BankReferenceNo,
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