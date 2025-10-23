use std::collections::HashMap;

use common_utils::{
    errors::CustomResult,
    ext_traits::ValueExt,
    request::Method,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
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
}

#[derive(Default, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskAuthType {
    pub merchant_id: Secret<String>,
    pub checksum_key: Secret<String>,
}

#[derive(Default, Debug, Deserialize)]
pub struct BilldeskAuth {
    pub merchant_id: Secret<String>,
    pub checksum_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for BilldeskAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key } => {
                let billdesk_auth: Self = api_key
                    .to_owned()
                    .parse_value("BilldeskAuth")
                    .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
                Ok(billdesk_auth)
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
    pub parameters: HashMap<String, String>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsSyncResponse {
    pub txn_reference_no: String,
    pub auth_status: String,
    pub txn_amount: String,
    pub currency: String,
    pub error_status: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskErrorResponse {
    pub error: String,
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

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskPaymentsSyncRequest {
    pub msg: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BilldeskPaymentsSyncResponse {
    pub txn_reference_no: String,
    pub auth_status: String,
    pub txn_amount: String,
    pub currency: String,
    pub error_status: Option<String>,
    pub error_description: Option<String>,
}

fn get_redirect_form_data(
    payment_method_type: common_enums::PaymentMethodType,
    response_data: BilldeskRdata,
) -> CustomResult<RedirectForm, errors::ConnectorError> {
    match payment_method_type {
        common_enums::PaymentMethodType::Upi => {
            if let Some(url) = response_data.url {
                Ok(RedirectForm::Form {
                    endpoint: url,
                    method: Method::Post,
                    form_fields: response_data
                        .parameters
                        .into_iter()
                        .map(|(k, v)| (k, v.into()))
                        .collect(),
                })
            } else {
                Err(errors::ConnectorError::MissingRequiredField {
                    field_name: "url",
                }
                .into())
            }
        }
        _ => Err(errors::ConnectorError::NotImplemented(
            utils::get_unimplemented_payment_method_error_message("Billdesk"),
        ))?,
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
        let transaction_id = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let ip_address = item.router_data.request.get_ip_address_as_optional()
            .map(|ip| ip.expose())
            .unwrap_or_else(|| "127.0.0.1".to_string());

        let user_agent = item.router_data.request.browser_info
            .as_ref()
            .and_then(|info| info.user_agent.clone())
            .unwrap_or_else(|| "Mozilla/5.0".to_string());

        match item.router_data.resource_common_data.payment_method {
            common_enums::PaymentMethod::Upi => {
                // Create the message for UPI transaction
                let msg = create_upi_message(
                    &transaction_id,
                    &amount,
                    &item.router_data.request.currency.to_string(),
                    &customer_id.get_string_repr(),
                )?;

                Ok(Self {
                    msg,
                    paydata: Some(create_upi_paydata(&item.router_data)?),
                    ipaddress: Some(ip_address),
                    useragent: Some(user_agent),
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                "Payment methods".to_string(),
            )
            .into()),
        }
    }
}

fn create_upi_message(
    transaction_id: &str,
    amount: &str,
    currency: &str,
    customer_id: &str,
) -> CustomResult<String, errors::ConnectorError> {
    // Create Billdesk UPI message format
    let message = format!(
        "TXN_REF_NO={}&TXN_AMOUNT={}&TXN_CURRENCY={}&CUST_ID={}",
        transaction_id, amount, currency, customer_id
    );
    Ok(message)
}

fn create_upi_paydata<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>(
    request_data: &PaymentsAuthorizeData<T>,
) -> CustomResult<String, errors::ConnectorError> {
    // Extract UPI specific data from payment method
    if let Some(payment_method_data) = &request_data.payment_method_data {
        match payment_method_data {
            PaymentMethodData::Upi(upi_data) => {
                if let Some(vpa) = &upi_data.vpa {
                    Ok(format!("VPA={}", vpa))
                } else {
                    Err(errors::ConnectorError::MissingRequiredField {
                        field_name: "vpa",
                    }
                    .into())
                }
            }
            _ => Err(errors::ConnectorError::MissingRequiredField {
                field_name: "upi_data",
            }
            .into()),
        }
    } else {
        Err(errors::ConnectorError::MissingRequiredField {
            field_name: "payment_method_data",
        }
        .into())
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
                
                if let Some(rdata) = response_data.rdata {
                    let redirection_data = get_redirect_form_data(payment_method_type, rdata)?;
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
                            code: "MISSING_RDATA".to_string(),
                            status_code: item.http_code,
                            message: "Response data missing".to_string(),
                            reason: Some("Response data missing".to_string()),
                            attempt_status: None,
                            connector_transaction_id: None,
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: None,
                        }),
                    )
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

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
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
        let transaction_id = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        let msg = format!(
            "TXN_REF_NO={}&REQUEST_TYPE=STATUS",
            transaction_id
        );

        Ok(Self { msg })
    }
}

impl<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> TryFrom<BilldeskPaymentsSyncResponse> for PaymentsResponseData {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(response: BilldeskPaymentsSyncResponse) -> Result<Self, Self::Error> {
        let status = match response.auth_status.as_str() {
            "0300" | "0399" => common_enums::AttemptStatus::Charged,
            "0396" => common_enums::AttemptStatus::AuthenticationPending,
            "0397" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Pending,
        };

        Ok(Self::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.txn_reference_no),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: Some(response.txn_reference_no),
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: 200,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskIncomingWebhook {
    pub txn_reference_no: String,
    pub auth_status: String,
    pub txn_amount: String,
    pub currency: String,
    pub error_status: Option<String>,
    pub error_description: Option<String>,
}