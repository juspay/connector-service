use std::collections::HashMap;

use common_utils::{
    errors::CustomResult,
    ext_traits::ValueExt,
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

// Additional imports for missing types
use common_enums;
use domain_types::router_request_types::{
    AccessTokenRequestData, ConnectorCustomerData, PaymentCreateOrderData, PaymentMethodTokenizationData,
    PaymentsAuthenticateData, PaymentsCaptureData, PaymentsPostAuthenticateData, PaymentsPreAuthenticateData,
    RepeatPaymentData, SessionTokenRequestData, SetupMandateRequestData, SubmitEvidenceData,
};
use domain_types::connector_types::{
    AcceptDisputeData, ConnectorCustomerResponse, DisputeDefendData, DisputeFlowData, DisputeResponseData,
    PaymentCreateOrderResponse, PaymentMethodTokenResponse, SessionTokenResponseData,
};
use domain_types::router_request_types::{PaymentVoidData, RefundsData, RefundSyncData};

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsRequest {
    msg: String,
    useragent: String,
    ipaddress: String,
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
    pub rdata: Option<BilldeskRdataResponse>,
    pub txnrefno: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskRdataResponse {
    pub parameters: HashMap<String, String>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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
    pub _RefundStatus: Option<String>,
    pub _TotalRefundAmount: Option<String>,
    pub _LastRefundDate: Option<String>,
    pub _LastRefundRefNo: Option<String>,
    pub _QueryStatus: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskAuthType {
    pub api_key: Secret<String>,
    pub merchant_id: Secret<String>,
    pub checksum_key: Secret<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskAuth {
    pub api_key: Secret<String>,
    pub merchant_id: Secret<String>,
    pub checksum_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for BilldeskAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                ..
            } => Ok(Self {
                api_key: api_key.clone(),
                merchant_id: key1.clone(),
                checksum_key: Secret::new("".to_string()), // Will be populated from key1 if needed
            }),
            ConnectorAuthType::Key { api_key, key1 } => Ok(Self {
                api_key: api_key.clone(),
                merchant_id: key1.clone(),
                checksum_key: Secret::new("".to_string()),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

impl TryFrom<&ConnectorAuthType> for BilldeskAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                ..
            } => Ok(Self {
                api_key: api_key.clone(),
                merchant_id: key1.clone(),
                checksum_key: Secret::new("".to_string()),
            }),
            ConnectorAuthType::Key { api_key, key1 } => Ok(Self {
                api_key: api_key.clone(),
                merchant_id: key1.clone(),
                checksum_key: Secret::new("".to_string()),
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
        let auth_type = BilldeskAuth::try_from(&item.router_data.connector_auth_type)?;
        
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Build the message for UPI payment
        let mut message_data = HashMap::new();
        message_data.insert("merchantid".to_string(), auth_type.merchant_id.peek().to_string());
        message_data.insert("customerid".to_string(), customer_id.get_string_repr());
        message_data.insert("txnamount".to_string(), amount);
        message_data.insert("currency".to_string(), item.router_data.request.currency.to_string());
        message_data.insert("txntype".to_string(), "UPI".to_string());
        message_data.insert("itemcode".to_string(), "DIRECT".to_string());
        
        // Add UPI specific fields if available
        if let Some(payment_method) = &item.router_data.resource_common_data.payment_method {
            if let common_enums::PaymentMethod::Upi = payment_method {
                if let Some(upi_data) = &item.router_data.request.payment_method_data {
                    if let Some(upi) = upi_data.get_upi() {
                        if let Some(vpa) = &upi.vpa {
                            message_data.insert("vpa".to_string(), vpa.peek().to_string());
                        }
                    }
                }
            }
        }

        // Convert message to JSON string
        let msg = serde_json::to_string(&message_data)
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let ip_address = item.router_data.request.get_ip_address_as_optional()
            .map(|ip| ip.expose())
            .unwrap_or_else(|| "127.0.0.1".to_string());

        let user_agent = item.router_data.request.browser_info
            .as_ref()
            .and_then(|info| info.user_agent.clone())
            .unwrap_or_else(|| "Mozilla/5.0".to_string());

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
        let auth_type = BilldeskAuth::try_from(&item.router_data.connector_auth_type)?;
        
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        // Build the message for status check
        let mut message_data = HashMap::new();
        message_data.insert("merchantid".to_string(), auth_type.merchant_id.peek().to_string());
        message_data.insert("customerid".to_string(), customer_id.get_string_repr());
        message_data.insert("txnreferenceNo".to_string(), transaction_id);
        message_data.insert("requesttype".to_string(), "STATUS".to_string());

        // Convert message to JSON string
        let msg = serde_json::to_string(&message_data)
            .change_context(ConnectorError::RequestEncodingFailed)?;

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
                form_fields: rdata
                    .parameters
                    .into_iter()
                    .map(|(k, v)| (k, v.into_masked()))
                    .collect(),
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

        let status = match response._AuthStatus.as_str() {
            "0300" | "0399" => common_enums::AttemptStatus::Charged,
            "0396" | "0397" | "0398" => common_enums::AttemptStatus::Failure,
            "0001" | "0002" => common_enums::AttemptStatus::AuthenticationPending,
            _ => common_enums::AttemptStatus::Pending,
        };

        let error_code = if status == common_enums::AttemptStatus::Failure {
            Some(response._ErrorStatus.clone())
        } else {
            None
        };

        let error_message = if status == common_enums::AttemptStatus::Failure {
            Some(response._ErrorDescription.clone())
        } else {
            None
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response._TxnReferenceNo),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: response._BankReferenceNo,
                connector_response_reference_id: Some(response._TxnReferenceNo),
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