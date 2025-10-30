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

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsRequest {
    msg: String,
    paydata: Option<String>,
    ipaddress: String,
    useragent: String,
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
    pub _BankReferenceNo: String,
    pub _TxnAmount: String,
    pub _BankID: String,
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
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskErrorResponse {
    pub error: serde_json::Value,
    pub error_description: String,
}

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
            ConnectorAuthType::SignatureKey { api_key, key1 } => {
                let merchant_id = api_key
                    .clone()
                    .ok_or(errors::ConnectorError::FailedToObtainAuthType)?;
                let checksum_key = key1
                    .clone()
                    .ok_or(errors::ConnectorError::FailedToObtainAuthType)?;
                Ok(Self {
                    merchant_id: Secret::new(merchant_id),
                    checksum_key: Secret::new(checksum_key),
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
        let ip_address = item.router_data.request.get_ip_address_as_optional()
            .map(|ip| ip.expose())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        
        let user_agent = item.router_data.request.browser_info
            .as_ref()
            .and_then(|info| info.user_agent.clone())
            .unwrap_or_else(|| "Mozilla/5.0".to_string());

        // Create the message based on payment method type
        let msg = match item.router_data.request.payment_method_type {
            Some(common_enums::PaymentMethodType::Upi) => {
                // UPI payment message format
                format!(
                    "MERCHANTID={}&TXN_REFERENCE_NO={}&AMOUNT={}&CURRENCY={}&CUSTOMER_ID={}&TXN_TYPE=UPI&ITEM_CODE=DIRECT&RETURN_URL={}",
                    get_merchant_id(&item.router_data.connector_auth_type)?,
                    item.router_data.resource_common_data.connector_request_reference_id,
                    item.connector.amount_converter.get_amount_as_string(),
                    item.router_data.request.currency,
                    customer_id,
                    item.router_data.request.get_router_return_url().unwrap_or_default()
                )
            }
            _ => return Err(errors::ConnectorError::MissingPaymentMethodType.into()),
        };

        match item.router_data.resource_common_data.payment_method {
            common_enums::PaymentMethod::Upi => Ok(Self {
                msg,
                paydata: None, // Will be populated based on UPI specific data
                ipaddress: ip_address,
                useragent: user_agent,
            }),
            _ => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("Billdesk"),
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
        let msg = format!(
            "MERCHANTID={}&TXN_REFERENCE_NO={}",
            get_merchant_id(&item.router_data.connector_auth_type)?,
            item.router_data.resource_common_data.connector_request_reference_id
        );

        Ok(Self { msg })
    }
}

fn get_merchant_id(connector_auth_type: &ConnectorAuthType) -> Result<String, errors::ConnectorError> {
    match BilldeskAuth::try_from(connector_auth_type) {
        Ok(billdesk_auth) => Ok(billdesk_auth.merchant_id.peek().to_string()),
        Err(_) => Err(errors::ConnectorError::FailedToObtainAuthType),
    }
}

fn get_redirect_form_data(
    payment_method_type: common_enums::PaymentMethodType,
    response_data: BilldeskPaymentsResponseData,
) -> CustomResult<RedirectForm, errors::ConnectorError> {
    match payment_method_type {
        common_enums::PaymentMethodType::Upi => {
            if let Some(rdata) = response_data.rdata {
                let url = rdata.url.unwrap_or_default();
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
                    field_name: "rdata",
                }
                .into())
            }
        }
        _ => Err(errors::ConnectorError::NotImplemented(
            utils::get_unimplemented_payment_method_error_message("Billdesk"),
        )),
    }
}

impl<F> TryFrom<ResponseRouterData<BilldeskPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<common_enums::PaymentMethod>, PaymentsResponseData>
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
                let redirection_data = get_redirect_form_data(payment_method_type, response_data)?;
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

impl TryFrom<BilldeskPaymentsSyncResponse> for PaymentsResponseData {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(response: BilldeskPaymentsSyncResponse) -> Result<Self, Self::Error> {
        let status = match response._AuthStatus.as_str() {
            "0300" | "0399" => common_enums::AttemptStatus::Charged,
            "0396" => common_enums::AttemptStatus::AuthorizationPending,
            "0397" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Failure,
        };

        let amount = response._TxnAmount.parse::<i64>()
            .map(|amt| common_utils::types::MinorUnit::from_i64(amt))
            .ok();

        Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response._TxnReferenceNo),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: Some(response._BankReferenceNo),
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: 200,
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