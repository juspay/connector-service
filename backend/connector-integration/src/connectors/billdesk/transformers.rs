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

use crate::{connectors::billdesk::BilldeskRouterData, types::ResponseRouterData};

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
    pub _ErrorStatus: String,
    pub _ErrorDescription: String,
    pub _Checksum: String,
}

#[derive(Debug, Deserialize, Serialize)]
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
pub struct BilldeskDefendDisputeRequest;
#[derive(Debug, Clone)]
pub struct BilldeskDefendDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskSubmitEvidenceRequest;
#[derive(Debug, Clone)]
pub struct BilldeskSubmitEvidenceResponse;

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

fn get_merchant_id(
    connector_auth_type: &ConnectorAuthType,
) -> Result<Secret<String>, errors::ConnectorError> {
    match connector_auth_type {
        ConnectorAuthType::SignatureKey { api_key, .. } => Ok(api_key.clone()),
        _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
    }
}

fn build_billdesk_message(
    merchant_id: &str,
    customer_id: &str,
    txn_reference_no: &str,
    amount: &str,
    currency: &str,
    return_url: &str,
) -> String {
    // Based on the Haskell implementation, build the message for Billdesk
    // This is a simplified version - actual implementation may need more fields
    format!(
        "MerchantID={}&CustomerID={}&TxnReferenceNo={}&TxnAmount={}&Currency={}&ReturnURL={}",
        merchant_id, customer_id, txn_reference_no, amount, currency, return_url
    )
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
        let return_url = item.router_data.request.get_router_return_url()?;
        let merchant_id = get_merchant_id(&item.router_data.connector_auth_type)?;
        
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        let txn_reference_no = item
            .router_data
            .resource_common_data
            .connector_request_reference_id;

        let ip_address = item.router_data.request.get_ip_address_as_optional()
            .map(|ip| ip.expose())
            .unwrap_or_else(|| "127.0.0.1".to_string());

        let user_agent = item.router_data.request.browser_info
            .as_ref()
            .and_then(|info| info.user_agent.clone())
            .unwrap_or_else(|| "Mozilla/5.0".to_string());

        // Build the message for Billdesk UPI transaction
        let msg = build_billdesk_message(
            merchant_id.peek(),
            &customer_id.get_string_repr(),
            txn_reference_no,
            amount.as_str(),
            &item.router_data.request.currency.to_string(),
            &return_url,
        );

        match item.router_data.resource_common_data.payment_method {
            common_enums::PaymentMethod::Upi => Ok(Self {
                msg,
                useragent: user_agent,
                ipaddress: ip_address,
            }),
            _ => Err(errors::ConnectorError::NotImplemented(
                "Payment method not supported".to_string(),
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
        let merchant_id = get_merchant_id(&item.router_data.connector_auth_type)?;
        let txn_reference_no = item
            .router_data
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;

        // Build status check message
        let msg = format!(
            "MerchantID={}&TxnReferenceNo={}",
            merchant_id.peek(),
            txn_reference_no
        );

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
                    .map(|(k, v)| (k, v.into()))
                    .collect(),
            })
        } else {
            Err(errors::ConnectorError::MissingRequiredField {
                field_name: "url".to_string(),
            }
            .into())
        }
    } else {
        Err(errors::ConnectorError::MissingRequiredField {
            field_name: "rdata".to_string(),
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
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<BilldeskPaymentsSyncResponse> for PaymentsResponseData {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(response: BilldeskPaymentsSyncResponse) -> Result<Self, Self::Error> {
        let status = match response._AuthStatus.as_str() {
            "0300" | "0399" => common_enums::AttemptStatus::Charged,
            "0396" => common_enums::AttemptStatus::Failure,
            "0001" | "0002" => common_enums::AttemptStatus::AuthenticationPending,
            _ => common_enums::AttemptStatus::Pending,
        };

        Ok(Self::TransactionResponse {
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