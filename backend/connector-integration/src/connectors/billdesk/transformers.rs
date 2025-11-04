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

// Type alias for router data
pub type BilldeskRouterData<R, T> = crate::ConnectorRouterData<R>;

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

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsSyncResponse {
    pub _request_type: Option<String>,
    pub _merchant_id: String,
    pub _customer_id: String,
    pub _txn_reference_no: String,
    pub _bank_reference_no: Option<String>,
    pub _txn_amount: String,
    pub _bank_id: Option<String>,
    pub _filler1: Option<String>,
    pub _txn_type: Option<String>,
    pub _currency_type: String,
    pub _item_code: String,
    pub _filler2: Option<String>,
    pub _filler3: Option<String>,
    pub _filler4: Option<String>,
    pub _txn_date: Option<String>,
    pub _auth_status: String,
    pub _filler5: Option<String>,
    pub _additional_info1: Option<String>,
    pub _additional_info2: Option<String>,
    pub _additional_info3: Option<String>,
    pub _additional_info4: Option<String>,
    pub _additional_info5: Option<String>,
    pub _additional_info6: Option<String>,
    pub _additional_info7: Option<String>,
    pub _error_status: String,
    pub _error_description: String,
    pub _filler6: Option<String>,
    pub _refund_status: String,
    pub _total_refund_amount: String,
    pub _last_refund_date: Option<String>,
    pub _last_refund_ref_no: Option<String>,
    pub _query_status: String,
    pub _checksum: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
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
#[serde(rename_all = "lowercase")]
pub enum BilldeskPaymentStatus {
    Success,
    Failure,
    Pending,
    #[default]
    Processing,
}

impl From<BilldeskPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: BilldeskPaymentStatus) -> Self {
        match item {
            BilldeskPaymentStatus::Success => Self::Charged,
            BilldeskPaymentStatus::Failure => Self::Failure,
            BilldeskPaymentStatus::Pending => Self::AuthenticationPending,
            BilldeskPaymentStatus::Processing => Self::AuthenticationPending,
        }
    }
}

fn create_billdesk_message(
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
    
    let transaction_id = router_data
        .router_data
        .resource_common_data
        .connector_request_reference_id;
    
    let currency = router_data.router_data.request.currency.to_string();
    
    // Create the message in the format expected by Billdesk
    // This is based on the Haskell implementation patterns
    let message = format!(
        "MerchantID={}&CustomerID={}&TxnReferenceNo={}&TxnAmount={}&Currency={}&ItemCode=DIRECT&TxnType=UPI&AdditionalInfo1={}&AdditionalInfo2={}&AdditionalInfo3={}&AdditionalInfo4={}&AdditionalInfo5={}&AdditionalInfo6={}&AdditionalInfo7={}",
        get_merchant_id(&router_data.router_data.connector_auth_type)?,
        customer_id,
        transaction_id,
        amount,
        currency,
        "", // AdditionalInfo1
        "", // AdditionalInfo2
        "", // AdditionalInfo3
        "", // AdditionalInfo4
        "", // AdditionalInfo5
        "", // AdditionalInfo6
        "", // AdditionalInfo7
    );
    
    Ok(message)
}

fn get_merchant_id(connector_auth_type: &ConnectorAuthType) -> Result<String, errors::ConnectorError> {
    match connector_auth_type {
        ConnectorAuthType::SignatureKey { api_key, .. } => Ok(api_key.peek().to_string()),
        ConnectorAuthType::Key { api_key, .. } => Ok(api_key.peek().to_string()),
        _ => Err(errors::ConnectorError::FailedToObtainAuthType),
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
        let payment_method_type = item.router_data.request.payment_method_type
            .ok_or(errors::ConnectorError::MissingPaymentMethodType)?;
        
        match payment_method_type {
            common_enums::PaymentMethodType::Upi | common_enums::PaymentMethodType::UpiCollect => {
                let msg = create_billdesk_message(&item)?;
                
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
        let transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;
        
        let message = format!(
            "MerchantID={}&TxnReferenceNo={}",
            merchant_id,
            transaction_id
        );
        
        Ok(Self {
            msg: message,
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
                if let Some(rdata) = response_data.rdata {
                    if let Some(url) = rdata.url {
                        let redirection_data = RedirectForm::Form {
                            endpoint: url,
                            method: Method::Get,
                            form_fields: rdata
                                .parameters
                                .into_iter()
                                .map(|(k, v)| (k, v.into()))
                                .collect(),
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
                                code: "NO_URL".to_string(),
                                status_code: http_code,
                                message: "No redirect URL provided".to_string(),
                                reason: Some("No redirect URL provided".to_string()),
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
                            code: "NO_RDATA".to_string(),
                            status_code: http_code,
                            message: "No response data provided".to_string(),
                            reason: Some("No response data provided".to_string()),
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
    > TryFrom<BilldeskPaymentsSyncResponse> for PaymentsResponseData {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(response: BilldeskPaymentsSyncResponse) -> Result<Self, Self::Error> {
        let status = match response._auth_status.as_str() {
            "0300" | "0399" => common_enums::AttemptStatus::Charged,
            "0396" => common_enums::AttemptStatus::AuthenticationPending,
            "0398" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Failure,
        };

        let error_code = if status == common_enums::AttemptStatus::Failure {
            Some(response._error_status.clone())
        } else {
            None
        };

        let error_message = if status == common_enums::AttemptStatus::Failure {
            Some(response._error_description.clone())
        } else {
            None
        };

        Ok(Self::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response._txn_reference_no),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: response._bank_reference_no,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: 200,
        })
    }
}