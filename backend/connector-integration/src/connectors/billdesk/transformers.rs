use std::collections::HashMap;

use common_utils::request::Method;
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface};
use serde::{Deserialize, Serialize};
use crate::connectors::billdesk::BilldeskRouterData;

use crate::types::ResponseRouterData;

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

#[derive(Default, Debug, Deserialize, Serialize)]
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

fn get_merchant_id(connector_auth_type: &ConnectorAuthType) -> Result<String, errors::ConnectorError> {
    match connector_auth_type {
        ConnectorAuthType::SignatureKey { api_key, .. } => Ok(api_key.peek().to_string()),
        _ => Err(errors::ConnectorError::FailedToObtainAuthType),
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<BilldeskRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for BilldeskPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: BilldeskRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let payment_method_type = item.router_data.request.payment_method_type
            .ok_or(errors::ConnectorError::MissingPaymentMethodType)?;
        
        match payment_method_type {
            common_enums::PaymentMethodType::UpiCollect => {
                let customer_id = item.router_data.resource_common_data.get_customer_id()?;
                let amount = item
                    .connector
                    .amount_converter
                    .convert(
                        item.router_data.request.minor_amount,
                        item.router_data.request.currency,
                    )
                    .change_context(ConnectorError::RequestEncodingFailed)?;
                
                let transaction_id = item
                    .router_data
                    .resource_common_data
                    .connector_request_reference_id.clone();
                
                let currency = item.router_data.request.currency.to_string();
                
                // Extract UPI specific details from payment method data
                let upi_vpa = if let Some(payment_method_data) = &item.router_data.request.payment_method_data {
                    match payment_method_data {
                        domain_types::payment_method_data::PaymentMethodData::Upi(upi_data) => {
                            upi_data.vpa.as_ref().map(|vpa| vpa.get_string_repr().to_string())
                        }
                        _ => None,
                    }
                } else {
                    None
                };
                
                // Create the message in the format expected by Billdesk based on Haskell implementation
                // Based on BilldeskInitiateUPIRequest from the Haskell source
                let msg = if let Some(vpa) = upi_vpa {
                    format!(
                        "MerchantID={}&CustomerID={}&TxnReferenceNo={}&TxnAmount={}&Currency={}&ItemCode=DIRECT&TxnType=UPI&AdditionalInfo1={}&AdditionalInfo2={}&AdditionalInfo3={}&AdditionalInfo4={}&AdditionalInfo5={}&AdditionalInfo6={}&AdditionalInfo7={}",
                        get_merchant_id(&item.router_data.connector_auth_type)?,
                        customer_id.get_string_repr(),
                        transaction_id,
                        amount,
                        currency,
                        vpa, // AdditionalInfo1 - UPI VPA
                        "", // AdditionalInfo2
                        "", // AdditionalInfo3
                        "", // AdditionalInfo4
                        "", // AdditionalInfo5
                        "", // AdditionalInfo6
                        "", // AdditionalInfo7
                    )
                } else {
                    format!(
                        "MerchantID={}&CustomerID={}&TxnReferenceNo={}&TxnAmount={}&Currency={}&ItemCode=DIRECT&TxnType=UPI&AdditionalInfo1={}&AdditionalInfo2={}&AdditionalInfo3={}&AdditionalInfo4={}&AdditionalInfo5={}&AdditionalInfo6={}&AdditionalInfo7={}",
                        get_merchant_id(&item.router_data.connector_auth_type)?,
                        customer_id.get_string_repr(),
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
                    )
                };
                
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

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<BilldeskRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for BilldeskPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: BilldeskRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let merchant_id = get_merchant_id(&item.router_data.connector_auth_type)?;
        let transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;
        
        let message = format!(
            "MerchantID={}&TxnReferenceNo={}",
            merchant_id, transaction_id
        );
        
        Ok(Self {
            msg: message,
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize> TryFrom<ResponseRouterData<BilldeskPaymentsResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: ResponseRouterData<BilldeskPaymentsResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>,
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
                    message: error_data.error_description.clone().unwrap_or_default(),
                    reason: error_data.error_description.clone(),
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
                                resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(
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

impl TryFrom<BilldeskPaymentsSyncResponse> for PaymentsResponseData {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(response: BilldeskPaymentsSyncResponse) -> Result<Self, Self::Error> {
        // Map Billdesk status codes based on Haskell implementation
        let status = match response._auth_status.as_str() {
            "0300" | "0399" => common_enums::AttemptStatus::Charged,      // Success
            "0396" => common_enums::AttemptStatus::AuthenticationPending, // Pending
            "0398" => common_enums::AttemptStatus::Failure,         // Failure
            "0301" => common_enums::AttemptStatus::Pending,         // Initiated
            "0302" => common_enums::AttemptStatus::AuthenticationPending, // In Progress
            _ => {
                // Check error status for more specific error handling
                match response._error_status.as_str() {
                    "000" => common_enums::AttemptStatus::Charged,      // Success
                    "001" => common_enums::AttemptStatus::Failure,         // Failure
                    "002" => common_enums::AttemptStatus::AuthenticationPending, // Pending
                    _ => common_enums::AttemptStatus::Failure,         // Default to failure
                }
            }
        };

        let response_data = Self::TransactionResponse {
            resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(response._txn_reference_no),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: Some(serde_json::json!({
                "bank_reference_no": response._bank_reference_no,
                "auth_status": response._auth_status,
                "error_status": response._error_status,
                "error_description": response._error_description,
                "query_status": response._query_status,
                "refund_status": response._refund_status,
                "total_refund_amount": response._total_refund_amount,
                "last_refund_date": response._last_refund_date,
                "last_refund_ref_no": response._last_refund_ref_no,
                "checksum": response._checksum
            })),
            network_txn_id: response._bank_reference_no,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: 200,
        };

        // If the status is failure, return an error response
        if matches!(status, common_enums::AttemptStatus::Failure) {
            return Err(errors::ConnectorError::RequestEncodingFailed
                .attach_printable(format!(
                    "Billdesk transaction failed: {} - {}",
                    response._error_status,
                    response._error_description
                ))
                .into());
        }

        Ok(response_data)
    }
}

impl TryFrom<ResponseRouterData<BilldeskPaymentsSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: ResponseRouterData<BilldeskPaymentsSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        
        // Enhanced status mapping based on Haskell implementation
        let status = match response._auth_status.as_str() {
            "0300" | "0399" => common_enums::AttemptStatus::Charged,      // Success
            "0396" => common_enums::AttemptStatus::AuthenticationPending, // Pending
            "0398" => common_enums::AttemptStatus::Failure,         // Failure
            "0301" => common_enums::AttemptStatus::Pending,         // Initiated
            "0302" => common_enums::AttemptStatus::AuthenticationPending, // In Progress
            _ => {
                // Check error status for more specific error handling
                match response._error_status.as_str() {
                    "000" => common_enums::AttemptStatus::Charged,      // Success
                    "001" => common_enums::AttemptStatus::Failure,         // Failure
                    "002" => common_enums::AttemptStatus::AuthenticationPending, // Pending
                    _ => common_enums::AttemptStatus::Failure,         // Default to failure
                }
            }
        };

        let connector_metadata = Some(serde_json::json!({
            "bank_reference_no": response._bank_reference_no,
            "auth_status": response._auth_status,
            "error_status": response._error_status,
            "error_description": response._error_description,
            "query_status": response._query_status,
            "refund_status": response._refund_status,
            "total_refund_amount": response._total_refund_amount,
            "last_refund_date": response._last_refund_date,
            "last_refund_ref_no": response._last_refund_ref_no,
            "checksum": response._checksum
        }));

        let payments_response = PaymentsResponseData::TransactionResponse {
            resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(response._txn_reference_no),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata,
            network_txn_id: response._bank_reference_no,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(payments_response),
            ..router_data
        })
    }
}