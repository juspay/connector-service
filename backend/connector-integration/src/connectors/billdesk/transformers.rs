
use common_utils::{
    types::StringMinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsSyncData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Secret, PeekInterface, ExposeInterface};
use serde::{Deserialize, Serialize};

use crate::{connectors::billdesk::BilldeskRouterData, types::ResponseRouterData};

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsRequest {
    msg: Secret<String>,
    useragent: String,
    ipaddress: String,
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
            ConnectorAuthType::SignatureKey { api_key, key1, api_secret: _ } => Ok(Self {
                merchant_id: api_key.clone(),
                checksum_key: key1.clone(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskUPIRequestMessage {
    pub merchant_id: String,
    pub customer_id: String,
    pub txn_reference_no: String,
    pub amount: String,
    pub currency: String,
    pub item_code: String,
    pub txn_date: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vpa: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upi_mode: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskPaymentsResponse {
    pub msg: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskUPITransactionResponse {
    pub merchant_id: String,
    pub customer_id: String,
    pub txn_reference_no: String,
    pub bank_reference_no: Option<String>,
    pub amount: String,
    pub bank_id: Option<String>,
    pub bank_merchant_id: Option<String>,
    pub txn_type: String,
    pub currency: String,
    pub item_code: String,
    pub txn_date: String,
    pub auth_status: String,
    pub settlement_type: Option<String>,
    pub additional_info1: Option<String>,
    pub additional_info2: Option<String>,
    pub additional_info3: Option<String>,
    pub additional_info4: Option<String>,
    pub additional_info5: Option<String>,
    pub additional_info6: Option<String>,
    pub additional_info7: Option<String>,
    pub error_status: String,
    pub error_description: String,
    pub checksum: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BilldeskPaymentsResponseData {
    TransactionResponse(BilldeskUPITransactionResponse),
    ErrorResponse(BilldeskErrorResponse),
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BilldeskErrorResponse {
    pub error: String,
    pub error_description: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsSyncRequest {
    msg: Secret<String>,
}

fn format_upi_message(
    merchant_id: String,
    customer_id: String,
    transaction_id: String,
    amount: StringMinorUnit,
    currency: common_enums::Currency,
    vpa: Option<String>,
) -> Result<Secret<String>, errors::ConnectorError> {
    let txn_date = "2023-01-01 00:00:00".to_string();
    
    let upi_message = BilldeskUPIRequestMessage {
        merchant_id,
        customer_id,
        txn_reference_no: transaction_id,
        amount: amount.to_string(),
        currency: currency.to_string(),
        item_code: "UPI".to_string(),
        txn_date,
        vpa,
        upi_mode: Some("COLLECT".to_string()),
    };
    
    let message_str = serde_json::to_string(&upi_message)
        .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;
    
    Ok(Secret::new(message_str))
}

fn format_sync_message(
    merchant_id: String,
    transaction_id: String,
) -> Result<Secret<String>, errors::ConnectorError> {
    let sync_message = serde_json::json!({
        "merchant_id": merchant_id,
        "txn_reference_no": transaction_id,
    });
    
    let message_str = serde_json::to_string(&sync_message)
        .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;
    
    Ok(Secret::new(message_str))
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
        let auth = BilldeskAuth::try_from(&item.router_data.connector_auth_type)?;
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;
        
        match item.router_data.request.payment_method_type {
            Some(common_enums::PaymentMethodType::UpiCollect) | 
            Some(common_enums::PaymentMethodType::UpiIntent) => {
                // Extract VPA from payment method specific data
                let vpa = None; // This will be extracted from the payment method specific data
                
                let msg = format_upi_message(
                    auth.merchant_id.peek().to_string(),
                    customer_id.get_string_repr().to_string(),
                    item.router_data
                        .resource_common_data
                        .connector_request_reference_id,
                    amount,
                    item.router_data.request.currency,
                    vpa,
                )?;
                
                let user_agent = item.router_data.request.browser_info
                    .as_ref()
                    .and_then(|info| info.user_agent.clone())
                    .unwrap_or_else(|| "Mozilla/5.0".to_string());
                
                let ip_address = item.router_data.request.get_ip_address_as_optional()
                    .map(|ip| ip.expose())
                    .unwrap_or_else(|| "127.0.0.1".to_string());
                
                Ok(Self {
                    msg,
                    useragent: user_agent,
                    ipaddress: ip_address,
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                "Payment methods".to_string(),
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
        let auth = BilldeskAuth::try_from(&item.router_data.connector_auth_type)?;
        
        let msg = format_sync_message(
            auth.merchant_id.peek().to_string(),
            item.router_data
                .resource_common_data
                .connector_request_reference_id,
        )?;
        
        Ok(Self { msg })
    }
}

impl From<BilldeskUPITransactionResponse> for common_enums::AttemptStatus {
    fn from(item: BilldeskUPITransactionResponse) -> Self {
        match item.auth_status.as_str() {
            "0300" | "0000" | "00" => Self::Charged,
            "0301" | "0302" => Self::AuthenticationPending,
            _ => Self::Failure,
        }
    }
}

impl<F, T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<BilldeskPaymentsResponseData, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<BilldeskPaymentsResponseData, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        
        let (status, response) = match response {
            BilldeskPaymentsResponseData::TransactionResponse(transaction_data) => {
                let status: common_enums::AttemptStatus = transaction_data.clone().into();
                
                (
                    status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            router_data
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: transaction_data.bank_reference_no,
                        connector_response_reference_id: Some(transaction_data.txn_reference_no.clone()),
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            BilldeskPaymentsResponseData::ErrorResponse(error_data) => (
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
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status: status,
                ..router_data.resource_common_data
            },
            response,
            ..router_data
        })
    }
}

impl TryFrom<BilldeskPaymentsResponseData> for PaymentsResponseData {
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(response: BilldeskPaymentsResponseData) -> Result<Self, Self::Error> {
        match response {
            BilldeskPaymentsResponseData::TransactionResponse(transaction_data) => {
                let _status: common_enums::AttemptStatus = transaction_data.clone().into();
                
                let txn_reference_no = transaction_data.txn_reference_no.clone();
                
                Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(txn_reference_no.clone()),
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: transaction_data.bank_reference_no,
                    connector_response_reference_id: Some(txn_reference_no),
                    incremental_authorization_allowed: None,
                    status_code: 200,
                })
            }
            BilldeskPaymentsResponseData::ErrorResponse(_error_data) => {
                Err(errors::ConnectorError::ResponseDeserializationFailed
                    .into())
            }
        }
    }
}