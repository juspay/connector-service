use crate::types::ResponseRouterData;
use common_enums;
use common_utils::types::MinorUnit;
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize)]
pub struct BilldeskPaymentsRequest {
    pub msg: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskPaymentsResponse {
    pub msg: Option<String>,
    pub error_code: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BilldeskPaymentsSyncRequest {
    pub msg: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskPaymentsSyncResponse {
    pub msg: Option<String>,
    pub error_code: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskErrorResponse {
    pub error_code: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Debug)]
pub struct BilldeskAuthType {
    pub merchant_id: Secret<String>,
    pub security_id: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for BilldeskAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                merchant_id: api_key.clone(),
                security_id: key1.clone(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

fn create_billdesk_message(
    merchant_id: &str,
    security_id: &str,
    txn_id: &str,
    amount: &str,
    currency: &str,
    additional_info: &str,
    ru: &str,
) -> String {
    let msg = format!(
        "{}|{}|NA|{}|{}|{}|NA|NA|NA|NA|NA|{}|NA|NA|NA|NA|NA|{}|NA|NA|NA|NA|NA|NA|NA",
        merchant_id, txn_id, amount, currency, additional_info, security_id, ru
    );
    
    // Calculate checksum (simplified - in real implementation, use proper checksum algorithm)
    let checksum = calculate_checksum(&msg);
    format!("{}|{}", msg, checksum)
}

fn calculate_checksum(msg: &str) -> String {
    // Simplified checksum calculation - replace with actual Billdesk checksum algorithm
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    msg.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

fn parse_billdesk_response(response_msg: &str) -> Result<HashMap<String, String>, error_stack::Report<errors::ConnectorError>> {
    let parts: Vec<&str> = response_msg.split('|').collect();
    
    if parts.len() < 25 {
        return Err(errors::ConnectorError::ResponseDeserializationFailed.into());
    }
    
    let mut response_map = HashMap::new();
    response_map.insert("merchant_id".to_string(), parts[0].to_string());
    response_map.insert("txn_id".to_string(), parts[1].to_string());
    response_map.insert("amount".to_string(), parts[3].to_string());
    response_map.insert("currency".to_string(), parts[4].to_string());
    response_map.insert("txn_date".to_string(), parts[13].to_string());
    response_map.insert("auth_status".to_string(), parts[14].to_string());
    response_map.insert("error_status".to_string(), parts[22].to_string());
    response_map.insert("error_description".to_string(), parts[23].to_string());
    
    Ok(response_map)
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<crate::connectors::billdesk::BilldeskRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for BilldeskPaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: crate::connectors::billdesk::BilldeskRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = BilldeskAuthType::try_from(&item.router_data.connector_auth_type)?;
        
        // Get required fields using UCS v2 amount framework
        let amount = item.connector.amount_converter.convert(
            MinorUnit::new(item.router_data.request.amount),
            item.router_data.request.currency,
        ).change_context(errors::ConnectorError::AmountConversionFailed)?;
        let currency = item.router_data.request.currency.to_string();
        let txn_id = &item.router_data.resource_common_data.payment_id;
        
        // Create additional info based on payment method
        let additional_info = match &item.router_data.request.payment_method_data {
            domain_types::payment_method_data::PaymentMethodData::Upi(upi_data) => {
                match upi_data {
                    domain_types::payment_method_data::UpiData::UpiCollect(collect_data) => {
                        if let Some(vpa_id) = &collect_data.vpa_id {
                            format!("UPI|{}", vpa_id.peek())
                        } else {
                            "UPI|COLLECT".to_string()
                        }
                    }
                    domain_types::payment_method_data::UpiData::UpiIntent(_) => {
                        "UPI|INTENT".to_string()
                    }
                }
            }
            _ => return Err(errors::ConnectorError::NotSupported {
                message: "Payment method not supported".to_string(),
                connector: "Billdesk",
            }.into()),
        };
        
        let return_url = item.router_data.request.router_return_url.as_ref()
            .ok_or(errors::ConnectorError::RequestEncodingFailed)?;
        
        let msg = create_billdesk_message(
            auth.merchant_id.peek(),
            auth.security_id.peek(),
            txn_id,
            &amount.to_string(),
            &currency,
            &additional_info,
            return_url,
        );
        
        Ok(Self { msg })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<crate::connectors::billdesk::BilldeskRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for BilldeskPaymentsSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: crate::connectors::billdesk::BilldeskRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = BilldeskAuthType::try_from(&item.router_data.connector_auth_type)?;
        
        let txn_id = match &item.router_data.request.connector_transaction_id {
            domain_types::connector_types::ResponseId::ConnectorTransactionId(id) => id,
            domain_types::connector_types::ResponseId::NoResponseId => {
                return Err(errors::ConnectorError::MissingConnectorTransactionID.into());
            }
            domain_types::connector_types::ResponseId::EncodedData(data) => data,
        };
        
        // Create sync message format
        let msg = format!(
            "{}|{}|{}|{}",
            auth.merchant_id.peek(),
            txn_id,
            "QUERY",
            auth.security_id.peek()
        );
        
        Ok(Self { msg })
    }
}

impl<F, T>
    TryFrom<
        ResponseRouterData<
            BilldeskPaymentsResponse,
            RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>,
        >,
    > for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            BilldeskPaymentsResponse,
            RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        
        if let Some(msg) = &response.msg {
            let parsed_response = parse_billdesk_response(msg)?;
            let default_empty = String::new();
            let auth_status = parsed_response.get("auth_status").unwrap_or(&default_empty);
            let error_status = parsed_response.get("error_status").unwrap_or(&default_empty);
            
            let _status = match auth_status.as_str() {
                "0300" => common_enums::AttemptStatus::Charged,
                "0002" => common_enums::AttemptStatus::Pending,
                "0001" => common_enums::AttemptStatus::AuthenticationPending,
                _ => {
                    if error_status != "0" && !error_status.is_empty() {
                        common_enums::AttemptStatus::Failure
                    } else {
                        common_enums::AttemptStatus::Pending
                    }
                }
            };
            
            let connector_transaction_id = parsed_response.get("txn_id").cloned();
            
            Ok(Self {
                response: Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(
                        connector_transaction_id.unwrap_or_else(|| router_data.resource_common_data.payment_id.clone())
                    ),
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    status_code: http_code,
                }),
                ..router_data
            })
        } else {
            let error_message = response.error_description.clone()
                .unwrap_or_else(|| "Unknown error occurred".to_string());
            
            Ok(Self {
                response: Err(domain_types::router_data::ErrorResponse {
                    code: response.error_code.unwrap_or_else(|| "UNKNOWN_ERROR".to_string()),
                    message: error_message.clone(),
                    reason: Some(error_message),
                    status_code: http_code,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
                ..router_data
            })
        }
    }
}

impl
    TryFrom<
        ResponseRouterData<
            BilldeskPaymentsSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    >
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<BilldeskPaymentsSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        
        if let Some(msg) = &response.msg {
            let parsed_response = parse_billdesk_response(msg)?;
            let default_empty = String::new();
            let auth_status = parsed_response.get("auth_status").unwrap_or(&default_empty);
            let error_status = parsed_response.get("error_status").unwrap_or(&default_empty);
            
            let _status = match auth_status.as_str() {
                "0300" => common_enums::AttemptStatus::Charged,
                "0002" => common_enums::AttemptStatus::Pending,
                "0001" => common_enums::AttemptStatus::AuthenticationPending,
                _ => {
                    if error_status != "0" && !error_status.is_empty() {
                        common_enums::AttemptStatus::Failure
                    } else {
                        common_enums::AttemptStatus::Pending
                    }
                }
            };
            
            let connector_transaction_id = parsed_response.get("txn_id").cloned();
            
            Ok(Self {
                response: Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(
                        connector_transaction_id.unwrap_or_else(|| router_data.resource_common_data.payment_id.clone())
                    ),
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    status_code: http_code,
                }),
                ..router_data
            })
        } else {
            let error_message = response.error_description.clone()
                .unwrap_or_else(|| "Unknown error occurred".to_string());
            
            Ok(Self {
                response: Err(domain_types::router_data::ErrorResponse {
                    code: response.error_code.unwrap_or_else(|| "UNKNOWN_ERROR".to_string()),
                    message: error_message.clone(),
                    reason: Some(error_message),
                    status_code: http_code,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
                ..router_data
            })
        }
    }
}