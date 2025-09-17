use common_utils::{
    request::Method, MinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, UpiData, UpiCollectData},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Secret, ExposeInterface};
use serde::{Deserialize, Serialize};

use crate::{connectors::billdesk::BilldeskRouterData, types::ResponseRouterData};
use super::constants;

/// Authentication structure for Billdesk
#[derive(Debug, Deserialize)]
pub struct BilldeskAuth {
    pub api_key: Option<Secret<String>>,
    pub merchant_id: Option<Secret<String>>,
    pub secret_key: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for BilldeskAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: Some(api_key.clone()),
                merchant_id: None,
                secret_key: None,
            }),
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                api_key: Some(api_key.clone()),
                merchant_id: Some(key1.clone()),
                secret_key: None,
            }),
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self {
                api_key: Some(api_key.clone()),
                merchant_id: Some(key1.clone()),
                secret_key: Some(api_secret.clone()),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

/// UPI payment request structure for Billdesk
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsRequest {
    /// Merchant ID provided by Billdesk
    pub mercid: Secret<String>,
    /// Unique order ID
    pub orderid: String,
    /// Transaction amount in minor units (e.g., 1000 for ₹10.00)
    pub amount: String,
    /// Currency code (typically INR)
    pub currency: String,
    /// Customer ID
    pub customer_id: Secret<String>,
    /// Payment method type
    pub payment_method_type: String,
    /// UPI specific data
    pub upi: Option<BilldeskUpiData>,
    /// Customer IP address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipaddress: Option<String>,
    /// User agent string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub useragent: Option<String>,
    /// Return URL for redirect after payment
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ru: Option<String>,
    /// Device information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<BilldeskDeviceInfo>,
}

/// UPI-specific data for Billdesk
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskUpiData {
    /// UPI VPA (Virtual Payment Address) for collect flow
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vpa: Option<Secret<String>>,
}

/// Device information for UPI Intent flow
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskDeviceInfo {
    /// Operating system (android/ios)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// Device identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
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
        let auth = BilldeskAuth::try_from(&item.router_data.connector_auth_type)?;
        let merchant_id = auth.merchant_id.ok_or(errors::ConnectorError::FailedToObtainAuthType)?;
        
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let customer_id_string = customer_id.get_string_repr();
        
        // Get amount using UCS v2 amount framework
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;
        
        // Get IP address correctly
        let ip_address = item.router_data.request.get_ip_address_as_optional()
            .map(|ip| ip.expose()) 
            .unwrap_or_else(|| "127.0.0.1".to_string());
        
        // Get user agent
        let user_agent = item.router_data.request.browser_info
            .as_ref()
            .and_then(|info| info.user_agent.clone())
            .unwrap_or_else(|| "Mozilla/5.0".to_string());
        
        // Get return URL
        let return_url = item.router_data.request.get_router_return_url()?;
        
        // Handle UPI payment method
        match &item.router_data.request.payment_method_data {
            PaymentMethodData::Upi(upi_data) => {
                let (payment_method_type, upi_info, device_info) = match upi_data {
                    UpiData::UpiIntent(_) => {
                        // UPI Intent flow - customer will scan QR or use deep link
                        (
                            constants::UPI_INTENT.to_string(),
                            None,
                            Some(BilldeskDeviceInfo {
                                os: Some("android".to_string()), // Default to Android
                                device_id: None,
                            }),
                        )
                    }
                    UpiData::UpiCollect(collect_data) => {
                        // UPI Collect flow - send notification to customer's UPI app
                        (
                            constants::UPI_COLLECT.to_string(),
                            Some(BilldeskUpiData {
                                vpa: collect_data.vpa_id.clone(),
                            }),
                            None,
                        )
                    }
                };
                
                Ok(Self {
                    mercid: merchant_id,
                    orderid: item.router_data.resource_common_data.connector_request_reference_id.clone(),
                    amount: amount.to_string(),
                    currency: item.router_data.request.currency.to_string(),
                    customer_id: Secret::new(customer_id_string.to_string()),
                    payment_method_type,
                    upi: upi_info,
                    ipaddress: Some(ip_address),
                    useragent: Some(user_agent),
                    ru: Some(return_url),
                    device: device_info,
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("Billdesk"),
            ).into()),
        }
    }
}

/// Billdesk payment status enumeration
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum BilldeskPaymentStatus {
    Success,
    Failure,
    #[default]
    Pending,
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

/// Billdesk payments response - handles both success and error cases
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BilldeskPaymentsResponse {
    Success(BilldeskPaymentsResponseData),
    Error(BilldeskErrorResponse),
}

/// Successful payment response from Billdesk
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsResponseData {
    /// Billdesk transaction ID
    pub bdorderid: String,
    /// Merchant transaction ID
    pub mercid: String,
    /// Order ID
    pub orderid: String,
    /// Transaction amount
    pub amount: String,
    /// Currency
    pub currency: String,
    /// Transaction status
    pub status: String,
    /// Payment URL for redirect (UPI Intent)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_url: Option<String>,
    /// UPI data for Intent flow
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upi: Option<BilldeskUpiResponseData>,
    /// Links for various operations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<BilldeskPaymentLink>>,
}

/// UPI specific response data
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskUpiResponseData {
    /// UPI Intent URL for deep linking
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upi_intent_url: Option<String>,
    /// QR code data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qr_code: Option<String>,
    /// VPA for collect flow
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vpa: Option<String>,
}

/// Payment link structure
#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskPaymentLink {
    pub method: String,
    pub rel: String,
    pub href: String,
}

/// Payment sync request for status checking
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsSyncRequest {
    pub mercid: Secret<String>,
    pub orderid: String,
}

/// Payment sync response structure
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BilldeskPaymentsSyncResponse {
    Success(BilldeskPaymentsSyncData),
    Error(BilldeskErrorResponse),
}

/// Successful sync response data
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]  
pub struct BilldeskPaymentsSyncData {
    pub mercid: String,
    pub orderid: String,
    pub amount: String,
    pub currency: String,
    pub status: String,
    pub bdorderid: String,
    /// Bank reference number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bank_reference_no: Option<String>,
    /// Transaction date
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_date: Option<String>,
    /// UPI transaction details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upi: Option<BilldeskUpiSyncData>,
}

/// UPI specific sync data
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskUpiSyncData {
    /// UPI transaction reference
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upi_txn_id: Option<String>,
    /// Customer VPA
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_vpa: Option<String>,
}

/// Error response structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BilldeskErrorResponse {
    pub error_code: Option<String>,
    pub error_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Convert successful payment response to PaymentsResponseData
impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
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
            BilldeskPaymentsResponse::Error(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.error_code.unwrap_or_else(|| "UNKNOWN_ERROR".to_string()),
                    status_code: http_code,
                    message: error_data.error_description.clone().unwrap_or_else(|| "Payment failed".to_string()),
                    reason: error_data.error_description,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            BilldeskPaymentsResponse::Success(response_data) => {
                let connector_transaction_id = response_data.bdorderid.clone();
                
                // Determine status based on response
                let attempt_status = match response_data.status.as_str() {
                    constants::SUCCESS_STATUS => common_enums::AttemptStatus::Charged,
                    constants::PENDING_STATUS => common_enums::AttemptStatus::AuthenticationPending,
                    _ => common_enums::AttemptStatus::Failure,
                };
                
                // Handle UPI Intent redirections
                let redirection_data = if let Some(payment_url) = &response_data.payment_url {
                    Some(Box::new(RedirectForm::Form {
                        endpoint: payment_url.clone(),
                        method: Method::Get,
                        form_fields: Default::default(),
                    }))
                } else if let Some(upi_data) = &response_data.upi {
                    if let Some(intent_url) = &upi_data.upi_intent_url {
                        Some(Box::new(RedirectForm::Form {
                            endpoint: intent_url.clone(),
                            method: Method::Get,
                            form_fields: Default::default(),
                        }))
                    } else {
                        None
                    }
                } else {
                    None
                };
                
                (
                    attempt_status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id.clone()),
                        redirection_data,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: Some(connector_transaction_id),
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

/// Implement TryFrom for sync request
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
        let auth = BilldeskAuth::try_from(&item.router_data.connector_auth_type)?;
        let merchant_id = auth.merchant_id.ok_or(errors::ConnectorError::FailedToObtainAuthType)?;
        
        let transaction_id = item.router_data.request.connector_transaction_id
            .get_connector_transaction_id()
            .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?;
        
        Ok(Self {
            mercid: merchant_id,
            orderid: transaction_id,
        })
    }
}

/// Convert sync response to PaymentsResponseData
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
        
        let (status, response) = match response {
            BilldeskPaymentsSyncResponse::Error(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.error_code.unwrap_or_else(|| "SYNC_ERROR".to_string()),
                    status_code: http_code,
                    message: error_data.error_description.clone().unwrap_or_else(|| "Sync failed".to_string()),
                    reason: error_data.error_description,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            BilldeskPaymentsSyncResponse::Success(response_data) => {
                let connector_transaction_id = response_data.bdorderid.clone();
                
                // Parse amount if available
                let amount_received = if !response_data.amount.is_empty() {
                    response_data.amount.parse::<i64>()
                        .ok()
                        .map(MinorUnit::new)
                } else {
                    None
                };
                
                // Determine final status
                let attempt_status = match response_data.status.as_str() {
                    constants::SUCCESS_STATUS => common_enums::AttemptStatus::Charged,
                    constants::PENDING_STATUS => common_enums::AttemptStatus::AuthenticationPending,
                    _ => common_enums::AttemptStatus::Failure,
                };
                
                (
                    attempt_status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id.clone()),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: response_data.bank_reference_no,
                        connector_response_reference_id: Some(connector_transaction_id),
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