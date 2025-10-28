use std::collections::HashMap;

use common_utils::{
    errors::CustomResult, request::Method,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use hyperswitch_masking::{Secret, ExposeInterface};
use serde::{Deserialize, Serialize};

use crate::types::ResponseRouterData;

// Type alias for router data with connector
pub type BilldeskRouterData<RouterData, T> = crate::connectors::ConnectorRouterData<RouterData, T>;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsRequest {
    msg: String,
    useragent: String,
    ipaddress: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsSyncRequest {
    msg: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsResponse {
    msg: Option<String>,
    rdata: Option<BilldeskRdata>,
    txnrefno: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsSyncResponse {
    msg: Option<String>,
    rdata: Option<BilldeskRdata>,
    txnrefno: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskRdata {
    parameters: HashMap<String, String>,
    url: Option<String>,
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
pub struct BilldeskMandateRequest;
#[derive(Debug, Clone)]
pub struct BilldeskMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskRepeatPaymentRequest;
#[derive(Debug, Clone)]
pub struct BilldeskRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskCreateOrderRequest;
#[derive(Debug, Clone)]
pub struct BilldeskCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct BilldeskSessionTokenRequest;
#[derive(Debug, Clone)]
pub struct BilldeskSessionTokenResponse;

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

#[derive(Debug, Clone)]
pub struct BilldeskAuth {
    pub merchant_id: Secret<String>,
    pub checksum_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for BilldeskAuth {
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1, .. } => Ok(Self {
                merchant_id: api_key.clone(),
                checksum_key: key1.clone().unwrap_or_else(|| Secret::new("".to_string())),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

pub fn generate_checksum<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>(
    req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    auth: &BilldeskAuth,
    amount_converter: &dyn common_utils::types::AmountConverterTrait<Output = String>,
) -> CustomResult<String, errors::ConnectorError> {
    // Generate checksum based on Billdesk's requirements
    // This is a simplified implementation - in production, use proper checksum algorithm
    let amount = amount_converter.convert(
        req.request.minor_amount,
        req.request.currency,
    ).map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;
    
    let checksum_input = format!(
        "{}{}{}",
        req.resource_common_data.connector_request_reference_id,
        amount,
        auth.checksum_key.expose()
    );
    
    // Use SHA256 for checksum generation (adjust based on Billdesk's actual requirements)
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(checksum_input.as_bytes());
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<BilldeskRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for BilldeskPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: BilldeskRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let amount = item.connector.amount_converter.convert(
            item.router_data.request.minor_amount,
            item.router_data.request.currency,
        )?;
        let currency = item.router_data.request.currency.to_string();
        
        // Extract IP address
        let ip_address = item.router_data.request.get_ip_address_as_optional()
            .map(|ip| ip.expose())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        
        // Extract user agent
        let user_agent = item.router_data.request.browser_info
            .as_ref()
            .and_then(|info| info.user_agent.clone())
            .unwrap_or_else(|| "Mozilla/5.0".to_string());
        
        // Get merchant ID from auth type
        let merchant_id = match &item.router_data.connector_auth_type {
            ConnectorAuthType::SignatureKey { api_key, .. } => api_key.clone().expose(),
            _ => return Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        };

        // Build message based on payment method type
        let msg = match item.router_data.request.payment_method_type {
            Some(common_enums::PaymentMethodType::UpiCollect) => {
                // UPI payment message format
                format!(
                    r#"{{"merchantid":"{}","customerid":"{}","txnamount":"{}","currency":"{}","txntype":"UPI","itemcode":"DIRECT","txnreference":"{}"}}"#,
                    merchant_id,
                    customer_id.get_string_repr(),
                    amount,
                    currency,
                    item.router_data.resource_common_data.connector_request_reference_id
                )
            }
            _ => {
                // Default message format
                format!(
                    r#"{{"merchantid":"{}","customerid":"{}","txnamount":"{}","currency":"{}","txntype":"DIRECT","itemcode":"DIRECT","txnreference":"{}"}}"#,
                    merchant_id,
                    customer_id.get_string_repr(),
                    amount,
                    currency,
                    item.router_data.resource_common_data.connector_request_reference_id
                )
            }
        };
        
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
    > TryFrom<BilldeskRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for BilldeskPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: BilldeskRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        // Get merchant ID from auth type
        let merchant_id = match &item.router_data.connector_auth_type {
            ConnectorAuthType::SignatureKey { api_key, .. } => api_key.clone().expose(),
            _ => return Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        };

        let msg = format!(
            r#"{{"merchantid":"{}","txnreference":"{}"}}"#,
            merchant_id,
            item.router_data.request.connector_transaction_id.get_connector_transaction_id()
                .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?
        );
        
        Ok(Self { msg })
    }
}

impl TryFrom<BilldeskPaymentsResponse> for PaymentsResponseData {
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(response: BilldeskPaymentsResponse) -> Result<Self, Self::Error> {
        let status = if response.msg.is_some() {
            common_enums::AttemptStatus::Charged
        } else {
            common_enums::AttemptStatus::Failure
        };
        
        Ok(PaymentsResponseData::TransactionResponse {
            resource_id: response.txnrefno
                .map(ResponseId::ConnectorTransactionId)
                .unwrap_or_else(|| ResponseId::NoResponseId),
            redirection_data: response.rdata.and_then(|r| r.url).map(|url| {
                Box::new(RedirectForm::Form {
                    endpoint: url,
                    method: Method::Get,
                    form_fields: std::collections::HashMap::new(),
                })
            }),
            connector_metadata: Some(serde_json::json!(response)),
            mandate_reference: None,
            network_txn_id: None,
            connector_response_reference_id: response.txnrefno,
            incremental_authorization_allowed: None,
            status_code: if status == common_enums::AttemptStatus::Charged { 200 } else { 400 },
        })
    }
}

impl TryFrom<BilldeskPaymentsSyncResponse> for PaymentsResponseData {
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(response: BilldeskPaymentsSyncResponse) -> Result<Self, Self::Error> {
        let status = if response.msg.is_some() {
            common_enums::AttemptStatus::Charged
        } else {
            common_enums::AttemptStatus::Failure
        };
        
        Ok(PaymentsResponseData::TransactionResponse {
            resource_id: response.txnrefno
                .map(ResponseId::ConnectorTransactionId)
                .unwrap_or_else(|| ResponseId::NoResponseId),
            redirection_data: response.rdata.and_then(|r| r.url).map(|url| {
                Box::new(RedirectForm::Form {
                    endpoint: url,
                    method: Method::Get,
                    form_fields: std::collections::HashMap::new(),
                })
            }),
            connector_metadata: Some(serde_json::json!(response)),
            mandate_reference: None,
            network_txn_id: None,
            connector_response_reference_id: response.txnrefno,
            incremental_authorization_allowed: None,
            status_code: if status == common_enums::AttemptStatus::Charged { 200 } else { 400 },
        })
    }
}

// Implementation for ResponseRouterData to RouterDataV2 conversion (required by macro)
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<ResponseRouterData<BilldeskPaymentsResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
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
        
        let payments_response = PaymentsResponseData::try_from(response)?;
        
        Ok(Self {
            response: payments_response,
            router_data,
            http_code,
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
    > TryFrom<ResponseRouterData<BilldeskPaymentsSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
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
        
        let payments_response = PaymentsResponseData::try_from(response)?;
        
        Ok(Self {
            response: payments_response,
            router_data,
            http_code,
        })
    }
}