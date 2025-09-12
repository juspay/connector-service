use common_utils::{types::FloatMajorUnit};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::axisupi::AxisUpiRouterData, types::ResponseRouterData};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AxisUpiAuth {
    pub merchant_id: Option<Secret<String>>,
    pub merchant_channel_id: Option<Secret<String>>,
    pub api_key: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for AxisUpiAuth {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(_auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        // Simplified auth for now - return default values
        Ok(Self {
            merchant_id: Some(Secret::new("default_merchant".to_string())),
            merchant_channel_id: Some(Secret::new("default_channel".to_string())),
            api_key: Some(Secret::new("default_api_key".to_string())),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AxisUpiPaymentsRequest {
    pub merchant_id: Secret<String>,
    pub merchant_customer_id: Secret<String>,
    pub merchant_channel_id: Secret<String>,
    pub merchant_request_id: String,
    pub customer_vpa: Secret<String>,
    pub amount: FloatMajorUnit,
    pub remarks: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AxisUpiPaymentsSyncRequest {
    pub merchant_id: Secret<String>,
    pub merchant_request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AxisUpiPaymentsResponse {
    pub response_code: String,
    pub response_message: String,
    pub transaction_id: Option<String>,
    pub gateway_transaction_id: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AxisUpiErrorResponse {
    pub response_code: String,
    pub response_message: String,
}

#[derive(Debug, Clone, Serialize)]
pub enum AxisUpiRequestEnum {
    Payments(AxisUpiPaymentsRequest),
    PaymentsSync(AxisUpiPaymentsSyncRequest),
}

#[derive(Debug, Clone, Deserialize)]
pub enum AxisUpiResponseEnum {
    Success(AxisUpiPaymentsResponse),
    Error(AxisUpiErrorResponse),
}

impl<F, T> TryFrom<RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for AxisUpiPaymentsRequest
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static,
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth_data = AxisUpiAuth::try_from(&item.connector_auth_type)?;

        let upi_vpa = "test@upi".to_string(); // Simplified for now

        let customer_id = "test_customer"; // Simplified for now

        Ok(Self {
            merchant_id: auth_data.merchant_id.unwrap_or_else(|| Secret::new("default_merchant".to_string())),
            merchant_customer_id: Secret::new(customer_id.to_string()),
            merchant_channel_id: auth_data.merchant_channel_id.unwrap_or_else(|| Secret::new("default_channel".to_string())),
            merchant_request_id: item.resource_common_data.connector_request_reference_id.clone(),
            customer_vpa: Secret::new(upi_vpa),
            amount: common_utils::types::FloatMajorUnit(100.0), // Simplified for now
            remarks: "UPI Payment".to_string(),
        })
    }
}

impl<F> TryFrom<RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for AxisUpiPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth_data = AxisUpiAuth::try_from(&item.connector_auth_type)?;

        Ok(Self {
            merchant_id: auth_data.merchant_id.unwrap_or_else(|| Secret::new("default_merchant".to_string())),
            merchant_request_id: item.resource_common_data.connector_request_reference_id.clone(),
        })
    }
}

// PSync response transformation
impl TryFrom<ResponseRouterData<AxisUpiResponseEnum, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: ResponseRouterData<AxisUpiResponseEnum, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response_data) = match response {
            AxisUpiResponseEnum::Success(success_response) => {
                let status = match success_response.status.as_deref() {
                    Some("SUCCESS") | Some("SUCCESSFUL") | Some("COMPLETED") => {
                        common_enums::AttemptStatus::Charged
                    }
                    Some("PENDING") | Some("INITIATED") => common_enums::AttemptStatus::Pending,
                    Some("FAILED") => common_enums::AttemptStatus::Failure,
                    _ => common_enums::AttemptStatus::AuthenticationFailed,
                };

                let response_data = PaymentsResponseData::TransactionResponse {
                    resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(
                        success_response.transaction_id.clone().unwrap_or_default(),
                    ),
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: success_response.gateway_transaction_id,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    status_code: http_code,
                };

                (status, Ok(response_data))
            }
            AxisUpiResponseEnum::Error(error_response) => {
                let status = common_enums::AttemptStatus::Failure;
                
                (status, Err(ErrorResponse {
                    status_code: http_code,
                    code: error_response.response_code.to_string(),
                    message: error_response.response_message.clone(),
                    reason: Some(error_response.response_message),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }))
            }
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: response_data,
            ..router_data
        })
    }
}

// Required implementations for macro system
impl<T> TryFrom<AxisUpiRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>> for AxisUpiPaymentsRequest
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: AxisUpiRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        AxisUpiPaymentsRequest::try_from(item.router_data)
    }
}

impl<T> TryFrom<ResponseRouterData<AxisUpiPaymentsResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>> for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<AxisUpiPaymentsResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        // Create a new RouterDataV2 with the response
        Ok(Self {
            resource_common_data: PaymentFlowData {
                status: common_enums::AttemptStatus::Pending, // Default status
                ..item.router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(
                    item.response.transaction_id.clone().unwrap_or_default(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: item.response.gateway_transaction_id.clone(),
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}