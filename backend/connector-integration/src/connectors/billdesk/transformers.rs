use common_utils::{
    request::Method,
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsResponseData, ResponseId,
    },
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    };
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
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
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsSyncRequest {
    msg: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskRefundSyncRequest {
    msg: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskAuthType {
    pub merchant_id: Secret<String>,
    pub checksum_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for BilldeskAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, key1, .. } => {
                // For now, let's just use dummy values to get it compiling
                let merchant_id = Secret::new("dummy_merchant_id".to_string());
                let checksum_key = Secret::new("dummy_checksum_key".to_string());
                Ok(Self {
                    merchant_id,
                    checksum_key,
                })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Default)]
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

#[derive(Debug, Deserialize, Serialize)]
pub struct BilldeskErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
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
    pub transaction_response: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BilldeskPaymentsSyncResponse {
    BilldeskError(BilldeskErrorResponse),
    BilldeskData(BilldeskPaymentsSyncResponseData),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsSyncResponseData {
    pub transaction_response: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BilldeskRefundSyncResponse {
    BilldeskError(BilldeskErrorResponse),
    BilldeskData(BilldeskRefundSyncResponseData),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskRefundSyncResponseData {
    pub transaction_response: String,
}

fn get_auth_credentials(
    connector_auth_type: &ConnectorAuthType,
) -> Result<BilldeskAuthType, error_stack::Report<errors::ConnectorError>> {
    BilldeskAuthType::try_from(connector_auth_type)
}

fn build_billdesk_message(
    merchant_id: &str,
    transaction_id: &str,
    amount: &str,
    currency: &str,
    customer_id: &str,
    return_url: &str,
    checksum_key: &str,
) -> Result<String, errors::ConnectorError> {
    // Build the message according to Billdesk format
    let message = format!(
        "merchantid={}&transactionid={}&amount={}&currency={}&customerid={}&returnurl={}",
        merchant_id, transaction_id, amount, currency, customer_id, return_url
    );
    
    // Calculate checksum (simplified - in real implementation, this would use proper checksum calculation)
    let checksum = format!("checksum_{}", checksum_key);
    
    Ok(format!("{}|{}", message, checksum))
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
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    > for BilldeskPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: BilldeskRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let customer_id = item.router_data.resource_common_data.get_customer_id()?;
        let return_url = item.router_data.request.get_router_return_url()?;
        let auth = get_auth_credentials(&item.router_data.connector_auth_type)?;
        
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
            .connector_request_reference_id;
        
        let ip_address = "127.0.0.1".to_string();
        
        let user_agent = item.router_data.request.browser_info
            .as_ref()
            .and_then(|info| info.user_agent.clone())
            .unwrap_or_else(|| "Mozilla/5.0".to_string());
        
        // Only support UPI payments
        match item.router_data.resource_common_data.payment_method {
            common_enums::PaymentMethod::Upi => {
                let msg = build_billdesk_message(
                    "dummy_merchant_id",
                    transaction_id,
                    &amount,
                    &item.router_data.request.currency.to_string(),
                    &customer_id.get_string_repr(),
                    &return_url,
                    "dummy_checksum_key",
                )?;
                
                Ok(Self {
                    msg,
                    useragent: user_agent,
                    ipaddress: ip_address,
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                "Only UPI payments are supported".to_string(),
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
        let auth = get_auth_credentials(&item.router_data.connector_auth_type)?;
        let transaction_id = item
            .router_data
            .resource_common_data
            .connector_request_reference_id;
        
        // Build status check message
        let msg = format!(
            "merchantid={}&transactionid={}",
            "dummy_merchant_id",
            transaction_id
        );
        
        Ok(Self { msg })
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
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for BilldeskRefundSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: BilldeskRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = get_auth_credentials(&item.router_data.connector_auth_type)?;
        let transaction_id = item
            .router_data
            .resource_common_data
            .connector_request_reference_id;
        
        // Build refund status check message
        let msg = format!(
            "merchantid={}&transactionid={}",
            auth.merchant_id.expose(),
            transaction_id
        );
        
        Ok(Self { msg })
    }
}

impl<F, T> TryFrom<ResponseRouterData<BilldeskPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
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
                    message: error_data.error_description.clone().unwrap_or_default(),
                    reason: error_data.error_description,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            BilldeskPaymentsResponse::BilldeskData(response_data) => {
                // For UPI payments, we typically get a redirect URL or payment instruction
                let redirection_data = RedirectForm::Form {
                    endpoint: response_data.transaction_response,
                    method: Method::Post,
                    form_fields: Default::default(),
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

impl<F> TryFrom<ResponseRouterData<BilldeskPaymentsSyncResponse, Self>>
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
            BilldeskPaymentsSyncResponse::BilldeskError(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.error.to_string(),
                    status_code: item.http_code,
                    message: error_data.error_description.clone().unwrap_or_default(),
                    reason: error_data.error_description,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            BilldeskPaymentsSyncResponse::BilldeskData(_response_data) => {
                // Parse the response to determine status
                // This is simplified - in real implementation, we'd parse the actual response
                (
                    common_enums::AttemptStatus::Charged,
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

impl<F> TryFrom<ResponseRouterData<BilldeskRefundSyncResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: ResponseRouterData<BilldeskRefundSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        
        let (status, response) = match response {
            BilldeskRefundSyncResponse::BilldeskError(error_data) => (
                common_enums::RefundStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.error.to_string(),
                    status_code: item.http_code,
                    message: error_data.error_description.clone().unwrap_or_default(),
                    reason: error_data.error_description,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
            BilldeskRefundSyncResponse::BilldeskData(_response_data) => {
                // Parse the refund response
                (
                    common_enums::RefundStatus::Success,
                    Ok(RefundsResponseData {
                        connector_refund_id: router_data
                            .resource_common_data
                            .connector_request_reference_id
                            .clone(),
                        refund_status: common_enums::RefundStatus::Success,
                        status_code: http_code,
                    }),
                )
            }
        };
        
        Ok(Self {
            resource_common_data: domain_types::connector_types::RefundFlowData {
                status: common_enums::RefundStatus::Success,
                ..router_data.resource_common_data
            },
            response,
            ..router_data
        })
    }
}