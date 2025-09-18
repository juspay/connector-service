use common_utils::{
    errors::CustomResult,
    ext_traits::ValueExt,
    id_type,
    request::Method,
    types::StringMinorUnit,
    Email,
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsSyncData, RefundFlowData, RefundSyncData, InvoiceResponse},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::{ResponseId, Connectors},
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};
use hyperswitch_common_utils::types as connector_auth;

use crate::{
    connectors::billdesk::BilldeskRouterData,
    types::{ResponseRouterData, ConnectorRequest},
    utils::BuildRequest,
};

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsRequest {
    amount: String,
    currency: String,
    transaction_id: String,
    customer_id: String,
    merchant_id: String,
    upi: Option<BilldeskUpiDetails>,
    return_url: String,
    ip_address: String,
    user_agent: String,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskUpiDetails {
    vpa: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    payment_mode: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsResponse {
    transaction_id: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirection_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsSyncRequest {
    transaction_id: String,
    merchant_id: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskPaymentsSyncResponse {
    transaction_id: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskRefundsSyncRequest {
    refund_id: String,
    merchant_id: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskRefundsSyncResponse {
    refund_id: String,
    transaction_id: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refund_amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BilldeskErrorResponse {
    #[serde(rename = "error")]
    pub error: serde_json::Value,
    #[serde(rename = "errorDescription")]
    pub error_description: Option<String>,
    #[serde(rename = "errorCode")]
    pub error_code: Option<String>,
}

// Helper function to extract merchant ID from auth type
fn get_merchant_id(
    connector_auth_type: &ConnectorAuthType,
) -> Result<Secret<String>, errors::ConnectorError> {
    match connector_auth_type {
        ConnectorAuthType::ConnectorAuthKey { auth_key } => {
            let auth_key = auth_key.get_key()
                .expose()
                .parse_value::<connector_auth::BilldeskAuth>("BilldeskAuth")
                .change_context(errors::ConnectorError::InvalidDataFormat {
                    field_name: "auth_key",
                })?;
            Ok(auth_key.merchant_id)
        }
        _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
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
        let merchant_id = get_merchant_id(&item.router_data.connector_auth_type)?;
        
        let ip_address = item.router_data.request.get_ip_address_as_optional()
            .map(|ip| ip.expose())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        
        let user_agent = item.router_data.request.browser_info
            .as_ref()
            .and_then(|info| info.user_agent.clone())
            .unwrap_or_else(|| "Mozilla/5.0".to_string());

        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Extract UPI payment method details
        let upi_details = match &item.router_data.request.payment_method_data {
            domain_types::payment_method_data::PaymentMethodData::Upi(upi_data) => {
                match upi_data {
                    domain_types::payment_method_data::UpiData::UpiIntent(upi_intent) => Some(BilldeskUpiDetails {
                        vpa: upi_intent.vpa_id.clone().map(|vpa| vpa.expose()) 
                            .unwrap_or_else(|| "".to_string()),
                        payment_mode: Some("INTENT".to_string()),
                    }),
                    domain_types::payment_method_data::UpiData::Upi_collect(upi_collect) => Some(BilldeskUpiDetails {
                        vpa: upi_collect.vpa_id.clone().map(|vpa| vpa.expose())
                            .unwrap_or_else(|| "".to_string()),
                        payment_mode: Some("COLLECT".to_string()),
                    }),
                    _ => None,
                }
            }
            _ => None,
        };

        Ok(Self {
            amount,
            currency: item.router_data.request.currency.to_string(),
            transaction_id: item
                .router_data
                .resource_common_data
                .connector_request_reference_id,
            customer_id: customer_id.to_string(),
            merchant_id: merchant_id.expose(),
            upi: upi_details,
            return_url,
            ip_address,
            user_agent,
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
        let merchant_id = get_merchant_id(&item.router_data.connector_auth_type)?;
        let transaction_id = item.router_data.request.payment_method.transaction_id();
        
        Ok(Self {
            transaction_id,
            merchant_id: merchant_id.expose(),
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
> TryFrom<BilldeskRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>>
    for BilldeskRefundsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: BilldeskRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let merchant_id = get_merchant_id(&item.router_data.connector_auth_type)?;
        let refund_id = item.router_data.request.connector_refund_id.clone()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "connector_refund_id",
            })?;
        
        Ok(Self {
            refund_id,
            merchant_id: merchant_id.expose(),
        })
    }
}

impl<
    F,
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
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
            BilldeskPaymentsResponse {
                error: Some(error_value),
                error_description,
                ..
            } => {
                let error_code = error_value.as_str().to_string();
                let reason = error_description.clone();
                
                (
                    common_enums::AttemptStatus::Failure,
                    Err(ErrorResponse {
                        code: error_code,
                        status_code: http_code,
                        message: error_description.unwrap_or_else(|| "Unknown error".to_string()),
                        reason,
                        attempt_status: None,
                        connector_transaction_id: None,
                        network_advice_code: None,
                        network_decline_code: None,
                        network_error_message: None,
                    }),
                )
            }
            BilldeskPaymentsResponse {
                redirection_url: Some(url),
                ..
            } => {
                // Successful initiation with redirection
                let redirection_data = Some(Box::new(
                    domain_types::router_response_types::RedirectForm::Form {
                        endpoint: url.clone(),
                        method: Method::Post,
                        form_fields: Default::default(),
                    },
                ));
                
                (
                    common_enums::AttemptStatus::AuthenticationPending,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            router_data
                                .resource_common_data
                                .connector_request_reference_id
                                .clone(),
                        ),
                        redirection_data,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            _ => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: "UNKNOWN_STATUS".to_string(),
                    status_code: http_code,
                    message: "Unknown status received from Billdesk".to_string(),
                    reason: None,
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
                status,
                ..router_data.resource_common_data
            },
            response,
            ..router_data
        })
    }
}

impl<
    F,
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
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

        let status = match response.status.to_uppercase().as_str() {
            "SUCCESS" | "COMPLETED" | "CHARGED" => common_enums::AttemptStatus::Charged,
            "PENDING" | "PROCESSING" => common_enums::AttemptStatus::Pending,
            "FAILED" | "CANCELLED" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Pending,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.transaction_id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: response.auth_status,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: http_code,
            }),
            ..router_data
        })
    }
}

impl<
    F,
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
> TryFrom<ResponseRouterData<BilldeskRefundsSyncResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<BilldeskRefundsSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let status = match response.status.to_uppercase().as_str() {
            "SUCCESS" | "COMPLETED" | "CHARGED" => common_enums::RefundStatus::RefundSuccess,
            "PENDING" | "PROCESSING" => common_enums::RefundStatus::RefundPending,
            "FAILED" | "CANCELLED" => common_enums::RefundStatus::RefundFailure,
            _ => common_enums::RefundStatus::RefundPending,
        };

        Ok(Self {
            resource_common_data: router_data.resource_common_data,
            response: Ok(RefundsResponseData {
                connector_refund_id: response.refund_id,
                refund_status: status,
                connector_transaction_id: Some(response.transaction_id),
                error_code: response.error_code,
                error_message: response.error_description,
                status_code: http_code,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            }),
            ..router_data
        })
    }
}