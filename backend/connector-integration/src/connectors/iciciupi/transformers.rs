use common_utils::{
    types::StringMinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, ResponseId},
    errors::{self, ConnectorError},
    payment_method_data::PaymentMethodDataTypes,
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::iciciupi::IciciUpiRouterData, types::ResponseRouterData};

#[derive(Debug, Clone)]
pub struct IciciUpiRouterData<R, T> {
    pub router_data: R,
    pub connector: IciciUpiConnectorData<T>,
}

#[derive(Debug, Clone)]
pub struct IciciUpiConnectorData<T> {
    pub amount_converter: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiAuth {
    pub merchant_id: Secret<String>,
    pub sub_merchant_id: Option<Secret<String>>,
    pub terminal_id: Secret<String>,
    pub api_key: Option<Secret<String>>,
    pub encryption_key: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for IciciUpiAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, .. } => {
                // For now, create a basic auth structure
                // TODO: Implement proper auth parsing based on ICICI UPI requirements
                Ok(Self {
                    merchant_id: api_key.clone(), // Temporary - should be parsed properly
                    sub_merchant_id: None,
                    terminal_id: Secret::new("default".to_string()), // Temporary
                    api_key: Some(api_key.clone()),
                    encryption_key: None,
                })
            }
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiPaymentsRequest {
    pub payer_va: String,
    pub amount: StringMinorUnit,
    pub note: Option<String>,
    pub collect_by_date: Option<String>,
    pub merchant_id: String,
    pub merchant_name: Option<String>,
    pub sub_merchant_id: Option<String>,
    pub sub_merchant_name: Option<String>,
    pub terminal_id: String,
    pub merchant_tran_id: String,
    pub bill_number: Option<String>,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<IciciUpiRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for IciciUpiPaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: IciciUpiRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = IciciUpiAuth::try_from(&item.router_data.connector_auth_type)?;
        
        // Extract UPI payment method data
        let upi_data = item.router_data.router_data.request.payment_method_data
            .as_ref()
            .and_then(|pm| pm.upi.as_ref())
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "upi_payment_method_data",
            })?;

        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.router_data.request.minor_amount,
                item.router_data.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            payer_va: upi_data.vpa.clone(),
            amount,
            note: item.router_data.router_data.request.description.clone(),
            collect_by_date: None, // Can be configured based on requirements
            merchant_id: auth.merchant_id.expose().clone(),
            merchant_name: None, // Can be extracted from router data if available
            sub_merchant_id: auth.sub_merchant_id.as_ref().map(|s| s.expose().clone()),
            sub_merchant_name: None,
            terminal_id: auth.terminal_id.expose().clone(),
            merchant_tran_id: item.router_data.resource_common_data.connector_request_reference_id.clone(),
            bill_number: None, // Can be generated or extracted from router data
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiPaymentsSyncRequest {
    pub merchant_id: String,
    pub sub_merchant_id: Option<String>,
    pub terminal_id: String,
    pub transaction_type: Option<String>,
    pub merchant_tran_id: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<IciciUpiRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for IciciUpiPaymentsSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: IciciUpiRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = IciciUpiAuth::try_from(&item.router_data.connector_auth_type)?;

        Ok(Self {
            merchant_id: auth.merchant_id.expose().clone(),
            sub_merchant_id: auth.sub_merchant_id.as_ref().map(|s| s.expose().clone()),
            terminal_id: auth.terminal_id.expose().clone(),
            transaction_type: Some(crate::connectors::iciciupi::constants::COLLECT_PAY_TRANSACTION.to_string()),
            merchant_tran_id: item.router_data.request.connector_transaction_id
                .get_connector_transaction_id()
                .map_err(|_e| errors::ConnectorError::RequestEncodingFailed)?,
        })
    }
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiPaymentsResponse {
    pub act_code: Option<String>,
    pub merchant_id: Option<String>,
    pub sub_merchant_id: Option<String>,
    pub terminal_id: Option<String>,
    pub amount: Option<String>,
    pub success: bool,
    pub message: String,
    pub merchant_tran_id: Option<String>,
    pub bank_rrn: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiPaymentsSyncResponse {
    pub code: Option<i32>,
    pub status: Option<String>,
    pub response: Option<IciciUpiPaymentsResponse>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiErrorResponse {
    pub error_code: String,
    pub error_message: String,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(untagged)]
pub enum IciciUpiResponseEnum {
    Success(IciciUpiPaymentsResponse),
    Error(IciciUpiErrorResponse),
}

impl From<IciciUpiPaymentsResponse> for common_enums::AttemptStatus {
    fn from(item: IciciUpiPaymentsResponse) -> Self {
        if item.success {
            match item.act_code.as_deref() {
                Some("000") | Some("00") => Self::Charged,
                Some("001") | Some("01") => Self::Pending,
                _ => Self::AuthenticationPending,
            }
        } else {
            Self::Failure
        }
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<IciciUpiResponseEnum, IciciUpiRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<IciciUpiResponseEnum, IciciUpiRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            IciciUpiResponseEnum::Success(response_data) => {
                let attempt_status = common_enums::AttemptStatus::from(response_data.clone());
                
                (
                    attempt_status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            response_data
                                .merchant_tran_id
                                .clone()
                                .unwrap_or_else(|| router_data.router_data.resource_common_data.connector_request_reference_id.clone()),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: response_data.bank_rrn,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            IciciUpiResponseEnum::Error(error_data) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_data.error_code,
                    status_code: http_code,
                    message: error_data.error_message.clone(),
                    reason: Some(error_data.error_message),
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
                ..router_data.router_data.resource_common_data
            },
            response,
            ..router_data.router_data
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<IciciUpiPaymentsSyncResponse, IciciUpiRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<IciciUpiPaymentsSyncResponse, IciciUpiRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response.response {
            Some(response_data) => {
                let attempt_status = common_enums::AttemptStatus::from(response_data.clone());
                
                (
                    attempt_status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            response_data
                                .merchant_tran_id
                                .clone()
                                .unwrap_or_else(|| router_data.router_data.request.connector_transaction_id
                                    .get_connector_transaction_id()
                                    .unwrap_or_default()),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: response_data.bank_rrn,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            None => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: "NO_RESPONSE".to_string(),
                    status_code: http_code,
                    message: "No response received from ICICI UPI".to_string(),
                    reason: Some("No response received from ICICI UPI".to_string()),
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
                ..router_data.router_data.resource_common_data
            },
            response,
            ..router_data.router_data
        })
    }
}

// Stub types for unsupported flows - unique types for each flow
#[derive(Debug, Clone, Serialize)]
pub struct IciciUpiVoidRequest;

#[derive(Debug, Clone)]
pub struct IciciUpiVoidResponse;

#[derive(Debug, Clone, Serialize)]
pub struct IciciUpiCaptureRequest;

#[derive(Debug, Clone)]
pub struct IciciUpiCaptureResponse;

#[derive(Debug, Clone, Serialize)]
pub struct IciciUpiRefundRequest;

#[derive(Debug, Clone)]
pub struct IciciUpiRefundResponse;

#[derive(Debug, Clone, Serialize)]
pub struct IciciUpiRSyncRequest;

#[derive(Debug, Clone)]
pub struct IciciUpiRSyncResponse;

#[derive(Debug, Clone, Serialize)]
pub struct IciciUpiCreateOrderRequest;

#[derive(Debug, Clone)]
pub struct IciciUpiCreateOrderResponse;

#[derive(Debug, Clone, Serialize)]
pub struct IciciUpiSessionTokenRequest;

#[derive(Debug, Clone)]
pub struct IciciUpiSessionTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct IciciUpiSetupMandateRequest;

#[derive(Debug, Clone)]
pub struct IciciUpiSetupMandateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct IciciUpiRepeatPaymentRequest;

#[derive(Debug, Clone)]
pub struct IciciUpiRepeatPaymentResponse;

#[derive(Debug, Clone, Serialize)]
pub struct IciciUpiAcceptDisputeRequest;

#[derive(Debug, Clone)]
pub struct IciciUpiAcceptDisputeResponse;

#[derive(Debug, Clone, Serialize)]
pub struct IciciUpiSubmitEvidenceRequest;

#[derive(Debug, Clone)]
pub struct IciciUpiSubmitEvidenceResponse;

#[derive(Debug, Clone, Serialize)]
pub struct IciciUpiDefendDisputeRequest;

#[derive(Debug, Clone)]
pub struct IciciUpiDefendDisputeResponse;

// Additional stub types for authentication and other flows
#[derive(Debug, Clone, Serialize)]
pub struct IciciUpiPreAuthenticateRequest;

#[derive(Debug, Clone)]
pub struct IciciUpiPreAuthenticateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct IciciUpiAuthenticateRequest;

#[derive(Debug, Clone)]
pub struct IciciUpiAuthenticateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct IciciUpiPostAuthenticateRequest;

#[derive(Debug, Clone)]
pub struct IciciUpiPostAuthenticateResponse;

#[derive(Debug, Clone, Serialize)]
pub struct IciciUpiPaymentMethodTokenRequest;

#[derive(Debug, Clone)]
pub struct IciciUpiPaymentMethodTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct IciciUpiCreateAccessTokenRequest;

#[derive(Debug, Clone)]
pub struct IciciUpiCreateAccessTokenResponse;

#[derive(Debug, Clone, Serialize)]
pub struct IciciUpiCreateConnectorCustomerRequest;

#[derive(Debug, Clone)]
pub struct IciciUpiCreateConnectorCustomerResponse;