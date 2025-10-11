use std::collections::HashMap;

use common_utils::{
    errors::CustomResult, ext_traits::ValueExt, request::Method, types::StringMinorUnit,
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
use hyperswitch_masking::{Mask, Maskable, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{connectors::iciciupi::IciciUpiRouterData, types::ResponseRouterData};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiAuth {
    pub api_key: Option<Secret<String>>,
    pub merchant_id: Option<Secret<String>>,
    pub sub_merchant_id: Option<Secret<String>>,
    pub terminal_id: Option<Secret<String>>,
}

impl TryFrom<&ConnectorAuthType> for IciciUpiAuth {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey { api_key, .. } => {
                let auth_data: IciciUpiAuth = api_key
                    .parse_value("IciciUpiAuth")
                    .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
                Ok(auth_data)
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
    pub terminal_id: Option<String>,
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
        
        // Extract UPI virtual address from payment method data
        let payer_va = item.router_data.request.payment_method_data
            .get_upi_vpa()
            .change_context(ConnectorError::MissingRequiredField {
                field_name: "payer_va",
            })?;

        let amount = item.amount.get_amount_as_string();
        
        let merchant_id = auth.merchant_id
            .ok_or(ConnectorError::MissingRequiredField {
                field_name: "merchant_id",
            })?
            .expose()
            .clone();

        Ok(Self {
            payer_va,
            amount,
            note: item.router_data.request.description.clone(),
            collect_by_date: None, // Can be set based on business logic
            merchant_id,
            merchant_name: None, // Can be extracted from router data if available
            sub_merchant_id: auth.sub_merchant_id.map(|s| s.expose().clone()),
            sub_merchant_name: None,
            terminal_id: auth.terminal_id.map(|s| s.expose().clone()),
            merchant_tran_id: item.router_data.resource_common_data.connector_request_reference_id.clone(),
            bill_number: None, // Can be generated if needed
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiPaymentsSyncRequest {
    pub merchant_id: String,
    pub sub_merchant_id: Option<String>,
    pub terminal_id: Option<String>,
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
        
        let merchant_id = auth.merchant_id
            .ok_or(ConnectorError::MissingRequiredField {
                field_name: "merchant_id",
            })?
            .expose()
            .clone();

        Ok(Self {
            merchant_id,
            sub_merchant_id: auth.sub_merchant_id.map(|s| s.expose().clone()),
            terminal_id: auth.terminal_id.map(|s| s.expose().clone()),
            transaction_type: Some("COLLECT_PAY".to_string()),
            merchant_tran_id: item.router_data.request.connector_transaction_id
                .get_connector_transaction_id()
                .map_err(|_| ConnectorError::MissingRequiredField {
                    field_name: "connector_transaction_id",
                })?,
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
    pub act_code: Option<String>,
    pub merchant_id: Option<String>,
    pub sub_merchant_id: Option<String>,
    pub terminal_id: Option<String>,
    pub amount: Option<String>,
    pub success: bool,
    pub message: String,
    pub merchant_tran_id: Option<String>,
    pub bank_rrn: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IciciUpiErrorResponse {
    pub error_code: String,
    pub error_message: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum IciciUpiResponse {
    Success(IciciUpiPaymentsResponse),
    Error(IciciUpiErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum IciciUpiSyncResponse {
    Success(IciciUpiPaymentsSyncResponse),
    Error(IciciUpiErrorResponse),
}

impl From<IciciUpiPaymentsResponse> for common_enums::AttemptStatus {
    fn from(response: IciciUpiPaymentsResponse) -> Self {
        if response.success {
            match response.act_code.as_deref() {
                Some("00") | Some("0") => common_enums::AttemptStatus::Charged,
                Some("01") | Some("1") => common_enums::AttemptStatus::Pending,
                _ => common_enums::AttemptStatus::AuthenticationPending,
            }
        } else {
            common_enums::AttemptStatus::Failure
        }
    }
}

impl From<IciciUpiPaymentsSyncResponse> for common_enums::AttemptStatus {
    fn from(response: IciciUpiPaymentsSyncResponse) -> Self {
        if response.success {
            match response.status.as_deref() {
                Some("SUCCESS") => common_enums::AttemptStatus::Charged,
                Some("PENDING") => common_enums::AttemptStatus::Pending,
                _ => common_enums::AttemptStatus::AuthenticationPending,
            }
        } else {
            common_enums::AttemptStatus::Failure
        }
    }
}

impl<F, T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<IciciUpiResponse, RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<IciciUpiResponse, RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            IciciUpiResponse::Success(success_response) => {
                let attempt_status = success_response.clone().into();
                (
                    attempt_status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            success_response.merchant_tran_id.unwrap_or_else(|| {
                                router_data.resource_common_data.connector_request_reference_id.clone()
                            }),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: success_response.bank_rrn,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            IciciUpiResponse::Error(error_response) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_response.error_code,
                    status_code: http_code,
                    message: error_response.error_message.clone(),
                    reason: Some(error_response.error_message),
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

impl<F, T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<IciciUpiSyncResponse, RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<IciciUpiSyncResponse, RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let (status, response) = match response {
            IciciUpiSyncResponse::Success(success_response) => {
                let attempt_status = success_response.clone().into();
                (
                    attempt_status,
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            success_response.merchant_tran_id.unwrap_or_else(|| {
                                router_data.request.connector_transaction_id
                                    .get_connector_transaction_id()
                                    .unwrap_or_default()
                            }),
                        ),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: success_response.bank_rrn,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                )
            }
            IciciUpiSyncResponse::Error(error_response) => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: error_response.error_code,
                    status_code: http_code,
                    message: error_response.error_message.clone(),
                    reason: Some(error_response.error_message),
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

// Stub types for unsupported flows
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