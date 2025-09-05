use common_enums::{AttemptStatus, RefundStatus};
use common_utils::{
    types::MinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors::ConnectorError,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use crate::types::ResponseRouterData;

// Import the generated ForteRouterData type
use super::ForteRouterData;

// Authentication structure
#[derive(Debug, Clone)]
pub struct ForteAuthType {
    pub api_key: Secret<String>,
    pub organization_id: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for ForteAuthType {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
                organization_id: Secret::new("default".to_string()),
            }),
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                api_key: api_key.to_owned(),
                organization_id: key1.to_owned(),
            }),
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret: _,
            } => Ok(Self {
                api_key: api_key.to_owned(),
                organization_id: key1.to_owned(),
            }),
            _ => Err(ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Request structures with generics
#[derive(Debug, Serialize)]
pub struct FortePaymentRequest<
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
> {
    pub action: String,
    pub authorization_amount: MinorUnit,
    pub billing_address: Option<ForteBillingAddress>,
    pub card: Option<ForteCard<T>>,
    #[serde(rename = "echeck")]
    pub echeck: Option<ForteEcheck>,
}

#[derive(Debug, Serialize)]
pub struct ForteBillingAddress {
    pub first_name: Option<Secret<String>>,
    pub last_name: Option<Secret<String>>,
    pub company: Option<Secret<String>>,
    pub phone: Option<Secret<String>>,
    pub address_line1: Option<Secret<String>>,
    pub address_line2: Option<Secret<String>>,
    pub locality: Option<String>,
    pub region: Option<Secret<String>>,
    pub postal_code: Option<Secret<String>>,
    pub country: Option<common_enums::CountryAlpha2>,
}

#[derive(Debug, Serialize)]
pub struct ForteCard<
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
> {
    pub card_type: String,
    pub name_on_card: Secret<String>,
    pub account_number: RawCardNumber<T>,
    pub expire_month: Secret<String>,
    pub expire_year: Secret<String>,
    pub card_verification_value: Secret<String>,
}

#[derive(Debug, Serialize)]
pub struct ForteEcheck {
    pub sec_code: String,
    pub account_holder: Secret<String>,
    pub account_number: Secret<String>,
    pub routing_number: Secret<String>,
    pub account_type: String,
}

// Capture request
#[derive(Debug, Serialize)]
pub struct ForteCaptureRequest {
    pub action: String,
    pub authorization_amount: Option<MinorUnit>,
}

// Void request
#[derive(Debug, Serialize)]
pub struct ForteVoidRequest {
    pub action: String,
}

// Refund request
#[derive(Debug, Serialize)]
pub struct ForteRefundRequest {
    pub action: String,
    pub authorization_amount: MinorUnit,
    pub original_transaction_id: String,
}

// Sync requests (empty for GET requests)
#[derive(Debug, Serialize)]
pub struct FortePSyncRequest {}

#[derive(Debug, Serialize)]
pub struct ForteRSyncRequest {}

// Response structures
#[derive(Debug, Deserialize, Serialize)]
pub struct FortePaymentResponse {
    pub transaction_id: String,
    pub response: ForteTransactionResponse,
    pub authorization_amount: Option<MinorUnit>,
    pub entered_by: Option<String>,
    pub billing_address: Option<ForteBillingAddressResponse>,
    pub card: Option<ForteCardResponse>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForteTransactionResponse {
    pub response_code: String,
    pub response_desc: String,
    pub authorization_code: Option<String>,
    pub avs_result: Option<String>,
    pub cvv_result: Option<String>,
    pub environment: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForteBillingAddressResponse {
    pub address_id: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub company: Option<String>,
    pub phone: Option<String>,
    pub address_line1: Option<String>,
    pub address_line2: Option<String>,
    pub locality: Option<String>,
    pub region: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForteCardResponse {
    pub name_on_card: Option<String>,
    pub last_4_account_number: Option<String>,
    pub expire_month: Option<String>,
    pub expire_year: Option<String>,
    pub card_type: Option<String>,
}

// Type aliases for other response types
pub type ForteCaptureResponse = FortePaymentResponse;
pub type ForteVoidResponse = FortePaymentResponse;
pub type ForteRefundResponse = FortePaymentResponse;
pub type FortePSyncResponse = FortePaymentResponse;
pub type ForteRSyncResponse = FortePaymentResponse;

// Error response structure
#[derive(Debug, Deserialize, Serialize)]
pub struct ForteErrorResponse {
    pub error: Option<ForteError>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForteError {
    pub code: String,
    pub message: String,
}

// Status mapping functions
fn get_attempt_status_from_response_code(response_code: &str) -> AttemptStatus {
    match response_code {
        "A01" => AttemptStatus::Charged,
        "A05" => AttemptStatus::Authorized,
        "D01" | "D02" | "D03" | "D04" | "D05" | "D06" | "D07" | "D08" | "D09" | "D10" => {
            AttemptStatus::Failure
        }
        _ => AttemptStatus::Pending,
    }
}

fn get_refund_status_from_response_code(response_code: &str) -> RefundStatus {
    match response_code {
        "A01" => RefundStatus::Success,
        "D01" | "D02" | "D03" | "D04" | "D05" | "D06" | "D07" | "D08" | "D09" | "D10" => {
            RefundStatus::Failure
        }
        _ => RefundStatus::Pending,
    }
}

// Request transformation implementations
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for FortePaymentRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        
        let action = match router_data.request.capture_method {
            Some(common_enums::CaptureMethod::Manual) => "authorize".to_string(),
            _ => "sale".to_string(),
        };

        let (card, echeck) = match &router_data.request.payment_method_data {
            PaymentMethodData::Card(card_data) => {
                let forte_card = ForteCard {
                    card_type: get_card_type(&card_data.card_number)?,
                    name_on_card: card_data.card_holder_name.clone().unwrap_or_else(|| Secret::new("Unknown".to_string())),
                    account_number: card_data.card_number.clone(),
                    expire_month: card_data.card_exp_month.clone(),
                    expire_year: card_data.card_exp_year.clone(),
                    card_verification_value: card_data.card_cvc.clone(),
                };
                (Some(forte_card), None)
            }
            _ => {
                return Err(ConnectorError::NotImplemented(
                    "Payment method not supported".into(),
                )
                .into())
            }
        };

        // TODO: Fix billing address access - need to get from PaymentFlowData
        let billing_address = None;

        Ok(Self {
            action,
            authorization_amount: router_data.request.minor_amount,
            billing_address,
            card,
            echeck,
        })
    }
}

// Add TryFrom implementation for ForteRouterData wrapper
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ForteRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for FortePaymentRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        forte_router_data: ForteRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&forte_router_data.router_data)
    }
}

impl<T> TryFrom<ForteRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for FortePSyncRequest
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        _item: ForteRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {})
    }
}

impl<T> TryFrom<ForteRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, T>>
    for ForteCaptureRequest
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        forte_router_data: ForteRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let item = &forte_router_data.router_data;
        Ok(Self {
            action: "capture".to_string(),
            authorization_amount: Some(item.request.minor_amount_to_capture),
        })
    }
}

impl<T> TryFrom<ForteRouterData<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, T>>
    for ForteVoidRequest
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        _item: ForteRouterData<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            action: "void".to_string(),
        })
    }
}

impl<T> TryFrom<ForteRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>>
    for ForteRefundRequest
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        forte_router_data: ForteRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let item = &forte_router_data.router_data;
        Ok(Self {
            action: "credit".to_string(),
            authorization_amount: item.request.minor_refund_amount,
            original_transaction_id: item.request.connector_transaction_id.clone(),
        })
    }
}

impl<T> TryFrom<ForteRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>>
    for ForteRSyncRequest
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        _item: ForteRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {})
    }
}

// Response transformation implementations
impl<F, T> TryFrom<ResponseRouterData<FortePaymentResponse, RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<FortePaymentResponse, RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let status = get_attempt_status_from_response_code(&response.response.response_code);
        let mut router_data = router_data;
        router_data.resource_common_data.status = status;

        if status == AttemptStatus::Failure {
            router_data.response = Err(ErrorResponse {
                status_code: http_code,
                code: response.response.response_code.clone(),
                message: response.response.response_desc.clone(),
                reason: Some(response.response.response_desc),
                attempt_status: Some(AttemptStatus::Failure),
                connector_transaction_id: Some(response.transaction_id),
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            });
        } else {
            router_data.response = Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.transaction_id),
                redirection_data: None,
                connector_metadata: None,
                network_txn_id: response.response.authorization_code,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                mandate_reference: None,
                status_code: http_code,
            });
        }

        Ok(router_data)
    }
}

impl<F> TryFrom<ResponseRouterData<FortePSyncResponse, RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<FortePSyncResponse, RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let status = get_attempt_status_from_response_code(&response.response.response_code);
        let mut router_data = router_data;
        router_data.resource_common_data.status = status;

        if status == AttemptStatus::Failure {
            router_data.response = Err(ErrorResponse {
                status_code: http_code,
                code: response.response.response_code.clone(),
                message: response.response.response_desc.clone(),
                reason: Some(response.response.response_desc),
                attempt_status: Some(AttemptStatus::Failure),
                connector_transaction_id: Some(response.transaction_id),
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            });
        } else {
            router_data.response = Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.transaction_id),
                redirection_data: None,
                connector_metadata: None,
                network_txn_id: response.response.authorization_code,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                mandate_reference: None,
                status_code: http_code,
            });
        }

        Ok(router_data)
    }
}

impl<F> TryFrom<ResponseRouterData<ForteCaptureResponse, RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<ForteCaptureResponse, RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let status = get_attempt_status_from_response_code(&response.response.response_code);
        let mut router_data = router_data;
        router_data.resource_common_data.status = status;

        if status == AttemptStatus::Failure {
            router_data.response = Err(ErrorResponse {
                status_code: http_code,
                code: response.response.response_code.clone(),
                message: response.response.response_desc.clone(),
                reason: Some(response.response.response_desc),
                attempt_status: Some(AttemptStatus::Failure),
                connector_transaction_id: Some(response.transaction_id),
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            });
        } else {
            router_data.response = Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.transaction_id),
                redirection_data: None,
                connector_metadata: None,
                network_txn_id: response.response.authorization_code,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                mandate_reference: None,
                status_code: http_code,
            });
        }

        Ok(router_data)
    }
}

impl<F> TryFrom<ResponseRouterData<ForteVoidResponse, RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>>
    for RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<ForteVoidResponse, RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let status = get_attempt_status_from_response_code(&response.response.response_code);
        let mut router_data = router_data;
        router_data.resource_common_data.status = status;

        if status == AttemptStatus::Failure {
            router_data.response = Err(ErrorResponse {
                status_code: http_code,
                code: response.response.response_code.clone(),
                message: response.response.response_desc.clone(),
                reason: Some(response.response.response_desc),
                attempt_status: Some(AttemptStatus::Failure),
                connector_transaction_id: Some(response.transaction_id),
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            });
        } else {
            router_data.response = Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.transaction_id),
                redirection_data: None,
                connector_metadata: None,
                network_txn_id: response.response.authorization_code,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                mandate_reference: None,
                status_code: http_code,
            });
        }

        Ok(router_data)
    }
}

impl<F> TryFrom<ResponseRouterData<ForteRefundResponse, RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<ForteRefundResponse, RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let status = get_refund_status_from_response_code(&response.response.response_code);
        let mut router_data = router_data;
        router_data.resource_common_data.status = status;

        if status == RefundStatus::Failure {
            router_data.response = Err(ErrorResponse {
                status_code: http_code,
                code: response.response.response_code.clone(),
                message: response.response.response_desc.clone(),
                reason: Some(response.response.response_desc),
                attempt_status: None,
                connector_transaction_id: Some(response.transaction_id),
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            });
        } else {
            router_data.response = Ok(RefundsResponseData {
                connector_refund_id: response.transaction_id,
                refund_status: status,
                status_code: http_code,
            });
        }

        Ok(router_data)
    }
}

impl<F> TryFrom<ResponseRouterData<ForteRSyncResponse, RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<ForteRSyncResponse, RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let status = get_refund_status_from_response_code(&response.response.response_code);
        let mut router_data = router_data;
        router_data.resource_common_data.status = status;

        if status == RefundStatus::Failure {
            router_data.response = Err(ErrorResponse {
                status_code: http_code,
                code: response.response.response_code.clone(),
                message: response.response.response_desc.clone(),
                reason: Some(response.response.response_desc),
                attempt_status: None,
                connector_transaction_id: Some(response.transaction_id),
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            });
        } else {
            router_data.response = Ok(RefundsResponseData {
                connector_refund_id: response.transaction_id,
                refund_status: status,
                status_code: http_code,
            });
        }

        Ok(router_data)
    }
}

// Helper functions
fn get_card_type<T: PaymentMethodDataTypes>(
    _card_number: &RawCardNumber<T>,
) -> Result<String, error_stack::Report<ConnectorError>> {
    // For now, return a default card type since we can't easily access the card number
    // In a real implementation, you would need to determine the card type from the number
    Ok("visa".to_string())
}