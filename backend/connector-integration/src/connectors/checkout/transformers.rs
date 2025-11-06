use common_enums::enums;
use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    errors::CustomResult,
    types::MinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors::{self, ConnectorError},
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, RawCardNumber},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use error_stack::report;
# use common_utils::Secret;
use serde::{Deserialize, Serialize};

use crate::types::ResponseRouterData;

// Import the CheckoutRouterData from the parent module
// Create type aliases for response types to avoid template conflicts
pub type CheckoutAuthorizeResponse = CheckoutPaymentsResponse;
pub type CheckoutPSyncResponse = CheckoutPaymentsResponse;

// Define auth type
pub struct CheckoutAuthType {
    #[allow(dead_code)]
    pub(super) api_key: Secret<String>,
    pub(super) processing_channel_id: Secret<String>,
    pub(super) api_secret: Secret<String>,
}

// Sync request structure needed for PSync
#[derive(Debug, Serialize, Default)]
pub struct CheckoutSyncRequest {}

// Empty request structure for RSync
#[derive(Debug, Serialize, Default)]
pub struct CheckoutRefundSyncRequest {}

// Define the source types enum
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckoutSourceTypes {
    Card,
    Token,
}

// Card source structure
#[derive(Debug, Serialize)]
pub struct CardSource<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    #[serde(rename = "type")]
    pub source_type: CheckoutSourceTypes,
    pub number: RawCardNumber<T>,
    pub expiry_month: Secret<String>,
    pub expiry_year: Secret<String>,
    pub cvv: Secret<String>,
}

// Simple payment request structure
#[derive(Debug, Serialize)]
pub struct CheckoutPaymentsRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    pub source: CardSource<T>,
    pub amount: MinorUnit,
    pub currency: String,
    pub processing_channel_id: Secret<String>,
    pub capture: bool,
    pub reference: String,
}

// Payment response structure
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct CheckoutPaymentsResponse {
    pub id: String,
    pub amount: Option<MinorUnit>,
    pub currency: Option<String>,
    pub status: CheckoutPaymentStatus,
    pub reference: Option<String>,
    pub response_code: Option<String>,
    pub response_summary: Option<String>,
    pub action_id: Option<String>,
    pub balances: Option<Balances>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct Balances {
    pub available_to_capture: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckoutMeta {
    pub psync_flow: CheckoutPaymentIntent,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum CheckoutPaymentIntent {
    Capture,
    Authorize,
}

fn to_connector_meta(
    connector_meta: Option<serde_json::Value>,
) -> CustomResult<CheckoutMeta, ConnectorError> {
    connector_meta
        .map(|meta| {
            serde_json::from_value::<CheckoutMeta>(meta)
                .map_err(|_| report!(errors::ConnectorError::ResponseDeserializationFailed))
        })
        .unwrap_or(Ok(CheckoutMeta {
            psync_flow: CheckoutPaymentIntent::Capture,
        }))
}

fn get_connector_meta(
    capture_method: enums::CaptureMethod,
) -> CustomResult<serde_json::Value, ConnectorError> {
    match capture_method {
        enums::CaptureMethod::Automatic | enums::CaptureMethod::SequentialAutomatic => {
            Ok(serde_json::json!(CheckoutMeta {
                psync_flow: CheckoutPaymentIntent::Capture,
            }))
        }
        enums::CaptureMethod::Manual | enums::CaptureMethod::ManualMultiple => {
            Ok(serde_json::json!(CheckoutMeta {
                psync_flow: CheckoutPaymentIntent::Authorize,
            }))
        }
        enums::CaptureMethod::Scheduled => {
            Err(errors::ConnectorError::CaptureMethodNotSupported.into())
        }
    }
}

#[derive(Debug, Serialize)]
pub enum CaptureType {
    Final,
    NonFinal,
}

#[derive(Debug, Serialize)]
pub struct PaymentCaptureRequest {
    pub amount: Option<MinorUnit>,
    pub capture_type: Option<CaptureType>,
    pub processing_channel_id: Secret<String>,
    pub reference: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaymentCaptureResponse {
    pub action_id: String,
    pub reference: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RefundRequest {
    pub amount: Option<MinorUnit>,
    pub reference: String,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct RefundResponse {
    action_id: String,
    reference: String,
}

// Wrapper struct to match HS implementation
#[derive(Deserialize)]
pub struct CheckoutRefundResponse {
    pub(super) status: u16,
    pub(super) response: RefundResponse,
}

impl From<&CheckoutRefundResponse> for enums::RefundStatus {
    fn from(item: &CheckoutRefundResponse) -> Self {
        if item.status == 202 {
            Self::Success
        } else {
            Self::Failure
        }
    }
}

#[derive(Deserialize, Debug, Serialize)]
pub struct ActionResponse {
    #[serde(rename = "id")]
    pub action_id: String,
    pub amount: MinorUnit,
    pub approved: Option<bool>,
    pub reference: Option<String>,
}

impl From<&ActionResponse> for enums::RefundStatus {
    fn from(item: &ActionResponse) -> Self {
        match item.approved {
            Some(true) => Self::Success,
            Some(false) => Self::Failure,
            None => Self::Pending,
        }
    }
}

// Payment void request structure
#[derive(Clone, Default, Debug, Eq, PartialEq, Serialize)]
pub struct PaymentVoidRequest {
    pub reference: String,
}

// Payment void response structure
#[derive(Clone, Default, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct PaymentVoidResponse {
    #[serde(skip)]
    pub(super) status: u16,
    pub action_id: String,
    pub reference: String,
}

impl From<&PaymentVoidResponse> for enums::AttemptStatus {
    fn from(item: &PaymentVoidResponse) -> Self {
        if item.status == 202 {
            Self::Voided
        } else {
            Self::VoidFailed
        }
    }
}

// Payment status enum
#[derive(Default, Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum CheckoutPaymentStatus {
    Authorized,
    #[default]
    Pending,
    #[serde(rename = "Card Verified")]
    CardVerified,
    Declined,
    Captured,
    #[serde(rename = "Retry Scheduled")]
    RetryScheduled,
    Voided,
    #[serde(rename = "Partially Captured")]
    PartiallyCaptured,
    #[serde(rename = "Partially Refunded")]
    PartiallyRefunded,
    Refunded,
    Canceled,
    Expired,
}

// Helper functions to get attempt status based on different contexts
fn get_attempt_status_cap(
    item: (CheckoutPaymentStatus, Option<enums::CaptureMethod>),
) -> enums::AttemptStatus {
    let (status, capture_method) = item;
    match status {
        CheckoutPaymentStatus::Authorized => {
            if capture_method == Some(enums::CaptureMethod::Automatic) || capture_method.is_none() {
                enums::AttemptStatus::Pending
            } else {
                enums::AttemptStatus::Authorized
            }
        }
        CheckoutPaymentStatus::Captured
        | CheckoutPaymentStatus::PartiallyRefunded
        | CheckoutPaymentStatus::Refunded => enums::AttemptStatus::Charged,
        CheckoutPaymentStatus::PartiallyCaptured => enums::AttemptStatus::PartialCharged,
        CheckoutPaymentStatus::Declined
        | CheckoutPaymentStatus::Expired
        | CheckoutPaymentStatus::Canceled => enums::AttemptStatus::Failure,
        CheckoutPaymentStatus::Pending => enums::AttemptStatus::AuthenticationPending,
        CheckoutPaymentStatus::CardVerified | CheckoutPaymentStatus::RetryScheduled => {
            enums::AttemptStatus::Pending
        }
        CheckoutPaymentStatus::Voided => enums::AttemptStatus::Voided,
    }
}

fn get_attempt_status_intent(
    item: (CheckoutPaymentStatus, CheckoutPaymentIntent),
) -> enums::AttemptStatus {
    let (status, psync_flow) = item;

    match status {
        CheckoutPaymentStatus::Authorized => {
            if psync_flow == CheckoutPaymentIntent::Capture {
                enums::AttemptStatus::Pending
            } else {
                enums::AttemptStatus::Authorized
            }
        }
        CheckoutPaymentStatus::Captured
        | CheckoutPaymentStatus::PartiallyRefunded
        | CheckoutPaymentStatus::Refunded => enums::AttemptStatus::Charged,
        CheckoutPaymentStatus::PartiallyCaptured => enums::AttemptStatus::PartialCharged,
        CheckoutPaymentStatus::Declined
        | CheckoutPaymentStatus::Expired
        | CheckoutPaymentStatus::Canceled => enums::AttemptStatus::Failure,
        CheckoutPaymentStatus::Pending => enums::AttemptStatus::AuthenticationPending,
        CheckoutPaymentStatus::CardVerified | CheckoutPaymentStatus::RetryScheduled => {
            enums::AttemptStatus::Pending
        }
        CheckoutPaymentStatus::Voided => enums::AttemptStatus::Voided,
    }
}

fn get_attempt_status_bal(item: (CheckoutPaymentStatus, Option<Balances>)) -> enums::AttemptStatus {
    let (status, balances) = item;

    match status {
        CheckoutPaymentStatus::Authorized => {
            if let Some(Balances {
                available_to_capture: 0,
            }) = balances
            {
                enums::AttemptStatus::Charged
            } else {
                enums::AttemptStatus::Authorized
            }
        }
        CheckoutPaymentStatus::Captured
        | CheckoutPaymentStatus::PartiallyRefunded
        | CheckoutPaymentStatus::Refunded => enums::AttemptStatus::Charged,
        CheckoutPaymentStatus::PartiallyCaptured => enums::AttemptStatus::PartialCharged,
        CheckoutPaymentStatus::Declined
        | CheckoutPaymentStatus::Expired
        | CheckoutPaymentStatus::Canceled => enums::AttemptStatus::Failure,
        CheckoutPaymentStatus::Pending => enums::AttemptStatus::AuthenticationPending,
        CheckoutPaymentStatus::CardVerified | CheckoutPaymentStatus::RetryScheduled => {
            enums::AttemptStatus::Pending
        }
        CheckoutPaymentStatus::Voided => enums::AttemptStatus::Voided,
    }
}

// Map payment status to attempt status for simple cases
impl From<CheckoutPaymentStatus> for enums::AttemptStatus {
    fn from(status: CheckoutPaymentStatus) -> Self {
        get_attempt_status_bal((status, None))
    }
}

// Error response structure
#[derive(Default, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckoutErrorResponse {
    pub request_id: Option<String>,
    pub error_type: Option<String>,
    pub error_codes: Option<Vec<String>>,
}

// Auth type conversion
impl TryFrom<&ConnectorAuthType> for CheckoutAuthType {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        if let ConnectorAuthType::SignatureKey {
            api_key,
            api_secret,
            key1,
        } = auth_type
        {
            Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: api_secret.to_owned(),
                processing_channel_id: key1.to_owned(),
            })
        } else {
            Err(report!(ConnectorError::FailedToObtainAuthType))
        }
    }
}

// Payment request conversion
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        super::CheckoutRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for CheckoutPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: super::CheckoutRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Get card details from payment method data
        let card_details = match router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(card) => Ok(card),
            _ => Err(report!(ConnectorError::NotImplemented(
                "Payment method not supported by Checkout".to_string(),
            ))),
        }?;

        // Create card source
        let source = CardSource {
            source_type: CheckoutSourceTypes::Card,
            number: card_details.card_number.clone(),
            expiry_month: card_details.card_exp_month.clone(),
            expiry_year: card_details.card_exp_year.clone(),
            cvv: card_details.card_cvc,
        };

        // Determine capture mode
        let capture = matches!(
            router_data.request.capture_method,
            Some(enums::CaptureMethod::Automatic) | None
        );

        // Get processing channel ID
        let connector_auth = &router_data.connector_auth_type;
        let auth_type: CheckoutAuthType = connector_auth.try_into()?;
        let processing_channel_id = auth_type.processing_channel_id;

        Ok(Self {
            source,
            amount: router_data.request.minor_amount,
            currency: router_data.request.currency.to_string(),
            processing_channel_id,
            capture,
            reference: router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
        })
    }
}

// Payment response conversion
impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        ResponseRouterData<
            CheckoutPaymentsResponse,
            RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    > for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            CheckoutPaymentsResponse,
            RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        // Get attempt status from payment status based on capture method
        let status = get_attempt_status_cap((response.status, router_data.request.capture_method));

        let mut router_data = router_data;
        router_data.resource_common_data.status = status;

        // Check if the response indicates an error
        if status == enums::AttemptStatus::Failure {
            router_data.response = Err(ErrorResponse {
                status_code: http_code,
                code: response
                    .response_code
                    .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                message: response
                    .response_summary
                    .clone()
                    .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                reason: response.response_summary,
                attempt_status: None,
                connector_transaction_id: Some(response.id.clone()),
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            });
        } else {
            let connector_meta =
                get_connector_meta(router_data.request.capture_method.unwrap_or_default())?;

            // Handle successful response
            router_data.response = Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: Some(connector_meta),
                network_txn_id: None,
                connector_response_reference_id: Some(response.reference.unwrap_or(response.id)),
                incremental_authorization_allowed: None,
                status_code: http_code,
            });
        }

        Ok(router_data)
    }
}

// Implementation for PaymentCaptureRequest
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        super::CheckoutRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for PaymentCaptureRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: super::CheckoutRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let connector_auth = &router_data.connector_auth_type;
        let auth_type: CheckoutAuthType = connector_auth.try_into()?;
        let processing_channel_id = auth_type.processing_channel_id;

        // Determine if this is a multiple capture by checking if multiple_capture_data exists
        let capture_type = if router_data.request.multiple_capture_data.is_some() {
            CaptureType::NonFinal
        } else {
            CaptureType::Final
        };

        // Get optional reference for multiple captures
        let reference = router_data
            .request
            .multiple_capture_data
            .as_ref()
            .map(|mcd| mcd.capture_reference.clone());

        Ok(Self {
            amount: Some(router_data.request.minor_amount_to_capture),
            capture_type: Some(capture_type),
            processing_channel_id,
            reference,
        })
    }
}

// Implementation for RefundRequest
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        super::CheckoutRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for RefundRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: super::CheckoutRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: Some(MinorUnit::new(item.router_data.request.refund_amount)),
            reference: item.router_data.request.refund_id.clone(),
        })
    }
}

// Implementation for PaymentVoidRequest with the router data generated by the macro
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        super::CheckoutRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for PaymentVoidRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: super::CheckoutRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let connector_transaction_id = item.router_data.request.connector_transaction_id.clone();

        Ok(Self {
            reference: connector_transaction_id,
        })
    }
}

// Implementation for PaymentVoidRequest with direct RouterDataV2
impl TryFrom<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>
    for PaymentVoidRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let connector_transaction_id = item.request.connector_transaction_id.clone();

        Ok(Self {
            reference: connector_transaction_id,
        })
    }
}

// Also implement for reference version
impl TryFrom<&RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>
    for PaymentVoidRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let connector_transaction_id = item.request.connector_transaction_id.clone();

        Ok(Self {
            reference: connector_transaction_id,
        })
    }
}

// Payment capture response conversion
impl<F>
    TryFrom<
        ResponseRouterData<
            PaymentCaptureResponse,
            RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            PaymentCaptureResponse,
            RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        let mut router_data = router_data;

        // Set status based on HTTP response code
        let (status, amount_captured) = if http_code == 202 {
            (
                enums::AttemptStatus::Charged,
                Some(router_data.request.amount_to_capture),
            )
        } else {
            (enums::AttemptStatus::Pending, None)
        };

        router_data.resource_common_data.status = status;
        router_data.resource_common_data.amount_captured = amount_captured;

        // Determine the resource_id to return
        // If multiple capture, return action_id, otherwise return the original transaction ID
        let resource_id = if router_data.request.multiple_capture_data.is_some() {
            response.action_id.clone()
        } else {
            // Extract the String from the ResponseId
            match &router_data.request.connector_transaction_id {
                ResponseId::ConnectorTransactionId(id) => id.clone(),
                _ => response.action_id.clone(), // Fallback
            }
        };

        let connector_meta = serde_json::json!(CheckoutMeta {
            psync_flow: CheckoutPaymentIntent::Capture,
        });

        router_data.response = Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(resource_id),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: Some(connector_meta),
            network_txn_id: None,
            connector_response_reference_id: response.reference,
            incremental_authorization_allowed: None,
            status_code: http_code,
        });

        Ok(router_data)
    }
}

// Payment void response conversion
impl<F>
    TryFrom<
        ResponseRouterData<
            PaymentVoidResponse,
            RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            PaymentVoidResponse,
            RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            mut response,
            router_data,
            http_code,
        } = item;

        let mut router_data = router_data;

        // Set the HTTP status code in the response object
        response.status = http_code;

        // Get the attempt status using the From implementation
        let status = enums::AttemptStatus::from(&response);

        router_data.resource_common_data.status = status;

        let connector_meta = serde_json::json!(CheckoutMeta {
            psync_flow: CheckoutPaymentIntent::Authorize,
        });

        router_data.response = Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.action_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: Some(connector_meta),
            network_txn_id: None,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: http_code,
        });

        Ok(router_data)
    }
}

// Payment sync response conversion
impl<F>
    TryFrom<
        ResponseRouterData<
            CheckoutPaymentsResponse,
            RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            CheckoutPaymentsResponse,
            RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        // For PSync, extract connector_meta if available or create default based on balances
        let checkout_meta = to_connector_meta(router_data.request.connector_meta.clone())?;

        // Determine status based on both the payment intent from metadata and balances
        // This ensures we have the correct status even if metadata is missing
        let status = if let Some(balances) = &response.balances {
            get_attempt_status_bal((response.status.clone(), Some(balances.clone())))
        } else {
            get_attempt_status_intent((response.status.clone(), checkout_meta.psync_flow.clone()))
        };

        let mut router_data = router_data;
        router_data.resource_common_data.status = status;

        if status == enums::AttemptStatus::Failure {
            router_data.response = Err(ErrorResponse {
                status_code: http_code,
                code: response
                    .response_code
                    .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                message: response
                    .response_summary
                    .clone()
                    .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                reason: response.response_summary,
                attempt_status: None,
                connector_transaction_id: Some(response.id.clone()),
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            });
        } else {
            // Always include the connector metadata in the response
            // This preserves the payment intent information for subsequent operations
            let connector_meta = serde_json::json!(CheckoutMeta {
                psync_flow: checkout_meta.psync_flow.clone(),
            });

            router_data.response = Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: Some(connector_meta),
                network_txn_id: None,
                connector_response_reference_id: Some(response.reference.unwrap_or(response.id)),
                incremental_authorization_allowed: None,
                status_code: http_code,
            });
        }

        Ok(router_data)
    }
}

// Refund response conversion
impl<F>
    TryFrom<
        ResponseRouterData<
            RefundResponse,
            RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            RefundResponse,
            RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        // Create the wrapper structure with status code
        let checkout_refund_response = CheckoutRefundResponse {
            status: http_code,
            response,
        };

        // Get the refund status using the From implementation
        let refund_status = enums::RefundStatus::from(&checkout_refund_response);

        let mut router_data = router_data;
        router_data.response = Ok(RefundsResponseData {
            connector_refund_id: checkout_refund_response.response.action_id,
            refund_status,
            status_code: http_code,
        });

        Ok(router_data)
    }
}

// Refund sync response conversion
impl<F>
    TryFrom<
        ResponseRouterData<
            ActionResponse,
            RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            ActionResponse,
            RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        // Get the refund status using the From implementation
        let refund_status = enums::RefundStatus::from(&response);

        let mut router_data = router_data;
        router_data.response = Ok(RefundsResponseData {
            connector_refund_id: response.action_id,
            refund_status,
            status_code: http_code,
        });

        Ok(router_data)
    }
}

// Implementation for CheckoutSyncRequest with CheckoutRouterData - needed for PSync flow
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        super::CheckoutRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for CheckoutSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        _item: super::CheckoutRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {})
    }
}

// Implementation for CheckoutRefundSyncRequest with CheckoutRouterData
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        super::CheckoutRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for CheckoutRefundSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        _item: super::CheckoutRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {})
    }
}

// Also implement for borrowed ActionResponse
impl<F>
    TryFrom<
        ResponseRouterData<
            &ActionResponse,
            RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            &ActionResponse,
            RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;

        // Get the refund status using the From implementation
        let refund_status = enums::RefundStatus::from(response);

        let mut router_data = router_data;
        router_data.response = Ok(RefundsResponseData {
            connector_refund_id: response.action_id.clone(),
            refund_status,
            status_code: http_code,
        });

        Ok(router_data)
    }
}
