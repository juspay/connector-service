use crate::types::ResponseRouterData;
use common_enums::{AttemptStatus, RefundStatus};
use common_utils::types::{AmountConvertor, StringMinorUnit};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData, PaymentVoidData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, ResponseId},
    errors,
    payment_method_data::{Card, PaymentMethodData, PaymentMethodDataTypes},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

// Authentication Type Definition
#[derive(Debug, Clone)]
pub struct EbanxAuthType {
    pub integration_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for EbanxAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                integration_key: api_key.to_owned(),
            }),
            ConnectorAuthType::BodyKey { api_key, .. } => Ok(Self {
                integration_key: api_key.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

// Error Response Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbanxErrorResponse {
    pub code: String,
    pub message: String,
}

// Payment Sync Request Structure
#[derive(Debug, Serialize)]
pub struct EbanxSyncRequest {
    pub integration_key: Secret<String>,
    pub hash: String,
}

// Payment Sync Response Structure (reuses the same structure as Authorize)
pub type EbanxSyncResponse = EbanxPaymentResponse;

// Capture Request Structure
#[derive(Debug, Serialize)]
pub struct EbanxCaptureRequest {
    pub integration_key: Secret<String>,
    pub hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
}

// Capture Response Structure (reuses the same structure as Authorize and PSync)
pub type EbanxCaptureResponse = EbanxPaymentResponse;

// Payment Request Structure for Authorize Flow
#[derive(Debug, Serialize)]
pub struct EbanxPaymentRequest<T: PaymentMethodDataTypes> {
    pub integration_key: Secret<String>,
    pub payment: EbanxPaymentDetails<T>,
}

#[derive(Debug, Serialize)]
pub struct EbanxPaymentDetails<T: PaymentMethodDataTypes> {
    pub merchant_payment_code: String,
    pub amount_total: StringMinorUnit,
    pub currency_code: String,
    pub name: Secret<String>,
    pub email: Option<Secret<String>>,
    #[serde(flatten)]
    pub payment_method_data: EbanxPaymentMethodData<T>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum EbanxPaymentMethodData<T: PaymentMethodDataTypes> {
    Card(EbanxCardPayment<T>),
}

#[derive(Debug, Serialize)]
pub struct EbanxCardPayment<T: PaymentMethodDataTypes> {
    pub payment_type_code: String,
    #[serde(rename = "card")]
    pub card_details: EbanxCard<T>,
}

#[derive(Debug, Serialize)]
pub struct EbanxCard<T: PaymentMethodDataTypes> {
    #[serde(flatten)]
    pub card_number: domain_types::payment_method_data::RawCardNumber<T>,
    pub card_name: Secret<String>,
    pub card_due_date: Secret<String>,
    pub card_cvv: Secret<String>,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<T>,
}

// Request Transformation Implementation for macro-generated EbanxRouterData type
// The macro creates crate::connectors::ebanx::EbanxRouterData with fields: connector and router_data
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<crate::connectors::ebanx::EbanxRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for EbanxPaymentRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: crate::connectors::ebanx::EbanxRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Convert amount using the connector's amount_converter
        let amount = common_utils::types::StringMinorUnitForConnector.convert(
            router_data.request.minor_amount,
            router_data.request.currency,
        ).change_context(errors::ConnectorError::RequestEncodingFailed)?;

        // Get integration key from auth
        let auth = EbanxAuthType::try_from(&router_data.connector_auth_type)?;

        // Extract payment method data
        let payment_method_data = match &router_data.request.payment_method_data {
            PaymentMethodData::Card(card_data) => {
                let card_details = get_card_details(card_data)?;
                EbanxPaymentMethodData::Card(EbanxCardPayment {
                    payment_type_code: "creditcard".to_string(),
                    card_details,
                })
            }
            _ => {
                return Err(errors::ConnectorError::NotImplemented(
                    "Payment method not supported".to_string(),
                )
                .into())
            }
        };

        Ok(Self {
            integration_key: auth.integration_key,
            payment: EbanxPaymentDetails {
                merchant_payment_code: router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
                amount_total: amount,
                currency_code: router_data.request.currency.to_string(),
                name: router_data.request.customer_name.clone().unwrap_or_else(|| "Guest".to_string()).into(),
                email: None,  // EBANX doesn't require email for authorization
                payment_method_data,
            },
        })
    }
}

// Helper function to extract card details
fn get_card_details<T: PaymentMethodDataTypes>(
    card_data: &Card<T>,
) -> Result<EbanxCard<T>, error_stack::Report<errors::ConnectorError>> {
    // Format card expiry date as MM/YYYY
    let card_due_date = format!(
        "{}/{}",
        card_data.card_exp_month.peek(),
        card_data.card_exp_year.peek()
    );

    Ok(EbanxCard {
        card_number: card_data.card_number.to_owned(),
        card_name: card_data
            .card_holder_name
            .clone()
            .unwrap_or_else(|| Secret::new("Card Holder".to_string())),
        card_due_date: Secret::new(card_due_date),
        card_cvv: card_data.card_cvc.clone(),
        _phantom: std::marker::PhantomData,
    })
}

// Payment Response Structure
#[derive(Debug, Deserialize, Serialize)]
pub struct EbanxPaymentResponse {
    pub payment: EbanxPaymentData,
    pub status: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EbanxPaymentData {
    pub hash: String,
    pub country: Option<String>,
    pub merchant_payment_code: Option<String>,
    pub status: String,
    pub status_date: Option<String>,
    pub open_date: Option<String>,
    pub confirm_date: Option<String>,
    pub amount_br: Option<String>,
    pub amount_ext: Option<String>,
    pub currency_ext: Option<String>,
    pub payment_type_code: Option<String>,
    pub pre_approved: Option<bool>,
    pub capture_available: Option<bool>,
}

// Response Transformation Implementation
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<ResponseRouterData<EbanxPaymentResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EbanxPaymentResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Map EBANX status to AttemptStatus
        let status = get_attempt_status(&response.payment.status);

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.payment.hash.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: response.payment.merchant_payment_code.clone(),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// Status mapping function based on EBANX API documentation
fn get_attempt_status(ebanx_status: &str) -> AttemptStatus {
    match ebanx_status.to_uppercase().as_str() {
        "CO" => AttemptStatus::Charged,        // Confirmed - payment completed
        "PE" => AttemptStatus::Pending,         // Pending - awaiting confirmation
        "OP" => AttemptStatus::Authorized,      // Open - authorized but not captured
        "CA" => AttemptStatus::Voided,          // Cancelled
        "RE" => AttemptStatus::Failure,         // Rejected/Failed
        _ => AttemptStatus::Pending,            // Default to pending for unknown statuses
    }
}

// PSync Request Transformation Implementation
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<crate::connectors::ebanx::EbanxRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for EbanxSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: crate::connectors::ebanx::EbanxRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Get authentication
        let auth = EbanxAuthType::try_from(&router_data.connector_auth_type)?;

        // Extract transaction ID from connector_transaction_id using get_connector_transaction_id()
        let hash = router_data
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;

        Ok(Self {
            integration_key: auth.integration_key,
            hash,
        })
    }
}

// PSync Response Transformation Implementation
impl TryFrom<ResponseRouterData<EbanxSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EbanxSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Map EBANX status to AttemptStatus
        let status = get_attempt_status(&response.payment.status);

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.payment.hash.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: response.payment.merchant_payment_code.clone(),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// Capture Request Transformation Implementation
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<crate::connectors::ebanx::EbanxRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, T>>
    for EbanxCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: crate::connectors::ebanx::EbanxRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Get authentication
        let auth = EbanxAuthType::try_from(&router_data.connector_auth_type)?;

        // Extract transaction ID (hash) from connector_transaction_id
        let hash = router_data
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;

        // Get amount for partial capture
        // EBANX API accepts an optional amount field for partial captures
        // According to the tech spec, if amount is not provided, it captures the full authorized amount
        let amount = if router_data.request.multiple_capture_data.is_some() {
            // For partial/multiple captures, send the specific amount
            let converted_amount = common_utils::types::StringMinorUnitForConnector.convert(
                router_data.request.minor_amount_to_capture,
                router_data.request.currency,
            )
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
            Some(converted_amount.to_string())
        } else {
            // For full capture, don't send the amount field (EBANX will capture full amount)
            None
        };

        Ok(Self {
            integration_key: auth.integration_key,
            hash,
            amount,
        })
    }
}

// Capture Response Transformation Implementation
impl TryFrom<ResponseRouterData<EbanxCaptureResponse, RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EbanxCaptureResponse, RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Map EBANX status to AttemptStatus
        // Capture typically results in "CO" (Confirmed/Charged) status
        let status = get_attempt_status(&response.payment.status);

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.payment.hash.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: response.payment.merchant_payment_code.clone(),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// ===== REFUND FLOW STRUCTURES AND IMPLEMENTATIONS =====

// Refund Request Structure
#[derive(Debug, Serialize)]
pub struct EbanxRefundRequest {
    pub integration_key: Secret<String>,
    pub operation: String,  // "request" for creating refund
    pub hash: String,       // Original payment transaction ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,  // Optional for partial refund
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// Refund Response Structure
#[derive(Debug, Deserialize, Serialize)]
pub struct EbanxRefundResponse {
    pub payment: EbanxPaymentDataWithRefunds,
    pub status: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EbanxPaymentDataWithRefunds {
    pub hash: String,
    pub status: String,
    #[serde(default)]
    pub refunds: Option<Vec<EbanxRefundData>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EbanxRefundData {
    pub id: String,
    pub status: String,
    pub request_date: Option<String>,
    pub amount_ext: Option<String>,
    pub description: Option<String>,
}

// Refund Request Transformation Implementation
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<crate::connectors::ebanx::EbanxRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>>
    for EbanxRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: crate::connectors::ebanx::EbanxRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Get authentication
        let auth = EbanxAuthType::try_from(&router_data.connector_auth_type)?;

        // Convert refund amount
        let amount_str = common_utils::types::StringMinorUnitForConnector.convert(
            router_data.request.minor_refund_amount,
            router_data.request.currency,
        )
        .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            integration_key: auth.integration_key,
            operation: "request".to_string(),  // EBANX requires "request" operation
            hash: router_data.request.connector_transaction_id.clone(),
            amount: Some(amount_str.to_string()),
            description: router_data.request.reason.clone(),
        })
    }
}

// Refund Response Transformation Implementation
impl TryFrom<ResponseRouterData<EbanxRefundResponse, RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EbanxRefundResponse, RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let mut router_data = item.router_data;

        // Get the latest refund from refunds array
        let refund = response.payment.refunds
            .as_ref()
            .and_then(|refunds| refunds.last())
            .ok_or(errors::ConnectorError::ResponseHandlingFailed)?;

        // Map refund status
        let refund_status = get_refund_status(&refund.status);

        router_data.response = Ok(RefundsResponseData {
            connector_refund_id: refund.id.clone(),
            refund_status,
            status_code: item.http_code,
        });

        Ok(router_data)
    }
}

// Refund status mapping function
fn get_refund_status(status: &str) -> RefundStatus {
    match status.to_uppercase().as_str() {
        "RE" => RefundStatus::Success,      // Refunded
        "CO" => RefundStatus::Success,      // Confirmed/Completed
        "PE" => RefundStatus::Pending,      // Pending
        "CA" => RefundStatus::Failure,      // Cancelled
        _ => RefundStatus::Pending,         // Default to pending for unknown statuses
    }
}

// ===== VOID FLOW STRUCTURES AND IMPLEMENTATIONS =====

// Void Request Structure
#[derive(Debug, Serialize)]
pub struct EbanxVoidRequest {
    pub integration_key: Secret<String>,
    pub hash: String,  // Transaction ID to void/cancel
}

// Void Response Type (reuses EbanxPaymentResponse structure)
pub type EbanxVoidResponse = EbanxPaymentResponse;

// Void Request Transformation Implementation
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<crate::connectors::ebanx::EbanxRouterData<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, T>>
    for EbanxVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: crate::connectors::ebanx::EbanxRouterData<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Get authentication
        let auth = EbanxAuthType::try_from(&router_data.connector_auth_type)?;

        // Get transaction ID to void from connector_transaction_id
        let hash = router_data.request.connector_transaction_id.clone();

        Ok(Self {
            integration_key: auth.integration_key,
            hash,
        })
    }
}

// Void Response Transformation Implementation
impl TryFrom<ResponseRouterData<EbanxVoidResponse, RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EbanxVoidResponse, RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Map EBANX status to AttemptStatus
        // Status should be "CA" (Cancelled/Voided) after successful void
        let status = get_attempt_status(&response.payment.status);

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.payment.hash.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: response.payment.merchant_payment_code.clone(),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// ===== RSYNC FLOW STRUCTURES AND IMPLEMENTATIONS =====

// Type alias for RSync request (reuses EbanxSyncRequest structure)
// EBANX uses the same /ws/query endpoint for both payment sync and refund sync
pub type EbanxRefundSyncRequest = EbanxSyncRequest;

// Type alias for RSync response (reuses EbanxRefundResponse structure)
// The response contains payment data with refunds array
pub type EbanxRefundSyncResponse = EbanxRefundResponse;

// RSync Request Transformation Implementation
// Note: EBANX uses the original payment hash (connector_transaction_id) to query refund status
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<crate::connectors::ebanx::EbanxRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>>
    for EbanxRefundSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: crate::connectors::ebanx::EbanxRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Get authentication
        let auth = EbanxAuthType::try_from(&router_data.connector_auth_type)?;

        // CRITICAL: EBANX uses the original payment hash for refund sync, not the refund ID
        // The connector_transaction_id in RefundSyncData is the payment transaction ID
        let hash = router_data.request.connector_transaction_id.clone();

        Ok(Self {
            integration_key: auth.integration_key,
            hash,
        })
    }
}

// RSync Response Transformation Implementation
impl TryFrom<ResponseRouterData<EbanxRefundSyncResponse, RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<EbanxRefundSyncResponse, RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let mut router_data = item.router_data;

        // Find the specific refund by connector_refund_id
        let refund = response.payment.refunds
            .as_ref()
            .and_then(|refunds| {
                refunds.iter().find(|r|
                    Some(r.id.clone()) == Some(router_data.request.connector_refund_id.clone())
                )
            })
            .ok_or(errors::ConnectorError::ResponseHandlingFailed)?;

        // Map refund status using existing get_refund_status function
        let refund_status = get_refund_status(&refund.status);

        router_data.response = Ok(RefundsResponseData {
            connector_refund_id: refund.id.clone(),
            refund_status,
            status_code: item.http_code,
        });

        Ok(router_data)
    }
}
