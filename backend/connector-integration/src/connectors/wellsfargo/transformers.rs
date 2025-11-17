// Wellsfargo (CyberSource) transformers for V2 API
// This implements the request/response transformation for Wellsfargo payments

use domain_types::payment_method_data::RawCardNumber;
use common_enums::{AttemptStatus, RefundStatus};
use domain_types::{
    connector_flow::{Authorize, Capture, Refund, RSync, Void},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentVoidData, RefundFlowData, RefundsData, RefundSyncData, RefundsResponseData, PaymentsResponseData, ResponseId},
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    router_data::ErrorResponse,
    errors,
};
use error_stack::{Report};
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};
use crate::types::ResponseRouterData;

// ============================================================================
// REQUEST STRUCTURES
// ============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WellsfargoPaymentsRequest<T: PaymentMethodDataTypes> {
    processing_information: ProcessingInformation,
    payment_information: PaymentInformation<T>,
    order_information: OrderInformationWithBill,
    client_reference_information: ClientReferenceInformation,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessingInformation {
    commerce_indicator: String,
    capture: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum PaymentInformation<T: PaymentMethodDataTypes> {
    Cards(Box<CardPaymentInformation<T>>),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardPaymentInformation<T: PaymentMethodDataTypes> {
    card: Card<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Card<T: PaymentMethodDataTypes> {
    number: RawCardNumber<T>,
    expiration_month: Secret<String>,
    expiration_year: Secret<String>,
    security_code: Option<Secret<String>>,
    #[serde(rename = "type")]
    card_type: Option<String>,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderInformationWithBill {
    amount_details: Amount,
    bill_to: Option<BillTo>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Amount {
    total_amount: String,
    currency: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BillTo {
    first_name: Option<Secret<String>>,
    last_name: Option<Secret<String>>,
    address1: Option<Secret<String>>,
    locality: Option<String>,
    administrative_area: Option<Secret<String>>,
    postal_code: Option<Secret<String>>,
    country: Option<common_enums::CountryAlpha2>,
    email: Secret<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientReferenceInformation {
    code: Option<String>,
}

// ============================================================================
// CAPTURE REQUEST STRUCTURES
// ============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WellsfargoCaptureRequest {
    order_information: OrderInformationAmount,
    client_reference_information: ClientReferenceInformation,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderInformationAmount {
    amount_details: Amount,
}

// ============================================================================
// VOID REQUEST STRUCTURES
// ============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WellsfargoVoidRequest {
    client_reference_information: ClientReferenceInformation,
}

// ============================================================================
// REFUND REQUEST STRUCTURES
// ============================================================================


// HYPERSWITCH STRUCTURE : 

// pub enum WellsfargoRefundStatus {
//     Succeeded,
//     Transmitted,
//     Failed,
//     Pending,
//     Voided,
//     Cancelled,
// }

// impl From<WellsfargoRefundStatus> for enums::RefundStatus {
//     fn from(item: WellsfargoRefundStatus) -> Self {
//         match item {
//             WellsfargoRefundStatus::Succeeded | WellsfargoRefundStatus::Transmitted => {
//                 Self::Success
//             }
//             WellsfargoRefundStatus::Cancelled
//             | WellsfargoRefundStatus::Failed
//             | WellsfargoRefundStatus::Voided => Self::Failure,
//             WellsfargoRefundStatus::Pending => Self::Pending,
//         }
//     }
// }

// pub struct WellsfargoRefundRequest {
//     order_information: OrderInformation,
//     client_reference_information: ClientReferenceInformation,
// }

// pub struct WellsfargoRefundResponse {
//     id: String,
//     status: WellsfargoRefundStatus,
//     error_information: Option<WellsfargoErrorInformation>,
// }



#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WellsfargoRefundRequest {
    order_information: OrderInformationAmount,
    client_reference_information: ClientReferenceInformation,
}

// ============================================================================
// RESPONSE STRUCTURES
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WellsfargoPaymentsResponse {
    pub id: String,
    pub status: Option<WellsfargoPaymentStatus>,
    pub status_information: Option<StatusInformation>, // For PSync/GET responses
    pub client_reference_information: Option<ClientReferenceInformation>,
    pub processor_information: Option<ClientProcessorInformation>,
    pub error_information: Option<WellsfargoErrorInformation>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusInformation {
    pub reason: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WellsfargoPaymentStatus {
    Authorized,
    AuthorizedPendingReview,
    Declined,
    InvalidRequest,
    PendingAuthentication,
    PendingReview,
    Reversed,
    PartialAuthorized,
    Transmitted,
    Pending,
    AuthorizedRiskDeclined,
    Voided,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientProcessorInformation {
    pub network_transaction_id: Option<String>,
    pub avs: Option<Avs>,
    pub response_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Avs {
    pub code: Option<String>,
    pub code_raw: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WellsfargoErrorInformation {
    pub reason: Option<String>,
    pub message: Option<String>,
    pub details: Option<Vec<ErrorInfo>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ErrorInfo {
    pub field: Option<String>,
    pub reason: Option<String>,
}

// ============================================================================
// ERROR RESPONSE STRUCTURES
// ============================================================================

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum WellsfargoErrorResponse {
    StandardError(StandardErrorResponse),
    NotAvailableError(NotAvailableErrorResponse),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StandardErrorResponse {
    pub error_information: Option<WellsfargoErrorInformation>,
    pub status: Option<String>,
    pub message: Option<String>,
    pub reason: Option<String>,
    pub details: Option<Vec<ErrorInfo>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NotAvailableErrorResponse {
    pub errors: Vec<NotAvailableErrorObject>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NotAvailableErrorObject {
    #[serde(rename = "type")]
    pub error_type: Option<String>,
    pub message: Option<String>,
}

// ============================================================================
// AUTH TYPE
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WellsfargoAuthType {
    pub api_key: Secret<String>,
    pub merchant_account: Secret<String>,
    pub api_secret: Secret<String>,
}

impl TryFrom<&domain_types::router_data::ConnectorAuthType> for WellsfargoAuthType {
    type Error = Report<errors::ConnectorError>;

    fn try_from(auth_type: &domain_types::router_data::ConnectorAuthType) -> Result<Self, Self::Error> {
        use domain_types::router_data::ConnectorAuthType;
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self {
                api_key: api_key.clone(),
                merchant_account: key1.clone(),
                api_secret: api_secret.clone(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Convert minor units (cents) to major units (dollars) as decimal string
/// Example: 1000 cents -> "10.00"
fn minor_to_major_unit(minor_amount: i64) -> String {
    let major = minor_amount / 100;
    let minor_part = minor_amount % 100;
    format!("{}.{:02}", major, minor_part)
}

// ============================================================================
// REQUEST CONVERSION - TryFrom RouterDataV2 to WellsfargoPaymentsRequest
// ============================================================================

// Specific implementation for Authorize flow
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<super::WellsfargoRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for WellsfargoPaymentsRequest<T>
{
    type Error = Report<errors::ConnectorError>;

    fn try_from(
        item: super::WellsfargoRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>
    ) -> Result<Self, Self::Error> {
        use domain_types::payment_method_data::PaymentMethodData;

        // Access the router_data directly
        let router_data = &item.router_data;
        let request = &router_data.request;
        let common_data = &router_data.resource_common_data;

        // Get payment method data - for now we only support Cards
        let payment_information = match &request.payment_method_data {
            PaymentMethodData::Card(card_data) => {
                // Get card type as string
                let card_type = card_data.card_network.as_ref().map(|network| {
                    match network {
                        common_enums::CardNetwork::Visa => "001",
                        common_enums::CardNetwork::Mastercard => "002",
                        common_enums::CardNetwork::AmericanExpress => "003",
                        common_enums::CardNetwork::Discover => "004",
                        common_enums::CardNetwork::DinersClub => "005",
                        common_enums::CardNetwork::JCB => "007",
                        _ => "001", // Default to Visa
                    }
                }).map(String::from);

                let card = Card {
                    number: card_data.card_number.clone(),
                    expiration_month: card_data.card_exp_month.clone(),
                    expiration_year: card_data.card_exp_year.clone(),
                    security_code: Some(card_data.card_cvc.clone()),
                    card_type,
                    _phantom: std::marker::PhantomData,
                };
                PaymentInformation::Cards(Box::new(CardPaymentInformation { card }))
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                "Payment method not supported".to_string(),
            ))?,
        };

        // Get amount and currency - amount is in minor units (cents)
        let amount = request.minor_amount;
        let currency = request.currency;

        let amount_details = Amount {
            total_amount: minor_to_major_unit(amount.get_amount_as_i64()),
            currency: currency.to_string(),
        };

        // Build billing information if available
        let billing = common_data.address.get_payment_billing();
        let email = request.email.clone()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "email",
            })?;

        // Convert Email type to Secret<String>
        // Email wraps Secret<String, EmailStrategy>, we need to extract and re-wrap
        use hyperswitch_masking::ExposeInterface;
        let email_inner = email.expose();
        let email_secret = Secret::new(email_inner.expose());

        let bill_to = billing.and_then(|addr| {
            addr.address.as_ref().map(|details| BillTo {
                first_name: details.first_name.clone(),
                last_name: details.last_name.clone(),
                address1: details.line1.clone(),
                locality: details.city.clone(),
                administrative_area: details.state.clone(),
                postal_code: details.zip.clone(),
                country: details.country,
                email: email_secret.clone(),
            })
        }).or_else(|| Some(BillTo {
            first_name: None,
            last_name: None,
            address1: None,
            locality: None,
            administrative_area: None,
            postal_code: None,
            country: None,
            email: email_secret.clone(),
        }));

        let order_information = OrderInformationWithBill {
            amount_details,
            bill_to,
        };

        // Processing information
        let processing_information = ProcessingInformation {
            commerce_indicator: "internet".to_string(),
            capture: request.capture_method.map(|method| {
                matches!(method, common_enums::CaptureMethod::Automatic)
            }),
        };

        // Client reference - use payment_id from common data
        let client_reference_information = ClientReferenceInformation {
            code: Some(common_data.payment_id.clone()),
        };

        Ok(Self {
            processing_information,
            payment_information,
            order_information,
            client_reference_information,
            _phantom: std::marker::PhantomData,
        })
    }
}

// ============================================================================
// CAPTURE REQUEST CONVERSION - TryFrom RouterDataV2 to WellsfargoCaptureRequest
// ============================================================================

impl
    TryFrom<&RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>
    for WellsfargoCaptureRequest
{
    type Error = Report<errors::ConnectorError>;

    fn try_from(
        router_data: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let request = &router_data.request;
        let common_data = &router_data.resource_common_data;

        // Amount information
        let amount = request.minor_amount_to_capture;
        let currency = request.currency;

        let amount_details = Amount {
            total_amount: minor_to_major_unit(amount.get_amount_as_i64()),
            currency: currency.to_string(),
        };

        let order_information = OrderInformationAmount {
            amount_details,
        };

        // Client reference - use payment_id from common data
        let client_reference_information = ClientReferenceInformation {
            code: Some(common_data.payment_id.clone()),
        };

        Ok(Self {
            order_information,
            client_reference_information,
        })
    }
}

// ============================================================================
// VOID REQUEST CONVERSION - TryFrom RouterDataV2 to WellsfargoVoidRequest
// ============================================================================

impl
    TryFrom<&RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>
    for WellsfargoVoidRequest
{
    type Error = Report<errors::ConnectorError>;

    fn try_from(
        router_data: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let common_data = &router_data.resource_common_data;

        // Client reference - use payment_id from common data
        let client_reference_information = ClientReferenceInformation {
            code: Some(common_data.payment_id.clone()),
        };

        Ok(Self {
            client_reference_information,
        })
    }
}

// ============================================================================
// REFUND REQUEST CONVERSION - TryFrom RouterDataV2 to WellsfargoRefundRequest
// ============================================================================

impl
    TryFrom<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>
    for WellsfargoRefundRequest
{
    type Error = Report<errors::ConnectorError>;

    fn try_from(
        router_data: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let request = &router_data.request;
        // let common_data = &router_data.resource_common_data;

        // Amount information
        let amount = request.refund_amount;
        let currency = request.currency;

        let amount_details = Amount {
            total_amount: minor_to_major_unit(amount),
            currency: currency.to_string(),
        };

        let order_information = OrderInformationAmount {
            amount_details,
        };

        // Client reference - use refund_id from request
        let client_reference_information = ClientReferenceInformation {
            code: Some(request.refund_id.clone()),
        };

        Ok(Self {
            order_information,
            client_reference_information,
        })
    }
}

// ============================================================================
// RESPONSE CONVERSION - TryFrom ResponseRouterData to RouterDataV2
// ============================================================================

impl<T: PaymentMethodDataTypes>
    TryFrom<ResponseRouterData<WellsfargoPaymentsResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<WellsfargoPaymentsResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let status = get_payment_status(&response.status, &response.error_information);

        // Check if the payment was successful
        let response_data = if is_payment_successful(&response.status, &response.status_information) {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: response.processor_information
                    .as_ref()
                    .and_then(|info| info.network_transaction_id.clone()),
                connector_response_reference_id: response.client_reference_information
                    .as_ref()
                    .and_then(|info| info.code.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            })
        } else {
            // Build error response
            let error_message = response.error_information
                .as_ref()
                .and_then(|info| info.message.clone())
                .or_else(|| response.error_information
                    .as_ref()
                    .and_then(|info| info.reason.clone()))
                .unwrap_or_else(|| "Payment failed".to_string());

            let error_code = response.error_information
                .as_ref()
                .and_then(|info| info.reason.clone());

            Err(ErrorResponse {
                code: error_code.unwrap_or_else(|| "DECLINED".to_string()),
                message: error_message.clone(),
                reason: Some(error_message),
                status_code: item.http_code,
                attempt_status: Some(status),
                connector_transaction_id: Some(response.id.clone()),
                network_decline_code: response.processor_information
                    .as_ref()
                    .and_then(|info| info.response_code.clone()),
                network_advice_code: None,
                network_error_message: None,
            })
        };

        Ok(Self {
            response: response_data,
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// PSync Response Conversion - Handles GET response format which is different from Authorize
impl
    TryFrom<ResponseRouterData<WellsfargoPaymentsResponse, RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, domain_types::connector_types::PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, domain_types::connector_types::PaymentsSyncData, PaymentsResponseData>
{
    type Error = Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<WellsfargoPaymentsResponse, RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, domain_types::connector_types::PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;

        // For PSync, check both status (Authorize response) and status_information (GET response)
        let is_success = is_payment_successful(&response.status, &response.status_information);

        let status = if is_success && response.status.is_none() {
            // PSync GET response with statusInformation: Success → treat as Charged
            AttemptStatus::Charged
        } else {
            get_payment_status(&response.status, &response.error_information)
        };

        // Check if the payment was successful
        let response_data = if is_success {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: response.processor_information
                    .as_ref()
                    .and_then(|info| info.network_transaction_id.clone()),
                connector_response_reference_id: response.client_reference_information
                    .as_ref()
                    .and_then(|info| info.code.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            })
        } else {
            // Build error response
            let error_message = response.error_information
                .as_ref()
                .and_then(|info| info.message.clone())
                .or_else(|| response.error_information
                    .as_ref()
                    .and_then(|info| info.reason.clone()))
                .unwrap_or_else(|| "Payment failed".to_string());

            let error_code = response.error_information
                .as_ref()
                .and_then(|info| info.reason.clone());

            Err(ErrorResponse {
                code: error_code.unwrap_or_else(|| "DECLINED".to_string()),
                message: error_message.clone(),
                reason: Some(error_message),
                status_code: item.http_code,
                attempt_status: Some(status),
                connector_transaction_id: Some(response.id.clone()),
                network_decline_code: response.processor_information
                    .as_ref()
                    .and_then(|info| info.response_code.clone()),
                network_advice_code: None,
                network_error_message: None,
            })
        };

        Ok(Self {
            response: response_data,
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// Capture Response Conversion - Reuses same response structure as Authorize
impl
    TryFrom<ResponseRouterData<WellsfargoPaymentsResponse, RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<WellsfargoPaymentsResponse, RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let status = get_payment_status(&response.status, &response.error_information);

        // Check if the capture was successful
        let response_data = if is_payment_successful(&response.status, &response.status_information) {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: response.processor_information
                    .as_ref()
                    .and_then(|info| info.network_transaction_id.clone()),
                connector_response_reference_id: response.client_reference_information
                    .as_ref()
                    .and_then(|info| info.code.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            })
        } else {
            // Build error response
            let error_message = response.error_information
                .as_ref()
                .and_then(|info| info.message.clone())
                .or_else(|| response.error_information
                    .as_ref()
                    .and_then(|info| info.reason.clone()))
                .unwrap_or_else(|| "Capture failed".to_string());

            let error_code = response.error_information
                .as_ref()
                .and_then(|info| info.reason.clone());

            Err(ErrorResponse {
                code: error_code.unwrap_or_else(|| "DECLINED".to_string()),
                message: error_message.clone(),
                reason: Some(error_message),
                status_code: item.http_code,
                attempt_status: Some(status),
                connector_transaction_id: Some(response.id.clone()),
                network_decline_code: response.processor_information
                    .as_ref()
                    .and_then(|info| info.response_code.clone()),
                network_advice_code: None,
                network_error_message: None,
            })
        };

        Ok(Self {
            response: response_data,
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// Void Response Conversion - Reuses same response structure as Authorize/Capture
impl
    TryFrom<ResponseRouterData<WellsfargoPaymentsResponse, RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<WellsfargoPaymentsResponse, RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let status = get_payment_status(&response.status, &response.error_information);

        // Check if the void was successful
        let response_data = if is_payment_successful(&response.status, &response.status_information) {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: response.processor_information
                    .as_ref()
                    .and_then(|info| info.network_transaction_id.clone()),
                connector_response_reference_id: response.client_reference_information
                    .as_ref()
                    .and_then(|info| info.code.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            })
        } else {
            // Build error response
            let error_message = response.error_information
                .as_ref()
                .and_then(|info| info.message.clone())
                .or_else(|| response.error_information
                    .as_ref()
                    .and_then(|info| info.reason.clone()))
                .unwrap_or_else(|| "Void failed".to_string());

            let error_code = response.error_information
                .as_ref()
                .and_then(|info| info.reason.clone());

            Err(ErrorResponse {
                code: error_code.unwrap_or_else(|| "DECLINED".to_string()),
                message: error_message.clone(),
                reason: Some(error_message),
                status_code: item.http_code,
                attempt_status: Some(status),
                connector_transaction_id: Some(response.id.clone()),
                network_decline_code: response.processor_information
                    .as_ref()
                    .and_then(|info| info.response_code.clone()),
                network_advice_code: None,
                network_error_message: None,
            })
        };

        Ok(Self {
            response: response_data,
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// Refund Response Conversion - Reuses same response structure as Authorize/Capture/Void
impl
    TryFrom<ResponseRouterData<WellsfargoPaymentsResponse, RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<WellsfargoPaymentsResponse, RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let status = get_refund_status(&response.status, &response.error_information);

        // Check if the refund was successful
        let response_data = if is_payment_successful(&response.status, &response.status_information) {
            Ok(RefundsResponseData {
                connector_refund_id: response.id.clone(),
                refund_status: status,
                status_code: item.http_code,
            })
        } else {
            // Build error response
            let error_message = response.error_information
                .as_ref()
                .and_then(|info| info.message.clone())
                .or_else(|| response.error_information
                    .as_ref()
                    .and_then(|info| info.reason.clone()))
                .unwrap_or_else(|| "Refund failed".to_string());

            let error_code = response.error_information
                .as_ref()
                .and_then(|info| info.reason.clone());

            Err(ErrorResponse {
                code: error_code.unwrap_or_else(|| "DECLINED".to_string()),
                message: error_message.clone(),
                reason: Some(error_message),
                status_code: item.http_code,
                attempt_status: None, // Refunds don't have attempt status
                connector_transaction_id: Some(response.id.clone()),
                network_decline_code: response.processor_information
                    .as_ref()
                    .and_then(|info| info.response_code.clone()),
                network_advice_code: None,
                network_error_message: None,
            })
        };

        Ok(Self {
            response: response_data,
            resource_common_data: RefundFlowData {
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// ============================================================================
// RESPONSE CONVERSIONS - RSYNC (REFUND SYNC)
// ============================================================================

impl
    TryFrom<ResponseRouterData<WellsfargoPaymentsResponse, RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<WellsfargoPaymentsResponse, RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let status = get_refund_status(&response.status, &response.error_information);

        // Check if the refund sync was successful
        let response_data = if is_payment_successful(&response.status, &response.status_information) {
            Ok(RefundsResponseData {
                connector_refund_id: response.id.clone(),
                refund_status: status,
                status_code: item.http_code,
            })
        } else {
            // Build error response
            let error_message = response.error_information
                .as_ref()
                .and_then(|info| info.message.clone())
                .or_else(|| response.error_information
                    .as_ref()
                    .and_then(|info| info.reason.clone()))
                .unwrap_or_else(|| "Refund sync failed".to_string());

            let error_code = response.error_information
                .as_ref()
                .and_then(|info| info.reason.clone());

            Err(ErrorResponse {
                code: error_code.unwrap_or_else(|| "DECLINED".to_string()),
                message: error_message.clone(),
                reason: Some(error_message),
                status_code: item.http_code,
                attempt_status: None, // Refunds don't have attempt status
                connector_transaction_id: Some(response.id.clone()),
                network_decline_code: response.processor_information
                    .as_ref()
                    .and_then(|info| info.response_code.clone()),
                network_advice_code: None,
                network_error_message: None,
            })
        };

        Ok(Self {
            response: response_data,
            resource_common_data: RefundFlowData {
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn is_payment_successful(
    status: &Option<WellsfargoPaymentStatus>,
    status_info: &Option<StatusInformation>,
) -> bool {
    // Check if status field indicates success
    let status_success = matches!(
        status,
        Some(WellsfargoPaymentStatus::Authorized)
            | Some(WellsfargoPaymentStatus::AuthorizedPendingReview)
            | Some(WellsfargoPaymentStatus::PartialAuthorized)
            | Some(WellsfargoPaymentStatus::Pending) // Capture operations return PENDING status
            | Some(WellsfargoPaymentStatus::Voided) // Void operations may return VOIDED status
            | Some(WellsfargoPaymentStatus::Reversed) // Void operations return REVERSED status
    );

    // For refund sync operations, check status_information.reason for "Success"
    let status_info_success = status_info
        .as_ref()
        .and_then(|info| info.reason.as_deref())
        .map(|reason| reason.eq_ignore_ascii_case("success"))
        .unwrap_or(false);

    status_success || status_info_success
}

fn get_payment_status(
    status: &Option<WellsfargoPaymentStatus>,
    error_info: &Option<WellsfargoErrorInformation>,
) -> AttemptStatus {
    match status {
        Some(WellsfargoPaymentStatus::Authorized) => AttemptStatus::Charged,
        Some(WellsfargoPaymentStatus::AuthorizedPendingReview) => AttemptStatus::Pending,
        Some(WellsfargoPaymentStatus::Declined) => AttemptStatus::Failure,
        Some(WellsfargoPaymentStatus::InvalidRequest) => AttemptStatus::Failure,
        Some(WellsfargoPaymentStatus::AuthorizedRiskDeclined) => AttemptStatus::Failure,
        Some(WellsfargoPaymentStatus::PendingAuthentication) => AttemptStatus::AuthenticationPending,
        Some(WellsfargoPaymentStatus::PendingReview) => AttemptStatus::Pending,
        Some(WellsfargoPaymentStatus::Reversed) => AttemptStatus::Voided,
        Some(WellsfargoPaymentStatus::Voided) => AttemptStatus::Voided,
        Some(WellsfargoPaymentStatus::PartialAuthorized) => AttemptStatus::PartialCharged,
        Some(WellsfargoPaymentStatus::Transmitted) => AttemptStatus::Pending,
        Some(WellsfargoPaymentStatus::Pending) => AttemptStatus::Pending,
        None => {
            if error_info.is_some() {
                AttemptStatus::Failure
            } else {
                AttemptStatus::Pending
            }
        }
    }
}

fn get_refund_status(
    status: &Option<WellsfargoPaymentStatus>,
    error_info: &Option<WellsfargoErrorInformation>,
) -> RefundStatus {
    match status {
        Some(WellsfargoPaymentStatus::Pending) => RefundStatus::Pending,
        Some(WellsfargoPaymentStatus::Transmitted) => RefundStatus::Pending,
        Some(WellsfargoPaymentStatus::Declined) => RefundStatus::Failure,
        Some(WellsfargoPaymentStatus::InvalidRequest) => RefundStatus::Failure,
        None => {
            if error_info.is_some() {
                RefundStatus::Failure
            } else {
                RefundStatus::Pending
            }
        }
        _ => RefundStatus::Success, // Default to success for other statuses
    }
}

// ============================================================================
// ERROR REASON HELPER
// ============================================================================

pub fn get_error_reason(
    error_info: Option<WellsfargoErrorInformation>,
    default_message: String,
) -> String {
    error_info
        .and_then(|info| info.message.or(info.reason))
        .unwrap_or(default_message)
}
