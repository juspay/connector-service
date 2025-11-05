// Wellsfargo (CyberSource) transformers for V2 API
// This implements the request/response transformation for Wellsfargo payments

use domain_types::payment_method_data::RawCardNumber;
use common_enums::AttemptStatus;
use common_utils::errors::CustomResult;
use domain_types::{
    connector_flow::Authorize,
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, ResponseId},
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    router_data::ErrorResponse,
    errors,
};
use error_stack::{Report, ResultExt};
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
// RESPONSE STRUCTURES
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WellsfargoPaymentsResponse {
    pub id: String,
    pub status: Option<WellsfargoPaymentStatus>,
    pub client_reference_information: Option<ClientReferenceInformation>,
    pub processor_information: Option<ClientProcessorInformation>,
    pub error_information: Option<WellsfargoErrorInformation>,
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
            total_amount: amount.to_string(),
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
        let response_data = if is_payment_successful(&response.status) {
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

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn is_payment_successful(status: &Option<WellsfargoPaymentStatus>) -> bool {
    matches!(
        status,
        Some(WellsfargoPaymentStatus::Authorized)
            | Some(WellsfargoPaymentStatus::AuthorizedPendingReview)
            | Some(WellsfargoPaymentStatus::PartialAuthorized)
    )
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
