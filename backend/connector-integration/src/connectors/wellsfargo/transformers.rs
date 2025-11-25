use domain_types::payment_method_data::RawCardNumber;
use common_enums::{AttemptStatus, RefundStatus};
use domain_types::{
    connector_flow::{Authorize, Capture, Refund, RSync, SetupMandate, Void},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentVoidData, RefundFlowData, RefundsData, RefundSyncData, RefundsResponseData, PaymentsResponseData, ResponseId, SetupMandateRequestData},
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    router_data::ErrorResponse,
    errors,
};
use error_stack::{Report, ResultExt};
use hyperswitch_masking::{Secret, ExposeInterface, PeekInterface};
use serde::{Deserialize, Serialize};
use crate::types::ResponseRouterData;

mod error_messages {
    pub const PAYMENT_FAILED: &str = "Payment failed";
    pub const CAPTURE_FAILED: &str = "Capture failed";
    pub const VOID_FAILED: &str = "Void failed";
    pub const REFUND_FAILED: &str = "Refund failed";
    pub const SETUP_MANDATE_FAILED: &str = "Setup mandate failed";
    pub const REFUND_SYNC_FAILED: &str = "Refund sync failed";
    pub const MISSING_APPLICATION_INFO: &str = "Missing application_information in response";
}

// REQUEST STRUCTURES

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WellsfargoPaymentsRequest<T: PaymentMethodDataTypes> {
    processing_information: ProcessingInformation,
    payment_information: PaymentInformation<T>,
    order_information: OrderInformationWithBill,
    client_reference_information: ClientReferenceInformation,
    #[serde(skip_serializing_if = "Option::is_none")]
    merchant_defined_information: Option<Vec<MerchantDefinedInformation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    consumer_authentication_information: Option<ConsumerAuthenticationInformation>,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessingInformation {
    commerce_indicator: String,
    capture: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action_list: Option<Vec<WellsfargoActionsList>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action_token_types: Option<Vec<WellsfargoActionsTokenType>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_options: Option<WellsfargoAuthorizationOptions>,
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
    total_amount: common_utils::types::StringMajorUnit,
    currency: common_enums::Currency,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    phone_number: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MerchantDefinedInformation {
    key: u8,
    value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientReferenceInformation {
    code: Option<String>,
}

/// Consumer authentication information for 3DS transactions
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsumerAuthenticationInformation {
    /// Cardholder Authentication Verification Value
    #[serde(skip_serializing_if = "Option::is_none")]
    cavv: Option<Secret<String>>,
    /// Electronic Commerce Indicator
    #[serde(skip_serializing_if = "Option::is_none")]
    eci: Option<String>,
    /// 3DS Server Transaction ID (3DS 2.x)
    #[serde(skip_serializing_if = "Option::is_none")]
    threeds_server_transaction_id: Option<String>,
    /// Directory Server Transaction ID (3DS 2.x)
    #[serde(skip_serializing_if = "Option::is_none")]
    ds_transaction_id: Option<String>,
    /// ACS Transaction ID (3DS 2.x)
    #[serde(skip_serializing_if = "Option::is_none")]
    acs_transaction_id: Option<String>,
    /// 3DS Version (e.g., "2.1.0")
    #[serde(skip_serializing_if = "Option::is_none")]
    specification_version: Option<String>,
    /// UCAF Collection Indicator (Mastercard)
    #[serde(skip_serializing_if = "Option::is_none")]
    ucaf_collection_indicator: Option<String>,
    /// Transaction ID (XID for 3DS 1.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    xid: Option<String>,
}


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


#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WellsfargoVoidRequest {
    client_reference_information: ClientReferenceInformation,
    reversal_information: ReversalInformation,
    #[serde(skip_serializing_if = "Option::is_none")]
    merchant_defined_information: Option<Vec<MerchantDefinedInformation>>,
    // The connector documentation does not mention the merchantDefinedInformation field
    // for Void requests. But this has been still added because it works!
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReversalInformation {
    amount_details: Amount,
    reason: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WellsfargoRefundStatus {
    Succeeded,
    Transmitted,
    Failed,
    Pending,
    Voided,
    Cancelled,
}

impl From<WellsfargoRefundStatus> for RefundStatus {
    fn from(item: WellsfargoRefundStatus) -> Self {
        match item {
            WellsfargoRefundStatus::Succeeded | WellsfargoRefundStatus::Transmitted => {
                Self::Success
            }
            WellsfargoRefundStatus::Cancelled
            | WellsfargoRefundStatus::Failed
            | WellsfargoRefundStatus::Voided => Self::Failure,
            WellsfargoRefundStatus::Pending => Self::Pending,
        }
    }
}

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

// MANDATE SUPPORT STRUCTURES

#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WellsfargoActionsList {
    TokenCreate,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum WellsfargoActionsTokenType {
    PaymentInstrument,
    Customer,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WellsfargoAuthorizationOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    initiator: Option<WellsfargoPaymentInitiator>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WellsfargoPaymentInitiator {
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    initiator_type: Option<WellsfargoPaymentInitiatorTypes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_stored_on_file: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stored_credential_used: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WellsfargoPaymentInitiatorTypes {
    Customer,
    Merchant,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WellsfargoZeroMandateRequest<T: PaymentMethodDataTypes> {
    processing_information: ProcessingInformation,
    payment_information: PaymentInformation<T>,
    order_information: OrderInformationWithBill,
    client_reference_information: ClientReferenceInformation,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<T>,
}

// RESPONSE STRUCTURES

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WellsfargoPaymentsResponse {
    pub id: String,
    pub status: Option<WellsfargoPaymentStatus>,
    pub status_information: Option<StatusInformation>, // For PSync/GET responses
    pub client_reference_information: Option<ClientReferenceInformation>,
    pub processor_information: Option<ClientProcessorInformation>,
    pub error_information: Option<WellsfargoErrorInformation>,
    pub token_information: Option<WellsfargoTokenInformation>, // For SetupMandate responses
    #[serde(rename = "_links")]
    pub links: Option<WellsfargoLinks>, // HATEOAS links to determine payment state
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WellsfargoLinks {
    pub capture: Option<WellsfargoLink>,
    #[serde(rename = "self")]
    pub self_link: Option<WellsfargoLink>,
    pub auth_reversal: Option<WellsfargoLink>,
    pub void: Option<WellsfargoLink>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WellsfargoLink {
    pub href: String,
    pub method: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusInformation {
    pub reason: Option<String>,
    pub message: Option<String>,
}

// Response structure for TSS (Transaction Search Service) endpoint
// Used for RSync (Refund Sync) to query transaction status
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WellsfargoRSyncResponse {
    pub id: String,
    pub application_information: Option<RSyncApplicationInformation>,
    pub error_information: Option<WellsfargoErrorInformation>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RSyncApplicationInformation {
    pub status: Option<WellsfargoRefundStatus>,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WellsfargoTokenInformation {
    pub payment_instrument: Option<WellsfargoPaymentInstrument>,
    pub customer: Option<WellsfargoCustomer>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WellsfargoPaymentInstrument {
    pub id: Secret<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WellsfargoCustomer {
    pub id: Option<Secret<String>>,
}

// ERROR RESPONSE STRUCTURES

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum WellsfargoErrorResponse {
    AuthenticationError(Box<WellsfargoAuthenticationErrorResponse>),
    NotAvailableError(NotAvailableErrorResponse),
    StandardError(StandardErrorResponse),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WellsfargoAuthenticationErrorResponse {
    pub response: AuthenticationErrorInformation,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthenticationErrorInformation {
    pub rmsg: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StandardErrorResponse {
    pub id: Option<String>,  // Transaction ID if available in error response
    pub error_information: Option<WellsfargoErrorInformation>,
    pub status: Option<String>,
    pub message: Option<String>,
    pub reason: Option<String>,
    pub details: Option<Vec<ErrorInfo>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NotAvailableErrorResponse {
    pub id: Option<String>,  // Transaction ID if available in error response
    pub errors: Vec<NotAvailableErrorObject>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NotAvailableErrorObject {
    #[serde(rename = "type")]
    pub error_type: Option<String>,
    pub message: Option<String>,
}

// AUTH TYPE

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

// HELPER FUNCTIONS

/// Converts metadata JSON to Wells Fargo MerchantDefinedInformation format
fn convert_metadata_to_merchant_defined_info(metadata: serde_json::Value) -> Vec<MerchantDefinedInformation> {
    let hashmap: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_str(&metadata.to_string()).unwrap_or(std::collections::BTreeMap::new());
    let mut vector = Vec::new();
    let mut iter = 1;
    for (key, value) in hashmap {
        vector.push(MerchantDefinedInformation {
            key: iter,
            value: format!("{key}={value}"),
        });
        iter += 1;
    }
    vector
}

/// Converts CardIssuer enum to CyberSource/Wells Fargo card type code
fn card_issuer_to_cybersource_code(card_issuer: domain_types::utils::CardIssuer) -> String {
    use domain_types::utils::CardIssuer;
    match card_issuer {
        CardIssuer::Visa => "001",
        CardIssuer::Master => "002",
        CardIssuer::AmericanExpress => "003",
        CardIssuer::Discover => "004",
        CardIssuer::DinersClub => "005",
        CardIssuer::CarteBlanche => "006",
        CardIssuer::JCB => "007",
        CardIssuer::Maestro => "042",
        CardIssuer::CartesBancaires => "036",
    }
    .to_string()
}

/// Extracts phone number with country code from address
fn get_phone_number(
    address: Option<&domain_types::payment_address::Address>,
) -> Option<Secret<String>> {
    address
        .and_then(|addr| addr.phone.as_ref())
        .and_then(|phone| {
            phone.number.as_ref().and_then(|number| {
                phone.country_code.as_ref()
                    .map(|cc| Secret::new(format!("{}{}", cc, number.peek())))
            })
        })
}

/// Determines Wells Fargo commerce indicator based on 3DS authentication status
/// - Success (Y) → "vbv" (liability shift to issuer)
/// - NotVerified/VerificationNotPerformed (A/U) → "spa" (partial protection)
/// - Other/None → "internet" (merchant liable)
fn get_commerce_indicator(
    authentication_data: &Option<domain_types::router_request_types::AuthenticationData>,
) -> String {
    use common_enums::TransactionStatus;

    match authentication_data {
        Some(auth_data) => match auth_data.trans_status {
            Some(TransactionStatus::Success) => "vbv".to_string(),
            Some(TransactionStatus::NotVerified)
            | Some(TransactionStatus::VerificationNotPerformed) => "spa".to_string(),
            Some(TransactionStatus::Failure)
            | Some(TransactionStatus::Rejected)
            | Some(TransactionStatus::ChallengeRequired)
            | Some(TransactionStatus::ChallengeRequiredDecoupledAuthentication)
            | Some(TransactionStatus::InformationOnly)
            | None => "internet".to_string(),
        },
        None => "internet".to_string(),
    }
}

/// Converts AuthenticationData to ConsumerAuthenticationInformation for Wells Fargo
/// Returns None if no 3DS data is present
fn build_consumer_authentication_information(
    authentication_data: &Option<domain_types::router_request_types::AuthenticationData>,
) -> Option<ConsumerAuthenticationInformation> {
    authentication_data.as_ref().and_then(|auth_data| {
        let has_3ds_data = auth_data.cavv.is_some()
            || auth_data.eci.is_some()
            || auth_data.threeds_server_transaction_id.is_some()
            || auth_data.ds_trans_id.is_some()
            || auth_data.acs_transaction_id.is_some()
            || auth_data.message_version.is_some()
            || auth_data.ucaf_collection_indicator.is_some()
            || auth_data.transaction_id.is_some();

        if !has_3ds_data {
            return None;
        }

        Some(ConsumerAuthenticationInformation {
            cavv: auth_data.cavv.clone(),
            eci: auth_data.eci.clone(),
            threeds_server_transaction_id: auth_data.threeds_server_transaction_id.clone(),
            ds_transaction_id: auth_data.ds_trans_id.clone(),
            acs_transaction_id: auth_data.acs_transaction_id.clone(),
            specification_version: auth_data.message_version.as_ref().map(|v| v.to_string()),
            ucaf_collection_indicator: auth_data.ucaf_collection_indicator.clone(),
            xid: auth_data.transaction_id.clone(),
        })
    })
}

// REQUEST CONVERSION - TryFrom RouterDataV2 to WellsfargoPaymentsRequest

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

        // Get payment method data
        let payment_information = match &request.payment_method_data {
            PaymentMethodData::Card(card_data) => {
                // Use get_card_issuer for robust card type detection with fallback
                let card_issuer = domain_types::utils::get_card_issuer(&(format!("{:?}", card_data.card_number.0)));
                let card_type = match card_issuer {
                    Ok(issuer) => Some(card_issuer_to_cybersource_code(issuer)),
                    Err(_) => None,
                };

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
            // Connector supports these but not yet implemented
            PaymentMethodData::Wallet(_)
            | PaymentMethodData::CardToken(_)
            | PaymentMethodData::NetworkToken(_) => {
                Err(errors::ConnectorError::NotImplemented(
                    "Payment method supported by connector but not yet implemented".to_string(),
                ))?
            }
            // Connector does not support these payment methods
            PaymentMethodData::CardDetailsForNetworkTransactionId(_)
            | PaymentMethodData::CardRedirect(_)
            | PaymentMethodData::PayLater(_)
            | PaymentMethodData::BankRedirect(_)
            | PaymentMethodData::BankDebit(_)
            | PaymentMethodData::BankTransfer(_)
            | PaymentMethodData::Crypto(_)
            | PaymentMethodData::MandatePayment
            | PaymentMethodData::Reward
            | PaymentMethodData::RealTimePayment(_)
            | PaymentMethodData::Upi(_)
            | PaymentMethodData::Voucher(_)
            | PaymentMethodData::GiftCard(_)
            | PaymentMethodData::OpenBanking(_)
            | PaymentMethodData::MobilePayment(_) => {
                Err(errors::ConnectorError::NotSupported {
                    message: "Payment method not supported by Wellsfargo".to_string(),
                    connector: "Wellsfargo",
                })?
            }
        };

        // Get amount and currency - amount is in minor units (cents)
        let amount = request.minor_amount;
        let currency = request.currency;

        // Convert amount using the framework's amount converter
        let total_amount = item
            .connector
            .amount_converter
            .convert(amount, currency)
            .change_context(errors::ConnectorError::AmountConversionFailed)?;

        let amount_details = Amount {
            total_amount,
            currency,
        };

        // Build billing information if available
        let billing = common_data.address.get_payment_billing();
        let email = request.email.clone()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "email",
            })?;

        // Convert Email type to Secret<String>
        // Email wraps Secret<String, EmailStrategy>, we need to extract and re-wrap
        let email_inner = email.expose();
        let email_secret = Secret::new(email_inner.expose());

        let bill_to = billing.map(|addr| {
            let phone_number = get_phone_number(Some(addr));
            addr.address.as_ref().map(|details| BillTo {
                first_name: details.first_name.clone(),
                last_name: details.last_name.clone(),
                address1: details.line1.clone(),
                locality: details.city.clone(),
                administrative_area: details.state.clone(),
                postal_code: details.zip.clone(),
                country: details.country,
                email: email_secret.clone(),
                phone_number: phone_number.clone(),
            }).unwrap_or_else(|| BillTo {
                first_name: None,
                last_name: None,
                address1: None,
                locality: None,
                administrative_area: None,
                postal_code: None,
                country: None,
                email: email_secret.clone(),
                phone_number,
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
            phone_number: None,
        }));

        let order_information = OrderInformationWithBill {
            amount_details,
            bill_to,
        };

        // Processing information - set commerce indicator based on 3DS authentication
        let processing_information = ProcessingInformation {
            commerce_indicator: get_commerce_indicator(&request.authentication_data),
            capture: request.capture_method.map(|method| {
                matches!(method, common_enums::CaptureMethod::Automatic)
            }),
            action_list: None,
            action_token_types: None,
            authorization_options: None,
        };

        // Client reference - use payment_id from common data
        let client_reference_information = ClientReferenceInformation {
            code: Some(common_data.payment_id.clone()),
        };

        // Merchant defined information from metadata
        let merchant_defined_information = request
            .metadata
            .clone()
            .map(convert_metadata_to_merchant_defined_info);

        // Consumer authentication information from 3DS data
        let consumer_authentication_information =
            build_consumer_authentication_information(&request.authentication_data);

        Ok(Self {
            processing_information,
            payment_information,
            order_information,
            client_reference_information,
            merchant_defined_information,
            consumer_authentication_information,
            _phantom: std::marker::PhantomData,
        })
    }
}

// CAPTURE REQUEST CONVERSION - TryFrom RouterDataV2 to WellsfargoCaptureRequest

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<super::WellsfargoRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, T>>
    for WellsfargoCaptureRequest
{
    type Error = Report<errors::ConnectorError>;

    fn try_from(
        item: super::WellsfargoRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let request = &router_data.request;
        let common_data = &router_data.resource_common_data;

        // Amount information
        let amount = request.minor_amount_to_capture;
        let currency = request.currency;

        // Convert amount using the framework's amount converter
        let total_amount = item
            .connector
            .amount_converter
            .convert(amount, currency)
            .change_context(errors::ConnectorError::AmountConversionFailed)?;

        let amount_details = Amount {
            total_amount,
            currency,
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

// VOID REQUEST CONVERSION - TryFrom RouterDataV2 to WellsfargoVoidRequest

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<super::WellsfargoRouterData<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, T>>
    for WellsfargoVoidRequest
{
    type Error = Report<errors::ConnectorError>;

    fn try_from(
        item: super::WellsfargoRouterData<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let common_data = &router_data.resource_common_data;
        let request = &router_data.request;

        // Amount information - must be provided in the request
        let amount = request.amount.ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "amount",
            },
        )?;
        let currency = request.currency.ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "currency",
            },
        )?;

        // Convert amount using the framework's amount converter
        let total_amount = item
            .connector
            .amount_converter
            .convert(amount, currency)
            .change_context(errors::ConnectorError::AmountConversionFailed)?;

        let amount_details = Amount {
            total_amount,
            currency,
        };

        // Reversal information with amount and reason
        let reversal_information = ReversalInformation {
            amount_details,
            reason: request
                .cancellation_reason
                .clone()
                .unwrap_or_else(|| "Cancellation requested".to_string()),
        };

        // Client reference - use payment_id from common data
        let client_reference_information = ClientReferenceInformation {
            code: Some(common_data.payment_id.clone()),
        };

        // Merchant defined information from metadata
        // Note: PaymentVoidData in UCS v2 doesn't have metadata field, so set to None
        let merchant_defined_information = None;

        Ok(Self {
            client_reference_information,
            reversal_information,
            merchant_defined_information,
        })
    }
}

// REFUND REQUEST CONVERSION - TryFrom RouterDataV2 to WellsfargoRefundRequest

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<super::WellsfargoRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>>
    for WellsfargoRefundRequest
{
    type Error = Report<errors::ConnectorError>;

    fn try_from(
        item: super::WellsfargoRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let request = &router_data.request;

        // Amount information
        let amount = request.minor_refund_amount;
        let currency = request.currency;

        // Convert amount using the framework's amount converter
        let total_amount = item
            .connector
            .amount_converter
            .convert(amount, currency)
            .change_context(errors::ConnectorError::AmountConversionFailed)?;

        let amount_details = Amount {
            total_amount,
            currency,
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

// SETUPMANDATE REQUEST CONVERSION

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize>
    TryFrom<super::WellsfargoRouterData<RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>, T>>
    for WellsfargoZeroMandateRequest<T>
{
    type Error = Report<errors::ConnectorError>;

    fn try_from(
        item: super::WellsfargoRouterData<RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let request = &router_data.request;
        let common_data = &router_data.resource_common_data;

        // Get email - required for mandate setup
        let email = request.email.clone()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "email",
            })?;
        let email_secret = Secret::new(email.peek().to_string());

        // Create billing information from address data
        let billing_address = common_data.address.get_payment_method_billing();

        let bill_to = billing_address.map(|addr| {
            let phone_number = get_phone_number(Some(addr));
            addr.address.as_ref().map(|addr_details| BillTo {
                first_name: addr_details.first_name.clone(),
                last_name: addr_details.last_name.clone(),
                address1: addr_details.line1.clone(),
                locality: addr_details.city.clone(),
                administrative_area: addr_details.state.clone(),
                postal_code: addr_details.zip.clone(),
                country: addr_details.country,
                email: email_secret.clone(),
                phone_number: phone_number.clone(),
            }).unwrap_or_else(|| BillTo {
                first_name: request.customer_name.clone().map(Secret::new),
                last_name: None,
                address1: None,
                locality: None,
                administrative_area: None,
                postal_code: None,
                country: None,
                email: email_secret.clone(),
                phone_number,
            })
        }).or_else(|| {
            // Fallback to minimal billing info if no address
            Some(BillTo {
                first_name: request.customer_name.clone().map(Secret::new),
                last_name: None,
                address1: None,
                locality: None,
                administrative_area: None,
                postal_code: None,
                country: None,
                email: email_secret.clone(),
                phone_number: None,
            })
        });

        // Zero amount for mandate setup
        let order_information = OrderInformationWithBill {
            amount_details: Amount {
                total_amount: common_utils::types::StringMajorUnit::zero(),
                currency: request.currency,
            },
            bill_to,
        };

        // Processing information for mandate
        let processing_information = ProcessingInformation {
            commerce_indicator: "internet".to_string(),
            capture: Some(false),
            action_list: Some(vec![WellsfargoActionsList::TokenCreate]),
            action_token_types: Some(vec![
                WellsfargoActionsTokenType::PaymentInstrument,
                WellsfargoActionsTokenType::Customer,
            ]),
            authorization_options: Some(WellsfargoAuthorizationOptions {
                initiator: Some(WellsfargoPaymentInitiator {
                    initiator_type: Some(WellsfargoPaymentInitiatorTypes::Customer),
                    credential_stored_on_file: Some(true),
                    stored_credential_used: None,
                }),
            }),
        };

        // Payment information from card
        let payment_information = match &request.payment_method_data {
            domain_types::payment_method_data::PaymentMethodData::Card(card_data) => {
                PaymentInformation::Cards(Box::new(CardPaymentInformation {
                    card: Card {
                        number: card_data.card_number.clone(),
                        expiration_month: card_data.card_exp_month.clone(),
                        expiration_year: card_data.card_exp_year.clone(),
                        security_code: Some(card_data.card_cvc.clone()),
                        card_type: None,
                        _phantom: std::marker::PhantomData,
                    },
                }))
            },
            _ => {
                return Err(errors::ConnectorError::NotImplemented("Payment method not supported for SetupMandate".to_string()).into());
            }
        };

        // Client reference - use payment_id
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

// RESPONSE CONVERSION - TryFrom ResponseRouterData to RouterDataV2

impl<T: PaymentMethodDataTypes>
    TryFrom<ResponseRouterData<WellsfargoPaymentsResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<WellsfargoPaymentsResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        // For Authorize flow, determine if it's auto-capture or manual based on capture_method
        let is_auto_capture = item.router_data.request.capture_method
            .map(|method| matches!(method, common_enums::CaptureMethod::Automatic))
            .unwrap_or(false);
        let status = map_attempt_status(&response.status, is_auto_capture, &response.error_information);

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
                .unwrap_or_else(|| error_messages::PAYMENT_FAILED.to_string());

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
            AttemptStatus::Authorized
        } else {
            // For PSync with status field, capture=false to correctly map "Authorized" to "Authorized" not "Charged"
            map_attempt_status(&response.status, false, &response.error_information)
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
                .unwrap_or_else(|| error_messages::PAYMENT_FAILED.to_string());

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
        // For Capture flow, capture=true
        let status = map_attempt_status(&response.status, true, &response.error_information);

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
                .unwrap_or_else(|| error_messages::CAPTURE_FAILED.to_string());

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
        // For Void flow, capture=false
        let status = map_attempt_status(&response.status, false, &response.error_information);

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
                .unwrap_or_else(|| error_messages::VOID_FAILED.to_string());

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

// SETUPMANDATE RESPONSE CONVERSION

impl<T: PaymentMethodDataTypes>
    TryFrom<ResponseRouterData<WellsfargoPaymentsResponse, RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>>>
    for RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>
{
    type Error = Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<WellsfargoPaymentsResponse, RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        // For SetupMandate flow, capture=false (zero-dollar auth)
        let status = map_attempt_status(&response.status, false, &response.error_information);

        // Check if the mandate setup was successful
        let response_data = if is_payment_successful(&response.status, &response.status_information) {
            // Extract mandate reference from token information
            // Wells Fargo returns both payment_instrument.id and customer.id in token_information
            // We store payment_instrument.id as the connector_mandate_id for future recurring payments
            let mandate_reference = response.token_information
                .as_ref()
                .and_then(|token_info| token_info.payment_instrument.as_ref())
                .map(|instrument| {
                    domain_types::connector_types::MandateReference {
                        connector_mandate_id: Some(instrument.id.clone().expose()),
                        payment_method_id: None, // Could potentially use token_information.customer.id here if needed
                    }
                });

            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.id.clone()),
                redirection_data: None,
                mandate_reference: mandate_reference.map(Box::new),
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
                .unwrap_or_else(|| error_messages::SETUP_MANDATE_FAILED.to_string());

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

// RESPONSE CONVERSIONS - RSYNC (REFUND SYNC)

impl
    TryFrom<ResponseRouterData<WellsfargoRSyncResponse, RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<WellsfargoRSyncResponse, RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;

        // Extract status from application_information (TSS endpoint structure)
        let response_data = match response
            .application_information
            .as_ref()
            .and_then(|app_info| app_info.status.clone())
        {
            Some(refund_status) => {
                let status: RefundStatus = refund_status.clone().into();

                // Check if this is a failure status
                if matches!(status, RefundStatus::Failure) {
                    // Special handling for VOIDED status
                    if refund_status == WellsfargoRefundStatus::Voided {
                        Err(ErrorResponse {
                            code: "REFUND_VOIDED".to_string(),
                            message: "Refund has been voided".to_string(),
                            reason: Some("Refund has been voided".to_string()),
                            status_code: item.http_code,
                            attempt_status: None,
                            connector_transaction_id: Some(response.id.clone()),
                            network_decline_code: None,
                            network_advice_code: None,
                            network_error_message: None,
                        })
                    } else {
                        // Other failure cases
                        Err(ErrorResponse {
                            code: response.error_information
                                .as_ref()
                                .and_then(|info| info.reason.clone())
                                .unwrap_or_else(|| "REFUND_FAILED".to_string()),
                            message: response.error_information
                                .as_ref()
                                .and_then(|info| info.message.clone())
                                .unwrap_or_else(|| error_messages::REFUND_FAILED.to_string()),
                            reason: response.error_information
                                .as_ref()
                                .and_then(|info| info.message.clone()),
                            status_code: item.http_code,
                            attempt_status: None,
                            connector_transaction_id: Some(response.id.clone()),
                            network_decline_code: None,
                            network_advice_code: None,
                            network_error_message: None,
                        })
                    }
                } else {
                    // Success or pending status
                    Ok(RefundsResponseData {
                        connector_refund_id: response.id.clone(),
                        refund_status: status,
                        status_code: item.http_code,
                    })
                }
            }
            None => {
                // No status found - check for error information
                if let Some(error_info) = &response.error_information {
                    Err(ErrorResponse {
                        code: error_info.reason.clone().unwrap_or_else(|| "DECLINED".to_string()),
                        message: error_info.message.clone().unwrap_or_else(|| error_messages::REFUND_SYNC_FAILED.to_string()),
                        reason: error_info.message.clone(),
                        status_code: item.http_code,
                        attempt_status: None,
                        connector_transaction_id: Some(response.id.clone()),
                        network_decline_code: None,
                        network_advice_code: None,
                        network_error_message: None,
                    })
                } else {
                    // No status and no error - return unknown status error
                    Err(ErrorResponse {
                        code: "UNKNOWN_STATUS".to_string(),
                        message: "Unable to determine refund status".to_string(),
                        reason: Some(error_messages::MISSING_APPLICATION_INFO.to_string()),
                        status_code: item.http_code,
                        attempt_status: None,
                        connector_transaction_id: Some(response.id.clone()),
                        network_decline_code: None,
                        network_advice_code: None,
                        network_error_message: None,
                    })
                }
            }
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

// HELPER FUNCTIONS

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

/// Maps Wells Fargo payment status to AttemptStatus
/// The capture flag affects interpretation: Authorized+capture=true → Charged
fn map_attempt_status(
    status: &Option<WellsfargoPaymentStatus>,
    capture: bool,
    error_info: &Option<WellsfargoErrorInformation>,
) -> AttemptStatus {
    match status {
        Some(WellsfargoPaymentStatus::Authorized) | Some(WellsfargoPaymentStatus::AuthorizedPendingReview) => {
            if capture {
                AttemptStatus::Charged
            } else {
                AttemptStatus::Authorized
            }
        }
        Some(WellsfargoPaymentStatus::Pending) => {
            if capture {
                AttemptStatus::Charged
            } else {
                AttemptStatus::Pending
            }
        }
        Some(WellsfargoPaymentStatus::Transmitted) => AttemptStatus::Charged,
        Some(WellsfargoPaymentStatus::Voided) | Some(WellsfargoPaymentStatus::Reversed) => {
            AttemptStatus::Voided
        }
        Some(WellsfargoPaymentStatus::Declined)
        | Some(WellsfargoPaymentStatus::AuthorizedRiskDeclined)
        | Some(WellsfargoPaymentStatus::InvalidRequest) => AttemptStatus::Failure,
        Some(WellsfargoPaymentStatus::PendingAuthentication) => {
            AttemptStatus::AuthenticationPending
        }
        Some(WellsfargoPaymentStatus::PendingReview) => AttemptStatus::Pending,
        Some(WellsfargoPaymentStatus::PartialAuthorized) => {
            if capture {
                AttemptStatus::PartialCharged
            } else {
                AttemptStatus::Authorized
            }
        }
        None => {
            if error_info.is_some() {
                AttemptStatus::Failure
            } else {
                AttemptStatus::Pending
            }
        }
    }
}

/// Maps Wells Fargo payment status to RefundStatus
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
        _ => RefundStatus::Success,
    }
}

/// Combines error information into a formatted error message
pub fn get_error_reason(
    error_info: Option<String>,
    detailed_error_info: Option<String>,
    avs_error_info: Option<String>,
) -> Option<String> {
    match (error_info, detailed_error_info, avs_error_info) {
        (Some(message), Some(details), Some(avs_message)) => Some(format!(
            "{message}, detailed_error_information: {details}, avs_message: {avs_message}",
        )),
        (Some(message), Some(details), None) => {
            Some(format!("{message}, detailed_error_information: {details}"))
        }
        (Some(message), None, Some(avs_message)) => {
            Some(format!("{message}, avs_message: {avs_message}"))
        }
        (None, Some(details), Some(avs_message)) => {
            Some(format!("{details}, avs_message: {avs_message}"))
        }
        (Some(message), None, None) => Some(message),
        (None, Some(details), None) => Some(details),
        (None, None, Some(avs_message)) => Some(avs_message),
        (None, None, None) => None,
    }
}
