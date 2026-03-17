#![allow(unused_variables, unused_assignments)]

use common_utils::errors::ErrorSwitch;
// use api_models::errors::types::{ Extra};
use strum::Display;
#[derive(Debug, thiserror::Error, PartialEq, Clone)]
pub enum ApiClientError {
    #[error("Header map construction failed")]
    HeaderMapConstructionFailed,
    #[error("Invalid proxy configuration")]
    InvalidProxyConfiguration,
    #[error("Client construction failed")]
    ClientConstructionFailed,
    #[error("Certificate decode failed")]
    CertificateDecodeFailed,
    #[error("Request body serialization failed")]
    BodySerializationFailed,
    #[error("Unexpected state reached/Invariants conflicted")]
    UnexpectedState,
    #[error("Url Parsing Failed")]
    UrlParsingFailed,
    #[error("URL encoding of request payload failed")]
    UrlEncodingFailed,
    #[error("Failed to send request to connector {0}")]
    RequestNotSent(String),
    #[error("Failed to decode response")]
    ResponseDecodingFailed,

    #[error("Server responded with Request Timeout")]
    RequestTimeoutReceived,

    #[error("connection closed before a message could complete")]
    ConnectionClosedIncompleteMessage,

    #[error("Server responded with Internal Server Error")]
    InternalServerErrorReceived,
    #[error("Server responded with Bad Gateway")]
    BadGatewayReceived,
    #[error("Server responded with Service Unavailable")]
    ServiceUnavailableReceived,
    #[error("Server responded with Gateway Timeout")]
    GatewayTimeoutReceived,
    #[error("Server responded with unexpected response")]
    UnexpectedServerResponse,
}

#[derive(Debug, Clone, thiserror::Error, Display)]
pub enum ApplicationErrorResponse {
    Unauthorized(ApiError),
    ForbiddenCommonResource(ApiError),
    ForbiddenPrivateResource(ApiError),
    Conflict(ApiError),
    Gone(ApiError),
    Unprocessable(ApiError),
    InternalServerError(ApiError),
    NotImplemented(ApiError),
    NotFound(ApiError),
    MethodNotAllowed(ApiError),
    BadRequest(ApiError),
    DomainError(ApiError),
}

impl ApplicationErrorResponse {
    /// Returns a reference to the inner ApiError
    pub fn get_api_error(&self) -> &ApiError {
        match self {
            Self::Unauthorized(err) => err,
            Self::ForbiddenCommonResource(err) => err,
            Self::ForbiddenPrivateResource(err) => err,
            Self::Conflict(err) => err,
            Self::Gone(err) => err,
            Self::Unprocessable(err) => err,
            Self::InternalServerError(err) => err,
            Self::NotImplemented(err) => err,
            Self::NotFound(err) => err,
            Self::MethodNotAllowed(err) => err,
            Self::BadRequest(err) => err,
            Self::DomainError(err) => err,
        }
    }

    pub fn missing_required_field(field_name: &'static str) -> Self {
        Self::BadRequest(ApiError {
            sub_code: "MISSING_REQUIRED_FIELD".to_owned(),
            error_identifier: 400,
            error_message: format!("Missing required param: {field_name}"),
            error_object: None,
        })
    }

    pub fn empty_field_error(field_name: &str) -> Self {
        Self::BadRequest(ApiError {
            sub_code: format!("INVALID_{}", field_name.to_uppercase()),
            error_identifier: 400,
            error_message: format!("{} cannot be empty", field_name),
            error_object: None,
        })
    }
}

#[derive(Debug, serde::Serialize, Clone)]
pub struct ApiError {
    pub sub_code: String,
    pub error_identifier: u16,
    pub error_message: String,
    pub error_object: Option<serde_json::Value>,
}

#[derive(Debug, thiserror::Error)]
pub enum ParsingError {
    #[error("Failed to parse struct: {0}")]
    StructParseFailure(&'static str),
    #[error("Failed to serialize to {0} format")]
    EncodeError(&'static str),
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorType {
    InvalidRequestError,
    ObjectNotFound,
    RouterError,
    ProcessingError,
    BadGateway,
    ServerNotAvailable,
    DuplicateRequest,
    ValidationError,
    ConnectorError,
    LockTimeout,
}

// CE	Connector Error	Errors originating from connector's end
// HE	Hyperswitch Error	Errors originating from Hyperswitch's end
// IR	Invalid Request Error	Error caused due to invalid fields and values in API request
// WE	Webhook Error	Errors related to Webhooks
#[derive(Debug, Clone, router_derive::ApiError)]
#[error(error_type_enum = ErrorType)]
#[allow(unused_variables, unused_assignments)]
pub enum ApiErrorResponse {
    #[error(error_type = ErrorType::ConnectorError, code = "CE_00", message = "{code}: {message}", ignore = "status_code")]
    ExternalConnectorError {
        code: String,
        message: String,
        _connector: String,
        _status_code: u16,
        _reason: Option<String>,
    },
    #[error(error_type = ErrorType::ProcessingError, code = "CE_01", message = "Payment failed during authorization with connector. Retry payment")]
    PaymentAuthorizationFailed { _data: Option<serde_json::Value> },
    #[error(error_type = ErrorType::ProcessingError, code = "CE_02", message = "Payment failed during authentication with connector. Retry payment")]
    PaymentAuthenticationFailed { _data: Option<serde_json::Value> },
    #[error(error_type = ErrorType::ProcessingError, code = "CE_03", message = "Capture attempt failed while processing with connector")]
    PaymentCaptureFailed { _data: Option<serde_json::Value> },
    #[error(error_type = ErrorType::ProcessingError, code = "CE_04", message = "The card data is invalid")]
    InvalidCardData { _data: Option<serde_json::Value> },
    #[error(error_type = ErrorType::ProcessingError, code = "CE_05", message = "The card has expired")]
    CardExpired { _data: Option<serde_json::Value> },
    #[error(error_type = ErrorType::ProcessingError, code = "CE_06", message = "Refund failed while processing with connector. Retry refund")]
    RefundFailed { _data: Option<serde_json::Value> },
    #[error(error_type = ErrorType::ProcessingError, code = "CE_07", message = "Verification failed while processing with connector. Retry operation")]
    VerificationFailed { _data: Option<serde_json::Value> },
    #[error(error_type = ErrorType::ProcessingError, code = "CE_08", message = "Dispute operation failed while processing with connector. Retry operation")]
    DisputeFailed { _data: Option<serde_json::Value> },

    #[error(error_type = ErrorType::LockTimeout, code = "HE_00", message = "Resource is busy. Please try again later.")]
    ResourceBusy,
    #[error(error_type = ErrorType::ServerNotAvailable, code = "HE_00", message = "Something went wrong")]
    InternalServerError,
    #[error(error_type = ErrorType::ServerNotAvailable, code= "HE_00", message = "{component} health check is failing with error: {message}")]
    HealthCheckError {
        component: &'static str,
        message: String,
    },
    #[error(error_type = ErrorType::ValidationError, code = "HE_00", message = "Failed to convert currency to minor unit")]
    CurrencyConversionFailed,
    #[error(error_type = ErrorType::DuplicateRequest, code = "HE_01", message = "Duplicate refund request. Refund already attempted with the refund ID")]
    DuplicateRefundRequest,
    #[error(error_type = ErrorType::DuplicateRequest, code = "HE_01", message = "Duplicate mandate request. Mandate already attempted with the Mandate ID")]
    DuplicateMandate,
    #[error(error_type = ErrorType::DuplicateRequest, code = "HE_01", message = "The merchant account with the specified details already exists in our records")]
    DuplicateMerchantAccount,
    #[error(error_type = ErrorType::DuplicateRequest, code = "HE_01", message = "The merchant connector account with the specified profile_id '{profile_id}' and connector_label '{connector_label}' already exists in our records")]
    DuplicateMerchantConnectorAccount {
        profile_id: String,
        connector_label: String,
    },
    #[error(error_type = ErrorType::DuplicateRequest, code = "HE_01", message = "The payment method with the specified details already exists in our records")]
    DuplicatePaymentMethod,
    #[error(error_type = ErrorType::DuplicateRequest, code = "HE_01", message = "The payment with the specified payment_id already exists in our records")]
    DuplicatePayment {
        _payment_id: common_utils::id_type::PaymentId,
    },
    #[error(error_type = ErrorType::DuplicateRequest, code = "HE_01", message = "The payout with the specified payout_id '{payout_id}' already exists in our records")]
    DuplicatePayout { payout_id: String },
    #[error(error_type = ErrorType::DuplicateRequest, code = "HE_01", message = "The config with the specified key already exists in our records")]
    DuplicateConfig,
    #[error(error_type = ErrorType::ObjectNotFound, code = "HE_02", message = "Refund does not exist in our records")]
    RefundNotFound,
    #[error(error_type = ErrorType::ObjectNotFound, code = "HE_02", message = "Payment Link does not exist in our records")]
    PaymentLinkNotFound,
    #[error(error_type = ErrorType::ObjectNotFound, code = "HE_02", message = "Customer does not exist in our records")]
    CustomerNotFound,
    #[error(error_type = ErrorType::ObjectNotFound, code = "HE_02", message = "Config key does not exist in our records.")]
    ConfigNotFound,
    #[error(error_type = ErrorType::ObjectNotFound, code = "HE_02", message = "Payment does not exist in our records")]
    PaymentNotFound,
    #[error(error_type = ErrorType::ObjectNotFound, code = "HE_02", message = "Payment method does not exist in our records")]
    PaymentMethodNotFound,
    #[error(error_type = ErrorType::ObjectNotFound, code = "HE_02", message = "Merchant account does not exist in our records")]
    MerchantAccountNotFound,
    #[error(error_type = ErrorType::ObjectNotFound, code = "HE_02", message = "Merchant connector account does not exist in our records")]
    MerchantConnectorAccountNotFound { _id: String },
    #[error(error_type = ErrorType::ObjectNotFound, code = "HE_02", message = "Business profile with the given id  '{id}' does not exist in our records")]
    ProfileNotFound { id: String },
    #[error(error_type = ErrorType::ObjectNotFound, code = "HE_02", message = "Profile acquirer with id '{profile_acquirer_id}' not found for profile '{profile_id}'.")]
    ProfileAcquirerNotFound {
        profile_acquirer_id: String,
        profile_id: String,
    },
    #[error(error_type = ErrorType::ObjectNotFound, code = "HE_02", message = "Poll with the given id  '{id}' does not exist in our records")]
    PollNotFound { id: String },
    #[error(error_type = ErrorType::ObjectNotFound, code = "HE_02", message = "Resource ID does not exist in our records")]
    ResourceIdNotFound,
    #[error(error_type = ErrorType::ObjectNotFound, code = "HE_02", message = "Mandate does not exist in our records")]
    MandateNotFound,
    #[error(error_type = ErrorType::ObjectNotFound, code = "HE_02", message = "Authentication does not exist in our records")]
    AuthenticationNotFound { _id: String },
    #[error(error_type = ErrorType::ObjectNotFound, code = "HE_02", message = "Failed to update mandate")]
    MandateUpdateFailed,
    #[error(error_type = ErrorType::ObjectNotFound, code = "HE_02", message = "API Key does not exist in our records")]
    ApiKeyNotFound,
    #[error(error_type = ErrorType::ObjectNotFound, code = "HE_02", message = "Payout does not exist in our records")]
    PayoutNotFound,
    #[error(error_type = ErrorType::ObjectNotFound, code = "HE_02", message = "Event does not exist in our records")]
    EventNotFound,
    #[error(error_type = ErrorType::ValidationError, code = "HE_03", message = "Invalid mandate id passed from connector")]
    MandateSerializationFailed,
    #[error(error_type = ErrorType::ValidationError, code = "HE_03", message = "Unable to parse the mandate identifier passed from connector")]
    MandateDeserializationFailed,
    #[error(error_type = ErrorType::ValidationError, code = "HE_03", message = "Return URL is not configured and not passed in payments request")]
    ReturnUrlUnavailable,
    #[error(error_type = ErrorType::ValidationError, code = "HE_03", message = "This refund is not possible through Hyperswitch. Please raise the refund through {connector} dashboard")]
    RefundNotPossible { connector: String },
    #[error(error_type = ErrorType::ValidationError, code = "HE_03", message = "Mandate Validation Failed" )]
    MandateValidationFailed { _reason: String },
    #[error(error_type= ErrorType::ValidationError, code = "HE_03", message = "The payment has not succeeded yet. Please pass a successful payment to initiate refund")]
    PaymentNotSucceeded,
    #[error(error_type = ErrorType::ValidationError, code = "HE_03", message = "The specified merchant connector account is disabled")]
    MerchantConnectorAccountDisabled,
    #[error(error_type = ErrorType::ValidationError, code = "HE_03", message = "{code}: {message}")]
    PaymentBlockedError {
        code: u16,
        message: String,
        _status: String,
        _reason: String,
    },
    #[error(error_type = ErrorType::ValidationError, code = "HE_03", message = "File validation failed")]
    FileValidationFailed { _reason: String },
    #[error(error_type = ErrorType::ValidationError, code = "HE_03", message = "Dispute status validation failed")]
    DisputeStatusValidationFailed { _reason: String },
    #[error(error_type= ErrorType::ObjectNotFound, code = "HE_04", message = "Successful payment not found for the given payment id")]
    SuccessfulPaymentNotFound,
    #[error(error_type = ErrorType::ObjectNotFound, code = "HE_04", message = "The connector provided in the request is incorrect or not available")]
    IncorrectConnectorNameGiven,
    #[error(error_type = ErrorType::ObjectNotFound, code = "HE_04", message = "Address does not exist in our records")]
    AddressNotFound,
    #[error(error_type = ErrorType::ObjectNotFound, code = "HE_04", message = "Dispute does not exist in our records")]
    DisputeNotFound { _dispute_id: String },
    #[error(error_type = ErrorType::ObjectNotFound, code = "HE_04", message = "File does not exist in our records")]
    FileNotFound,
    #[error(error_type = ErrorType::ObjectNotFound, code = "HE_04", message = "File not available")]
    FileNotAvailable,
    #[error(error_type = ErrorType::ProcessingError, code = "HE_05", message = "Missing tenant id")]
    MissingTenantId,
    #[error(error_type = ErrorType::ProcessingError, code = "HE_05", message = "Invalid tenant id: {tenant_id}")]
    InvalidTenant { tenant_id: String },
    #[error(error_type = ErrorType::ValidationError, code = "HE_06", message = "Failed to convert amount to {amount_type} type")]
    AmountConversionFailed { amount_type: &'static str },
    #[error(error_type = ErrorType::ServerNotAvailable, code = "IR_00", message = "{message:?}")]
    NotImplemented { message: NotImplementedMessage },
    #[error(
        error_type = ErrorType::InvalidRequestError, code = "IR_01",
        message = "API key not provided or invalid API key used"
    )]
    Unauthorized,
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_02", message = "Unrecognized request URL")]
    InvalidRequestUrl,
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_03", message = "The HTTP method is not applicable for this API")]
    InvalidHttpMethod,
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_04", message = "Missing required param: {field_name}")]
    MissingRequiredField { field_name: &'static str },
    #[error(
        error_type = ErrorType::InvalidRequestError, code = "IR_05",
        message = "{field_name} contains invalid data. Expected format is {expected_format}"
    )]
    InvalidDataFormat {
        field_name: String,
        expected_format: String,
    },
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_06", message = "{message}")]
    InvalidRequestData { message: String },
    /// Typically used when a field has invalid value, or deserialization of the value contained in a field fails.
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_07", message = "Invalid value provided: {field_name}")]
    InvalidDataValue { field_name: &'static str },
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_08", message = "Client secret was not provided")]
    ClientSecretNotGiven,
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_08", message = "Client secret has expired")]
    ClientSecretExpired,
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_09", message = "The client_secret provided does not match the client_secret associated with the Payment")]
    ClientSecretInvalid,
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_10", message = "Customer has active mandate/subsciption")]
    MandateActive,
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_11", message = "Customer has already been redacted")]
    CustomerRedacted,
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_12", message = "Reached maximum refund attempts")]
    MaximumRefundCount,
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_13", message = "The refund amount exceeds the amount captured")]
    RefundAmountExceedsPaymentAmount,
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_14", message = "This Payment could not be {current_flow} because it has a {field_name} of {current_value}. The expected state is {states}")]
    PaymentUnexpectedState {
        current_flow: String,
        field_name: String,
        current_value: String,
        states: String,
    },
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_15", message = "Invalid Ephemeral Key for the customer")]
    InvalidEphemeralKey,
    /// Typically used when information involving multiple fields or previously provided information doesn't satisfy a condition.
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_16", message = "{message}")]
    PreconditionFailed { message: String },
    #[error(
        error_type = ErrorType::InvalidRequestError, code = "IR_17",
        message = "Access forbidden, invalid JWT token was used"
    )]
    InvalidJwtToken,
    #[error(
        error_type = ErrorType::InvalidRequestError, code = "IR_18",
        message = "{message}",
    )]
    GenericUnauthorized { message: String },
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_19", message = "{message}")]
    NotSupported { message: String },
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_20", message = "{flow} flow not supported by the {connector} connector")]
    FlowNotSupported { flow: String, connector: String },
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_21", message = "Missing required params")]
    MissingRequiredFields { _field_names: Vec<&'static str> },
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_22", message = "Access forbidden. Not authorized to access this resource {resource}")]
    AccessForbidden { resource: String },
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_23", message = "{message}")]
    FileProviderNotSupported { message: String },
    #[error(
        error_type = ErrorType::ProcessingError, code = "IR_24",
        message = "Invalid {wallet_name} wallet token"
    )]
    InvalidWalletToken { wallet_name: String },
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_25", message = "Cannot delete the default payment method")]
    PaymentMethodDeleteFailed,
    #[error(
        error_type = ErrorType::InvalidRequestError, code = "IR_26",
        message = "Invalid Cookie"
    )]
    InvalidCookie,
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_27", message = "Extended card info does not exist")]
    ExtendedCardInfoNotFound,
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_28", message = "{message}")]
    CurrencyNotSupported { message: String },
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_29", message = "{message}")]
    UnprocessableEntity { message: String },
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_30", message = "Merchant connector account is configured with invalid {config}")]
    InvalidConnectorConfiguration { config: String },
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_31", message = "Card with the provided iin does not exist")]
    InvalidCardIin,
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_32", message = "The provided card IIN length is invalid, please provide an iin with 6 or 8 digits")]
    InvalidCardIinLength,
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_33", message = "File not found / valid in the request")]
    MissingFile,
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_34", message = "Dispute id not found in the request")]
    MissingDisputeId,
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_35", message = "File purpose not found in the request or is invalid")]
    MissingFilePurpose,
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_36", message = "File content type not found / valid")]
    MissingFileContentType,
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_37", message = "{message}")]
    GenericNotFoundError { message: String },
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_38", message = "{message}")]
    GenericDuplicateError { message: String },
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_39", message = "required payment method is not configured or configured incorrectly for all configured connectors")]
    IncorrectPaymentMethodConfiguration,
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_40", message = "{message}")]
    LinkConfigurationError { message: String },
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_41", message = "Payout validation failed")]
    PayoutFailed { _data: Option<serde_json::Value> },
    #[error(
        error_type = ErrorType::InvalidRequestError, code = "IR_42",
        message = "Cookies are not found in the request"
    )]
    CookieNotFound,
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_43", message = "API does not support platform account operation")]
    PlatformAccountAuthNotSupported,
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_44", message = "Invalid platform account operation")]
    InvalidPlatformOperation,
    #[error(error_type = ErrorType::InvalidRequestError, code = "IR_45", message = "External vault failed during processing with connector")]
    ExternalVaultFailed,
    #[error(error_type = ErrorType::InvalidRequestError, code = "WE_01", message = "Failed to authenticate the webhook")]
    WebhookAuthenticationFailed,
    #[error(error_type = ErrorType::InvalidRequestError, code = "WE_02", message = "Bad request received in webhook")]
    WebhookBadRequest,
    #[error(error_type = ErrorType::RouterError, code = "WE_03", message = "There was some issue processing the webhook")]
    WebhookProcessingFailure,
    #[error(error_type = ErrorType::ObjectNotFound, code = "WE_04", message = "Webhook resource not found")]
    WebhookResourceNotFound,
    #[error(error_type = ErrorType::InvalidRequestError, code = "WE_05", message = "Unable to process the webhook body")]
    WebhookUnprocessableEntity,
    #[error(error_type = ErrorType::InvalidRequestError, code = "WE_06", message = "Merchant Secret set my merchant for webhook source verification is invalid")]
    WebhookInvalidMerchantSecret,
    #[error(error_type = ErrorType::ServerNotAvailable, code = "IE", message = "{reason} as data mismatched for {field_names}")]
    IntegrityCheckFailed {
        reason: String,
        field_names: String,
        _connector_transaction_id: Option<String>,
    },
}

#[derive(Clone)]
pub enum NotImplementedMessage {
    Reason(String),
    Default,
}

impl std::fmt::Debug for NotImplementedMessage {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reason(message) => write!(fmt, "{message} is not implemented"),
            Self::Default => {
                write!(
                    fmt,
                    "This API is under development and will be made available soon."
                )
            }
        }
    }
}

impl ::core::fmt::Display for ApiErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"{{"error":{}}}"#,
            serde_json::to_string(self).unwrap_or_else(|_| "API error response".to_string())
        )
    }
}

// impl ErrorSwitch<api_models::errors::types::ApiErrorResponse> for ApiErrorResponse {
//     fn switch(&self) -> api_models::errors::types::ApiErrorResponse {
//         use api_models::errors::types::{ApiError, ApiErrorResponse as AER};

//         match self {
//             Self::ExternalConnectorError {
//                 code,
//                 message,
//                 connector,
//                 reason,
//                 status_code,
//             } => AER::ConnectorError(ApiError::new("CE", 0, format!("{code}: {message}"), Some(Extra {connector: Some(connector.clone()), reason: reason.to_owned(), ..Default::default()})), StatusCode::from_u16(*status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)),
//             Self::PaymentAuthorizationFailed { data } => {
//                 AER::BadRequest(ApiError::new("CE", 1, "Payment failed during authorization with connector. Retry payment", Some(Extra { data: data.clone(), ..Default::default()})))
//             }
//             Self::PaymentAuthenticationFailed { data } => {
//                 AER::BadRequest(ApiError::new("CE", 2, "Payment failed during authentication with connector. Retry payment", Some(Extra { data: data.clone(), ..Default::default()})))
//             }
//             Self::PaymentCaptureFailed { data } => {
//                 AER::BadRequest(ApiError::new("CE", 3, "Capture attempt failed while processing with connector", Some(Extra { data: data.clone(), ..Default::default()})))
//             }
//             Self::InvalidCardData { data } => AER::BadRequest(ApiError::new("CE", 4, "The card data is invalid", Some(Extra { data: data.clone(), ..Default::default()}))),
//             Self::CardExpired { data } => AER::BadRequest(ApiError::new("CE", 5, "The card has expired", Some(Extra { data: data.clone(), ..Default::default()}))),
//             Self::RefundFailed { data } => AER::BadRequest(ApiError::new("CE", 6, "Refund failed while processing with connector. Retry refund", Some(Extra { data: data.clone(), ..Default::default()}))),
//             Self::VerificationFailed { data } => {
//                 AER::BadRequest(ApiError::new("CE", 7, "Verification failed while processing with connector. Retry operation", Some(Extra { data: data.clone(), ..Default::default()})))
//             },
//             Self::DisputeFailed { data } => {
//                 AER::BadRequest(ApiError::new("CE", 8, "Dispute operation failed while processing with connector. Retry operation", Some(Extra { data: data.clone(), ..Default::default()})))
//             }

//             Self::ResourceBusy => {
//                 AER::Unprocessable(ApiError::new("HE", 0, "There was an issue processing the webhook body", None))
//             }
//             Self::CurrencyConversionFailed => {
//                 AER::Unprocessable(ApiError::new("HE", 0, "Failed to convert currency to minor unit", None))
//             }
//             Self::InternalServerError => {
//                 AER::InternalServerError(ApiError::new("HE", 0, "Something went wrong", None))
//             },
//             Self::HealthCheckError { message,component } => {
//                 AER::InternalServerError(ApiError::new("HE",0,format!("{} health check failed with error: {}",component,message),None))
//             },
//             Self::DuplicateRefundRequest => AER::BadRequest(ApiError::new("HE", 1, "Duplicate refund request. Refund already attempted with the refund ID", None)),
//             Self::DuplicateMandate => AER::BadRequest(ApiError::new("HE", 1, "Duplicate mandate request. Mandate already attempted with the Mandate ID", None)),
//             Self::DuplicateMerchantAccount => AER::BadRequest(ApiError::new("HE", 1, "The merchant account with the specified details already exists in our records", None)),
//             Self::DuplicateMerchantConnectorAccount { profile_id, connector_label: connector_name } => {
//                 AER::BadRequest(ApiError::new("HE", 1, format!("The merchant connector account with the specified profile_id '{profile_id}' and connector_label '{connector_name}' already exists in our records"), None))
//             }
//             Self::DuplicatePaymentMethod => AER::BadRequest(ApiError::new("HE", 1, "The payment method with the specified details already exists in our records", None)),
//             Self::DuplicatePayment { payment_id } => {
//                 AER::BadRequest(ApiError::new("HE", 1, "The payment with the specified payment_id already exists in our records", Some(Extra {reason: Some(format!("{payment_id:?} already exists")), ..Default::default()})))
//             }
//             Self::DuplicatePayout { payout_id } => {
//                 AER::BadRequest(ApiError::new("HE", 1, format!("The payout with the specified payout_id '{payout_id}' already exists in our records"), None))
//             }
//             Self::DuplicateConfig => {
//                 AER::BadRequest(ApiError::new("HE", 1, "The config with the specified key already exists in our records", None))
//             }
//             Self::RefundNotFound => {
//                 AER::NotFound(ApiError::new("HE", 2, "Refund does not exist in our records.", None))
//             }
//             Self::PaymentLinkNotFound => {
//                 AER::NotFound(ApiError::new("HE", 2, "Payment Link does not exist in our records", None))
//             }
//             Self::CustomerNotFound => {
//                 AER::NotFound(ApiError::new("HE", 2, "Customer does not exist in our records", None))
//             }
//             Self::ConfigNotFound => {
//                 AER::NotFound(ApiError::new("HE", 2, "Config key does not exist in our records.", None))
//             },
//             Self::PaymentNotFound => {
//                 AER::NotFound(ApiError::new("HE", 2, "Payment does not exist in our records", None))
//             }
//             Self::PaymentMethodNotFound => {
//                 AER::NotFound(ApiError::new("HE", 2, "Payment method does not exist in our records", None))
//             }
//             Self::MerchantAccountNotFound => {
//                 AER::NotFound(ApiError::new("HE", 2, "Merchant account does not exist in our records", None))
//             }
//             Self::MerchantConnectorAccountNotFound {id } => {
//                 AER::NotFound(ApiError::new("HE", 2, "Merchant connector account does not exist in our records", Some(Extra {reason: Some(format!("{id} does not exist")), ..Default::default()})))
//             }
//             Self::ProfileNotFound { id } => {
//                 AER::NotFound(ApiError::new("HE", 2, format!("Business profile with the given id {id} does not exist"), None))
//             }
//             Self::ProfileAcquirerNotFound { profile_acquirer_id, profile_id } => {
//                 AER::NotFound(ApiError::new("HE", 2, format!("Profile acquirer with id '{profile_acquirer_id}' not found for profile '{profile_id}'."), None))
//             }
//             Self::PollNotFound { .. } => {
//                 AER::NotFound(ApiError::new("HE", 2, "Poll does not exist in our records", None))
//             },
//             Self::ResourceIdNotFound => {
//                 AER::NotFound(ApiError::new("HE", 2, "Resource ID does not exist in our records", None))
//             }
//             Self::MandateNotFound => {
//                 AER::NotFound(ApiError::new("HE", 2, "Mandate does not exist in our records", None))
//             }
//             Self::AuthenticationNotFound { .. } => {
//                 AER::NotFound(ApiError::new("HE", 2, "Authentication does not exist in our records", None))
//             },
//             Self::MandateUpdateFailed => {
//                 AER::InternalServerError(ApiError::new("HE", 2, "Mandate update failed", None))
//             },
//             Self::ApiKeyNotFound => {
//                 AER::NotFound(ApiError::new("HE", 2, "API Key does not exist in our records", None))
//             }
//             Self::PayoutNotFound => {
//                 AER::NotFound(ApiError::new("HE", 2, "Payout does not exist in our records", None))
//             }
//             Self::EventNotFound => {
//                 AER::NotFound(ApiError::new("HE", 2, "Event does not exist in our records", None))
//             }
//             Self::MandateSerializationFailed | Self::MandateDeserializationFailed => {
//                 AER::InternalServerError(ApiError::new("HE", 3, "Something went wrong", None))
//             },
//             Self::ReturnUrlUnavailable => AER::NotFound(ApiError::new("HE", 3, "Return URL is not configured and not passed in payments request", None)),
//             Self::RefundNotPossible { connector } => {
//                 AER::BadRequest(ApiError::new("HE", 3, format!("This refund is not possible through Hyperswitch. Please raise the refund through {connector} dashboard"), None))
//             }
//             Self::MandateValidationFailed { reason } => {
//                 AER::BadRequest(ApiError::new("HE", 3, "Mandate Validation Failed", Some(Extra { reason: Some(reason.to_owned()), ..Default::default() })))
//             }
//             Self::PaymentNotSucceeded => AER::BadRequest(ApiError::new("HE", 3, "The payment has not succeeded yet. Please pass a successful payment to initiate refund", None)),
//             Self::MerchantConnectorAccountDisabled => {
//                 AER::BadRequest(ApiError::new("HE", 3, "The selected merchant connector account is disabled", None))
//             }
//             Self::PaymentBlockedError {
//                 message,
//                 reason,
//                 ..
//             } => AER::DomainError(ApiError::new("HE", 3, message, Some(Extra { reason: Some(reason.clone()), ..Default::default() }))),
//             Self::FileValidationFailed { reason } => {
//                 AER::BadRequest(ApiError::new("HE", 3, format!("File validation failed {reason}"), None))
//             }
//             Self::DisputeStatusValidationFailed { .. } => {
//                 AER::BadRequest(ApiError::new("HE", 3, "Dispute status validation failed", None))
//             }
//             Self::SuccessfulPaymentNotFound => {
//                 AER::NotFound(ApiError::new("HE", 4, "Successful payment not found for the given payment id", None))
//             }
//             Self::IncorrectConnectorNameGiven => {
//                 AER::NotFound(ApiError::new("HE", 4, "The connector provided in the request is incorrect or not available", None))
//             }
//             Self::AddressNotFound => {
//                 AER::NotFound(ApiError::new("HE", 4, "Address does not exist in our records", None))
//             },
//             Self::DisputeNotFound { .. } => {
//                 AER::NotFound(ApiError::new("HE", 4, "Dispute does not exist in our records", None))
//             },
//             Self::FileNotFound => {
//                 AER::NotFound(ApiError::new("HE", 4, "File does not exist in our records", None))
//             }
//             Self::FileNotAvailable => {
//                 AER::NotFound(ApiError::new("HE", 4, "File not available", None))
//             }
//             Self::MissingTenantId => {
//                 AER::InternalServerError(ApiError::new("HE", 5, "Missing Tenant ID in the request".to_string(), None))
//             }
//             Self::InvalidTenant { tenant_id }  => {
//                 AER::InternalServerError(ApiError::new("HE", 5, format!("Invalid Tenant {tenant_id}"), None))
//             }
//             Self::AmountConversionFailed { amount_type }  => {
//                 AER::InternalServerError(ApiError::new("HE", 6, format!("Failed to convert amount to {amount_type} type"), None))
//             }

//             Self::NotImplemented { message } => {
//                 AER::NotImplemented(ApiError::new("IR", 0, format!("{message:?}"), None))
//             }
//             Self::Unauthorized => AER::Unauthorized(ApiError::new(
//                 "IR",
//                 1,
//                 "API key not provided or invalid API key used", None
//             )),
//             Self::InvalidRequestUrl => {
//                 AER::NotFound(ApiError::new("IR", 2, "Unrecognized request URL", None))
//             }
//             Self::InvalidHttpMethod => AER::MethodNotAllowed(ApiError::new(
//                 "IR",
//                 3,
//                 "The HTTP method is not applicable for this API", None
//             )),
//             Self::MissingRequiredField { field_name } => AER::BadRequest(
//                 ApiError::new("IR", 4, format!("Missing required param: {field_name}"), None),
//             ),
//             Self::InvalidDataFormat {
//                 field_name,
//                 expected_format,
//             } => AER::Unprocessable(ApiError::new(
//                 "IR",
//                 5,
//                 format!(
//                     "{field_name} contains invalid data. Expected format is {expected_format}"
//                 ), None
//             )),
//             Self::InvalidRequestData { message } => {
//                 AER::Unprocessable(ApiError::new("IR", 6, message.to_string(), None))
//             }
//             Self::InvalidDataValue { field_name } => AER::BadRequest(ApiError::new(
//                 "IR",
//                 7,
//                 format!("Invalid value provided: {field_name}"), None
//             )),
//             Self::ClientSecretNotGiven => AER::BadRequest(ApiError::new(
//                 "IR",
//                 8,
//                 "client_secret was not provided", None
//             )),
//             Self::ClientSecretExpired => AER::BadRequest(ApiError::new(
//                 "IR",
//                 8,
//                 "The provided client_secret has expired", None
//             )),
//             Self::ClientSecretInvalid => {
//                 AER::BadRequest(ApiError::new("IR", 9, "The client_secret provided does not match the client_secret associated with the Payment", None))
//             }
//             Self::MandateActive => {
//                 AER::BadRequest(ApiError::new("IR", 10, "Customer has active mandate/subsciption", None))
//             }
//             Self::CustomerRedacted => {
//                 AER::BadRequest(ApiError::new("IR", 11, "Customer has already been redacted", None))
//             }
//             Self::MaximumRefundCount => AER::BadRequest(ApiError::new("IR", 12, "Reached maximum refund attempts", None)),
//             Self::RefundAmountExceedsPaymentAmount => {
//                 AER::BadRequest(ApiError::new("IR", 13, "The refund amount exceeds the amount captured", None))
//             }
//             Self::PaymentUnexpectedState {
//                 current_flow,
//                 field_name,
//                 current_value,
//                 states,
//             } => AER::BadRequest(ApiError::new("IR", 14, format!("This Payment could not be {current_flow} because it has a {field_name} of {current_value}. The expected state is {states}"), None)),
//             Self::InvalidEphemeralKey => AER::Unauthorized(ApiError::new("IR", 15, "Invalid Ephemeral Key for the customer", None)),
//             Self::PreconditionFailed { message } => {
//                 AER::BadRequest(ApiError::new("IR", 16, message.to_string(), None))
//             }
//             Self::InvalidJwtToken => AER::Unauthorized(ApiError::new("IR", 17, "Access forbidden, invalid JWT token was used", None)),
//             Self::GenericUnauthorized { message } => {
//                 AER::Unauthorized(ApiError::new("IR", 18, message.to_string(), None))
//             },
//             Self::NotSupported { message } => {
//                 AER::BadRequest(ApiError::new("IR", 19, "Payment method type not supported", Some(Extra {reason: Some(message.to_owned()), ..Default::default()})))
//             },
//             Self::FlowNotSupported { flow, connector } => {
//                 AER::BadRequest(ApiError::new("IR", 20, format!("{flow} flow not supported"), Some(Extra {connector: Some(connector.to_owned()), ..Default::default()}))) //FIXME: error message
//             }
//             Self::MissingRequiredFields { field_names } => AER::BadRequest(
//                 ApiError::new("IR", 21, "Missing required params".to_string(), Some(Extra {data: Some(serde_json::json!(field_names)), ..Default::default() })),
//             ),
//             Self::AccessForbidden {resource} => {
//                 AER::ForbiddenCommonResource(ApiError::new("IR", 22, format!("Access forbidden. Not authorized to access this resource {resource}"), None))
//             },
//             Self::FileProviderNotSupported { message } => {
//                 AER::BadRequest(ApiError::new("IR", 23, message.to_string(), None))
//             },
//             Self::InvalidWalletToken { wallet_name} => AER::Unprocessable(ApiError::new(
//                 "IR",
//                 24,
//                 format!("Invalid {wallet_name} wallet token"), None
//             )),
//             Self::PaymentMethodDeleteFailed => {
//                 AER::BadRequest(ApiError::new("IR", 25, "Cannot delete the default payment method", None))
//             }
//             Self::InvalidCookie => {
//                 AER::BadRequest(ApiError::new("IR", 26, "Invalid Cookie", None))
//             }
//             Self::ExtendedCardInfoNotFound => {
//                 AER::NotFound(ApiError::new("IR", 27, "Extended card info does not exist", None))
//             }
//             Self::CurrencyNotSupported { message } => {
//                 AER::BadRequest(ApiError::new("IR", 28, message, None))
//             }
//             Self::UnprocessableEntity {message} => AER::Unprocessable(ApiError::new("IR", 29, message.to_string(), None)),
//             Self::InvalidConnectorConfiguration {config} => {
//                 AER::BadRequest(ApiError::new("IR", 30, format!("Merchant connector account is configured with invalid {config}"), None))
//             }
//             Self::InvalidCardIin => AER::BadRequest(ApiError::new("IR", 31, "The provided card IIN does not exist", None)),
//             Self::InvalidCardIinLength  => AER::BadRequest(ApiError::new("IR", 32, "The provided card IIN length is invalid, please provide an IIN with 6 digits", None)),
//             Self::MissingFile => {
//                 AER::BadRequest(ApiError::new("IR", 33, "File not found in the request", None))
//             }
//             Self::MissingDisputeId => {
//                 AER::BadRequest(ApiError::new("IR", 34, "Dispute id not found in the request", None))
//             }
//             Self::MissingFilePurpose => {
//                 AER::BadRequest(ApiError::new("IR", 35, "File purpose not found in the request or is invalid", None))
//             }
//             Self::MissingFileContentType => {
//                 AER::BadRequest(ApiError::new("IR", 36, "File content type not found", None))
//             }
//             Self::GenericNotFoundError { message } => {
//                 AER::NotFound(ApiError::new("IR", 37, message, None))
//             },
//             Self::GenericDuplicateError { message } => {
//                 AER::BadRequest(ApiError::new("IR", 38, message, None))
//             }
//             Self::IncorrectPaymentMethodConfiguration => {
//                 AER::BadRequest(ApiError::new("IR", 39, "No eligible connector was found for the current payment method configuration", None))
//             }
//             Self::LinkConfigurationError { message } => {
//                 AER::BadRequest(ApiError::new("IR", 40, message, None))
//             },
//             Self::PayoutFailed { data } => {
//                 AER::BadRequest(ApiError::new("IR", 41, "Payout failed while processing with connector.", Some(Extra { data: data.clone(), ..Default::default()})))
//             },
//             Self::CookieNotFound => {
//                 AER::Unauthorized(ApiError::new("IR", 42, "Cookies are not found in the request", None))
//             },
//             Self::ExternalVaultFailed => {
//                 AER::BadRequest(ApiError::new("IR", 45, "External Vault failed while processing with connector.", None))
//             },

//             Self::WebhookAuthenticationFailed => {
//                 AER::Unauthorized(ApiError::new("WE", 1, "Webhook authentication failed", None))
//             }
//             Self::WebhookBadRequest => {
//                 AER::BadRequest(ApiError::new("WE", 2, "Bad request body received", None))
//             }
//             Self::WebhookProcessingFailure => {
//                 AER::InternalServerError(ApiError::new("WE", 3, "There was an issue processing the webhook", None))
//             },
//             Self::WebhookResourceNotFound => {
//                 AER::NotFound(ApiError::new("WE", 4, "Webhook resource was not found", None))
//             }
//             Self::WebhookUnprocessableEntity => {
//                 AER::Unprocessable(ApiError::new("WE", 5, "There was an issue processing the webhook body", None))
//             },
//             Self::WebhookInvalidMerchantSecret => {
//                 AER::BadRequest(ApiError::new("WE", 6, "Merchant Secret set for webhook source verification is invalid", None))
//             }
//             Self::IntegrityCheckFailed {
//                 reason,
//                 field_names,
//                 connector_transaction_id
//             } => AER::InternalServerError(ApiError::new(
//                 "IE",
//                 0,
//                 format!("{} as data mismatched for {}", reason, field_names),
//                 Some(Extra {
//                     connector_transaction_id: connector_transaction_id.to_owned(),
//                     ..Default::default()
//                 })
//             )),
//             Self::PlatformAccountAuthNotSupported => {
//                 AER::BadRequest(ApiError::new("IR", 43, "API does not support platform operation", None))
//             }
//             Self::InvalidPlatformOperation => {
//                 AER::Unauthorized(ApiError::new("IR", 44, "Invalid platform account operation", None))
//             }
//         }
//     }
// }

// impl actix_web::ResponseError for ApiErrorResponse {
//     fn status_code(&self) -> StatusCode {
//         ErrorSwitch::<api_models::errors::types::ApiErrorResponse>::switch(self).status_code()
//     }

//     fn error_response(&self) -> actix_web::HttpResponse {
//         ErrorSwitch::<api_models::errors::types::ApiErrorResponse>::switch(self).error_response()
//     }
// }

impl From<ApiErrorResponse> for crate::router_data::ErrorResponse {
    fn from(error: ApiErrorResponse) -> Self {
        Self {
            code: error.error_code(),
            message: error.error_message(),
            reason: None,
            status_code: match error {
                ApiErrorResponse::ExternalConnectorError { _status_code, .. } => _status_code,
                _ => 500,
            },
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        }
    }
}

/// Connector Errors
#[allow(missing_docs, missing_debug_implementations)]
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ConnectorError {
    #[error("Error while obtaining URL for the integration")]
    FailedToObtainIntegrationUrl,
    #[error("Failed to encode connector request")]
    RequestEncodingFailed,
    #[error("Request encoding failed : {0}")]
    RequestEncodingFailedWithReason(String),
    #[error("Parsing failed")]
    ParsingFailed,
    #[error("Integrity check failed: {field_names}")]
    IntegrityCheckFailed {
        field_names: String,
        connector_transaction_id: Option<String>,
    },
    #[error("Failed to deserialize connector response")]
    ResponseDeserializationFailed,
    #[error("Failed to execute a processing step: {0:?}")]
    ProcessingStepFailed(Option<bytes::Bytes>),
    #[error("The connector returned an unexpected response: {0:?}")]
    UnexpectedResponseError(bytes::Bytes),
    #[error("Failed to parse custom routing rules from merchant account")]
    RoutingRulesParsingError,
    #[error("Failed to obtain preferred connector from merchant account")]
    FailedToObtainPreferredConnector,
    #[error("An invalid connector name was provided")]
    InvalidConnectorName,
    #[error("An invalid Wallet was used")]
    InvalidWallet,
    #[error("Failed to handle connector response")]
    ResponseHandlingFailed,
    #[error("Missing required field: {field_name}")]
    MissingRequiredField { field_name: &'static str },
    #[error("Missing required fields: {field_names:?}")]
    MissingRequiredFields { field_names: Vec<&'static str> },
    #[error("Failed to obtain authentication type")]
    FailedToObtainAuthType,
    #[error("Failed to obtain certificate")]
    FailedToObtainCertificate,
    #[error("Connector meta data not found")]
    NoConnectorMetaData,
    #[error("Connector wallet details not found")]
    NoConnectorWalletDetails,
    #[error("Failed to obtain certificate key")]
    FailedToObtainCertificateKey,
    #[error("Failed to verify source of the response")]
    SourceVerificationFailed,
    #[error("Failed to decode message: {0:?}")]
    DecodingFailed(Option<String>),
    #[error("This step has not been implemented for: {0}")]
    NotImplemented(String),
    #[error("{message} is not supported by {connector}")]
    NotSupported {
        message: String,
        connector: &'static str,
    },
    #[error("{flow} flow not supported by {connector} connector")]
    FlowNotSupported { flow: String, connector: String },
    #[error("Capture method not supported")]
    CaptureMethodNotSupported,
    #[error("Missing connector mandate ID")]
    MissingConnectorMandateID,
    #[error("Missing connector mandate metadata")]
    MissingConnectorMandateMetadata,
    #[error("Missing connector transaction ID")]
    MissingConnectorTransactionID,
    #[error("Missing connector refund ID")]
    MissingConnectorRefundID,
    #[error("Missing apple pay tokenization data")]
    MissingApplePayTokenData,
    #[error("Webhooks not implemented for this connector")]
    WebhooksNotImplemented,
    #[error("Failed to decode webhook event body")]
    WebhookBodyDecodingFailed,
    #[error("Failed to decode webhook")]
    WebhookDecodingFailed,
    #[error("Signature not found for incoming webhook")]
    WebhookSignatureNotFound,
    #[error("Failed to verify webhook source")]
    WebhookSourceVerificationFailed,
    #[error("Could not find merchant secret in DB for incoming webhook source verification")]
    WebhookVerificationSecretNotFound,
    #[error("Merchant secret found for incoming webhook source verification is invalid")]
    WebhookVerificationSecretInvalid,
    #[error("Incoming webhook object reference ID not found")]
    WebhookReferenceIdNotFound,
    #[error("Incoming webhook event type not found")]
    WebhookEventTypeNotFound,
    #[error("Incoming webhook event resource object not found")]
    WebhookResourceObjectNotFound,
    #[error("Could not respond to the incoming webhook event")]
    WebhookResponseEncodingFailed,
    #[error("Invalid Date/time format")]
    InvalidDateFormat,
    #[error("Date Formatting Failed")]
    DateFormattingFailed,
    #[error("Invalid Data format: {field_name}")]
    InvalidDataFormat { field_name: &'static str },
    #[error("Payment Method data / Payment Method Type / Payment Experience Mismatch ")]
    MismatchedPaymentData,
    #[error("Failed to parse {wallet_name} wallet token")]
    InvalidWalletToken { wallet_name: String },
    #[error("Missing Connector Related Transaction ID")]
    MissingConnectorRelatedTransactionID { id: String },
    #[error("File Validation failed")]
    FileValidationFailed { reason: String },
    #[error("Missing 3DS redirection payload: {field_name}")]
    MissingConnectorRedirectionPayload { field_name: &'static str },
    #[error("Failed at connector's end with code '{code}'")]
    FailedAtConnector { message: String, code: String },
    #[error("Payment Method Type not found")]
    MissingPaymentMethodType,
    #[error("Balance in the payment method is low")]
    InSufficientBalanceInPaymentMethod,
    #[error("Server responded with Request Timeout")]
    RequestTimeoutReceived,
    #[error("The given currency method is not configured with the given connector")]
    CurrencyNotSupported {
        message: String,
        connector: &'static str,
    },
    #[error("Invalid Configuration: {config}")]
    InvalidConnectorConfig { config: &'static str },
    #[error("Failed to convert amount to required type")]
    AmountConversionFailed,
    #[error("Generic Error")]
    GenericError {
        error_message: String,
        error_object: serde_json::Value,
    },
    #[error("Field {fields} doesn't match with the ones used during mandate creation")]
    MandatePaymentDataMismatch { fields: String },
    #[error("Field '{field_name}' is too long for connector '{connector}'")]
    MaxFieldLengthViolated {
        connector: String,
        field_name: String,
        max_length: usize,
        received_length: usize,
    },
    #[error("Validation failed for fields: {}", field_errors.keys().map(|k| k.as_str()).collect::<Vec<_>>().join(", "))]
    ValidationFailed {
        field_errors: std::collections::HashMap<String, String>,
    },
}

impl ConnectorError {
    /// fn is_connector_timeout
    pub fn is_connector_timeout(&self) -> bool {
        self == &Self::RequestTimeoutReceived
    }

    /// Convenience constructor for single missing field
    pub fn missing_field(field_name: &'static str) -> Self {
        let mut errors = std::collections::HashMap::new();
        errors.insert(field_name.to_string(), "This field is required".to_string());
        Self::ValidationFailed { field_errors: errors }
    }

    /// Get structured field errors from this error
    pub fn get_field_errors(&self) -> std::collections::HashMap<String, String> {
        match self {
            Self::ValidationFailed { field_errors } => field_errors.clone(),
            Self::MissingRequiredField { field_name } => {
                let mut map = std::collections::HashMap::new();
                map.insert(field_name.to_string(), "This field is required".to_string());
                map
            }
            Self::MissingRequiredFields { field_names } => {
                let mut map = std::collections::HashMap::new();
                for field in field_names {
                    map.insert(field.to_string(), "This field is required".to_string());
                }
                map
            }
            Self::InvalidDataFormat { field_name } => {
                let mut map = std::collections::HashMap::new();
                map.insert(field_name.to_string(), format!("Invalid format for {}", field_name));
                map
            }
            Self::IntegrityCheckFailed { field_names, .. } => {
                let mut map = std::collections::HashMap::new();
                for field in field_names.split(", ") {
                    map.insert(
                        field.to_string(),
                        "Value doesn't match mandate creation".to_string(),
                    );
                }
                map
            }
            _ => std::collections::HashMap::new(),
        }
    }


    /// Get machine-readable error code for documentation and SDK
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::ValidationFailed { .. } => "CE_VALIDATION_FAILED",
            Self::MissingRequiredField { .. } => "CE_MISSING_REQUIRED_FIELD",
            Self::MissingRequiredFields { .. } => "CE_MISSING_REQUIRED_FIELDS",
            Self::InvalidDataFormat { .. } => "CE_INVALID_DATA_FORMAT",
            Self::MismatchedPaymentData => "CE_MISMATCHED_PAYMENT_DATA",
            Self::IntegrityCheckFailed { .. } => "CE_INTEGRITY_CHECK_FAILED",
            Self::CurrencyNotSupported { .. } => "CE_CURRENCY_NOT_SUPPORTED",
            Self::InvalidWallet => "CE_INVALID_WALLET",
            Self::InvalidWalletToken { .. } => "CE_INVALID_WALLET_TOKEN",
            Self::FileValidationFailed { .. } => "CE_FILE_VALIDATION_FAILED",
            Self::MissingConnectorRedirectionPayload { .. } => {
                "CE_MISSING_CONNECTOR_REDIRECTION_PAYLOAD"
            }
            Self::InvalidDateFormat => "CE_INVALID_DATE_FORMAT",
            Self::DateFormattingFailed => "CE_DATE_FORMATTING_FAILED",
            Self::MaxFieldLengthViolated { .. } => "CE_MAX_FIELD_LENGTH_VIOLATED",
            Self::MandatePaymentDataMismatch { .. } => "CE_MANDATE_PAYMENT_DATA_MISMATCH",

            Self::FailedToObtainAuthType => "CE_AUTH_TYPE_MISSING",
            Self::InvalidConnectorConfig { .. } => "CE_INVALID_CONNECTOR_CONFIG",
            Self::FailedToObtainCertificate => "CE_CERTIFICATE_MISSING",
            Self::FailedToObtainCertificateKey => "CE_CERTIFICATE_KEY_MISSING",
            Self::NoConnectorMetaData => "CE_NO_CONNECTOR_METADATA",
            Self::NoConnectorWalletDetails => "CE_NO_CONNECTOR_WALLET_DETAILS",
            Self::InvalidConnectorName => "CE_INVALID_CONNECTOR_NAME",

            Self::NotImplemented(_) => "CE_NOT_IMPLEMENTED",
            Self::NotSupported { .. } => "CE_NOT_SUPPORTED",
            Self::FlowNotSupported { .. } => "CE_FLOW_NOT_SUPPORTED",
            Self::CaptureMethodNotSupported => "CE_CAPTURE_METHOD_NOT_SUPPORTED",

            Self::RequestEncodingFailed | Self::RequestEncodingFailedWithReason(_) => {
                "CE_REQUEST_ENCODING_FAILED"
            }
            Self::ResponseDeserializationFailed => "CE_RESPONSE_DESERIALIZATION_FAILED",
            Self::ResponseHandlingFailed => "CE_RESPONSE_HANDLING_FAILED",
            Self::AmountConversionFailed => "CE_AMOUNT_CONVERSION_FAILED",
            Self::ParsingFailed => "CE_PARSING_FAILED",
            Self::ProcessingStepFailed(_) => "CE_PROCESSING_STEP_FAILED",
            Self::UnexpectedResponseError(_) => "CE_UNEXPECTED_RESPONSE",
            Self::DecodingFailed(_) => "CE_DECODING_FAILED",
            Self::FailedToObtainIntegrationUrl => "CE_INTEGRATION_URL_MISSING",
            Self::RoutingRulesParsingError => "CE_ROUTING_RULES_PARSING_ERROR",
            Self::FailedToObtainPreferredConnector => "CE_PREFERRED_CONNECTOR_MISSING",
            Self::SourceVerificationFailed => "CE_SOURCE_VERIFICATION_FAILED",
            Self::GenericError { .. } => "CE_GENERIC_ERROR",

            Self::RequestTimeoutReceived => "CE_REQUEST_TIMEOUT",
            Self::FailedAtConnector { .. } => "CE_CONNECTOR_ERROR",

            Self::MissingConnectorTransactionID => "CE_MISSING_CONNECTOR_TRANSACTION_ID",
            Self::MissingConnectorRefundID => "CE_MISSING_CONNECTOR_REFUND_ID",
            Self::MissingConnectorMandateID => "CE_MISSING_CONNECTOR_MANDATE_ID",
            Self::MissingConnectorMandateMetadata => "CE_MISSING_CONNECTOR_MANDATE_METADATA",
            Self::MissingApplePayTokenData => "CE_MISSING_APPLE_PAY_TOKEN_DATA",
            Self::MissingConnectorRelatedTransactionID { .. } => {
                "CE_MISSING_CONNECTOR_RELATED_TRANSACTION_ID"
            }
            Self::InSufficientBalanceInPaymentMethod => "CE_INSUFFICIENT_BALANCE",
            Self::MissingPaymentMethodType => "CE_MISSING_PAYMENT_METHOD_TYPE",

            Self::WebhookBodyDecodingFailed => "CE_WEBHOOK_BODY_DECODING_FAILED",
            Self::WebhookDecodingFailed => "CE_WEBHOOK_DECODING_FAILED",
            Self::WebhookSignatureNotFound => "CE_WEBHOOK_SIGNATURE_NOT_FOUND",
            Self::WebhookSourceVerificationFailed => "CE_WEBHOOK_SOURCE_VERIFICATION_FAILED",
            Self::WebhookVerificationSecretNotFound => "CE_WEBHOOK_VERIFICATION_SECRET_NOT_FOUND",
            Self::WebhookVerificationSecretInvalid => "CE_WEBHOOK_VERIFICATION_SECRET_INVALID",
            Self::WebhookReferenceIdNotFound => "CE_WEBHOOK_REFERENCE_ID_NOT_FOUND",
            Self::WebhookEventTypeNotFound => "CE_WEBHOOK_EVENT_TYPE_NOT_FOUND",
            Self::WebhookResourceObjectNotFound => "CE_WEBHOOK_RESOURCE_OBJECT_NOT_FOUND",
            Self::WebhookResponseEncodingFailed => "CE_WEBHOOK_RESPONSE_ENCODING_FAILED",
            Self::WebhooksNotImplemented => "CE_WEBHOOKS_NOT_IMPLEMENTED",
        }
    }

    /// Get HTTP status code for this error
    pub fn http_status_code(&self) -> u16 {
        match self {
            // 400 - Bad Request (validation/input errors)
            Self::ValidationFailed { .. }
            | Self::MissingRequiredField { .. }
            | Self::MissingRequiredFields { .. }
            | Self::InvalidDataFormat { .. }
            | Self::MismatchedPaymentData
            | Self::IntegrityCheckFailed { .. }
            | Self::CurrencyNotSupported { .. }
            | Self::InvalidWallet
            | Self::MissingPaymentMethodType
            | Self::InvalidWalletToken { .. }
            | Self::FileValidationFailed { .. }
            | Self::MissingConnectorRedirectionPayload { .. }
            | Self::InvalidDateFormat
            | Self::DateFormattingFailed
            | Self::MaxFieldLengthViolated { .. }
            | Self::MandatePaymentDataMismatch { .. }
            | Self::WebhookBodyDecodingFailed
            | Self::WebhookDecodingFailed
            | Self::WebhookSignatureNotFound
            | Self::WebhookSourceVerificationFailed
            | Self::WebhookVerificationSecretNotFound
            | Self::WebhookVerificationSecretInvalid
            | Self::WebhookReferenceIdNotFound
            | Self::WebhookEventTypeNotFound
            | Self::WebhookResourceObjectNotFound
            | Self::WebhookResponseEncodingFailed => 400,

            // 401 - Unauthorized (auth/config errors)
            Self::FailedToObtainAuthType
            | Self::InvalidConnectorConfig { .. }
            | Self::FailedToObtainCertificate
            | Self::FailedToObtainCertificateKey
            | Self::NoConnectorMetaData
            | Self::NoConnectorWalletDetails
            | Self::InvalidConnectorName => 401,

            // 501 - Not Implemented
            Self::NotImplemented(_)
            | Self::NotSupported { .. }
            | Self::FlowNotSupported { .. }
            | Self::CaptureMethodNotSupported
            | Self::WebhooksNotImplemented => 501,

            // 504 - Gateway Timeout
            Self::RequestTimeoutReceived => 504,

            // 500 - Internal Server Error (processing errors)
            _ => 500,
        }
    }

    /// Check if this error is retryable
    ///
    /// Currently all errors are non-retryable by default.
    /// This will be fine-tuned based on production data and testing.
    pub fn is_retryable(&self) -> bool {
        // TODO: Implement retry logic based on production analysis
        // Candidates for retry:
        // - RequestTimeoutReceived (network timeout)
        // - ResponseDeserializationFailed (transient PSP issue)
        // - WebhookBodyDecodingFailed (PSP might retry)
        false
    }

    /// Get documentation URL for this error
    pub fn documentation_url(&self) -> String {
        format!("https://docs.ucs.com/errors/{}", self.error_code())
    }

    /// Get actionable guidance for developers
    pub fn suggested_action(&self) -> Option<String> {
        match self {
            Self::ValidationFailed { field_errors } => Some(format!(
                "Fix the following fields: {}. Check the connector documentation for field requirements.",
                field_errors.keys().map(|k| format!("'{}'", k)).collect::<Vec<_>>().join(", ")
            )),
            Self::MissingRequiredField { field_name } => Some(format!(
                "Add the '{}' field to your payment request. Check the connector documentation for the expected format.",
                field_name
            )),
            Self::MissingRequiredFields { field_names } => Some(format!(
                "Add the following required fields: {}",
                field_names.iter().map(|f| format!("'{}'", f)).collect::<Vec<_>>().join(", ")
            )),
            Self::InvalidDataFormat { field_name } => Some(format!(
                "Fix the data format for '{}'. Verify the field contains a valid value in the correct format.",
                field_name
            )),
            Self::MismatchedPaymentData => Some(
                "Verify payment method data, payment method type, and payment experience are compatible.".to_string()
            ),
            Self::IntegrityCheckFailed { field_names, .. } => Some(format!(
                "The following fields failed validation: {}. Ensure these match the values used during mandate/token creation.",
                field_names
            )),
            Self::CurrencyNotSupported { message, connector } => Some(format!(
                "Use a different currency supported by {}. Check the connector documentation for supported currencies.",
                connector
            )),
            Self::InvalidWalletToken { wallet_name } => Some(format!(
                "Verify the {} wallet token is valid and correctly formatted.",
                wallet_name
            )),
            Self::MaxFieldLengthViolated { field_name, max_length, connector, .. } => Some(format!(
                "Reduce the length of '{}' to {} characters or less (required by {}).",
                field_name, max_length, connector
            )),

            Self::FailedToObtainAuthType => Some(
                "Verify connector authentication configuration. Ensure all required credentials are correctly configured.".to_string()
            ),
            Self::InvalidConnectorConfig { config } => Some(format!(
                "Fix the configuration for '{}'. Review the connector setup documentation.",
                config
            )),
            Self::FailedToObtainCertificate | Self::FailedToObtainCertificateKey => Some(
                "Check certificate configuration and ensure certificate files are accessible.".to_string()
            ),

            Self::NotImplemented(feature) => Some(format!(
                "{} is not yet implemented for this connector. File a feature request or use an alternative connector.",
                feature
            )),
            Self::NotSupported { message, connector } => Some(format!(
                "{} is not available with {}. Consider using a different connector or payment method.",
                message, connector
            )),
            Self::FlowNotSupported { flow, connector } => Some(format!(
                "Change your payment flow to avoid '{}' with {}. For example, try using auto-capture instead of manual capture.",
                flow, connector
            )),

            Self::RequestEncodingFailedWithReason(reason) => Some(format!(
                "Fix the data formatting issue: {}. Verify all fields match their expected types.",
                reason
            )),
            Self::RequestEncodingFailed => Some(
                "Check that all payment data fields contain valid values in the correct format.".to_string()
            ),
            Self::ResponseDeserializationFailed => Some(
                "This may indicate a connector API version mismatch. Check for UCS updates and verify connector configuration.".to_string()
            ),
            Self::AmountConversionFailed => Some(
                "Verify the amount and currency values. Ensure the currency is supported and amount is within acceptable limits.".to_string()
            ),

            Self::RequestTimeoutReceived => Some(
                "Retry the request. If timeouts persist, check network connectivity or increase timeout settings.".to_string()
            ),

            Self::WebhookSourceVerificationFailed => Some(
                "Check your webhook secret configuration. Ensure it matches the one configured in the connector dashboard.".to_string()
            ),
            Self::WebhookBodyDecodingFailed => Some(
                "Verify the webhook payload format matches the expected schema. This may indicate a webhook version mismatch.".to_string()
            ),

            _ => None,
        }
    }

    /// Get broad error category for SDK classification
    /// Provides high-level grouping for error handling logic
    pub fn category(&self) -> ErrorCategory {
        match self {
            // Validation/Input errors
            Self::ValidationFailed { .. }
            | Self::MissingRequiredField { .. }
            | Self::MissingRequiredFields { .. }
            | Self::InvalidDataFormat { .. }
            | Self::MismatchedPaymentData
            | Self::IntegrityCheckFailed { .. }
            | Self::CurrencyNotSupported { .. }
            | Self::InvalidWallet
            | Self::MissingPaymentMethodType
            | Self::InvalidWalletToken { .. }
            | Self::FileValidationFailed { .. }
            | Self::MissingConnectorRedirectionPayload { .. }
            | Self::InvalidDateFormat
            | Self::DateFormattingFailed
            | Self::MaxFieldLengthViolated { .. }
            | Self::MandatePaymentDataMismatch { .. } => ErrorCategory::ValidationError,

            // Configuration errors
            Self::FailedToObtainAuthType
            | Self::InvalidConnectorConfig { .. }
            | Self::FailedToObtainCertificate
            | Self::FailedToObtainCertificateKey
            | Self::NoConnectorMetaData
            | Self::NoConnectorWalletDetails
            | Self::InvalidConnectorName => ErrorCategory::ConfigurationError,

            // Not supported/implemented
            Self::NotImplemented(_)
            | Self::CaptureMethodNotSupported
            | Self::WebhooksNotImplemented => ErrorCategory::NotImplemented,

            Self::NotSupported { .. } | Self::FlowNotSupported { .. } => {
                ErrorCategory::NotSupported
            }

            // Timeout
            Self::RequestTimeoutReceived => ErrorCategory::TimeoutError,

            // Connector-specific errors
            Self::FailedAtConnector { .. } => ErrorCategory::ConnectorError,

            // Webhook errors
            Self::WebhookBodyDecodingFailed
            | Self::WebhookDecodingFailed
            | Self::WebhookSignatureNotFound
            | Self::WebhookSourceVerificationFailed
            | Self::WebhookVerificationSecretNotFound
            | Self::WebhookVerificationSecretInvalid
            | Self::WebhookReferenceIdNotFound
            | Self::WebhookEventTypeNotFound
            | Self::WebhookResourceObjectNotFound
            | Self::WebhookResponseEncodingFailed => ErrorCategory::WebhookError,

            // Processing errors (everything else)
            _ => ErrorCategory::ProcessingError,
        }
    }
}

/// Broad error categories for SDK classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    ValidationError,
    ConfigurationError,
    NotSupported,
    NotImplemented,
    ProcessingError,
    TimeoutError,
    ConnectorError,
    WebhookError,
}

impl ErrorSwitch<ConnectorError> for common_utils::errors::ParsingError {
    fn switch(&self) -> ConnectorError {
        ConnectorError::ParsingFailed
    }
}

impl ErrorSwitch<ApiErrorResponse> for ConnectorError {
    fn switch(&self) -> ApiErrorResponse {
        match self {
            Self::WebhookSourceVerificationFailed => ApiErrorResponse::WebhookAuthenticationFailed,
            Self::WebhookSignatureNotFound
            | Self::WebhookReferenceIdNotFound
            | Self::WebhookResourceObjectNotFound
            | Self::WebhookBodyDecodingFailed
            | Self::WebhooksNotImplemented => ApiErrorResponse::WebhookBadRequest,
            Self::WebhookEventTypeNotFound => ApiErrorResponse::WebhookUnprocessableEntity,
            Self::WebhookVerificationSecretInvalid => {
                ApiErrorResponse::WebhookInvalidMerchantSecret
            }
            _ => ApiErrorResponse::InternalServerError,
        }
    }
}

// http client errors
#[allow(missing_docs, missing_debug_implementations)]
#[derive(Debug, Clone, thiserror::Error, PartialEq)]
pub enum HttpClientError {
    #[error("Header map construction failed")]
    HeaderMapConstructionFailed,
    #[error("Invalid proxy configuration")]
    InvalidProxyConfiguration,
    #[error("Client construction failed")]
    ClientConstructionFailed,
    #[error("Certificate decode failed")]
    CertificateDecodeFailed,
    #[error("Request body serialization failed")]
    BodySerializationFailed,
    #[error("Unexpected state reached/Invariants conflicted")]
    UnexpectedState,

    #[error("Failed to parse URL")]
    UrlParsingFailed,
    #[error("URL encoding of request payload failed")]
    UrlEncodingFailed,
    #[error("Failed to send request to connector {0}")]
    RequestNotSent(String),
    #[error("Failed to decode response")]
    ResponseDecodingFailed,

    #[error("Server responded with Request Timeout")]
    RequestTimeoutReceived,

    #[error("connection closed before a message could complete")]
    ConnectionClosedIncompleteMessage,

    #[error("Server responded with Internal Server Error")]
    InternalServerErrorReceived,
    #[error("Server responded with Bad Gateway")]
    BadGatewayReceived,
    #[error("Server responded with Service Unavailable")]
    ServiceUnavailableReceived,
    #[error("Server responded with Gateway Timeout")]
    GatewayTimeoutReceived,
    #[error("Server responded with unexpected response")]
    UnexpectedServerResponse,
}

impl ErrorSwitch<ApiClientError> for HttpClientError {
    fn switch(&self) -> ApiClientError {
        match self {
            Self::HeaderMapConstructionFailed => ApiClientError::HeaderMapConstructionFailed,
            Self::InvalidProxyConfiguration => ApiClientError::InvalidProxyConfiguration,
            Self::ClientConstructionFailed => ApiClientError::ClientConstructionFailed,
            Self::CertificateDecodeFailed => ApiClientError::CertificateDecodeFailed,
            Self::BodySerializationFailed => ApiClientError::BodySerializationFailed,
            Self::UnexpectedState => ApiClientError::UnexpectedState,
            Self::UrlParsingFailed => ApiClientError::UrlParsingFailed,
            Self::UrlEncodingFailed => ApiClientError::UrlEncodingFailed,
            Self::RequestNotSent(reason) => ApiClientError::RequestNotSent(reason.clone()),
            Self::ResponseDecodingFailed => ApiClientError::ResponseDecodingFailed,
            Self::RequestTimeoutReceived => ApiClientError::RequestTimeoutReceived,
            Self::ConnectionClosedIncompleteMessage => {
                ApiClientError::ConnectionClosedIncompleteMessage
            }
            Self::InternalServerErrorReceived => ApiClientError::InternalServerErrorReceived,
            Self::BadGatewayReceived => ApiClientError::BadGatewayReceived,
            Self::ServiceUnavailableReceived => ApiClientError::ServiceUnavailableReceived,
            Self::GatewayTimeoutReceived => ApiClientError::GatewayTimeoutReceived,
            Self::UnexpectedServerResponse => ApiClientError::UnexpectedServerResponse,
        }
    }
}
