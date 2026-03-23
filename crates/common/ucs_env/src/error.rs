use common_utils::errors::ErrorSwitch as CommonErrorSwitch;
use domain_types::errors::{
    doc_url_for_error_code, ApiClientError, ApplicationErrorResponse, ConnectorFlowError,
    ConnectorRequestError, ConnectorResponseError, WebhookError,
};
use grpc_api_types::payments::PaymentServiceAuthorizeResponse;
use tonic::Status;

use crate::logger;

/// Allows [error_stack::Report] to change between error contexts
/// using the dependent [ErrorSwitch] trait to define relations & mappings between traits
pub trait ReportSwitchExt<T, U> {
    /// Switch to the intended report by calling switch
    /// requires error switch to be already implemented on the error type
    fn switch(self) -> Result<T, error_stack::Report<U>>;
}

impl<T, U, V> ReportSwitchExt<T, U> for Result<T, error_stack::Report<V>>
where
    V: CommonErrorSwitch<U> + error_stack::Context,
    U: error_stack::Context,
{
    #[track_caller]
    fn switch(self) -> Result<T, error_stack::Report<U>> {
        match self {
            Ok(i) => Ok(i),
            Err(er) => {
                let new_c = er.current_context().switch();
                Err(er.change_context(new_c))
            }
        }
    }
}

/// Allow [error_stack::Report] to convert between error types
/// This auto-implements [ReportSwitchExt] for the corresponding errors
pub trait ErrorSwitch<T> {
    /// Get the next error type that the source error can be escalated into
    /// This does not consume the source error since we need to keep it in context
    fn switch(&self) -> T;
}

pub trait IntoGrpcStatus {
    fn into_grpc_status(self) -> Status;
}

pub trait ResultExtGrpc<T> {
    #[allow(clippy::result_large_err)]
    fn into_grpc_status(self) -> Result<T, Status>;
}

impl<T, E> ResultExtGrpc<T> for error_stack::Result<T, E>
where
    error_stack::Report<E>: IntoGrpcStatus,
{
    fn into_grpc_status(self) -> Result<T, Status> {
        match self {
            Ok(x) => Ok(x),
            Err(err) => Err(err.into_grpc_status()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigurationError {
    #[error("Invalid host for socket: {0}")]
    AddressError(#[from] std::net::AddrParseError),
    #[error("Failed while building grpc reflection service: {0}")]
    GrpcReflectionServiceError(#[from] tonic_reflection::server::Error),
    #[error("Error while creating metrics server")]
    MetricsServerError,
    #[error("Error while creating the server: {0}")]
    ServerError(#[from] tonic::transport::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

impl IntoGrpcStatus for error_stack::Report<ApplicationErrorResponse> {
    fn into_grpc_status(self) -> Status {
        logger::error!(error=?self);
        match self.current_context() {
            ApplicationErrorResponse::Unauthorized(_) => Status::unauthenticated(self.to_string()),
            ApplicationErrorResponse::ForbiddenCommonResource(_)
            | ApplicationErrorResponse::ForbiddenPrivateResource(_) => {
                Status::permission_denied(self.to_string())
            }
            ApplicationErrorResponse::BadRequest(_)
            | ApplicationErrorResponse::MethodNotAllowed(_)
            | ApplicationErrorResponse::Unprocessable(_) => {
                Status::invalid_argument(self.to_string())
            }
            ApplicationErrorResponse::NotFound(_) | ApplicationErrorResponse::Gone(_) => {
                Status::not_found(self.to_string())
            }
            ApplicationErrorResponse::Conflict(_) => Status::already_exists(self.to_string()),
            ApplicationErrorResponse::NotImplemented(_) => Status::unimplemented(self.to_string()),
            ApplicationErrorResponse::InternalServerError(_)
            | ApplicationErrorResponse::DomainError(_) => Status::internal(self.to_string()),
        }
    }
}

/// Request-phase errors occur before the connector HTTP call; there is no real connector HTTP status.
fn connector_request_error_details(
    e: &ConnectorRequestError,
) -> (Option<u16>, String, String, Option<String>) {
    let msg = e.to_string();
    let error_code = e.error_code().to_string();
    let suggested_action = match e {
        ConnectorRequestError::FailedToObtainIntegrationUrl => {
            Some("Verify connector configuration and integration URL setup".to_string())
        }
        ConnectorRequestError::FailedToObtainAuthType => {
            Some("Verify connector authentication configuration".to_string())
        }
        ConnectorRequestError::RequestEncodingFailed
        | ConnectorRequestError::HeaderMapConstructionFailed
        | ConnectorRequestError::BodySerializationFailed
        | ConnectorRequestError::UrlParsingFailed
        | ConnectorRequestError::UrlEncodingFailed => {
            Some("Check request payload format and structure".to_string())
        }
        ConnectorRequestError::AmountConversionFailed => {
            Some("Ensure amount is in the correct format (minor units) and valid numeric range".to_string())
        }
        ConnectorRequestError::MandatePaymentDataMismatch { .. } => {
            Some("Ensure payment data matches the data used during mandate creation".to_string())
        }
        ConnectorRequestError::InvalidConnectorConfig { .. } => {
            Some("Review and correct connector configuration in merchant account".to_string())
        }
        ConnectorRequestError::InvalidWallet
        | ConnectorRequestError::InvalidWalletToken { .. } => {
            Some("Use a valid wallet or wallet token for the selected payment method".to_string())
        }
        ConnectorRequestError::MissingRequiredField { field_name } => {
            Some(format!("Provide the required field '{field_name}' in your request"))
        }
        ConnectorRequestError::MissingRequiredFields { field_names } => {
            Some(format!("Provide all required fields: {:?}", field_names))
        }
        ConnectorRequestError::InvalidDataFormat { field_name } => {
            Some(format!("Fix the format of field '{field_name}' to match the expected schema"))
        }
        ConnectorRequestError::MismatchedPaymentData => {
            Some("Ensure payment method data, type, and experience are consistent".to_string())
        }
        ConnectorRequestError::MissingPaymentMethodType => {
            Some("Specify a valid payment method type in your request".to_string())
        }
        ConnectorRequestError::NotSupported { .. } | ConnectorRequestError::FlowNotSupported { .. } => {
            Some("Use a supported payment method or flow for this connector".to_string())
        }
        ConnectorRequestError::SourceVerificationFailed => {
            Some("Verify signature, webhook secret, or request source configuration".to_string())
        }
        ConnectorRequestError::MissingApplePayTokenData => {
            Some("Provide valid Apple Pay tokenization data".to_string())
        }
        ConnectorRequestError::CurrencyNotSupported { .. } => {
            Some("Use a currency supported by the connector or add it to connector configuration".to_string())
        }
        ConnectorRequestError::NoConnectorMetaData => {
            Some("Ensure connector metadata is configured in merchant account".to_string())
        }
        ConnectorRequestError::MaxFieldLengthViolated { max_length, .. } => {
            Some(format!("Shorten the field value to at most {max_length} characters"))
        }
        ConnectorRequestError::MissingConnectorMandateID
        | ConnectorRequestError::MissingConnectorMandateMetadata => {
            Some("Complete the mandate flow first to obtain mandate ID and metadata".to_string())
        }
        ConnectorRequestError::MissingConnectorTransactionID
        | ConnectorRequestError::MissingConnectorRefundID
        | ConnectorRequestError::MissingConnectorRelatedTransactionID { .. } => {
            Some("Ensure the prior step completed successfully and provided the required ID".to_string())
        }
        ConnectorRequestError::NotImplemented(_)
        | ConnectorRequestError::CaptureMethodNotSupported => {
            Some("Use a supported capture method or check if this feature is available for the connector".to_string())
        }
        ConnectorRequestError::ConfigurationError { message, .. } => {
            Some(format!("Fix configuration: {}", message))
        }
    };
    (None, error_code, msg, suggested_action)
}

impl ErrorSwitch<grpc_api_types::payments::IntegrationError> for ConnectorRequestError {
    fn switch(&self) -> grpc_api_types::payments::IntegrationError {
        let (_, error_code, error_message, suggested_action) =
            connector_request_error_details(self);
        grpc_api_types::payments::IntegrationError {
            error_message,
            error_code: error_code.clone(),
            suggested_action,
            doc_url: doc_url_for_error_code(&error_code),
        }
    }
}

impl ErrorSwitch<grpc_api_types::payments::ConnectorResponseTransformationError>
    for ConnectorRequestError
{
    fn switch(&self) -> grpc_api_types::payments::ConnectorResponseTransformationError {
        let (_, error_code, error_message, _) = connector_request_error_details(self);
        grpc_api_types::payments::ConnectorResponseTransformationError {
            error_message,
            error_code: error_code.clone(),
            http_status_code: None, // Request-phase: no connector HTTP call yet
        }
    }
}

fn connector_response_error_details(
    e: &ConnectorResponseError,
) -> (Option<u16>, String, String, Option<String>) {
    let msg = e.to_string();
    let error_code = e.as_ref().to_string();
    // Use real connector HTTP status only; never invent when we don't have it.
    let http_status_code = e.http_status_code();
    let suggested_action = match e {
        ConnectorResponseError::ResponseDeserializationFailed { .. }
        | ConnectorResponseError::ResponseHandlingFailed { .. }
        | ConnectorResponseError::UnexpectedResponseError { .. } => Some(
            "Retry the request; if persistent, check connector response format and compatibility"
                .to_string(),
        ),
        ConnectorResponseError::MissingConnectorTransactionID { .. } => Some(
            "Ensure the prior connector call completed and returned the required ID".to_string(),
        ),
    };
    (http_status_code, error_code, msg, suggested_action)
}

impl ErrorSwitch<grpc_api_types::payments::IntegrationError> for ConnectorResponseError {
    fn switch(&self) -> grpc_api_types::payments::IntegrationError {
        let (_, error_code, error_message, suggested_action) =
            connector_response_error_details(self);
        grpc_api_types::payments::IntegrationError {
            error_message,
            error_code: error_code.clone(),
            suggested_action,
            doc_url: doc_url_for_error_code(&error_code),
        }
    }
}

impl ErrorSwitch<grpc_api_types::payments::ConnectorResponseTransformationError>
    for ConnectorResponseError
{
    fn switch(&self) -> grpc_api_types::payments::ConnectorResponseTransformationError {
        let (_, error_code, error_message, _) = connector_response_error_details(self);
        grpc_api_types::payments::ConnectorResponseTransformationError {
            error_message,
            error_code: error_code.clone(),
            http_status_code: self.http_status_code().map(Into::into),
        }
    }
}

impl ErrorSwitch<grpc_api_types::payments::ConnectorResponseTransformationError>
    for ApplicationErrorResponse
{
    fn switch(&self) -> grpc_api_types::payments::ConnectorResponseTransformationError {
        let api_err = self.get_api_error();
        grpc_api_types::payments::ConnectorResponseTransformationError {
            error_message: api_err.error_message.clone(),
            error_code: api_err.sub_code.clone(),
            http_status_code: Some(api_err.error_identifier.into()),
        }
    }
}

impl ErrorSwitch<grpc_api_types::payments::IntegrationError> for ApplicationErrorResponse {
    fn switch(&self) -> grpc_api_types::payments::IntegrationError {
        let api_err = self.get_api_error();
        grpc_api_types::payments::IntegrationError {
            error_message: api_err.error_message.clone(),
            error_code: api_err.sub_code.clone(),
            suggested_action: None,
            doc_url: doc_url_for_error_code(&api_err.sub_code),
        }
    }
}

/// Client errors (timeout, connection failed, etc.) may not have a real connector HTTP response.
fn api_client_error_details(e: &ApiClientError) -> (Option<u16>, String, String) {
    let msg = e.to_string();
    let error_code = e.as_ref().to_string();
    (None, error_code, msg)
}

impl ErrorSwitch<grpc_api_types::payments::IntegrationError> for ApiClientError {
    fn switch(&self) -> grpc_api_types::payments::IntegrationError {
        let (_, error_code, error_message) = api_client_error_details(self);
        grpc_api_types::payments::IntegrationError {
            error_message,
            error_code: error_code.clone(),
            suggested_action: None,
            doc_url: doc_url_for_error_code(&error_code),
        }
    }
}

impl ErrorSwitch<grpc_api_types::payments::ConnectorResponseTransformationError>
    for ApiClientError
{
    fn switch(&self) -> grpc_api_types::payments::ConnectorResponseTransformationError {
        let (_, error_code, error_message) = api_client_error_details(self);
        grpc_api_types::payments::ConnectorResponseTransformationError {
            error_message,
            error_code: error_code.clone(),
            http_status_code: None, // Client errors: no real connector HTTP status
        }
    }
}

impl ErrorSwitch<grpc_api_types::payments::IntegrationError> for ConnectorFlowError {
    fn switch(&self) -> grpc_api_types::payments::IntegrationError {
        match self {
            Self::Request(e) => ErrorSwitch::switch(e),
            Self::Client(e) => ErrorSwitch::switch(e),
            Self::Response(e) => ErrorSwitch::switch(e),
        }
    }
}

impl ErrorSwitch<grpc_api_types::payments::ConnectorResponseTransformationError>
    for ConnectorFlowError
{
    fn switch(&self) -> grpc_api_types::payments::ConnectorResponseTransformationError {
        match self {
            Self::Request(e) => ErrorSwitch::switch(e),
            Self::Client(e) => ErrorSwitch::switch(e),
            Self::Response(e) => ErrorSwitch::switch(e),
        }
    }
}

/// Webhook errors occur during our validation; there is no connector HTTP call.
fn webhook_error_details(e: &WebhookError) -> (Option<u16>, String, String) {
    let msg = e.to_string();
    let error_code = e.as_ref().to_string();
    (None, error_code, msg)
}

impl ErrorSwitch<grpc_api_types::payments::IntegrationError> for WebhookError {
    fn switch(&self) -> grpc_api_types::payments::IntegrationError {
        let (_, error_code, error_message) = webhook_error_details(self);
        grpc_api_types::payments::IntegrationError {
            error_message,
            error_code: error_code.clone(),
            suggested_action: None,
            doc_url: doc_url_for_error_code(&error_code),
        }
    }
}

impl ErrorSwitch<grpc_api_types::payments::ConnectorResponseTransformationError> for WebhookError {
    fn switch(&self) -> grpc_api_types::payments::ConnectorResponseTransformationError {
        let (_, error_code, error_message) = webhook_error_details(self);
        grpc_api_types::payments::ConnectorResponseTransformationError {
            error_message,
            error_code: error_code.clone(),
            http_status_code: None, // Webhook errors: no connector HTTP call
        }
    }
}

/// Extract (connector_http_status_code, error_code, error_message) from a connector flow error.
/// Only Response errors can have a real connector HTTP status (from the actual HTTP response).
/// Request/Client/Webhook: always None — no connector HTTP call or no real status.
pub fn connector_flow_error_to_error_details(
    e: &ConnectorFlowError,
) -> (Option<u16>, String, String) {
    match e {
        ConnectorFlowError::Request(req) => {
            let (_, code, msg, _) = connector_request_error_details(req);
            (None, code, msg)
        }
        ConnectorFlowError::Client(client) => {
            let (_, code, msg) = api_client_error_details(client);
            (None, code, msg)
        }
        ConnectorFlowError::Response(resp) => {
            let (status_code, code, msg, _) = connector_response_error_details(resp);
            (status_code, code, msg)
        }
    }
}

/// Map a request-phase connector error report to `IntegrationError`.
pub fn connector_request_error_report_to_integration(
    report: error_stack::Report<ConnectorRequestError>,
) -> grpc_api_types::payments::IntegrationError {
    ErrorSwitch::switch(report.current_context())
}

/// Map a report (ConnectorRequestError or ApplicationErrorResponse, etc.) into `IntegrationError`.
pub fn report_connector_context_to_integration<E>(
    report: error_stack::Report<E>,
) -> grpc_api_types::payments::IntegrationError
where
    E: ErrorSwitch<grpc_api_types::payments::IntegrationError> + error_stack::Context,
{
    ErrorSwitch::switch(report.current_context())
}

/// Map a request-phase connector error report to `ConnectorResponseTransformationError`.
pub fn connector_request_error_report_to_response_transformation(
    report: error_stack::Report<ConnectorRequestError>,
) -> grpc_api_types::payments::ConnectorResponseTransformationError {
    ErrorSwitch::switch(report.current_context())
}

/// Map a connector response error report to `ConnectorResponseTransformationError`.
pub fn connector_response_error_report_to_response_transformation(
    report: error_stack::Report<ConnectorResponseError>,
) -> grpc_api_types::payments::ConnectorResponseTransformationError {
    ErrorSwitch::switch(report.current_context())
}

/// Map a report (ConnectorRequestError or ConnectorResponseError) into `ConnectorResponseTransformationError`.
pub fn report_connector_context_to_response_transformation<E>(
    report: error_stack::Report<E>,
) -> grpc_api_types::payments::ConnectorResponseTransformationError
where
    E: ErrorSwitch<grpc_api_types::payments::ConnectorResponseTransformationError>
        + error_stack::Context,
{
    ErrorSwitch::switch(report.current_context())
}

#[derive(Debug, Clone)]
pub struct PaymentAuthorizationError {
    pub status: grpc_api_types::payments::PaymentStatus,
    pub error_message: Option<String>,
    pub error_code: Option<String>,
    pub status_code: Option<u32>,
}

impl PaymentAuthorizationError {
    pub fn new(
        status: grpc_api_types::payments::PaymentStatus,
        error_message: Option<String>,
        error_code: Option<String>,
        status_code: Option<u32>,
    ) -> Self {
        Self {
            status,
            error_message,
            error_code,
            status_code,
        }
    }
}

impl From<PaymentAuthorizationError> for PaymentServiceAuthorizeResponse {
    fn from(error: PaymentAuthorizationError) -> Self {
        Self {
            merchant_transaction_id: None,
            connector_transaction_id: None,
            redirection_data: None,
            network_transaction_id: None,
            incremental_authorization_allowed: None,
            status: error.status.into(),
            error: Some(grpc_api_types::payments::ErrorInfo {
                unified_details: None,
                connector_details: Some(grpc_api_types::payments::ConnectorErrorDetails {
                    code: error.error_code.clone(),
                    message: error.error_message.clone(),
                    reason: None,
                }),
                issuer_details: None,
            }),
            status_code: error.status_code.unwrap_or(500),
            response_headers: std::collections::HashMap::new(),
            connector_feature_data: None,
            raw_connector_response: None,
            raw_connector_request: None,
            state: None,
            mandate_reference: None,
            capturable_amount: None,
            captured_amount: None,
            authorized_amount: None,
            connector_response: None,
        }
    }
}
