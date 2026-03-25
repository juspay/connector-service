use common_utils::errors::ErrorSwitch as CommonErrorSwitch;
use domain_types::errors::{
    combine_error_message_with_context, doc_url_for_error_code, ApiClientError,
    ApplicationErrorResponse, ConnectorFlowError, ConnectorResponseTransformationError,
    IntegrationError, IntegrationErrorContext, WebhookError,
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
    V: ErrorSwitch<U> + error_stack::Context,
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

/// Allow [error_stack::Report] to convert between error types
/// This serves as an alternative to [ErrorSwitch]
pub trait ErrorSwitchFrom<T> {
    /// Convert to an error type that the source error can be escalated into
    /// This does not consume the source error since we need to keep it in context
    fn switch_from(error: &T) -> Self;
}

impl<T, S> ErrorSwitch<T> for S
where
    T: ErrorSwitchFrom<Self>,
{
    fn switch(&self) -> T {
        T::switch_from(self)
    }
}

// Bridge domain_types' `common_utils::errors::ErrorSwitch` impls so `ReportSwitchExt` (which uses
// this module's `ErrorSwitch`) can convert connector errors to `ApplicationErrorResponse`.
impl ErrorSwitch<ApplicationErrorResponse> for ConnectorFlowError {
    fn switch(&self) -> ApplicationErrorResponse {
        <Self as CommonErrorSwitch<ApplicationErrorResponse>>::switch(self)
    }
}

impl ErrorSwitch<ApplicationErrorResponse> for IntegrationError {
    fn switch(&self) -> ApplicationErrorResponse {
        <Self as CommonErrorSwitch<ApplicationErrorResponse>>::switch(self)
    }
}

impl ErrorSwitch<ApplicationErrorResponse> for ConnectorResponseTransformationError {
    fn switch(&self) -> ApplicationErrorResponse {
        <Self as CommonErrorSwitch<ApplicationErrorResponse>>::switch(self)
    }
}

impl ErrorSwitch<ApplicationErrorResponse> for WebhookError {
    fn switch(&self) -> ApplicationErrorResponse {
        <Self as CommonErrorSwitch<ApplicationErrorResponse>>::switch(self)
    }
}

impl ErrorSwitch<ApplicationErrorResponse> for ApiClientError {
    fn switch(&self) -> ApplicationErrorResponse {
        <Self as CommonErrorSwitch<ApplicationErrorResponse>>::switch(self)
    }
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
            ApplicationErrorResponse::Unauthorized(api_error) => {
                Status::unauthenticated(&api_error.error_message)
            }
            ApplicationErrorResponse::ForbiddenCommonResource(api_error)
            | ApplicationErrorResponse::ForbiddenPrivateResource(api_error) => {
                Status::permission_denied(&api_error.error_message)
            }
            ApplicationErrorResponse::Conflict(api_error)
            | ApplicationErrorResponse::Gone(api_error)
            | ApplicationErrorResponse::Unprocessable(api_error)
            | ApplicationErrorResponse::InternalServerError(api_error)
            | ApplicationErrorResponse::MethodNotAllowed(api_error)
            | ApplicationErrorResponse::DomainError(api_error) => {
                Status::internal(&api_error.error_message)
            }
            ApplicationErrorResponse::NotImplemented(api_error) => {
                Status::unimplemented(&api_error.error_message)
            }
            ApplicationErrorResponse::NotFound(api_error) => {
                Status::not_found(&api_error.error_message)
            }
            ApplicationErrorResponse::BadRequest(api_error) => {
                Status::invalid_argument(&api_error.error_message)
            }
        }
    }
}

/// Merge base UCS defaults with optional connector-provided [`IntegrationErrorContext`] on the error.
fn merge_request_integration_context(
    base_integration_context: IntegrationErrorContext,
    e: &IntegrationError,
) -> IntegrationErrorContext {
    let v = e.integration_context();
    IntegrationErrorContext {
        suggested_action: v
            .suggested_action
            .clone()
            .or(base_integration_context.suggested_action),
        doc_url: v.doc_url.clone().or(base_integration_context.doc_url),
        additional_context: v
            .additional_context
            .clone()
            .or(base_integration_context.additional_context),
    }
}

/// Request-phase errors occur before the connector HTTP call; there is no real connector HTTP status.
fn connector_request_error_details(
    e: &IntegrationError,
) -> (Option<u16>, String, String, IntegrationErrorContext) {
    let msg = e.to_string();
    let error_code = e.error_code().to_string();
    let suggested_action = match e {
        IntegrationError::FailedToObtainIntegrationUrl { .. } => {
            Some("Verify connector configuration and integration URL setup".to_string())
        }
        IntegrationError::FailedToObtainAuthType { .. } => {
            Some("Verify connector authentication configuration".to_string())
        }
        IntegrationError::RequestEncodingFailed { .. }
        | IntegrationError::HeaderMapConstructionFailed { .. }
        | IntegrationError::BodySerializationFailed { .. }
        | IntegrationError::UrlParsingFailed { .. }
        | IntegrationError::UrlEncodingFailed { .. } => {
            Some("Check request payload format and structure".to_string())
        }
        IntegrationError::AmountConversionFailed { .. } => {
            Some("Ensure amount is in the correct format (minor units) and valid numeric range".to_string())
        }
        IntegrationError::MandatePaymentDataMismatch { .. } => {
            Some("Ensure payment data matches the data used during mandate creation".to_string())
        }
        IntegrationError::InvalidConnectorConfig { .. } => {
            Some("Review and correct connector configuration in merchant account".to_string())
        }
        IntegrationError::InvalidWallet { .. } | IntegrationError::InvalidWalletToken { .. } => {
            Some("Use a valid wallet or wallet token for the selected payment method".to_string())
        }
        IntegrationError::MissingRequiredField { field_name, .. } => {
            Some(format!("Provide the required field '{field_name}' in your request"))
        }
        IntegrationError::MissingRequiredFields { field_names, .. } => {
            Some(format!("Provide all required fields: {:?}", field_names))
        }
        IntegrationError::InvalidDataFormat { field_name, .. } => {
            Some(format!("Fix the format of field '{field_name}' to match the expected schema"))
        }
        IntegrationError::MismatchedPaymentData { .. } => {
            Some("Ensure payment method data, type, and experience are consistent".to_string())
        }
        IntegrationError::MissingPaymentMethodType { .. } => {
            Some("Specify a valid payment method type in your request".to_string())
        }
        IntegrationError::NotSupported { .. } | IntegrationError::FlowNotSupported { .. } => {
            Some("Use a supported payment method or flow for this connector".to_string())
        }
        IntegrationError::SourceVerificationFailed { .. } => {
            Some("Verify signature, webhook secret, or request source configuration".to_string())
        }
        IntegrationError::MissingApplePayTokenData { .. } => {
            Some("Provide valid Apple Pay tokenization data".to_string())
        }
        IntegrationError::CurrencyNotSupported { .. } => {
            Some("Use a currency supported by the connector or add it to connector configuration".to_string())
        }
        IntegrationError::NoConnectorMetaData { .. } => {
            Some("Ensure connector metadata is configured in merchant account".to_string())
        }
        IntegrationError::MaxFieldLengthViolated { max_length, .. } => {
            Some(format!("Shorten the field value to at most {max_length} characters"))
        }
        IntegrationError::MissingConnectorMandateID { .. }
        | IntegrationError::MissingConnectorMandateMetadata { .. } => {
            Some("Complete the mandate flow first to obtain mandate ID and metadata".to_string())
        }
        IntegrationError::MissingConnectorTransactionID { .. }
        | IntegrationError::MissingConnectorRefundID { .. }
        | IntegrationError::MissingConnectorRelatedTransactionID { .. } => {
            Some("Ensure the prior step completed successfully and provided the required ID".to_string())
        }
        IntegrationError::NotImplemented(..) | IntegrationError::CaptureMethodNotSupported { .. } => {
            Some("Use a supported capture method or check if this feature is available for the connector".to_string())
        }
        IntegrationError::ConfigurationError { message, .. } => {
            Some(format!("Fix configuration: {}", message))
        }
    };
    let base_integration_context = IntegrationErrorContext {
        suggested_action,
        doc_url: doc_url_for_error_code(&error_code),
        additional_context: None,
    };
    let merged_integration_context = merge_request_integration_context(base_integration_context, e);
    (None, error_code, msg, merged_integration_context)
}

impl ErrorSwitch<grpc_api_types::payments::IntegrationError> for IntegrationError {
    fn switch(&self) -> grpc_api_types::payments::IntegrationError {
        let (_, error_code, base_message, merged_integration_context) =
            connector_request_error_details(self);
        let error_message = combine_error_message_with_context(
            &base_message,
            merged_integration_context.additional_context.as_deref(),
        );
        grpc_api_types::payments::IntegrationError {
            error_message,
            error_code: error_code.clone(),
            suggested_action: merged_integration_context.suggested_action,
            doc_url: merged_integration_context.doc_url,
        }
    }
}

fn connector_response_error_details(
    e: &ConnectorResponseTransformationError,
) -> (Option<u16>, String, String, Option<String>) {
    let base_msg = e.to_string();
    let error_code = e.as_ref().to_string();
    // Use real connector HTTP status only; never invent when we don't have it.
    let http_status_code = e.http_status_code();
    let error_message = combine_error_message_with_context(&base_msg, e.additional_context());
    let suggested_action = match e {
        ConnectorResponseTransformationError::ResponseDeserializationFailed { .. }
        | ConnectorResponseTransformationError::ResponseHandlingFailed { .. }
        | ConnectorResponseTransformationError::UnexpectedResponseError { .. } => Some(
            "Share the error code with support to verify integration compatibility and configuration."
                .to_string(),
        ),
    };
    (
        http_status_code,
        error_code,
        error_message,
        suggested_action,
    )
}

impl ErrorSwitch<grpc_api_types::payments::ConnectorResponseTransformationError>
    for ConnectorResponseTransformationError
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
            let (_, code, base_msg, merged_integration_context) =
                connector_request_error_details(req);
            let msg = combine_error_message_with_context(
                &base_msg,
                merged_integration_context.additional_context.as_deref(),
            );
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
    report: error_stack::Report<IntegrationError>,
) -> grpc_api_types::payments::IntegrationError {
    ErrorSwitch::switch(report.current_context())
}

/// Map a report (IntegrationError or ApplicationErrorResponse, etc.) into `IntegrationError`.
pub fn report_connector_context_to_integration<E>(
    report: error_stack::Report<E>,
) -> grpc_api_types::payments::IntegrationError
where
    E: ErrorSwitch<grpc_api_types::payments::IntegrationError> + error_stack::Context,
{
    ErrorSwitch::switch(report.current_context())
}

/// Map a connector response error report to `ConnectorResponseTransformationError`.
pub fn connector_response_error_report_to_response_transformation(
    report: error_stack::Report<ConnectorResponseTransformationError>,
) -> grpc_api_types::payments::ConnectorResponseTransformationError {
    ErrorSwitch::switch(report.current_context())
}

/// Map a report into `ConnectorResponseTransformationError` (e.g. `ApplicationErrorResponse`,
/// `ConnectorResponseTransformationError`, `ApiClientError`, `WebhookError`).
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

/// Convert ApplicationErrorResponse to proto IntegrationError
impl ErrorSwitch<grpc_api_types::payments::IntegrationError> for ApplicationErrorResponse {
    fn switch(&self) -> grpc_api_types::payments::IntegrationError {
        let api_error = self.get_api_error();
        grpc_api_types::payments::IntegrationError {
            error_message: api_error.error_message.clone(),
            error_code: api_error.sub_code.clone(),
            suggested_action: None,
            doc_url: None,
        }
    }
}

/// Convert ApplicationErrorResponse to proto ConnectorResponseTransformationError
impl ErrorSwitch<grpc_api_types::payments::ConnectorResponseTransformationError>
    for ApplicationErrorResponse
{
    fn switch(&self) -> grpc_api_types::payments::ConnectorResponseTransformationError {
        let api_error = self.get_api_error();
        grpc_api_types::payments::ConnectorResponseTransformationError {
            error_message: api_error.error_message.clone(),
            error_code: api_error.sub_code.clone(),
            http_status_code: Some(api_error.error_identifier.into()),
        }
    }
}
