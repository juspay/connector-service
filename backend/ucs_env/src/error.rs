use domain_types::errors::{ApiClientError, ApiError, ApplicationErrorResponse, ConnectorError};
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
    /// Convert to an error type that the source can be escalated into
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

impl ErrorSwitch<ApplicationErrorResponse> for ConnectorError {
    fn switch(&self) -> ApplicationErrorResponse {
        // Create ApiError with all rich fields from ConnectorError methods
        let api_error = ApiError {
            sub_code: self.error_code().to_string(),
            error_identifier: self.http_status_code(),
            error_message: self.to_string(),
            error_object: None,
            category: format!("{:?}", self.category()),
            field_errors: self.get_field_errors(),
            suggested_action: self.suggested_action(),
            documentation_url: self.documentation_url(),
            retryable: self.is_retryable(),
        };

        // Wrap in appropriate HTTP status variant based on status code
        match self.http_status_code() {
            400 => ApplicationErrorResponse::BadRequest(api_error),
            401 => ApplicationErrorResponse::Unauthorized(api_error),
            404 => ApplicationErrorResponse::NotFound(api_error),
            422 => ApplicationErrorResponse::Unprocessable(api_error),
            501 => ApplicationErrorResponse::NotImplemented(api_error),
            504 | 500 => ApplicationErrorResponse::InternalServerError(api_error),
            _ => ApplicationErrorResponse::InternalServerError(api_error),
        }
    }
}

impl ErrorSwitch<ApplicationErrorResponse> for ApiClientError {
    fn switch(&self) -> ApplicationErrorResponse {
        let (sub_code, status_code) = match self {
            Self::RequestTimeoutReceived | Self::GatewayTimeoutReceived => {
                ("REQUEST_TIMEOUT", 504)
            }
            _ => ("INTERNAL_SERVER_ERROR", 500),
        };

        ApplicationErrorResponse::InternalServerError(ApiError {
            sub_code: sub_code.to_string(),
            error_identifier: status_code,
            error_message: self.to_string(),
            error_object: None,
            category: "ProcessingError".to_string(),
            field_errors: std::collections::HashMap::new(),
            suggested_action: Some("Retry the request or contact support if the issue persists".to_string()),
            documentation_url: format!("https://docs.ucs.com/errors/{}", sub_code),
        })
    }
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

/// Convert ApplicationErrorResponse to proto RequestError
impl ErrorSwitch<grpc_api_types::payments::RequestError> for ApplicationErrorResponse {
    fn switch(&self) -> grpc_api_types::payments::RequestError {
        let api_error = self.get_api_error();

        // Parse category string to enum
        let category_enum = match api_error.category.as_str() {
            "ValidationError" => grpc_api_types::sdk_config::ErrorCategory::ValidationError,
            "ConfigurationError" => grpc_api_types::sdk_config::ErrorCategory::ConfigurationError,
            "NotSupported" => grpc_api_types::sdk_config::ErrorCategory::NotSupported,
            "NotImplemented" => grpc_api_types::sdk_config::ErrorCategory::NotImplemented,
            "ProcessingError" => grpc_api_types::sdk_config::ErrorCategory::ProcessingError,
            "TimeoutError" => grpc_api_types::sdk_config::ErrorCategory::TimeoutError,
            "ConnectorError" => grpc_api_types::sdk_config::ErrorCategory::ConnectorError,
            "WebhookError" => grpc_api_types::sdk_config::ErrorCategory::WebhookError,
            _ => grpc_api_types::sdk_config::ErrorCategory::ProcessingError,
        };

        grpc_api_types::sdk_config::RequestError {
            status: grpc_api_types::payments::PaymentStatus::Pending.into(),
            error_message: Some(api_error.error_message.clone()),
            error_code: Some(api_error.sub_code.clone()),
            category: Some(category_enum as i32),
            status_code: Some(api_error.error_identifier as u32),
            field_errors: api_error.field_errors.clone(),
            suggested_action: api_error.suggested_action.clone(),
            documentation_url: Some(api_error.documentation_url.clone()),
        }
    }
}

/// Convert ApplicationErrorResponse to proto ResponseError
impl ErrorSwitch<grpc_api_types::sdk_config::ResponseError> for ApplicationErrorResponse {
    fn switch(&self) -> grpc_api_types::sdk_config::ResponseError {
        let api_error = self.get_api_error();

        // Parse category string to enum
        let category_enum = match api_error.category.as_str() {
            "ValidationError" => grpc_api_types::sdk_config::ErrorCategory::ValidationError,
            "ConfigurationError" => grpc_api_types::sdk_config::ErrorCategory::ConfigurationError,
            "NotSupported" => grpc_api_types::sdk_config::ErrorCategory::NotSupported,
            "NotImplemented" => grpc_api_types::sdk_config::ErrorCategory::NotImplemented,
            "ProcessingError" => grpc_api_types::sdk_config::ErrorCategory::ProcessingError,
            "TimeoutError" => grpc_api_types::sdk_config::ErrorCategory::TimeoutError,
            "ConnectorError" => grpc_api_types::sdk_config::ErrorCategory::ConnectorError,
            "WebhookError" => grpc_api_types::sdk_config::ErrorCategory::WebhookError,
            _ => grpc_api_types::sdk_config::ErrorCategory::ProcessingError,
        };

        grpc_api_types::sdk_config::ResponseError {
            status: grpc_api_types::payments::PaymentStatus::Pending.into(),
            error_message: Some(api_error.error_message.clone()),
            error_code: Some(api_error.sub_code.clone()),
            category: Some(category_enum as i32),
            status_code: Some(api_error.error_identifier as u32),
            field_errors: api_error.field_errors.clone(),
            suggested_action: api_error.suggested_action.clone(),
            documentation_url: Some(api_error.documentation_url.clone()),
        }
    }
}
