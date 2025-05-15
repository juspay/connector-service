use domain_types::errors::{ApiClientError, ApplicationErrorResponse, ParsingError};
use hyperswitch_interfaces::errors::ConnectorError;
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
        match self {
            ConnectorError::FailedToObtainIntegrationUrl
            | ConnectorError::FailedToObtainPreferredConnector
            | ConnectorError::FailedToObtainAuthType
            | ConnectorError::FailedToObtainCertificate
            | ConnectorError::FailedToObtainCertificateKey
            | ConnectorError::RequestEncodingFailed
            | ConnectorError::RequestEncodingFailedWithReason(_)
            | ConnectorError::ParsingFailed
            | ConnectorError::ResponseDeserializationFailed
            | ConnectorError::ResponseHandlingFailed
            | ConnectorError::WebhookResponseEncodingFailed
            | ConnectorError::ProcessingStepFailed(_)
            | ConnectorError::UnexpectedResponseError(_)
            | ConnectorError::RoutingRulesParsingError
            | ConnectorError::FailedAtConnector { .. }
            | ConnectorError::AmountConversionFailed
            | ConnectorError::GenericError { .. } => {
                ApplicationErrorResponse::InternalServerError(domain_types::errors::ApiError {
                    sub_code: "INTERNAL_SERVER_ERROR".to_string(),
                    error_identifier: 500,
                    error_message: self.to_string(),
                    error_object: None,
                })
            }
            ConnectorError::InvalidConnectorName
            | ConnectorError::InvalidWallet
            | ConnectorError::MissingRequiredField { .. }
            | ConnectorError::MissingRequiredFields { .. }
            | ConnectorError::InvalidDateFormat
            | ConnectorError::DateFormattingFailed
            | ConnectorError::InvalidDataFormat { .. }
            | ConnectorError::MismatchedPaymentData
            | ConnectorError::InvalidWalletToken { .. }
            | ConnectorError::FileValidationFailed { .. }
            | ConnectorError::MissingConnectorRedirectionPayload { .. }
            | ConnectorError::MissingPaymentMethodType
            | ConnectorError::CurrencyNotSupported { .. }
            | ConnectorError::InvalidConnectorConfig { .. } => {
                ApplicationErrorResponse::BadRequest(domain_types::errors::ApiError {
                    sub_code: "BAD_REQUEST".to_string(),
                    error_identifier: 400,
                    error_message: self.to_string(),
                    error_object: None,
                })
            }
            ConnectorError::NoConnectorMetaData
            | ConnectorError::MissingConnectorMandateID
            | ConnectorError::MissingConnectorTransactionID
            | ConnectorError::MissingConnectorRefundID
            | ConnectorError::MissingConnectorRelatedTransactionID { .. }
            | ConnectorError::InSufficientBalanceInPaymentMethod => {
                ApplicationErrorResponse::Unprocessable(domain_types::errors::ApiError {
                    sub_code: "UNPROCESSABLE_ENTITY".to_string(),
                    error_identifier: 422,
                    error_message: self.to_string(),
                    error_object: None,
                })
            }
            ConnectorError::NotImplemented(_)
            | ConnectorError::NotSupported { .. }
            | ConnectorError::FlowNotSupported { .. }
            | ConnectorError::CaptureMethodNotSupported
            | ConnectorError::WebhooksNotImplemented => {
                ApplicationErrorResponse::NotImplemented(domain_types::errors::ApiError {
                    sub_code: "NOT_IMPLEMENTED".to_string(),
                    error_identifier: 501,
                    error_message: self.to_string(),
                    error_object: None,
                })
            }
            ConnectorError::MissingApplePayTokenData
            | ConnectorError::WebhookBodyDecodingFailed
            | ConnectorError::WebhookSignatureNotFound
            | ConnectorError::WebhookSourceVerificationFailed
            | ConnectorError::WebhookVerificationSecretNotFound
            | ConnectorError::WebhookVerificationSecretInvalid
            | ConnectorError::WebhookReferenceIdNotFound
            | ConnectorError::WebhookEventTypeNotFound
            | ConnectorError::WebhookResourceObjectNotFound => {
                ApplicationErrorResponse::BadRequest(domain_types::errors::ApiError {
                    sub_code: "INVALID_WEBHOOK_DATA".to_string(),
                    error_identifier: 400,
                    error_message: self.to_string(),
                    error_object: None,
                })
            }
            ConnectorError::RequestTimeoutReceived => {
                ApplicationErrorResponse::InternalServerError(domain_types::errors::ApiError {
                    sub_code: "REQUEST_TIMEOUT".to_string(),
                    error_identifier: 504,
                    error_message: self.to_string(),
                    error_object: None,
                })
            }
        }
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
