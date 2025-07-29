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
        match self {
            Self::FailedToObtainIntegrationUrl
            | Self::FailedToObtainPreferredConnector
            | Self::FailedToObtainAuthType
            | Self::FailedToObtainCertificate
            | Self::FailedToObtainCertificateKey
            | Self::RequestEncodingFailed
            | Self::RequestEncodingFailedWithReason(_)
            | Self::ParsingFailed
            | Self::ResponseDeserializationFailed
            | Self::ResponseHandlingFailed
            | Self::WebhookResponseEncodingFailed
            | Self::ProcessingStepFailed(_)
            | Self::UnexpectedResponseError(_)
            | Self::RoutingRulesParsingError
            | Self::FailedAtConnector { .. }
            | Self::AmountConversionFailed
            | Self::GenericError { .. } => {
                ApplicationErrorResponse::InternalServerError(ApiError {
                    sub_code: "INTERNAL_SERVER_ERROR".to_string(),
                    error_identifier: 500,
                    error_message: self.to_string(),
                    error_object: None,
                })
            }
            Self::InvalidConnectorName
            | Self::InvalidWallet
            | Self::MissingRequiredField { .. }
            | Self::MissingRequiredFields { .. }
            | Self::InvalidDateFormat
            | Self::NotSupported { .. }
            | Self::FlowNotSupported { .. }
            | Self::DateFormattingFailed
            | Self::InvalidDataFormat { .. }
            | Self::MismatchedPaymentData
            | Self::InvalidWalletToken { .. }
            | Self::FileValidationFailed { .. }
            | Self::MissingConnectorRedirectionPayload { .. }
            | Self::MissingPaymentMethodType
            | Self::CurrencyNotSupported { .. }
            | Self::NoConnectorWalletDetails
            | Self::MissingConnectorMandateMetadata
            | Self::IntegrityCheckFailed { .. }
            | Self::SourceVerificationFailed
            | Self::InvalidConnectorConfig { .. } => {
                ApplicationErrorResponse::BadRequest(ApiError {
                    sub_code: "BAD_REQUEST".to_string(),
                    error_identifier: 400,
                    error_message: self.to_string(),
                    error_object: None,
                })
            }
            Self::NoConnectorMetaData
            | Self::MissingConnectorMandateID
            | Self::MissingConnectorTransactionID
            | Self::MissingConnectorRefundID
            | Self::MissingConnectorRelatedTransactionID { .. }
            | Self::InSufficientBalanceInPaymentMethod => {
                ApplicationErrorResponse::Unprocessable(ApiError {
                    sub_code: "UNPROCESSABLE_ENTITY".to_string(),
                    error_identifier: 422,
                    error_message: self.to_string(),
                    error_object: None,
                })
            }
            Self::NotImplemented(_)
            | Self::CaptureMethodNotSupported
            | Self::WebhooksNotImplemented => ApplicationErrorResponse::NotImplemented(ApiError {
                sub_code: "NOT_IMPLEMENTED".to_string(),
                error_identifier: 501,
                error_message: self.to_string(),
                error_object: None,
            }),
            Self::MissingApplePayTokenData
            | Self::WebhookBodyDecodingFailed
            | Self::WebhookSourceVerificationFailed
            | Self::WebhookVerificationSecretInvalid => {
                ApplicationErrorResponse::BadRequest(ApiError {
                    sub_code: "INVALID_WEBHOOK_DATA".to_string(),
                    error_identifier: 400,
                    error_message: self.to_string(),
                    error_object: None,
                })
            }
            Self::RequestTimeoutReceived => {
                ApplicationErrorResponse::InternalServerError(ApiError {
                    sub_code: "REQUEST_TIMEOUT".to_string(),
                    error_identifier: 504,
                    error_message: self.to_string(),
                    error_object: None,
                })
            }
            Self::WebhookEventTypeNotFound
            | Self::WebhookSignatureNotFound
            | Self::WebhookReferenceIdNotFound
            | Self::WebhookResourceObjectNotFound
            | Self::WebhookVerificationSecretNotFound => {
                ApplicationErrorResponse::NotFound(ApiError {
                    sub_code: "WEBHOOK_DETAILS_NOT_FOUND".to_string(),
                    error_identifier: 404,
                    error_message: self.to_string(),
                    error_object: None,
                })
            }
        }
    }
}

impl ErrorSwitch<ApplicationErrorResponse> for ApiClientError {
    fn switch(&self) -> ApplicationErrorResponse {
        match self {
            Self::HeaderMapConstructionFailed
            | Self::InvalidProxyConfiguration
            | Self::ClientConstructionFailed
            | Self::CertificateDecodeFailed
            | Self::BodySerializationFailed
            | Self::UnexpectedState
            | Self::UrlEncodingFailed
            | Self::RequestNotSent(_)
            | Self::ResponseDecodingFailed
            | Self::InternalServerErrorReceived
            | Self::BadGatewayReceived
            | Self::ServiceUnavailableReceived
            | Self::UrlParsingFailed
            | Self::UnexpectedServerResponse => {
                ApplicationErrorResponse::InternalServerError(ApiError {
                    sub_code: "INTERNAL_SERVER_ERROR".to_string(),
                    error_identifier: 500,
                    error_message: self.to_string(),
                    error_object: None,
                })
            }
            Self::RequestTimeoutReceived | Self::GatewayTimeoutReceived => {
                ApplicationErrorResponse::InternalServerError(ApiError {
                    sub_code: "REQUEST_TIMEOUT".to_string(),
                    error_identifier: 504,
                    error_message: self.to_string(),
                    error_object: None,
                })
            }
            Self::ConnectionClosedIncompleteMessage => {
                ApplicationErrorResponse::InternalServerError(ApiError {
                    sub_code: "INTERNAL_SERVER_ERROR".to_string(),
                    error_identifier: 500,
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

#[derive(Debug, Clone)]
pub struct PaymentAuthorizationError {
    pub status: grpc_api_types::payments::PaymentStatus,
    pub error_message: Option<String>,
    pub error_code: Option<String>,
    pub raw_connector_response: Option<String>,
    pub status_code: Option<u32>,
}

impl PaymentAuthorizationError {
    pub fn new(
        status: grpc_api_types::payments::PaymentStatus,
        error_message: Option<String>,
        error_code: Option<String>,
        raw_connector_response: Option<String>,
        status_code: Option<u32>,
    ) -> Self {
        Self {
            status,
            error_message,
            error_code,
            raw_connector_response,
            status_code,
        }
    }
}

impl From<PaymentAuthorizationError> for PaymentServiceAuthorizeResponse {
    fn from(error: PaymentAuthorizationError) -> Self {
        Self {
            transaction_id: None,
            redirection_data: None,
            network_txn_id: None,
            response_ref_id: None,
            incremental_authorization_allowed: None,
            status: error.status.into(),
            error_message: error.error_message,
            error_code: error.error_code,
            raw_connector_response: error.raw_connector_response,
            status_code: error.status_code,
        }
    }
}
