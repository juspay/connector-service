use domain_types::errors::{
    ApiClientError, ConnectorFlowError, ConnectorRequestError, ConnectorResponseError,
    WebhookError,
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

impl IntoGrpcStatus for error_stack::Report<ConnectorRequestError> {
    fn into_grpc_status(self) -> Status {
        logger::error!(error=?self);
        match self.current_context() {
            ConnectorRequestError::MissingRequiredField { .. }
            | ConnectorRequestError::MissingRequiredFields { .. }
            | ConnectorRequestError::InvalidDataFormat { .. }
            | ConnectorRequestError::InvalidWallet
            | ConnectorRequestError::MissingPaymentMethodType
            | ConnectorRequestError::MismatchedPaymentData
            | ConnectorRequestError::MandatePaymentDataMismatch { .. }
            | ConnectorRequestError::MissingApplePayTokenData
            | ConnectorRequestError::MissingConnectorTransactionID
            | ConnectorRequestError::MissingConnectorRefundID
            | ConnectorRequestError::MissingConnectorMandateID
            | ConnectorRequestError::MissingConnectorMandateMetadata
            | ConnectorRequestError::MissingConnectorRelatedTransactionID { .. } => {
                Status::invalid_argument(self.to_string())
            }
            ConnectorRequestError::NotSupported { .. }
            | ConnectorRequestError::FlowNotSupported { .. }
            | ConnectorRequestError::NotImplemented(_)
            | ConnectorRequestError::CaptureMethodNotSupported => {
                Status::unimplemented(self.to_string())
            }
            ConnectorRequestError::CurrencyNotSupported { .. }
            | ConnectorRequestError::InvalidConnectorConfig { .. } => {
                Status::failed_precondition(self.to_string())
            }
            _ => Status::internal(self.to_string()),
        }
    }
}

impl IntoGrpcStatus for error_stack::Report<ConnectorResponseError> {
    fn into_grpc_status(self) -> Status {
        logger::error!(error=?self);
        Status::internal(self.to_string())
    }
}

impl IntoGrpcStatus for error_stack::Report<ApiClientError> {
    fn into_grpc_status(self) -> Status {
        logger::error!(error=?self);
        match self.current_context() {
            ApiClientError::RequestTimeoutReceived | ApiClientError::GatewayTimeoutReceived => {
                Status::deadline_exceeded(self.to_string())
            }
            _ => Status::unavailable(self.to_string()),
        }
    }
}

impl IntoGrpcStatus for error_stack::Report<WebhookError> {
    fn into_grpc_status(self) -> Status {
        logger::error!(error=?self);
        match self.current_context() {
            WebhookError::WebhookSourceVerificationFailed
            | WebhookError::WebhookSignatureNotFound
            | WebhookError::WebhookVerificationSecretNotFound
            | WebhookError::WebhookVerificationSecretInvalid => Status::unauthenticated(self.to_string()),
            WebhookError::WebhookBodyDecodingFailed
            | WebhookError::WebhookReferenceIdNotFound
            | WebhookError::WebhookEventTypeNotFound
            | WebhookError::WebhookResourceObjectNotFound => Status::invalid_argument(self.to_string()),
            WebhookError::WebhooksNotImplemented => Status::unimplemented(self.to_string()),
            _ => Status::internal(self.to_string()),
        }
    }
}

impl IntoGrpcStatus for error_stack::Report<ConnectorFlowError> {
    fn into_grpc_status(self) -> Status {
        match self.current_context().clone() {
            ConnectorFlowError::Request(e) => self.change_context(e).into_grpc_status(),
            ConnectorFlowError::Client(e) => self.change_context(e).into_grpc_status(),
            ConnectorFlowError::Response(e) => self.change_context(e).into_grpc_status(),
        }
    }
}

fn connector_request_error_details(e: &ConnectorRequestError) -> (u16, &'static str, String) {
    let msg = e.to_string();
    match e {
        ConnectorRequestError::FailedToObtainIntegrationUrl
        | ConnectorRequestError::FailedToObtainAuthType
        | ConnectorRequestError::RequestEncodingFailed
        | ConnectorRequestError::HeaderMapConstructionFailed
        | ConnectorRequestError::BodySerializationFailed
        | ConnectorRequestError::UrlParsingFailed
        | ConnectorRequestError::UrlEncodingFailed
        | ConnectorRequestError::AmountConversionFailed
        | ConnectorRequestError::MandatePaymentDataMismatch { .. } => (500, "INTERNAL_SERVER_ERROR", msg),
        ConnectorRequestError::InvalidConnectorConfig { .. }
        | ConnectorRequestError::InvalidWallet
        | ConnectorRequestError::InvalidWalletToken { .. }
        | ConnectorRequestError::MissingRequiredField { .. }
        | ConnectorRequestError::MissingRequiredFields { .. }
        | ConnectorRequestError::InvalidDataFormat { .. }
        | ConnectorRequestError::MismatchedPaymentData
        | ConnectorRequestError::MissingPaymentMethodType
        | ConnectorRequestError::NotSupported { .. }
        | ConnectorRequestError::FlowNotSupported { .. }
        | ConnectorRequestError::SourceVerificationFailed
        | ConnectorRequestError::MissingApplePayTokenData
        | ConnectorRequestError::CurrencyNotSupported { .. } => (400, "BAD_REQUEST", msg),
        ConnectorRequestError::NoConnectorMetaData
        | ConnectorRequestError::MaxFieldLengthViolated { .. }
        | ConnectorRequestError::MissingConnectorMandateID
        | ConnectorRequestError::MissingConnectorTransactionID
        | ConnectorRequestError::MissingConnectorRefundID
        | ConnectorRequestError::MissingConnectorRelatedTransactionID { .. }
        | ConnectorRequestError::MissingConnectorMandateMetadata => (422, "UNPROCESSABLE_ENTITY", msg),
        ConnectorRequestError::NotImplemented(_) | ConnectorRequestError::CaptureMethodNotSupported => {
            (501, "NOT_IMPLEMENTED", msg)
        }
        ConnectorRequestError::ConfigurationError { code, message } => (400, *code, message.clone()),
    }
}

impl ErrorSwitch<grpc_api_types::payments::IntegrationError> for ConnectorRequestError {
    fn switch(&self) -> grpc_api_types::payments::IntegrationError {
        let (_, error_code, error_message) = connector_request_error_details(self);
        grpc_api_types::payments::IntegrationError {
            error_message,
            error_code: error_code.to_string(),
            suggested_action: None,
            doc_url: None,
        }
    }
}

impl ErrorSwitch<grpc_api_types::payments::ConnectorResponseTransformationError> for ConnectorRequestError {
    fn switch(&self) -> grpc_api_types::payments::ConnectorResponseTransformationError {
        let (status_code, error_code, error_message) = connector_request_error_details(self);
        grpc_api_types::payments::ConnectorResponseTransformationError {
            error_message,
            error_code: error_code.to_string(),
            http_status_code: Some(status_code.into()),
        }
    }
}

fn connector_response_error_details(e: &ConnectorResponseError) -> (u16, &'static str, String) {
    let msg = e.to_string();
    match e {
        ConnectorResponseError::ResponseDeserializationFailed
        | ConnectorResponseError::ResponseHandlingFailed
        | ConnectorResponseError::UnexpectedResponseError
        | ConnectorResponseError::InternalServerErrorReceived
        | ConnectorResponseError::BadGatewayReceived
        | ConnectorResponseError::ServiceUnavailableReceived
        | ConnectorResponseError::GatewayTimeoutReceived
        | ConnectorResponseError::FailedAtConnector { .. } => (500, "INTERNAL_SERVER_ERROR", msg),
        ConnectorResponseError::MissingRequiredField { .. } => (400, "BAD_REQUEST", msg),
        ConnectorResponseError::MissingConnectorTransactionID | ConnectorResponseError::MissingConnectorRefundID => {
            (422, "UNPROCESSABLE_ENTITY", msg)
        }
    }
}

impl ErrorSwitch<grpc_api_types::payments::IntegrationError> for ConnectorResponseError {
    fn switch(&self) -> grpc_api_types::payments::IntegrationError {
        let (_, error_code, error_message) = connector_response_error_details(self);
        grpc_api_types::payments::IntegrationError {
            error_message,
            error_code: error_code.to_string(),
            suggested_action: None,
            doc_url: None,
        }
    }
}

impl ErrorSwitch<grpc_api_types::payments::ConnectorResponseTransformationError> for ConnectorResponseError {
    fn switch(&self) -> grpc_api_types::payments::ConnectorResponseTransformationError {
        let (status_code, error_code, error_message) = connector_response_error_details(self);
        grpc_api_types::payments::ConnectorResponseTransformationError {
            error_message,
            error_code: error_code.to_string(),
            http_status_code: Some(status_code.into()),
        }
    }
}

fn api_client_error_details(e: &ApiClientError) -> (u16, &'static str, String) {
    let msg = e.to_string();
    match e {
        ApiClientError::RequestTimeoutReceived | ApiClientError::GatewayTimeoutReceived => {
            (504, "REQUEST_TIMEOUT", msg)
        }
        _ => (500, "INTERNAL_SERVER_ERROR", msg),
    }
}

impl ErrorSwitch<grpc_api_types::payments::IntegrationError> for ApiClientError {
    fn switch(&self) -> grpc_api_types::payments::IntegrationError {
        let (_, error_code, error_message) = api_client_error_details(self);
        grpc_api_types::payments::IntegrationError {
            error_message,
            error_code: error_code.to_string(),
            suggested_action: None,
            doc_url: None,
        }
    }
}

impl ErrorSwitch<grpc_api_types::payments::ConnectorResponseTransformationError> for ApiClientError {
    fn switch(&self) -> grpc_api_types::payments::ConnectorResponseTransformationError {
        let (status_code, error_code, error_message) = api_client_error_details(self);
        grpc_api_types::payments::ConnectorResponseTransformationError {
            error_message,
            error_code: error_code.to_string(),
            http_status_code: Some(status_code.into()),
        }
    }
}

impl ErrorSwitch<grpc_api_types::payments::IntegrationError> for ConnectorFlowError {
    fn switch(&self) -> grpc_api_types::payments::IntegrationError {
        match self {
            Self::Request(e) => e.switch(),
            Self::Client(e) => e.switch(),
            Self::Response(e) => e.switch(),
        }
    }
}

impl ErrorSwitch<grpc_api_types::payments::ConnectorResponseTransformationError> for ConnectorFlowError {
    fn switch(&self) -> grpc_api_types::payments::ConnectorResponseTransformationError {
        match self {
            Self::Request(e) => e.switch(),
            Self::Client(e) => e.switch(),
            Self::Response(e) => e.switch(),
        }
    }
}

/// Extract (status_code, error_code, error_message) from a connector flow error for building ErrorResponse.
pub fn connector_flow_error_to_error_details(e: &ConnectorFlowError) -> (u16, String, String) {
    match e {
        ConnectorFlowError::Request(req) => {
            let (sc, code, msg) = connector_request_error_details(req);
            (sc, code.to_string(), msg)
        }
        ConnectorFlowError::Client(client) => {
            let (sc, code, msg) = api_client_error_details(client);
            (sc, code.to_string(), msg)
        }
        ConnectorFlowError::Response(resp) => {
            let (sc, code, msg) = connector_response_error_details(resp);
            (sc, code.to_string(), msg)
        }
    }
}

/// Map a request-phase connector error report to `IntegrationError`.
pub fn connector_request_error_report_to_integration(
    report: error_stack::Report<ConnectorRequestError>,
) -> grpc_api_types::payments::IntegrationError {
    report.current_context().switch()
}

/// Map a request-phase connector error report to `ConnectorResponseTransformationError`.
pub fn connector_request_error_report_to_response_transformation(
    report: error_stack::Report<ConnectorRequestError>,
) -> grpc_api_types::payments::ConnectorResponseTransformationError {
    report.current_context().switch()
}

/// Map a connector response error report to `ConnectorResponseTransformationError`.
pub fn connector_response_error_report_to_response_transformation(
    report: error_stack::Report<ConnectorResponseError>,
) -> grpc_api_types::payments::ConnectorResponseTransformationError {
    report.current_context().switch()
}

/// Map a report (ConnectorRequestError or ConnectorResponseError) into `ConnectorResponseTransformationError`.
pub fn report_connector_context_to_response_transformation<E>(
    report: error_stack::Report<E>,
) -> grpc_api_types::payments::ConnectorResponseTransformationError
where
    E: ErrorSwitch<grpc_api_types::payments::ConnectorResponseTransformationError> + error_stack::Context,
{
    report.current_context().switch()
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

