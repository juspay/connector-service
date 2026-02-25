/// Generic error type for FFI payment flows (authorize, capture, etc.)
/// Can be reused across all FFI payment operations.
#[derive(Debug, Clone)]

pub struct FfiPaymentError {
    pub status: grpc_api_types::payments::PaymentStatus,
    pub error_message: Option<String>,
    pub error_code: Option<String>,
    pub status_code: Option<u32>,
}

impl FfiPaymentError {
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

/// Errors arising from FFI utility operations (header parsing, metadata building).
#[derive(Debug, thiserror::Error)]
pub enum FfiError {
    #[error("Missing required header: {key}")]
    MissingRequiredHeader { key: String },
    #[error("Invalid header value for '{key}': {reason}")]
    InvalidHeaderValue { key: String, reason: String },
    #[error("Integration error: {message}")]
    IntegrationError { message: String },
    #[error("Failed to parse config: {message}")]
    ConfigError { message: String },
}

/// Error type exposed over the UniFFI boundary.
#[derive(Debug, Clone, thiserror::Error, uniffi::Error)]
pub enum UniffiError {
    #[error("Failed to decode protobuf request: {msg}")]
    DecodeError { msg: String },
    #[error("Missing metadata key: {key}")]
    MissingMetadata { key: String },
    #[error("Failed to parse metadata: {msg}")]
    MetadataParseError { msg: String },
    #[error("Handler error: {msg}")]
    HandlerError { msg: String },
    #[error("No connector request generated")]
    NoConnectorRequest,
    #[error("Response failure error: {error_message:?}")]
    ConnectorError {
        status: i32,
        error_message: Option<String>,
        error_code: Option<String>,
        status_code: u32,
    },
    #[error("Integration error: {message}")]
    IntegrationError { message: String },
}

impl From<FfiError> for FfiPaymentError {
    fn from(e: FfiError) -> Self {
        FfiPaymentError::new(
            grpc_api_types::payments::PaymentStatus::Pending,
            Some(e.to_string()),
            None,
            Some(500),
        )
    }
}

impl From<FfiError> for UniffiError {
    fn from(e: FfiError) -> Self {
        match e {
            FfiError::IntegrationError { message } => Self::IntegrationError { message },
            _ => Self::MetadataParseError { msg: e.to_string() },
        }
    }
}

impl From<FfiPaymentError> for UniffiError {
    fn from(e: FfiPaymentError) -> Self {
        UniffiError::ConnectorError {
            status: e.status.into(),
            error_message: e.error_message,
            error_code: e.error_code,
            status_code: e.status_code.unwrap_or(500),
        }
    }
}
