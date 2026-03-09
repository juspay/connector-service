/// Unified error type for FFI utility and UniFFI-boundary operations.
#[cfg_attr(feature = "uniffi", derive(Clone, uniffi::Error))]
#[derive(Debug, thiserror::Error)]
pub enum FfiError {
    // --- Utility-layer errors (header parsing, metadata building) ---
    #[error("Missing required header: {key}")]
    MissingRequiredHeader { key: String },
    #[error("Invalid header value for '{key}': {reason}")]
    InvalidHeaderValue { key: String, reason: String },
    #[error("Failed to parse config: {message}")]
    ConfigError { message: String },

    // --- UniFFI-boundary errors ---
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

    // --- Shared ---
    #[error("Integration error: {message}")]
    IntegrationError { message: String },

    // --- Connector/Application Errors ---
    #[error("{error_message}")]
    ConnectorFailure {
        error_code: Option<String>,
        error_message: String,
        status_code: u32,
    },
}

// =============================================================================
// Conversions: FfiError → gRPC error types
// =============================================================================

impl From<FfiError> for grpc_api_types::payments::FfiRequestError {
    fn from(e: FfiError) -> Self {
        match &e {
            FfiError::ConnectorFailure { error_code, error_message, status_code } => {
                grpc_api_types::payments::FfiRequestError {
                    status: grpc_api_types::payments::PaymentStatus::Failure.into(),
                    error_message: Some(error_message.clone()),
                    error_code: error_code.clone(),
                    status_code: Some(*status_code),
                }
            }
            _ => grpc_api_types::payments::FfiRequestError {
                status: grpc_api_types::payments::PaymentStatus::Pending.into(),
                error_message: Some(e.to_string()),
                error_code: None,
                status_code: Some(500),
            },
        }
    }
}

impl From<FfiError> for grpc_api_types::payments::FfiResponseError {
    fn from(e: FfiError) -> Self {
        match &e {
            FfiError::ConnectorFailure { error_code, error_message, status_code } => {
                grpc_api_types::payments::FfiResponseError {
                    status: grpc_api_types::payments::PaymentStatus::Failure.into(),
                    error_message: Some(error_message.clone()),
                    error_code: error_code.clone(),
                    status_code: Some(*status_code),
                }
            }
            _ => grpc_api_types::payments::FfiResponseError {
                status: grpc_api_types::payments::PaymentStatus::Pending.into(),
                error_message: Some(e.to_string()),
                error_code: None,
                status_code: Some(500),
            },
        }
    }
}

// =============================================================================
// Conversions: ConnectorError → FfiError (local type, allowed by orphan rules)
// =============================================================================

impl From<domain_types::errors::ConnectorError> for FfiError {
    fn from(e: domain_types::errors::ConnectorError) -> Self {
        FfiError::ConnectorFailure {
            error_code: None,
            error_message: e.to_string(),
            status_code: 500,
        }
    }
}

impl From<&domain_types::errors::ConnectorError> for FfiError {
    fn from(e: &domain_types::errors::ConnectorError) -> Self {
        FfiError::ConnectorFailure {
            error_code: None,
            error_message: e.to_string(),
            status_code: 500,
        }
    }
}

// =============================================================================
// Conversions: ApplicationErrorResponse → FfiError (local type, allowed by orphan rules)
// =============================================================================

impl From<domain_types::errors::ApplicationErrorResponse> for FfiError {
    fn from(e: domain_types::errors::ApplicationErrorResponse) -> Self {
        let api_error = e.get_api_error();
        FfiError::ConnectorFailure {
            error_code: Some(format!("{}_{}", api_error.sub_code, api_error.error_identifier)),
            error_message: api_error.error_message.clone(),
            status_code: api_error.error_identifier as u32,
        }
    }
}

impl From<&domain_types::errors::ApplicationErrorResponse> for FfiError {
    fn from(e: &domain_types::errors::ApplicationErrorResponse) -> Self {
        let api_error = e.get_api_error();
        FfiError::ConnectorFailure {
            error_code: Some(format!("{}_{}", api_error.sub_code, api_error.error_identifier)),
            error_message: api_error.error_message.clone(),
            status_code: api_error.error_identifier as u32,
        }
    }
}