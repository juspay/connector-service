/// Shared error type for interface-level operations (header parsing, metadata extraction).
/// Each transport layer can convert this into its own error type.
#[derive(Debug, thiserror::Error)]
pub enum InterfaceError {
    #[error("Missing required header: {key}")]
    MissingRequiredHeader { key: String },
    #[error("Invalid header value for '{key}': {reason}")]
    InvalidHeaderValue { key: String, reason: String },
}

impl From<InterfaceError> for tonic::Status {
    fn from(err: InterfaceError) -> Self {
        Self::invalid_argument(err.to_string())
    }
}

impl ucs_env::error::ErrorSwitch<grpc_api_types::payments::IntegrationError> for InterfaceError {
    fn switch(&self) -> grpc_api_types::payments::IntegrationError {
        match self {
            Self::MissingRequiredHeader { key } => grpc_api_types::payments::IntegrationError {
                error_message: format!("Missing required header: {key}"),
                error_code: "MISSING_REQUIRED_HEADER".to_string(),
                suggested_action: None,
                doc_url: None,
            },
            Self::InvalidHeaderValue { key, reason } => {
                grpc_api_types::payments::IntegrationError {
                    error_message: format!("{key}: {reason}"),
                    error_code: "INVALID_HEADER_VALUE".to_string(),
                    suggested_action: None,
                    doc_url: None,
                }
            }
        }
    }
}
