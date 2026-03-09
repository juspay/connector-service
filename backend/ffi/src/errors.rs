// /// Unified error type for FFI utility and UniFFI-boundary operations.
// #[cfg_attr(feature = "uniffi", derive(Clone, uniffi::Error))]
// #[derive(Debug, thiserror::Error)]
// pub enum FfiError {
//     // --- Utility-layer errors (header parsing, metadata building) ---
//     #[error("Missing required header: {key}")]
//     MissingRequiredHeader { key: String },
//     #[error("Invalid header value for '{key}': {reason}")]
//     InvalidHeaderValue { key: String, reason: String },
//     #[error("Failed to parse config: {message}")]
//     ConfigError { message: String },

//     // --- UniFFI-boundary errors ---
//     #[error("Failed to decode protobuf request: {msg}")]
//     DecodeError { msg: String },
//     #[error("Missing metadata key: {key}")]
//     MissingMetadata { key: String },
//     #[error("Failed to parse metadata: {msg}")]
//     MetadataParseError { msg: String },
//     #[error("Handler error: {msg}")]
//     HandlerError { msg: String },
//     #[error("No connector request generated")]
//     NoConnectorRequest,

//     // --- Shared ---
//     #[error("Integration error: {message}")]
//     IntegrationError { message: String },
// }

// // =============================================================================
// // Conversions: FfiError → gRPC error types
// // =============================================================================

// impl From<FfiError> for grpc_api_types::payments::FfiRequestError {
//     fn from(e: FfiError) -> Self {
//         grpc_api_types::payments::FfiRequestError {
//             status: grpc_api_types::payments::PaymentStatus::Pending.into(),
//             error_message: Some(e.to_string()),
//             error_code: None,
//             status_code: Some(500),
//         }
//     }
// }

// impl From<FfiError> for grpc_api_types::payments::FfiResponseError {
//     fn from(e: FfiError) -> Self {
//         grpc_api_types::payments::FfiResponseError {
//             status: grpc_api_types::payments::PaymentStatus::Pending.into(),
//             error_message: Some(e.to_string()),
//             error_code: None,
//             status_code: Some(500),
//         }
//     }
// }