//! SDK-layer errors for FFI boundaries.
//!
//! Centralizes error codes and messages used when the FFI layer fails before
//! or after calling connector transformers (decode failures, empty options, etc.).

use common_utils::errors::ErrorSwitch;
use grpc_api_types::payments::{
    ConnectorResponseTransformationError, IntegrationError,
};

#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("Body encoding failed: {0}")]
    BodyEncodingFailed(String),

    #[error("{0}")]
    DecodeFailed(String),

    #[error("Invalid HTTP status code: {0}")]
    InvalidStatusCode(String),

    #[error("Empty options payload")]
    EmptyPayload,

    #[error("Missing connector_config")]
    MissingConnectorConfig,

    #[error("Connector config type unspecified")]
    UnspecifiedConnectorConfig,

    #[error("Request not produced by handler")]
    RequestNotProduced,

    #[error("Payload validation failed: {0}")]
    PayloadValidationFailed(String),

    #[error("Missing required field: {0}")]
    MissingRequiredField(String),

    #[error("Conversion failed: {0}")]
    ConversionFailed(String),

    #[error("Webhook processing failed: {0}")]
    WebhookProcessingFailed(String),
}

impl ErrorSwitch<IntegrationError> for SdkError {
    fn switch(&self) -> IntegrationError {
        let (error_code, error_message) = self.to_code_and_message();
        IntegrationError {
            error_message,
            error_code,
            suggested_action: None,
            doc_url: None,
        }
    }
}

impl ErrorSwitch<ConnectorResponseTransformationError> for SdkError {
    fn switch(&self) -> ConnectorResponseTransformationError {
        let (error_code, error_message) = self.to_code_and_message();
        ConnectorResponseTransformationError {
            error_message,
            error_code,
            http_status_code: None,
        }
    }
}

impl SdkError {
    fn to_code_and_message(&self) -> (String, String) {
        match self {
            Self::BodyEncodingFailed(msg) => ("BODY_ENCODING_FAILED".to_string(), msg.clone()),
            Self::DecodeFailed(msg) => ("DECODE_FAILED".to_string(), msg.clone()),
            Self::InvalidStatusCode(msg) => ("INVALID_STATUS_CODE".to_string(), msg.clone()),
            Self::EmptyPayload => ("EMPTY_PAYLOAD".to_string(), "Empty options payload".to_string()),
            Self::MissingConnectorConfig => {
                ("MISSING_CONNECTOR_CONFIG".to_string(), "Missing connector_config".to_string())
            }
            Self::UnspecifiedConnectorConfig => (
                "UNSPECIFIED_CONNECTOR_CONFIG".to_string(),
                "Connector config type unspecified".to_string(),
            ),
            Self::RequestNotProduced => (
                "REQUEST_NOT_PRODUCED".to_string(),
                "Request not produced by handler".to_string(),
            ),
            Self::PayloadValidationFailed(msg) => {
                ("PAYLOAD_VALIDATION_FAILED".to_string(), msg.clone())
            }
            Self::MissingRequiredField(field) => {
                ("MISSING_REQUIRED_FIELD".to_string(), format!("Missing required field: {field}"))
            }
            Self::ConversionFailed(msg) => ("CONVERSION_FAILED".to_string(), msg.clone()),
            Self::WebhookProcessingFailed(msg) => (
                "WEBHOOK_PROCESSING_FAILED".to_string(),
                format!("Webhook processing failed: {msg}"),
            ),
        }
    }
}
