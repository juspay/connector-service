use common_utils::metadata::{HeaderMaskingConfig, MaskedMetadata};
use domain_types::errors::ConnectorError;
use grpc_api_types::payments::RequestError;
use std::collections::HashMap;
use std::sync::Arc;
use ucs_env::configs::Config;

/// Converts FFI headers (HashMap) to gRPC metadata with masking support.
/// Delegates to the shared `headers_to_masked_metadata` implementation.
pub fn ffi_headers_to_masked_metadata(
    headers: &HashMap<String, String>,
) -> Result<MaskedMetadata, RequestError> {
    ucs_interface_common::headers::headers_to_masked_metadata(
        headers,
        HeaderMaskingConfig::default(),
    )
    .map_err(|e| match e {
        ucs_interface_common::error::InterfaceError::MissingRequiredHeader { key } => {
            RequestError {
                status: grpc_api_types::payments::PaymentStatus::Pending.into(),
                error_message: Some(format!("Missing required header: {}", key)),
                error_code: None,
                status_code: Some(400),
            }
        }
        ucs_interface_common::error::InterfaceError::InvalidHeaderValue { key, reason } => {
            RequestError {
                status: grpc_api_types::payments::PaymentStatus::Pending.into(),
                error_message: Some(format!("{}: {}", key, reason)),
                error_code: None,
                status_code: Some(400),
            }
        }
    })
}

/// Load development config from the embedded config string.
/// This avoids runtime path lookup by embedding the config at build time.
pub fn load_config(embedded_config: &str) -> Result<Arc<Config>, ConnectorError> {
    toml::from_str(embedded_config)
        .map(Arc::new)
        .map_err(|e| ConnectorError::GenericError {
            error_message: e.to_string(),
            error_object: serde_json::Value::Null,
        })
}
