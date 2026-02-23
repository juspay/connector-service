use common_utils::consts;
use common_utils::metadata::{HeaderMaskingConfig, MaskedMetadata};
use std::collections::HashMap;
use std::sync::Arc;
use tonic::metadata::{Ascii, MetadataMap, MetadataValue};
use ucs_env::{configs::Config, error::PaymentAuthorizationError};

/// Errors arising from FFI utility operations (header parsing, metadata building).
#[derive(Debug, thiserror::Error)]
pub enum FfiError {
    #[error("Missing required header: {key}")]
    MissingRequiredHeader { key: String },
    #[error("Invalid header value for '{key}': {reason}")]
    InvalidHeaderValue { key: String, reason: String },
    #[error("Missing required field: {0}")]
    MissingField(String),
    #[error("Invalid field value: {0}")]
    InvalidField(String),
}

/// Converts FFI headers (HashMap) to gRPC metadata with masking support.
/// Returns an error if any required header is absent or contains an invalid value.
pub fn ffi_headers_to_masked_metadata(
    headers: &HashMap<String, String>,
) -> Result<MaskedMetadata, FfiError> {
    let mut metadata = MetadataMap::new();

    // Required headers - these must be present
    let required_headers = [
        consts::X_CONNECTOR_NAME,
        consts::X_MERCHANT_ID,
        consts::X_REQUEST_ID,
        consts::X_TENANT_ID,
        consts::X_AUTH,
    ];

    // Optional headers - these may or may not be present
    let optional_headers = [
        consts::X_REFERENCE_ID,
        consts::X_API_KEY,
        consts::X_API_SECRET,
        consts::X_KEY1,
        consts::X_KEY2,
        consts::X_AUTH_KEY_MAP,
        consts::X_SHADOW_MODE,
    ];

    // Process required headers - return error if missing
    for header_name in required_headers {
        let header_name: &str = header_name;
        let header_value =
            headers
                .get(header_name)
                .ok_or_else(|| FfiError::MissingRequiredHeader {
                    key: header_name.to_string(),
                })?;
        let metadata_value = convert_to_metadata_value(header_name, header_value)?;
        metadata.insert(header_name, metadata_value);
    }

    // Process optional headers - skip if missing
    for header_name in optional_headers {
        let header_name: &str = header_name;
        if let Some(header_value) = headers.get(header_name) {
            if let Ok(metadata_value) = convert_to_metadata_value(header_name, header_value) {
                metadata.insert(header_name, metadata_value);
            }
        }
    }

    Ok(MaskedMetadata::new(
        metadata,
        HeaderMaskingConfig::default(),
    ))
}

fn convert_to_metadata_value(key: &str, value: &str) -> Result<MetadataValue<Ascii>, FfiError> {
    MetadataValue::try_from(value).map_err(|e| FfiError::InvalidHeaderValue {
        key: key.to_string(),
        reason: e.to_string(),
    })
}

/// Load development config from the embedded config string.
/// This avoids runtime path lookup by embedding the config at build time.
pub fn load_config(embedded_config: &str) -> Result<Arc<Config>, PaymentAuthorizationError> {
    toml::from_str(embedded_config).map(Arc::new).map_err(|e| {
        PaymentAuthorizationError::new(
            grpc_api_types::payments::PaymentStatus::Failure,
            Some(e.to_string()),
            Some("CONFIG_PARSE_ERROR".to_string()),
            None,
        )
    })
}
