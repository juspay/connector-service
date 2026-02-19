use common_crate::{configs::Config, error::PaymentAuthorizationError};
use common_utils::consts;
use common_utils::metadata::{HeaderMaskingConfig, MaskedMetadata};
use std::collections::HashMap;
use std::sync::Arc;
use tonic::metadata::{Ascii, MetadataMap, MetadataValue};

/// Converts FFI headers (HashMap) to gRPC metadata with masking support
/// Similar to http_headers_to_grpc_metadata but for FFI input
pub fn ffi_headers_to_masked_metadata(headers: &HashMap<String, String>) -> MaskedMetadata {
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

    // Process required headers - fail if missing
    for header_name in required_headers {
        let header_name: &str = header_name;
        if let Some(header_value) = headers.get(header_name) {
            if let Ok(metadata_value) = convert_to_metadata_value(header_value) {
                metadata.insert(header_name, metadata_value);
            }
        }
    }

    // Process optional headers - skip if missing
    for header_name in optional_headers {
        let header_name: &str = header_name;
        if let Some(header_value) = headers.get(header_name) {
            if let Ok(metadata_value) = convert_to_metadata_value(header_value) {
                metadata.insert(header_name, metadata_value);
            }
        }
    }

    MaskedMetadata::new(metadata, HeaderMaskingConfig::default())
}

fn convert_to_metadata_value(header_value: &str) -> Result<MetadataValue<Ascii>, String> {
    MetadataValue::try_from(header_value)
        .map_err(|e| format!("Cannot convert header value to metadata: {e}"))
}

/// Load development config from the embedded config string
/// This avoids runtime path lookup by embedding the config at build time
pub fn load_config(embedded_config: &str) -> Result<Arc<Config>, PaymentAuthorizationError> {
    toml::from_str(embedded_config).map(Arc::new).map_err(|e| {
        PaymentAuthorizationError::new(
            grpc_api_types::payments::PaymentStatus::Pending,
            Some(e.to_string()),
            Some("CONFIG_PARSE_ERROR".to_string()),
            None,
        )
    })
}
