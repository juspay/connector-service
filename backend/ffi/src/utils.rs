use common_utils::metadata::{HeaderMaskingConfig, MaskedMetadata};
use domain_types::errors::ConnectorRequestError;
use grpc_api_types::payments::IntegrationError;
use std::collections::HashMap;
use std::sync::Arc;
use ucs_env::configs::Config;
use ucs_env::error::ErrorSwitch;

/// Converts FFI headers (HashMap) to gRPC metadata with masking support.
/// Delegates to the shared `headers_to_masked_metadata` implementation.
pub fn ffi_headers_to_masked_metadata(
    headers: &HashMap<String, String>,
) -> Result<MaskedMetadata, IntegrationError> {
    ucs_interface_common::headers::headers_to_masked_metadata(
        headers,
        HeaderMaskingConfig::default(),
    )
    .map_err(|e| ErrorSwitch::switch(&e))
}

/// Load development config from the embedded config string.
/// This avoids runtime path lookup by embedding the config at build time.
pub fn load_config(embedded_config: &str) -> Result<Arc<Config>, ConnectorRequestError> {
    toml::from_str(embedded_config)
        .map(Arc::new)
        .map_err(|e| ConnectorRequestError::NotImplemented(e.to_string()))
}
