use common_utils::consts;
use common_utils::metadata::{HeaderMaskingConfig, MaskedMetadata};
use std::collections::HashMap;
use tonic::metadata::{Ascii, MetadataMap, MetadataValue};

use crate::error::InterfaceError;

/// Abstraction over different header container types.
/// Allows unified header-to-metadata conversion for FFI (`HashMap`),
/// HTTP (`http::HeaderMap`), and any future transport.
pub trait HeaderSource {
    fn get_header(&self, key: &str) -> Option<&str>;
}

impl HeaderSource for HashMap<String, String> {
    fn get_header(&self, key: &str) -> Option<&str> {
        self.get(key).map(|s| s.as_str())
    }
}

impl HeaderSource for http::HeaderMap {
    fn get_header(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(|v| v.to_str().ok())
    }
}

/// Required headers that must be present in every request.
const REQUIRED_HEADERS: &[&str] = &[
    consts::X_CONNECTOR_NAME,
    consts::X_MERCHANT_ID,
    consts::X_REQUEST_ID,
    consts::X_TENANT_ID,
    consts::X_AUTH,
];

/// Optional headers that may or may not be present.
const OPTIONAL_HEADERS: &[&str] = &[
    consts::X_REFERENCE_ID,
    consts::X_API_KEY,
    consts::X_API_SECRET,
    consts::X_KEY1,
    consts::X_KEY2,
    consts::X_AUTH_KEY_MAP,
    consts::X_SHADOW_MODE,
    consts::X_CONNECTOR_AUTH,
    consts::X_RESOURCE_ID,
];

fn to_metadata_value(key: &str, value: &str) -> Result<MetadataValue<Ascii>, InterfaceError> {
    MetadataValue::try_from(value).map_err(|e| InterfaceError::InvalidHeaderValue {
        key: key.to_string(),
        reason: e.to_string(),
    })
}

/// Converts headers from any `HeaderSource` into a gRPC `MetadataMap`.
/// Validates that all required headers are present.
pub fn headers_to_metadata<H: HeaderSource>(
    headers: &H,
) -> Result<MetadataMap, InterfaceError> {
    let mut metadata = MetadataMap::new();

    for header_name in REQUIRED_HEADERS {
        let value = headers.get_header(header_name).ok_or_else(|| {
            InterfaceError::MissingRequiredHeader {
                key: header_name.to_string(),
            }
        })?;
        let metadata_value = to_metadata_value(header_name, value)?;
        metadata.insert(*header_name, metadata_value);
    }

    for header_name in OPTIONAL_HEADERS {
        if let Some(value) = headers.get_header(header_name) {
            if let Ok(metadata_value) = to_metadata_value(header_name, value) {
                metadata.insert(*header_name, metadata_value);
            }
        }
    }

    Ok(metadata)
}

/// Converts headers from any `HeaderSource` into a `MaskedMetadata`,
/// which wraps a `MetadataMap` with masking configuration for sensitive values.
pub fn headers_to_masked_metadata<H: HeaderSource>(
    headers: &H,
    masking_config: HeaderMaskingConfig,
) -> Result<MaskedMetadata, InterfaceError> {
    let metadata = headers_to_metadata(headers)?;
    Ok(MaskedMetadata::new(metadata, masking_config))
}
