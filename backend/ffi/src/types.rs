use common_utils::metadata::MaskedMetadata;
use domain_types::{connector_types::ConnectorEnum, router_data::ConnectorAuthType};
use std::collections::HashMap;
#[derive(Clone, Debug, serde::Deserialize)]
pub struct FfiMetadataPayload {
    pub connector: ConnectorEnum,
    pub connector_auth_type: ConnectorAuthType,
}

#[derive(Debug, serde::Deserialize)]
pub struct FfiRequestData<T> {
    pub payload: T,
    pub extracted_metadata: FfiMetadataPayload,
    #[serde(skip_deserializing)] // MaskedMetadata is not deserialized; populated at runtime
    pub masked_metadata: Option<MaskedMetadata>, // None when not provided
}

/// Intermediate structure for deserializing Node.js API response
#[derive(Debug, serde::Deserialize)]
pub struct FfiApiResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

/// Unified Request structure exported via UniFFI
#[derive(uniffi::Record, Debug)]
pub struct FfiConnectorHttpRequest {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}
