use common_utils::metadata::MaskedMetadata;
use domain_types::{connector_types::ConnectorEnum, router_data::ConnectorAuthType};
use std::collections::HashMap;
#[derive(Clone, Debug, serde::Deserialize)]
pub struct FFIMetadataPayload {
    pub connector: ConnectorEnum,
    pub connector_auth_type: ConnectorAuthType,
}

#[derive(Debug, serde::Deserialize)]
pub struct FFIRequestData<T> {
    pub payload: T,
    pub extracted_metadata: FFIMetadataPayload,
    #[serde(skip_deserializing, default)]
    pub masked_metadata: MaskedMetadata, // all metadata with masking config
}

/// Intermediate structure for deserializing Node.js API response
#[derive(Debug, serde::Deserialize)]
pub struct FFIApiResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}
