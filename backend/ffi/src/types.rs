use common_utils::metadata::MaskedMetadata;
use domain_types::{connector_types::ConnectorEnum, router_data::ConnectorAuthType};
#[derive(Clone, Debug, serde::Deserialize)]
pub struct MetadataPayload {
    pub connector: ConnectorEnum,
    pub connector_auth_type: ConnectorAuthType,
}

#[derive(Debug, serde::Deserialize)]
pub struct RequestData<T> {
    pub payload: T,
    pub extracted_metadata: MetadataPayload,

    #[serde(skip_deserializing, default)]
    pub masked_metadata: MaskedMetadata, // all metadata with masking config
}
