use common_utils::metadata::MaskedMetadata;
use domain_types::{connector_types::ConnectorEnum, router_data::ConnectorSpecificAuth};
#[derive(Clone, Debug, serde::Deserialize)]
pub struct FfiMetadataPayload {
    pub connector: ConnectorEnum,
    pub connector_auth_type: ConnectorSpecificAuth,
}

#[derive(Debug, serde::Deserialize)]
pub struct FfiRequestData<T> {
    pub payload: T,
    pub extracted_metadata: FfiMetadataPayload,
    #[serde(skip_deserializing)] // MaskedMetadata is not deserialized; populated at runtime
    pub masked_metadata: Option<MaskedMetadata>, // None when not provided
}
