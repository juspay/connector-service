use std::sync::Arc;

use common_utils::metadata::MaskedMetadata;

use crate::{
    configs,
    error::IntoGrpcStatus,
    utils::{get_metadata_payload, MetadataPayload},
};

/// Structured request data with secure metadata access.
#[derive(Debug)]
pub struct RequestData<T> {
    pub payload: T,
    pub extracted_metadata: MetadataPayload,
    pub masked_metadata: MaskedMetadata, // all metadata with masking config
    pub extensions: tonic::Extensions,
}

impl<T> RequestData<T> {
    pub fn from_grpc_request(
        request: tonic::Request<T>,
        config: Arc<configs::Config>,
    ) -> Result<Self, tonic::Status> {
        let (metadata, extensions, payload) = request.into_parts();

        // Construct MetadataPayload from raw metadata (existing functions need it)
        let metadata_payload =
            get_metadata_payload(&metadata, config.clone()).map_err(|e| e.into_grpc_status())?;

        // Pass tonic metadata and config to MaskedMetadata
        let masked_metadata = MaskedMetadata::new(metadata, config.unmasked_headers.clone());

        Ok(RequestData {
            payload,
            extracted_metadata: metadata_payload,
            masked_metadata,
            extensions,
        })
    }
}
