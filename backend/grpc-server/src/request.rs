use std::sync::Arc;

use common_utils::metadata::MaskedMetadata;

use crate::utils::{get_metadata_payload, MetadataPayload};
use ucs_env::{configs, error::ResultExtGrpc};

/// Structured request data with secure metadata access.
#[derive(Debug)]
pub struct RequestData<T> {
    pub payload: T,
    pub extracted_metadata: MetadataPayload,
    pub masked_metadata: MaskedMetadata, // all metadata with masking config
    pub extensions: tonic::Extensions,
}

impl<T> RequestData<T> {
    #[allow(clippy::result_large_err)]
    pub fn from_grpc_request(
        request: tonic::Request<T>,
        config: Arc<configs::Config>,
    ) -> Result<Self, tonic::Status> {
        let (metadata, extensions, payload) = request.into_parts();

        // Construct MetadataPayload from raw metadata (existing functions need it)
        let metadata_payload =
            get_metadata_payload(&metadata, config.clone()).into_grpc_status()?;

        // Pass tonic metadata and config to MaskedMetadata
        let masked_metadata = MaskedMetadata::new(metadata, config.unmasked_headers.clone());

        Ok(Self {
            payload,
            extracted_metadata: metadata_payload,
            masked_metadata,
            extensions,
        })
    }
}
