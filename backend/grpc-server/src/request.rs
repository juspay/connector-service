use std::sync::Arc;

use common_utils::metadata::MaskedMetadata;

use crate::{
    configs,
    error::ResultExtGrpc,
    utils::{extract_proto_auth_from_payload, get_metadata_payload, MetadataPayload},
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
    #[allow(clippy::result_large_err)]
    pub fn from_grpc_request(
        request: tonic::Request<T>,
        config: Arc<configs::Config>,
    ) -> Result<Self, tonic::Status>
    where
        T: serde::Serialize,
    {
        let (metadata, extensions, payload) = request.into_parts();
        let proto_auth = extract_proto_auth_from_payload(&payload);

        // Construct MetadataPayload from raw metadata (existing functions need it)
        let metadata_payload =
            get_metadata_payload(&metadata, config.clone(), proto_auth).into_grpc_status()?;

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
