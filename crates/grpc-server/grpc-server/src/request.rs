use std::sync::Arc;

use common_utils::metadata::MaskedMetadata;
use domain_types::{
    connector_types, errors::IntegrationError, router_data::ConnectorSpecificConfig,
};
use error_stack::Report;
use tonic::metadata;
use ucs_env::{configs, error::ResultExtGrpc};

use crate::utils::MetadataPayload;

/// Structured request data with secure metadata access.
/// This is the gRPC-specific wrapper around `InterfaceRequestData` that
/// provides non-optional extensions for backward compatibility.
#[derive(Debug)]
pub struct RequestData<T> {
    pub payload: T,
    pub extracted_metadata: MetadataPayload,
    pub masked_metadata: MaskedMetadata,
    pub extensions: tonic::Extensions,
}

impl<T> RequestData<T> {
    #[allow(clippy::result_large_err)]
    pub fn from_grpc_request(
        request: tonic::Request<T>,
        config: Arc<configs::Config>,
    ) -> Result<Self, tonic::Status> {
        let interface_data =
            ucs_interface_common::request::InterfaceRequestData::from_grpc_request(
                request, config,
            )?;

        Ok(Self {
            payload: interface_data.payload,
            extracted_metadata: interface_data.extracted_metadata,
            masked_metadata: interface_data.masked_metadata,
            extensions: interface_data
                .extensions
                .ok_or_else(|| tonic::Status::internal("Extensions missing from gRPC request"))?,
        })
    }

    /// Parse request for webhook flows that only need routing metadata.
    /// This does not require connector authentication credentials.
    #[allow(clippy::result_large_err)]
    pub fn from_grpc_request_unauthenticated(
        request: tonic::Request<T>,
        config: Arc<configs::Config>,
    ) -> Result<Self, tonic::Status> {
        let (metadata, extensions, payload) = request.into_parts();

        // Extract routing metadata only (connector, request_id, etc.)
        // without requiring connector_config/auth credentials
        let routing_metadata =
            extract_routing_metadata_only(&metadata, config.clone()).into_grpc_status()?;

        let masked_metadata = MaskedMetadata::new(metadata, config.unmasked_headers.clone());

        Ok(Self {
            payload,
            extracted_metadata: routing_metadata,
            masked_metadata,
            extensions,
        })
    }
}

/// Extract only routing metadata without requiring authentication credentials.
/// Used for webhook flows where connector_config is not needed for initial processing.
fn extract_routing_metadata_only(
    metadata: &metadata::MetadataMap,
    _config: Arc<configs::Config>,
) -> Result<MetadataPayload, Report<IntegrationError>> {
    use common_utils::consts;
    use std::str::FromStr;
    use ucs_interface_common::metadata::{
        merchant_id_from_metadata, request_id_from_metadata, tenant_id_from_metadata,
    };

    // Extract connector name - optional for webhooks during initial parsing
    let connector = metadata
        .get(consts::X_CONNECTOR_NAME)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| connector_types::ConnectorEnum::from_str(s).ok());

    // Extract other routing fields - use defaults where appropriate
    let merchant_id = merchant_id_from_metadata(metadata).unwrap_or_default();
    let tenant_id = tenant_id_from_metadata(metadata).unwrap_or_default();
    let request_id = request_id_from_metadata(metadata).unwrap_or_default();

    // For webhooks, we use NoKey variant initially.
    // The actual config can be loaded later when needed via the payload's webhook_secrets.
    let connector_config = ConnectorSpecificConfig::NoKey;

    // Extract optional fields
    let reference_id = metadata
        .get(consts::X_REFERENCE_ID)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let resource_id = metadata
        .get(consts::X_RESOURCE_ID)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let shadow_mode = metadata
        .get(consts::X_SHADOW_MODE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_lowercase() == "true")
        .unwrap_or(false);

    let environment = metadata
        .get(consts::X_ENVIRONMENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // For unauthenticated flows, we need a connector to proceed
    // Return error if connector is not provided
    let connector = connector.ok_or_else(|| {
        Report::new(IntegrationError::MissingRequiredField {
            field_name: "x-connector",
            context: domain_types::errors::IntegrationErrorContext {
                additional_context: Some(
                    "Connector name is required for webhook processing".to_string(),
                ),
                ..Default::default()
            },
        })
    })?;

    Ok(MetadataPayload {
        tenant_id,
        request_id,
        merchant_id,
        connector,
        lineage_ids: common_utils::lineage::LineageIds::empty(""),
        connector_config,
        reference_id,
        shadow_mode,
        resource_id,
        environment,
    })
}
