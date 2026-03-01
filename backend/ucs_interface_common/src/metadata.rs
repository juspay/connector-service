use common_utils::{
    consts::{self, X_SHADOW_MODE},
    errors::CustomResult,
    lineage::LineageIds,
};
use domain_types::{
    connector_types,
    errors::{ApiError, ApplicationErrorResponse},
    router_data::ConnectorSpecificAuth,
};
use error_stack::Report;
use std::{str::FromStr, sync::Arc};
use tonic::metadata;
use ucs_env::configs;

use crate::auth::resolve_connector_auth;

/// Struct to hold extracted metadata payload.
///
/// SECURITY WARNING: This struct should only contain non-sensitive business metadata.
/// For any sensitive data (API keys, tokens, credentials, etc.), always:
/// 1. Wrap in hyperswitch_masking::Secret<T>
/// 2. Extract via MaskedMetadata methods instead of adding here
#[derive(Clone, Debug)]
pub struct MetadataPayload {
    pub tenant_id: String,
    pub request_id: String,
    pub merchant_id: String,
    pub connector: connector_types::ConnectorEnum,
    pub lineage_ids: LineageIds<'static>,
    pub connector_auth_type: ConnectorSpecificAuth,
    pub reference_id: Option<String>,
    pub shadow_mode: bool,
    pub resource_id: Option<String>,
}

pub fn get_metadata_payload(
    metadata: &metadata::MetadataMap,
    server_config: Arc<configs::Config>,
) -> CustomResult<MetadataPayload, ApplicationErrorResponse> {
    let connector = connector_from_metadata(metadata)?;
    let merchant_id = merchant_id_from_metadata(metadata)?;
    let tenant_id = tenant_id_from_metadata(metadata)?;
    let request_id = request_id_from_metadata(metadata)?;
    let lineage_ids = extract_lineage_fields_from_metadata(metadata, &server_config.lineage);
    let connector_auth_type = resolve_connector_auth(metadata, &connector)?;
    let reference_id = reference_id_from_metadata(metadata)?;
    let resource_id = resource_id_from_metadata(metadata)?;
    let shadow_mode = shadow_mode_from_metadata(metadata);
    Ok(MetadataPayload {
        tenant_id,
        request_id,
        merchant_id,
        connector,
        lineage_ids,
        connector_auth_type,
        reference_id,
        shadow_mode,
        resource_id,
    })
}

/// Extract lineage fields from header
pub fn extract_lineage_fields_from_metadata(
    metadata: &metadata::MetadataMap,
    config: &configs::LineageConfig,
) -> LineageIds<'static> {
    if !config.enabled {
        return LineageIds::empty(&config.field_prefix).to_owned();
    }
    metadata
        .get(&config.header_name)
        .and_then(|value| value.to_str().ok())
        .map(|header_value| LineageIds::new(&config.field_prefix, header_value))
        .transpose()
        .inspect(|value| {
            tracing::info!(
                parsed_fields = ?value,
                "Successfully parsed lineage header"
            )
        })
        .inspect_err(|err| {
            tracing::warn!(
                error = %err,
                "Failed to parse lineage header, continuing without lineage fields"
            )
        })
        .ok()
        .flatten()
        .unwrap_or_else(|| LineageIds::empty(&config.field_prefix))
        .to_owned()
}

pub fn connector_from_metadata(
    metadata: &metadata::MetadataMap,
) -> CustomResult<connector_types::ConnectorEnum, ApplicationErrorResponse> {
    parse_metadata(metadata, consts::X_CONNECTOR_NAME).and_then(|inner| {
        connector_types::ConnectorEnum::from_str(inner).map_err(|e| {
            Report::new(ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "INVALID_CONNECTOR".to_string(),
                error_identifier: 400,
                error_message: format!("Invalid connector: {e}"),
                error_object: None,
            }))
        })
    })
}

pub fn merchant_id_from_metadata(
    metadata: &metadata::MetadataMap,
) -> CustomResult<String, ApplicationErrorResponse> {
    parse_metadata(metadata, consts::X_MERCHANT_ID)
        .map(|inner| inner.to_string())
        .map_err(|e| {
            Report::new(ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "MISSING_MERCHANT_ID".to_string(),
                error_identifier: 400,
                error_message: format!("Missing merchant ID in request metadata: {e}"),
                error_object: None,
            }))
        })
}

pub fn request_id_from_metadata(
    metadata: &metadata::MetadataMap,
) -> CustomResult<String, ApplicationErrorResponse> {
    parse_metadata(metadata, consts::X_REQUEST_ID)
        .map(|inner| inner.to_string())
        .map_err(|e| {
            Report::new(ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "MISSING_REQUEST_ID".to_string(),
                error_identifier: 400,
                error_message: format!("Missing request ID in request metadata: {e}"),
                error_object: None,
            }))
        })
}

pub fn tenant_id_from_metadata(
    metadata: &metadata::MetadataMap,
) -> CustomResult<String, ApplicationErrorResponse> {
    parse_metadata(metadata, consts::X_TENANT_ID)
        .map(|s| s.to_string())
        .or_else(|_| Ok("DefaultTenantId".to_string()))
}

pub fn reference_id_from_metadata(
    metadata: &metadata::MetadataMap,
) -> CustomResult<Option<String>, ApplicationErrorResponse> {
    parse_optional_metadata(metadata, consts::X_REFERENCE_ID).map(|s| s.map(|s| s.to_string()))
}

pub fn resource_id_from_metadata(
    metadata: &metadata::MetadataMap,
) -> CustomResult<Option<String>, ApplicationErrorResponse> {
    parse_optional_metadata(metadata, consts::X_RESOURCE_ID).map(|s| s.map(|s| s.to_string()))
}

pub fn shadow_mode_from_metadata(metadata: &metadata::MetadataMap) -> bool {
    parse_optional_metadata(metadata, X_SHADOW_MODE)
        .ok()
        .flatten()
        .map(|value| value.to_lowercase() == "true")
        .unwrap_or(false)
}

pub fn parse_metadata<'a>(
    metadata: &'a metadata::MetadataMap,
    key: &str,
) -> CustomResult<&'a str, ApplicationErrorResponse> {
    metadata
        .get(key)
        .ok_or_else(|| {
            Report::new(ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "MISSING_METADATA".to_string(),
                error_identifier: 400,
                error_message: format!("Missing {key} in request metadata"),
                error_object: None,
            }))
        })
        .and_then(|value| {
            value.to_str().map_err(|e| {
                Report::new(ApplicationErrorResponse::BadRequest(ApiError {
                    sub_code: "INVALID_METADATA".to_string(),
                    error_identifier: 400,
                    error_message: format!("Invalid {key} in request metadata: {e}"),
                    error_object: None,
                }))
            })
        })
}

pub fn parse_optional_metadata<'a>(
    metadata: &'a metadata::MetadataMap,
    key: &str,
) -> CustomResult<Option<&'a str>, ApplicationErrorResponse> {
    metadata
        .get(key)
        .map(|value| value.to_str())
        .transpose()
        .map_err(|e| {
            Report::new(ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "INVALID_METADATA".to_string(),
                error_identifier: 400,
                error_message: format!("Invalid {key} in request metadata: {e}"),
                error_object: None,
            }))
        })
}
