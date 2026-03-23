//! Shared utility functions for UniFFI bindings.
//!
//! Provides helper functions for parsing metadata, building requests/responses,
//! and handling FFI option decoding.

use bytes::Bytes;
use common_utils::errors::ErrorSwitch;
use domain_types::connector_types::ConnectorEnum;
use domain_types::router_data::ConnectorSpecificConfig;
use domain_types::router_response_types::Response;
use domain_types::utils::ForeignTryFrom;
use grpc_api_types::payments::{
    ConnectorResponseTransformationError, FfiConnectorHttpRequest, FfiConnectorHttpResponse,
    FfiOptions, IntegrationError,
};
use http::header::{HeaderMap, HeaderName, HeaderValue};
use prost::Message;

use crate::error::SdkError;

/// Helper to convert internal Request to Protobuf FfiConnectorHttpRequest bytes.
pub fn build_ffi_request_bytes(
    request: &common_utils::request::Request,
) -> Result<Vec<u8>, IntegrationError> {
    let mut headers = request.get_headers_map();
    let (body, boundary) = request
        .body
        .as_ref()
        .map(|b| b.get_body_bytes())
        .transpose()
        .map_err(|e| SdkError::BodyEncodingFailed(e.to_string()).switch())?
        .unwrap_or((None, None));

    if let Some(boundary) = boundary {
        headers.insert(
            "content-type".to_string(),
            format!("multipart/form-data; boundary={}", boundary),
        );
    }

    let proto = FfiConnectorHttpRequest {
        url: request.url.clone(),
        method: request.method.to_string(),
        headers,
        body,
    };

    Ok(proto.encode_to_vec())
}

/// Helper to convert Protobuf FfiConnectorHttpResponse bytes to internal Response.
pub fn build_domain_response(
    response_bytes: Vec<u8>,
) -> Result<Response, ConnectorResponseTransformationError> {
    let response = FfiConnectorHttpResponse::decode(Bytes::from(response_bytes))
        .map_err(|e| SdkError::DecodeFailed(format!("ConnectorHttpResponse decode failed: {e}")).switch())?;

    let mut header_map = HeaderMap::new();
    for (key, value) in &response.headers {
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(key.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            header_map.insert(name, val);
        }
    }

    Ok(Response {
        headers: if header_map.is_empty() {
            None
        } else {
            Some(header_map)
        },
        response: Bytes::from(response.body),
        status_code: response.status_code.try_into().map_err(|e: std::num::TryFromIntError| {
            SdkError::InvalidStatusCode(e.to_string()).switch()
        })?,
    })
}

/// Parse FfiOptions from optional bytes (for request path).
pub fn parse_ffi_options_for_req(options_bytes: Vec<u8>) -> Result<FfiOptions, IntegrationError> {
    if options_bytes.is_empty() {
        return Err(SdkError::EmptyPayload.switch());
    }
    FfiOptions::decode(Bytes::from(options_bytes))
        .map_err(|e| SdkError::DecodeFailed(format!("Options decode failed: {e}")).switch())
}

/// Parse FfiOptions from optional bytes (for response path).
pub fn parse_ffi_options_for_res(
    options_bytes: Vec<u8>,
) -> Result<FfiOptions, ConnectorResponseTransformationError> {
    if options_bytes.is_empty() {
        return Err(SdkError::EmptyPayload.switch());
    }
    FfiOptions::decode(Bytes::from(options_bytes))
        .map_err(|e| SdkError::DecodeFailed(format!("Options decode failed: {e}")).switch())
}

/// Build FfiMetadataPayload from FfiOptions.
/// The connector identity is inferred from which ConnectorSpecificConfig variant is set.
pub fn parse_metadata_for_req(
    options: &FfiOptions,
) -> Result<crate::types::FfiMetadataPayload, IntegrationError> {
    // 1. Resolve ConnectorSpecificConfig from FfiOptions
    let proto_config = options
        .connector_config
        .as_ref()
        .ok_or_else(|| SdkError::MissingConnectorConfig.switch())?;

    // 2. Infer connector from which oneof variant is set
    let config_variant = proto_config
        .config
        .as_ref()
        .ok_or_else(|| SdkError::UnspecifiedConnectorConfig.switch())?;

    let connector = ConnectorEnum::foreign_try_from(config_variant.clone())
        .map_err(ucs_env::error::connector_request_error_report_to_integration)?;

    // 3. Convert proto config to domain ConnectorSpecificConfig
    let connector_config = ConnectorSpecificConfig::foreign_try_from(proto_config.clone())
        .map_err(ucs_env::error::connector_request_error_report_to_integration)?;

    Ok(crate::types::FfiMetadataPayload {
        connector,
        connector_config,
    })
}

/// Build FfiMetadataPayload from FfiOptions (for response path).
pub fn parse_metadata_for_res(
    options: &FfiOptions,
) -> Result<crate::types::FfiMetadataPayload, ConnectorResponseTransformationError> {
    // 1. Resolve ConnectorSpecificConfig from FfiOptions
    let proto_config = options
        .connector_config
        .as_ref()
        .ok_or_else(|| SdkError::MissingConnectorConfig.switch())?;

    // 2. Infer connector from which oneof variant is set
    let config_variant = proto_config
        .config
        .as_ref()
        .ok_or_else(|| SdkError::UnspecifiedConnectorConfig.switch())?;

    let connector = ConnectorEnum::foreign_try_from(config_variant.clone())
        .map_err(ucs_env::error::connector_request_error_report_to_response_transformation)?;

    // 3. Convert proto config to domain ConnectorSpecificConfig
    let connector_config = ConnectorSpecificConfig::foreign_try_from(proto_config.clone())
        .map_err(ucs_env::error::connector_request_error_report_to_response_transformation)?;

    Ok(crate::types::FfiMetadataPayload {
        connector,
        connector_config,
    })
}
