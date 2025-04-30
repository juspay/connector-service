use std::str::FromStr;

use crate::consts;
use domain_types::connector_types;
use http::request::Request;
use hyperswitch_domain_models::router_data::ConnectorAuthType;
use tonic::metadata;

/// Record the header's fields in request's trace
pub fn record_fields_from_header<B: hyper::body::Body>(request: &Request<B>) -> tracing::Span {
    let url_path = request.uri().path();

    let span = tracing::debug_span!(
        "request",
        uri = %url_path,
        version = ?request.version(),
        tenant_id = tracing::field::Empty,
        request_id = tracing::field::Empty,
    );
    request
        .headers()
        .get(consts::X_TENANT_ID)
        .and_then(|value| value.to_str().ok())
        .map(|tenant_id| span.record("tenant_id", tenant_id));

    request
        .headers()
        .get(consts::X_REQUEST_ID)
        .and_then(|value| value.to_str().ok())
        .map(|request_id| span.record("request_id", request_id));

    span
}

pub fn connector_from_metadata(
    metadata: &metadata::MetadataMap,
) -> Result<connector_types::ConnectorEnum, tonic::Status> {
    parse_metadata(metadata, consts::X_CONNECTOR).and_then(|inner| {
        connector_types::ConnectorEnum::from_str(inner)
            .map_err(|e| tonic::Status::invalid_argument(format!("Invalid connector: {e}")))
    })
}

pub fn auth_from_metadata(
    metadata: &metadata::MetadataMap,
) -> Result<ConnectorAuthType, tonic::Status> {
    const X_AUTH: &str = "x-auth";
    const X_API_KEY: &str = "x-api-key";
    const X_KEY1: &str = "x-key1";
    const X_KEY2: &str = "x-key2";
    const X_API_SECRET: &str = "x-api-secret";

    let auth = parse_metadata(metadata, X_AUTH)?;

    #[allow(clippy::wildcard_in_or_patterns)]
    match auth {
        "header-key" => Ok(ConnectorAuthType::HeaderKey {
            api_key: parse_metadata(metadata, X_API_KEY)?.to_string().into(),
        }),
        "body-key" => Ok(ConnectorAuthType::BodyKey {
            api_key: parse_metadata(metadata, X_API_KEY)?.to_string().into(),
            key1: parse_metadata(metadata, X_KEY1)?.to_string().into(),
        }),
        "signature-key" => Ok(ConnectorAuthType::SignatureKey {
            api_key: parse_metadata(metadata, X_API_KEY)?.to_string().into(),
            key1: parse_metadata(metadata, X_KEY1)?.to_string().into(),
            api_secret: parse_metadata(metadata, X_API_SECRET)?.to_string().into(),
        }),
        "multi-auth-key" => Ok(ConnectorAuthType::MultiAuthKey {
            api_key: parse_metadata(metadata, X_API_KEY)?.to_string().into(),
            key1: parse_metadata(metadata, X_KEY1)?.to_string().into(),
            key2: parse_metadata(metadata, X_KEY2)?.to_string().into(),
            api_secret: parse_metadata(metadata, X_API_SECRET)?.to_string().into(),
        }),
        "no-key" => Ok(ConnectorAuthType::NoKey),
        "temporary-auth" => Ok(ConnectorAuthType::TemporaryAuth),
        "currency-auth-key" | "certificate-auth" | _ => Err(tonic::Status::invalid_argument(
            format!("Invalid auth type: {auth}"),
        )),
    }
}

fn parse_metadata<'a>(
    metadata: &'a metadata::MetadataMap,
    key: &str,
) -> Result<&'a str, tonic::Status> {
    metadata
        .get(key)
        .ok_or(tonic::Status::invalid_argument(format!(
            "Missing {} in request metadata",
            key
        )))
        .and_then(|value| {
            value.to_str().map_err(|e| {
                tonic::Status::invalid_argument(format!("Invalid {} in request metadata: {e}", key))
            })
        })
}
