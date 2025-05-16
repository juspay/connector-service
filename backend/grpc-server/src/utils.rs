use serde_json::Value;
use std::str::FromStr;

use crate::{
    configs::{Config, ServiceType},
    consts,
    logger::config,
};
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

pub fn config_from_metadata(
    metadata: &metadata::MetadataMap,
    mut config: Config,
) -> Result<Config, tonic::Status> {
    // Get the override JSON from metadata
    let override_json = match metadata.get("x-config-override") {
        Some(value) => {
            let json_str = value.to_str().map_err(|e| {
                tonic::Status::invalid_argument(format!("Invalid JSON in x-config-override: {}", e))
            })?;

            serde_json::from_str::<Value>(json_str).map_err(|e| {
                tonic::Status::invalid_argument(format!(
                    "Invalid JSON format in x-config-override: {}",
                    e
                ))
            })?
        }
        None => return Ok(config), // If no override provided, return the original config
    };

    // Apply overrides based on the JSON structure
    if let Some(connectors) = override_json.get("connectors").and_then(Value::as_object) {
        for (connector_name, connector_config) in connectors {
            match connector_name.as_str() {
                "adyen" => {
                    if let Some(settings) = connector_config.as_object() {
                        if let Some(base_url) = settings.get("base_url").and_then(Value::as_str) {
                            config.connectors.adyen.base_url = base_url.to_string();
                        }
                    }
                }
                "razorpay" => {
                    if let Some(settings) = connector_config.as_object() {
                        if let Some(base_url) = settings.get("base_url").and_then(Value::as_str) {
                            config.connectors.razorpay.base_url = base_url.to_string();
                        }
                    }
                }
                // Add other connectors as needed
                _ => {
                    tracing::warn!("Unknown connector in config override: {}", connector_name);
                }
            }
        }
    }

    // proxy
    if let Some(proxy) = override_json.get("proxy").and_then(Value::as_object) {
        if let Some(timeout) = proxy.get("idle_pool_connection_timeout") {
            if let Some(timeout_val) = timeout.as_u64() {
                config.proxy.idle_pool_connection_timeout = Some(timeout_val);
            }
        }
        if let Some(bypass) = proxy.get("bypass_proxy_urls").and_then(Value::as_array) {
            let urls = bypass
                .iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect();
            config.proxy.bypass_proxy_urls = urls;
        }
    }

    // metrics
    if let Some(metrics) = override_json.get("metrics") {
        if let Some(host) = metrics.get("host").and_then(Value::as_str) {
            config.metrics.host = host.to_string();
        }
        if let Some(port) = metrics.get("port").and_then(Value::as_u64) {
            config.metrics.port = u16::try_from(port)
                .map_err(|_| tonic::Status::internal("Port number out of range for u16"))?;
        }
    }

    // server
    if let Some(server) = override_json.get("server") {
        if let Some(host) = server.get("host").and_then(Value::as_str) {
            config.server.host = host.to_string();
        }
        if let Some(port) = server.get("port").and_then(Value::as_u64) {
            config.server.port = u16::try_from(port)
                .map_err(|_| tonic::Status::internal("Port number out of range for u16"))?;
        }
        if let Some(server_type) = server.get("type").and_then(Value::as_str) {
            config.server.type_ = match server_type {
                "http" => ServiceType::Http,
                "https" => ServiceType::Grpc,
                _ => {
                    return Err(tonic::Status::invalid_argument(format!(
                        "Invalid server type: {}",
                        server_type
                    )))
                }
            };
        }
    }

    // log.console
    if let Some(log) = override_json.get("log").and_then(|v| v.get("console")) {
        if let Some(enabled) = log.get("enabled").and_then(Value::as_bool) {
            config.log.console.enabled = enabled;
        }
        if let Some(format) = log.get("log_format").and_then(Value::as_str) {
            config.log.console.log_format = match format {
                "json" => config::LogFormat::Json,
                "default" => config::LogFormat::Default,
                _ => {
                    return Err(tonic::Status::invalid_argument(format!(
                        "Invalid log format: {}",
                        format
                    )))
                }
            };
        }
    }

    Ok(config)
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
