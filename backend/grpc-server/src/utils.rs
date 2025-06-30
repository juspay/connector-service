use serde_json::Value;
use std::str::FromStr;

use crate::configs::Config;
use common_utils::{
    consts::{self, X_API_KEY, X_API_SECRET, X_AUTH, X_KEY1, X_KEY2},
    errors::CustomResult,
};
use domain_types::connector_types;
use domain_types::errors::{ApiError, ApplicationErrorResponse};
use domain_types::router_data::ConnectorAuthType;
use error_stack::Report;
use http::request::Request;
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

pub fn connector_merchant_id_tenant_id_request_id_from_metadata(
    metadata: &metadata::MetadataMap,
) -> CustomResult<(connector_types::ConnectorEnum, String, String, String), ApplicationErrorResponse>
{
    let connector = connector_from_metadata(metadata)?;
    let merchant_id = merchant_id_from_metadata(metadata)?;
    let tenant_id = tenant_id_from_metadata(metadata)?;
    let request_id = request_id_from_metadata(metadata)?;
    Ok((connector, merchant_id, tenant_id, request_id))
}

pub fn connector_from_metadata(
    metadata: &metadata::MetadataMap,
) -> CustomResult<connector_types::ConnectorEnum, ApplicationErrorResponse> {
    parse_metadata(metadata, consts::X_CONNECTOR).and_then(|inner| {
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
        .map(|inner| inner.to_string())
        .map_err(|e| {
            Report::new(ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "MISSING_TENANT_ID".to_string(),
                error_identifier: 400,
                error_message: format!("Missing tenant ID in request metadata: {e}"),
                error_object: None,
            }))
        })
}

pub fn auth_from_metadata(
    metadata: &metadata::MetadataMap,
) -> CustomResult<ConnectorAuthType, ApplicationErrorResponse> {
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
        "currency-auth-key" | "certificate-auth" | _ => Err(Report::new(
            ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "INVALID_AUTH_TYPE".to_string(),
                error_identifier: 400,
                error_message: format!("Invalid auth type: {auth}"),
                error_object: None,
            }),
        )),
    }
}

pub fn config_from_metadata(
    config_override: String,
    config: Config,
) -> CustomResult<Config, ApplicationErrorResponse> {
    if !config_override.is_empty() {
        let override_value = serde_json::from_str(&config_override).map_err(|e| {
            Report::new(ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "CANNOT_CONVERT_TO_JSON".into(),
                error_identifier: 400,
                error_message: format!("Cannot convert override config to JSON: {e}"),
                error_object: None,
            }))
        })?;
        let base_value = serde_json::to_value(&config).map_err(|e| {
            Report::new(ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "CANNOT_SERIALIZE_TO_JSON".into(),
                error_identifier: 400,
                error_message: format!("Cannot serialize base config to JSON: {e}"),
                error_object: None,
            }))
        })?;
        tracing::info!(
            "Override config: {}",
            serde_json::to_string_pretty(&override_value)
                .unwrap_or_else(|_| "Invalid JSON".to_string())
        );
        tracing::info!(
            "Base config: {}",
            serde_json::to_string_pretty(&base_value)
                .unwrap_or_else(|_| "Invalid JSON".to_string())
        );
        let merged = merge_configs(&override_value, &base_value);

        tracing::info!(
            "Merged config: {}",
            serde_json::to_string_pretty(&merged).unwrap_or_else(|_| "Invalid JSON".to_string())
        );
        return serde_json::from_value(merged).map_err(|e| {
            Report::new(ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "CANNOT_DESERIALIZE_JSON".into(),
                error_identifier: 400,
                error_message: format!("Cannot deserialize merged config: {e}"),
                error_object: None,
            }))
        });
    }
    Ok(config)
}

fn merge_configs(override_val: &Value, base_val: &Value) -> Value {
    match (base_val, override_val) {
        (Value::Object(base_map), Value::Object(override_map)) => {
            let mut merged = base_map.clone();
            for (key, override_value) in override_map {
                let base_value = base_map.get(key).unwrap_or(&Value::Null);
                merged.insert(key.clone(), merge_configs(override_value, base_value));
            }
            Value::Object(merged)
        }
        // override replaces base for primitive, null, or array
        (_, override_val) => override_val.clone(),
    }
}

pub fn extract_override_json(
    metadata: &metadata::MetadataMap,
) -> CustomResult<Option<Value>, ApplicationErrorResponse> {
    match metadata.get("x-config-override") {
        Some(value) => {
            let json_str = value.to_str().map_err(|e| {
                Report::new(ApplicationErrorResponse::BadRequest(ApiError {
                    sub_code: "INVALID_METADATA".into(),
                    error_identifier: 400,
                    error_message: format!("Invalid JSON in x-config-override: {e}"),
                    error_object: None,
                }))
            })?;

            let config = serde_json::from_str::<Value>(json_str).map_err(|e| {
                Report::new(ApplicationErrorResponse::BadRequest(ApiError {
                    sub_code: "INVALID_JSON_FORMAT".into(),
                    error_identifier: 400,
                    error_message: format!("Invalid JSON format in x-config-override: {e}"),
                    error_object: None,
                }))
            })?;

            Ok(Some(config))
        }
        None => Ok(None),
    }
}

fn parse_metadata<'a>(
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

#[macro_export]
macro_rules! implement_connector_operation {
    (
        fn_name: $fn_name:ident,
        log_prefix: $log_prefix:literal,
        request_type: $request_type:ty,
        response_type: $response_type:ty,
        flow_marker: $flow_marker:ty,
        resource_common_data_type: $resource_common_data_type:ty,
        request_data_type: $request_data_type:ty,
        response_data_type: $response_data_type:ty,
        request_data_constructor: $request_data_constructor:path,
        common_flow_data_constructor: $common_flow_data_constructor:path,
        generate_response_fn: $generate_response_fn:path,
        all_keys_required: $all_keys_required:expr
    ) => {
        async fn $fn_name(
            &self,
            request: tonic::Request<$request_type>,
        ) -> Result<tonic::Response<$response_type>, tonic::Status> {
            tracing::info!(concat!($log_prefix, "_FLOW: initiated"));
            // let config = $crate::utils::config_from_metadata(request.metadata(), self.config.clone())
            //     .into_grpc_status()?;
            let config = match request.extensions().get::<Config>(){
            Some(config) => config.clone(),
            None => {
                return Err(tonic::Status::internal(
                    "Configuration not found in request extensions",
                ))
            }
            };
            let connector = $crate::utils::connector_from_metadata(request.metadata()).into_grpc_status()?;
            let connector_auth_details = $crate::utils::auth_from_metadata(request.metadata()).into_grpc_status()?;
            let payload = request.into_inner();

            // Get connector data
            let connector_data = connector_integration::types::ConnectorData::get_connector_by_name(&connector);

            // Get connector integration
            let connector_integration: interfaces::connector_integration_v2::BoxedConnectorIntegrationV2<
                '_,
                $flow_marker,
                $resource_common_data_type,
                $request_data_type,
                $response_data_type,
            > = connector_data.connector.get_connector_integration_v2();

            // Create connector request data
            let specific_request_data = $request_data_constructor(payload.clone())
                .into_grpc_status()?;

            // Create common request data
            let common_flow_data = $common_flow_data_constructor((payload.clone(), config.connectors.clone()))
                .into_grpc_status()?;

            // Create router data
            let router_data = domain_types::router_data_v2::RouterDataV2::<
                $flow_marker,
                $resource_common_data_type,
                $request_data_type,
                $response_data_type,
            > {
                flow: std::marker::PhantomData,
                resource_common_data: common_flow_data,
                connector_auth_type: connector_auth_details,
                request: specific_request_data,
                response: Err(domain_types::router_data::ErrorResponse::default()),
            };

            // Execute connector processing
            let response_result = external_services::service::execute_connector_processing_step(
                &config.proxy,
                connector_integration,
                router_data,
                $all_keys_required,
            )
            .await
            .switch()
            .into_grpc_status()?;

            // Generate response
            let final_response = $generate_response_fn(response_result)
                .into_grpc_status()?;

            Ok(tonic::Response::new(final_response))
        }
    };
}
