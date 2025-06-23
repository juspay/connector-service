use std::str::FromStr;

use crate::consts;
use domain_types::connector_types;
use domain_types::errors::{ApiError, ApplicationErrorResponse};
use error_stack::Report;
use http::request::Request;
use hyperswitch_common_utils::errors::CustomResult;
use hyperswitch_domain_models::router_data::ConnectorAuthType;
use serde_json::Value;
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
                error_message: format!("Invalid connector: {}", e),
                error_object: None,
            }))
        })
    })
}

pub fn merchant_id_from_metadata(
    metadata: &metadata::MetadataMap,
) -> CustomResult<String, ApplicationErrorResponse> {
    parse_metadata(metadata, consts::X_TENANT_ID)
        .map(|inner| inner.to_string())
        .map_err(|e| {
            Report::new(ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "MISSING_MERCHANT_ID".to_string(),
                error_identifier: 400,
                error_message: format!("Missing merchant ID in request metadata: {}", e),
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
                error_message: format!("Missing request ID in request metadata: {}", e),
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
                error_message: format!("Missing tenant ID in request metadata: {}", e),
                error_object: None,
            }))
        })
}

pub fn auth_from_metadata(
    metadata: &metadata::MetadataMap,
) -> CustomResult<ConnectorAuthType, ApplicationErrorResponse> {
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
        "currency-auth-key" | "certificate-auth" | _ => Err(Report::new(
            ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "INVALID_AUTH_TYPE".to_string(),
                error_identifier: 400,
                error_message: format!("Invalid auth type: {}", auth),
                error_object: None,
            }),
        )),
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
                error_message: format!("Missing {} in request metadata", key),
                error_object: None,
            }))
        })
        .and_then(|value| {
            value.to_str().map_err(|e| {
                Report::new(ApplicationErrorResponse::BadRequest(ApiError {
                    sub_code: "INVALID_METADATA".to_string(),
                    error_identifier: 400,
                    error_message: format!("Invalid {} in request metadata: {}", key, e),
                    error_object: None,
                }))
            })
        })
}

pub fn mask_sensitive_fields(body: String) -> String {
    let sensitive_keys = [
        "card_number",
        "card_exp_month",
        "card_exp_year",
        "card_cvc",
        "card_holder_name",
        "eci",
        "cavv",
        "ds_transaction_id",
    ];

    let parsed: Result<Value, _> = serde_json::from_str(&body);

    match parsed {
        Ok(mut json_value) => {
            fn mask(value: &mut Value, keys: &[&str]) {
                match value {
                    Value::Object(map) => {
                        for (k, v) in map.iter_mut() {
                            if keys.contains(&k.as_str()) {
                                *v = Value::String("****".to_string());
                            } else {
                                mask(v, keys);
                            }
                        }
                    }
                    Value::Array(arr) => {
                        for item in arr.iter_mut() {
                            mask(item, keys);
                        }
                    }
                    _ => {}
                }
            }

            mask(&mut json_value, &sensitive_keys);
            json_value.to_string()
        }
        Err(_) => "{\"error\": \"Invalid JSON\"}".to_string(),
    }
}

pub fn attempt_status_to_str(status: String) -> &'static str {
    match status.parse::<i32>() {
        Ok(0) => "STARTED",
        Ok(1) => "AUTHENTICATION_FAILED",
        Ok(2) => "ROUTER_DECLINED",
        Ok(3) => "AUTHENTICATION_PENDING",
        Ok(4) => "AUTHENTICATION_SUCCESSFUL",
        Ok(5) => "AUTHORIZED",
        Ok(6) => "AUTHORIZATION_FAILED",
        Ok(7) => "CHARGED",
        Ok(8) => "AUTHORIZING",
        Ok(9) => "COD_INITIATED",
        Ok(10) => "VOIDED",
        Ok(11) => "VOID_INITIATED",
        Ok(12) => "CAPTURE_INITIATED",
        Ok(13) => "CAPTURE_FAILED",
        Ok(14) => "VOID_FAILED",
        Ok(15) => "AUTO_REFUNDED",
        Ok(16) => "PARTIAL_CHARGED",
        Ok(17) => "PARTIAL_CHARGED_AND_CHARGEABLE",
        Ok(18) => "UNRESOLVED",
        Ok(19) => "PENDING",
        Ok(20) => "FAILURE",
        Ok(21) => "PAYMENT_METHOD_AWAITED",
        Ok(22) => "CONFIRMATION_AWAITED",
        Ok(23) => "DEVICE_DATA_COLLECTION_PENDING",
        _ => "UNKNOWN",
    }
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
        generate_response_fn: $generate_response_fn:path
    ) => {
        async fn $fn_name(
            &self,
            request: tonic::Request<$request_type>,
        ) -> Result<tonic::Response<$response_type>, tonic::Status> {
            tracing::info!(concat!($log_prefix, "_FLOW: initiated"));

            let connector = $crate::utils::connector_from_metadata(request.metadata()).into_grpc_status()?;
            let connector_auth_details = $crate::utils::auth_from_metadata(request.metadata()).into_grpc_status()?;
            let payload = request.into_inner();

            // Get connector data
            let connector_data = connector_integration::types::ConnectorData::get_connector_by_name(&connector);

            // Get connector integration
            let connector_integration: hyperswitch_interfaces::connector_integration_v2::BoxedConnectorIntegrationV2<
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
            let common_flow_data = $common_flow_data_constructor((payload.clone(), self.config.connectors.clone()))
                .into_grpc_status()?;

            // Create router data
            let router_data = hyperswitch_domain_models::router_data_v2::RouterDataV2::<
                $flow_marker,
                $resource_common_data_type,
                $request_data_type,
                $response_data_type,
            > {
                flow: std::marker::PhantomData,
                resource_common_data: common_flow_data,
                connector_auth_type: connector_auth_details,
                request: specific_request_data,
                response: Err(hyperswitch_domain_models::router_data::ErrorResponse::default()),
            };

            // Execute connector processing
            let response_result = external_services::service::execute_connector_processing_step(
                &self.config.proxy,
                connector_integration,
                router_data,
                payload.all_keys_required,
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
