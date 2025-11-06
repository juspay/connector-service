use std::{str::FromStr, sync::Arc};

use common_utils::{
    consts::{self, X_API_KEY, X_API_SECRET, X_AUTH, X_AUTH_KEY_MAP, X_KEY1, X_KEY2, X_SESSION_ID},
    errors::CustomResult,
    events::FlowName,
    lineage::LineageIds,
};
use domain_types::{
    connector_flow::{
        Accept, Authorize, Capture, CreateOrder, CreateSessionToken, DefendDispute, PSync, RSync,
        Refund, RepeatPayment, SetupMandate, SubmitEvidence, Void,
    },
    connector_types,
    errors::{ApiError, ApplicationErrorResponse},
    router_data::ConnectorAuthType,
};
use error_stack::{Report, ResultExt};
use http::request::Request;
use hyperswitch_masking;
use tonic::metadata;

use crate::{configs, error::ResultExtGrpc};

// Helper function to map flow markers to flow names
pub fn flow_marker_to_flow_name<F>() -> FlowName
where
    F: 'static,
{
    let type_id = std::any::TypeId::of::<F>();

    if type_id == std::any::TypeId::of::<Authorize>() {
        FlowName::Authorize
    } else if type_id == std::any::TypeId::of::<PSync>() {
        FlowName::Psync
    } else if type_id == std::any::TypeId::of::<RSync>() {
        FlowName::Rsync
    } else if type_id == std::any::TypeId::of::<Void>() {
        FlowName::Void
    } else if type_id == std::any::TypeId::of::<Refund>() {
        FlowName::Refund
    } else if type_id == std::any::TypeId::of::<Capture>() {
        FlowName::Capture
    } else if type_id == std::any::TypeId::of::<SetupMandate>() {
        FlowName::SetupMandate
    } else if type_id == std::any::TypeId::of::<RepeatPayment>() {
        FlowName::RepeatPayment
    } else if type_id == std::any::TypeId::of::<CreateOrder>() {
        FlowName::CreateOrder
    } else if type_id == std::any::TypeId::of::<CreateSessionToken>() {
        FlowName::CreateSessionToken
    } else if type_id == std::any::TypeId::of::<Accept>() {
        FlowName::AcceptDispute
    } else if type_id == std::any::TypeId::of::<DefendDispute>() {
        FlowName::DefendDispute
    } else if type_id == std::any::TypeId::of::<SubmitEvidence>() {
        FlowName::SubmitEvidence
    } else {
        tracing::warn!("Unknown flow marker type: {}", std::any::type_name::<F>());
        FlowName::Unknown
    }
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

/// Struct to hold extracted metadata payload
pub struct MetadataPayload {
    pub tenant_id: String,
    pub request_id: String,
    pub merchant_id: String,
    pub connector: connector_types::ConnectorEnum,
    pub lineage_ids: LineageIds<'static>,
    pub connector_auth_type: ConnectorAuthType,
    pub reference_id: Option<String>,
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
    let connector_auth_type = auth_from_metadata(metadata)?;
    let reference_id = reference_id_from_metadata(metadata)?;
    Ok(MetadataPayload {
        tenant_id,
        request_id,
        merchant_id,
        connector,
        lineage_ids,
        connector_auth_type,
        reference_id,
    })
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
        .map(|s| s.to_string())
        .or_else(|_| Ok("DefaultTenantId".to_string()))
}

pub fn session_id_from_metadata(metadata: &metadata::MetadataMap) -> Option<String> {
    parse_metadata(metadata, X_SESSION_ID)
        .map(|inner| inner.to_string())
        .ok()
}

pub fn reference_id_from_metadata(
    metadata: &metadata::MetadataMap,
) -> CustomResult<Option<String>, ApplicationErrorResponse> {
    parse_optional_metadata(metadata, consts::X_REFERENCE_ID).map(|s| s.map(|s| s.to_string()))
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
        "currency-auth-key" => {
            let auth_key_map_str = parse_metadata(metadata, X_AUTH_KEY_MAP)?;
            let auth_key_map: std::collections::HashMap<
                common_enums::enums::Currency,
                common_utils::pii::SecretSerdeValue,
            > = serde_json::from_str(auth_key_map_str).change_context(
                ApplicationErrorResponse::BadRequest(ApiError {
                    sub_code: "INVALID_AUTH_KEY_MAP".to_string(),
                    error_identifier: 400,
                    error_message: "Invalid auth-key-map format".to_string(),
                    error_object: None,
                }),
            )?;
            Ok(ConnectorAuthType::CurrencyAuthKey { auth_key_map })
        }
        "certificate-auth" | _ => Err(Report::new(ApplicationErrorResponse::BadRequest(
            ApiError {
                sub_code: "INVALID_AUTH_TYPE".to_string(),
                error_identifier: 400,
                error_message: format!("Invalid auth type: {auth}"),
                error_object: None,
            },
        ))),
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

fn parse_optional_metadata<'a>(
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

pub fn log_before_initialization<T>(
    request: &tonic::Request<T>,
    service_name: &str,
    metadata_payload: &MetadataPayload,
) -> CustomResult<(), ApplicationErrorResponse>
where
    T: serde::Serialize,
{
    let MetadataPayload {
        connector,
        merchant_id,
        tenant_id,
        request_id,
        ..
    } = metadata_payload;
    let current_span = tracing::Span::current();
    let req_body = request.get_ref();
    let req_body_json = match hyperswitch_masking::masked_serialize(req_body) {
        Ok(masked_value) => masked_value.to_string(),
        Err(e) => {
            tracing::error!("Masked serialization error: {:?}", e);
            "<masked serialization error>".to_string()
        }
    };
    current_span.record("service_name", service_name);
    current_span.record("request_body", req_body_json);
    current_span.record("gateway", connector.to_string());
    current_span.record("merchant_id", merchant_id);
    current_span.record("tenant_id", tenant_id);
    current_span.record("request_id", request_id);
    tracing::info!("Golden Log Line (incoming)");
    Ok(())
}

pub fn log_after_initialization<T>(result: &Result<tonic::Response<T>, tonic::Status>)
where
    T: serde::Serialize + std::fmt::Debug,
{
    let current_span = tracing::Span::current();
    // let duration = start_time.elapsed().as_millis();
    //     current_span.record("response_time", duration);

    match &result {
        Ok(response) => {
            current_span.record("response_body", tracing::field::debug(response.get_ref()));

            let res_ref = response.get_ref();

            // Try converting to JSON Value
            if let Ok(serde_json::Value::Object(map)) = serde_json::to_value(res_ref) {
                if let Some(status_val) = map.get("status") {
                    let status_num_opt = status_val.as_number();
                    let status_u32_opt: Option<u32> = status_num_opt
                        .and_then(|n| n.as_u64())
                        .and_then(|n| u32::try_from(n).ok());
                    let status_str = if let Some(s) = status_u32_opt {
                        common_enums::AttemptStatus::try_from(s)
                            .unwrap_or(common_enums::AttemptStatus::Unknown)
                            .to_string()
                    } else {
                        common_enums::AttemptStatus::Unknown.to_string()
                    };
                    current_span.record("flow_specific_fields.status", status_str);
                }
            } else {
                tracing::warn!("Could not serialize response to JSON to extract status");
            }
        }
        Err(status) => {
            current_span.record("error_message", status.message());
            current_span.record("status_code", status.code().to_string());
        }
    }
    tracing::info!("Golden Log Line (incoming)");
}

pub async fn grpc_logging_wrapper<T, F, Fut, R>(
    request: tonic::Request<T>,
    service_name: &str,
    config: Arc<configs::Config>,
    handler: F,
) -> Result<tonic::Response<R>, tonic::Status>
where
    T: serde::Serialize + std::fmt::Debug + Send + 'static,
    F: FnOnce(tonic::Request<T>, MetadataPayload) -> Fut + Send,
    Fut: std::future::Future<Output = Result<tonic::Response<R>, tonic::Status>> + Send,
    R: serde::Serialize + std::fmt::Debug,
{
    let current_span = tracing::Span::current();
    let header_payload =
        get_metadata_payload(request.metadata(), config.clone()).into_grpc_status()?;
    log_before_initialization(&request, service_name, &header_payload).into_grpc_status()?;
    let start_time = tokio::time::Instant::now();
    let result = handler(request, header_payload).await;
    let duration = start_time.elapsed().as_millis();
    current_span.record("response_time", duration);
    log_after_initialization(&result);
    result
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
            let service_name = request
            .extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "unknown_service".to_string());
            let current_span = tracing::Span::current();
            let metadata_payload = $crate::utils::get_metadata_payload(request.metadata(), self.config.clone()).into_grpc_status()?;
            $crate::utils::log_before_initialization(&request, service_name.as_str(), &metadata_payload).into_grpc_status()?;
            let start_time = tokio::time::Instant::now();
            let result = Box::pin(async{
            let (connector, request_id, connector_auth_details) = (metadata_payload.connector, metadata_payload.request_id, metadata_payload.connector_auth_type);
            let metadata = request.metadata().clone();
            let payload = request.into_inner();

            // Get connector data
            let connector_data: ConnectorData<domain_types::payment_method_data::DefaultPCIHolder> = connector_integration::types::ConnectorData::get_connector_by_name(&connector);

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
            let common_flow_data = $common_flow_data_constructor((payload.clone(), self.config.connectors.clone(), &metadata))
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

            // Calculate flow name for dynamic flow-specific configurations
            let flow_name = $crate::utils::flow_marker_to_flow_name::<$flow_marker>();

            // Get API tag for the current flow
            let api_tag = self
                .config
                .api_tags
                .get_tag_for_flow(flow_name);

            // Create test context if test mode is enabled
            let test_context = if self.config.test.enabled {
                let ctx = external_services::service::TestContext::new(
                    self.config.test.mock_server_url.clone(),
                    &metadata,
                );
                tracing::info!(
                    "Test context created: flow={:?}, enabled={}, mock_server_url={:?}, is_test_env={}",
                    flow_name,
                    self.config.test.enabled,
                    self.config.test.mock_server_url,
                    ctx.is_test_env
                );
                Some(ctx)
            } else {
                tracing::info!("Test mode disabled for flow={:?}", flow_name);
                None
            };

            // Execute connector processing
            let event_params = external_services::service::EventProcessingParams {
                connector_name: &connector.to_string(),
                service_name: &service_name,
                flow_name,
                event_config: &self.config.events,
                raw_request_data: Some(common_utils::pii::SecretSerdeValue::new(payload.masked_serialize().unwrap_or_default())),
                request_id: &request_id,
                lineage_ids: &metadata_payload.lineage_ids,
                reference_id: &metadata_payload.reference_id,
            };
            let response_result = external_services::service::execute_connector_processing_step(
                &self.config.proxy,
                connector_integration,
                router_data,
                $all_keys_required,
                event_params,
                test_context,
                api_tag,
            )
            .await
            .switch()
            .into_grpc_status()?;

            // Generate response
            let final_response = $generate_response_fn(response_result)
                .into_grpc_status()?;
            Ok(tonic::Response::new(final_response))
        }).await;
        let duration = start_time.elapsed().as_millis();
        current_span.record("response_time", duration);
        $crate::utils::log_after_initialization(&result);
        result
    }
}
}
