use std::{str::FromStr, time::Duration};

use base64::engine::Engine;
use common_utils::ext_traits::AsyncExt;
use common_utils::{
    request::{Method, Request, RequestContent},
};
use common_enums::ApiClientError;
use domain_types::{
    connector_types::{ConnectorResponseHeaders, RawConnectorResponse},
    errors::{ApiErrorResponse, ConnectorError},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Proxy,
};
// Use hyperswitch_masking that's already available

pub trait ConnectorRequestReference {
    fn get_connector_request_reference_id(&self) -> &str;
}

impl ConnectorRequestReference for domain_types::connector_types::PaymentFlowData {
    fn get_connector_request_reference_id(&self) -> &str {
        &self.connector_request_reference_id
    }
}

impl ConnectorRequestReference for domain_types::connector_types::RefundFlowData {
    fn get_connector_request_reference_id(&self) -> &str {
        &self.connector_request_reference_id
    }
}

impl ConnectorRequestReference for domain_types::connector_types::DisputeFlowData {
    fn get_connector_request_reference_id(&self) -> &str {
        &self.connector_request_reference_id
    }
}
use common_utils::{
    emit_event_with_config,
    events::{Event, EventConfig, EventStage, FlowName},
    pii::SecretSerdeValue,
};
use error_stack::{report, ResultExt};
use interfaces::{
    connector_integration_v2::BoxedConnectorIntegrationV2,
    integrity::{CheckIntegrity, FlowIntegrity, GetIntegrityObject},
};
use hyperswitch_masking::{ErasedMaskSerialize, ExposeInterface, Maskable, Secret};
use once_cell::sync::OnceCell;
use reqwest::Client;
use serde_json::json;
use tracing::field::Empty;

use crate::shared_metrics as metrics;

// TokenData is now imported from hyperswitch_injector
use injector::{injector_core, InjectorRequest, TokenData, ConnectorPayload, ConnectionConfig, HttpMethod};
pub type Headers = std::collections::HashSet<(String, Maskable<String>)>;

// Base64 engine for certificate processing
const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

trait ToHttpMethod {
    fn to_http_method(&self) -> HttpMethod;
}

impl ToHttpMethod for Method {
    fn to_http_method(&self) -> HttpMethod {
        match self {
            Self::Get => HttpMethod::GET,
            Self::Post => HttpMethod::POST,
            Self::Put => HttpMethod::PUT,
            Self::Patch => HttpMethod::PATCH,
            Self::Delete => HttpMethod::DELETE,
        }
    }
}

/// Process base64 encoded certificate for injector use
fn process_certificate_for_injector(
    encoded_certificate: &Secret<String>,
) -> Result<Secret<String>, ConnectorError> {
    
    // Try to decode as base64 first
    let certificate_content = match BASE64_ENGINE.decode(encoded_certificate.clone().expose()) {
        Ok(decoded_bytes) => {
            // Successfully decoded base64, convert to string
            match String::from_utf8(decoded_bytes) {
                Ok(decoded_string) => {
                    decoded_string
                }
                Err(_) => {
                    encoded_certificate.clone().expose().to_string()
                }
            }
        }
        Err(_) => {
            // Not base64 encoded, assume it's already in PEM format
            encoded_certificate.clone().expose().to_string()
        }
    };
    
    // Certificate should already have proper PEM headers from source
    let processed_cert = certificate_content.replace("\\n", "\n");
    
    Ok(Secret::new(processed_cert))
}

/// Process client certificate and key for injector use  
fn process_client_certificate_for_injector(
    encoded_certificate: &Secret<String>,
    encoded_certificate_key: &Secret<String>,
) -> Result<(Secret<String>, Secret<String>), ConnectorError> {
    
    // Process certificate
    let processed_cert = process_certificate_for_injector(encoded_certificate)?;
    
    // Process certificate key
    let key_content = match BASE64_ENGINE.decode(encoded_certificate_key.clone().expose()) {
        Ok(decoded_bytes) => {
            match String::from_utf8(decoded_bytes) {
                Ok(decoded_string) => {
                    decoded_string
                }
                Err(_) => {
                    encoded_certificate_key.clone().expose().to_string()
                }
            }
        }
        Err(_) => {
            encoded_certificate_key.clone().expose().to_string()
        }
    };
    
    // Private key should already have proper PEM headers from source
    let processed_key = key_content;
    
    Ok((processed_cert, Secret::new(processed_key)))
}

fn convert_to_injector_request<ResourceCommonData>(
    connector_request: &Request,
    token_data: &TokenData,
    proxy: &Proxy,
    payment_flow_data: &ResourceCommonData,
) -> Result<InjectorRequest, ConnectorError> 
where
    ResourceCommonData: Clone + 'static,
{
    use std::collections::HashMap;
    
    let http_method = connector_request.method.to_http_method();

    let injector_token_data = TokenData {
        vault_connector: token_data.vault_connector,
        specific_token_data: token_data.specific_token_data.clone(),
    };
    
    // Use the connector request body as the template (after credit_proxy/debit_proxy conversion)
    let template = connector_request.body
        .as_ref()
        .ok_or(ConnectorError::RequestEncodingFailed)?
        .get_inner_value()
        .expose()
        .to_string();
    
    let connector_payload = ConnectorPayload { template };

    // Parse the URL to separate base_url and endpoint_path
    let parsed_url = reqwest::Url::parse(&connector_request.url)
        .map_err(|_| ConnectorError::RequestEncodingFailed)?;
    
    // Create base URL with scheme, host, and port only
    let mut base_url_parsed = parsed_url.clone();
    base_url_parsed.set_path("");
    base_url_parsed.set_query(None);
    base_url_parsed.set_fragment(None);
    
    // Convert to string for injector compatibility and remove trailing slash
    let base_url = base_url_parsed.to_string().trim_end_matches('/').to_string();
    
    // Extract the path as endpoint_path
    let endpoint_path = parsed_url.path().to_string();

    // Convert headers to HashMap<String, String> and let injector handle Secret wrapping
    let mut headers = HashMap::new();
    let mut vault_proxy_url = None;
    let mut ca_cert_from_header = None;
    
    // Use existing proxy configuration as fallback
    let fallback_proxy_url = proxy.https_url.as_ref().or(proxy.http_url.as_ref())
        .and_then(|url| reqwest::Url::parse(url).ok());
    
    // Try to extract headers from PaymentFlowData if available
    // Safe downcast wrapper to avoid clippy warning
    let payment_flow_any: &dyn std::any::Any = payment_flow_data;
    if let Some(payment_flow) = payment_flow_any.downcast_ref::<domain_types::connector_types::PaymentFlowData>() {
        if let Some(additional_headers) = &payment_flow.additional_headers {
            
            for (key, value) in additional_headers {
                match key.as_str() {
                    "x-vault-proxy-url" => {
                        vault_proxy_url = reqwest::Url::parse(value).ok();
                    }
                    "x-ca-certificate" => {
                        ca_cert_from_header = Some(Secret::new(value.clone()));
                    }
                    _ => {
                        headers.insert(key.clone(), value.clone());
                    }
                }
            }
        }
    }
    
    // Always process connector request headers to get authentication and other necessary headers
    
    for (key, value) in &connector_request.headers {
        // Handle vault headers (but only if not already found in PaymentFlowData)
        match key.to_lowercase().as_str() {
            "x-vault-proxy-url" => {
                // Only process if not already found in PaymentFlowData
                if vault_proxy_url.is_none() {
                    let proxy_url_str = match value {
                        Maskable::Normal(val) => val.clone(),
                        Maskable::Masked(val) => val.clone().expose().to_string(),
                    };
                    vault_proxy_url = reqwest::Url::parse(&proxy_url_str).ok();
                }
            }
            "x-ca-cert" => {
                // Only process if not already found in PaymentFlowData
                if ca_cert_from_header.is_none() {
                    let ca_cert_value = match value {
                        Maskable::Normal(val) => Secret::new(val.clone()),
                        Maskable::Masked(val) => Secret::new(val.clone().expose().to_string()),
                    };
                    ca_cert_from_header = Some(ca_cert_value);
                }
            }
            _ => {
                // Add all other headers (including authentication headers like X-Api-Key, Content-Type, etc.)
                let header_value = match value {
                    Maskable::Normal(val) => val.clone(),
                    Maskable::Masked(val) => val.clone().expose().to_string(),
                };
                headers.insert(key.clone(), header_value);
            }
        }
    }

    let final_proxy_url = vault_proxy_url.or(fallback_proxy_url);
    let final_ca_cert = ca_cert_from_header.or_else(|| {
        connector_request.ca_certificate.as_ref().map(|cert| Secret::new(cert.clone().expose().to_string()))
    });
    
    // Convert proxy URL to string for injector
    let injector_proxy_url = final_proxy_url.as_ref().map(|url| {
        url.to_string()
    });
    
    // Process certificates for injector compatibility
    let (processed_client_cert, processed_client_key) = match (&connector_request.certificate, &connector_request.certificate_key) {
        (Some(cert), Some(key)) => {
            match process_client_certificate_for_injector(cert, key) {
                Ok((processed_cert, processed_key)) => {
                    (
                        Some(processed_cert.expose().to_string()),
                        Some(processed_key.expose().to_string())
                    )
                }
                Err(_) => {
                    (
                        connector_request.certificate.as_ref().map(|c| c.clone().expose().to_string()),
                        connector_request.certificate_key.as_ref().map(|k| k.clone().expose().to_string())
                    )
                }
            }
        }
        _ => {
            (
                connector_request.certificate.as_ref().map(|c| c.clone().expose().to_string()),
                connector_request.certificate_key.as_ref().map(|k| k.clone().expose().to_string())
            )
        }
    };
    
    let processed_ca_cert = match &final_ca_cert {
        Some(ca_cert) => {
            match process_certificate_for_injector(ca_cert) {
                Ok(processed_cert) => {
                    Some(processed_cert.expose().to_string())
                }
                Err(_) => {
                    Some(ca_cert.clone().expose().to_string())
                }
            }
        }
        None => None
    };
    
    // Create injector headers using hyperswitch_masking::Secret
    let injector_headers: HashMap<String, Secret<String>> = headers
        .into_iter()
        .map(|(k, v)| {
            (k, Secret::new(v))
        })
        .collect();
    
    let connection_config = ConnectionConfig {
        base_url,
        endpoint_path,
        http_method,
        headers: injector_headers,
        proxy_url: injector_proxy_url.map(Secret::new),
        client_cert: processed_client_cert.map(Secret::new),
        client_key: processed_client_key.map(Secret::new),
        ca_cert: processed_ca_cert.map(Secret::new),
        insecure: None,
        cert_password: None,
        cert_format: None,
        max_response_size: None,
    };

    let injector_request = InjectorRequest {
        token_data: injector_token_data,
        connector_payload,
        connection_config,
    };
    
    Ok(injector_request)
}

#[derive(Debug)]
pub struct EventProcessingParams<'a> {
    pub connector_name: &'a str,
    pub service_name: &'a str,
    pub flow_name: FlowName,
    pub event_config: &'a EventConfig,
    pub raw_request_data: Option<SecretSerdeValue>,
    pub request_id: &'a str,
}

#[tracing::instrument(
    name = "execute_connector_processing_step",
    skip_all,
    fields(
        request.headers = Empty,
        request.body = Empty,
        request.url = Empty,
        request.method = Empty,
        response.body = Empty,
        response.headers = Empty,
        response.error_message = Empty,
        response.status_code = Empty,
        message_ = "Golden Log Line (outgoing)",
        latency = Empty,
    )
)]
pub async fn execute_connector_processing_step<T, F, ResourceCommonData, Req, Resp>(
    proxy: &Proxy,
    connector: BoxedConnectorIntegrationV2<'static, F, ResourceCommonData, Req, Resp>,
    router_data: RouterDataV2<F, ResourceCommonData, Req, Resp>,
    all_keys_required: Option<bool>,
    event_params: EventProcessingParams<'_>,
    token_data: Option<TokenData>,
) -> CustomResult<RouterDataV2<F, ResourceCommonData, Req, Resp>, ConnectorError>
where
    F: Clone + 'static,
    T: FlowIntegrity,
    Req: Clone + 'static + std::fmt::Debug + GetIntegrityObject<T> + CheckIntegrity<Req, T>,
    Resp: Clone + 'static + std::fmt::Debug,
    ResourceCommonData: Clone
        + 'static
        + RawConnectorResponse
        + ConnectorResponseHeaders
        + ConnectorRequestReference,
{
    let start = tokio::time::Instant::now();
    let connector_request = connector.build_request_v2(&router_data)?;

    let headers = connector_request
        .as_ref()
        .map(|connector_request| connector_request.headers.clone())
        .unwrap_or_default();
    tracing::info!(?headers, "headers of connector request");

    let masked_headers = headers
        .iter()
        .fold(serde_json::Map::new(), |mut acc, (k, v)| {
            let value = match v {
                Maskable::Masked(_) => {
                    serde_json::Value::String("*** alloc::string::String ***".to_string())
                }
                Maskable::Normal(iv) => serde_json::Value::String(iv.to_owned()),
            };
            acc.insert(k.clone(), value);
            acc
        });
    let headers = serde_json::Value::Object(masked_headers);
    tracing::Span::current().record("request.headers", tracing::field::display(&headers));
    let router_data = router_data.clone();

    let req = connector_request.as_ref().map(|connector_request| {
        let masked_request = match connector_request.body.as_ref() {
            Some(request) => match request {
                RequestContent::Json(i)
                | RequestContent::FormUrlEncoded(i)
                | RequestContent::Xml(i) => (**i)
                    .masked_serialize()
                    .unwrap_or(json!({ "error": "failed to mask serialize connector request"})),
                RequestContent::FormData(_) => json!({"request_type": "FORM_DATA"}),
                RequestContent::RawBytes(_) => json!({"request_type": "RAW_BYTES"}),
            },
            None => serde_json::Value::Null,
        };
        tracing::info!(request=?masked_request, "request of connector");
        tracing::Span::current().record("request.body", tracing::field::display(&masked_request));

        masked_request
    });

    let result = match connector_request {
        Some(request) => {
            let url = request.url.clone();
            let method = request.method;
            metrics::EXTERNAL_SERVICE_TOTAL_API_CALLS
                .with_label_values(&[
                    &method.to_string(),
                    event_params.service_name,
                    event_params.connector_name,
                ])
                .inc();
            let external_service_start_latency = tokio::time::Instant::now();
            tracing::Span::current().record("request.url", tracing::field::display(&url));
            tracing::Span::current().record("request.method", tracing::field::display(method));
            let request_id = event_params.request_id.to_string();
            
            
            let response = if let Some(token_data) = token_data {
                let injector_request = convert_to_injector_request(&request, &token_data, proxy, &router_data.resource_common_data)
                    .change_context(ConnectorError::RequestEncodingFailed)?;
                
                // New injector handles HTTP request internally and returns JSON response
                let injector_response = injector_core(injector_request)
                    .await
                    .change_context(ConnectorError::RequestEncodingFailed)?;
                
                // Convert JSON response to our Response format
                let response_bytes = serde_json::to_vec(&injector_response)
                    .map_err(|_| ConnectorError::ResponseHandlingFailed)?;
                
                Ok(Ok(Response {
                    headers: None, // Injector handles headers internally
                    response: response_bytes.into(),
                    status_code: 200, // Injector success implies 200
                }))
            } else {
                call_connector_api(proxy, request, "execute_connector_processing_step")
                    .await
                    .change_context(ConnectorError::RequestEncodingFailed)
                    .inspect_err(|err| {
                        info_log(
                            "NETWORK_ERROR",
                            &json!(format!(
                                "Failed getting response from connector. Error: {:?}",
                                err
                            )),
                        );
                    })
            };
            let external_service_elapsed = external_service_start_latency.elapsed();
            metrics::EXTERNAL_SERVICE_API_CALLS_LATENCY
                .with_label_values(&[
                    &method.to_string(),
                    event_params.service_name,
                    event_params.connector_name,
                ])
                .observe(external_service_elapsed.as_secs_f64());
            tracing::info!(?response, "response from connector");

            match &response {
                Ok(Ok(body)) => {
                    let res_body = serde_json::from_slice::<serde_json::Value>(&body.response).ok();

                    let latency =
                        u64::try_from(external_service_elapsed.as_millis()).unwrap_or(u64::MAX); // Convert to milliseconds
                    let status_code = body.status_code;

                    // Emit success response event
                    tokio::spawn({
                        let connector_name = event_params.connector_name.to_string();
                        let event_config = event_params.event_config.clone();
                        let request_data = req.clone();
                        let response_data = res_body.clone();
                        let raw_request_data_clone = event_params.raw_request_data.clone();
                        let url_clone = url.clone();
                        let flow_name = event_params.flow_name;

                        async move {
                            let event = Event {
                                request_id: request_id.to_string(),
                                timestamp: chrono::Utc::now().timestamp().into(),
                                flow_type: flow_name,
                                connector: connector_name.clone(),
                                url: Some(url_clone),
                                stage: EventStage::ConnectorCall,
                                latency: Some(latency),
                                status_code: Some(status_code),
                                request_data: raw_request_data_clone,
                                connector_request_data: request_data.map(Secret::new),
                                connector_response_data: response_data.map(Secret::new),
                                additional_fields: std::collections::HashMap::new(),
                            };

                            match emit_event_with_config(event, &event_config).await {
                                Ok(true) => tracing::info!(
                                    "Successfully published response event for {}",
                                    connector_name
                                ),
                                Ok(false) => tracing::info!(
                                    "Event publishing is disabled for {}",
                                    connector_name
                                ),
                                Err(e) => {
                                    tracing::error!("Failed to publish response event: {:?}", e)
                                }
                            }
                        }
                    });
                }
                Ok(Err(error_body)) => {
                    let error_res_body =
                        serde_json::from_slice::<serde_json::Value>(&error_body.response).ok();

                    let latency =
                        u64::try_from(external_service_elapsed.as_millis()).unwrap_or(u64::MAX);
                    let status_code = error_body.status_code;

                    // Emit error response event
                    tokio::spawn({
                        let connector_name = event_params.connector_name.to_string();
                        let event_config = event_params.event_config.clone();
                        let request_data = req.clone();
                        let response_data = error_res_body.clone();
                        let raw_request_data_clone = event_params.raw_request_data.clone();
                        let url_clone = url.clone();
                        let flow_name = event_params.flow_name;

                        async move {
                            let event = Event {
                                request_id: request_id.to_string(),
                                timestamp: chrono::Utc::now().timestamp().into(),
                                flow_type: flow_name,
                                connector: connector_name.clone(),
                                url: Some(url_clone),
                                stage: EventStage::ConnectorCall,
                                latency: Some(latency),
                                status_code: Some(status_code),
                                request_data: raw_request_data_clone,
                                connector_request_data: request_data.map(Secret::new),
                                connector_response_data: response_data.map(Secret::new),
                                additional_fields: std::collections::HashMap::new(),
                            };

                            match emit_event_with_config(event, &event_config).await {
                                Ok(true) => tracing::info!(
                                    "Successfully published error response event for {}",
                                    connector_name
                                ),
                                Ok(false) => tracing::info!(
                                    "Event publishing is disabled for {}",
                                    connector_name
                                ),
                                Err(e) => tracing::error!(
                                    "Failed to publish error response event: {:?}",
                                    e
                                ),
                            }
                        }
                    });
                }
                Err(network_error) => {
                    tracing::error!(
                        "Network error occurred while calling connector {}: {:?}",
                        event_params.connector_name,
                        network_error
                    );

                    // Emit network error event
                    tokio::spawn({
                        let connector_name = event_params.connector_name.to_string();
                        let event_config = event_params.event_config.clone();
                        let request_data = req.clone();
                        let raw_request_data_clone = event_params.raw_request_data.clone();
                        let url_clone = url.clone();
                        let flow_name = event_params.flow_name;

                        async move {
                            let event = Event {
                                request_id: request_id.to_string(),
                                timestamp: chrono::Utc::now().timestamp().into(),
                                flow_type: flow_name,
                                connector: connector_name.clone(),
                                url: Some(url_clone),
                                stage: EventStage::ConnectorCall,
                                latency: None,
                                status_code: None,
                                request_data: raw_request_data_clone,
                                connector_request_data: request_data.map(Secret::new),
                                connector_response_data: None,
                                additional_fields: std::collections::HashMap::new(),
                            };

                            match emit_event_with_config(event, &event_config).await {
                                Ok(true) => tracing::info!(
                                    "Successfully published network error event for {}",
                                    connector_name
                                ),
                                Ok(false) => tracing::info!(
                                    "Event publishing is disabled for {}",
                                    connector_name
                                ),
                                Err(e) => tracing::error!(
                                    "Failed to publish network error event: {:?}",
                                    e
                                ),
                            }
                        }
                    });
                }
            }

            match response {
                Ok(body) => {
                    let response = match body {
                        Ok(body) => {
                            let status_code = body.status_code;
                            tracing::Span::current()
                                .record("status_code", tracing::field::display(status_code));
                            if let Ok(response) = parse_json_with_bom_handling(&body.response) {
                                let headers = body.headers.clone().unwrap_or_default();
                                let map = headers.iter().fold(
                                    serde_json::Map::new(),
                                    |mut acc, (left, right)| {
                                        let header_value = if right.is_sensitive() {
                                            serde_json::Value::String(
                                                "*** alloc::string::String ***".to_string(),
                                            )
                                        } else if let Ok(x) = right.to_str() {
                                            serde_json::Value::String(x.to_string())
                                        } else {
                                            return acc;
                                        };
                                        acc.insert(left.as_str().to_string(), header_value);
                                        acc
                                    },
                                );
                                let header_map = serde_json::Value::Object(map);
                                tracing::Span::current().record(
                                    "response.headers",
                                    tracing::field::display(header_map),
                                );
                                tracing::Span::current().record("response.body", tracing::field::display(response.masked_serialize().unwrap_or(json!({ "error": "failed to mask serialize connector response"}))));
                            }

                            let is_source_verified = connector.verify(&router_data, interfaces::verification::ConnectorSourceVerificationSecrets::AuthHeaders(router_data.connector_auth_type.clone()), &body.response)?;

                            if !is_source_verified {
                                return Err(error_stack::report!(
                                    ConnectorError::SourceVerificationFailed
                                ));
                            }

                            // Set raw_connector_response BEFORE calling the transformer
                            let mut updated_router_data = router_data.clone();
                            if all_keys_required.unwrap_or(true) {
                                let raw_response_string =
                                    strip_bom_and_convert_to_string(&body.response);
                                updated_router_data
                                    .resource_common_data
                                    .set_raw_connector_response(raw_response_string);

                                // Set response headers if available
                                updated_router_data
                                    .resource_common_data
                                    .set_connector_response_headers(body.headers.clone());
                            }

                            let handle_response_result = connector.handle_response_v2(
                                &updated_router_data,
                                None,
                                body.clone(),
                            );

                            match handle_response_result {
                                Ok(data) => {
                                    tracing::info!("Transformer completed successfully");
                                    Ok(data)
                                }
                                Err(err) => Err(err),
                            }?
                        }
                        Err(body) => {
                            metrics::EXTERNAL_SERVICE_API_CALLS_ERRORS
                                .with_label_values(&[
                                    &method.to_string(),
                                    event_params.service_name,
                                    event_params.connector_name,
                                    body.status_code.to_string().as_str(),
                                ])
                                .inc();

                            // Set raw connector response for error cases BEFORE processing error
                            let mut updated_router_data = router_data.clone();
                            if all_keys_required.unwrap_or(true) {
                                let raw_response_string =
                                    strip_bom_and_convert_to_string(&body.response);
                                updated_router_data
                                    .resource_common_data
                                    .set_raw_connector_response(raw_response_string);
                                updated_router_data
                                    .resource_common_data
                                    .set_connector_response_headers(body.headers.clone());
                            }

                            let error = match body.status_code {
                                500..=511 => {
                                    connector.get_5xx_error_response(body.clone(), None)?
                                }
                                _ => connector.get_error_response_v2(body.clone(), None)?,
                            };
                            tracing::Span::current().record(
                                "response.error_message",
                                tracing::field::display(&error.message),
                            );
                            tracing::Span::current().record(
                                "response.status_code",
                                tracing::field::display(error.status_code),
                            );
                            updated_router_data.response = Err(error);
                            updated_router_data
                        }
                    };
                    Ok(response)
                }
                Err(err) => {
                    tracing::Span::current().record("url", tracing::field::display(url));
                    Err(err.change_context(ConnectorError::ProcessingStepFailed(None)))
                }
            }
        }
        None => Ok(router_data),
    };

    let result_with_integrity_check = match result {
        Ok(data) => {
            data.request
                .check_integrity(&data.request.clone(), None)
                .map_err(|err| ConnectorError::IntegrityCheckFailed {
                    field_names: err.field_names,
                    connector_transaction_id: err.connector_transaction_id,
                })?;
            Ok(data)
        }
        Err(err) => Err(err),
    };

    let elapsed = start.elapsed().as_millis();
    if let Some(req) = req {
        tracing::Span::current().record("request.body", tracing::field::display(req));
    }
    tracing::Span::current().record("latency", elapsed);
    tracing::info!(tag = ?Tag::OutgoingApi, log_type = "api", "Outgoing Request completed");
    result_with_integrity_check
}

pub enum ApplicationResponse<R> {
    Json(R),
}

pub type CustomResult<T, E> = error_stack::Result<T, E>;
pub type RouterResult<T> = CustomResult<T, ApiErrorResponse>;
pub type RouterResponse<T> = CustomResult<ApplicationResponse<T>, ApiErrorResponse>;

pub async fn call_connector_api(
    proxy: &Proxy,
    request: Request,
    _flow_name: &str,
) -> CustomResult<Result<Response, Response>, ApiClientError> {
    let url =
        reqwest::Url::parse(&request.url).change_context(ApiClientError::UrlEncodingFailed)?;

    let should_bypass_proxy = proxy.bypass_proxy_urls.contains(&url.to_string());

    let client = create_client(
        proxy,
        should_bypass_proxy,
        request.certificate,
        request.certificate_key,
    )?;

    let headers = request.headers.construct_header_map()?;

    // Process and log the request body based on content type
    let request = {
        match request.method {
            Method::Get => client.get(url),
            Method::Post => {
                let client = client.post(url);
                match request.body {
                    Some(RequestContent::Json(payload)) => client.json(&payload),
                    Some(RequestContent::FormUrlEncoded(payload)) => client.form(&payload),
                    Some(RequestContent::Xml(payload)) => {
                        // Use serde_json for XML conversion instead of quick_xml
                        let body = serde_json::to_string(&payload)
                            .change_context(ApiClientError::UrlEncodingFailed)?;
                        client.body(body).header("Content-Type", "application/xml")
                    }
                    Some(RequestContent::FormData(form)) => client.multipart(form),
                    _ => client,
                }
            }
            _ => client.post(url),
        }
        .add_headers(headers)
    };
    let send_request = async {
        request.send().await.map_err(|error| {
            let api_error = match error {
                error if error.is_timeout() => ApiClientError::RequestTimeoutReceived,
                _ => ApiClientError::RequestNotSent(error.to_string()),
            };
            info_log(
                "REQUEST_FAILURE",
                &json!(format!("Unable to send request to connector.",)),
            );
            report!(api_error)
        })
    };

    let response = send_request.await;

    handle_response(response).await
}

pub fn create_client(
    proxy_config: &Proxy,
    should_bypass_proxy: bool,
    _client_certificate: Option<Secret<String>>,
    _client_certificate_key: Option<Secret<String>>,
) -> CustomResult<Client, ApiClientError> {
    get_base_client(proxy_config, should_bypass_proxy)
    // match (client_certificate, client_certificate_key) {
    //     (Some(encoded_certificate), Some(encoded_certificate_key)) => {
    //         let client_builder = get_client_builder(proxy_config, should_bypass_proxy)?;

    //         let identity = create_identity_from_certificate_and_key(
    //             encoded_certificate.clone(),
    //             encoded_certificate_key,
    //         )?;
    //         let certificate_list = create_certificate(encoded_certificate)?;
    //         let client_builder = certificate_list
    //             .into_iter()
    //             .fold(client_builder, |client_builder, certificate| {
    //                 client_builder.add_root_certificate(certificate)
    //             });
    //         client_builder
    //             .identity(identity)
    //             .use_rustls_tls()
    //             .build()
    //             .change_context(ApiClientError::ClientConstructionFailed)
    //             .inspect_err(|err| {
    //                 info_log(
    //                     "ERROR",
    //                     &json!(format!(
    //                         "Failed to construct client with certificate and certificate key. Error: {:?}",
    //                         err
    //                     )),
    //                 );
    //             })
    //     }
    //     _ => ,
    // }
}

static NON_PROXIED_CLIENT: OnceCell<Client> = OnceCell::new();
static PROXIED_CLIENT: OnceCell<Client> = OnceCell::new();

fn get_base_client(
    proxy_config: &Proxy,
    should_bypass_proxy: bool,
) -> CustomResult<Client, ApiClientError> {
    Ok(if should_bypass_proxy
        || (proxy_config.http_url.is_none() && proxy_config.https_url.is_none())
    {
        &NON_PROXIED_CLIENT
    } else {
        &PROXIED_CLIENT
    }
    .get_or_try_init(|| {
        get_client_builder(proxy_config, should_bypass_proxy)?
            .build()
            .change_context(ApiClientError::ClientConstructionFailed)
            .inspect_err(|err| {
                info_log(
                    "ERROR",
                    &json!(format!("Failed to construct base client. Error: {:?}", err)),
                );
            })
    })?
    .clone())
}

fn get_client_builder(
    proxy_config: &Proxy,
    should_bypass_proxy: bool,
) -> CustomResult<reqwest::ClientBuilder, ApiClientError> {
    let mut client_builder = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .pool_idle_timeout(Duration::from_secs(
            proxy_config
                .idle_pool_connection_timeout
                .unwrap_or_default(),
        ));

    if should_bypass_proxy {
        return Ok(client_builder);
    }

    // Proxy all HTTPS traffic through the configured HTTPS proxy
    if let Some(url) = proxy_config.https_url.as_ref() {
        client_builder = client_builder.proxy(
            reqwest::Proxy::https(url)
                .change_context(ApiClientError::InvalidProxyConfiguration)
                .inspect_err(|err| {
                    info_log(
                        "PROXY_ERROR",
                        &json!(format!("HTTPS proxy configuration error. Error: {:?}", err)),
                    );
                })?,
        );
    }

    // Proxy all HTTP traffic through the configured HTTP proxy
    if let Some(url) = proxy_config.http_url.as_ref() {
        client_builder = client_builder.proxy(
            reqwest::Proxy::http(url)
                .change_context(ApiClientError::InvalidProxyConfiguration)
                .inspect_err(|err| {
                    info_log(
                        "PROXY_ERROR",
                        &json!(format!("HTTP proxy configuration error. Error: {:?}", err)),
                    );
                })?,
        );
    }

    Ok(client_builder)
}

// pub fn create_identity_from_certificate_and_key(
//     encoded_certificate: hyperswitch_masking::Secret<String>,
//     encoded_certificate_key: hyperswitch_masking::Secret<String>,
// ) -> Result<reqwest::Identity, error_stack::Report<ApiClientError>> {
//     let decoded_certificate = BASE64_ENGINE
//         .decode(encoded_certificate.expose())
//         .change_context(ApiClientError::CertificateDecodeFailed)?;

//     let decoded_certificate_key = BASE64_ENGINE
//         .decode(encoded_certificate_key.expose())
//         .change_context(ApiClientError::CertificateDecodeFailed)?;

//     let certificate = String::from_utf8(decoded_certificate)
//         .change_context(ApiClientError::CertificateDecodeFailed)?;

//     let certificate_key = String::from_utf8(decoded_certificate_key)
//         .change_context(ApiClientError::CertificateDecodeFailed)?;

//     let key_chain = format!("{}{}", certificate_key, certificate);
//     reqwest::Identity::from_pem(key_chain.as_bytes())
//         .change_context(ApiClientError::CertificateDecodeFailed)
// }

// pub fn create_certificate(
//     encoded_certificate: hyperswitch_masking::Secret<String>,
// ) -> Result<Vec<reqwest::Certificate>, error_stack::Report<ApiClientError>> {
//     let decoded_certificate = BASE64_ENGINE
//         .decode(encoded_certificate.expose())
//         .change_context(ApiClientError::CertificateDecodeFailed)?;

//     let certificate = String::from_utf8(decoded_certificate)
//         .change_context(ApiClientError::CertificateDecodeFailed)?;
//     reqwest::Certificate::from_pem_bundle(certificate.as_bytes())
//         .change_context(ApiClientError::CertificateDecodeFailed)
// }

async fn handle_response(
    response: CustomResult<reqwest::Response, ApiClientError>,
) -> CustomResult<Result<Response, Response>, ApiClientError> {
    response
        .async_map(|resp| async {
            let status_code = resp.status().as_u16();
            let headers = Some(resp.headers().to_owned());
            match status_code {
                200..=202 | 302 | 204 => {
                    let response = resp
                        .bytes()
                        .await
                        .change_context(ApiClientError::ResponseDecodingFailed)?;
                    Ok(Ok(Response {
                        headers,
                        response,
                        status_code,
                    }))
                }
                500..=599 => {
                    let bytes = resp.bytes().await.map_err(|error| {
                        report!(error).change_context(ApiClientError::ResponseDecodingFailed)
                    })?;

                    Ok(Err(Response {
                        headers,
                        response: bytes,
                        status_code,
                    }))
                }

                400..=499 => {
                    let bytes = resp.bytes().await.map_err(|error| {
                        report!(error).change_context(ApiClientError::ResponseDecodingFailed)
                    })?;

                    Ok(Err(Response {
                        headers,
                        response: bytes,
                        status_code,
                    }))
                }
                _ => {
                    info_log(
                        "UNEXPECTED_RESPONSE",
                        &json!("Unexpected response from server."),
                    );
                    Err(report!(ApiClientError::UnexpectedServerResponse))
                }
            }
        })
        .await?
}

/// Helper function to remove BOM from response bytes and convert to string
fn strip_bom_and_convert_to_string(response_bytes: &[u8]) -> Option<String> {
    String::from_utf8(response_bytes.to_vec()).ok().map(|s| {
        // Remove BOM if present (UTF-8 BOM is 0xEF, 0xBB, 0xBF)
        if s.starts_with('\u{FEFF}') {
            s.trim_start_matches('\u{FEFF}').to_string()
        } else {
            s
        }
    })
}

/// Helper function to parse JSON from response bytes with BOM handling
fn parse_json_with_bom_handling(
    response_bytes: &[u8],
) -> Result<serde_json::Value, serde_json::Error> {
    // Try direct parsing first (most common case)
    match serde_json::from_slice::<serde_json::Value>(response_bytes) {
        Ok(value) => Ok(value),
        Err(_) => {
            // If direct parsing fails, try after removing BOM
            let cleaned_response = if response_bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
                // UTF-8 BOM detected, remove it
                #[allow(clippy::indexing_slicing)]
                &response_bytes[3..]
            } else {
                response_bytes
            };
            serde_json::from_slice::<serde_json::Value>(cleaned_response)
        }
    }
}

pub(super) trait HeaderExt {
    fn construct_header_map(self) -> CustomResult<reqwest::header::HeaderMap, ApiClientError>;
}

impl HeaderExt for Headers {
    fn construct_header_map(self) -> CustomResult<reqwest::header::HeaderMap, ApiClientError> {
        use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

        self.into_iter().try_fold(
            HeaderMap::new(),
            |mut header_map, (header_name, header_value)| {
                let header_name = HeaderName::from_str(&header_name)
                    .change_context(ApiClientError::HeaderMapConstructionFailed)?;
                let header_value = header_value.into_inner();
                let header_value = HeaderValue::from_str(&header_value)
                    .change_context(ApiClientError::HeaderMapConstructionFailed)?;
                header_map.append(header_name, header_value);
                Ok(header_map)
            },
        )
    }
}

pub(super) trait RequestBuilderExt {
    fn add_headers(self, headers: reqwest::header::HeaderMap) -> Self;
}

impl RequestBuilderExt for reqwest::RequestBuilder {
    fn add_headers(mut self, headers: reqwest::header::HeaderMap) -> Self {
        self = self.headers(headers);
        self
    }
}

#[derive(Debug, Default, serde::Deserialize, Clone, strum::EnumString)]
pub enum Tag {
    /// General.
    #[default]
    General,
    /// Redis: get.
    RedisGet,
    /// Redis: set.
    RedisSet,
    /// API: incoming web request.
    ApiIncomingRequest,
    /// API: outgoing web request body.
    ApiOutgoingRequestBody,
    /// API: outgoingh headers
    ApiOutgoingRequestHeaders,
    /// End Request
    EndRequest,
    /// Call initiated to connector.
    InitiatedToConnector,
    /// Incoming response
    IncomingApi,
    /// Api Outgoing Request
    OutgoingApi,
}

#[inline]
pub fn debug_log(action: &str, message: &serde_json::Value) {
    tracing::debug!(tags = %action, json_value= %message);
}

#[inline]
pub fn info_log(action: &str, message: &serde_json::Value) {
    tracing::info!(tags = %action, json_value= %message);
}

#[inline]
pub fn error_log(action: &str, message: &serde_json::Value) {
    tracing::error!(tags = %action, json_value= %message);
}

#[inline]
pub fn warn_log(action: &str, message: &serde_json::Value) {
    tracing::warn!(tags = %action, json_value= %message);
}
