use std::{str::FromStr, time::Duration};

use common_utils::ext_traits::AsyncExt;
// use base64::engine::Engine;
use common_utils::{
    // consts::BASE64_ENGINE,
    request::{Method, Request, RequestContent},
};
use domain_types::{
    connector_types::{ConnectorResponseHeaders, RawConnectorResponse},
    errors::{ApiClientError, ApiErrorResponse, ConnectorError},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Proxy,
};

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
// use base64::engine::Engine;
use crate::shared_metrics as metrics;
use common_utils::dapr::{emit_event, EventStage};
use error_stack::{report, ResultExt};
use interfaces::{
    connector_integration_v2::BoxedConnectorIntegrationV2,
    integrity::{CheckIntegrity, FlowIntegrity, GetIntegrityObject},
};
use masking::{ErasedMaskSerialize, Maskable};
use once_cell::sync::OnceCell;
use reqwest::Client;
use serde_json::{json, Value};
use tracing::field::Empty;

pub type Headers = std::collections::HashSet<(String, Maskable<String>)>;

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
    connector_name: &str,
    service_name: &str,
    flow_name: common_utils::dapr::FlowName,
) -> CustomResult<
    RouterDataV2<F, ResourceCommonData, Req, Resp>,
    domain_types::errors::ConnectorError,
>
where
    F: Clone + 'static,
    T: FlowIntegrity,
    Req: Clone + 'static + std::fmt::Debug + GetIntegrityObject<T> + CheckIntegrity<Req, T>,
    Resp: Clone + 'static + std::fmt::Debug,
    ResourceCommonData: Clone + 'static + RawConnectorResponse + ConnectorResponseHeaders + ConnectorRequestReference,
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
            let ref_id = Some(
                router_data
                    .resource_common_data
                    .get_connector_request_reference_id()
                    .to_string(),
            );

            let url = request.url.clone();
            let method = request.method;
            metrics::EXTERNAL_SERVICE_TOTAL_API_CALLS
                .with_label_values(&[&method.to_string(), service_name, connector_name])
                .inc();
            let external_service_start_latency = tokio::time::Instant::now();
            tracing::Span::current().record("request.url", tracing::field::display(&url));
            tracing::Span::current().record("request.method", tracing::field::display(method));
            let response = call_connector_api(proxy, request, "execute_connector_processing_step")
                .await
                .change_context(domain_types::errors::ConnectorError::RequestEncodingFailed)
                .inspect_err(|err| {
                    info_log(
                        "NETWORK_ERROR",
                        &json!(format!(
                            "Failed getting response from connector. Error: {:?}",
                            err
                        )),
                    );
                });
            let external_service_elapsed = external_service_start_latency.elapsed().as_secs_f64();
            metrics::EXTERNAL_SERVICE_API_CALLS_LATENCY
                .with_label_values(&[&method.to_string(), service_name, connector_name])
                .observe(external_service_elapsed);
            tracing::info!(?response, "response from connector");

            let ref_id_clone = ref_id.clone();

            if let Some(ref_id) = ref_id_clone {
                match &response {
                    Ok(Ok(body)) => {
                        let connector_txn_id = Some(ref_id.clone());

                        let res_body =
                            serde_json::from_slice::<serde_json::Value>(&body.response).ok();

                        let res_headers = body.headers.as_ref().map(|headers| {
                            serde_json::Value::Object(headers.iter().fold(
                                serde_json::Map::new(),
                                |mut acc, (left, right)| {
                                    if let Ok(x) = right.to_str() {
                                        acc.insert(
                                            left.as_str().to_string(),
                                            serde_json::Value::String(x.to_string()),
                                        );
                                    }
                                    acc
                                },
                            ))
                        });

                        let latency = external_service_elapsed as u64 * 1000; // Convert to milliseconds
                        let status_code = body.status_code;

                        // Emit success response event
                        let connector_name_clone = connector_name.to_string();
                        let url_clone = url.clone();
                        let flow_name_clone = flow_name;
                        let ref_id_for_event = ref_id.clone();
                        let final_connector_txn_id = connector_txn_id.or(Some(ref_id.clone()));

                        tokio::spawn(async move {
                            let result = emit_event(
                                flow_name_clone,
                                &connector_name_clone,
                                EventStage::ResponseReceived,
                                &url_clone,
                                Some(ref_id_for_event),
                                final_connector_txn_id,
                                None,
                                res_body,
                                None,
                                res_headers,
                                Some(latency),
                                Some(status_code),
                                None,
                                None,
                            )
                            .await;

                            match result {
                                Ok(_) => tracing::info!(
                                    "Successfully published outgoing response event for {}",
                                    connector_name_clone
                                ),
                                Err(e) => tracing::error!(
                                    "Failed to publish outgoing response event: {:?}",
                                    e
                                ),
                            }
                        });
                    }
                    Ok(Err(error_body)) => {
                        let error_res_body =
                            serde_json::from_slice::<serde_json::Value>(&error_body.response).ok();

                        let res_headers = error_body.headers.as_ref().map(|headers| {
                            serde_json::Value::Object(headers.iter().fold(
                                serde_json::Map::new(),
                                |mut acc, (left, right)| {
                                    if let Ok(x) = right.to_str() {
                                        acc.insert(
                                            left.as_str().to_string(),
                                            serde_json::Value::String(x.to_string()),
                                        );
                                    }
                                    acc
                                },
                            ))
                        });

                        let latency = external_service_elapsed as u64 * 1000;
                        let status_code = error_body.status_code;

                        let error_code = if let Some(json_body) = &error_res_body {
                            json_body
                                .get("error_code")
                                .or_else(|| json_body.get("code"))
                                .and_then(|v| v.as_str())
                                .map(String::from)
                        } else {
                            None
                        };

                        let error_reason = if let Some(json_body) = &error_res_body {
                            json_body
                                .get("message")
                                .or_else(|| json_body.get("error_message"))
                                .and_then(|v| v.as_str())
                                .map(String::from)
                        } else {
                            None
                        };

                        // Emit error response event
                        let connector_name_clone = connector_name.to_string();
                        let url_clone = url.clone();
                        let flow_name_clone = flow_name;
                        let ref_id_for_event = ref_id.clone();
                        let ref_id_clone = ref_id.clone();

                        tokio::spawn(async move {
                            let result = emit_event(
                                flow_name_clone,
                                &connector_name_clone,
                                EventStage::Error,
                                &url_clone,
                                Some(ref_id_for_event),
                                Some(ref_id_clone),
                                None,
                                error_res_body,
                                None,
                                res_headers,
                                Some(latency),
                                Some(status_code),
                                error_code,
                                error_reason,
                            )
                            .await;

                            match result {
                                Ok(_) => tracing::info!(
                                    "Successfully published outgoing error response event for {}",
                                    connector_name_clone
                                ),
                                Err(e) => tracing::error!(
                                    "Failed to publish outgoing error response event: {:?}",
                                    e
                                ),
                            }
                        });
                    }
                    Err(network_error) => {
                        tracing::error!(
                            "Network error occurred while calling connector {}: {:?}",
                            connector_name,
                            network_error
                        );

                        // Emit network error event
                        let connector_name_clone = connector_name.to_string();
                        let url_clone = url.clone();
                        let flow_name_clone = flow_name;
                        let ref_id_for_event = ref_id.clone();
                        let ref_id_clone = ref_id.clone();
                        let error_message =
                            format!("Failed to get response from connector: {network_error:?}");

                        tokio::spawn(async move {
                            let result = emit_event(
                                flow_name_clone,
                                &connector_name_clone,
                                EventStage::Error,
                                &url_clone,
                                Some(ref_id_for_event),
                                Some(ref_id_clone),
                                None,
                                None,
                                None,
                                None,
                                None,
                                None,
                                Some("NETWORK_ERROR".to_string()),
                                Some(error_message),
                            )
                            .await;

                            match result {
                                Ok(_) => tracing::info!(
                                    "Successfully published outgoing network error event for {}",
                                    connector_name_clone
                                ),
                                Err(e) => tracing::error!(
                                    "Failed to publish outgoing network error event: {:?}",
                                    e
                                ),
                            }
                        });
                    }
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
                                    domain_types::errors::ConnectorError::SourceVerificationFailed
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
                                    service_name,
                                    connector_name,
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
                    Err(err.change_context(
                        domain_types::errors::ConnectorError::ProcessingStepFailed(None),
                    ))
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
    _client_certificate: Option<masking::Secret<String>>,
    _client_certificate_key: Option<masking::Secret<String>>,
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
pub fn debug_log(action: &str, message: &Value) {
    tracing::debug!(tags = %action, json_value= %message);
}

#[inline]
pub fn info_log(action: &str, message: &Value) {
    tracing::info!(tags = %action, json_value= %message);
}

#[inline]
pub fn error_log(action: &str, message: &Value) {
    tracing::error!(tags = %action, json_value= %message);
}

#[inline]
pub fn warn_log(action: &str, message: &Value) {
    tracing::warn!(tags = %action, json_value= %message);
}
