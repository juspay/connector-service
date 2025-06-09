use domain_types::{errors::ApiClientError, types::Proxy};
// use base64::engine::Engine;
use error_stack::{report, ResultExt};
use hyperswitch_common_utils::{
    // consts::BASE64_ENGINE,
    ext_traits::AsyncExt,
    request::{Method, Request, RequestContent},
};
use hyperswitch_domain_models::{
    errors::api_error_response::ApiErrorResponse, router_data_v2::RouterDataV2,
};
use hyperswitch_masking::{ErasedMaskSerialize, Maskable};
use once_cell::sync::OnceCell;
use reqwest::Client;
use serde_json::json;
use std::{str::FromStr, time::Duration};
use tracing::{field::Empty, info_span};

use hyperswitch_interfaces::{
    connector_integration_v2::BoxedConnectorIntegrationV2, errors::ConnectorError, types::Response,
};
use serde_json::Value;

pub type Headers = std::collections::HashSet<(String, Maskable<String>)>;

pub async fn execute_connector_processing_step<F, ResourceCommonData, Req, Resp>(
    proxy: &Proxy,
    connector: BoxedConnectorIntegrationV2<'static, F, ResourceCommonData, Req, Resp>,
    router_data: RouterDataV2<F, ResourceCommonData, Req, Resp>,
) -> CustomResult<RouterDataV2<F, ResourceCommonData, Req, Resp>, ConnectorError>
where
    F: Clone + 'static,
    Req: Clone + 'static + std::fmt::Debug,
    Resp: Clone + 'static + std::fmt::Debug,
    ResourceCommonData: Clone + 'static,
{
    let span = tracing::info_span!(
        "ucs_outgoing_app_data",
        request_headers = Empty,
        request_body = Empty,
        response_headers = Empty,
        response_body = Empty,
        status_code = Empty,
        latency = Empty,
        url = Empty,
    );
    let _enter = span.enter();
    let start = tokio::time::Instant::now();
    let connector_request = connector.build_request_v2(&router_data)?;

    let headers = connector_request
        .as_ref()
        .map(|connector_request| connector_request.headers.clone())
        .unwrap_or_default();

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
    let mut router_data = router_data.clone();

    let req = connector_request.as_ref().map(|connector_request| {
        let body = connector_request.body.as_ref();
        tracing::info!("shivral ------ ");
        tracing::info!("shivral ------ {:?}", body);

        tracing::Span::current().record("body", tracing::field::debug(body));
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
        masked_request
    });
    let result = match connector_request {
        Some(request) => {
            let url = request.url.clone();
            let method = request.method.clone();
            let body = request.body.as_ref().unwrap();

            let response = call_connector_api(proxy, request, "execute_connector_processing_step")
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
                });
            tracing::info!(?response, "response from connector");

            match response {
                Ok(body) => {
                    tracing::Span::current().record("url", tracing::field::display(&url));
                    tracing::Span::current().record("method", tracing::field::display(method));

                    let response = match body {
                        Ok(body) => {
                            tracing::Span::current()
                                .record("shivral", tracing::field::debug(body.clone()));

                            let status_code = body.status_code;
                            if let Ok(response) =
                                serde_json::from_slice::<serde_json::Value>(&body.response)
                            {
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
                                tracing::Span::current()
                                    .record("response_header", tracing::field::display(header_map));
                                tracing::Span::current().record("response_body", tracing::field::display(response.masked_serialize().unwrap_or(json!({ "error": "failed to mask serialize connector response"}))));
                            }
                            tracing::Span::current()
                                .record("status_code", tracing::field::display(status_code));

                            let handle_response_result =
                                connector.handle_response_v2(&router_data, None, body.clone());

                            match handle_response_result {
                                Ok(data) => Ok(data),
                                Err(err) => Err(err),
                            }?
                        }
                        Err(body) => {
                            tracing::Span::current()
                                .record("shivral", tracing::field::debug(body.clone()));

                            let error = match body.status_code {
                                500..=511 => connector.get_5xx_error_response(body, None)?,
                                _ => connector.get_error_response_v2(body, None)?,
                            };
                            router_data.response = Err(error);
                            router_data
                        }
                    };
                    Ok(response)
                }
                Err(err) => {
                    tracing::Span::current().record("url", tracing::field::display(&url));
                    Err(err.change_context(ConnectorError::ProcessingStepFailed(None)))
                }
            }
        }
        None => Ok(router_data),
    };
    let elapsed = start.elapsed().as_millis();
    if let Some(req) = req {
        tracing::Span::current().record("request_body", tracing::field::display(req));
    }
    tracing::Span::current().record("latency", elapsed);
    tracing::Span::current().record("request_header", tracing::field::display(headers));
    tracing::info!(tag = ?Tag::OutgoingApi, log_type = "api", "Outgoing Request completed");
    result
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

    let request = {
        match request.method {
            Method::Get => client.get(url),
            Method::Post => {
                let client = client.post(url);
                match request.body {
                    Some(RequestContent::Json(payload)) => client.json(&payload),
                    Some(RequestContent::FormUrlEncoded(payload)) => {
                        tracing::info!(
                            "shivral ------ {:?}",
                            serde_urlencoded::to_string(&payload).unwrap_or_default()
                        );
                        client.form(&payload)
                    }
                    _ => client,
                }
            }
            _ => client.post(url),
        }
        .add_headers(headers)
    };

    let send_request = async {
        request.send().await.map_err(|error| {
            tracing::info!("shivral ------ {:?}", error);

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
    _client_certificate: Option<hyperswitch_masking::Secret<String>>,
    _client_certificate_key: Option<hyperswitch_masking::Secret<String>>,
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
