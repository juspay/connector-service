use common_utils::request::Method;
use grpc_api_types::payments::{CaCert, HttpConfig, HttpDefault};
use std::collections::HashMap;
use std::time::{Duration, Instant};

// Native options for decoupling the SDK from the Protobuf-generated transport types.
#[derive(Clone, Debug, Default)]
pub struct ProxyConfig {
    pub http_url: Option<String>,
    pub https_url: Option<String>,
    pub bypass_urls: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct HttpOptions {
    pub total_timeout_ms: Option<u32>,
    pub connect_timeout_ms: Option<u32>,
    pub response_timeout_ms: Option<u32>,
    pub keep_alive_timeout_ms: Option<u32>,
    pub proxy: Option<ProxyConfig>,
    pub ca_cert: Option<CaCert>,
}

// ---------------------------------------------------------------------------
// Converters: Map from Protobuf types to Native Transport types
// ---------------------------------------------------------------------------

impl From<&HttpConfig> for HttpOptions {
    fn from(proto: &HttpConfig) -> Self {
        let proxy = proto.proxy.as_ref().map(|p| ProxyConfig {
            http_url: p.http_url.clone(),
            https_url: p.https_url.clone(),
            bypass_urls: p.bypass_urls.clone(),
        });

        Self {
            total_timeout_ms: proto.total_timeout_ms,
            connect_timeout_ms: proto.connect_timeout_ms,
            response_timeout_ms: proto.response_timeout_ms,
            keep_alive_timeout_ms: proto.keep_alive_timeout_ms,
            proxy,
            ca_cert: proto.ca_cert.clone(),
        }
    }
}

pub struct HttpRequest {
    pub url: String,
    pub method: Method,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

pub struct HttpResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub latency_ms: u128,
}

#[derive(Debug, thiserror::Error)]
pub enum HttpClientError {
    #[error("Connection Timeout: {0}")]
    ConnectTimeout(String),
    #[error("Response Timeout: {0}")]
    ResponseTimeout(String),
    #[error("Total Request Timeout: {0}")]
    TotalTimeout(String),
    #[error("Network Error: {0}")]
    NetworkFailure(String),
    #[error("Invalid Configuration: {0}")]
    InvalidConfiguration(String),
    #[error("Client Initialization Failure: {0}")]
    ClientInitialization(String),
}

impl HttpClientError {
    pub fn status_code(&self) -> u16 {
        match self {
            Self::ConnectTimeout(_) | Self::ResponseTimeout(_) | Self::TotalTimeout(_) => 504,
            Self::NetworkFailure(_)
            | Self::InvalidConfiguration(_)
            | Self::ClientInitialization(_) => 500,
        }
    }

    pub fn error_code(&self) -> &'static str {
        match self {
            Self::ConnectTimeout(_) => "CONNECT_TIMEOUT",
            Self::ResponseTimeout(_) => "RESPONSE_TIMEOUT",
            Self::TotalTimeout(_) => "TOTAL_TIMEOUT",
            Self::NetworkFailure(_) => "NETWORK_FAILURE",
            Self::InvalidConfiguration(_) => "INVALID_CONFIGURATION",
            Self::ClientInitialization(_) => "CLIENT_INITIALIZATION_FAILURE",
        }
    }
}

pub struct HttpClient {
    client: reqwest::Client,
    options: HttpOptions,
}

impl HttpClient {
    /// Initialize a new HttpClient with fixed infrastructure settings.
    pub fn new(options: HttpOptions) -> Result<Self, HttpClientError> {
        let connect_timeout = options
            .connect_timeout_ms
            .unwrap_or(HttpDefault::ConnectTimeoutMs as u32);

        let total_timeout = options
            .total_timeout_ms
            .unwrap_or(HttpDefault::TotalTimeoutMs as u32);

        let keep_alive_timeout = options
            .keep_alive_timeout_ms
            .unwrap_or(HttpDefault::KeepAliveTimeoutMs as u32);

        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(connect_timeout as u64))
            .timeout(Duration::from_millis(total_timeout as u64))
            .pool_idle_timeout(Duration::from_millis(keep_alive_timeout as u64))
            .redirect(reqwest::redirect::Policy::none());

        if let Some(ca) = &options.ca_cert {
            let cert = match &ca.format {
                Some(grpc_api_types::payments::ca_cert::Format::Pem(pem)) => {
                    reqwest::Certificate::from_pem(pem.as_bytes()).map_err(|e| {
                        HttpClientError::InvalidConfiguration(format!("Invalid PEM: {}", e))
                    })
                }
                Some(grpc_api_types::payments::ca_cert::Format::Der(der)) => {
                    reqwest::Certificate::from_der(der).map_err(|e| {
                        HttpClientError::InvalidConfiguration(format!("Invalid DER: {}", e))
                    })
                }
                None => Err(HttpClientError::InvalidConfiguration(
                    "Missing cert format".to_string(),
                )),
            }?;
            builder = builder.add_root_certificate(cert);
        }

        if let Some(proxy_config) = &options.proxy {
            if let Some(url) = proxy_config
                .https_url
                .as_ref()
                .or(proxy_config.http_url.as_ref())
            {
                if let Ok(mut proxy) = reqwest::Proxy::all(url) {
                    for bypass in &proxy_config.bypass_urls {
                        proxy = proxy.no_proxy(reqwest::NoProxy::from_string(bypass));
                    }
                    builder = builder.proxy(proxy);
                }
            }
        }

        let client = builder.build().map_err(|e| {
            HttpClientError::ClientInitialization(format!("Failed to build HTTP client: {}", e))
        })?;

        Ok(Self { client, options })
    }

    /// Execute an HTTP request, applying per-call behavioral overrides if provided.
    pub async fn execute(
        &self,
        request: HttpRequest,
        override_options: Option<HttpOptions>,
    ) -> Result<HttpResponse, HttpClientError> {
        let start_time = Instant::now();

        let mut req_builder = match request.method {
            Method::Get => self.client.get(&request.url),
            Method::Post => self.client.post(&request.url),
            Method::Put => self.client.put(&request.url),
            Method::Delete => self.client.delete(&request.url),
            Method::Patch => self.client.patch(&request.url),
        };

        // Efficient Override: Apply total timeout directly to RequestBuilder.
        let effective_total_timeout =
            if let Some(total) = override_options.as_ref().and_then(|o| o.total_timeout_ms) {
                req_builder = req_builder.timeout(Duration::from_millis(total as u64));
                total
            } else {
                self.options
                    .total_timeout_ms
                    .unwrap_or(HttpDefault::TotalTimeoutMs as u32)
            };

        for (key, value) in &request.headers {
            req_builder = req_builder.header(key, value);
        }

        if let Some(body_bytes) = request.body {
            req_builder = req_builder.body(body_bytes);
        }

        let response = req_builder.send().await.map_err(|e| {
            let elapsed = start_time.elapsed().as_millis() as u32;

            if e.is_timeout() {
                if e.is_connect() {
                    HttpClientError::ConnectTimeout(request.url.clone())
                } else if elapsed >= effective_total_timeout {
                    HttpClientError::TotalTimeout(request.url.clone())
                } else {
                    HttpClientError::ResponseTimeout(request.url.clone())
                }
            } else {
                HttpClientError::NetworkFailure(e.to_string())
            }
        })?;

        let latency = start_time.elapsed().as_millis();
        let status_code = response.status().as_u16();
        let mut response_headers = HashMap::new();
        for (key, value) in response.headers() {
            response_headers.insert(
                key.to_string().to_lowercase(),
                value.to_str().unwrap_or("").to_string(),
            );
        }

        let body = response
            .bytes()
            .await
            .map_err(|e| HttpClientError::NetworkFailure(e.to_string()))?
            .to_vec();

        Ok(HttpResponse {
            status_code,
            headers: response_headers,
            body,
            latency_ms: latency,
        })
    }
}

pub fn resolve_proxy_url(_url: &str, proxy: &Option<ProxyConfig>) -> Option<String> {
    let proxy = proxy.as_ref()?;
    proxy.https_url.clone().or_else(|| proxy.http_url.clone())
}
