use common_utils::request::Method;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use grpc_api_types::payments::SdkDefault;
use once_cell::sync::Lazy;

// Re-exporting or defining native options for decoupling
#[derive(Clone, Debug)]
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
    pub ca_cert: Option<Vec<u8>>,
}

// Static cache for connection pooling
static CLIENT_CACHE: Lazy<Mutex<HashMap<String, reqwest::Client>>> = Lazy::new(|| Mutex::new(HashMap::new()));

const MAX_CACHE_SIZE: usize = 100;
const TRANSPORT_DIRECT: &str = "TRANSPORT_DIRECT";

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
            Self::NetworkFailure(_) | Self::InvalidConfiguration(_) | Self::ClientInitialization(_) => 500,
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
    pub fn new(options: HttpOptions) -> Result<Self, HttpClientError> {
        // 1. Resolve Identity for Caching
        let proxy_url = options.proxy.as_ref().and_then(|p| p.https_url.clone().or(p.http_url.clone()));
        let cache_key = get_connection_key(proxy_url.as_deref(), &options);

        let mut cache = CLIENT_CACHE.lock().map_err(|_| HttpClientError::ClientInitialization("Failed to access global connection pool".to_string()))?;
        
        if let Some(existing_client) = cache.get(&cache_key) {
            return Ok(Self {
                client: existing_client.clone(),
                options,
            });
        }

        // 2. Cache miss - create new pooled client
        let connect_timeout = options.connect_timeout_ms.unwrap_or(SdkDefault::ConnectTimeoutMs as u32);
        let total_timeout = options.total_timeout_ms.unwrap_or(SdkDefault::TotalTimeoutMs as u32);
        let keep_alive_timeout = options.keep_alive_timeout_ms.unwrap_or(SdkDefault::KeepAliveTimeoutMs as u32);

        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(connect_timeout as u64))
            .timeout(Duration::from_millis(total_timeout as u64))
            .pool_idle_timeout(Duration::from_millis(keep_alive_timeout as u64))
            .redirect(reqwest::redirect::Policy::none());

        if let Some(ca_cert_bytes) = &options.ca_cert {
            let cert = reqwest::Certificate::from_pem(ca_cert_bytes)
                .map_err(|e| HttpClientError::InvalidConfiguration(format!("Invalid CA Certificate: {}", e)))?;
            builder = builder.add_root_certificate(cert);
        }

        if let Some(proxy_config) = &options.proxy {
            if let Some(url) = proxy_config.https_url.as_ref().or(proxy_config.http_url.as_ref()) {
                if let Ok(mut proxy) = reqwest::Proxy::all(url) {
                    for bypass in &proxy_config.bypass_urls {
                        proxy = proxy.no_proxy(reqwest::NoProxy::from_string(bypass));
                    }
                    builder = builder.proxy(proxy);
                }
            }
        }

        let client = builder.build()
            .map_err(|e| HttpClientError::ClientInitialization(format!("Failed to build HTTP client: {}", e)))?;

        // 3. Eviction strategy: FIFO attempt
        if cache.len() >= MAX_CACHE_SIZE {
            if let Some(oldest_key) = cache.keys().next().cloned() {
                cache.remove(&oldest_key);
            }
        }

        cache.insert(cache_key, client.clone());
        Ok(Self { client, options })
    }

    pub async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, HttpClientError> {
        let start_time = Instant::now();

        let mut req_builder = match request.method {
            Method::Get => self.client.get(&request.url),
            Method::Post => self.client.post(&request.url),
            Method::Put => self.client.put(&request.url),
            Method::Delete => self.client.delete(&request.url),
            Method::Patch => self.client.patch(&request.url),
        };

        for (key, value) in &request.headers {
            req_builder = req_builder.header(key, value);
        }

        if let Some(body_bytes) = request.body {
            req_builder = req_builder.body(body_bytes);
        }

        let response = req_builder.send().await.map_err(|e| {
            let elapsed = start_time.elapsed().as_millis() as u64;
            let total_timeout = self.options.total_timeout_ms.unwrap_or(SdkDefault::TotalTimeoutMs as u32) as u64;
            if e.is_timeout() {
                if e.is_connect() {
                    HttpClientError::ConnectTimeout(request.url.clone())
                } else if elapsed >= total_timeout {
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

        let body = response.bytes().await.map_err(|e| HttpClientError::NetworkFailure(e.to_string()))?.to_vec();

        Ok(HttpResponse {
            status_code,
            headers: response_headers,
            body,
            latency_ms: latency,
        })
    }
}

/// Helper to resolve proxy URL, honoring bypass rules.
pub fn resolve_proxy_url(url: &str, proxy: &Option<ProxyConfig>) -> Option<String> {
    let proxy = proxy.as_ref()?;
    let should_bypass = proxy.bypass_urls.iter().any(|b| b == url);
    if should_bypass {
        return None;
    }
    proxy.https_url.clone().or_else(|| proxy.http_url.clone())
}

/// Generates a stable key to identify a unique connection pool configuration.
pub fn get_connection_key(proxy_url: Option<&str>, options: &HttpOptions) -> String {
    format!(
        "uri={:?};connect={:?};res={:?};ca={:?}",
        proxy_url.unwrap_or(TRANSPORT_DIRECT),
        options.connect_timeout_ms,
        options.response_timeout_ms,
        options.ca_cert.as_ref().map(|c| c.len())
    )
}
