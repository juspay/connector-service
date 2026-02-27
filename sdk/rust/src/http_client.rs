use std::collections::HashMap;
use std::time::{Duration, Instant};
use common_utils::request::Method;

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

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub http_url: Option<String>,
    pub https_url: Option<String>,
    pub bypass_urls: Vec<String>,
}

#[derive(Debug)]
pub struct HttpOptions {
    pub total_timeout_ms: u64,
    pub connect_timeout_ms: u64,
    pub response_timeout_ms: u64,
    pub keep_alive_timeout: u64,
    pub proxy: Option<ProxyConfig>,
    pub ca_cert: Option<String>,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            total_timeout_ms: 45_000,
            connect_timeout_ms: 10_000,
            response_timeout_ms: 30_000,
            keep_alive_timeout: 60_000,
            proxy: None,
            ca_cert: None,
        }
    }
}

pub struct HttpClient {
    client: reqwest::Client,
}

impl HttpClient {
    pub fn new(options: HttpOptions) -> Self {
        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(options.connect_timeout_ms))
            .timeout(Duration::from_millis(options.total_timeout_ms))
            .pool_idle_timeout(Duration::from_millis(options.keep_alive_timeout))
            .redirect(reqwest::redirect::Policy::none());

        // Add CA cert if provided
        if let Some(ca_cert_pem) = options.ca_cert {
            if let Ok(cert) = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes()) {
                builder = builder.add_root_certificate(cert);
            }
        }

        // We handle proxy at the client level for now to mirror the JS SDK's Dispatcher behavior
        if let Some(proxy_config) = options.proxy {
            if let Some(proxy_url) = proxy_config.https_url.or(proxy_config.http_url) {
                if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
                    let mut proxy = proxy;
                    for bypass in proxy_config.bypass_urls {
                        proxy = proxy.no_proxy(reqwest::header::HeaderValue::from_str(&bypass).unwrap_or(reqwest::header::HeaderValue::from_static("")));
                    }
                    builder = builder.proxy(proxy);
                }
            }
        }

        let client = builder.build().unwrap_or_else(|_| reqwest::Client::new());

        Self { client }
    }

    pub async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        
        let mut req_builder = match request.method {
            Method::Get => self.client.get(&request.url),
            Method::Post => self.client.post(&request.url),
            Method::Put => self.client.put(&request.url),
            Method::Delete => self.client.delete(&request.url),
            Method::Patch => self.client.patch(&request.url),
        };

        // Add headers
        for (key, value) in &request.headers {
            req_builder = req_builder.header(key, value);
        }

        // Add body
        if let Some(body_bytes) = request.body {
            req_builder = req_builder.body(body_bytes);
        }

        let response = req_builder.send().await?;
        let latency = start_time.elapsed().as_millis();

        let status_code = response.status().as_u16();
        let mut response_headers = HashMap::new();
        for (key, value) in response.headers() {
            // Normalize to lowercase for global parity
            response_headers.insert(key.to_string().to_lowercase(), value.to_str().unwrap_or("").to_string());
        }

        let body = response.bytes().await?.to_vec();

        Ok(HttpResponse {
            status_code,
            headers: response_headers,
            body,
            latency_ms: latency,
        })
    }
}
