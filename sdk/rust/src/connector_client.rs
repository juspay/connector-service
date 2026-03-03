use std::collections::HashMap;
use std::error::Error;

use crate::http_client::{
    HttpClient, HttpClientError, HttpOptions as NativeHttpOptions,
    HttpRequest as ClientHttpRequest, ProxyConfig,
};
use connector_service_ffi::handlers::payments::{authorize_req_handler, authorize_res_handler};
use connector_service_ffi::types::{FfiMetadataPayload, FfiRequestData};
use connector_service_ffi::utils::ffi_headers_to_masked_metadata;
use domain_types::router_response_types::Response;
use grpc_api_types::payments::{
    FfiOptions, Options, PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse,
};

/// A Rust-native connector client that calls handler functions directly.
/// Owns its primary connection pool (http_client).
pub struct ConnectorClient {
    http_client: HttpClient,
    options: Options,
}

impl ConnectorClient {
    /**
     * @param options - unified SDK configuration (http, ffi)
     */
    pub fn new(options: Options) -> Result<Self, HttpClientError> {
        // Map the Protobuf options to native transport options
        let native_opts = Self::get_native_http_options(&options.http);

        // Initialize the connection pool.
        let http_client = HttpClient::new(native_opts)?;

        Ok(Self {
            http_client,
            options,
        })
    }

    /// Internal helper to map Protobuf HttpOptions to Native HttpClient options.
    fn get_native_http_options(
        proto: &Option<grpc_api_types::payments::HttpOptions>,
    ) -> NativeHttpOptions {
        // If the user provided no HTTP options, we return a blank native struct.
        // The HttpClient::new() method will then use SdkDefault values for any missing fields.
        match proto {
            None => NativeHttpOptions::default(),
            Some(http) => NativeHttpOptions {
                total_timeout_ms: http.total_timeout_ms,
                connect_timeout_ms: http.connect_timeout_ms,
                response_timeout_ms: http.response_timeout_ms,
                keep_alive_timeout_ms: http.keep_alive_timeout_ms,
                proxy: http.proxy.as_ref().map(|p| ProxyConfig {
                    http_url: p.http_url.clone(),
                    https_url: p.https_url.clone(),
                    bypass_urls: p.bypass_urls.clone(),
                }),
                ca_cert: http.ca_cert.clone(),
            },
        }
    }

    /// Authorize a payment by:
    /// 1. Building the connector HTTP request via `authorize_req_handler`
    /// 2. Making the HTTP call with HttpClient
    /// 3. Parsing the response via `authorize_res_handler`
    ///
    /// # Arguments
    /// * `request` - The PaymentServiceAuthorizeRequest protobuf message.
    /// * `metadata` - Metadata map containing connector routing and auth info.
    ///   Must contain:
    ///   - `"connector"`: connector name (e.g. `"Stripe"`)
    ///   - `"connector_auth_type"`: JSON string of the auth config
    ///     (e.g. `{"auth_type":"HeaderKey","api_key":"sk_test_xxx"}`)
    ///   - `x-*` headers for MaskedMetadata
    /// * `ffi_options` - Optional FfiOptions message override for this specific call.
    pub async fn authorize(
        &self,
        request: PaymentServiceAuthorizeRequest,
        metadata: &HashMap<String, String>,
        ffi_options: Option<FfiOptions>,
    ) -> Result<PaymentServiceAuthorizeResponse, Box<dyn Error>> {
        let ffi_request = build_ffi_request(request.clone(), metadata)?;

        // Resolve FFI options (prefer call-specific override)
        let ffi = ffi_options.or(self.options.ffi);
        let test_mode = ffi
            .as_ref()
            .and_then(|f| f.env.as_ref())
            .map(|e| e.test_mode);

        // 1. Build the connector HTTP request
        let connector_request = authorize_req_handler(ffi_request, test_mode)
            .map_err(|e| format!("authorize_req_handler failed: {:?}", e))?
            .ok_or("No connector request generated")?;

        // 2. Resolve the client
        let client = &self.http_client;

        // 3. Execute HTTP
        let (body, boundary) = connector_request
            .body
            .as_ref()
            .map(|b| b.get_body_bytes())
            .transpose()
            .map_err(|e| format!("Body extraction failed: {e}"))?
            .unwrap_or((None, None));
        let mut headers = connector_request.get_headers_map();

        if let Some(boundary) = boundary {
            headers.insert(
                "content-type".to_string(),
                format!("multipart/form-data; boundary={}", boundary),
            );
        }

        let http_req = ClientHttpRequest {
            url: connector_request.url.clone(),
            method: connector_request.method,
            headers,
            body,
        };

        let http_response = client.execute(http_req).await?;

        // 4. Convert HTTP response to domain Response type
        let mut header_map = http::HeaderMap::new();
        for (key, value) in &http_response.headers {
            if let Ok(name) = http::header::HeaderName::from_bytes(key.as_bytes()) {
                if let Ok(val) = http::header::HeaderValue::from_bytes(value.as_bytes()) {
                    header_map.insert(name, val);
                }
            }
        }

        let response = Response {
            headers: if header_map.is_empty() {
                None
            } else {
                Some(header_map)
            },
            response: bytes::Bytes::from(http_response.body),
            status_code: http_response.status_code,
        };

        // 5. Parse response via authorize_res_handler
        let ffi_request_for_res = build_ffi_request(request, metadata)?;
        match authorize_res_handler(ffi_request_for_res, response, test_mode) {
            Ok(auth_response) => Ok(auth_response),
            Err(error_response) => {
                Err(format!("Authorization failed: {:?}", error_response).into())
            }
        }
    }
}

pub fn build_ffi_request(
    payload: PaymentServiceAuthorizeRequest,
    metadata: &HashMap<String, String>,
) -> Result<FfiRequestData<PaymentServiceAuthorizeRequest>, Box<dyn Error>> {
    let connector_val = metadata.get("connector").ok_or("Missing 'connector'")?;
    let auth_type_json = metadata
        .get("connector_auth_type")
        .ok_or("Missing 'connector_auth_type'")?;
    let auth_json: serde_json::Value = serde_json::from_str(auth_type_json)?;

    let obj = serde_json::json!({
        "connector": connector_val,
        "connector_auth_type": auth_json,
    });

    let extracted_metadata: FfiMetadataPayload = serde_json::from_value(obj)?;
    let masked_metadata = ffi_headers_to_masked_metadata(metadata)?;

    Ok(FfiRequestData {
        payload,
        extracted_metadata,
        masked_metadata: Some(masked_metadata),
    })
}
