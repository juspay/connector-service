use std::collections::HashMap;
use std::error::Error;

use connector_service_ffi::handlers::payments::{authorize_req_handler, authorize_res_handler};
use connector_service_ffi::types::{FfiMetadataPayload, FfiRequestData};
use connector_service_ffi::utils::ffi_headers_to_masked_metadata;
use domain_types::router_response_types::Response;
use grpc_api_types::payments::{PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse};

/// A Rust-native connector client that calls handler functions directly
/// without going through FFI or gRPC serialization boundaries.
pub struct ConnectorClient;

impl ConnectorClient {
    /// Authorize a payment by:
    /// 1. Building the connector HTTP request via `authorize_req_handler`
    /// 2. Extracting the raw request JSON (url, method, headers, body)
    /// 3. Making the HTTP call with reqwest
    /// 4. Parsing the response via `authorize_res_handler`
    pub async fn authorize(
        &self,
        request: PaymentServiceAuthorizeRequest,
        metadata: &HashMap<String, String>,
    ) -> Result<PaymentServiceAuthorizeResponse, Box<dyn Error>> {
        let ffi_request = build_ffi_request(request.clone(), metadata)?;

        // Step 1: Build the connector HTTP request
        let connector_request = authorize_req_handler(ffi_request, None)
            .map_err(|e| format!("authorize_req_handler failed: {:?}", e))?
            .ok_or("No connector request generated")?;

        // Step 2: Extract data using native methods (Binary Safe)
        let url = connector_request.url.clone();
        let method = connector_request.method;
        let mut headers = connector_request.get_headers_map();
        let (body, boundary) = connector_request.body.as_ref().map_or((None, None), |b| b.get_body_bytes());

        if let Some(boundary) = boundary {
            headers.insert("content-type".to_string(), format!("multipart/form-data; boundary={}", boundary));
        }

        // Step 3: Make the HTTP call with reqwest
        let client = reqwest::Client::new();
        let mut req_builder = match method {
            common_utils::request::Method::Get => client.get(url),
            common_utils::request::Method::Post => client.post(url),
            common_utils::request::Method::Put => client.put(url),
            common_utils::request::Method::Delete => client.delete(url),
            common_utils::request::Method::Patch => client.patch(url),
        };

        // Add headers
        for (key, value) in headers {
            req_builder = req_builder.header(key, value);
        }

        // Add body
        if let Some(body_bytes) = body {
            req_builder = req_builder.body(body_bytes);
        }

        let http_response = req_builder.send().await?;

        // Step 4: Convert HTTP response to domain Response type
        let status_code = http_response.status().as_u16();
        let mut header_map = http::HeaderMap::new();
        for (key, value) in http_response.headers() {
            if let Ok(name) = http::header::HeaderName::from_bytes(key.as_str().as_bytes()) {
                if let Ok(val) = http::header::HeaderValue::from_bytes(value.as_bytes()) {
                    header_map.insert(name, val);
                }
            }
        }
        let response_bytes: bytes::Bytes = http_response.bytes().await?;

        let response = Response {
            headers: if header_map.is_empty() {
                None
            } else {
                Some(header_map)
            },
            response: response_bytes,
            status_code,
        };

        // Step 5: Parse response via authorize_res_handler
        let ffi_request_for_res = build_ffi_request(request, metadata)?;
        match authorize_res_handler(ffi_request_for_res, response, None) {
            Ok(auth_response) => Ok(auth_response),
            Err(error_response) => {
                Err(format!("Authorization failed: {:?}", error_response).into())
            }
        }
    }
}

/// Build an FfiRequestData from a request and metadata HashMap.
///
/// The metadata map must contain:
/// - `"connector"`: connector name (e.g. `"Stripe"`)
/// - `"connector_auth_type"`: JSON string of the auth config
///   (e.g. `{"auth_type":"HeaderKey","api_key":"sk_test_xxx"}`)
/// - `x-*` headers for MaskedMetadata
pub fn build_ffi_request(
    payload: PaymentServiceAuthorizeRequest,
    metadata: &HashMap<String, String>,
) -> Result<FfiRequestData<PaymentServiceAuthorizeRequest>, Box<dyn Error>> {
    // Parse connector + auth type from metadata using serde (same approach as uniffi bindings)
    let connector_val = metadata
        .get("connector")
        .ok_or("Missing 'connector' in metadata")?;

    let auth_type_json = metadata
        .get("connector_auth_type")
        .ok_or("Missing 'connector_auth_type' in metadata")?;

    let auth_json: serde_json::Value = serde_json::from_str(auth_type_json)
        .map_err(|e| format!("connector_auth_type is not valid JSON: {}", e))?;

    let obj = serde_json::json!({
        "connector": connector_val,
        "connector_auth_type": auth_json,
    });

    let extracted_metadata: FfiMetadataPayload =
        serde_json::from_value(obj).map_err(|e| format!("Failed to parse metadata: {}", e))?;

    let masked_metadata = ffi_headers_to_masked_metadata(metadata)
        .map_err(|e| format!("Failed to build masked metadata: {}", e))?;

    Ok(FfiRequestData {
        payload,
        extracted_metadata,
        masked_metadata: Some(masked_metadata),
    })
}
