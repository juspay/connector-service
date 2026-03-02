use std::collections::HashMap;
use std::error::Error;

use crate::http_client::{HttpClient, HttpClientError, HttpRequest as ClientHttpRequest};
use connector_service_ffi::handlers::payments::{authorize_req_handler, authorize_res_handler};
use connector_service_ffi::types::{FfiMetadataPayload, FfiRequestData};
use connector_service_ffi::utils::ffi_headers_to_masked_metadata;
use domain_types::router_response_types::Response;
use grpc_api_types::payments::{
    FfiOptions, HttpOptions, PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse,
};

/// A Rust-native connector client that calls handler functions directly
/// without going through FFI or gRPC serialization boundaries.
pub struct ConnectorClient {
    http_client: HttpClient,
    options: grpc_api_types::payments::Options,
}

impl ConnectorClient {
    /**
     * @param options - unified SDK configuration (http, ffi)
     */
    pub fn new(options: grpc_api_types::payments::Options) -> Result<Self, HttpClientError> {
        let http_options = options.http.clone().unwrap_or_else(HttpOptions::default);
        Ok(Self {
            http_client: HttpClient::new(http_options)?,
            options,
        })
    }

    /// Authorize a payment by:
    /// 1. Building the connector HTTP request via `authorize_req_handler`
    /// 2. Making the HTTP call with HttpClient
    /// 3. Parsing the response via `authorize_res_handler`
    ///
    /// # Arguments
    /// * `request` - The PaymentServiceAuthorizeRequest protobuf message.
    /// * `metadata` - Metadata map containing connector routing and auth info.
    ///                Must contain:
    ///                - `"connector"`: connector name (e.g. `"Stripe"`)
    ///                - `"connector_auth_type"`: JSON string of the auth config
    ///                  (e.g. `{"auth_type":"HeaderKey","api_key":"sk_test_xxx"}`)
    ///                - `x-*` headers for MaskedMetadata
    /// * `ffi_options` - Optional FfiOptions message override for this specific call.
    pub async fn authorize(
        &self,
        request: PaymentServiceAuthorizeRequest,
        metadata: &HashMap<String, String>,
        ffi_options: Option<FfiOptions>,
    ) -> Result<PaymentServiceAuthorizeResponse, Box<dyn Error>> {
        let ffi_request = build_ffi_request(request.clone(), metadata)?;

        // Resolve FFI options (prefer call-specific, fallback to client-global)
        let ffi = ffi_options.or_else(|| self.options.ffi.clone());
        let test_mode = ffi
            .as_ref()
            .and_then(|f| f.env.as_ref())
            .map(|e| e.test_mode);

        // Step 1: Build the connector HTTP request
        let connector_request = authorize_req_handler(ffi_request, test_mode)
            .map_err(|e| format!("authorize_req_handler failed: {:?}", e))?
            .ok_or("No connector request generated")?;

        // Step 2: Prepare and execute the HTTP request via our high-performance client
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

        let http_response = self.http_client.execute(http_req).await?;

        // Step 3: Convert HTTP response to domain Response type
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

        // Step 4: Parse response via authorize_res_handler
        let ffi_request_for_res = build_ffi_request(request, metadata)?;
        match authorize_res_handler(ffi_request_for_res, response, test_mode) {
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
