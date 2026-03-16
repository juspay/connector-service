use std::collections::HashMap;
use std::error::Error;

use crate::http_client::{
    HttpClient, HttpClientError, HttpOptions as NativeHttpOptions, HttpRequest as ClientHttpRequest,
};
use connector_service_ffi::handlers::payments::{authorize_req_handler, authorize_res_handler};
use connector_service_ffi::types::{FfiMetadataPayload, FfiRequestData};
use connector_service_ffi::utils::ffi_headers_to_masked_metadata;
use domain_types::router_data::ConnectorSpecificConfig;
use domain_types::router_response_types::Response;
use domain_types::utils::ForeignTryFrom;
use grpc_api_types::payments::{
    ConnectorConfig, FfiOptions, PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse,
    RequestConfig,
};

/// ConnectorClient — high-level Rust wrapper for the Connector Service.
///
/// Handles the full round-trip for any payment flow:
///   1. Build connector HTTP request via Rust core handlers
///   2. Execute the HTTP request via our standardized HttpClient (reqwest)
///   3. Parse the connector response via Rust core handlers
///
/// This client owns its primary connection pool (http_client).
pub struct ConnectorClient {
    http_client: HttpClient,
    config: ConnectorConfig,
    #[allow(dead_code)] // reserved for merging with per-request RequestConfig (e.g. http)
    defaults: RequestConfig,
}

impl ConnectorClient {
    /// Initialize a new ConnectorClient.
    ///
    /// # Arguments
    /// * `config` - The ConnectorConfig (connector_config with typed auth, options with environment).
    /// * `options` - Optional RequestConfig for default http/vault settings.
    pub fn new(
        config: ConnectorConfig,
        options: Option<RequestConfig>,
    ) -> Result<Self, HttpClientError> {
        let defaults = options.unwrap_or_default();

        // Map the Protobuf options to native transport options
        let native_opts = match defaults.http.as_ref() {
            Some(http_proto) => NativeHttpOptions::from(http_proto),
            None => NativeHttpOptions::default(),
        };

        let http_client = HttpClient::new(native_opts)?;

        Ok(Self {
            http_client,
            config,
            defaults,
        })
    }

    /// Builds FfiOptions from config. Environment comes from SdkOptions (immutable).
    fn resolve_ffi_options(&self, _options: &Option<RequestConfig>) -> FfiOptions {
        let environment = self
            .config
            .options
            .as_ref()
            .map(|o| o.environment)
            .unwrap_or(0);
        FfiOptions {
            environment,
            connector_config: self.config.connector_config.clone(),
        }
    }

    /// Authorize a payment flow.
    ///
    /// # Arguments
    /// * `request` - The PaymentServiceAuthorizeRequest protobuf message.
    /// * `metadata` - Metadata map containing x-* headers for MaskedMetadata.
    /// * `options` - Optional RequestConfig for per-call overrides (http, vault).
    pub async fn authorize(
        &self,
        request: PaymentServiceAuthorizeRequest,
        metadata: &HashMap<String, String>,
        options: Option<RequestConfig>,
    ) -> Result<PaymentServiceAuthorizeResponse, Box<dyn Error>> {
        // 1. Resolve final configuration
        let ffi_options = self.resolve_ffi_options(&options);

        let override_opts = options
            .as_ref()
            .and_then(|o| o.http.as_ref())
            .map(NativeHttpOptions::from);

        let ffi_request = build_ffi_request(request.clone(), metadata, &ffi_options)?;
        let environment = Some(grpc_api_types::payments::Environment::try_from(
            ffi_options.environment,
        )?);

        // 2. Build the connector HTTP request via core handler
        let connector_request = authorize_req_handler(ffi_request, environment)
            .map_err(|e| format!("authorize_req_handler failed: {:?}", e))?
            .ok_or("No connector request generated")?;

        // 3. Execute HTTP using the instance-owned client and potential overrides
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

        let http_response = self.http_client.execute(http_req, override_opts).await?;

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
            headers: Some(header_map),
            response: bytes::Bytes::from(http_response.body),
            status_code: http_response.status_code,
        };

        // 5. Parse response via core handler
        let ffi_request_for_res = build_ffi_request(request, metadata, &ffi_options)?;
        match authorize_res_handler(ffi_request_for_res, response, environment) {
            Ok(auth_response) => Ok(auth_response),
            Err(error_response) => {
                Err(format!("Authorization failed: {:?}", error_response).into())
            }
        }
    }
}

/// Internal helper to build the context-heavy FfiRequestData from raw inputs.
pub fn build_ffi_request<T>(
    payload: T,
    metadata: &HashMap<String, String>,
    options: &FfiOptions,
) -> Result<FfiRequestData<T>, Box<dyn Error>> {
    let proto_config = options
        .connector_config
        .as_ref()
        .ok_or("Missing connector_config in FfiOptions")?;

    let config_variant = proto_config
        .config
        .as_ref()
        .ok_or("Missing config variant in ConnectorSpecificConfig")?;

    let connector =
        domain_types::connector_types::ConnectorEnum::foreign_try_from(config_variant.clone())
            .map_err(|e| format!("Connector mapping failed: {e}"))?;

    let connector_config = ConnectorSpecificConfig::foreign_try_from(proto_config.clone())
        .map_err(|e| format!("Connector config mapping failed: {e}"))?;

    let masked_metadata = ffi_headers_to_masked_metadata(metadata)
        .map_err(|e| format!("Metadata mapping failed: {:?}", e))?;

    Ok(FfiRequestData {
        payload,
        extracted_metadata: FfiMetadataPayload {
            connector,
            connector_config,
        },
        masked_metadata: Some(masked_metadata),
    })
}
