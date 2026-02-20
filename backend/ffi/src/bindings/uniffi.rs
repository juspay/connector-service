#[cfg(feature = "uniffi")]
mod uniffi_bindings_inner {
    use crate::handlers::payments::{authorize_req_handler, authorize_res_handler};
    use crate::types::{FfiMetadataPayload, FfiRequestData};
    use crate::utils::{ffi_headers_to_masked_metadata, FfiError};
    use bytes::Bytes;
    use domain_types::router_response_types::Response;
    use external_services::service::extract_raw_connector_request;
    use grpc_api_types::payments::PaymentServiceAuthorizeRequest;
    use http::header::{HeaderMap, HeaderName, HeaderValue};
    use prost::Message;
    use std::collections::HashMap;

    /// Error type exposed over the UniFFI boundary.
    #[derive(Debug, thiserror::Error, uniffi::Error)]
    pub enum UniffiError {
        #[error("Failed to decode protobuf request: {msg}")]
        DecodeError { msg: String },
        #[error("Missing metadata key: {key}")]
        MissingMetadata { key: String },
        #[error("Failed to parse metadata: {msg}")]
        MetadataParseError { msg: String },
        #[error("Handler error: {msg}")]
        HandlerError { msg: String },
        #[error("No connector request generated")]
        NoConnectorRequest,
    }

    impl From<FfiError> for UniffiError {
        fn from(e: FfiError) -> Self {
            Self::MetadataParseError { msg: e.to_string() }
        }
    }

    /// Build FfiMetadataPayload from the caller's flat HashMap.
    ///
    /// Expected keys:
    ///   "connector"           — connector name, e.g. "stripe"
    ///   "connector_auth_type" — JSON-encoded ConnectorAuthType, e.g.
    ///                           '{"HeaderKey":{"api_key":"sk_test_..."}}'
    fn parse_metadata(
        metadata: &HashMap<String, String>,
    ) -> Result<FfiMetadataPayload, UniffiError> {
        let connector_val =
            metadata
                .get("connector")
                .ok_or_else(|| UniffiError::MissingMetadata {
                    key: "connector".to_string(),
                })?;
        let auth_val =
            metadata
                .get("connector_auth_type")
                .ok_or_else(|| UniffiError::MissingMetadata {
                    key: "connector_auth_type".to_string(),
                })?;

        let auth_json: serde_json::Value =
            serde_json::from_str(auth_val).map_err(|e| UniffiError::MetadataParseError {
                msg: format!("connector_auth_type is not valid JSON: {e}"),
            })?;

        let obj = serde_json::json!({
            "connector": connector_val,
            "connector_auth_type": auth_json,
        });

        serde_json::from_value(obj)
            .map_err(|e| UniffiError::MetadataParseError { msg: e.to_string() })
    }

    /// Build the connector HTTP request.
    ///
    /// # Arguments
    /// - `request_bytes`: protobuf-encoded `PaymentServiceAuthorizeRequest`
    /// - `metadata`: flat map with keys `connector` and `connector_auth_type`
    ///
    /// # Returns
    /// JSON string: `{"url":"...","method":"POST","headers":{...},"body":{...}}`
    #[uniffi::export]
    pub fn authorize_req_transformer(
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
    ) -> Result<String, UniffiError> {
        let payload = PaymentServiceAuthorizeRequest::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let result = authorize_req_handler(request).map_err(|e| UniffiError::HandlerError {
            msg: format!("{e:?}"),
        })?;

        let connector_request = result.ok_or(UniffiError::NoConnectorRequest)?;

        Ok(extract_raw_connector_request(&connector_request))
    }

    /// Process the connector HTTP response and produce a structured response.
    ///
    /// # Arguments
    /// - `response_body`: raw bytes from the connector's HTTP response body
    /// - `status_code`: HTTP status code from the connector response
    /// - `response_headers`: HTTP response headers from the connector
    /// - `request_bytes`: the original protobuf-encoded `PaymentServiceAuthorizeRequest`
    /// - `metadata`: the original metadata map passed to `authorize_req_transformer`
    ///
    /// # Returns
    /// protobuf-encoded `PaymentServiceAuthorizeResponse` bytes
    #[uniffi::export]
    pub fn authorize_res_transformer(
        response_body: Vec<u8>,
        status_code: u16,
        response_headers: HashMap<String, String>,
        request_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
    ) -> Result<Vec<u8>, UniffiError> {
        let mut header_map = HeaderMap::new();
        for (key, value) in &response_headers {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(key.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                header_map.insert(name, val);
            }
        }

        let response = Response {
            headers: if header_map.is_empty() {
                None
            } else {
                Some(header_map)
            },
            response: Bytes::from(response_body),
            status_code,
        };

        let payload = PaymentServiceAuthorizeRequest::decode(Bytes::from(request_bytes))
            .map_err(|e| UniffiError::DecodeError { msg: e.to_string() })?;

        let ffi_metadata = parse_metadata(&metadata)?;
        let masked_metadata = ffi_headers_to_masked_metadata(&metadata)?;

        let request = FfiRequestData {
            payload,
            extracted_metadata: ffi_metadata,
            masked_metadata: Some(masked_metadata),
        };

        let proto_response = authorize_res_handler(request, response)
            .unwrap_or_else(grpc_api_types::payments::PaymentServiceAuthorizeResponse::from);

        Ok(proto_response.encode_to_vec())
    }
}

#[cfg(feature = "uniffi")]
pub use uniffi_bindings_inner::*;
